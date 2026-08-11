import "jsr:@supabase/functions-js@2.4.5/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.95.0";
import {
  decodeSecretKey,
  decryptEmail,
  encryptEmail,
  hmacHex,
  maskEmail,
  normalizeEmail,
} from "./crypto.mjs";
import {
  invitationProvisioningConfigured,
  provisionInvitation,
} from "../invite-member/admin-provisioning.ts";
import { isApplicationApprovalRole } from "./decision-policy.mjs";
import { accessProvisioningStatus } from "./provisioning-outcome.mjs";
import { trustedRequestSource } from "./request-source.mjs";

const MAX_BODY_BYTES = 8 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
class RequestInputError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

async function readBoundedJsonObject(
  request: Request,
): Promise<Record<string, unknown>> {
  const contentType = (request.headers.get("Content-Type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") {
    throw new RequestInputError(415, "json_content_type_required");
  }
  const contentLength = request.headers.get("Content-Length");
  if (contentLength) {
    if (!/^\d+$/u.test(contentLength)) {
      throw new RequestInputError(400, "invalid_content_length");
    }
    if (Number(contentLength) > MAX_BODY_BYTES) {
      throw new RequestInputError(413, "body_too_large");
    }
  }
  if (!request.body) {
    throw new RequestInputError(400, "invalid_json");
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new RequestInputError(413, "body_too_large");
    }
    chunks.push(value);
  }
  if (total === 0) {
    throw new RequestInputError(400, "invalid_json");
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
  } catch {
    throw new RequestInputError(400, "invalid_json");
  }
  if (!isPlainObject(parsed)) {
    throw new RequestInputError(400, "plain_json_object_required");
  }
  return parsed;
}

function response(
  status: number,
  payload: Record<string, unknown>,
  origin = "",
): Response {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
  }
  return new Response(status === 204 ? null : JSON.stringify(payload), {
    status,
    headers,
  });
}

function allowedOrigins(): Set<string> {
  const configured = (Deno.env.get("V9_ALLOWED_ORIGINS") || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (configured.length) return new Set(configured);
  const local: string[] = [];
  for (let port = 49231; port <= 49235; port += 1) {
    local.push(`http://127.0.0.1:${port}`);
  }
  return new Set(local);
}

function publishableKey(): string {
  const namedKeys = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS") || "";
  if (!namedKeys) return "";
  try {
    const parsed: unknown = JSON.parse(namedKeys);
    if (
      isPlainObject(parsed) &&
      typeof parsed.default === "string" &&
      parsed.default.startsWith("sb_publishable_")
    ) {
      return parsed.default;
    }
  } catch {
    // Configuration failure is returned without reflecting secret material.
  }
  return "";
}

function applicationSecrets(): {
  hmacKey: Uint8Array;
  encryptionKey: Uint8Array;
  keyVersion: number;
} {
  const hmacKey = decodeSecretKey(
    Deno.env.get("ACCESS_APPLICATION_HMAC_KEY") || "",
  );
  const encryptionKey = decodeSecretKey(
    Deno.env.get("ACCESS_APPLICATION_ENCRYPTION_KEY") || "",
  );
  const rawVersion = Deno.env.get("ACCESS_APPLICATION_ENCRYPTION_KEY_VERSION")
    || "1";
  if (!/^[1-9][0-9]{0,2}$/u.test(rawVersion)) {
    throw new TypeError("invalid_application_key_version");
  }
  const keyVersion = Number(rawVersion);
  if (keyVersion > 100) {
    throw new TypeError("invalid_application_key_version");
  }
  return { hmacKey, encryptionKey, keyVersion };
}

function genericApplyResponse(origin: string): Response {
  return response(202, {
    status: "received",
    request_reference: crypto.randomUUID(),
  }, origin);
}

function hasOnlyKeys(
  input: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const keys = Object.keys(input);
  return keys.length === allowed.length &&
    keys.every((key) => allowed.includes(key));
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function applyForAccess(
  request: Request,
  input: Record<string, unknown>,
  origin: string,
  supabaseUrl: string,
  serviceRoleKey: string,
  secrets: ReturnType<typeof applicationSecrets>,
): Promise<Response> {
  const generic = () => genericApplyResponse(origin);
  if (
    !hasOnlyKeys(input, ["action", "email", "terms_version"]) ||
    input.action !== "apply" ||
    typeof input.email !== "string" ||
    typeof input.terms_version !== "string" ||
    !/^[A-Za-z0-9._-]{1,64}$/u.test(input.terms_version)
  ) {
    return generic();
  }
  let normalizedEmail: string;
  try {
    normalizedEmail = normalizeEmail(input.email);
  } catch {
    return generic();
  }
  try {
    const userAgent = (request.headers.get("User-Agent") || "unavailable")
      .slice(0, 512);
    const [emailHmac, ipHmac, userAgentHmac, encrypted] = await Promise.all([
      hmacHex(secrets.hmacKey, "email", normalizedEmail),
      hmacHex(secrets.hmacKey, "ip", trustedRequestSource(request.headers)),
      hmacHex(secrets.hmacKey, "user-agent", userAgent),
      encryptEmail(normalizedEmail, secrets.encryptionKey, secrets.keyVersion),
    ]);
    const serviceClient = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    await serviceClient.rpc("submit_access_application", {
      p_email_hmac: emailHmac,
      p_email_ciphertext: encrypted.ciphertext,
      p_email_nonce: encrypted.nonce,
      p_email_key_version: encrypted.keyVersion,
      p_terms_version: input.terms_version,
      p_ip_hmac: ipHmac,
      p_user_agent_hmac: userAgentHmac,
    });
  } catch {
    // Submission, duplicate, throttled, and transient failures are
    // caller-indistinguishable. Operators observe only redacted DB audits.
  }
  return generic();
}

async function authenticatedClient(
  request: Request,
  supabaseUrl: string,
  anonymousKey: string,
) {
  const authorization = request.headers.get("Authorization") || "";
  if (!authorization.startsWith("Bearer ")) return null;
  const token = authorization.slice("Bearer ".length);
  const client = createClient(supabaseUrl, anonymousKey, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: authorization } },
  });
  const { data, error } = await client.auth.getUser(token);
  return error || !data.user ? null : client;
}

type AuthenticatedClient = NonNullable<
  Awaited<ReturnType<typeof authenticatedClient>>
>;

async function listApplications(
  client: AuthenticatedClient,
  input: Record<string, unknown>,
  origin: string,
): Promise<Response> {
  if (
    !hasOnlyKeys(input, ["action", "status", "cursor", "limit"]) ||
    typeof input.status !== "string" ||
    !["pending", "approved", "rejected", "invited", "cancelled", "all"]
      .includes(input.status) ||
    !(input.cursor === null ||
      (typeof input.cursor === "string" && UUID.test(input.cursor))) ||
    typeof input.limit !== "number" ||
    !Number.isInteger(input.limit) ||
    input.limit < 1 ||
    input.limit > 100
  ) {
    return response(400, { error: "invalid_list_request" }, origin);
  }
  const { data, error } = await client.rpc("list_access_applications", {
    p_status: input.status,
    p_cursor: input.cursor,
    p_limit: input.limit,
  });
  if (error || !isPlainObject(data) || !Array.isArray(data.items)) {
    return response(403, { error: "review_not_authorized" }, origin);
  }
  let secrets: ReturnType<typeof applicationSecrets>;
  try {
    secrets = applicationSecrets();
  } catch {
    return response(503, { error: "server_not_configured" }, origin);
  }
  const applications: Array<Record<string, unknown>> = [];
  try {
    for (const raw of data.items) {
      if (!isPlainObject(raw)) throw new TypeError("invalid_application_row");
      const item = { ...raw };
      const normalized = await decryptEmail({
        ciphertext: item.email_ciphertext,
        nonce: item.email_nonce,
        keyVersion: item.email_key_version,
      }, secrets.encryptionKey);
      item.id = item.application_id;
      item.email_masked = maskEmail(normalized);
      delete item.application_id;
      delete item.email_ciphertext;
      delete item.email_nonce;
      delete item.email_key_version;
      applications.push({
        id: item.id,
        email_masked: item.email_masked,
        terms_version: item.terms_version,
        status: item.status,
        provisioning_status: item.provisioning_status ?? null,
        requested_role: item.requested_role ?? null,
        created_at: item.created_at,
        last_submitted_at: item.last_submitted_at,
        submission_count: item.submission_count,
      });
    }
  } catch {
    return response(500, { error: "application_decryption_failed" }, origin);
  }
  return response(200, {
    applications,
    next_cursor: data.next_cursor ?? null,
  }, origin);
}

async function decideApplication(
  client: AuthenticatedClient,
  input: Record<string, unknown>,
  origin: string,
  supabaseUrl: string,
): Promise<Response> {
  if (
    !hasOnlyKeys(
      input,
      ["action", "application_id", "decision", "role"],
    ) ||
    typeof input.application_id !== "string" ||
    !UUID.test(input.application_id) ||
    typeof input.decision !== "string" ||
    !["approved", "rejected"].includes(input.decision) ||
    !isApplicationApprovalRole(input.role)
  ) {
    return response(400, { error: "invalid_decision_request" }, origin);
  }
  if (
    input.decision === "approved" &&
    !invitationProvisioningConfigured()
  ) {
    return response(503, { error: "server_not_configured" }, origin);
  }
  let secrets: ReturnType<typeof applicationSecrets>;
  try {
    secrets = applicationSecrets();
  } catch {
    return response(503, { error: "server_not_configured" }, origin);
  }
  const { data: review, error: reviewError } = await client.rpc(
    "get_access_application_for_review",
    { p_application_id: input.application_id },
  );
  if (reviewError || !isPlainObject(review)) {
    return response(409, { error: "application_decision_failed" }, origin);
  }
  let normalizedEmail: string;
  try {
    normalizedEmail = await decryptEmail({
      ciphertext: review.email_ciphertext,
      nonce: review.email_nonce,
      keyVersion: review.email_key_version,
    }, secrets.encryptionKey);
  } catch {
    return response(500, { error: "application_decryption_failed" }, origin);
  }
  const emailSha256 = await sha256Hex(normalizedEmail);
  const { data: decision, error: decisionError } = await client.rpc(
    "decide_access_application",
    {
      p_application_id: input.application_id,
      p_decision: input.decision,
      p_role: input.decision === "approved" ? input.role : null,
      p_email_sha256: input.decision === "approved" ? emailSha256 : null,
      p_reason_code: null,
    },
  );
  if (decisionError || !isPlainObject(decision)) {
    return response(409, { error: "application_decision_failed" }, origin);
  }
  if (input.decision === "approved") {
    if (decision.status === "approved") {
      const invitationId = decision.invitation_id;
      if (typeof invitationId !== "string" || !UUID.test(invitationId)) {
        return response(500, { error: "invitation_registration_failed" }, origin);
      }
      let status = "retryable";
      try {
        const provisioning = await provisionInvitation({
          supabaseUrl,
          invitationId,
          email: normalizedEmail,
          emailSha256,
          applicationId: input.application_id,
        });
        status = accessProvisioningStatus(provisioning);
      } catch {
        status = "retryable";
      }
      return response(200, {
        application_id: input.application_id,
        status,
      }, origin);
    } else if (
      !["invited", "cancelled"].includes(String(decision.status)) ||
      !(decision.invitation_id === null ||
        (typeof decision.invitation_id === "string" &&
          UUID.test(decision.invitation_id)))
    ) {
      return response(500, { error: "invitation_registration_failed" }, origin);
    }
  }
  return response(200, {
    application_id: input.application_id,
    status: decision.status,
  }, origin);
}

Deno.serve(async (request: Request) => {
  const origin = request.headers.get("Origin") || "";
  if (origin && !allowedOrigins().has(origin)) {
    return response(403, { error: "origin_not_allowed" });
  }
  if (request.method === "OPTIONS") {
    const preflight = response(204, {}, origin);
    preflight.headers.set(
      "Access-Control-Allow-Headers",
      "authorization, apikey, content-type",
    );
    preflight.headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    return preflight;
  }
  if (request.method !== "POST") {
    return response(405, { error: "method_not_allowed" }, origin);
  }
  let input: Record<string, unknown>;
  try {
    input = await readBoundedJsonObject(request);
  } catch (error) {
    if (error instanceof RequestInputError) {
      return response(error.status, { error: error.message }, origin);
    }
    return response(400, { error: "invalid_json" }, origin);
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  if (!supabaseUrl || !serviceRoleKey) {
    return response(503, { error: "server_not_configured" }, origin);
  }
  if (input.action === "apply") {
    let secrets: ReturnType<typeof applicationSecrets>;
    try {
      secrets = applicationSecrets();
    } catch {
      return response(503, { error: "server_not_configured" }, origin);
    }
    return await applyForAccess(
      request,
      input,
      origin,
      supabaseUrl,
      serviceRoleKey,
      secrets,
    );
  }
  if (input.action !== "list" && input.action !== "decision") {
    return response(400, { error: "unsupported_action" }, origin);
  }
  const anonymousKey = publishableKey();
  if (!anonymousKey) {
    return response(503, { error: "server_not_configured" }, origin);
  }
  const client = await authenticatedClient(request, supabaseUrl, anonymousKey);
  if (!client) {
    return response(401, { error: "authentication_required" }, origin);
  }
  if (input.action === "list") {
    return await listApplications(client, input, origin);
  }
  return await decideApplication(client, input, origin, supabaseUrl);
});
