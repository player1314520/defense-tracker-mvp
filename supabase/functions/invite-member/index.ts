import "jsr:@supabase/functions-js@2.4.5/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.95.0";
import {
  invitationProvisioningConfigured,
  provisionInvitation,
} from "./admin-provisioning.ts";

declare const EdgeRuntime: {
  waitUntil(promise: Promise<unknown>): void;
};

const ROLES = new Set([
  "owner",
  "admin",
  "collector",
  "analyst",
  "editor",
  "approver",
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const MAX_BODY_BYTES = 8 * 1024;

class RequestInputError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function isPlainObject(
  value: unknown,
): value is Record<string, unknown> {
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
    if (!/^\d+$/.test(contentLength)) {
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
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = JSON.parse(decoded);
  } catch {
    throw new RequestInputError(400, "invalid_json");
  }
  if (!isPlainObject(parsed)) {
    throw new RequestInputError(400, "plain_json_object_required");
  }
  return parsed;
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
  if (namedKeys) {
    try {
      const parsed: unknown = JSON.parse(namedKeys);
      if (
        isPlainObject(parsed) &&
        typeof parsed["default"] === "string" &&
        parsed["default"].startsWith("sb_publishable_")
      ) {
        return parsed["default"];
      }
    } catch {
      // Invalid platform configuration is handled by server_not_configured.
    }
  }
  return "";
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
  const body = status === 204 ? null : JSON.stringify(payload);
  return new Response(body, { status, headers });
}

function invitationRegisteredResponse(
  origin: string,
): Response {
  return response(202, {
    status: "registered",
    request_reference: crypto.randomUUID(),
    message: "邀请已登记，成员需在目标设备发起登录",
  }, origin);
}

Deno.serve(async (request: Request) => {
  const origin = request.headers.get("Origin") || "";
  const origins = allowedOrigins();
  if (origin && !origins.has(origin)) {
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

  const authorization = request.headers.get("Authorization") || "";
  if (!authorization.startsWith("Bearer ")) {
    return response(401, { error: "authentication_required" }, origin);
  }
  const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
  const anonKey = publishableKey();
  if (!supabaseUrl || !anonKey || !invitationProvisioningConfigured()) {
    return response(503, { error: "server_not_configured" }, origin);
  }

  const userClient = createClient(supabaseUrl, anonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: authorization } },
  });
  const token = authorization.slice("Bearer ".length);
  const { data: userData, error: userError } =
    await userClient.auth.getUser(token);
  const actor = userData.user;
  if (userError || !actor) {
    return response(401, { error: "invalid_session" }, origin);
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
  const supported = new Set([
    "organization_id",
    "email",
    "role",
  ]);
  if (Object.keys(input).some((key) => !supported.has(key))) {
    return response(400, { error: "metadata_fields_only" }, origin);
  }
  if (
    typeof input.organization_id !== "string" ||
    typeof input.email !== "string" ||
    typeof input.role !== "string"
  ) {
    return response(400, { error: "invalid_invitation_metadata" }, origin);
  }
  const organizationId = input.organization_id;
  const email = input.email.trim().toLowerCase();
  const role = input.role;
  if (
    !UUID.test(organizationId) ||
    !EMAIL.test(email) ||
    email.length > 254 ||
    email.split("@", 1)[0].length > 64 ||
    !ROLES.has(role)
  ) {
    return response(400, { error: "invalid_invitation_metadata" }, origin);
  }

  const emailSha256 = await sha256Hex(email);
  const { data: invitationId, error: beginError } = await userClient
    .rpc("begin_member_invitation", {
      p_organization_id: organizationId,
      p_email_sha256: emailSha256,
      p_role: role,
    });
  if (
    beginError ||
    typeof invitationId !== "string" ||
    !UUID.test(invitationId)
  ) {
    return response(403, { error: "invitation_not_authorized" }, origin);
  }

  // Auth 模板和目标设备 PKCE 仍是外部配置门。固定回调由服务端配置，
  // code_verifier 只由目标设备持有。租约使崩溃或重复 worker 可安全重试。
  EdgeRuntime.waitUntil(
    provisionInvitation({
      supabaseUrl,
      invitationId,
      email,
      emailSha256,
    }).catch(() => undefined),
  );
  return invitationRegisteredResponse(origin);
});
