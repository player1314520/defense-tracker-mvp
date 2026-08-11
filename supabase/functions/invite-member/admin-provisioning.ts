import { createClient } from "npm:@supabase/supabase-js@2.95.0";
import {
  applicationOutcomeForClaimAction,
  applicationOutcomeForCompletion,
  classifyInviteError,
  classifyThrownInviteError,
} from "./provisioning.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type ProvisionInput = {
  supabaseUrl: string;
  invitationId: string;
  email: string;
  emailSha256: string;
  applicationId?: string;
};

type ProvisionResult = {
  claimed: boolean;
  applied: boolean;
  outcome?: string;
  resultCode?: string;
  compensated?: boolean;
  applicationOutcome?: "invited" | "retryable" | "cancelled";
  applicationApplied?: boolean;
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fixedRedirectUrl(): string {
  const configured = Deno.env.get("V9_INVITE_REDIRECT_URL") || "";
  let parsed: URL;
  try {
    parsed = new URL(configured);
  } catch {
    throw new Error("invalid_invite_redirect_configuration");
  }
  if (
    configured.length > 2048 ||
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    parsed.origin === "null"
  ) {
    throw new Error("invalid_invite_redirect_configuration");
  }
  return parsed.toString();
}

export function invitationProvisioningConfigured(): boolean {
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  if (!serviceRoleKey) return false;
  try {
    fixedRedirectUrl();
    return true;
  } catch {
    return false;
  }
}

export async function provisionInvitation(
  input: ProvisionInput,
): Promise<ProvisionResult> {
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  if (!serviceRoleKey) {
    throw new Error("invitation_provisioning_not_configured");
  }
  const redirectTo = fixedRedirectUrl();
  const adminClient = createClient(input.supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
  const finishApplication = async (
    applicationOutcome: "invited" | "retryable" | "cancelled",
  ): Promise<boolean | undefined> => {
    if (!input.applicationId || !UUID.test(input.applicationId)) {
      return undefined;
    }
    try {
      const { data, error } = await adminClient.rpc(
        "finish_access_application_invitation",
        {
          p_application_id: input.applicationId,
          p_invitation_id: input.invitationId,
          p_outcome: applicationOutcome,
        },
      );
      return !error && data === true;
    } catch {
      return false;
    }
  };

  let claim: unknown;
  let claimError: unknown;
  try {
    const result = await adminClient
      .rpc("claim_member_invitation_provisioning", {
        p_invitation_id: input.invitationId,
        p_email_sha256: input.emailSha256,
      });
    claim = result.data;
    claimError = result.error;
  } catch {
    const applicationOutcome = "retryable" as const;
    return {
      claimed: false,
      applied: false,
      applicationOutcome,
      applicationApplied: await finishApplication(applicationOutcome),
    };
  }
  if (
    claimError ||
    !isPlainObject(claim)
  ) {
    const applicationOutcome = "retryable" as const;
    return {
      claimed: false,
      applied: false,
      applicationOutcome,
      applicationApplied: await finishApplication(applicationOutcome),
    };
  }
  if (claim.action !== "provision") {
    const applicationOutcome = applicationOutcomeForClaimAction(
      claim.action,
    ) as "invited" | "retryable" | "cancelled";
    return {
      claimed: false,
      applied: applicationOutcome === "invited",
      applicationOutcome,
      applicationApplied: await finishApplication(applicationOutcome),
    };
  }
  if (
    typeof claim.attempt_id !== "string" ||
    !UUID.test(claim.attempt_id)
  ) {
    const applicationOutcome = "retryable" as const;
    return {
      claimed: false,
      applied: false,
      applicationOutcome,
      applicationApplied: await finishApplication(applicationOutcome),
    };
  }

  const attemptId = claim.attempt_id;
  let outcome: string;
  let resultCode: string;
  let createdUserId = "";
  try {
    const { data, error } = await adminClient.auth.admin.inviteUserByEmail(
      input.email,
      { redirectTo },
    );
    const classified = classifyInviteError(error);
    outcome = classified.outcome;
    resultCode = classified.resultCode;
    if (!error && data.user && UUID.test(data.user.id)) {
      createdUserId = data.user.id;
    } else if (!error) {
      outcome = "retryable_failure";
      resultCode = "unexpected";
    }
  } catch (error) {
    const classified = classifyThrownInviteError(error);
    outcome = classified.outcome;
    resultCode = classified.resultCode;
  }

  let completion: unknown;
  let completionError: unknown;
  try {
    const result = await adminClient
      .rpc("finish_member_invitation_provisioning", {
        p_invitation_id: input.invitationId,
        p_attempt_id: attemptId,
        p_outcome: outcome,
        p_result_code: resultCode,
      });
    completion = result.data;
    completionError = result.error;
  } catch {
    const applicationOutcome = "retryable" as const;
    return {
      claimed: true,
      applied: false,
      outcome,
      resultCode,
      applicationOutcome,
      applicationApplied: await finishApplication(applicationOutcome),
    };
  }
  if (completionError || !isPlainObject(completion)) {
    const applicationOutcome = "retryable" as const;
    return {
      claimed: true,
      applied: false,
      outcome,
      resultCode,
      applicationOutcome,
      applicationApplied: await finishApplication(applicationOutcome),
    };
  }

  let compensated = false;
  if (completion.compensate === true) {
    if (createdUserId) {
      const { error: deletionError } = await adminClient.auth.admin.deleteUser(
        createdUserId,
        false,
      );
      compensated = !deletionError;
    }
    await adminClient.rpc("record_member_invitation_compensation", {
      p_invitation_id: input.invitationId,
      p_attempt_id: attemptId,
      p_succeeded: compensated,
    });
  }

  const applied = completion.applied === true;
  const applicationOutcome = applicationOutcomeForCompletion({
    applied,
    outcome,
    reason: completion.reason,
    compensate: completion.compensate,
  }) as "invited" | "retryable" | "cancelled";
  return {
    claimed: true,
    applied,
    outcome,
    resultCode,
    compensated,
    applicationOutcome,
    applicationApplied: await finishApplication(applicationOutcome),
  };
}
