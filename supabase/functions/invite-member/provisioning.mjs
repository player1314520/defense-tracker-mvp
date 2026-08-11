export function classifyInviteError(error) {
  if (!error) {
    return { outcome: "provisioned", resultCode: "created" };
  }
  const code = typeof error.code === "string" ? error.code : "";
  const status = typeof error.status === "number" ? error.status : 0;
  if (
    code === "user_already_exists" ||
    code === "email_exists" ||
    code === "email_address_already_registered"
  ) {
    return { outcome: "provisioned", resultCode: "already_exists" };
  }
  if (
    code === "email_address_invalid" ||
    code === "email_provider_disabled"
  ) {
    return {
      outcome: "deterministic_failure",
      resultCode: "invalid_identity",
    };
  }
  if (status === 429 || code === "over_email_send_rate_limit") {
    return { outcome: "retryable_failure", resultCode: "rate_limited" };
  }
  if (status >= 500) {
    return {
      outcome: "retryable_failure",
      resultCode: "provider_unavailable",
    };
  }
  return { outcome: "retryable_failure", resultCode: "unexpected" };
}

export function classifyThrownInviteError(error) {
  if (
    error &&
    typeof error === "object" &&
    error.name === "AbortError"
  ) {
    return { outcome: "retryable_failure", resultCode: "timeout" };
  }
  return { outcome: "retryable_failure", resultCode: "unexpected" };
}

export function applicationOutcomeForClaimAction(action) {
  if (action === "provisioned") return "invited";
  if (action === "cancelled") return "cancelled";
  return "retryable";
}

export function applicationOutcomeForCompletion({
  applied,
  outcome,
  reason,
  compensate,
}) {
  if (
    outcome === "deterministic_failure" ||
    reason === "invitation_closed" ||
    compensate === true
  ) {
    return "cancelled";
  }
  if (applied === true && outcome === "provisioned") {
    return "invited";
  }
  return "retryable";
}
