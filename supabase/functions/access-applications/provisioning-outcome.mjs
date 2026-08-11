const ACCESS_PROVISIONING_OUTCOMES = new Set([
  "invited",
  "retryable",
  "cancelled",
]);

export function accessProvisioningStatus(result) {
  if (
    !result ||
    typeof result !== "object" ||
    result.applicationApplied !== true ||
    !ACCESS_PROVISIONING_OUTCOMES.has(result.applicationOutcome)
  ) {
    return "retryable";
  }
  return result.applicationOutcome;
}
