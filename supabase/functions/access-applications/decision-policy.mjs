const APPLICATION_APPROVAL_ROLES = Object.freeze([
  "collector",
  "analyst",
  "editor",
  "approver",
]);

const APPLICATION_APPROVAL_ROLE_SET = new Set(APPLICATION_APPROVAL_ROLES);

export function isApplicationApprovalRole(value) {
  return typeof value === "string" && APPLICATION_APPROVAL_ROLE_SET.has(value);
}
