const WORKFLOW_TARGETS = Object.freeze({
  editor: Object.freeze({
    draft: ["pending_approval"],
    editing: ["pending_approval"],
  }),
  approver: Object.freeze({
    pending_approval: ["editing", "signed"],
    signed: ["recalled"],
  }),
  owner: Object.freeze({
    draft: ["pending_approval"],
    editing: ["pending_approval"],
    pending_approval: ["editing", "signed"],
    signed: ["recalled"],
  }),
});

export function workflowTargets(role, currentState) {
  const targets = WORKFLOW_TARGETS[String(role || "").toLowerCase()]?.[
    String(currentState || "").toLowerCase()
  ];
  return targets ? [...targets] : [];
}

export function canManageAccess(role) {
  return ["owner", "admin"].includes(String(role || "").toLowerCase());
}

export function workflowRequest(
  organizationId,
  record,
  workflow,
  targetState,
) {
  const recordHash = String(record?.content_hash || "").toLowerCase();
  const workflowHash = String(workflow?.content_hash || "").toLowerCase();
  if (
    !/^[0-9a-f]{64}$/.test(recordHash)
    || recordHash !== workflowHash
  ) {
    throw new Error("工作流哈希与当前密文记录不一致");
  }
  const version = Number(workflow?.version);
  if (!Number.isSafeInteger(version) || version < 0) {
    throw new Error("工作流版本无效");
  }
  return {
    organization_id: String(organizationId || ""),
    record_id: String(record?.record_id || ""),
    expected_version: version,
    target_state: String(targetState || ""),
    content_hash: recordHash,
  };
}

function maskEmail(value) {
  const raw = String(value || "").trim();
  const separator = raw.lastIndexOf("@");
  if (separator <= 0 || separator === raw.length - 1) return "申请人已隐藏";
  return `${raw.slice(0, 1)}***@${raw.slice(separator + 1)}`;
}

const APPLICATION_ROLES = new Set([
  "collector",
  "analyst",
  "editor",
  "approver",
]);

export function safeApplicationSummary(application) {
  const requestedRole = String(application?.requested_role || "").toLowerCase();
  const provisioningStatus = String(
    application?.provisioning_status || "",
  ).toLowerCase();
  return {
    id: String(application?.id || ""),
    emailMasked: maskEmail(
      application?.email_masked || application?.email,
    ),
    status: String(application?.status || "pending"),
    provisioningStatus: provisioningStatus === "retryable"
      ? provisioningStatus
      : null,
    requestedRole: APPLICATION_ROLES.has(requestedRole)
      ? requestedRole
      : null,
    createdAt: String(application?.created_at || ""),
  };
}
