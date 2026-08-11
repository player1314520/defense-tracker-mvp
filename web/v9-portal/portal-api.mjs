const APPLICATION_ROLES = new Set([
  "collector",
  "analyst",
  "editor",
  "approver",
]);

async function invokeAccessApplications(client, body) {
  const { data, error } = await client.functions.invoke(
    "access-applications",
    { body },
  );
  if (error) throw error;
  return data || {};
}

export async function submitAccessApplication(
  client,
  email,
  termsVersion,
) {
  const normalizedEmail = String(email || "").trim();
  if (
    !normalizedEmail
    || normalizedEmail.length > 254
    || /[\r\n]/.test(normalizedEmail)
  ) {
    throw new Error("申请邮箱无效");
  }
  return invokeAccessApplications(client, {
    action: "apply",
    email: normalizedEmail,
    terms_version: String(termsVersion || ""),
  });
}

export async function listAccessApplications(client, cursor = null) {
  return invokeAccessApplications(client, {
    action: "list",
    status: "pending",
    cursor,
    limit: 50,
  });
}

export async function decideAccessApplication(
  client,
  applicationId,
  decision,
  role = "collector",
) {
  const normalizedDecision = String(decision || "").toLowerCase();
  const normalizedRole = String(role || "").toLowerCase();
  if (!["approved", "rejected"].includes(normalizedDecision)) {
    throw new Error("申请决策无效");
  }
  if (!APPLICATION_ROLES.has(normalizedRole)) {
    throw new Error("申请角色无效");
  }
  return invokeAccessApplications(client, {
    action: "decision",
    application_id: String(applicationId || ""),
    decision: normalizedDecision,
    role: normalizedRole,
  });
}
