import assert from "node:assert/strict";
import { test } from "node:test";


let policy = null;
try {
  policy = await import("../../web/v9-portal/policy.mjs");
} catch {
  // The first TDD run intentionally reaches this branch before the module exists.
}


test("Portal 工作流按钮严格按六角色和当前状态开放", () => {
  assert.ok(policy, "policy.mjs 尚未实现");
  assert.deepEqual(policy.workflowTargets("editor", "editing"), [
    "pending_approval",
  ]);
  assert.deepEqual(policy.workflowTargets("editor", "pending_approval"), []);
  assert.deepEqual(policy.workflowTargets("approver", "pending_approval"), [
    "editing",
    "signed",
  ]);
  assert.deepEqual(policy.workflowTargets("approver", "signed"), ["recalled"]);
  assert.deepEqual(policy.workflowTargets("owner", "pending_approval"), [
    "editing",
    "signed",
  ]);
  assert.deepEqual(policy.workflowTargets("admin", "pending_approval"), []);
  assert.equal(policy.canManageAccess("owner"), true);
  assert.equal(policy.canManageAccess("admin"), true);
  assert.equal(policy.canManageAccess("approver"), false);
});


test("工作流 RPC 始终携带乐观锁版本和当前密文内容哈希", () => {
  assert.ok(policy, "policy.mjs 尚未实现");
  const request = policy.workflowRequest(
    "org-1",
    {
      record_id: "record-1",
      content_hash: "a".repeat(64),
    },
    {
      version: 7,
      state: "pending_approval",
      content_hash: "a".repeat(64),
    },
    "signed",
  );
  assert.deepEqual(request, {
    organization_id: "org-1",
    record_id: "record-1",
    expected_version: 7,
    target_state: "signed",
    content_hash: "a".repeat(64),
  });
  assert.throws(
    () => policy.workflowRequest(
      "org-1",
      { record_id: "record-1", content_hash: "b".repeat(64) },
      { version: 7, state: "pending_approval", content_hash: "a".repeat(64) },
      "signed",
    ),
    /哈希.*不一致/,
  );
});


test("申请队列只产生脱敏展示模型", () => {
  assert.ok(policy, "policy.mjs 尚未实现");
  const summary = policy.safeApplicationSummary({
    id: "application-1",
    email: "sensitive@example.com",
    email_masked: "s***@example.com",
    status: "pending",
    provisioning_status: null,
    requested_role: null,
    created_at: "2026-08-09T00:00:00Z",
  });
  assert.deepEqual(summary, {
    id: "application-1",
    emailMasked: "s***@example.com",
    status: "pending",
    provisioningStatus: null,
    requestedRole: null,
    createdAt: "2026-08-09T00:00:00Z",
  });
  assert.equal(JSON.stringify(summary).includes("sensitive@example.com"), false);

  const unsafeBackendLabel = policy.safeApplicationSummary({
    id: "application-2",
    email_masked: "backend-leaked@example.com",
  });
  assert.equal(
    JSON.stringify(unsafeBackendLabel).includes("backend-leaked@example.com"),
    false,
  );

  const retryable = policy.safeApplicationSummary({
    id: "application-3",
    email_masked: "r***@example.com",
    status: "approved",
    provisioning_status: "retryable",
    requested_role: "editor",
  });
  assert.equal(retryable.provisioningStatus, "retryable");
  assert.equal(retryable.requestedRole, "editor");

  const untrusted = policy.safeApplicationSummary({
    status: "approved",
    provisioning_status: "sent-ish",
    requested_role: "owner",
  });
  assert.equal(untrusted.provisioningStatus, null);
  assert.equal(untrusted.requestedRole, null);
});
