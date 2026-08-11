import assert from "node:assert/strict";
import { test } from "node:test";


let api = null;
try {
  api = await import("../../web/v9-portal/portal-api.mjs");
} catch {
  // The first TDD run intentionally reaches this branch before the module exists.
}

function recordingClient(response = { data: {}, error: null }) {
  const calls = [];
  return {
    calls,
    functions: {
      invoke: async (...args) => {
        calls.push(args);
        return response;
      },
    },
  };
}

test("匿名申请只向单一 Edge Function 发送必要字段", async () => {
  assert.ok(api, "portal-api.mjs 尚未实现");
  const client = recordingClient({ data: { accepted: true }, error: null });
  await api.submitAccessApplication(
    client,
    " applicant@example.com ",
    "mvp-2026-08",
  );
  assert.deepEqual(client.calls, [[
    "access-applications",
    {
      body: {
        action: "apply",
        email: "applicant@example.com",
        terms_version: "mvp-2026-08",
      },
    },
  ]]);
});

test("管理申请队列使用游标且决策角色被限制为非管理角色", async () => {
  assert.ok(api, "portal-api.mjs 尚未实现");
  const client = recordingClient({
    data: { applications: [], next_cursor: null },
    error: null,
  });
  await api.listAccessApplications(client, "cursor-1");
  await api.decideAccessApplication(
    client,
    "application-1",
    "approved",
    "collector",
  );

  assert.equal(client.calls[0][1].body.action, "list");
  assert.equal(client.calls[0][1].body.cursor, "cursor-1");
  assert.deepEqual(client.calls[1][1].body, {
    action: "decision",
    application_id: "application-1",
    decision: "approved",
    role: "collector",
  });
  await assert.rejects(
    api.decideAccessApplication(
      client,
      "application-1",
      "approved",
      "owner",
    ),
    /角色/,
  );
});
test("Edge Function 错误原样进入受控 UI 错误通道", async () => {
  assert.ok(api, "portal-api.mjs 尚未实现");
  const client = recordingClient({
    data: null,
    error: new Error("request rejected"),
  });
  await assert.rejects(
    api.listAccessApplications(client, null),
    /request rejected/,
  );
});
