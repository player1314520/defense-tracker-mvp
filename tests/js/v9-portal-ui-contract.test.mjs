import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";


const [html, source, authSource] = await Promise.all([
  readFile(new URL("../../web/v9-portal/index.html", import.meta.url), "utf8"),
  readFile(new URL("../../web/v9-portal/app.js", import.meta.url), "utf8"),
  readFile(new URL("../../web/v9-auth/src/portal.js", import.meta.url), "utf8"),
]);


test("匿名区仅提供申请和登录且业务仪表盘默认隐藏", () => {
  assert.match(html, /id="anonymous-access"/);
  assert.match(html, /id="application-form"/);
  assert.match(html, /id="login-form"/);
  assert.match(html, /id="authenticated-dashboard"[^>]*hidden/);
  assert.match(source, /submitAccessApplication/);
  assert.match(html, /id="application-submit"[^>]*disabled/);
  assert.match(html, /id="login-submit"[^>]*disabled/);
  assert.match(
    source,
    /config\.access_applications_enabled\s*===\s*true/,
  );
});


test("登录工作区展示角色并为工作流和管理队列提供独立容器", () => {
  assert.match(html, /id="current-role"/);
  assert.match(html, /id="alert-list"/);
  assert.match(html, /id="job-list"/);
  assert.match(html, /id="publication-list"/);
  assert.match(html, /id="admin-panel"[^>]*hidden/);
  assert.match(html, /id="application-list"/);
  assert.match(html, /id="device-list"/);
});


test("工作流、申请和设备动作共用防双击 busy 门禁", () => {
  assert.match(source, /busyActions:\s*new Set\(\)/);
  assert.match(source, /async function runBusyAction/);
  assert.match(source, /transition_workflow/);
  assert.match(source, /pair_device/);
  assert.match(source, /listAccessApplications/);
  assert.match(source, /decideAccessApplication/);
  assert.match(source, /runBusyAction\("logout"/);
});


test("Portal 会话不写持久存储且启动时清理旧版令牌", () => {
  assert.match(authSource, /persistSession:\s*true/);
  assert.match(authSource, /\bstorage\s*,/);
  const initialize = source.slice(
    source.indexOf("async function initialize()"),
    source.indexOf('byId("login-form")'),
  );
  assert.match(initialize, /await clearLegacyAuthSessions\(authStorage\)/);
  assert.match(initialize, /createPortalClient\([\s\S]*portalAuthStorage/);
  assert.ok(
    initialize.indexOf("await clearLegacyAuthSessions(authStorage)")
      < initialize.indexOf("createPortalClient("),
  );
});


test("PKCE 回调在兑换前清除地址栏 code，失败也不残留历史", () => {
  const callback = source.slice(
    source.indexOf("async function handleCallback()"),
    source.indexOf("async function acceptPendingInvitations()"),
  );
  assert.ok(
    callback.indexOf("history.replaceState")
      < callback.indexOf("exchangeCodeForSession"),
  );
});


test("审批邀请失败会保留显式重试入口且不误报已发送", () => {
  assert.match(source, /application\.provisioningStatus\s*===\s*"retryable"/);
  assert.match(source, /重试发送邀请/);
  assert.match(source, /result\?\.status\s*===\s*"invited"/);
  assert.match(source, /邀请发送暂未完成，请重试/);
  assert.doesNotMatch(
    source,
    /decision === "approved" \? "申请已批准并发送邀请"/,
  );
});


test("申请队列暴露游标翻页入口而不是永久截断在前五十条", () => {
  assert.match(source, /accessNextCursor:\s*null/);
  assert.match(source, /async function loadMoreAccessApplications/);
  assert.match(
    source,
    /listAccessApplications\(state\.client,\s*state\.accessNextCursor\)/,
  );
  assert.match(source, /"application-load-more"/);
  assert.match(source, /applications\.next_cursor/);
});


test("浏览器设备注册、工作流和配对请求携带安全契约字段", () => {
  const registration = source.slice(
    source.indexOf("async function registerStoredDevice"),
    source.indexOf("async function createAndStoreDevice"),
  );
  assert.match(registration, /device_kind:\s*"browser"/);

  const workflow = source.slice(
    source.indexOf("async function performWorkflowTransition"),
    source.indexOf("async function approvePendingDevice"),
  );
  assert.match(workflow, /"transition_workflow"/);
  assert.match(workflow, /workflowRequest\(/);

  const pairing = source.slice(
    source.indexOf("async function approvePendingDevice"),
    source.indexOf("async function handlePortalAction"),
  );
  for (const field of [
    "target_user_id",
    "envelope_key_version",
    "ephemeral_public_key",
    "envelope_nonce",
    "envelope_ciphertext",
  ]) {
    assert.match(pairing, new RegExp(`${field}:`));
  }
});
