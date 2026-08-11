import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const source = await readFile(
  new URL("../../web/v9-portal/app.js", import.meta.url),
  "utf8",
);


test("门户组织列表保留 RLS 返回的 invited membership", () => {
  const start = source.indexOf("async function loadOrganizations()");
  const end = source.indexOf("async function handleCallback()", start);
  const block = source.slice(start, end);

  assert.ok(start >= 0 && end > start);
  assert.doesNotMatch(block, /\.eq\("status",\s*"active"\)/);
  assert.match(block, /\.eq\("user_id", state\.session\.user\.id\)/);
  assert.match(block, /\.in\("status", \["active", "invited"\]\)/);
  assert.match(block, /item\.status === "invited"/);
  assert.match(block, /待设备配对/);
});


test("invited 组织仍沿用受控 register_device onboarding", () => {
  assert.match(source, /async function createAndStoreDevice/);
  assert.match(source, /\.rpc\("register_device"/);
  assert.match(source, /if \(!device\)/);
  assert.match(source, /createAndStoreDevice\(organizationId, userId\)/);
  assert.match(source, /remoteDevice\.status !== "active"/);
});


test("门户只接受 PKCE code 并在加载组织前幂等接受邀请", () => {
  const callbackStart = source.indexOf("async function handleCallback()");
  const callbackEnd = source.indexOf(
    "async function acceptPendingInvitations()",
    callbackStart,
  );
  const callback = source.slice(callbackStart, callbackEnd);
  const initializeStart = source.indexOf("async function initialize()");
  const initializeEnd = source.indexOf(
    'byId("login-form").addEventListener',
    initializeStart,
  );
  const initialize = source.slice(initializeStart, initializeEnd);

  assert.ok(callbackStart >= 0 && callbackEnd > callbackStart);
  assert.match(callback, /getAll\("code"\)/);
  assert.match(callback, /exchangeCodeForSession/);
  assert.doesNotMatch(callback, /verifyOtp/);
  assert.match(source, /\.rpc\(\s*"accept_member_invitation",\s*\{\}/);
  assert.ok(
    initialize.indexOf("await acceptPendingInvitations()")
      < initialize.indexOf("await loadOrganizations()"),
  );
});


test("公网登录永不通过 OTP 隐式创建未审批用户", () => {
  const initializeStart = source.indexOf("async function initialize()");
  const initializeEnd = source.indexOf(
    'byId("login-form").addEventListener',
    initializeStart,
  );
  const initialize = source.slice(initializeStart, initializeEnd);
  const login = source.slice(initializeEnd);

  assert.doesNotMatch(initialize, /invited_signup_enabled/);
  assert.match(login, /shouldCreateUser:\s*false/);
  assert.match(login, /仅受邀成员可登录/);
  assert.doesNotMatch(login, /shouldCreateUser:\s*true/);
});
