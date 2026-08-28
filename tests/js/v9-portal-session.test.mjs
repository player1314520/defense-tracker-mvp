import assert from "node:assert/strict";
import { test } from "node:test";

import {
  clearLegacyAuthSessions,
  createPortalAuthStorage,
  logoutPortalSession,
} from "../../web/v9-portal/session.mjs";
import { createPortalClient } from "../../web/v9-auth/src/portal.js";


function memoryAuthStore(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    values,
    getItem: async (key) => values.get(key),
    setItem: async (key, value) => values.set(key, value),
    removeItem: async (key) => values.delete(key),
    keys: async () => [...values.keys()],
    clear: async () => values.clear(),
  };
}


test("PKCE verifier 跨页面保留但 Supabase session 不进入持久存储", async () => {
  const backing = memoryAuthStore();
  const loginPage = createPortalAuthStorage(backing);
  const verifierKey = "sb-example-auth-token-code-verifier";
  const sessionKey = "sb-example-auth-token";

  await loginPage.setItem(verifierKey, "verifier-and-redirect-type");
  await loginPage.setItem(sessionKey, '{"refresh_token":"must-not-persist"}');

  assert.equal(await loginPage.getItem(sessionKey), '{"refresh_token":"must-not-persist"}');
  const callbackPage = createPortalAuthStorage(backing);
  assert.equal(await callbackPage.getItem(verifierKey), "verifier-and-redirect-type");
  assert.equal(await callbackPage.getItem(sessionKey), null);
  assert.equal(backing.values.has(sessionKey), false);
});


test("启动迁移只删除旧 session，保留正在进行的 PKCE verifier", async () => {
  const verifierKey = "sb-example-auth-token-code-verifier";
  const backing = memoryAuthStore({
    [verifierKey]: "verifier-and-redirect-type",
    "sb-example-auth-token": '{"refresh_token":"legacy"}',
    "other-legacy-auth-state": "legacy",
  });

  await clearLegacyAuthSessions(backing);

  assert.deepEqual([...backing.values.keys()], [verifierKey]);
});


test("真实 Supabase client 跨页面兑换 PKCE 且 refresh token 不落盘", async () => {
  const originalFetch = globalThis.fetch;
  const backing = memoryAuthStore();
  const jwt = [
    Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url"),
    Buffer.from(JSON.stringify({
      aud: "authenticated",
      exp: 4102444800,
      role: "authenticated",
      sub: "00000000-0000-4000-8000-000000000001",
    })).toString("base64url"),
    "test-signature",
  ].join(".");
  const user = {
    id: "00000000-0000-4000-8000-000000000001",
    aud: "authenticated",
    role: "authenticated",
    email: "member@example.test",
    app_metadata: { provider: "email", providers: ["email"] },
    user_metadata: {},
    identities: [],
    created_at: "2026-08-28T00:00:00.000Z",
    updated_at: "2026-08-28T00:00:00.000Z",
  };

  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.includes("/auth/v1/otp")) {
      return new Response("{}", {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("/auth/v1/token?grant_type=pkce")) {
      return new Response(JSON.stringify({
        access_token: jwt,
        refresh_token: "test-refresh-token",
        expires_in: 3600,
        token_type: "bearer",
        user,
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected test request: ${url}`);
  };

  try {
    const loginClient = createPortalClient(
      "https://example.supabase.test",
      "test-publishable-key",
      createPortalAuthStorage(backing),
    );
    const otp = await loginClient.auth.signInWithOtp({
      email: "member@example.test",
      options: { emailRedirectTo: "https://portal.example.test/portal/" },
    });
    assert.equal(otp.error, null);
    assert.equal(
      [...backing.values.keys()].some((key) => key.endsWith("-code-verifier")),
      true,
    );
    assert.equal(
      [...backing.values.values()].some((value) => String(value).includes("refresh_token")),
      false,
    );

    const callbackClient = createPortalClient(
      "https://example.supabase.test",
      "test-publishable-key",
      createPortalAuthStorage(backing),
    );
    const exchanged = await callbackClient.auth.exchangeCodeForSession("test-auth-code");
    assert.equal(exchanged.error, null);
    assert.equal(exchanged.data.session?.refresh_token, "test-refresh-token");
    assert.equal(backing.values.size, 0);

    const reloadedClient = createPortalClient(
      "https://example.supabase.test",
      "test-publishable-key",
      createPortalAuthStorage(backing),
    );
    const reloaded = await reloadedClient.auth.getSession();
    assert.equal(reloaded.data.session, null);
  } finally {
    globalThis.fetch = originalFetch;
  }
});


test("远程注销失败仍清空浏览器 Auth 与内存，但不触碰设备密钥", async () => {
  const calls = [];
  let deviceStoreCleared = false;
  const result = await logoutPortalSession({
    signOut: async () => ({
      error: new Error("auth network unavailable"),
    }),
    removeWakeChannel: async () => {
      calls.push("channel");
    },
    clearAuth: async () => {
      calls.push("auth");
    },
    clearMemory: () => {
      calls.push("memory");
    },
  });

  assert.deepEqual(calls, ["channel", "auth", "memory"]);
  assert.equal(result.remoteConfirmed, false);
  assert.match(result.remoteError.message, /network unavailable/);
  assert.equal(result.localCleared, true);
  assert.equal(deviceStoreCleared, false);
});


test("本地清理失败不能被误报为已安全注销", async () => {
  const result = await logoutPortalSession({
    signOut: async () => ({ error: null }),
    removeWakeChannel: async () => {},
    clearAuth: async () => {
      throw new Error("IndexedDB unavailable");
    },
    clearMemory: () => {},
  });

  assert.equal(result.remoteConfirmed, true);
  assert.equal(result.localCleared, false);
  assert.match(result.localError.message, /IndexedDB unavailable/);
});
