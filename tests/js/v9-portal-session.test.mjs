import assert from "node:assert/strict";
import { test } from "node:test";

import { logoutPortalSession } from "../../web/v9-portal/session.mjs";


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
