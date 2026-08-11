import assert from "node:assert/strict";
import { test } from "node:test";

import {
  initializePersonalBusinessContext,
} from "../../web/v9-auth/src/business-context.js";


test("个人上下文 bootstrap 失败时锁定并结束初始化等待", async () => {
  const expected = Object.assign(new Error("bootstrap failed"), {
    status: 503,
  });
  const locked = [];

  await assert.rejects(
    initializePersonalBusinessContext({
      discover: async () => {
        throw Object.assign(new Error("not initialized"), { status: 409 });
      },
      bootstrap: async () => {
        throw expected;
      },
      validate: () => {},
      publish: () => {
        throw new Error("must not publish");
      },
      lock: (reason) => locked.push(reason),
    }),
    expected,
  );

  assert.deepEqual(locked, ["personal_context_unavailable"]);
});


test("云登录准备可确认个人恢复码但不提前发布个人上下文", async () => {
  const context = { organization_id: "organization-1" };
  let published = false;
  let locked = false;

  const resolved = await initializePersonalBusinessContext(
    {
      discover: async () => {
        throw Object.assign(new Error("pending"), { status: 409 });
      },
      bootstrap: async () => context,
      validate: (value) => assert.equal(value, context),
      publish: () => {
        published = true;
      },
      lock: () => {
        locked = true;
      },
    },
    { publishContext: false },
  );

  assert.equal(resolved, context);
  assert.equal(published, false);
  assert.equal(locked, false);
});
