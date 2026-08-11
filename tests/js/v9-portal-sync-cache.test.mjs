import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";


const source = await readFile(
  new URL("../../web/v9-portal/app.js", import.meta.url),
  "utf8",
);


test("门户为每个用户组织持久化密文记录头和完整页游标", () => {
  assert.match(source, /createObjectStore\("recordHeads"\)/);
  assert.match(source, /createObjectStore\("syncState"\)/);
  assert.match(source, /async function restoreCachedWorkspace/);
  assert.match(source, /async function persistCiphertextPage/);

  const start = source.indexOf("async function persistCiphertextPage");
  const end = source.indexOf("async function pullCiphertextChanges", start);
  const block = source.slice(start, end);
  assert.ok(start >= 0 && end > start);
  assert.match(block, /event\.payload/);
  assert.doesNotMatch(block, /event\.content/);
});


test("解锁后先恢复本地密文快照再从已提交游标续拉", () => {
  const start = source.indexOf("state.orgKey = orgKey");
  const end = source.indexOf("await initialRefresh", start);
  const block = source.slice(start, end);

  assert.ok(start >= 0 && end > start);
  assert.match(block, /await restoreCachedWorkspace/);
  assert.ok(
    block.indexOf("await restoreCachedWorkspace")
      < block.indexOf("await subscribeToWakeups"),
  );
});
