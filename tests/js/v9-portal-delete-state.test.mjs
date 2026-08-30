import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";


const source = await readFile(
  new URL("../../web/v9-portal/app.js", import.meta.url),
  "utf8",
);


test("移动门户按已验证密文载荷的 deleted 状态更新记录头", () => {
  const start = source.indexOf("async function pullCiphertextChanges");
  const end = source.indexOf("state.records = [...heads.values()]", start);
  const block = source.slice(start, end);

  assert.ok(start >= 0 && end > start);
  assert.match(block, /event\.payload\?\.deleted === true/);
  assert.doesNotMatch(block, /event\.operation === "delete"/);
});
