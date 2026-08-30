import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  RecordPlaintextError,
  decryptRecord,
  encryptRecord,
} from "../../web/v9-portal/crypto.mjs";
import { validateRecordPlaintext } from "../../web/v9-portal/record-schema.mjs";


const encoder = new TextEncoder();

function b64(value) {
  return Buffer.from(value).toString("base64url");
}

async function encrypt(keyBytes, nonce, plaintext, aad) {
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, "AES-GCM", false, ["encrypt"],
  );
  return new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(aad) },
    key,
    plaintext,
  ));
}

async function encryptedEnvelope(
  plaintextText,
  recordType = "alert",
  commitment = "legacy",
) {
  const orgKey = crypto.getRandomValues(new Uint8Array(32));
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const wrapNonce = crypto.getRandomValues(new Uint8Array(12));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const organizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const recordId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const version = 1;
  const keyVersion = 1;
  const plaintext = encoder.encode(plaintextText);
  const wrapped = await encrypt(
    orgKey,
    wrapNonce,
    dataKey,
    `v9:record-key:1:${organizationId}:${recordId}:${recordType}:${version}:${keyVersion}`,
  );
  const ciphertext = await encrypt(
    dataKey,
    nonce,
    plaintext,
    `v9:record-content:1:${organizationId}:${recordId}:${recordType}:${version}`,
  );
  const contentAad = `v9:record-content:1:${organizationId}:${recordId}:${recordType}:${version}`;
  const committedBytes = commitment === "current"
    ? Buffer.concat([
      Buffer.from("DefenseTracker-V9-record-ciphertext-commitment-v1\0"),
      Buffer.from(contentAad),
      Buffer.from(nonce),
      Buffer.from(ciphertext),
    ])
    : plaintext;
  const contentHash = Buffer.from(
    await crypto.subtle.digest("SHA-256", committedBytes),
  ).toString("hex");
  return {
    orgKey,
    envelope: {
      organization_id: organizationId,
      record_id: recordId,
      record_type: recordType,
      version,
      key_version: keyVersion,
      ciphertext: b64(ciphertext),
      nonce: b64(nonce),
      wrapped_data_key: b64(wrapped),
      wrap_nonce: b64(wrapNonce),
      content_hash: contentHash,
    },
  };
}


test("合法 AES-GCM 与哈希不能让非 JSON 明文越过隔离边界", async () => {
  const { orgKey, envelope } = await encryptedEnvelope("not-json");
  await assert.rejects(
    decryptRecord(orgKey, envelope),
    (error) => error instanceof RecordPlaintextError
      && error.code === "invalid_json",
  );
});


test("Portal 接受桌面端当前随机密文 commitment 而非仅兼容旧明文哈希", async () => {
  const { orgKey, envelope } = await encryptedEnvelope(
    '{"schema_version":1,"title":"当前承诺","status":"new"}',
    "alert",
    "current",
  );
  assert.deepEqual(await decryptRecord(orgKey, envelope), {
    schema_version: 1,
    title: "当前承诺",
    status: "new",
  });
});


test("Portal 生成的管理员墓碑是可由桌面协议解密的真实密文", async () => {
  const orgKey = crypto.getRandomValues(new Uint8Array(32));
  const organizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const recordId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const content = {
    schema_version: 1,
    title: "已删除的隔离记录",
    status: "deleted",
  };
  const encrypted = await encryptRecord(orgKey, {
    organizationId,
    recordId,
    recordType: "alert",
    version: 2,
    keyVersion: 1,
    content,
  });

  assert.deepEqual(await decryptRecord(orgKey, {
    organization_id: organizationId,
    record_id: recordId,
    record_type: "alert",
    version: 2,
    key_version: 1,
    ...encrypted,
  }), content);
});


test("按 record_type 的 V1 最小 schema 拒绝不可渲染结构", () => {
  assert.throws(
    () => validateRecordPlaintext("alert", {
      schema_version: 1,
      title: { attacker: "not-renderable-as-title" },
      status: "new",
    }),
    (error) => error instanceof RecordPlaintextError
      && error.code === "invalid_schema",
  );
  assert.deepEqual(
    validateRecordPlaintext("document", { body: "legacy sent" }),
    { body: "legacy sent" },
  );
  assert.deepEqual(
    validateRecordPlaintext("alert", {
      schema_version: 1,
      title: "<img src=x onerror=alert(1)>",
      status: "new",
    }),
    {
      schema_version: 1,
      title: "<img src=x onerror=alert(1)>",
      status: "new",
    },
  );
  assert.throws(
    () => validateRecordPlaintext("alert", {
      schema_version: 2,
      title: "future",
    }),
    (error) => error instanceof RecordPlaintextError
      && error.code === "unsupported_schema",
  );
});


test("Portal 隔离坏事件后仍持久化整页游标且只用 textContent 渲染", async () => {
  const source = await readFile(
    new URL("../../web/v9-portal/app.js", import.meta.url),
    "utf8",
  );
  const pullStart = source.indexOf("async function pullCiphertextChanges");
  const pullEnd = source.indexOf("function beginCiphertextRefresh", pullStart);
  const pull = source.slice(pullStart, pullEnd);
  const persistStart = source.indexOf("async function persistCiphertextPage");
  const persistEnd = source.indexOf("async function loadWorkflowStates", persistStart);
  const persist = source.slice(persistStart, persistEnd);

  assert.match(source, /createObjectStore\("syncQuarantine"\)/);
  assert.match(source, /MAX_SYNC_PAGE_ENCODED_BYTES = 24 \* 1024 \* 1024/);
  assert.match(pull, /quarantineEvent/);
  assert.match(source, /report_sync_event_quarantine/);
  assert.match(source, /admin_tombstone_quarantined_record/);
  assert.match(source, /p_event:\s*tombstoneEvent/);
  assert.match(source, /encryptRecord/);
  assert.match(pull, /cursor\s*=\s*Math\.max/);
  assert.match(persist, /syncState/);
  assert.match(persist, /syncQuarantine/);
  assert.match(persist, /\{ cursor \}/);
  assert.match(source, /\.textContent\s*=/);
  assert.doesNotMatch(source, /\.innerHTML\s*=/);
});
