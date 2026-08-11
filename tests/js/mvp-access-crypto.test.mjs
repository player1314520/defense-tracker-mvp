import assert from "node:assert/strict";
import { test } from "node:test";

import {
  decryptEmail,
  encryptEmail,
  hmacHex,
  maskEmail,
  normalizeEmail,
} from "../../supabase/functions/access-applications/crypto.mjs";


const encryptionKey = new Uint8Array(32).fill(7);
const hmacKey = new Uint8Array(32).fill(11);


test("access email encryption is randomized and round trips", async () => {
  const email = normalizeEmail("  User.Name@Example.COM ");
  const first = await encryptEmail(email, encryptionKey, 1);
  const second = await encryptEmail(email, encryptionKey, 1);

  assert.equal(email, "user.name@example.com");
  assert.notEqual(first.ciphertext, second.ciphertext);
  assert.notEqual(first.nonce, second.nonce);
  assert.equal(await decryptEmail(first, encryptionKey), email);
  assert.equal(await decryptEmail(second, encryptionKey), email);
  assert.equal(first.keyVersion, 1);
});


test("access deduplication HMAC is deterministic and context separated", async () => {
  const one = await hmacHex(hmacKey, "email", "user@example.com");
  const two = await hmacHex(hmacKey, "email", "user@example.com");
  const ip = await hmacHex(hmacKey, "ip", "user@example.com");

  assert.equal(one, two);
  assert.match(one, /^[0-9a-f]{64}$/);
  assert.notEqual(one, ip);
});


test("email masking never returns the local part", () => {
  assert.equal(maskEmail("person@example.com"), "p***@example.com");
  assert.equal(maskEmail("x@example.com"), "x***@example.com");
  assert.ok(!maskEmail("person@example.com").includes("person"));
});


test("encrypted email fails closed for the wrong key or key version", async () => {
  const encrypted = await encryptEmail(
    "person@example.com",
    encryptionKey,
    7,
  );
  await assert.rejects(
    decryptEmail(encrypted, new Uint8Array(32).fill(8)),
    /email_decryption_failed/,
  );
  await assert.rejects(
    decryptEmail({ ...encrypted, keyVersion: 8 }, encryptionKey),
    /email_decryption_failed/,
  );
});


test("email normalization rejects ambiguous or oversized identities", () => {
  assert.throws(() => normalizeEmail("not-an-email"), /invalid_email/);
  assert.throws(
    () => normalizeEmail(`${"a".repeat(65)}@example.com`),
    /invalid_email/,
  );
  assert.throws(() => maskEmail("@example.com"), /invalid_email/);
});
