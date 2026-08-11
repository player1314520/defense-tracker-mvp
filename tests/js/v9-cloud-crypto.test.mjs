import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const cryptoSource = await readFile(
  new URL("../../web/v9-portal/crypto.mjs", import.meta.url),
  "utf8",
);

const {
  decryptRecord,
  createPkceRequest,
  createBrowserDeviceKeyPair,
  openOrgKeyForP256,
  sealOrgKeyForP256,
} = await import(
  "../../web/v9-portal/crypto.mjs"
);

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

test("浏览器只用 Web Crypto 解开与桌面兼容的 AES-GCM 信封", async () => {
  const orgKey = crypto.getRandomValues(new Uint8Array(32));
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const wrapNonce = crypto.getRandomValues(new Uint8Array(12));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const organizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const recordId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const recordType = "alert";
  const version = 2;
  const keyVersion = 1;
  const plaintext = encoder.encode('{"status":"open","title":"本地解密"}');
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
  const hash = Buffer.from(
    await crypto.subtle.digest("SHA-256", plaintext),
  ).toString("hex");
  const result = await decryptRecord(orgKey, {
    organization_id: organizationId,
    record_id: recordId,
    record_type: recordType,
    version,
    key_version: keyVersion,
    ciphertext: b64(ciphertext),
    nonce: b64(nonce),
    wrapped_data_key: b64(wrapped),
    wrap_nonce: b64(wrapNonce),
    content_hash: hash,
  });
  assert.deepEqual(result, { status: "open", title: "本地解密" });
});

test("PKCE 使用 S256 且授权 URL 不包含 verifier", async () => {
  const result = await createPkceRequest(
    "https://project.supabase.co",
    "https://portal.example/callback",
  );
  const url = new URL(result.authorizationUrl);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("state"), result.state);
  assert.equal(url.toString().includes(result.codeVerifier), false);
});

test("浏览器 P-256 设备私钥不可导出且能解开组织密钥信封", async () => {
  const browser = await createBrowserDeviceKeyPair();
  assert.equal(browser.privateKey.extractable, false);
  await assert.rejects(
    crypto.subtle.exportKey("pkcs8", browser.privateKey),
    /extractable|InvalidAccess/i,
  );

  const organizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const deviceId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const keyVersion = 3;
  const browserPublic = await crypto.subtle.importKey(
    "raw",
    Buffer.from(browser.publicKey, "base64url"),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: browserPublic },
    ephemeral.privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey(
    "raw", shared, "HKDF", false, ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(
        `v9:org-envelope-salt:1:${organizationId}:${deviceId}:${keyVersion}`,
      ),
      info: encoder.encode("v9:org-envelope-kek:1"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const orgKey = crypto.getRandomValues(new Uint8Array(32));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: encoder.encode(
        `v9:org-envelope:1:${organizationId}:${deviceId}:${keyVersion}:p256`,
      ),
    },
    key,
    orgKey,
  ));
  const ephemeralPublic = new Uint8Array(
    await crypto.subtle.exportKey("raw", ephemeral.publicKey),
  );
  const opened = await openOrgKeyForP256(browser.privateKey, {
    organization_id: organizationId,
    device_id: deviceId,
    key_version: keyVersion,
    ephemeral_public_key: b64(ephemeralPublic),
    nonce: b64(nonce),
    ciphertext: b64(ciphertext),
  });
  assert.deepEqual(opened, orgKey);
});

test("浏览器设备私钥从生成起即不可导出且不经过 PKCS8 明文", () => {
  assert.doesNotMatch(cryptoSource, /exportKey\("pkcs8"/);
  assert.match(
    cryptoSource,
    /generateKey\([\s\S]*?namedCurve:\s*"P-256"[\s\S]*?false,[\s\S]*?\["deriveBits"\]/,
  );
});

test("Owner 浏览器可为待批准 P-256 设备封装组织密钥", async () => {
  const target = await createBrowserDeviceKeyPair();
  const organizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const deviceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const keyVersion = 4;
  const orgKey = crypto.getRandomValues(new Uint8Array(32));

  const envelope = await sealOrgKeyForP256(orgKey, target.publicKey, {
    organizationId,
    deviceId,
    keyVersion,
  });
  const opened = await openOrgKeyForP256(target.privateKey, {
    organization_id: organizationId,
    device_id: deviceId,
    key_version: keyVersion,
    ephemeral_public_key: envelope.ephemeralPublicKey,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
  });

  assert.deepEqual(opened, orgKey);
  assert.equal(Buffer.from(envelope.ephemeralPublicKey, "base64url").length, 65);
  assert.equal(Buffer.from(envelope.nonce, "base64url").length, 12);
  assert.equal(Buffer.from(envelope.ciphertext, "base64url").length, 48);
});
