const encoder = new TextEncoder();

export function base64urlToBytes(value) {
  const padded = String(value) + "=".repeat((4 - String(value).length % 4) % 4);
  const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function bytesToBase64url(value) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export async function createPkceRequest(
  supabaseUrl,
  redirectUri,
  clientId = "defense-tracker-web",
) {
  const verifierBytes = crypto.getRandomValues(new Uint8Array(48));
  const verifier = bytesToBase64url(verifierBytes);
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(verifier));
  const challenge = bytesToBase64url(new Uint8Array(digest));
  const state = bytesToBase64url(crypto.getRandomValues(new Uint8Array(24)));
  const url = new URL("/auth/v1/oauth/authorize", supabaseUrl);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    scope: "openid email profile",
  });
  return { authorizationUrl: url.toString(), codeVerifier: verifier, state };
}

async function aesDecrypt(keyBytes, nonce, ciphertext, additionalData) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  return new Uint8Array(await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: encoder.encode(additionalData),
      tagLength: 128,
    },
    key,
    ciphertext,
  ));
}

export async function decryptRecord(orgKeyBytes, envelope) {
  const orgId = envelope.organization_id;
  const recordId = envelope.record_id;
  const recordType = envelope.record_type;
  const version = Number(envelope.version);
  const keyVersion = Number(envelope.key_version);
  const keyAad = `v9:record-key:1:${orgId}:${recordId}:${recordType}:${version}:${keyVersion}`;
  const dataKey = await aesDecrypt(
    orgKeyBytes,
    base64urlToBytes(envelope.wrap_nonce),
    base64urlToBytes(envelope.wrapped_data_key),
    keyAad,
  );
  const contentAad = `v9:record-content:1:${orgId}:${recordId}:${recordType}:${version}`;
  const plaintext = await aesDecrypt(
    dataKey,
    base64urlToBytes(envelope.nonce),
    base64urlToBytes(envelope.ciphertext),
    contentAad,
  );
  const digest = bytesToBase64url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", plaintext)),
  );
  const expected = bytesToBase64url(
    Uint8Array.from(envelope.content_hash.match(/.{2}/g), (part) => parseInt(part, 16)),
  );
  if (digest !== expected) throw new Error("内容哈希校验失败");
  return JSON.parse(new TextDecoder().decode(plaintext));
}

export async function createBrowserDeviceKeyPair() {
  const keys = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const publicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", keys.publicKey),
  );
  return {
    privateKey: keys.privateKey,
    publicKey: bytesToBase64url(publicKey),
    keyAlgorithm: "p256",
  };
}

export async function openOrgKeyForP256(privateKey, envelope) {
  const ephemeralPublicKey = await crypto.subtle.importKey(
    "raw",
    base64urlToBytes(envelope.ephemeral_public_key),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeralPublicKey },
    privateKey,
    256,
  ));
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveKey"],
  );
  const organizationId = envelope.organization_id;
  const deviceId = envelope.device_id;
  const keyVersion = Number(envelope.key_version);
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
    ["decrypt"],
  );
  return new Uint8Array(await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64urlToBytes(envelope.nonce),
      additionalData: encoder.encode(
        `v9:org-envelope:1:${organizationId}:${deviceId}:${keyVersion}:p256`,
      ),
      tagLength: 128,
    },
    key,
    base64urlToBytes(envelope.ciphertext),
  ));
}

export async function sealOrgKeyForP256(
  orgKeyBytes,
  targetPublicKey,
  { organizationId, deviceId, keyVersion },
) {
  const orgKey = new Uint8Array(orgKeyBytes);
  const publicKeyBytes = base64urlToBytes(targetPublicKey);
  if (orgKey.length !== 32 || publicKeyBytes.length !== 65) {
    throw new Error("P-256 组织密钥封装参数无效");
  }
  const target = await crypto.subtle.importKey(
    "raw",
    publicKeyBytes,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: target },
    ephemeral.privateKey,
    256,
  ));
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveKey"],
  );
  sharedSecret.fill(0);
  sharedSecret.fill(0);
  const key = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(
        `v9:org-envelope-salt:1:${organizationId}:${deviceId}:${Number(keyVersion)}`,
      ),
      info: encoder.encode("v9:org-envelope-kek:1"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: encoder.encode(
        `v9:org-envelope:1:${organizationId}:${deviceId}:${Number(keyVersion)}:p256`,
      ),
      tagLength: 128,
    },
    key,
    orgKey,
  ));
  const ephemeralPublicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", ephemeral.publicKey),
  );
  return {
    ephemeralPublicKey: bytesToBase64url(ephemeralPublicKey),
    nonce: bytesToBase64url(nonce),
    ciphertext: bytesToBase64url(ciphertext),
  };
}
