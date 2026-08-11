const EMAIL_PATTERN = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function assertBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new TypeError(`invalid_${label}`);
  }
}

export function encodeBase64Url(value) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("invalid_bytes");
  }
  let binary = "";
  for (let offset = 0; offset < value.byteLength; offset += 0x8000) {
    binary += String.fromCharCode(...value.subarray(offset, offset + 0x8000));
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function decodeBase64Url(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 8192 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    throw new TypeError("invalid_base64url");
  }
  const remainder = value.length % 4;
  if (remainder === 1) {
    throw new TypeError("invalid_base64url");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") +
    "=".repeat((4 - remainder) % 4);
  let decoded;
  try {
    decoded = atob(padded);
  } catch {
    throw new TypeError("invalid_base64url");
  }
  const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) {
    throw new TypeError("non_canonical_base64url");
  }
  return bytes;
}

export function decodeSecretKey(value) {
  const key = decodeBase64Url(value);
  assertBytes(key, KEY_BYTES, "secret_key");
  return key;
}

export function normalizeEmail(value) {
  if (typeof value !== "string") {
    throw new TypeError("invalid_email");
  }
  const normalized = value.trim().toLowerCase();
  const separator = normalized.lastIndexOf("@");
  if (
    normalized.length > 254 ||
    separator < 1 ||
    separator > 64 ||
    !EMAIL_PATTERN.test(normalized)
  ) {
    throw new TypeError("invalid_email");
  }
  return normalized;
}

export async function hmacHex(keyBytes, context, value) {
  assertBytes(keyBytes, KEY_BYTES, "hmac_key");
  if (
    typeof context !== "string" ||
    !/^[a-z][a-z0-9_-]{0,31}$/u.test(context) ||
    typeof value !== "string" ||
    value.length > 2048
  ) {
    throw new TypeError("invalid_hmac_input");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`${context}\0${value}`),
  );
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function emailAad(keyVersion) {
  if (!Number.isInteger(keyVersion) || keyVersion < 1 || keyVersion > 100) {
    throw new TypeError("invalid_key_version");
  }
  return encoder.encode(`access-application-email:v${keyVersion}`);
}

export async function encryptEmail(email, keyBytes, keyVersion) {
  const normalized = normalizeEmail(email);
  assertBytes(keyBytes, KEY_BYTES, "encryption_key");
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: emailAad(keyVersion) },
    key,
    encoder.encode(normalized),
  );
  return {
    ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
    nonce: encodeBase64Url(nonce),
    keyVersion,
  };
}

export async function decryptEmail(record, keyBytes) {
  if (!record || typeof record !== "object") {
    throw new TypeError("invalid_encrypted_email");
  }
  assertBytes(keyBytes, KEY_BYTES, "encryption_key");
  const nonce = decodeBase64Url(record.nonce);
  assertBytes(nonce, NONCE_BYTES, "email_nonce");
  const ciphertext = decodeBase64Url(record.ciphertext);
  if (ciphertext.byteLength < 17 || ciphertext.byteLength > 512) {
    throw new TypeError("invalid_email_ciphertext");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: emailAad(record.keyVersion),
      },
      key,
      ciphertext,
    );
  } catch {
    throw new TypeError("email_decryption_failed");
  }
  return normalizeEmail(decoder.decode(plaintext));
}

export function maskEmail(email) {
  const normalized = normalizeEmail(email);
  const separator = normalized.lastIndexOf("@");
  return `${normalized[0]}***${normalized.slice(separator)}`;
}
