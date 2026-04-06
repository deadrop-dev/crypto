import { bytesToBase64Url, base64UrlToBytes } from "./encoding.js";

export interface EncryptedPayload {
  ciphertext: ArrayBuffer;
  iv: Uint8Array;
}

/** PBKDF2 iteration count for password-based key derivation */
export const PBKDF2_ITERATIONS = 600_000;

/** AES-GCM IV length in bytes */
export const IV_LENGTH = 12;

/** AES key length in bits */
export const KEY_LENGTH = 256;

/** Default key hash length in base64url characters (22 chars = 128 bits) */
export const KEY_HASH_LENGTH = 22;

/** Generate a new AES-256-GCM key */
export async function generateKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: KEY_LENGTH },
    true,
    ["encrypt", "decrypt"],
  );
}

/** Export key as base64url string */
export async function exportKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bytesToBase64Url(new Uint8Array(raw));
}

/** Import key from base64url string */
export async function importKey(keyB64: string): Promise<CryptoKey> {
  const raw = base64UrlToBytes(keyB64);
  return crypto.subtle.importKey(
    "raw",
    raw.buffer as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
}

/**
 * Import key from base64url as extractable with encrypt + decrypt permissions.
 * Use only when you need to re-export the key (e.g. for hashing or re-encryption).
 * Prefer `importKey()` for decrypt-only operations.
 */
export async function importKeyExtractable(keyB64: string): Promise<CryptoKey> {
  const raw = base64UrlToBytes(keyB64);
  return crypto.subtle.importKey(
    "raw",
    raw.buffer as ArrayBuffer,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"],
  );
}

/** Encrypt plaintext with AES-256-GCM */
export async function encrypt(
  plaintext: string,
  key: CryptoKey,
): Promise<EncryptedPayload> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded,
  );
  return { ciphertext, iv };
}

/** Decrypt ciphertext with AES-256-GCM */
export async function decrypt(
  payload: EncryptedPayload,
  key: CryptoKey,
): Promise<string> {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(payload.iv) as unknown as BufferSource },
    key,
    payload.ciphertext,
  );
  return new TextDecoder().decode(decrypted);
}

/**
 * Compute base64url(SHA-256(rawKey)) truncated to KEY_HASH_LENGTH chars.
 * The key must be extractable — keys from `importKey()` will throw.
 * Use `computeKeyHashFromB64()` if you only have the base64url key string.
 */
export async function computeKeyHash(key: CryptoKey, length: number = KEY_HASH_LENGTH): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  const hash = await crypto.subtle.digest("SHA-256", raw);
  return bytesToBase64Url(new Uint8Array(hash)).slice(0, length);
}

/** Compute key hash from a base64url-encoded key string. No extractability requirement. */
export async function computeKeyHashFromB64(keyB64: string, length: number = KEY_HASH_LENGTH): Promise<string> {
  const raw = base64UrlToBytes(keyB64);
  const hash = await crypto.subtle.digest("SHA-256", raw.buffer as ArrayBuffer);
  return bytesToBase64Url(new Uint8Array(hash)).slice(0, length);
}

/** Derive AES-256-GCM key from password + URL key via PBKDF2 */
export async function deriveKeyWithPassword(
  urlKeyRaw: Uint8Array,
  password: string,
): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array(urlKeyRaw) as unknown as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: KEY_LENGTH },
    true,
    ["encrypt", "decrypt"],
  );
}

/**
 * Serialize an EncryptedPayload to a portable format.
 * Returns base64url-encoded ciphertext and IV.
 */
export function serializePayload(payload: EncryptedPayload): {
  ciphertext: string;
  iv: string;
} {
  return {
    ciphertext: bytesToBase64Url(new Uint8Array(payload.ciphertext)),
    iv: bytesToBase64Url(payload.iv),
  };
}

/**
 * Deserialize a portable payload back to EncryptedPayload.
 */
export function deserializePayload(data: {
  ciphertext: string;
  iv: string;
}): EncryptedPayload {
  return {
    ciphertext: base64UrlToBytes(data.ciphertext).buffer as ArrayBuffer,
    iv: base64UrlToBytes(data.iv),
  };
}
