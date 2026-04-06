/**
 * Generate deterministic test vectors for cross-implementation verification.
 * Run with: npx tsx src/generate-test-vectors.ts
 *
 * These vectors allow any implementation (Go, Python, Rust, etc.) to verify
 * it produces identical ciphertext given the same key, IV, and plaintext.
 */
import {
  importKeyExtractable,
  encrypt,
  decrypt,
  deriveKeyWithPassword,
  computeKeyHash,
  serializePayload,
  deserializePayload,
} from "./crypto.js";
import { bytesToBase64Url, base64UrlToBytes } from "./encoding.js";

interface TestVector {
  name: string;
  description: string;
  key_b64: string;
  iv_b64: string;
  plaintext: string;
  ciphertext_b64: string;
  key_hash: string;
}

interface PasswordTestVector {
  name: string;
  description: string;
  url_key_b64: string;
  password: string;
  derived_key_b64: string;
  derived_key_hash: string;
  iv_b64: string;
  plaintext: string;
  ciphertext_b64: string;
}

async function encryptWithFixedIV(
  plaintext: string,
  key: CryptoKey,
  iv: Uint8Array,
): Promise<ArrayBuffer> {
  const encoded = new TextEncoder().encode(plaintext);
  return crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
}

async function main() {
  const vectors: TestVector[] = [];
  const passwordVectors: PasswordTestVector[] = [];

  // Vector 1: Simple ASCII
  {
    const keyBytes = new Uint8Array(32);
    keyBytes[0] = 0x01;
    const key = await importKeyExtractable(bytesToBase64Url(keyBytes));
    const iv = new Uint8Array(12);
    iv[0] = 0x01;
    const plaintext = "Hello, World!";
    const ct = await encryptWithFixedIV(plaintext, key, iv);
    vectors.push({
      name: "simple-ascii",
      description: "Basic ASCII text with deterministic key and IV",
      key_b64: bytesToBase64Url(keyBytes),
      iv_b64: bytesToBase64Url(iv),
      plaintext,
      ciphertext_b64: bytesToBase64Url(new Uint8Array(ct)),
      key_hash: await computeKeyHash(key),
    });
  }

  // Vector 2: Empty string
  {
    const keyBytes = new Uint8Array(32);
    keyBytes[0] = 0x02;
    const key = await importKeyExtractable(bytesToBase64Url(keyBytes));
    const iv = new Uint8Array(12);
    iv[0] = 0x02;
    const plaintext = "";
    const ct = await encryptWithFixedIV(plaintext, key, iv);
    vectors.push({
      name: "empty-string",
      description: "Empty plaintext produces only the GCM auth tag",
      key_b64: bytesToBase64Url(keyBytes),
      iv_b64: bytesToBase64Url(iv),
      plaintext,
      ciphertext_b64: bytesToBase64Url(new Uint8Array(ct)),
      key_hash: await computeKeyHash(key),
    });
  }

  // Vector 3: Unicode with emoji
  {
    const keyBytes = new Uint8Array(32);
    keyBytes[0] = 0x03;
    const key = await importKeyExtractable(bytesToBase64Url(keyBytes));
    const iv = new Uint8Array(12);
    iv[0] = 0x03;
    const plaintext = "Secret \u{1F512}\u{1F30D}";
    const ct = await encryptWithFixedIV(plaintext, key, iv);
    vectors.push({
      name: "unicode-emoji",
      description: "Unicode text with emoji (multi-byte UTF-8)",
      key_b64: bytesToBase64Url(keyBytes),
      iv_b64: bytesToBase64Url(iv),
      plaintext,
      ciphertext_b64: bytesToBase64Url(new Uint8Array(ct)),
      key_hash: await computeKeyHash(key),
    });
  }

  // Vector 4: Multi-line .env content
  {
    const keyBytes = new Uint8Array(32);
    keyBytes[0] = 0x04;
    const key = await importKeyExtractable(bytesToBase64Url(keyBytes));
    const iv = new Uint8Array(12);
    iv[0] = 0x04;
    const plaintext = "DB_HOST=localhost\nDB_PORT=5432\nDB_PASS=s3cret!";
    const ct = await encryptWithFixedIV(plaintext, key, iv);
    vectors.push({
      name: "multiline-env",
      description: "Multi-line .env file content (common use case)",
      key_b64: bytesToBase64Url(keyBytes),
      iv_b64: bytesToBase64Url(iv),
      plaintext,
      ciphertext_b64: bytesToBase64Url(new Uint8Array(ct)),
      key_hash: await computeKeyHash(key),
    });
  }

  // Vector 5: Max typical size (7500 chars)
  {
    const keyBytes = new Uint8Array(32);
    keyBytes[0] = 0x05;
    const key = await importKeyExtractable(bytesToBase64Url(keyBytes));
    const iv = new Uint8Array(12);
    iv[0] = 0x05;
    const plaintext = "X".repeat(7500);
    const ct = await encryptWithFixedIV(plaintext, key, iv);
    vectors.push({
      name: "max-size",
      description: "Maximum typical secret size (7500 chars)",
      key_b64: bytesToBase64Url(keyBytes),
      iv_b64: bytesToBase64Url(iv),
      plaintext,
      ciphertext_b64: bytesToBase64Url(new Uint8Array(ct)),
      key_hash: await computeKeyHash(key),
    });
  }

  // Password Vector 1: Simple password derivation
  {
    const urlKeyBytes = new Uint8Array(32);
    urlKeyBytes[0] = 0x10;
    const password = "correcthorsebatterystaple";
    const derived = await deriveKeyWithPassword(urlKeyBytes, password);
    const derivedRaw = new Uint8Array(await crypto.subtle.exportKey("raw", derived));
    const iv = new Uint8Array(12);
    iv[0] = 0x10;
    const plaintext = "password-protected secret";
    const ct = await encryptWithFixedIV(plaintext, derived, iv);
    passwordVectors.push({
      name: "simple-password",
      description: "PBKDF2 derivation with common password",
      url_key_b64: bytesToBase64Url(urlKeyBytes),
      password,
      derived_key_b64: bytesToBase64Url(derivedRaw),
      derived_key_hash: await computeKeyHash(derived),
      iv_b64: bytesToBase64Url(iv),
      plaintext,
      ciphertext_b64: bytesToBase64Url(new Uint8Array(ct)),
    });
  }

  // Password Vector 2: Unicode password
  {
    const urlKeyBytes = new Uint8Array(32);
    urlKeyBytes[0] = 0x11;
    const password = "\u043F\u0430\u0440\u043E\u043B\u044C123";
    const derived = await deriveKeyWithPassword(urlKeyBytes, password);
    const derivedRaw = new Uint8Array(await crypto.subtle.exportKey("raw", derived));
    const iv = new Uint8Array(12);
    iv[0] = 0x11;
    const plaintext = "unicode password test";
    const ct = await encryptWithFixedIV(plaintext, derived, iv);
    passwordVectors.push({
      name: "unicode-password",
      description: "PBKDF2 derivation with Cyrillic password (\u043F\u0430\u0440\u043E\u043B\u044C123)",
      url_key_b64: bytesToBase64Url(urlKeyBytes),
      password,
      derived_key_b64: bytesToBase64Url(derivedRaw),
      derived_key_hash: await computeKeyHash(derived),
      iv_b64: bytesToBase64Url(iv),
      plaintext,
      ciphertext_b64: bytesToBase64Url(new Uint8Array(ct)),
    });
  }

  const output = {
    version: 1,
    algorithm: "AES-256-GCM",
    key_derivation: "PBKDF2-SHA256",
    pbkdf2_iterations: 600_000,
    iv_bytes: 12,
    key_bytes: 32,
    key_hash_algorithm: "SHA-256 -> base64url -> first 22 chars (128 bits)",
    encoding: "base64url (RFC 4648 §5, no padding)",
    vectors,
    password_vectors: passwordVectors,
  };

  console.log(JSON.stringify(output, null, 2));
}

main().catch(console.error);
