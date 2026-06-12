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
import {
  deriveWrappingKey,
  wrapDataKey,
  computeClaimProof,
  computeFingerprint,
  REQUEST_WRAP_INFO,
} from "./request.js";

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
  return crypto.subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) as unknown as BufferSource },
    key,
    encoded,
  );
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

  // Request-flow vector (SPEC §9): fixed ECDH keypairs generated once and
  // embedded so regeneration is deterministic. Any implementation must derive
  // the same wrapping key and produce/verify the same wrapped data key.
  const requestVectors = [];
  {
    const requester = {
      publicKeyB64:
        "BHvBnbanQSX69Hzwg1WNsTYU0RROn4eW61iZhRLqJqWnyqM0MGrn2_5VTcUIm7E8YrUQ03eHg8MMWkESj0-Nprw",
      privateKeyB64:
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaOBOADootP2bogHVZMGCe3dqXueHGsQL23r4qkmhQ2mhRANCAAR7wZ22p0El-vR88INVjbE2FNEUTp-HlutYmYUS6ialp8qjNDBq59v-VU3FCJuxPGK1ENN3h4PDDFpBEo9Pjaa8",
    };
    const responder = {
      publicKeyB64:
        "BMtbdkO6kE6SGwLktnWTQpvZXsYE4MhCJ4Yp5036VnPGMjzx_wceBfVh9QPoS6lYTYZMXzampIpq9UQxk2Ch-Qs",
      privateKeyB64:
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg_N-NHZL6XYmGVQPeoIghcP-wv-rEtAZLZtHtwboQvU6hRANCAATLW3ZDupBOkhsC5LZ1k0Kb2V7GBODIQieGKedN-lZzxjI88f8HHgX1YfUD6EupWE2GTF82pqSKavVEMZNgofkL",
    };
    const hkdfSalt = new Uint8Array(16);
    hkdfSalt[0] = 0x20;
    const wrapIv = new Uint8Array(12);
    wrapIv[0] = 0x21;
    const dataKeyRaw = new Uint8Array(32);
    dataKeyRaw[0] = 0x22;
    const dataKey = await importKeyExtractable(bytesToBase64Url(dataKeyRaw));
    const iv = new Uint8Array(12);
    iv[0] = 0x23;
    const plaintext = "request-flow secret";

    const wrappingKey = await deriveWrappingKey(
      responder.privateKeyB64,
      requester.publicKeyB64,
      hkdfSalt,
    );
    const wrappedKey = await wrapDataKey(dataKeyRaw, wrappingKey, wrapIv);
    const ct = await encryptWithFixedIV(plaintext, dataKey, iv);

    requestVectors.push({
      name: "request-flow-basic",
      description:
        "ECDH P-256 + HKDF-SHA256 wrap: responder wraps a fixed data key to the requester public key; requester side must unwrap to the same key and decrypt",
      requester_public_key_b64: requester.publicKeyB64,
      requester_private_key_pkcs8_b64: requester.privateKeyB64,
      responder_public_key_b64: responder.publicKeyB64,
      responder_private_key_pkcs8_b64: responder.privateKeyB64,
      hkdf_salt_b64: bytesToBase64Url(hkdfSalt),
      hkdf_info: REQUEST_WRAP_INFO,
      wrap_iv_b64: bytesToBase64Url(wrapIv),
      data_key_b64: bytesToBase64Url(dataKeyRaw),
      wrapped_key_b64: wrappedKey,
      iv_b64: bytesToBase64Url(iv),
      plaintext,
      ciphertext_b64: bytesToBase64Url(new Uint8Array(ct)),
      claim_proof: await computeClaimProof(requester.privateKeyB64),
      requester_fingerprint: await computeFingerprint(requester.publicKeyB64),
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
    request_vectors: requestVectors,
  };

  console.log(JSON.stringify(output, null, 2));
}

main().catch(console.error);
