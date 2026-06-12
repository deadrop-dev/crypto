import { describe, it, expect } from "vitest";
import {
  generateRequestKeyPair,
  computeClaimProof,
  computeFingerprint,
  deriveWrappingKey,
  wrapDataKey,
  unwrapDataKey,
  encryptForRequest,
  decryptResponse,
  REQUEST_WRAP_INFO,
  HKDF_SALT_LENGTH,
  FINGERPRINT_LENGTH,
} from "./request.js";
import { generateKey, exportKey } from "./crypto.js";
import { base64UrlToBytes, bytesToBase64Url } from "./encoding.js";

describe("generateRequestKeyPair", () => {
  it("produces a raw uncompressed P-256 public key (65 bytes, 0x04 prefix)", async () => {
    const { publicKeyB64 } = await generateRequestKeyPair();
    const raw = base64UrlToBytes(publicKeyB64);
    expect(raw.length).toBe(65);
    expect(raw[0]).toBe(0x04);
  });

  it("produces a PKCS8 private key importable for derivation", async () => {
    const { privateKeyB64, publicKeyB64 } = await generateRequestKeyPair();
    expect(privateKeyB64.length).toBeGreaterThan(100);
    // round-trip proof: deriving against own public key must not throw
    const salt = new Uint8Array(HKDF_SALT_LENGTH);
    await deriveWrappingKey(privateKeyB64, publicKeyB64, salt);
  });

  it("generates distinct keypairs", async () => {
    const a = await generateRequestKeyPair();
    const b = await generateRequestKeyPair();
    expect(a.publicKeyB64).not.toBe(b.publicKeyB64);
    expect(a.privateKeyB64).not.toBe(b.privateKeyB64);
  });
});

describe("computeClaimProof", () => {
  it("is deterministic and 22 chars (128 bits)", async () => {
    const { privateKeyB64 } = await generateRequestKeyPair();
    const p1 = await computeClaimProof(privateKeyB64);
    const p2 = await computeClaimProof(privateKeyB64);
    expect(p1).toBe(p2);
    expect(p1).toHaveLength(22);
    expect(p1).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("differs for different private keys", async () => {
    const a = await generateRequestKeyPair();
    const b = await generateRequestKeyPair();
    expect(await computeClaimProof(a.privateKeyB64)).not.toBe(
      await computeClaimProof(b.privateKeyB64),
    );
  });
});

describe("computeFingerprint", () => {
  it("is 8 chars, deterministic, and differs across keys", async () => {
    const a = await generateRequestKeyPair();
    const b = await generateRequestKeyPair();
    const fa = await computeFingerprint(a.publicKeyB64);
    expect(fa).toHaveLength(FINGERPRINT_LENGTH);
    expect(fa).toBe(await computeFingerprint(a.publicKeyB64));
    expect(fa).not.toBe(await computeFingerprint(b.publicKeyB64));
  });
});

describe("ECDH wrap/unwrap symmetry", () => {
  it("requester and responder derive the same wrapping key", async () => {
    const requester = await generateRequestKeyPair();
    const responder = await generateRequestKeyPair();
    const salt = crypto.getRandomValues(new Uint8Array(HKDF_SALT_LENGTH));

    const dataKey = await generateKey();
    const rawDataKey = base64UrlToBytes(await exportKey(dataKey));

    const responderSide = await deriveWrappingKey(
      responder.privateKeyB64,
      requester.publicKeyB64,
      salt,
    );
    const wrapIv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = await wrapDataKey(rawDataKey, responderSide, wrapIv);
    // 32-byte key + 16-byte GCM tag
    expect(base64UrlToBytes(wrapped).length).toBe(48);

    const requesterSide = await deriveWrappingKey(
      requester.privateKeyB64,
      responder.publicKeyB64,
      salt,
    );
    const unwrapped = await unwrapDataKey(wrapped, requesterSide, wrapIv);
    expect(bytesToBase64Url(unwrapped)).toBe(bytesToBase64Url(rawDataKey));
  });

  it("info string is pinned by the spec", () => {
    expect(REQUEST_WRAP_INFO).toBe("deadrop/request-wrap/v1");
  });
});

describe("encryptForRequest / decryptResponse round trip", () => {
  it("responder encrypts, requester decrypts", async () => {
    const requester = await generateRequestKeyPair();
    const secret = "db_password=correct horse battery staple — æøå 🔑";

    const response = await encryptForRequest(secret, requester.publicKeyB64);
    expect(response.encrypted.length).toBeGreaterThan(0);
    expect(base64UrlToBytes(response.iv).length).toBe(12);
    expect(base64UrlToBytes(response.wrapIv).length).toBe(12);
    expect(base64UrlToBytes(response.hkdfSalt).length).toBe(HKDF_SALT_LENGTH);
    expect(base64UrlToBytes(response.responderPublicKey).length).toBe(65);

    const decrypted = await decryptResponse(response, requester.privateKeyB64);
    expect(decrypted).toBe(secret);
  });

  it("a different private key cannot decrypt", async () => {
    const requester = await generateRequestKeyPair();
    const intruder = await generateRequestKeyPair();
    const response = await encryptForRequest("top secret", requester.publicKeyB64);
    await expect(
      decryptResponse(response, intruder.privateKeyB64),
    ).rejects.toThrow();
  });

  it("tampered wrappedKey fails authentication", async () => {
    const requester = await generateRequestKeyPair();
    const response = await encryptForRequest("top secret", requester.publicKeyB64);
    const bytes = base64UrlToBytes(response.wrappedKey);
    bytes[0] ^= 0xff;
    const tampered = { ...response, wrappedKey: bytesToBase64Url(bytes) };
    await expect(
      decryptResponse(tampered, requester.privateKeyB64),
    ).rejects.toThrow();
  });

  it("tampered ciphertext fails authentication", async () => {
    const requester = await generateRequestKeyPair();
    const response = await encryptForRequest("top secret", requester.publicKeyB64);
    const bytes = base64UrlToBytes(response.encrypted);
    bytes[bytes.length - 1] ^= 0x01;
    const tampered = { ...response, encrypted: bytesToBase64Url(bytes) };
    await expect(
      decryptResponse(tampered, requester.privateKeyB64),
    ).rejects.toThrow();
  });

  it("each response uses fresh randomness", async () => {
    const requester = await generateRequestKeyPair();
    const a = await encryptForRequest("same secret", requester.publicKeyB64);
    const b = await encryptForRequest("same secret", requester.publicKeyB64);
    expect(a.encrypted).not.toBe(b.encrypted);
    expect(a.wrappedKey).not.toBe(b.wrappedKey);
    expect(a.responderPublicKey).not.toBe(b.responderPublicKey);
    expect(a.hkdfSalt).not.toBe(b.hkdfSalt);
  });
});
