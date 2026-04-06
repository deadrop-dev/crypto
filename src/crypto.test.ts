import { describe, it, expect } from "vitest";
import {
  generateKey,
  exportKey,
  importKey,
  importKeyExtractable,
  encrypt,
  decrypt,
  computeKeyHash,
  computeKeyHashFromB64,
  deriveKeyWithPassword,
  serializePayload,
  deserializePayload,
  PBKDF2_ITERATIONS,
  IV_LENGTH,
  KEY_LENGTH,
} from "./crypto.js";
import { bytesToBase64Url, base64UrlToBytes } from "./encoding.js";

describe("constants", () => {
  it("has correct values", () => {
    expect(PBKDF2_ITERATIONS).toBe(600_000);
    expect(IV_LENGTH).toBe(12);
    expect(KEY_LENGTH).toBe(256);
  });
});

describe("generateKey", () => {
  it("generates an AES-GCM CryptoKey", async () => {
    const key = await generateKey();
    expect(key.type).toBe("secret");
    expect(key.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    expect(key.extractable).toBe(true);
    expect(key.usages).toContain("encrypt");
    expect(key.usages).toContain("decrypt");
  });

  it("generates unique keys each time", async () => {
    const key1 = await generateKey();
    const key2 = await generateKey();
    const raw1 = await crypto.subtle.exportKey("raw", key1);
    const raw2 = await crypto.subtle.exportKey("raw", key2);
    expect(new Uint8Array(raw1)).not.toEqual(new Uint8Array(raw2));
  });
});

describe("exportKey / importKey", () => {
  it("exports key as 43-char base64url string", async () => {
    const key = await generateKey();
    const exported = await exportKey(key);
    expect(exported).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(exported.length).toBe(43);
  });

  it("round-trips key export and import", async () => {
    const originalKey = await generateKey();
    const exported = await exportKey(originalKey);
    const importedKey = await importKey(exported);
    const plaintext = "round-trip test";
    const payload = await encrypt(plaintext, originalKey);
    const decrypted = await decrypt(payload, importedKey);
    expect(decrypted).toBe(plaintext);
  });
});

describe("importKeyExtractable", () => {
  it("imports with encrypt + decrypt permissions", async () => {
    const originalKey = await generateKey();
    const exported = await exportKey(originalKey);
    const fullKey = await importKeyExtractable(exported);
    expect(fullKey.extractable).toBe(true);
    expect(fullKey.usages).toContain("encrypt");
    expect(fullKey.usages).toContain("decrypt");

    const plaintext = "full key test";
    const payload = await encrypt(plaintext, fullKey);
    const decrypted = await decrypt(payload, fullKey);
    expect(decrypted).toBe(plaintext);
  });
});

describe("encrypt / decrypt", () => {
  it("encrypts and decrypts a simple string", async () => {
    const key = await generateKey();
    const plaintext = "Hello, World!";
    const payload = await encrypt(plaintext, key);
    expect(await decrypt(payload, key)).toBe(plaintext);
  });

  it("produces a 12-byte IV", async () => {
    const key = await generateKey();
    const payload = await encrypt("test", key);
    expect(payload.iv.length).toBe(12);
  });

  it("produces different ciphertext for same plaintext (random IV)", async () => {
    const key = await generateKey();
    const p1 = await encrypt("same message", key);
    const p2 = await encrypt("same message", key);
    expect(Array.from(p1.iv)).not.toEqual(Array.from(p2.iv));
  });

  it("handles unicode text", async () => {
    const key = await generateKey();
    const plaintext = "Hello \u{1F512} Secret \u{1F30D}";
    expect(await decrypt(await encrypt(plaintext, key), key)).toBe(plaintext);
  });

  it("handles empty string", async () => {
    const key = await generateKey();
    expect(await decrypt(await encrypt("", key), key)).toBe("");
  });

  it("handles large text", async () => {
    const key = await generateKey();
    const plaintext = "A".repeat(10000);
    expect(await decrypt(await encrypt(plaintext, key), key)).toBe(plaintext);
  });

  it("fails to decrypt with wrong key", async () => {
    const key1 = await generateKey();
    const key2 = await generateKey();
    const payload = await encrypt("secret", key1);
    await expect(decrypt(payload, key2)).rejects.toThrow();
  });
});

describe("serializePayload / deserializePayload", () => {
  it("round-trips through serialization", async () => {
    const key = await generateKey();
    const plaintext = "serialize test";
    const payload = await encrypt(plaintext, key);
    const serialized = serializePayload(payload);

    expect(typeof serialized.ciphertext).toBe("string");
    expect(typeof serialized.iv).toBe("string");
    expect(serialized.ciphertext).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(serialized.iv).toMatch(/^[A-Za-z0-9_-]+$/);

    const deserialized = deserializePayload(serialized);
    expect(await decrypt(deserialized, key)).toBe(plaintext);
  });
});

describe("computeKeyHash", () => {
  it("produces an 8-char base64url hash", async () => {
    const key = await generateKey();
    const hash = await computeKeyHash(key);
    expect(hash.length).toBe(22);
    expect(hash).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("same key produces same hash", async () => {
    const key = await generateKey();
    expect(await computeKeyHash(key)).toBe(await computeKeyHash(key));
  });

  it("different keys produce different hashes", async () => {
    const key1 = await generateKey();
    const key2 = await generateKey();
    expect(await computeKeyHash(key1)).not.toBe(await computeKeyHash(key2));
  });
});

describe("computeKeyHashFromB64", () => {
  it("matches computeKeyHash for same key", async () => {
    const key = await generateKey();
    const keyB64 = await exportKey(key);
    expect(await computeKeyHashFromB64(keyB64)).toBe(await computeKeyHash(key));
  });
});

describe("deriveKeyWithPassword", () => {
  it("derives an AES-GCM key", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const derived = await deriveKeyWithPassword(raw, "testpassword");
    expect(derived.type).toBe("secret");
    expect(derived.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    expect(derived.extractable).toBe(true);
  });

  it("same inputs produce same derived key", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const k1 = await deriveKeyWithPassword(raw, "password123");
    const k2 = await deriveKeyWithPassword(raw, "password123");
    const r1 = new Uint8Array(await crypto.subtle.exportKey("raw", k1));
    const r2 = new Uint8Array(await crypto.subtle.exportKey("raw", k2));
    expect(Array.from(r1)).toEqual(Array.from(r2));
  });

  it("different passwords produce different keys", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const k1 = await deriveKeyWithPassword(raw, "password1");
    const k2 = await deriveKeyWithPassword(raw, "password2");
    const r1 = new Uint8Array(await crypto.subtle.exportKey("raw", k1));
    const r2 = new Uint8Array(await crypto.subtle.exportKey("raw", k2));
    expect(Array.from(r1)).not.toEqual(Array.from(r2));
  });

  it("different URL keys produce different derived keys", async () => {
    const raw1 = crypto.getRandomValues(new Uint8Array(32));
    const raw2 = crypto.getRandomValues(new Uint8Array(32));
    const k1 = await deriveKeyWithPassword(raw1, "same");
    const k2 = await deriveKeyWithPassword(raw2, "same");
    const r1 = new Uint8Array(await crypto.subtle.exportKey("raw", k1));
    const r2 = new Uint8Array(await crypto.subtle.exportKey("raw", k2));
    expect(Array.from(r1)).not.toEqual(Array.from(r2));
  });

  it("encrypts and decrypts with derived key", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const derived = await deriveKeyWithPassword(raw, "secretpass");
    const plaintext = "password-protected message";
    expect(await decrypt(await encrypt(plaintext, derived), derived)).toBe(plaintext);
  });

  it("cannot decrypt with wrong password", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const correct = await deriveKeyWithPassword(raw, "correct");
    const wrong = await deriveKeyWithPassword(raw, "wrong");
    const payload = await encrypt("secret", correct);
    await expect(decrypt(payload, wrong)).rejects.toThrow();
  });
});

describe("end-to-end: create → view", () => {
  it("without password", async () => {
    const key = await generateKey();
    const keyB64 = await exportKey(key);
    const plaintext = "no password secret";
    const payload = await encrypt(plaintext, key);
    const keyHash = await computeKeyHash(key);
    const serialized = serializePayload(payload);

    // View side
    const viewKeyHash = await computeKeyHashFromB64(keyB64);
    expect(viewKeyHash).toBe(keyHash);

    const viewKey = await importKey(keyB64);
    const deserialized = deserializePayload(serialized);
    expect(await decrypt(deserialized, viewKey)).toBe(plaintext);
  });

  it("with password", async () => {
    const password = "strongpassword";
    const key = await generateKey();
    const keyB64 = await exportKey(key);
    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    const derivedKey = await deriveKeyWithPassword(rawKey, password);

    const plaintext = "password-protected secret";
    const payload = await encrypt(plaintext, derivedKey);
    const keyHash = await computeKeyHash(derivedKey);
    const serialized = serializePayload(payload);

    // View side
    const urlKeyRaw = base64UrlToBytes(keyB64);
    const viewDerived = await deriveKeyWithPassword(urlKeyRaw, password);
    expect(await computeKeyHash(viewDerived)).toBe(keyHash);

    const deserialized = deserializePayload(serialized);
    expect(await decrypt(deserialized, viewDerived)).toBe(plaintext);
  });

  it("wrong password produces wrong keyHash", async () => {
    const key = await generateKey();
    const keyB64 = await exportKey(key);
    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    const derivedKey = await deriveKeyWithPassword(rawKey, "correct");
    const keyHash = await computeKeyHash(derivedKey);

    const urlKeyRaw = base64UrlToBytes(keyB64);
    const wrongDerived = await deriveKeyWithPassword(urlKeyRaw, "wrong");
    expect(await computeKeyHash(wrongDerived)).not.toBe(keyHash);
  });
});
