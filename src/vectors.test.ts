import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve } from "path";
import {
  generateKey,
  importKey,
  importKeyExtractable,
  encrypt,
  decrypt,
  deriveKeyWithPassword,
  computeKeyHash,
} from "./crypto.js";
import { bytesToBase64Url, base64UrlToBytes } from "./encoding.js";

const vectorsPath = resolve(__dirname, "../test-vectors.json");
const data = JSON.parse(readFileSync(vectorsPath, "utf-8"));

describe("test vectors: basic encryption", () => {
  for (const v of data.vectors) {
    it(`decrypts vector: ${v.name}`, async () => {
      const key = await importKeyExtractable(v.key_b64);
      const iv = base64UrlToBytes(v.iv_b64);
      const ciphertext = base64UrlToBytes(v.ciphertext_b64).buffer as ArrayBuffer;
      const decrypted = await decrypt({ ciphertext, iv }, key);
      expect(decrypted).toBe(v.plaintext);
    });

    it(`verifies key hash: ${v.name}`, async () => {
      const key = await importKeyExtractable(v.key_b64);
      const hash = await computeKeyHash(key);
      expect(hash).toBe(v.key_hash);
    });
  }
});

describe("test vectors: password derivation", () => {
  for (const v of data.password_vectors) {
    it(`derives correct key: ${v.name}`, async () => {
      const urlKeyRaw = base64UrlToBytes(v.url_key_b64);
      const derived = await deriveKeyWithPassword(urlKeyRaw, v.password);
      const derivedRaw = new Uint8Array(await crypto.subtle.exportKey("raw", derived));
      const expectedRaw = base64UrlToBytes(v.derived_key_b64);
      expect(Array.from(derivedRaw)).toEqual(Array.from(expectedRaw));
    });

    it(`verifies derived key hash: ${v.name}`, async () => {
      const urlKeyRaw = base64UrlToBytes(v.url_key_b64);
      const derived = await deriveKeyWithPassword(urlKeyRaw, v.password);
      expect(await computeKeyHash(derived)).toBe(v.derived_key_hash);
    });

    it(`decrypts with derived key: ${v.name}`, async () => {
      const urlKeyRaw = base64UrlToBytes(v.url_key_b64);
      const derived = await deriveKeyWithPassword(urlKeyRaw, v.password);
      const iv = base64UrlToBytes(v.iv_b64);
      const ciphertext = base64UrlToBytes(v.ciphertext_b64).buffer as ArrayBuffer;
      const decrypted = await decrypt({ ciphertext, iv }, derived);
      expect(decrypted).toBe(v.plaintext);
    });
  }
});

describe("negative vectors: wrong key", () => {
  for (const v of data.vectors) {
    it(`wrong key fails: ${v.name}`, async () => {
      const wrongKey = await generateKey();
      const iv = base64UrlToBytes(v.iv_b64);
      const ciphertext = base64UrlToBytes(v.ciphertext_b64).buffer as ArrayBuffer;
      await expect(decrypt({ ciphertext, iv }, wrongKey)).rejects.toThrow();
    });
  }
});

describe("negative vectors: wrong IV", () => {
  it("modified IV fails GCM authentication", async () => {
    const v = data.vectors[0];
    const key = await importKeyExtractable(v.key_b64);
    const correctIv = base64UrlToBytes(v.iv_b64);
    const wrongIv = new Uint8Array(correctIv);
    wrongIv[0] ^= 0xff;
    const ciphertext = base64UrlToBytes(v.ciphertext_b64).buffer as ArrayBuffer;
    await expect(decrypt({ ciphertext, iv: wrongIv }, key)).rejects.toThrow();
  });
});

describe("negative vectors: modified ciphertext/tag", () => {
  it("flipped ciphertext bit fails GCM authentication", async () => {
    const v = data.vectors[0];
    const key = await importKeyExtractable(v.key_b64);
    const iv = base64UrlToBytes(v.iv_b64);
    const ctBytes = base64UrlToBytes(v.ciphertext_b64);
    const modified = new Uint8Array(ctBytes);
    modified[0] ^= 0x01;
    await expect(decrypt({ ciphertext: modified.buffer as ArrayBuffer, iv }, key)).rejects.toThrow();
  });

  it("flipped auth tag bit fails GCM authentication", async () => {
    const v = data.vectors[0];
    const key = await importKeyExtractable(v.key_b64);
    const iv = base64UrlToBytes(v.iv_b64);
    const ctBytes = base64UrlToBytes(v.ciphertext_b64);
    const modified = new Uint8Array(ctBytes);
    modified[modified.length - 1] ^= 0x01; // last byte is part of the GCM tag
    await expect(decrypt({ ciphertext: modified.buffer as ArrayBuffer, iv }, key)).rejects.toThrow();
  });

  it("truncated ciphertext fails", async () => {
    const v = data.vectors[0];
    const key = await importKeyExtractable(v.key_b64);
    const iv = base64UrlToBytes(v.iv_b64);
    const ctBytes = base64UrlToBytes(v.ciphertext_b64);
    const truncated = ctBytes.slice(0, ctBytes.length - 4);
    await expect(decrypt({ ciphertext: truncated.buffer as ArrayBuffer, iv }, key)).rejects.toThrow();
  });
});

describe("negative vectors: wrong password", () => {
  for (const v of data.password_vectors) {
    it(`wrong password fails decryption: ${v.name}`, async () => {
      const urlKeyRaw = base64UrlToBytes(v.url_key_b64);
      const wrongDerived = await deriveKeyWithPassword(urlKeyRaw, v.password + "wrong");
      const iv = base64UrlToBytes(v.iv_b64);
      const ciphertext = base64UrlToBytes(v.ciphertext_b64).buffer as ArrayBuffer;
      await expect(decrypt({ ciphertext, iv }, wrongDerived)).rejects.toThrow();
    });

    it(`empty password fails decryption: ${v.name}`, async () => {
      const urlKeyRaw = base64UrlToBytes(v.url_key_b64);
      const emptyDerived = await deriveKeyWithPassword(urlKeyRaw, "");
      const iv = base64UrlToBytes(v.iv_b64);
      const ciphertext = base64UrlToBytes(v.ciphertext_b64).buffer as ArrayBuffer;
      await expect(decrypt({ ciphertext, iv }, emptyDerived)).rejects.toThrow();
    });
  }
});

describe("negative vectors: malformed base64url", () => {
  it("invalid base64url throws on decode", () => {
    expect(() => base64UrlToBytes("!!!invalid!!!")).toThrow();
  });

  it("wrong key length rejects on import", async () => {
    const badKey = bytesToBase64Url(new Uint8Array(15)); // 120 bits — not a valid AES key length
    await expect(importKey(badKey)).rejects.toThrow();
  });

  it("wrong IV length fails encryption", async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode("test");
    const wrongIv = new Uint8Array(8); // 8 bytes instead of 12
    await expect(
      crypto.subtle.encrypt({ name: "AES-GCM", iv: wrongIv }, key, plaintext)
    ).rejects.toThrow();
  });
});

describe("negative vectors: non-extractable key with computeKeyHash", () => {
  it("computeKeyHash throws on non-extractable key", async () => {
    const key = await generateKey();
    const keyB64 = bytesToBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
    const nonExtractable = await importKey(keyB64); // decrypt-only, non-extractable
    await expect(computeKeyHash(nonExtractable)).rejects.toThrow();
  });
});
