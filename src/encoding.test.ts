import { describe, it, expect } from "vitest";
import { bytesToBase64Url, base64UrlToBytes, timingSafeEqual } from "./encoding.js";

describe("bytesToBase64Url", () => {
  it("encodes bytes to URL-safe base64 without padding", () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]);
    const result = bytesToBase64Url(bytes);
    expect(result).toBe("SGVsbG8");
    expect(result).not.toMatch(/[+/=]/);
  });

  it("handles empty input", () => {
    expect(bytesToBase64Url(new Uint8Array([]))).toBe("");
  });

  it("replaces + with - and / with _", () => {
    const bytes = new Uint8Array([0xfb, 0xff]);
    const result = bytesToBase64Url(bytes);
    expect(result).not.toContain("+");
    expect(result).not.toContain("/");
    expect(result).not.toContain("=");
  });
});

describe("base64UrlToBytes", () => {
  it("decodes URL-safe base64 back to bytes", () => {
    const result = base64UrlToBytes("SGVsbG8");
    expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]);
  });

  it("handles empty input", () => {
    expect(base64UrlToBytes("").length).toBe(0);
  });

  it("handles base64url with - and _ characters", () => {
    const original = new Uint8Array([0xfb, 0xff, 0xfe, 0x3e, 0x3f]);
    const encoded = bytesToBase64Url(original);
    const decoded = base64UrlToBytes(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });
});

describe("round-trip", () => {
  it("round-trips 12 bytes (IV size)", () => {
    const original = crypto.getRandomValues(new Uint8Array(12));
    const decoded = base64UrlToBytes(bytesToBase64Url(original));
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });

  it("round-trips 24 bytes (ID size)", () => {
    const original = crypto.getRandomValues(new Uint8Array(24));
    const encoded = bytesToBase64Url(original);
    expect(encoded.length).toBe(32);
    expect(Array.from(base64UrlToBytes(encoded))).toEqual(Array.from(original));
  });

  it("round-trips 32 bytes (key size)", () => {
    const original = crypto.getRandomValues(new Uint8Array(32));
    const decoded = base64UrlToBytes(bytesToBase64Url(original));
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });

  it("round-trips all byte values 0-255", () => {
    const original = new Uint8Array(256);
    for (let i = 0; i < 256; i++) original[i] = i;
    const decoded = base64UrlToBytes(bytesToBase64Url(original));
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });
});

describe("timingSafeEqual", () => {
  it("returns true for identical arrays", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3, 4]), new Uint8Array([1, 2, 3, 4]))).toBe(true);
  });

  it("returns false for different arrays", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3, 4]), new Uint8Array([1, 2, 3, 5]))).toBe(false);
  });

  it("returns false for different length arrays", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3, 4]))).toBe(false);
  });

  it("returns true for empty arrays", () => {
    expect(timingSafeEqual(new Uint8Array([]), new Uint8Array([]))).toBe(true);
  });
});
