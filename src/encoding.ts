/** Base64url encode (URL-safe, no padding) */
export function bytesToBase64Url(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCodePoint(b)).join("");
  const b64 = btoa(binString);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Base64url decode */
export function base64UrlToBytes(b64: string): Uint8Array {
  const standard = b64.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard + "=".repeat((4 - (standard.length % 4)) % 4);
  const binString = atob(padded);
  return Uint8Array.from(binString, (c) => c.codePointAt(0)!);
}

/**
 * Best-effort constant-time byte array comparison for fixed-length values.
 * The length check is not constant-time (safe for fixed-size key hashes and IVs).
 * JavaScript/JIT runtimes do not provide hard constant-time guarantees — this is
 * a best-effort mitigation, not a cryptographic primitive. For server-side use,
 * prefer `crypto.timingSafeEqual` from Node.js.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
