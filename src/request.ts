/**
 * Request flow (Request-a-Secret) primitives — SPEC §9.
 *
 * Hybrid encryption: the responder encrypts a fresh AES-256-GCM data key to
 * the requester's ephemeral ECDH P-256 public key via HKDF-SHA256, so the
 * request link itself carries nothing that decrypts anything.
 */
import { generateKey, exportKey, encrypt, decrypt, IV_LENGTH } from "./crypto.js";
import { bytesToBase64Url, base64UrlToBytes } from "./encoding.js";

/** HKDF info string pinned by SPEC §9.1 — changing it is a protocol version bump. */
export const REQUEST_WRAP_INFO = "deadrop/request-wrap/v1";

/** HKDF salt length in bytes (SPEC §9.1) */
export const HKDF_SALT_LENGTH = 16;

/** Fingerprint length in base64url characters (SPEC §9.1) */
export const FINGERPRINT_LENGTH = 8;

/** Claim proof length in base64url characters (128 bits, same gate width as keyHash) */
export const CLAIM_PROOF_LENGTH = 22;

export interface RequestKeyPair {
  /** Raw uncompressed P-256 point (65 bytes), base64url — sent to the server. */
  publicKeyB64: string;
  /** PKCS8, base64url — lives ONLY in the claim-link URL fragment. */
  privateKeyB64: string;
}

/** The wire shape of a fulfilled response (SPEC §9.2), all fields base64url. */
export interface RequestResponse {
  encrypted: string;
  iv: string;
  wrappedKey: string;
  wrapIv: string;
  hkdfSalt: string;
  responderPublicKey: string;
}

const ECDH_PARAMS: EcKeyGenParams = { name: "ECDH", namedCurve: "P-256" };

/** Generate an ephemeral ECDH P-256 keypair for a request. */
export async function generateRequestKeyPair(): Promise<RequestKeyPair> {
  const pair = await crypto.subtle.generateKey(ECDH_PARAMS, true, [
    "deriveBits",
  ]);
  const publicRaw = await crypto.subtle.exportKey("raw", pair.publicKey);
  const privatePkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  return {
    publicKeyB64: bytesToBase64Url(new Uint8Array(publicRaw)),
    privateKeyB64: bytesToBase64Url(new Uint8Array(privatePkcs8)),
  };
}

/**
 * Claim proof = base64url(SHA-256(UTF-8 bytes of the base64url private key
 * string)), truncated to 22 chars (SPEC §9.1). Registered at create time;
 * gates the claim-burn the same way keyHash gates the forward flow.
 */
export async function computeClaimProof(privateKeyB64: string): Promise<string> {
  const bytes = new TextEncoder().encode(privateKeyB64);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToBase64Url(new Uint8Array(hash)).slice(0, CLAIM_PROOF_LENGTH);
}

/**
 * Fingerprint = first 8 base64url chars of SHA-256(raw 65-byte public key)
 * (SPEC §9.1). Shown on both the fulfill and claim UIs for out-of-band
 * machine-in-the-middle detection (SPEC §9.4).
 */
export async function computeFingerprint(publicKeyB64: string): Promise<string> {
  const raw = base64UrlToBytes(publicKeyB64);
  const hash = await crypto.subtle.digest("SHA-256", raw.buffer as ArrayBuffer);
  return bytesToBase64Url(new Uint8Array(hash)).slice(0, FINGERPRINT_LENGTH);
}

async function importPublicKey(publicKeyB64: string): Promise<CryptoKey> {
  const raw = base64UrlToBytes(publicKeyB64);
  return crypto.subtle.importKey(
    "raw",
    raw.buffer as ArrayBuffer,
    ECDH_PARAMS,
    false,
    [],
  );
}

async function importPrivateKey(privateKeyB64: string): Promise<CryptoKey> {
  const pkcs8 = base64UrlToBytes(privateKeyB64);
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8.buffer as ArrayBuffer,
    ECDH_PARAMS,
    false,
    ["deriveBits"],
  );
}

/**
 * Derive the AES-256-GCM wrapping key from one side's private key and the
 * other side's public key: ECDH → 256 shared bits → HKDF-SHA256(salt, info).
 * Symmetric — both sides derive the same key (SPEC §9.1).
 */
export async function deriveWrappingKey(
  privateKeyB64: string,
  publicKeyB64: string,
  hkdfSalt: Uint8Array,
): Promise<CryptoKey> {
  const privateKey = await importPrivateKey(privateKeyB64);
  const publicKey = await importPublicKey(publicKeyB64);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(hkdfSalt) as unknown as BufferSource,
      info: new TextEncoder().encode(REQUEST_WRAP_INFO),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Wrap the raw 32-byte data key under the wrapping key (AES-256-GCM, SPEC §9.1). */
export async function wrapDataKey(
  dataKeyRaw: Uint8Array,
  wrappingKey: CryptoKey,
  wrapIv: Uint8Array,
): Promise<string> {
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(wrapIv) as unknown as BufferSource },
    wrappingKey,
    new Uint8Array(dataKeyRaw) as unknown as BufferSource,
  );
  return bytesToBase64Url(new Uint8Array(wrapped));
}

/** Unwrap the raw data key. Throws if the wrap was tampered with or keys mismatch. */
export async function unwrapDataKey(
  wrappedKeyB64: string,
  wrappingKey: CryptoKey,
  wrapIv: Uint8Array,
): Promise<Uint8Array> {
  const unwrapped = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(wrapIv) as unknown as BufferSource },
    wrappingKey,
    base64UrlToBytes(wrappedKeyB64).buffer as ArrayBuffer,
  );
  return new Uint8Array(unwrapped);
}

/**
 * Responder side (SPEC §9.2 Fulfill): encrypt a secret to the requester's
 * public key. Generates the data key, the ephemeral responder keypair, the
 * HKDF salt, and both IVs — everything fresh per call.
 */
export async function encryptForRequest(
  plaintext: string,
  requesterPublicKeyB64: string,
): Promise<RequestResponse> {
  const dataKey = await generateKey();
  const payload = await encrypt(plaintext, dataKey);

  const responder = await generateRequestKeyPair();
  const hkdfSalt = crypto.getRandomValues(new Uint8Array(HKDF_SALT_LENGTH));
  const wrappingKey = await deriveWrappingKey(
    responder.privateKeyB64,
    requesterPublicKeyB64,
    hkdfSalt,
  );
  const wrapIv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const dataKeyRaw = base64UrlToBytes(await exportKey(dataKey));
  const wrappedKey = await wrapDataKey(dataKeyRaw, wrappingKey, wrapIv);

  return {
    encrypted: bytesToBase64Url(new Uint8Array(payload.ciphertext)),
    iv: bytesToBase64Url(payload.iv),
    wrappedKey,
    wrapIv: bytesToBase64Url(wrapIv),
    hkdfSalt: bytesToBase64Url(hkdfSalt),
    responderPublicKey: responder.publicKeyB64,
  };
}

/**
 * Requester side (SPEC §9.2 Claim): decrypt a fulfilled response with the
 * private key from the claim-link fragment. Throws on any tampering or key
 * mismatch (GCM authentication).
 */
export async function decryptResponse(
  response: RequestResponse,
  privateKeyB64: string,
): Promise<string> {
  const wrappingKey = await deriveWrappingKey(
    privateKeyB64,
    response.responderPublicKey,
    base64UrlToBytes(response.hkdfSalt),
  );
  const dataKeyRaw = await unwrapDataKey(
    response.wrappedKey,
    wrappingKey,
    base64UrlToBytes(response.wrapIv),
  );
  const dataKey = await crypto.subtle.importKey(
    "raw",
    dataKeyRaw.buffer as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  return decrypt(
    {
      ciphertext: base64UrlToBytes(response.encrypted).buffer as ArrayBuffer,
      iv: base64UrlToBytes(response.iv),
    },
    dataKey,
  );
}
