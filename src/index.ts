export {
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
  KEY_HASH_LENGTH,
} from "./crypto.js";

export type { EncryptedPayload, DeriveKeyOptions } from "./crypto.js";

export {
  generateRequestKeyPair,
  derivePublicKeyB64,
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
  CLAIM_PROOF_LENGTH,
} from "./request.js";

export type { RequestKeyPair, RequestResponse } from "./request.js";

export {
  bytesToBase64Url,
  base64UrlToBytes,
  timingSafeEqual,
} from "./encoding.js";
