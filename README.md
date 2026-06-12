# @deadrop/crypto

Auditable AES-256-GCM encryption library for [Deadrop](https://deadrop.dev). Zero dependencies.

This is the cryptographic core used by Deadrop's [web app](https://deadrop.dev), [CLI](https://github.com/deadrop-dev/cli), and validated against the [Go self-host server](https://github.com/deadrop-dev/server). It's published separately so anyone can audit, verify, or reimplement the encryption.

## Install

```bash
npm install @deadrop/crypto
```

## Usage

### Encrypt a secret

```typescript
import { generateKey, exportKey, encrypt, serializePayload } from "@deadrop/crypto";

const key = await generateKey();
const keyB64 = await exportKey(key); // put this in the URL fragment

const payload = await encrypt("my secret", key);
const { ciphertext, iv } = serializePayload(payload); // send these to the server
```

### Decrypt a secret

```typescript
import { importKey, decrypt, deserializePayload } from "@deadrop/crypto";

const key = await importKey(keyB64); // from URL fragment
const payload = deserializePayload({ ciphertext, iv }); // from server response
const plaintext = await decrypt(payload, key);
```

### Password protection

```typescript
import { generateKey, exportKey, deriveKeyWithPassword, encrypt } from "@deadrop/crypto";

const key = await generateKey();
const keyB64 = await exportKey(key);
const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));

const derivedKey = await deriveKeyWithPassword(rawKey, "user-password");
const payload = await encrypt("protected secret", derivedKey);
```

Passwords are Unicode NFC-normalized before derivation (see *Password Protection* in [SPEC.md](./SPEC.md)), so the same password typed on different platforms derives the same key. Pass `{ normalization: "none" }` to reproduce pre-2.0 behavior when decrypting legacy secrets.

### Request flow — SPEC §9 (Request-a-Secret)

The reverse flow: a requester asks for a secret and hands out a link; the responder encrypts *to* the requester's ephemeral public key. The request link carries no key material at all.

```typescript
import {
  generateRequestKeyPair, computeClaimProof, computeFingerprint,
  encryptForRequest, decryptResponse,
} from "@deadrop/crypto";

// Requester — generate an ephemeral ECDH P-256 keypair
const { publicKeyB64, privateKeyB64 } = await generateRequestKeyPair();
const claimProof = await computeClaimProof(privateKeyB64);
// publicKeyB64 + claimProof go to the server.
// privateKeyB64 lives ONLY in the claim-link URL fragment.

// Responder — encrypt a secret to the requester's public key
// (fresh AES-256-GCM data key, wrapped via ECDH + HKDF-SHA256)
const response = await encryptForRequest("the staging DB password", publicKeyB64);
// → { encrypted, iv, wrappedKey, wrapIv, hkdfSalt, responderPublicKey }

// Both sides — display the fingerprint for out-of-band comparison (§9.4)
const fingerprint = await computeFingerprint(publicKeyB64);

// Requester — decrypt the fulfilled response
const plaintext = await decryptResponse(response, privateKeyB64);
```

### Key hash (server verification)

```typescript
import { computeKeyHash, computeKeyHashFromB64 } from "@deadrop/crypto";

const hash = await computeKeyHash(key);        // from CryptoKey
const hash2 = await computeKeyHashFromB64(keyB64); // from base64url string
// Send hash to server — it verifies without seeing the key
```

## API

| Function | Description |
|----------|-------------|
| `generateKey()` | Generate a new AES-256-GCM key |
| `exportKey(key)` | Export key as base64url string |
| `importKey(keyB64)` | Import key (decrypt-only, non-extractable) |
| `importKeyExtractable(keyB64)` | Import key (encrypt + decrypt, extractable) |
| `encrypt(plaintext, key)` | Encrypt with AES-256-GCM |
| `decrypt(payload, key)` | Decrypt with AES-256-GCM |
| `computeKeyHash(key, length?)` | SHA-256 hash of key (requires extractable key) |
| `computeKeyHashFromB64(keyB64, length?)` | Same, from base64url string (no extractability needed) |
| `deriveKeyWithPassword(urlKeyRaw, password)` | PBKDF2 key derivation |
| `serializePayload(payload)` | Convert to base64url strings |
| `deserializePayload(data)` | Convert from base64url strings |
| `bytesToBase64Url(bytes)` | Encode bytes to base64url |
| `base64UrlToBytes(b64)` | Decode base64url to bytes |
| `timingSafeEqual(a, b)` | Best-effort constant-time byte comparison |

### Request flow (SPEC §9)

| Function | Description |
|----------|-------------|
| `generateRequestKeyPair()` | Ephemeral ECDH P-256 keypair (raw public key + PKCS8 private key, base64url) |
| `computeClaimProof(privateKeyB64)` | 22-char hash registered at create time; gates the claim-burn |
| `computeFingerprint(publicKeyB64)` | 8-char key fingerprint for out-of-band verification (§9.4) |
| `derivePublicKeyB64(privateKeyB64)` | Recover the public key from the claim-link private key |
| `deriveWrappingKey(privB64, pubB64, hkdfSalt)` | ECDH → HKDF-SHA256 → AES-256-GCM wrapping key (symmetric for both sides) |
| `wrapDataKey(dataKeyRaw, wrappingKey, wrapIv)` | Wrap the 32-byte data key |
| `unwrapDataKey(wrappedKeyB64, wrappingKey, wrapIv)` | Unwrap the data key; throws on tampering |
| `encryptForRequest(plaintext, requesterPublicKeyB64)` | Responder side: everything fresh per call — data key, responder keypair, salt, IVs |
| `decryptResponse(response, privateKeyB64)` | Requester side: unwrap and decrypt a fulfilled response |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `KEY_LENGTH` | 256 | AES key bits |
| `IV_LENGTH` | 12 | GCM IV bytes |
| `KEY_HASH_LENGTH` | 22 | Default key hash chars (128 bits) |
| `PBKDF2_ITERATIONS` | 600,000 | Password derivation rounds |
| `REQUEST_WRAP_INFO` | `deadrop/request-wrap/v1` | HKDF info string (§9.1) — changing it is a protocol version bump |
| `HKDF_SALT_LENGTH` | 16 | HKDF salt bytes (§9.1) |
| `FINGERPRINT_LENGTH` | 8 | Key fingerprint chars (§9.1) |
| `CLAIM_PROOF_LENGTH` | 22 | Claim proof chars (128 bits, same gate width as `KEY_HASH_LENGTH`) |

## Test Vectors

`test-vectors.json` contains deterministic pairs for cross-implementation verification, in three sections: `vectors` (AES-256-GCM encrypt/decrypt), `password_vectors` (PBKDF2 derivation, including non-NFC inputs), and `request_vectors` (§9 request-flow round trips). Any implementation (Go, Python, Rust) can validate against these vectors to prove interoperability — the [Go server](https://github.com/deadrop-dev/server) round-trips them in its test suite.

```bash
npm test
```

## Spec

See [SPEC.md](./SPEC.md) for the full cryptographic specification.

## License

MIT
