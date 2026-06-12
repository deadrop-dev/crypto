# Deadrop Cryptographic & Protocol Specification

Version: 2.1

## Changelog

**2.1 (2026-06-12)** — additive over 2.0.

- **Request flow (Request-a-Secret) is specified** (§9): ephemeral ECDH P-256 + HKDF-SHA256 hybrid encryption, claim-proof gate, atomic claim-burn, endpoint contract. Implementing §9 is optional; implementations that offer a reverse flow MUST implement it exactly as specified.

**2.0 (2026-06-12)** — additive over 1.1; everything in 1.1 not contradicted here remains in force.

- **Atomic verify-and-burn is normative** (see *Server Protocol* §3): retrieval must not expose a window where two correct-key requests both receive the blob.
- **Trusted client-IP resolution is normative** for any IP-based control (§5).
- **Rate limits** specified for creation and retrieval-class operations (§7).
- **Password NFC normalization** on the encrypt path, with a TTL-bounded decrypt fallback for legacy secrets (see *Password Protection*).
- **KDF versioning / URL grammar** formalized; `a2.` (Argon2id) selector **reserved**, not yet implemented (§4, §6).
- Wire format section corrected to match the live API (`1.1` documented field names that were never shipped).
- Reference burn script returns an empty bulk string on hash mismatch rather than a Lua error reply — error replies surface as exceptions in client libraries, which is a worse contract for a non-exceptional outcome.

## Overview

Deadrop uses client-side encryption so the server never sees plaintext. The encryption key is embedded in the URL fragment (`#`), which browsers never send to the server per RFC 3986 section 3.5. Note that the fragment can still leak through client-side logging, copied URLs, browser extensions, or compromised JavaScript.

## Algorithms

| Parameter     | Value                                                             |
| ------------- | ----------------------------------------------------------------- |
| Cipher        | AES-256-GCM                                                       |
| Key length    | 256 bits (32 bytes)                                               |
| IV length     | 96 bits (12 bytes)                                                |
| IV generation | Cryptographically random (`crypto.getRandomValues`)               |
| Auth tag      | 128 bits (appended to ciphertext by GCM)                          |
| Key hash      | SHA-256, base64url-encoded, truncated to 22 characters (128 bits) |
| Encoding      | Base64url (RFC 4648 section 5, no padding)                        |
| Text encoding | UTF-8. Secret plaintext: raw codepoints as-is. Passwords: NFC-normalized since 2.0 (see Password Protection) |

## Key Generation

A fresh AES-256-GCM key is generated for every secret using the Web Crypto API:

```ts
key = crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  (extractable = true),
  ["encrypt", "decrypt"],
);
```

The raw key bytes (32 bytes) are exported and encoded as base64url (43 characters, no padding).

**Extractability:** Keys are created as extractable because the protocol requires exporting raw bytes for URL embedding and hash computation. This is a deliberate design choice, not an oversight. Extractable keys carry higher risk of accidental exposure through logging or debugging — consumers should treat exported key material as sensitive and avoid persisting it beyond immediate use.

## Encryption

```ts
iv = crypto.getRandomValues(new Uint8Array(12));
plaintext_bytes = TextEncoder.encode(plaintext);
ciphertext = crypto.subtle.encrypt(
  { name: "AES-GCM", iv },
  key,
  plaintext_bytes,
);
```

The output is `ciphertext || 16-byte GCM authentication tag` (the Web Crypto API appends the tag automatically). Both ciphertext+tag and IV are base64url-encoded for transport.

## Decryption

```ts
plaintext_bytes = crypto.subtle.decrypt(
  { name: "AES-GCM", iv },
  key,
  ciphertext_with_tag,
);
plaintext = TextDecoder.decode(plaintext_bytes);
```

GCM authentication is verified automatically. If the ciphertext, tag, or key is wrong, decryption throws. This is the primary integrity and authenticity mechanism.

## Key Hash (Server-Side Access Gate)

The server stores a hash of the key to verify the client holds the correct key before performing the destructive burn-on-read:

```ts
raw_key = crypto.subtle.exportKey("raw", key);
hash = crypto.subtle.digest("SHA-256", raw_key);
key_hash = base64url(hash).slice(0, 22);
```

The 22-character hash provides 128 bits of collision resistance. This is an access-control gate — a hash collision would cause the server to burn the secret and return ciphertext to a client that cannot decrypt it. At 128 bits, the probability of accidental or adversarial collision is negligible (2^-128).

The server compares the client-provided `key_hash` against its stored value using constant-time comparison. A mismatch returns an error without burning the secret.

## Password Protection (Optional)

When a password is set, the URL key is combined with the password via PBKDF2 to derive a new encryption key:

```ts
password_key = crypto.subtle.importKey(
  "raw",
  TextEncoder.encode(password),
  "PBKDF2",
  false,
  ["deriveKey"],
);
derived_key = crypto.subtle.deriveKey(
  {
    name: "PBKDF2",
    salt: url_key_raw_bytes,
    iterations: 600000,
    hash: "SHA-256",
  },
  password_key,
  { name: "AES-GCM", length: 256 },
  (extractable = true),
  ["encrypt", "decrypt"],
);
```

| Parameter  | Value                        | Rationale                                                                                                                                                                                                                            |
| ---------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| KDF        | PBKDF2                       | Web Crypto API native — zero dependencies, works in all browsers and Node.js. Argon2id would be stronger against GPU attacks but requires a WASM or native dependency, which conflicts with the auditability goal.                   |
| Hash       | SHA-256                      | Standard, hardware-accelerated on most platforms                                                                                                                                                                                     |
| Iterations | 600,000                      | Meets OWASP 2024 minimum recommendation for PBKDF2-SHA256                                                                                                                                                                            |
| Salt       | Raw URL key bytes (32 bytes) | Each secret has a unique random key, so the salt is unique per secret. Using the URL key as salt is an intentional design choice — it avoids storing or transmitting a separate salt value while providing 256 bits of salt entropy. |
| Output     | AES-256-GCM key              |                                                                                                                                                                                                                                      |

The `key_hash` sent to the server is computed from the **derived** key, not the URL key. The server verifies that the client-provided hash of the derived key matches the stored hash — this confirms the client knows both the URL key and the correct password, without the server ever seeing either.

**Unicode normalization (since 2.0).** Passwords MUST be NFC-normalized before UTF-8 encoding on the **encrypt** path. Without this, a password typed with a precomposed "é" on one device and a decomposed "é" on another derives a different key — a silent, unrecoverable lockout. NFC is a no-op for ASCII passwords, so this is backward-compatible for the overwhelming majority of existing secrets.

On the **decrypt** path, implementations MUST try the NFC-normalized password first and SHOULD fall back to the raw (un-normalized) password bytes if key-hash verification or GCM authentication fails — this covers secrets created by pre-2.0 clients with non-NFC passwords. The fallback is self-retiring: the maximum TTL is 7 days, so legacy secrets expire within a week of clients shipping normalization, after which the fallback MAY be removed.

## URL Format & KDF Versioning (§4)

```
https://{host}/s/{id}#{key}        ; no password,        KDF = none
https://{host}/s/{id}#p.{key}      ; password,           KDF = pbkdf2-sha256-600k (default)
https://{host}/s/{id}#a2.{key}     ; password,           KDF = argon2id (RESERVED — §6)
```

- `id`: 32-char base64url (24 random bytes), generated client-side.
- `key`: 43-char base64url (32 raw bytes), no padding.
- The fragment prefix is the KDF selector. A client encountering an **unknown prefix MUST refuse with a clear error** — never guess a KDF.
- The fragment MUST NOT be transmitted in any request. (The reveal page is client-rendered with SSR disabled, so the fragment never reaches the server even indirectly.)

### Reserved: Argon2id (§6 — do not implement before its phase)

Selector `a2.` is reserved for an opt-in Argon2id KDF (client-side WASM). Parameters will be pinned in-spec when implemented (target: OWASP baseline m=19 MiB, t=2, p=1, tuned to ~250–500 ms on reference hardware; salt = raw URL key bytes, same as PBKDF2). The default path stays PBKDF2 to preserve the zero-dependency property.

## Wire Format

### Create (POST /api/secrets)

```json
{
  "id": "<32-char base64url, client-generated>",
  "encrypted": "<base64url(ciphertext || 16-byte GCM tag)>",
  "iv": "<base64url(12-byte IV)>",
  "keyHash": "<22-char base64url key hash>",
  "expiresMinutes": 60,
  "hint": "optional password hint (≤140 chars)"
}
```

`expiresMinutes` is clamped server-side to [1, 10080] (7 days max).

### Retrieve (GET /api/secrets/{id}?k={keyHash})

The server verifies `keyHash` (constant-time), then **atomically** burns and returns the blob (§3):

```json
{
  "encrypted": "<base64url(ciphertext || 16-byte GCM tag)>",
  "iv": "<base64url(12-byte IV)>",
  "hint": "password hint if set, else null"
}
```

### Meta (GET /api/secrets/{id}/meta)

Returns `{ "hint": ... }` without key proof, so the recipient can see the password hint before deriving the key. Hints are therefore **semi-public** (visible to anyone holding the ID) — creators must be warned not to put the password itself in the hint.

### Revoke (DELETE /api/secrets/{id}?k={keyHash})

Same key-hash proof and the same atomic compare-and-delete as retrieval; returns no content.

## Server Protocol (Normative)

### §2 Zero-knowledge invariants — the server MUST

- Store only: `id`, `keyHash`, `iv`, `ciphertext`, optional `hint`, expiry. Never anything derived from the URL fragment.
- Never log ciphertext, hint, keyHash, or any fragment-derived value. (Client IP alone, for abuse defense, is allowed.)
- Compare `keyHash` in constant time.
- Burn atomically (§3) and resolve client IPs through a trust chain (§5).

### §3 Atomic verify-and-burn

Retrieve-and-burn MUST be atomic: there must be no window in which two requests presenting the correct `keyHash` both receive the blob. Reference implementation (Redis/Valkey ≥ 6.2), a single server-side script:

```lua
-- KEYS[1] = secret:{id}   ARGV[1] = client-provided keyHash
local v = redis.call('GET', KEYS[1])
if not v then return nil end
local sep = string.find(v, ':', 1, true)
if string.sub(v, 1, sep - 1) ~= ARGV[1] then return '' end   -- wrong key: do NOT burn
redis.call('DEL', KEYS[1])
return v
```

Return contract: `nil` = already gone; empty string = hash mismatch without burning (stored payloads are never empty, so this is unambiguous); payload = match, with the key deleted in the same atomic step. The constant-time guarantee for hash comparison is preserved at the application layer before the script runs; the script's equality is an exact-match gate on an already-128-bit value (collision-infeasible). Revocation MUST use the same compare-and-delete.

Non-Redis stores MUST use an equivalent atomic compare-and-delete: `DELETE … WHERE id = ? AND key_hash = ? RETURNING …` (SQLite 3.35+/Postgres), or a serializable transaction.

### §5 Trusted client-IP resolution

An implementation behind a proxy MUST establish a **trust chain** before believing a forwarded IP:

- Accept `CF-Connecting-IP` (or the last `X-Forwarded-For` hop) **only** when the request is proven to originate from the deployment's own edge — via one of: an edge-injected shared secret header (compared in constant time), mTLS / Authenticated Origin Pulls, or an edge IP allowlist.
- Absent the trust proof, fall back to the socket IP and treat all forwarded headers as untrusted.

Blindly trusting `X-Forwarded-For` moves IP spoofing from "impossible" to "trivial" — the trust chain is the requirement, not the header read. Applies to rate limiting and any future IP-based policy.

### §7 Rate limiting

- `POST /api/secrets`: ≤ 10/min/clientIP.
- `GET /api/secrets/{id}` (including `/meta`) and `DELETE`: ≤ 60/min/clientIP (retrieval-class bucket — bounds ID enumeration, key probing, and revoke spam).
- `clientIP` per §5. Limits MUST be configurable in self-host deployments.

### §8 Implementation compliance

Every implementation (SaaS, self-host server, CLI, SDKs) MUST pass the `@deadrop/crypto` test vectors end-to-end and honor this section. Implementations are spec-compatible, not code-shared.

## §9 Request Flow (Request-a-Secret) — Normative since 2.1

The reverse flow: a **requester** asks for a secret; a **responder** supplies it; the requester retrieves it once. The forward flow's symmetric key cannot work here — the request link is transmitted over untrusted channels, so anything it carries must be useless for decryption. The flow is therefore hybrid: the responder encrypts to the requester's ephemeral public key.

### §9.1 Algorithms

| Parameter | Value |
| --- | --- |
| Key agreement | ECDH, curve P-256 (Web Crypto `ECDH`/`P-256`) |
| KDF | HKDF-SHA256, 16-byte random salt, info = UTF-8 `"deadrop/request-wrap/v1"`, output 256 bits |
| Key wrap | AES-256-GCM over the raw 32 data-key bytes, fresh random 96-bit `wrapIv` (output 48 bytes: 32 + 16 tag) |
| Data encryption | Identical to the forward flow (fresh AES-256-GCM key K, §Encryption) |
| Public key encoding | Raw uncompressed point (65 bytes, `0x04‖X‖Y`), base64url |
| Private key encoding | PKCS8, base64url (URL fragment of the claim link only) |
| Claim proof | `base64url(SHA-256(UTF-8 bytes of privateKeyB64)))` truncated to 22 chars |
| Fingerprint | First 8 chars of `base64url(SHA-256(raw 65-byte public key))` |

### §9.2 Protocol

**Create (requester):** generate an ephemeral ECDH P-256 keypair. `POST /api/requests` with `{id, publicKey, claimProof, prompt?, expiresMinutes}`. `id` uses the secret-id grammar; `prompt` ≤ 140 chars, semi-public (same caveat as password hints); `expiresMinutes` clamped to `[1, 10080]`, never rejected for range. Duplicate `id` → 409. Two links result: the **request link** `/r/{id}` (no fragment — the responder gets the public key from the server) and the **claim link** `/r/{id}/claim#{privateKeyB64}` (the private key exists ONLY in this fragment; losing it makes the response unrecoverable).

**Fulfill (responder):** `GET /api/requests/{id}` → `{publicKey, prompt, fulfilled}`. Generate a fresh AES-256-GCM data key K; encrypt the secret with K exactly per the forward flow. Generate an ephemeral responder ECDH keypair; `sharedBits = ECDH(responderPrivate, requesterPublic)`; `wrappingKey = HKDF-SHA256(sharedBits, salt, info)` per §9.1; `wrappedKey = AES-GCM(wrappingKey, wrapIv, raw K)`. `POST /api/requests/{id}/response` with `{encrypted, iv, wrappedKey, wrapIv, hkdfSalt, responderPublicKey}`. Exactly one response per request: already fulfilled → 409, atomically enforced (no window in which two responders both get 201).

**Claim (requester):** `GET /api/requests/{id}/response?proof={claimProof}`. Status precedence is normative: **404** unknown/expired/already-claimed (indistinguishable) → **403** proof mismatch (nothing burned) → **202** valid proof but not yet fulfilled (nothing burned) → **200** blob returned and the entire request record (request + response) deleted in the same atomic step (§3 contract, claim-burn). Decrypt: `ECDH(requesterPrivate, responderPublicKey)` → same HKDF → unwrap K → decrypt.

### §9.3 Server obligations

- Store only: `id`, `publicKey`, `claimProof`, optional `prompt`, expiry; after fulfillment additionally the opaque response fields. None of it decrypts anything.
- The response inherits the request's original expiry (one deadline for the whole exchange).
- Claim-burn MUST be a single atomic compare-and-delete over the whole record; two concurrent correct-proof claims MUST resolve to exactly one 200 and one 404.
- Rate limits (§7): `POST /api/requests` joins the create bucket; the other three request endpoints join the retrieval-class bucket.
- Never log `prompt`, key material, proofs, or response fields.

### §9.4 Threat model honesty

The server hands the responder the requester's public key, so a malicious server could substitute its own (machine-in-the-middle) and read the response. Mitigation: both the fulfill and claim UIs MUST display the §9.1 fingerprint of the requester public key they are using, so the parties can compare out-of-band. This is honest mitigation, not elimination — the same residual trust in served JavaScript applies to every zero-knowledge web application. State it; do not pretend otherwise.

## Security Properties

- **Zero-knowledge**: The server stores only ciphertext and a truncated key hash. It cannot decrypt.
- **Key independence**: Each secret has a unique randomly-generated key. Compromising one key reveals nothing about others. (This is not forward secrecy in the Diffie-Hellman sense — there is no key exchange protocol.)
- **Burn-on-read**: The server deletes the encrypted blob in the same atomic step that returns it (§3) — two concurrent correct-key requests can never both receive the blob.
- **Password brute-force resistance**: 600,000 PBKDF2 iterations make offline attacks expensive. The cost is platform-dependent (hardware, runtime, JIT optimization).
- **IV uniqueness**: Random 96-bit IVs provide negligible collision probability. Since each secret uses its own key, the GCM security bound (2^32 encryptions per key) is never approached.

## Test Vectors

The `test-vectors.json` file contains deterministic encryption/decryption pairs with known keys, IVs, and expected ciphertexts. Any implementation claiming compatibility must pass all vectors. The file includes both basic encryption vectors and password-derivation vectors with the expected derived key material.
