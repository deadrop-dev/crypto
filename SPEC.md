# Deadrop Cryptographic Specification

Version: 1.1

## Overview

Deadrop uses client-side encryption so the server never sees plaintext. The encryption key is embedded in the URL fragment (`#`), which browsers never send to the server per RFC 3986 section 3.5. Note that the fragment can still leak through client-side logging, copied URLs, browser extensions, or compromised JavaScript.

## Algorithms

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-GCM |
| Key length | 256 bits (32 bytes) |
| IV length | 96 bits (12 bytes) |
| IV generation | Cryptographically random (`crypto.getRandomValues`) |
| Auth tag | 128 bits (appended to ciphertext by GCM) |
| Key hash | SHA-256, base64url-encoded, truncated to 22 characters (128 bits) |
| Encoding | Base64url (RFC 4648 section 5, no padding) |
| Text encoding | UTF-8 (no Unicode normalization — raw codepoints as-is) |

## Key Generation

A fresh AES-256-GCM key is generated for every secret using the Web Crypto API:

```
key = crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, extractable=true, ["encrypt", "decrypt"])
```

The raw key bytes (32 bytes) are exported and encoded as base64url (43 characters, no padding).

**Extractability:** Keys are created as extractable because the protocol requires exporting raw bytes for URL embedding and hash computation. This is a deliberate design choice, not an oversight. Extractable keys carry higher risk of accidental exposure through logging or debugging — consumers should treat exported key material as sensitive and avoid persisting it beyond immediate use.

## Encryption

```
iv = crypto.getRandomValues(new Uint8Array(12))
plaintext_bytes = TextEncoder.encode(plaintext)
ciphertext = crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext_bytes)
```

The output is `ciphertext || 16-byte GCM authentication tag` (the Web Crypto API appends the tag automatically). Both ciphertext+tag and IV are base64url-encoded for transport.

## Decryption

```
plaintext_bytes = crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext_with_tag)
plaintext = TextDecoder.decode(plaintext_bytes)
```

GCM authentication is verified automatically. If the ciphertext, tag, or key is wrong, decryption throws. This is the primary integrity and authenticity mechanism.

## Key Hash (Server-Side Access Gate)

The server stores a hash of the key to verify the client holds the correct key before performing the destructive burn-on-read:

```
raw_key = crypto.subtle.exportKey("raw", key)
hash = crypto.subtle.digest("SHA-256", raw_key)
key_hash = base64url(hash).slice(0, 22)
```

The 22-character hash provides 128 bits of collision resistance. This is an access-control gate — a hash collision would cause the server to burn the secret and return ciphertext to a client that cannot decrypt it. At 128 bits, the probability of accidental or adversarial collision is negligible (2^-128).

The server compares the client-provided `key_hash` against its stored value using constant-time comparison. A mismatch returns an error without burning the secret.

## Password Protection (Optional)

When a password is set, the URL key is combined with the password via PBKDF2 to derive a new encryption key:

```
password_key = crypto.subtle.importKey("raw", TextEncoder.encode(password), "PBKDF2", false, ["deriveKey"])
derived_key = crypto.subtle.deriveKey(
  { name: "PBKDF2", salt: url_key_raw_bytes, iterations: 600000, hash: "SHA-256" },
  password_key,
  { name: "AES-GCM", length: 256 },
  extractable=true,
  ["encrypt", "decrypt"]
)
```

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| KDF | PBKDF2 | Web Crypto API native — zero dependencies, works in all browsers and Node.js. Argon2id would be stronger against GPU attacks but requires a WASM or native dependency, which conflicts with the auditability goal. |
| Hash | SHA-256 | Standard, hardware-accelerated on most platforms |
| Iterations | 600,000 | Meets OWASP 2024 minimum recommendation for PBKDF2-SHA256 |
| Salt | Raw URL key bytes (32 bytes) | Each secret has a unique random key, so the salt is unique per secret. Using the URL key as salt is an intentional design choice — it avoids storing or transmitting a separate salt value while providing 256 bits of salt entropy. |
| Output | AES-256-GCM key | |

The `key_hash` sent to the server is computed from the **derived** key, not the URL key. The server verifies that the client-provided hash of the derived key matches the stored hash — this confirms the client knows both the URL key and the correct password, without the server ever seeing either.

Passwords are encoded as raw UTF-8 with no Unicode normalization. Two passwords that are visually identical but use different Unicode representations (e.g. precomposed vs decomposed) will produce different derived keys.

## URL Format

```
https://deadrop.dev/s/{secret_id}#{key_b64}         (no password)
https://deadrop.dev/s/{secret_id}#p.{key_b64}       (password-protected)
```

The `p.` prefix signals that the client must prompt for a password before deriving the decryption key.

## Wire Format

### Create (POST /api/secrets)

```json
{
  "encryptedContent": "<base64url(ciphertext || 16-byte GCM tag)>",
  "iv": "<base64url(12-byte IV)>",
  "keyHash": "<22-char base64url key hash>",
  "ttl": 3600,
  "hint": "optional password hint"
}
```

### Retrieve (GET /api/secrets/{id}?keyHash={hash})

The server verifies `keyHash` matches (constant-time), returns the encrypted blob, and deletes it:

```json
{
  "encryptedContent": "<base64url(ciphertext || 16-byte GCM tag)>",
  "iv": "<base64url(12-byte IV)>"
}
```

## Security Properties

- **Zero-knowledge**: The server stores only ciphertext and a truncated key hash. It cannot decrypt.
- **Key independence**: Each secret has a unique randomly-generated key. Compromising one key reveals nothing about others. (This is not forward secrecy in the Diffie-Hellman sense — there is no key exchange protocol.)
- **Burn-on-read**: The server deletes the encrypted blob immediately after retrieval.
- **Password brute-force resistance**: 600,000 PBKDF2 iterations make offline attacks expensive. The cost is platform-dependent (hardware, runtime, JIT optimization).
- **IV uniqueness**: Random 96-bit IVs provide negligible collision probability. Since each secret uses its own key, the GCM security bound (2^32 encryptions per key) is never approached.

## Test Vectors

The `test-vectors.json` file contains deterministic encryption/decryption pairs with known keys, IVs, and expected ciphertexts. Any implementation claiming compatibility must pass all vectors. The file includes both basic encryption vectors and password-derivation vectors with the expected derived key material.
