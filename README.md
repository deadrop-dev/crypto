# @deadrop/crypto

Auditable AES-256-GCM encryption library for [Deadrop](https://deadrop.dev). Zero dependencies.

This is the cryptographic core used by Deadrop's web app, CLI, and SDKs. It's published separately so anyone can audit, verify, or reimplement the encryption.

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

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `KEY_LENGTH` | 256 | AES key bits |
| `IV_LENGTH` | 12 | GCM IV bytes |
| `KEY_HASH_LENGTH` | 22 | Default key hash chars (128 bits) |
| `PBKDF2_ITERATIONS` | 600,000 | Password derivation rounds |

## Test Vectors

`test-vectors.json` contains deterministic encryption pairs for cross-implementation verification. Any implementation (Go, Python, Rust) can validate against these vectors to prove interoperability.

```bash
npm test
```

## Spec

See [SPEC.md](./SPEC.md) for the full cryptographic specification.

## License

MIT
