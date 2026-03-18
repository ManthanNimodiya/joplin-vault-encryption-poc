# Joplin Vault Encryption — Proof of Concept

Standalone proof-of-concept for per-note vault encryption proposed in my [GSoC 2026 application](https://github.com/joplin/gsoc/blob/master/ideas.md) for **Joplin — Project #7: Support for Encrypted Notes**.

## What This Demonstrates

This PoC validates the core cryptographic design before integrating into Joplin's codebase:

- **PBKDF2-SHA512** key derivation (100,000 iterations, random 128-bit salt)
- **AES-256-GCM** authenticated encryption (random 96-bit IV, 128-bit auth tag)
- **JEV01 format** encoding/decoding: `JEV01:<salt>:<iv>:<authTag>:<ciphertext>`
- **Title + body** encrypted together as `JSON.stringify({ title, body })`
- **Wrong password detection** via GCM authentication tag failure
- **Zero external dependencies** — uses only Node.js built-in `crypto`

## JEV01 Format Specification

```
JEV01:<salt_hex>:<iv_hex>:<authTag_hex>:<base64_ciphertext>
```

| Field | Encoding | Size | Purpose |
|-------|----------|------|---------|
| Prefix | ASCII | 5 chars | Format version identifier |
| Salt | Hex | 32 chars (16 bytes) | PBKDF2 salt, random per encryption |
| IV | Hex | 24 chars (12 bytes) | AES-GCM initialization vector, random per encryption |
| AuthTag | Hex | 32 chars (16 bytes) | GCM authentication tag for integrity |
| Ciphertext | Base64 | Variable | Encrypted `JSON.stringify({ title, body })` |

## Quick Start

```bash
# No npm install needed — zero dependencies
node VaultService.js

# Run the test suite
node VaultService.test.js
```

## File Structure

```
├── VaultService.js       # Core encryption service (encrypt, decrypt, isVaultEncrypted)
├── VaultService.test.js  # Test suite (8 tests covering all edge cases)
└── README.md
```

## Test Coverage

| Test | What It Validates |
|------|-------------------|
| Encrypt/decrypt roundtrip | Correct title + body recovery |
| Wrong password rejection | GCM auth tag failure throws error |
| Unique salt per call | Two encryptions of same data produce different outputs |
| Empty content handling | Empty title and body encrypt/decrypt correctly |
| Large payload (1 MB) | Performance acceptable for large notes |
| JEV01 format structure | Prefix, field count, hex/base64 encoding |
| `isVaultEncrypted()` | Correctly identifies JEV01 strings |
| Tampered ciphertext | Modified payload detected via auth tag |

## Relevance to GSoC Proposal

This PoC will become the foundation for `packages/lib/services/vault/VaultService.ts` in Joplin's monorepo. The production version will:

1. Be written in TypeScript with full type annotations
2. Integrate with Joplin's `Note` model and `BaseItem` serialization
3. Include guards in `Synchronizer.ts` and `DecryptionWorker.ts`
4. Add a React `VaultPasswordDialog` in `packages/app-desktop`

## Author

**Manthan Nimodiya** — GSoC 2026 Applicant for Joplin
- GitHub: [@ManthanNimodiya](https://github.com/ManthanNimodiya)
- Joplin Forum: [manthan](https://discourse.joplinapp.org/u/manthan)
