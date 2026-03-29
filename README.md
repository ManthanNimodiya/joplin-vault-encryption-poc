# Joplin Vault Encryption — Proof of Concept

Standalone proof-of-concept for **single-key vault encryption** proposed in my [GSoC 2026 application](https://github.com/joplin/gsoc/blob/master/ideas.md) for **Joplin — Project #7: Support for Encrypted Notes**.

## What This Demonstrates

This PoC validates the core cryptographic design before integrating into Joplin's codebase:

- **Single vault key model** — one password unlocks all encrypted notes for a session
- **PBKDF2-SHA512** key derivation (100,000 iterations, global 128-bit vault salt)
- **AES-256-GCM** authenticated encryption (random 96-bit IV per note, 128-bit auth tag)
- **`JOPLIN_CIPHER:1:` format** — versioned, intentionally distinct from Joplin's E2EE format
- **Title + body** encrypted together as `JSON.stringify({ title, body })`
- **Wrong password detection** via GCM authentication tag failure
- **Tamper detection** — any byte modification to ciphertext is caught
- **Cross-device correctness** — same salt + password on a different instance derives identical key
- **Zero external dependencies** — uses only Node.js built-in `crypto`

## JOPLIN_CIPHER:1: Format Specification

```
JOPLIN_CIPHER:<version>:<iv_hex>:<authTag_hex>:<base64_ciphertext>
```

**Example (version 1):**
```
JOPLIN_CIPHER:1:3b01767686e7d1ea147374ef:88c053fed05a7e412c92719aa02a737f:jSrAYXhIJqU/2rur...
```

| Segment | Field | Encoding | Size | Purpose |
|---|---|---|---|---|
| 0 | Prefix | ASCII | 13 chars | Format identifier — `JOPLIN_CIPHER` |
| 1 | Version | ASCII | 1 char | Algorithm version — enables future upgrades without prefix changes |
| 2 | IV | Hex | 24 chars (12 bytes) | AES-GCM initialization vector — **random per note** |
| 3 | AuthTag | Hex | 32 chars (16 bytes) | GCM 128-bit authentication tag — detects tampering + wrong password |
| 4 | Ciphertext | Base64 | Variable | Encrypted `JSON.stringify({ title, body })` |

> **Design notes:**
> - The vault salt is **not** embedded in each note's payload.
>   It is stored once globally in Joplin settings (generated on first vault setup).
>   Per-note random IVs provide ciphertext uniqueness even with a stable vault key.
> - The version field (`1`) enables future algorithm upgrades (e.g., Argon2id for v2)
>   without changing the prefix. Old notes (`v1`) continue to decrypt with the original logic.
> - `JOPLIN_CIPHER:` is intentionally distinct from Joplin's E2EE format — no ambiguity.

## VaultService API

```typescript
export interface VaultPayload { title: string; body: string; }

export default class VaultService {
    // constructor accepts an optional existing salt (simulates Joplin settings)
    // throws TypeError if salt is not a Buffer of exactly 16 bytes
    constructor(vaultSalt?: Buffer);

    // Session lifecycle
    public async unlockVault(password: string): Promise<void>;  // derives + caches vault key (PBKDF2 once)
    public lockVault(): void;                                    // clears cached key from memory

    // Encryption / Decryption (vault must be unlocked)
    public async encrypt(payload: VaultPayload): Promise<string>;           // → JOPLIN_CIPHER:1:...
    public async decrypt(encryptedPayload: string): Promise<VaultPayload>;  // ← JOPLIN_CIPHER:1:...

    // Detection (used by DecryptionWorker after E2EE decryption)
    public isVaultEncrypted(body: string): boolean;

    // Read-only
    public get vaultSalt(): Buffer;
    public get isUnlocked(): boolean;
}
```

## Sync Design (Vault ↔ E2EE Interaction)

The vault layer sits **below** Joplin's existing E2EE:

```
┌──────────────┐   encrypt()    ┌─────────────────────────────────────────────────────┐
│ Plain note   │ ─────────────► │ JOPLIN_CIPHER:1:<iv>:<authTag>:<ciphertext>          │ ← SQLite
└──────────────┘                └─────────────────────────────────────────────────────┘
                                          │  (E2EE wraps this body as opaque content)
                                          ▼
                                ┌─────────────────────────────────────────────────────┐
                                │  E2EE ciphertext (in transit / at rest on server)   │
                                └─────────────────────────────────────────────────────┘
```

`DecryptionWorker` detects the prefix after E2EE decryption:

```typescript
if (decryptedItem.body?.startsWith('JOPLIN_CIPHER:')) {
    decryptedItem.is_vault_encrypted = 1;
    await Note.save(decryptedItem);  // save JOPLIN_CIPHER: payload as-is
    continue;                        // stop — do not attempt vault decrypt here
}
```

No changes to `Synchronizer.ts` are needed — E2EE treats the `JOPLIN_CIPHER:` body as opaque content.

## Quick Start

```bash
# No npm install needed — zero dependencies
node VaultService.js          # live demo showing all primitives

# Run the full test suite (10 tests)
node VaultService.test.js
```

## File Structure

```
├── VaultService.js       # Core encryption service
├── VaultService.test.js  # Test suite (10 tests covering all edge cases)
└── README.md
```

## Test Coverage

| # | Test | What It Validates |
|---|---|---|
| 1 | Roundtrip — unicode | Title + body survive encrypt → decrypt (unicode, emoji, multi-line) |
| 2 | Roundtrip — 10 MB | 10 MB body encrypts and decrypts within 10 s |
| 3 | Cross-instance roundtrip | Same salt + password on a new VaultService instance decrypts correctly (simulates Device B syncing from Device A) |
| 4 | Wrong password | Different vault key → `VaultDecryptionError` (GCM auth tag mismatch) |
| 5 | IV uniqueness | Same plaintext + same key → different IV and ciphertext each call |
| 6 | Empty note | `{ title: '', body: '' }` encrypts/decrypts correctly |
| 7 | Format structure | Prefix `JOPLIN_CIPHER`, version `1`, 5 segments, IV 24 hex chars, AuthTag 32 hex chars, base64 ciphertext — no salt in payload |
| 8 | `isVaultEncrypted()` | Correctly identifies `JOPLIN_CIPHER:` strings; rejects `JEV01:` and lowercase variants |
| 9 | Tamper detection | Modified ciphertext byte → `VaultDecryptionError` |
| 10 | Locked vault + bad salt | `encrypt()`/`decrypt()` on locked vault → `VaultNotUnlockedError`; wrong salt type/size → `TypeError` |

## Relevance to GSoC Proposal

This PoC will become the foundation for `packages/lib/services/vault/VaultService.ts` in Joplin's monorepo. The production version will:

1. Be written in **TypeScript** with full type annotations
2. Load/store the global `vaultSalt` from **Joplin's settings DB** (generated once on first vault setup, synced across devices)
3. Integrate with Joplin's `Note` model and `BaseItem` serialization
4. Include a guard in **`DecryptionWorker.ts`** to detect `JOPLIN_CIPHER:` after E2EE decryption
5. Add a React **`VaultPasswordDialog`** in `packages/app-desktop`

## Author

**Manthan Nimodiya** — GSoC 2026 Contributor for Joplin
- GitHub: [@ManthanNimodiya](https://github.com/ManthanNimodiya)
- Joplin Forum: [manthan](https://discourse.joplinapp.org/u/manthan)
- PoC Repo: [joplin-vault-encryption-poc](https://github.com/ManthanNimodiya/joplin-vault-encryption-poc)
