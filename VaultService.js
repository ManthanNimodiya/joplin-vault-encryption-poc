/**
 * VaultService — Single-Key Vault Encryption for Joplin
 *
 * Proof-of-concept implementing the JOPLIN_CIPHER: encrypted format.
 * Uses only Node.js built-in `crypto` — zero external dependencies.
 *
 * Cryptographic design:
 *   Key derivation:  PBKDF2-SHA512, 100,000 iterations, global 128-bit vault salt
 *   Cipher:          AES-256-GCM, random 96-bit IV per note, 128-bit auth tag
 *   Payload:         JSON.stringify({ title, body })
 *   Format:          JOPLIN_CIPHER:<version>:<iv_hex>:<authTag_hex>:<base64_ciphertext>
 *
 * Format versioning:
 *   Version 1  →  JOPLIN_CIPHER:1:<iv_hex>:<authTag_hex>:<base64_ciphertext>
 *   Future v2 could adopt Argon2id — old notes (v1) decode with original logic,
 *   new encryptions use v2. No migration required; version field enables this.
 *
 * Key design decisions:
 *   - ONE password → ONE vault key (derived once on unlockVault, cached in memory)
 *   - Global vault salt stored in Joplin settings (not embedded per-note)
 *   - Per-note random 96-bit IV ensures ciphertext uniqueness even with a stable key
 *   - JOPLIN_CIPHER: prefix is intentionally distinct from Joplin's E2EE format — no ambiguity
 *   - Vault layer sits BELOW E2EE: E2EE wraps the JOPLIN_CIPHER: body as opaque content
 *
 * Production integration (packages/lib/services/vault/VaultService.ts):
 *   - vaultSalt loaded from / saved to Joplin settings (generated once per install)
 *   - vaultKey held in memory; cleared on app lock / screen-lock event
 *   - DecryptionWorker detects JOPLIN_CIPHER: prefix post-E2EE → sets is_vault_encrypted=1
 *
 * Author: Manthan Nimodiya (GSoC 2026 — Joplin)
 */

'use strict';

const crypto = require('crypto');

// ── Constants ────────────────────────────────────────────────────────────────

const VAULT_FORMAT_PREFIX  = 'JOPLIN_CIPHER';
const VAULT_FORMAT_VERSION = '1';             // bumped when crypto algorithm changes
const PBKDF2_ITERATIONS    = 100_000;
const PBKDF2_KEYLEN        = 32;   // 256 bits → AES-256
const PBKDF2_DIGEST        = 'sha512';
const SALT_BYTES           = 16;   // 128-bit global vault salt
const IV_BYTES             = 12;   // 96-bit per-note IV (NIST recommended for GCM)
const AUTH_TAG_LENGTH      = 16;   // 128-bit GCM authentication tag
const CIPHER_ALGORITHM     = 'aes-256-gcm';

// ── Custom Error Types ────────────────────────────────────────────────────────

class VaultDecryptionError extends Error {
    constructor(message) {
        super(message);
        this.name = 'VaultDecryptionError';
    }
}

class VaultNotUnlockedError extends Error {
    constructor() {
        super('Vault is locked. Call unlockVault(password) first.');
        this.name = 'VaultNotUnlockedError';
    }
}

// ── VaultService ──────────────────────────────────────────────────────────────

class VaultService {
    /**
     * @param {Buffer} [vaultSalt]
     *   Optional existing 128-bit global salt. If omitted, a new random salt is
     *   generated — simulating "initial vault setup" in Joplin.
     *
     *   In production Joplin, this salt is stored once in the app's settings DB
     *   and reloaded on every launch. Pass an existing Buffer here to simulate
     *   the "same device, subsequent session" scenario in tests.
     *
     * @throws {TypeError} If vaultSalt is provided but is not a Buffer of exactly SALT_BYTES
     */
    constructor(vaultSalt) {
        if (vaultSalt !== undefined) {
            if (!Buffer.isBuffer(vaultSalt)) {
                throw new TypeError(`vaultSalt must be a Buffer, got ${typeof vaultSalt}`);
            }
            if (vaultSalt.length !== SALT_BYTES) {
                throw new TypeError(
                    `vaultSalt must be ${SALT_BYTES} bytes, got ${vaultSalt.length}`
                );
            }
            this._vaultSalt = vaultSalt;
        } else {
            this._vaultSalt = crypto.randomBytes(SALT_BYTES);
        }
        this._vaultKey = null;  // null → vault is locked
    }

    // ── Public getters ────────────────────────────────────────────────────────

    /**
     * The global vault salt (simulates reading from Joplin settings).
     * Expose so tests/demo can share it across VaultService instances.
     * @returns {Buffer}
     */
    get vaultSalt() { return this._vaultSalt; }

    /**
     * Whether the vault key is currently cached in memory.
     * @returns {boolean}
     */
    get isUnlocked() { return this._vaultKey !== null; }

    // ── Core API ──────────────────────────────────────────────────────────────

    /**
     * Derives the vault key from `password` + global salt and caches it in
     * memory for the current session. Must be called before encrypt/decrypt.
     *
     * PBKDF2-SHA512 with 100,000 iterations makes brute-force expensive while
     * keeping per-session unlock time under ~300 ms on modern hardware.
     * The cost is paid ONCE per session — not once per note.
     *
     * @param {string} password - User-provided vault password
     * @returns {Promise<void>}
     */
    async unlockVault(password) {
        if (!password || typeof password !== 'string') {
            throw new TypeError('Password must be a non-empty string');
        }
        this._vaultKey = await VaultService._deriveKey(password, this._vaultSalt);
    }

    /**
     * Clears the cached vault key from memory.
     * After this call, isUnlocked === false and any encrypt/decrypt attempt
     * throws VaultNotUnlockedError until unlockVault() is called again.
     */
    lockVault() {
        this._vaultKey = null;
    }

    /**
     * Encrypts a note's title + body using the cached vault key.
     *
     * Format produced: JOPLIN_CIPHER:1:<iv_hex>:<authTag_hex>:<base64_ciphertext>
     *   - Version field (1) enables future algorithm upgrades without prefix changes
     *   - vault_salt is stored globally in Joplin settings — NOT embedded in the payload
     *   - Prefix is intentionally distinct from Joplin's E2EE format — no ambiguity
     *
     * A fresh random 96-bit IV is generated for every call, so encrypting the
     * same plaintext twice produces different ciphertexts — even though the
     * vault key (and global salt) remain stable across the session.
     *
     * @param {{ title: string, body: string }} payload
     * @returns {Promise<string>} JOPLIN_CIPHER:1:<iv_hex>:<authTag_hex>:<base64_ciphertext>
     * @throws {VaultNotUnlockedError} If the vault is locked
     */
    async encrypt(payload) {
        if (!this._vaultKey) throw new VaultNotUnlockedError();

        const iv        = crypto.randomBytes(IV_BYTES);  // fresh per note
        const plaintext = JSON.stringify({
            title: payload.title  ?? '',
            body:  payload.body   ?? '',
        });

        const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, this._vaultKey, iv, {
            authTagLength: AUTH_TAG_LENGTH,
        });

        const ciphertext = Buffer.concat([
            cipher.update(plaintext, 'utf8'),
            cipher.final(),
        ]);
        const authTag = cipher.getAuthTag();

        // Format: JOPLIN_CIPHER:<version>:<iv_hex>:<authTag_hex>:<base64_ciphertext>
        // Salt intentionally omitted — stored globally in Joplin settings
        return [
            VAULT_FORMAT_PREFIX,
            VAULT_FORMAT_VERSION,
            iv.toString('hex'),
            authTag.toString('hex'),
            ciphertext.toString('base64'),
        ].join(':');
    }

    /**
     * Decrypts a JOPLIN_CIPHER:-formatted string back into { title, body }.
     *
     * Supports version routing: currently only version "1" is defined.
     * Future versions (e.g., "2" with Argon2id) can be handled by
     * dispatching on parts[1] before decryption.
     *
     * @param {string} encryptedPayload
     *   Format: JOPLIN_CIPHER:<version>:<iv_hex>:<authTag_hex>:<base64_ciphertext>
     * @returns {Promise<{ title: string, body: string }>}
     * @throws {VaultNotUnlockedError}   If the vault is locked
     * @throws {VaultDecryptionError}    If format is invalid, version unknown,
     *                                   password was wrong, or ciphertext tampered
     */
    async decrypt(encryptedPayload) {
        if (!this._vaultKey) throw new VaultNotUnlockedError();

        // Split on ':' — base64 uses only [A-Za-z0-9+/=], never ':'
        const parts = encryptedPayload.split(':');

        // Minimum: JOPLIN_CIPHER + version + iv + authTag + ciphertext = 5 segments
        if (parts.length < 5 || parts[0] !== VAULT_FORMAT_PREFIX) {
            throw new VaultDecryptionError(
                `Invalid vault format: expected "${VAULT_FORMAT_PREFIX}:<version>:<iv>:<authTag>:<ciphertext>", ` +
                `got ${parts.length} segment(s) with prefix "${parts[0]}"`
            );
        }

        const version = parts[1];
        if (version !== VAULT_FORMAT_VERSION) {
            throw new VaultDecryptionError(
                `Unsupported vault format version "${version}". ` +
                `Only version "${VAULT_FORMAT_VERSION}" is supported by this build.`
            );
        }

        const [, , ivHex, authTagHex, ...rest] = parts;
        const ciphertextBase64 = rest.join(':');  // defensive rejoin (base64 never has ':', but safe)

        const iv         = Buffer.from(ivHex,            'hex');
        const authTag    = Buffer.from(authTagHex,       'hex');
        const ciphertext = Buffer.from(ciphertextBase64, 'base64');

        if (iv.length !== IV_BYTES) {
            throw new VaultDecryptionError(
                `Invalid IV length: ${iv.length} byte(s), expected ${IV_BYTES}`
            );
        }
        if (authTag.length !== AUTH_TAG_LENGTH) {
            throw new VaultDecryptionError(
                `Invalid auth tag length: ${authTag.length} byte(s), expected ${AUTH_TAG_LENGTH}`
            );
        }

        try {
            const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, this._vaultKey, iv, {
                authTagLength: AUTH_TAG_LENGTH,
            });
            decipher.setAuthTag(authTag);

            const decrypted = Buffer.concat([
                decipher.update(ciphertext),
                decipher.final(),
            ]);

            const parsed = JSON.parse(decrypted.toString('utf8'));
            return { title: parsed.title, body: parsed.body };

        } catch (err) {
            // Node.js surfaces GCM auth-tag failures under several error codes
            if (
                err.code === 'ERR_OSSL_BAD_DECRYPT'        ||
                err.code === 'ERR_CRYPTO_INVALID_AUTH_TAG'  ||
                err.message.toLowerCase().includes('auth')  ||
                err.message.includes('Unsupported state')
            ) {
                throw new VaultDecryptionError(
                    'Decryption failed: wrong vault key or tampered data ' +
                    '(GCM authentication tag mismatch)'
                );
            }
            throw err;
        }
    }

    /**
     * Returns true if `body` is vault-encrypted (starts with JOPLIN_CIPHER:).
     *
     * Used by DecryptionWorker to detect vault notes after E2EE decryption:
     *   if (decryptedItem.body?.startsWith('JOPLIN_CIPHER:')) { ... }
     *
     * Prefix is intentionally distinct from Joplin's E2EE format — no ambiguity.
     *
     * @param {string} body
     * @returns {boolean}
     */
    isVaultEncrypted(body) {
        if (!body || typeof body !== 'string') return false;
        return body.startsWith(VAULT_FORMAT_PREFIX + ':');
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Derives a 256-bit key via PBKDF2-SHA512.
     * @private
     */
    static _deriveKey(password, salt) {
        return new Promise((resolve, reject) => {
            crypto.pbkdf2(
                password, salt,
                PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST,
                (err, key) => err ? reject(err) : resolve(key)
            );
        });
    }
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
    VaultService,
    VaultDecryptionError,
    VaultNotUnlockedError,
    VAULT_FORMAT_PREFIX,
    VAULT_FORMAT_VERSION,
};

// ── CLI Demo ──────────────────────────────────────────────────────────────────

if (require.main === module) {
    (async () => {
        console.log('╔══════════════════════════════════════════════════════╗');
        console.log('║     Joplin Vault Encryption — PoC Demo               ║');
        console.log('║     PBKDF2-SHA512 + AES-256-GCM + JOPLIN_CIPHER:1    ║');
        console.log('╚══════════════════════════════════════════════════════╝\n');

        const vault    = new VaultService();   // generates global salt (simulates Joplin settings)
        const password = 'my-secret-vault-password';
        const note     = {
            title: 'Medical Records',
            body:  'Blood type: O+\nAllergies: Penicillin\nLast checkup: 2026-01-15',
        };

        console.log('── Original note ───────────────────────────────────────');
        console.log(`  Title:       ${note.title}`);
        console.log(`  Body:        ${note.body.split('\n')[0]} ...`);
        console.log(`  Vault salt:  ${vault.vaultSalt.toString('hex')}  (stored in Joplin settings)`);
        console.log(`  isUnlocked:  ${vault.isUnlocked}\n`);

        // 1. Unlock — PBKDF2 runs once, key cached for the whole session
        console.log('── unlockVault() ────────────────────────────────────────');
        const t0 = Date.now();
        await vault.unlockVault(password);
        console.log(`  PBKDF2-SHA512 (100K iterations): ${Date.now() - t0} ms`);
        console.log(`  isUnlocked: ${vault.isUnlocked}\n`);

        // 2. Encrypt
        console.log('── encrypt() → JOPLIN_CIPHER:1:<iv>:<authTag>:<ciphertext> ─');
        const t1 = Date.now();
        const encrypted = await vault.encrypt(note);
        console.log(`  Time: ${Date.now() - t1} ms`);
        const fp = encrypted.split(':');
        console.log(`  Prefix:    ${fp[0]}`);
        console.log(`  Version:   ${fp[1]}`);
        console.log(`  IV:        ${fp[2]}  (${fp[2].length / 2} bytes)`);
        console.log(`  AuthTag:   ${fp[3]}  (${fp[3].length / 2} bytes)`);
        console.log(`  Ciphertext (preview): ${fp[4].substring(0, 40)}...`);
        console.log(`  isVaultEncrypted: ${vault.isVaultEncrypted(encrypted)}\n`);

        // 3. Decrypt (same vault instance — key already cached)
        console.log('── decrypt() ─────────────────────────────────────────────');
        const t2 = Date.now();
        const decrypted = await vault.decrypt(encrypted);
        console.log(`  Time: ${Date.now() - t2} ms`);
        console.log(`  Title: ${decrypted.title}`);
        console.log(`  Body:  ${decrypted.body.split('\n')[0]} ...`);
        console.log(`  Match: ${decrypted.title === note.title && decrypted.body === note.body}\n`);

        // 4. Cross-instance decrypt — simulates "same device, new app session"
        console.log('── Cross-instance decrypt (simulates new app session) ────');
        const vault2 = new VaultService(vault.vaultSalt);  // same global salt from Joplin settings
        await vault2.unlockVault(password);                 // same password → identical vault key
        const decrypted2 = await vault2.decrypt(encrypted);
        console.log(`  New VaultService instance, same salt + password`);
        console.log(`  Match: ${decrypted2.title === note.title && decrypted2.body === note.body}\n`);

        // 5. IV uniqueness — same content, same key → different IV and ciphertext each time
        console.log('── IV uniqueness ─────────────────────────────────────────');
        const enc1 = await vault.encrypt(note);
        const enc2 = await vault.encrypt(note);
        const iv1  = enc1.split(':')[2];
        const iv2  = enc2.split(':')[2];
        console.log(`  IV 1: ${iv1}`);
        console.log(`  IV 2: ${iv2}`);
        console.log(`  Different IVs: ${iv1 !== iv2}`);
        console.log(`  Different ciphertexts: ${enc1 !== enc2}\n`);

        // 6. Wrong password
        console.log('── Wrong password ────────────────────────────────────────');
        const vault3 = new VaultService(vault.vaultSalt);
        await vault3.unlockVault('wrong-password');
        try {
            await vault3.decrypt(encrypted);
            console.log('  ERROR: Should have thrown!');
        } catch (err) {
            console.log(`  Caught ${err.name}`);
            console.log(`  Message: ${err.message}\n`);
        }

        // 7. Lock and attempt encrypt
        console.log('── lockVault() ───────────────────────────────────────────');
        vault.lockVault();
        console.log(`  isUnlocked: ${vault.isUnlocked}`);
        try {
            await vault.encrypt(note);
        } catch (err) {
            console.log(`  Locked encrypt → ${err.name}: ${err.message}\n`);
        }

        console.log('╔══════════════════════════════════════════════════════╗');
        console.log('║  PoC Complete — all cryptographic primitives verified ║');
        console.log('╚══════════════════════════════════════════════════════╝');
    })();
}
