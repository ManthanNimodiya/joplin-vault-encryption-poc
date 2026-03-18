/**
 * VaultService — Per-Note Vault Encryption for Joplin
 *
 * Proof-of-concept implementing the JEV01 encrypted format.
 * Uses only Node.js built-in `crypto` — zero external dependencies.
 *
 * Cryptographic design:
 *   Key derivation:  PBKDF2-SHA512, 100,000 iterations, random 128-bit salt
 *   Cipher:          AES-256-GCM, random 96-bit IV, 128-bit auth tag
 *   Payload:         JSON.stringify({ title, body })
 *   Format:          JEV01:<salt_hex>:<iv_hex>:<authTag_hex>:<base64_ciphertext>
 *
 * Author: Manthan Nimodiya (GSoC 2026 — Joplin)
 */

const crypto = require('crypto');

const VAULT_FORMAT_PREFIX = 'JEV01';
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 32;        // 256 bits for AES-256
const PBKDF2_DIGEST = 'sha512';
const SALT_BYTES = 16;            // 128-bit salt
const IV_BYTES = 12;              // 96-bit IV (recommended for GCM)
const AUTH_TAG_LENGTH = 16;       // 128-bit auth tag
const CIPHER_ALGORITHM = 'aes-256-gcm';

class VaultDecryptionError extends Error {
    constructor(message) {
        super(message);
        this.name = 'VaultDecryptionError';
    }
}

class VaultService {

    /**
     * Derives a 256-bit key from a password using PBKDF2-SHA512.
     *
     * @param {string} password - User-provided vault password
     * @param {Buffer} salt - Random 128-bit salt
     * @returns {Promise<Buffer>} 256-bit derived key
     */
    static deriveKey(password, salt) {
        return new Promise((resolve, reject) => {
            crypto.pbkdf2(
                password,
                salt,
                PBKDF2_ITERATIONS,
                PBKDF2_KEYLEN,
                PBKDF2_DIGEST,
                (err, derivedKey) => {
                    if (err) reject(err);
                    else resolve(derivedKey);
                }
            );
        });
    }

    /**
     * Encrypts a note's title and body into a JEV01 formatted string.
     *
     * @param {{ title: string, body: string }} payload - Note content
     * @param {string} password - User-provided vault password
     * @returns {Promise<string>} JEV01 formatted encrypted string
     */
    static async encrypt(payload, password) {
        if (!password || typeof password !== 'string') {
            throw new Error('Password must be a non-empty string');
        }

        // Generate random salt and IV
        const salt = crypto.randomBytes(SALT_BYTES);
        const iv = crypto.randomBytes(IV_BYTES);

        // Derive key from password
        const key = await VaultService.deriveKey(password, salt);

        // Serialize payload to JSON
        const plaintext = JSON.stringify({
            title: payload.title || '',
            body: payload.body || '',
        });

        // Encrypt with AES-256-GCM
        const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, key, iv, {
            authTagLength: AUTH_TAG_LENGTH,
        });

        const encrypted = Buffer.concat([
            cipher.update(plaintext, 'utf8'),
            cipher.final(),
        ]);

        const authTag = cipher.getAuthTag();

        // Encode to JEV01 format
        const jev01String = [
            VAULT_FORMAT_PREFIX,
            salt.toString('hex'),
            iv.toString('hex'),
            authTag.toString('hex'),
            encrypted.toString('base64'),
        ].join(':');

        return jev01String;
    }

    /**
     * Decrypts a JEV01 formatted string back into title and body.
     *
     * @param {string} jev01String - JEV01 formatted encrypted string
     * @param {string} password - User-provided vault password
     * @returns {Promise<{ title: string, body: string }>} Decrypted note content
     * @throws {VaultDecryptionError} If password is wrong or data is tampered
     */
    static async decrypt(jev01String, password) {
        if (!password || typeof password !== 'string') {
            throw new Error('Password must be a non-empty string');
        }

        // Parse JEV01 format
        const parts = jev01String.split(':');
        if (parts.length !== 5 || parts[0] !== VAULT_FORMAT_PREFIX) {
            throw new VaultDecryptionError(
                `Invalid vault format: expected JEV01 prefix with 5 fields, got ${parts.length} fields`
            );
        }

        const [, saltHex, ivHex, authTagHex, ciphertextBase64] = parts;

        const salt = Buffer.from(saltHex, 'hex');
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const ciphertext = Buffer.from(ciphertextBase64, 'base64');

        // Validate parsed lengths
        if (salt.length !== SALT_BYTES) {
            throw new VaultDecryptionError(`Invalid salt length: ${salt.length} bytes (expected ${SALT_BYTES})`);
        }
        if (iv.length !== IV_BYTES) {
            throw new VaultDecryptionError(`Invalid IV length: ${iv.length} bytes (expected ${IV_BYTES})`);
        }
        if (authTag.length !== AUTH_TAG_LENGTH) {
            throw new VaultDecryptionError(`Invalid auth tag length: ${authTag.length} bytes (expected ${AUTH_TAG_LENGTH})`);
        }

        // Derive key from password
        const key = await VaultService.deriveKey(password, salt);

        // Decrypt with AES-256-GCM
        try {
            const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, key, iv, {
                authTagLength: AUTH_TAG_LENGTH,
            });
            decipher.setAuthTag(authTag);

            const decrypted = Buffer.concat([
                decipher.update(ciphertext),
                decipher.final(),
            ]);

            const parsed = JSON.parse(decrypted.toString('utf8'));

            return {
                title: parsed.title,
                body: parsed.body,
            };
        } catch (err) {
            if (err.code === 'ERR_OSSL_BAD_DECRYPT' || err.message.includes('auth')) {
                throw new VaultDecryptionError(
                    'Decryption failed: wrong password or tampered data (GCM authentication tag mismatch)'
                );
            }
            throw err;
        }
    }

    /**
     * Checks if a note body string is vault-encrypted by testing for the JEV01 prefix.
     *
     * @param {string} body - Note body string to check
     * @returns {boolean} True if the body starts with JEV01
     */
    static isVaultEncrypted(body) {
        if (!body || typeof body !== 'string') return false;
        return body.startsWith(VAULT_FORMAT_PREFIX + ':');
    }
}

module.exports = { VaultService, VaultDecryptionError, VAULT_FORMAT_PREFIX };

// ── CLI Demo ──
if (require.main === module) {
    (async () => {
        console.log('=== Joplin Vault Encryption PoC ===\n');

        const password = 'my-secret-vault-password';
        const note = {
            title: 'Medical Records',
            body: 'Blood type: O+\nAllergies: Penicillin\nLast checkup: 2026-01-15',
        };

        console.log('Original note:');
        console.log(`  Title: ${note.title}`);
        console.log(`  Body:  ${note.body.split('\n')[0]}...`);
        console.log();

        // Encrypt
        console.log('Encrypting with PBKDF2-SHA512 (100K iterations) + AES-256-GCM...');
        const startEnc = Date.now();
        const encrypted = await VaultService.encrypt(note, password);
        const encTime = Date.now() - startEnc;
        console.log(`  Time: ${encTime}ms`);
        console.log(`  Format: ${encrypted.substring(0, 80)}...`);
        console.log(`  Length: ${encrypted.length} chars`);
        console.log(`  isVaultEncrypted: ${VaultService.isVaultEncrypted(encrypted)}`);
        console.log();

        // Decrypt with correct password
        console.log('Decrypting with correct password...');
        const startDec = Date.now();
        const decrypted = await VaultService.decrypt(encrypted, password);
        const decTime = Date.now() - startDec;
        console.log(`  Time: ${decTime}ms`);
        console.log(`  Title: ${decrypted.title}`);
        console.log(`  Body:  ${decrypted.body.split('\n')[0]}...`);
        console.log(`  Match: ${decrypted.title === note.title && decrypted.body === note.body}`);
        console.log();

        // Decrypt with wrong password
        console.log('Decrypting with wrong password...');
        try {
            await VaultService.decrypt(encrypted, 'wrong-password');
            console.log('  ERROR: Should have thrown!');
        } catch (err) {
            console.log(`  Caught: ${err.name}: ${err.message}`);
        }
        console.log();

        // Unique salt verification
        console.log('Verifying unique salt per encryption...');
        const enc1 = await VaultService.encrypt(note, password);
        const enc2 = await VaultService.encrypt(note, password);
        const salt1 = enc1.split(':')[1];
        const salt2 = enc2.split(':')[1];
        console.log(`  Salt 1: ${salt1}`);
        console.log(`  Salt 2: ${salt2}`);
        console.log(`  Different: ${salt1 !== salt2}`);

        console.log('\n=== PoC Complete ===');
    })();
}
