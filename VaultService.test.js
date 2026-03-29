/**
 * VaultService Test Suite
 *
 * 10 tests covering the complete single-key vault encryption PoC.
 * Zero external dependencies — runs with plain Node.js.
 *
 * Usage:
 *   node VaultService.test.js
 *
 * Tests:
 *   1.  Encrypt/decrypt roundtrip — unicode/emoji content
 *   2.  Encrypt/decrypt roundtrip — 10 MB payload
 *   3.  Cross-instance roundtrip — same salt + password, different VaultService instance
 *   4.  Wrong password → VaultDecryptionError
 *   5.  IV uniqueness — two encryptions of same data differ
 *   6.  Empty note { title: '', body: '' }
 *   7.  JOPLIN_CIPHER:1: format structure (5 segments, version field, lengths, encodings)
 *   8.  isVaultEncrypted() detection
 *   9.  Tampered ciphertext → VaultDecryptionError (auth tag mismatch)
 *   10. Locked vault → VaultNotUnlockedError; constructor rejects bad salt type/size
 *
 * Author: Manthan Nimodiya (GSoC 2026 — Joplin)
 */

'use strict';

const {
    VaultService,
    VaultDecryptionError,
    VaultNotUnlockedError,
    VAULT_FORMAT_PREFIX,
    VAULT_FORMAT_VERSION,
} = require('./VaultService');

// ── Tiny test harness ─────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log(`  ✅ ${name}`);
    } catch (err) {
        failed++;
        console.log(`  ❌ ${name}`);
        console.log(`     ${err.stack || err.message}`);
    }
}

function assert(condition, message) {
    if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, label) {
    if (actual !== expected) {
        throw new Error(
            `${label || 'Value'} mismatch:\n` +
            `  expected: ${JSON.stringify(expected)}\n` +
            `  actual:   ${JSON.stringify(actual)}`
        );
    }
}

// ── Helper: create + unlock a fresh vault ────────────────────────────────────

async function freshVault(password = 'test-password', saltBuf = undefined) {
    const vault = new VaultService(saltBuf);
    await vault.unlockVault(password);
    return vault;
}

// ── Test Suite ────────────────────────────────────────────────────────────────

(async () => {
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║       VaultService Test Suite  — 10 tests                ║');
    console.log('╚══════════════════════════════════════════════════════════╝\n');

    // ── Test 1: Roundtrip (unicode, emoji, multi-line) ────────────────────────
    await test('Encrypt/decrypt roundtrip preserves title and body (unicode)', async () => {
        const vault = await freshVault('test-password-1');
        const note  = {
            title: 'Sécrèt Nötë — 你好 🔐',
            body:  'Line 1: résumé\nLine 2: café\nLine 3: naïve\nEmoji: 🎉🎊',
        };

        const encrypted = await vault.encrypt(note);
        const decrypted = await vault.decrypt(encrypted);

        assertEqual(decrypted.title, note.title, 'Title');
        assertEqual(decrypted.body,  note.body,  'Body');
    });

    // ── Test 2: 10 MB payload ─────────────────────────────────────────────────
    await test('Encrypt/decrypt roundtrip — 10 MB payload', async () => {
        const vault     = await freshVault('large-payload-pw');
        const largeBody = 'X'.repeat(10 * 1024 * 1024);  // 10 MB
        const note      = { title: '10 MB Note', body: largeBody };

        const t0        = Date.now();
        const encrypted = await vault.encrypt(note);
        const encTime   = Date.now() - t0;

        const t1        = Date.now();
        const decrypted = await vault.decrypt(encrypted);
        const decTime   = Date.now() - t1;

        assertEqual(decrypted.title,       note.title,       'Title');
        assertEqual(decrypted.body.length, largeBody.length, 'Body length');
        assert(encTime < 10_000, `Encryption took ${encTime} ms — should be < 10 s`);
        assert(decTime < 10_000, `Decryption took ${decTime} ms — should be < 10 s`);
    });

    // ── Test 3: Cross-instance roundtrip (simulates persistent Joplin settings) ─
    await test('Cross-instance decrypt — same salt + password, different VaultService instance', async () => {
        // Simulate: Device A encrypts a note and syncs
        const vaultA    = await freshVault('shared-vault-password');
        const note      = { title: 'Synced Secret', body: 'Encrypted on Device A' };
        const encrypted = await vaultA.encrypt(note);

        // Simulate: Device B loads the same global salt from Joplin settings and creates
        // a new VaultService instance — key derivation must produce the identical vault key
        const sharedSalt = vaultA.vaultSalt;                            // ← from Joplin settings DB
        const vaultB     = await freshVault('shared-vault-password', sharedSalt);

        const decrypted = await vaultB.decrypt(encrypted);

        assertEqual(decrypted.title, note.title, 'Title (cross-instance)');
        assertEqual(decrypted.body,  note.body,  'Body (cross-instance)');

        // Also verify that a different password with the same salt CANNOT decrypt
        const vaultC = await freshVault('different-password', sharedSalt);
        let threw = false;
        try { await vaultC.decrypt(encrypted); } catch (e) { threw = true; }
        assert(threw, 'Different password with same salt must fail');
    });

    // ── Test 4: Wrong password → VaultDecryptionError ─────────────────────────
    await test('Wrong password throws VaultDecryptionError', async () => {
        const vault     = await freshVault('correct-password');
        const encrypted = await vault.encrypt({ title: 'Secret', body: 'Sensitive content' });

        // Same salt, wrong password → different derived key → GCM auth tag mismatch
        const vaultWrong = await freshVault('wrong-password', vault.vaultSalt);

        let threw = false;
        try {
            await vaultWrong.decrypt(encrypted);
        } catch (err) {
            threw = true;
            assert(
                err instanceof VaultDecryptionError,
                `Expected VaultDecryptionError, got ${err.constructor.name}: ${err.message}`
            );
            assert(
                err.message.toLowerCase().includes('wrong vault key') ||
                err.message.toLowerCase().includes('tampered'),
                `Error message should describe key mismatch: "${err.message}"`
            );
        }
        assert(threw, 'Should have thrown VaultDecryptionError for wrong password');
    });

    // ── Test 5: IV uniqueness ─────────────────────────────────────────────────
    await test('Each encryption generates a unique IV (same key, same plaintext)', async () => {
        const vault = await freshVault('iv-test-password');
        const note  = { title: 'Same title', body: 'Same body' };

        const enc1 = await vault.encrypt(note);
        const enc2 = await vault.encrypt(note);

        // Format: JOPLIN_CIPHER:1:<iv>:<authTag>:<ciphertext> — IV is at index 2
        const iv1 = enc1.split(':')[2];
        const iv2 = enc2.split(':')[2];

        assert(iv1 !== iv2,   `IVs must differ across encryptions: ${iv1} === ${iv2}`);
        assert(enc1 !== enc2, 'Full encrypted strings must differ');

        // Both must still decrypt correctly
        const dec1 = await vault.decrypt(enc1);
        const dec2 = await vault.decrypt(enc2);
        assertEqual(dec1.title, note.title, 'Decrypted title from enc1');
        assertEqual(dec2.title, note.title, 'Decrypted title from enc2');
    });

    // ── Test 6: Empty note ────────────────────────────────────────────────────
    await test('Empty note { title: "", body: "" } encrypts and decrypts correctly', async () => {
        const vault     = await freshVault('empty-note-pw');
        const note      = { title: '', body: '' };
        const encrypted = await vault.encrypt(note);
        const decrypted = await vault.decrypt(encrypted);

        assertEqual(decrypted.title, '', 'Title (empty)');
        assertEqual(decrypted.body,  '', 'Body (empty)');

        assert(encrypted.length > 50, 'Encrypted string should still have length > 50');
        assert(vault.isVaultEncrypted(encrypted), 'Empty note must still carry JOPLIN_CIPHER: prefix');
    });

    // ── Test 7: JOPLIN_CIPHER:1: format structure ─────────────────────────────
    await test('JOPLIN_CIPHER:1: format — 5 segments, version field, correct encodings', async () => {
        const vault     = await freshVault('format-test-pw');
        const encrypted = await vault.encrypt({ title: 'Format Test', body: 'Body text' });

        // Exactly 5 colon-separated segments:
        //   JOPLIN_CIPHER  :  1  :  <iv>  :  <authTag>  :  <ciphertext>
        //   [0]               [1]   [2]       [3]            [4]
        const parts = encrypted.split(':');
        assertEqual(parts.length, 5, 'Segment count');

        // Segment 0 — prefix
        assertEqual(parts[0], VAULT_FORMAT_PREFIX, 'Prefix constant');
        assertEqual(parts[0], 'JOPLIN_CIPHER',     'Literal prefix value');

        // Segment 1 — version
        assertEqual(parts[1], VAULT_FORMAT_VERSION, 'Version constant');
        assertEqual(parts[1], '1',                  'Literal version value');

        // Segment 2 — IV: 12 bytes → 24 lowercase hex chars
        assertEqual(parts[2].length, 24, 'IV hex length (12 bytes × 2)');
        assert(/^[0-9a-f]{24}$/.test(parts[2]), `IV must be lowercase hex: "${parts[2]}"`);

        // Segment 3 — AuthTag: 16 bytes → 32 lowercase hex chars
        assertEqual(parts[3].length, 32, 'AuthTag hex length (16 bytes × 2)');
        assert(/^[0-9a-f]{32}$/.test(parts[3]), `AuthTag must be lowercase hex: "${parts[3]}"`);

        // Segment 4 — Ciphertext: valid non-empty base64
        assert(parts[4].length > 0, 'Ciphertext must be non-empty');
        const decoded = Buffer.from(parts[4], 'base64');
        assert(decoded.length > 0, 'Ciphertext base64 must decode to non-empty buffer');

        // Salt must NOT appear in the payload (global salt is stored externally in Joplin settings)
        assertEqual(parts.length, 5, '5 segments — no 6th salt segment');
    });

    // ── Test 8: isVaultEncrypted() detection ──────────────────────────────────
    await test('isVaultEncrypted() correctly identifies JOPLIN_CIPHER: strings', async () => {
        const vault     = await freshVault('detection-pw');
        const encrypted = await vault.encrypt({ title: 'T', body: 'B' });

        // True cases
        assert(vault.isVaultEncrypted(encrypted) === true,
            'Should detect a real encrypted string');
        assert(vault.isVaultEncrypted('JOPLIN_CIPHER:1:aabbcc:ddeeff:SGVsbG8=') === true,
            'Should detect JOPLIN_CIPHER: prefix (manual v1)');

        // False cases
        assert(vault.isVaultEncrypted('Regular note body')    === false, 'Plain text');
        assert(vault.isVaultEncrypted('JEV01:old:format')     === false, 'Old JEV01 format');
        assert(vault.isVaultEncrypted('joplin_cipher:lower')  === false, 'Lowercase prefix (case-sensitive)');
        assert(vault.isVaultEncrypted('JOPLIN_CIPHER')        === false, 'Prefix with no trailing colon');
        assert(vault.isVaultEncrypted('')                     === false, 'Empty string');
        assert(vault.isVaultEncrypted(null)                   === false, 'null');
        assert(vault.isVaultEncrypted(undefined)              === false, 'undefined');
    });

    // ── Test 9: Tampered ciphertext → auth tag mismatch ───────────────────────
    await test('Tampered ciphertext is detected via GCM authentication tag', async () => {
        const vault     = await freshVault('tamper-test-pw');
        const encrypted = await vault.encrypt({ title: 'Tamper Test', body: 'Integrity check' });

        // Flip one character in the base64 ciphertext (last segment, index 4)
        const parts     = encrypted.split(':');
        const original  = parts[4];
        const flipped   = (original[0] === 'A' ? 'B' : 'A') + original.slice(1);
        parts[4]        = flipped;
        const tampered  = parts.join(':');

        let threw = false;
        try {
            await vault.decrypt(tampered);
        } catch (err) {
            threw = true;
            assert(
                err instanceof VaultDecryptionError,
                `Expected VaultDecryptionError, got ${err.constructor.name}`
            );
        }
        assert(threw, 'Modified ciphertext must throw VaultDecryptionError');

        // Original must still decrypt cleanly (key not affected)
        const clean = await vault.decrypt(encrypted);
        assertEqual(clean.body, 'Integrity check', 'Original ciphertext still valid after tamper attempt');
    });

    // ── Test 10: Locked vault + constructor validation ────────────────────────
    await test('Locked vault → VaultNotUnlockedError; bad salt → TypeError', async () => {
        // 10a: Never-unlocked vault rejects encrypt and decrypt
        const vault = new VaultService();

        let encThrew = false;
        try { await vault.encrypt({ title: 'T', body: 'B' }); }
        catch (err) {
            encThrew = true;
            assert(err instanceof VaultNotUnlockedError,
                `Expected VaultNotUnlockedError for encrypt, got ${err.constructor.name}`);
        }
        assert(encThrew, 'encrypt() on locked vault must throw VaultNotUnlockedError');

        let decThrew = false;
        try { await vault.decrypt('JOPLIN_CIPHER:1:aaa:bbb:ccc'); }
        catch (err) {
            decThrew = true;
            assert(err instanceof VaultNotUnlockedError,
                `Expected VaultNotUnlockedError for decrypt, got ${err.constructor.name}`);
        }
        assert(decThrew, 'decrypt() on locked vault must throw VaultNotUnlockedError');

        // 10b: Lock after unlock also prevents access
        await vault.unlockVault('some-password');
        assert(vault.isUnlocked, 'Vault should be unlocked after unlockVault()');
        vault.lockVault();
        assert(!vault.isUnlocked, 'Vault should be locked after lockVault()');

        // 10c: Constructor rejects wrong salt type
        let typeThrew = false;
        try { new VaultService('not-a-buffer'); }
        catch (err) {
            typeThrew = true;
            assert(err instanceof TypeError, `Expected TypeError, got ${err.constructor.name}`);
        }
        assert(typeThrew, 'Constructor must reject non-Buffer salt');

        // 10d: Constructor rejects wrong salt size
        let sizeThrew = false;
        try { new VaultService(Buffer.alloc(8)); }  // 8 bytes, expected 16
        catch (err) {
            sizeThrew = true;
            assert(err instanceof TypeError, `Expected TypeError for wrong size, got ${err.constructor.name}`);
        }
        assert(sizeThrew, 'Constructor must reject Buffer of wrong length');
    });

    // ── Summary ───────────────────────────────────────────────────────────────

    const total = passed + failed;
    console.log(`\n${'─'.repeat(58)}`);
    console.log(`  Results: ${passed} passed, ${failed} failed, ${total} total`);
    console.log(`${'─'.repeat(58)}`);

    if (failed > 0) {
        console.log('\n  ⚠  Some tests failed. See details above.\n');
        process.exit(1);
    } else {
        console.log('\n  All tests passed ✅\n');
    }
})();
