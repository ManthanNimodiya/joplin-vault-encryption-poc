/**
 * VaultService Test Suite
 *
 * Tests for the JEV01 vault encryption proof-of-concept.
 * No test framework needed — runs with plain Node.js.
 *
 * Usage: node VaultService.test.js
 *
 * Author: Manthan Nimodiya (GSoC 2026 — Joplin)
 */

const { VaultService, VaultDecryptionError, VAULT_FORMAT_PREFIX } = require('./VaultService');

let passed = 0;
let failed = 0;

async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log(`  \u2705 ${name}`);
    } catch (err) {
        failed++;
        console.log(`  \u274C ${name}`);
        console.log(`     ${err.message}`);
    }
}

function assert(condition, message) {
    if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, label) {
    if (actual !== expected) {
        throw new Error(`${label || 'Values'}: expected "${expected}", got "${actual}"`);
    }
}

(async () => {
    console.log('=== VaultService Test Suite ===\n');

    // ── Test 1: Encrypt/Decrypt Roundtrip ──
    await test('Encrypt/decrypt roundtrip preserves title and body', async () => {
        const note = { title: 'Secret Title', body: 'Secret body with unicode: \u00E9\u00E0\u00FC \u4F60\u597D' };
        const password = 'test-password-123';

        const encrypted = await VaultService.encrypt(note, password);
        const decrypted = await VaultService.decrypt(encrypted, password);

        assertEqual(decrypted.title, note.title, 'Title');
        assertEqual(decrypted.body, note.body, 'Body');
    });

    // ── Test 2: Wrong Password Rejection ──
    await test('Wrong password throws VaultDecryptionError', async () => {
        const note = { title: 'Test', body: 'Test body' };
        const encrypted = await VaultService.encrypt(note, 'correct-password');

        let threw = false;
        try {
            await VaultService.decrypt(encrypted, 'wrong-password');
        } catch (err) {
            threw = true;
            assert(err instanceof VaultDecryptionError, `Expected VaultDecryptionError, got ${err.name}`);
            assert(err.message.includes('wrong password'), `Error message should mention wrong password: ${err.message}`);
        }
        assert(threw, 'Should have thrown VaultDecryptionError');
    });

    // ── Test 3: Unique Salt Per Encryption ──
    await test('Each encryption generates a unique salt', async () => {
        const note = { title: 'Same', body: 'Same content' };
        const password = 'same-password';

        const enc1 = await VaultService.encrypt(note, password);
        const enc2 = await VaultService.encrypt(note, password);

        const salt1 = enc1.split(':')[1];
        const salt2 = enc2.split(':')[1];

        assert(salt1 !== salt2, `Salts should differ: ${salt1} vs ${salt2}`);
        assert(enc1 !== enc2, 'Full encrypted strings should differ');
    });

    // ── Test 4: Empty Content ──
    await test('Empty title and body encrypt/decrypt correctly', async () => {
        const note = { title: '', body: '' };
        const password = 'empty-test';

        const encrypted = await VaultService.encrypt(note, password);
        const decrypted = await VaultService.decrypt(encrypted, password);

        assertEqual(decrypted.title, '', 'Title');
        assertEqual(decrypted.body, '', 'Body');
    });

    // ── Test 5: Large Payload (1 MB) ──
    await test('Large payload (1 MB) encrypts/decrypts correctly', async () => {
        const largeBody = 'A'.repeat(1024 * 1024); // 1 MB
        const note = { title: 'Large Note', body: largeBody };
        const password = 'large-test';

        const start = Date.now();
        const encrypted = await VaultService.encrypt(note, password);
        const encTime = Date.now() - start;

        const startDec = Date.now();
        const decrypted = await VaultService.decrypt(encrypted, password);
        const decTime = Date.now() - startDec;

        assertEqual(decrypted.body.length, largeBody.length, 'Body length');
        assertEqual(decrypted.title, 'Large Note', 'Title');
        assert(encTime < 5000, `Encryption took ${encTime}ms (should be < 5s)`);
        assert(decTime < 5000, `Decryption took ${decTime}ms (should be < 5s)`);
    });

    // ── Test 6: JEV01 Format Structure ──
    await test('JEV01 format has correct structure', async () => {
        const note = { title: 'Format Test', body: 'Body' };
        const encrypted = await VaultService.encrypt(note, 'format-test');

        const parts = encrypted.split(':');
        assertEqual(parts.length, 5, 'Field count');
        assertEqual(parts[0], 'JEV01', 'Prefix');

        // Salt: 16 bytes = 32 hex chars
        assertEqual(parts[1].length, 32, 'Salt hex length');
        assert(/^[0-9a-f]+$/.test(parts[1]), 'Salt should be lowercase hex');

        // IV: 12 bytes = 24 hex chars
        assertEqual(parts[2].length, 24, 'IV hex length');
        assert(/^[0-9a-f]+$/.test(parts[2]), 'IV should be lowercase hex');

        // AuthTag: 16 bytes = 32 hex chars
        assertEqual(parts[3].length, 32, 'AuthTag hex length');
        assert(/^[0-9a-f]+$/.test(parts[3]), 'AuthTag should be lowercase hex');

        // Ciphertext: valid base64
        assert(parts[4].length > 0, 'Ciphertext should not be empty');
        const decoded = Buffer.from(parts[4], 'base64');
        assert(decoded.length > 0, 'Ciphertext should decode from base64');
    });

    // ── Test 7: isVaultEncrypted Detection ──
    await test('isVaultEncrypted() correctly identifies JEV01 strings', async () => {
        const encrypted = await VaultService.encrypt({ title: 'T', body: 'B' }, 'pw');

        assert(VaultService.isVaultEncrypted(encrypted) === true, 'Should detect JEV01');
        assert(VaultService.isVaultEncrypted('JEV01:abc:def:ghi:jkl') === true, 'Should detect JEV01 prefix');
        assert(VaultService.isVaultEncrypted('Regular note body') === false, 'Should reject plain text');
        assert(VaultService.isVaultEncrypted('') === false, 'Should reject empty string');
        assert(VaultService.isVaultEncrypted(null) === false, 'Should reject null');
        assert(VaultService.isVaultEncrypted(undefined) === false, 'Should reject undefined');
        assert(VaultService.isVaultEncrypted('JEV02:something') === false, 'Should reject other versions');
    });

    // ── Test 8: Tampered Ciphertext Detection ──
    await test('Tampered ciphertext is detected via auth tag', async () => {
        const note = { title: 'Tamper Test', body: 'Original body' };
        const encrypted = await VaultService.encrypt(note, 'tamper-password');

        // Modify one character in the ciphertext (last field)
        const parts = encrypted.split(':');
        const ciphertext = parts[4];
        const tamperedChar = ciphertext[0] === 'A' ? 'B' : 'A';
        parts[4] = tamperedChar + ciphertext.slice(1);
        const tampered = parts.join(':');

        let threw = false;
        try {
            await VaultService.decrypt(tampered, 'tamper-password');
        } catch (err) {
            threw = true;
            assert(err instanceof VaultDecryptionError, `Expected VaultDecryptionError, got ${err.name}`);
        }
        assert(threw, 'Should detect tampered ciphertext');
    });

    // ── Summary ──
    console.log(`\n${'='.repeat(40)}`);
    console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
    console.log(`${'='.repeat(40)}`);

    if (failed > 0) process.exit(1);
})();
