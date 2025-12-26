#!/usr/bin/env node
/**
 * Node.js test script for OpenABE-RABE WASM module
 *
 * Run with: node test-node.mjs
 */

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Load WASM module
const wasmPath = join(__dirname, 'pkg', 'openabe_rabe_bg.wasm');
const jsPath = join(__dirname, 'pkg', 'openabe_rabe.js');

console.log('OpenABE-RABE WASM Test (Node.js)');
console.log('================================\n');

try {
    // Dynamic import of the WASM bindings
    const wasmModule = await import(jsPath);

    // Read and instantiate the WASM
    const wasmBytes = await readFile(wasmPath);
    await wasmModule.default(wasmBytes);

    console.log('WASM module loaded successfully!\n');

    // Test 1: Basic WASM check
    console.log('Test 1: WASM Module Check');
    const testResult = wasmModule.test_wasm();
    console.log('  Result:', testResult);
    console.log('  Status: PASSED\n');

    // Test 2: BSW CP-ABE Roundtrip
    console.log('Test 2: BSW CP-ABE Roundtrip');
    const bswResult = wasmModule.test_bsw_roundtrip();
    if (bswResult.success) {
        console.log('  Result:', bswResult.data);
        console.log('  Status: PASSED\n');
    } else {
        console.log('  Error:', bswResult.error);
        console.log('  Status: FAILED\n');
        process.exit(1);
    }

    // Test 3: Manual BSW workflow
    console.log('Test 3: Manual BSW CP-ABE Workflow');

    // Setup
    console.log('  1. Setup...');
    const setupResult = wasmModule.bsw_setup();
    if (!setupResult.success) {
        throw new Error('Setup failed: ' + setupResult.error);
    }
    const keys = JSON.parse(setupResult.data);
    console.log('     OK');

    // Keygen
    console.log('  2. Keygen (attrs: role:admin, dept:eng)...');
    const keygenResult = wasmModule.bsw_keygen(
        JSON.stringify(keys.mpk),
        JSON.stringify(keys.msk),
        '["role:admin", "dept:eng"]'
    );
    if (!keygenResult.success) {
        throw new Error('Keygen failed: ' + keygenResult.error);
    }
    console.log('     OK');

    // Encrypt
    console.log('  3. Encrypt (policy: "role:admin" and "dept:eng")...');
    const plaintext = 'Hello from Node.js WASM!';
    const plaintextB64 = Buffer.from(plaintext).toString('base64');
    const encryptResult = wasmModule.bsw_encrypt(
        JSON.stringify(keys.mpk),
        '"role:admin" and "dept:eng"',
        plaintextB64
    );
    if (!encryptResult.success) {
        throw new Error('Encrypt failed: ' + encryptResult.error);
    }
    console.log('     OK');

    // Decrypt
    console.log('  4. Decrypt...');
    const decryptResult = wasmModule.bsw_decrypt(
        keygenResult.data,
        encryptResult.data
    );
    if (!decryptResult.success) {
        throw new Error('Decrypt failed: ' + decryptResult.error);
    }
    const decrypted = Buffer.from(decryptResult.data, 'base64').toString('utf-8');
    console.log('     OK');

    // Verify
    console.log('  5. Verify plaintext:', decrypted);
    if (decrypted !== plaintext) {
        throw new Error('Decrypted text does not match!');
    }
    console.log('  Status: PASSED\n');

    // Test 4: AC17 CP-ABE
    console.log('Test 4: AC17 CP-ABE Roundtrip');

    // Setup
    console.log('  1. Setup...');
    const ac17SetupResult = wasmModule.ac17_cp_setup();
    if (!ac17SetupResult.success) {
        throw new Error('AC17 Setup failed: ' + ac17SetupResult.error);
    }
    const ac17Keys = JSON.parse(ac17SetupResult.data);
    console.log('     OK');

    // Keygen
    console.log('  2. Keygen (attrs: A, B, C)...');
    const ac17KeygenResult = wasmModule.ac17_cp_keygen(
        JSON.stringify(ac17Keys.mpk),
        JSON.stringify(ac17Keys.msk),
        '["A", "B", "C"]'
    );
    if (!ac17KeygenResult.success) {
        throw new Error('AC17 Keygen failed: ' + ac17KeygenResult.error);
    }
    console.log('     OK');

    // Encrypt
    console.log('  3. Encrypt (policy: "A" and "B")...');
    const ac17Plaintext = 'AC17 secret message';
    const ac17PlaintextB64 = Buffer.from(ac17Plaintext).toString('base64');
    const ac17EncryptResult = wasmModule.ac17_cp_encrypt(
        JSON.stringify(ac17Keys.mpk),
        '"A" and "B"',
        ac17PlaintextB64
    );
    if (!ac17EncryptResult.success) {
        throw new Error('AC17 Encrypt failed: ' + ac17EncryptResult.error);
    }
    console.log('     OK');

    // Decrypt
    console.log('  4. Decrypt...');
    const ac17DecryptResult = wasmModule.ac17_cp_decrypt(
        ac17KeygenResult.data,
        ac17EncryptResult.data
    );
    if (!ac17DecryptResult.success) {
        throw new Error('AC17 Decrypt failed: ' + ac17DecryptResult.error);
    }
    const ac17Decrypted = Buffer.from(ac17DecryptResult.data, 'base64').toString('utf-8');
    console.log('     OK');

    // Verify
    console.log('  5. Verify plaintext:', ac17Decrypted);
    if (ac17Decrypted !== ac17Plaintext) {
        throw new Error('AC17 Decrypted text does not match!');
    }
    console.log('  Status: PASSED\n');

    // Test 5: AC17 KP-ABE (Key-Policy ABE)
    console.log('Test 5: AC17 KP-ABE Roundtrip');

    // Setup
    console.log('  1. Setup...');
    const ac17KpSetupResult = wasmModule.ac17_kp_setup();
    if (!ac17KpSetupResult.success) {
        throw new Error('AC17 KP-ABE Setup failed: ' + ac17KpSetupResult.error);
    }
    const ac17KpKeys = JSON.parse(ac17KpSetupResult.data);
    console.log('     OK');

    // Keygen (KP-ABE: key contains policy)
    console.log('  2. Keygen (policy: "A" and "B")...');
    const ac17KpKeygenResult = wasmModule.ac17_kp_keygen(
        JSON.stringify(ac17KpKeys.msk),
        '"A" and "B"'
    );
    if (!ac17KpKeygenResult.success) {
        throw new Error('AC17 KP-ABE Keygen failed: ' + ac17KpKeygenResult.error);
    }
    console.log('     OK');

    // Encrypt (KP-ABE: ciphertext contains attributes)
    console.log('  3. Encrypt (attrs: A, B)...');
    const kpPlaintext = 'KP-ABE secret message';
    const kpPlaintextB64 = Buffer.from(kpPlaintext).toString('base64');
    const ac17KpEncryptResult = wasmModule.ac17_kp_encrypt(
        JSON.stringify(ac17KpKeys.mpk),
        '["A", "B"]',
        kpPlaintextB64
    );
    if (!ac17KpEncryptResult.success) {
        throw new Error('AC17 KP-ABE Encrypt failed: ' + ac17KpEncryptResult.error);
    }
    console.log('     OK');

    // Decrypt
    console.log('  4. Decrypt...');
    const ac17KpDecryptResult = wasmModule.ac17_kp_decrypt(
        ac17KpKeygenResult.data,
        ac17KpEncryptResult.data
    );
    if (!ac17KpDecryptResult.success) {
        throw new Error('AC17 KP-ABE Decrypt failed: ' + ac17KpDecryptResult.error);
    }
    const kpDecrypted = Buffer.from(ac17KpDecryptResult.data, 'base64').toString('utf-8');
    console.log('     OK');

    // Verify
    console.log('  5. Verify plaintext:', kpDecrypted);
    if (kpDecrypted !== kpPlaintext) {
        throw new Error('AC17 KP-ABE Decrypted text does not match!');
    }
    console.log('  Status: PASSED\n');

    // Test 6: LSW KP-ABE
    console.log('Test 6: LSW KP-ABE Roundtrip');

    // Setup
    console.log('  1. Setup...');
    const lswSetupResult = wasmModule.lsw_setup();
    if (!lswSetupResult.success) {
        throw new Error('LSW KP-ABE Setup failed: ' + lswSetupResult.error);
    }
    const lswKeys = JSON.parse(lswSetupResult.data);
    console.log('     OK');

    // Keygen (KP-ABE: key contains policy)
    console.log('  2. Keygen (policy: "X" or "Y")...');
    const lswKeygenResult = wasmModule.lsw_keygen(
        JSON.stringify(lswKeys.mpk),
        JSON.stringify(lswKeys.msk),
        '"X" or "Y"'
    );
    if (!lswKeygenResult.success) {
        throw new Error('LSW KP-ABE Keygen failed: ' + lswKeygenResult.error);
    }
    console.log('     OK');

    // Encrypt (KP-ABE: ciphertext contains attributes)
    console.log('  3. Encrypt (attrs: X)...');
    const lswPlaintext = 'LSW KP-ABE secret';
    const lswPlaintextB64 = Buffer.from(lswPlaintext).toString('base64');
    const lswEncryptResult = wasmModule.lsw_encrypt(
        JSON.stringify(lswKeys.mpk),
        '["X"]',
        lswPlaintextB64
    );
    if (!lswEncryptResult.success) {
        throw new Error('LSW KP-ABE Encrypt failed: ' + lswEncryptResult.error);
    }
    console.log('     OK');

    // Decrypt
    console.log('  4. Decrypt...');
    const lswDecryptResult = wasmModule.lsw_decrypt(
        lswKeygenResult.data,
        lswEncryptResult.data
    );
    if (!lswDecryptResult.success) {
        throw new Error('LSW KP-ABE Decrypt failed: ' + lswDecryptResult.error);
    }
    const lswDecrypted = Buffer.from(lswDecryptResult.data, 'base64').toString('utf-8');
    console.log('     OK');

    // Verify
    console.log('  5. Verify plaintext:', lswDecrypted);
    if (lswDecrypted !== lswPlaintext) {
        throw new Error('LSW KP-ABE Decrypted text does not match!');
    }
    console.log('  Status: PASSED\n');

    // Summary
    console.log('================================');
    console.log('All tests PASSED!');
    console.log('  - BSW CP-ABE');
    console.log('  - AC17 CP-ABE');
    console.log('  - AC17 KP-ABE');
    console.log('  - LSW KP-ABE');
    console.log('================================');

} catch (error) {
    console.error('Test failed:', error.message);
    process.exit(1);
}
