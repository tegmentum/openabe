#!/usr/bin/env node
/**
 * Node.js test script for OpenABE-RABE WASM module (BLS12-381)
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

console.log('OpenABE-RABE WASM Test (BLS12-381)');
console.log('==================================\n');

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

    // Test 2: Verify curve
    console.log('Test 2: Verify Curve');
    const curve = wasmModule.get_curve();
    console.log('  Curve:', curve);
    if (curve !== 'BLS12-381') {
        throw new Error('Expected BLS12-381 curve');
    }
    console.log('  Status: PASSED\n');

    // Test 3: BSW CP-ABE Roundtrip
    console.log('Test 3: BSW CP-ABE Roundtrip (BLS12-381)');
    const bswResult = wasmModule.test_bsw_roundtrip();
    if (bswResult.success) {
        console.log('  Result:', bswResult.data);
        console.log('  Status: PASSED\n');
    } else {
        console.log('  Error:', bswResult.error);
        console.log('  Status: FAILED\n');
        process.exit(1);
    }

    // Test 4: Manual BSW workflow
    console.log('Test 4: Manual BSW CP-ABE Workflow');

    // Setup
    console.log('  1. Setup...');
    const setupResult = wasmModule.bsw_setup();
    if (!setupResult.success) {
        throw new Error('Setup failed: ' + setupResult.error);
    }
    const keys = JSON.parse(setupResult.data);
    console.log('     OK (scheme:', keys.mpk.scheme + ')');

    // Keygen
    console.log('  2. Keygen (attrs: admin, dept:eng)...');
    const keygenResult = wasmModule.bsw_keygen(
        JSON.stringify(keys.mpk),
        JSON.stringify(keys.msk),
        '["admin", "dept:eng"]'
    );
    if (!keygenResult.success) {
        throw new Error('Keygen failed: ' + keygenResult.error);
    }
    console.log('     OK');

    // Encrypt
    console.log('  3. Encrypt (policy: admin, dept:eng)...');
    const plaintext = 'Hello from BLS12-381 WASM!';
    const plaintextB64 = Buffer.from(plaintext).toString('base64');
    const encryptResult = wasmModule.bsw_encrypt(
        JSON.stringify(keys.mpk),
        'admin, dept:eng',
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

    // Test 5: Policy not satisfied
    console.log('Test 5: Policy Not Satisfied');

    // Create a key with different attributes
    console.log('  1. Keygen (attrs: user)...');
    const userKeyResult = wasmModule.bsw_keygen(
        JSON.stringify(keys.mpk),
        JSON.stringify(keys.msk),
        '["user"]'
    );
    if (!userKeyResult.success) {
        throw new Error('User keygen failed: ' + userKeyResult.error);
    }
    console.log('     OK');

    // Try to decrypt with wrong key
    console.log('  2. Attempt decrypt with wrong key...');
    const failDecryptResult = wasmModule.bsw_decrypt(
        userKeyResult.data,
        encryptResult.data
    );
    if (failDecryptResult.success) {
        throw new Error('Decryption should have failed!');
    }
    console.log('     Correctly rejected: policy not satisfied');
    console.log('  Status: PASSED\n');

    // Summary
    console.log('==================================');
    console.log('All tests PASSED!');
    console.log('  - Curve: BLS12-381 (128-bit security)');
    console.log('  - Scheme: BSW CP-ABE');
    console.log('==================================');

} catch (error) {
    console.error('Test failed:', error.message);
    process.exit(1);
}
