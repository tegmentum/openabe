#!/usr/bin/env node
// Decrypt a native-encrypted ciphertext using WASM

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const skPath = process.argv[2] || '/tmp/user.key';
const ctPath = process.argv[3] || '/tmp/cipher.json';

console.log('Cross-Platform WASM Decrypt Test');
console.log('=================================');
console.log('SK file:', skPath);
console.log('CT file:', ctPath);
console.log('');

try {
    const wasmPath = join(__dirname, 'pkg', 'openabe_rabe_bg.wasm');
    const jsPath = join(__dirname, 'pkg', 'openabe_rabe.js');

    const wasmModule = await import(jsPath);
    const wasmBytes = await readFile(wasmPath);
    await wasmModule.default(wasmBytes);
    console.log('WASM module loaded');

    const skJson = await readFile(skPath, 'utf-8');
    const ctJson = await readFile(ctPath, 'utf-8');
    console.log('Key and ciphertext loaded');

    console.log('Decrypting...');
    const result = wasmModule.bsw_decrypt(skJson, ctJson);

    if (result.success) {
        const plaintext = Buffer.from(result.data, 'base64').toString('utf-8');
        console.log('');
        console.log('Decrypted plaintext:', plaintext);
        console.log('');
        console.log('Cross-platform decrypt PASSED!');
    } else {
        console.error('Decryption failed:', result.error);
        process.exit(1);
    }
} catch (e) {
    console.error('Error:', e.message);
    process.exit(1);
}
