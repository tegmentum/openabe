#!/bin/bash
# Cross-platform test: Native encrypt → WASM decrypt

set -e

echo "================================"
echo "Cross-Platform Roundtrip Test"
echo "Native CLI → WASM Module"
echo "================================"
echo ""

cd "$(dirname "$0")"

# Create temp directory
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "1. Setup (Native CLI)..."
./target/release/openabe-rabe-cli setup --scheme bsw \
    --mpk "$TMPDIR/mpk.json" \
    --msk "$TMPDIR/msk.json" 2>&1 | grep -v "^Generating\|^Master\|^Setup"
echo "   OK"

echo "2. Keygen (Native CLI)..."
./target/release/openabe-rabe-cli keygen --scheme bsw \
    --mpk "$TMPDIR/mpk.json" \
    --msk "$TMPDIR/msk.json" \
    --attrs "role:admin,dept:engineering" \
    --sk "$TMPDIR/user.key" 2>&1 | grep -v "^Generating\|^User\|^Keygen"
echo "   OK"

echo "3. Encrypt (Native CLI)..."
echo "Hello from native, decrypted by WASM!" > "$TMPDIR/plain.txt"
./target/release/openabe-rabe-cli encrypt --scheme bsw \
    --mpk "$TMPDIR/mpk.json" \
    --policy '"role:admin" and "dept:engineering"' \
    --input "$TMPDIR/plain.txt" \
    --output "$TMPDIR/cipher.json" 2>&1 | grep -v "^Encrypting\|^Ciphertext\|^Encryption"
echo "   OK"

echo "4. Decrypt (WASM via Node.js)..."

# Create Node.js script for WASM decryption
cat > "$TMPDIR/wasm-decrypt.mjs" << 'NODESCRIPT'
import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const args = process.argv.slice(2);
const skPath = args[0];
const ctPath = args[1];

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmDir = process.env.WASM_DIR || __dirname;

const wasmPath = join(wasmDir, 'pkg', 'openabe_rabe_bg.wasm');
const jsPath = join(wasmDir, 'pkg', 'openabe_rabe.js');

try {
    const wasmModule = await import(jsPath);
    const wasmBytes = await readFile(wasmPath);
    await wasmModule.default(wasmBytes);

    const skJson = await readFile(skPath, 'utf-8');
    const ctJson = await readFile(ctPath, 'utf-8');

    const result = wasmModule.bsw_decrypt(skJson, ctJson);
    if (!result.success) {
        console.error('Decryption failed:', result.error);
        process.exit(1);
    }

    const plaintext = Buffer.from(result.data, 'base64').toString('utf-8');
    console.log(plaintext);
} catch (e) {
    console.error('Error:', e.message);
    process.exit(1);
}
NODESCRIPT

WASM_DIR="$(pwd)" node "$TMPDIR/wasm-decrypt.mjs" "$TMPDIR/user.key" "$TMPDIR/cipher.json" > "$TMPDIR/decrypted.txt" 2>/dev/null
echo "   OK"

echo "5. Verify..."
ORIGINAL=$(cat "$TMPDIR/plain.txt")
DECRYPTED=$(cat "$TMPDIR/decrypted.txt")

if [ "$ORIGINAL" = "$DECRYPTED" ]; then
    echo "   Original:  $ORIGINAL"
    echo "   Decrypted: $DECRYPTED"
    echo ""
    echo "================================"
    echo "Cross-Platform Test PASSED!"
    echo "================================"
else
    echo "   Original:  $ORIGINAL"
    echo "   Decrypted: $DECRYPTED"
    echo ""
    echo "================================"
    echo "Cross-Platform Test FAILED!"
    echo "================================"
    exit 1
fi
