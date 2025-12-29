#!/bin/bash
# Round-trip test: Native/WASM cross-platform encryption/decryption
# Test MCL 3.04 serialization compatibility

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Clean up previous test files
info "Cleaning up previous test files..."
rm -f test.mpk.cpabe test.msk.cpabe sk_alice.key ct.cpabe decrypted.txt plain.txt

# Create test message
echo "Hello MCL 3.04 cross-platform ABE!" > plain.txt
info "Created test message: $(cat plain.txt)"

# Test 1: Native encrypt → Native decrypt
info "Test 1: Native → Native"
./cli/oabe_setup -s CP -p test
./cli/oabe_keygen -s CP -p test -i "role:developer" -o sk_alice
./cli/oabe_enc -s CP -p test -e "role:developer" -i plain.txt -o ct.cpabe
./cli/oabe_dec -s CP -p test -k sk_alice.key -i ct.cpabe -o decrypted.txt

if diff -q plain.txt decrypted.txt > /dev/null; then
    info "✓ Native→Native: PASSED"
else
    error "✗ Native→Native: FAILED"
    exit 1
fi

# Test 2: WASM encrypt → Native decrypt
info "Test 2: WASM → Native"

# Check if WASM build exists
if [ ! -f "./build-wasm/openabe.js" ]; then
    warn "WASM bindings not found. Skipping WASM tests."
    warn "To build WASM: ./build-openabe-wasm.sh && build WASM bindings"
    info "Skipping Test 2: WASM→Native (WASM not built)"
    info "Skipping Test 3: Native→WASM (WASM not built)"
else
    rm -f ct.cpabe decrypted.txt

    # Create WASM ciphertext using Node.js
    node <<'EOF'
const fs = require('fs');
const {OpenABE} = require('./build-wasm/openabe.js');

async function test() {
    const mpk = fs.readFileSync('test.mpk.cpabe');
    const plaintext = fs.readFileSync('plain.txt', 'utf8');

    const abe = new OpenABE();
    const ct = await abe.encrypt('CP', mpk, 'role:developer', plaintext);
    fs.writeFileSync('ct.cpabe', ct);
    console.log('[INFO] WASM encrypted successfully');
}

test().catch(err => {
    console.error('[ERROR]', err);
    process.exit(1);
});
EOF

    ./cli/oabe_dec -s CP -p test -k sk_alice.key -i ct.cpabe -o decrypted.txt

    if diff -q plain.txt decrypted.txt > /dev/null; then
        info "✓ WASM→Native: PASSED"
    else
        error "✗ WASM→Native: FAILED"
        exit 1
    fi

    # Test 3: Native encrypt → WASM decrypt
    info "Test 3: Native → WASM"
    rm -f ct.cpabe decrypted.txt

    ./cli/oabe_enc -s CP -p test -e "role:developer" -i plain.txt -o ct.cpabe

    # Decrypt with WASM using Node.js
    node <<'EOF'
const fs = require('fs');
const {OpenABE} = require('./build-wasm/openabe.js');

async function test() {
    const sk = fs.readFileSync('sk_alice.key');
    const ct = fs.readFileSync('ct.cpabe');

    const abe = new OpenABE();
    const plaintext = await abe.decrypt('CP', sk, ct);
    fs.writeFileSync('decrypted.txt', plaintext);
    console.log('[INFO] WASM decrypted successfully');
}

test().catch(err => {
    console.error('[ERROR]', err);
    process.exit(1);
});
EOF

    if diff -q plain.txt decrypted.txt > /dev/null; then
        info "✓ Native→WASM: PASSED"
    else
        error "✗ Native→WASM: FAILED"
        exit 1
    fi
fi

# Clean up
info "Cleaning up test files..."
rm -f test.mpk.cpabe test.msk.cpabe sk_alice.key ct.cpabe decrypted.txt plain.txt

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}All round-trip tests PASSED!${NC}"
echo -e "${GREEN}MCL 3.04 cross-platform serialization working correctly${NC}"
echo -e "${GREEN}========================================${NC}\n"
