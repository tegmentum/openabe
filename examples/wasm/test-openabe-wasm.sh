#!/bin/bash
# Complete OpenABE WASM workflow test
cd /Users/zacharywhitley/git/openabe-wasm

echo "=== Step 1: Setup (Generate Master Keys) ==="
wasmtime --dir=. cli-wasm/oabe_setup.wasm -s CP

echo ""
echo "=== Step 2: Generate User Key ==="
wasmtime --dir=. cli-wasm/oabe_keygen.wasm -s CP -i "alice|manager" -o alice.key

echo ""
echo "=== Step 3: Create Message ==="
echo "Secret message for managers!" > message.txt
cat message.txt

echo ""
echo "=== Step 4: Encrypt ==="
wasmtime --dir=. cli-wasm/oabe_enc.wasm -s CP -e "(alice and manager)" -i message.txt -o message.ct

echo ""
echo "=== Step 5: Decrypt ==="
wasmtime --dir=. cli-wasm/oabe_dec.wasm -s CP -k alice.key -i message.ct -o decrypted.txt

echo ""
echo "=== Step 6: Verify Decryption ==="
cat decrypted.txt

echo ""
echo "=== Generated Files ==="
ls -lh *.cpabe *.key *.ct *.txt 2>/dev/null
