# Makefile for rabe-abe
# Attribute-Based Encryption library with WASM Component support

.PHONY: all build test clean wasm wasm-release native native-release help

# Default target
all: native wasm

# Native build
native:
	cargo build --lib

native-release:
	cargo build --lib --release

# Native CLI
cli:
	cargo build --bin rabe-cli

cli-release:
	cargo build --bin rabe-cli --release

# Run tests
test:
	cargo test

# WASM Component builds (WASI Preview 2)
wasm:
	cargo build --lib --target wasm32-wasip2 --features wasm --no-default-features

wasm-release:
	cargo build --lib --target wasm32-wasip2 --features wasm --no-default-features --release

# WASM CLI Component (wasi:cli)
wasm-cli:
	cargo build --bin rabe-cli --target wasm32-wasip2

wasm-cli-release:
	cargo build --bin rabe-cli --target wasm32-wasip2 --release

# Validate WASM component
wasm-validate: wasm-cli-release
	wasm-tools validate --features component-model target/wasm32-wasip2/release/rabe-cli.wasm

# Test WASM CLI with wasmtime
wasm-test: wasm-cli-release
	@echo "Testing WASM CLI with wasmtime..."
	@mkdir -p /tmp/rabe-wasm-test
	@echo "Hello WASM ABE!" > /tmp/rabe-wasm-test/plaintext.txt
	@cd /tmp/rabe-wasm-test && \
		wasmtime run --dir=. $(CURDIR)/target/wasm32-wasip2/release/rabe-cli.wasm setup -s waters -p mpk.cbor -m msk.cbor && \
		wasmtime run --dir=. $(CURDIR)/target/wasm32-wasip2/release/rabe-cli.wasm keygen -s waters -p mpk.cbor -m msk.cbor -o sk.cbor -a "admin,developer" && \
		wasmtime run --dir=. $(CURDIR)/target/wasm32-wasip2/release/rabe-cli.wasm encrypt -s waters -p mpk.cbor -a "(admin AND developer)" -i plaintext.txt -o ct.cbor && \
		wasmtime run --dir=. $(CURDIR)/target/wasm32-wasip2/release/rabe-cli.wasm decrypt -s waters -p mpk.cbor -k sk.cbor -i ct.cbor -o decrypted.txt && \
		echo "=== WASM ABE Test ===" && \
		echo "Original: $$(cat plaintext.txt)" && \
		echo "Decrypted: $$(cat decrypted.txt)" && \
		diff -q plaintext.txt decrypted.txt && echo "SUCCESS: WASM ABE test passed!"
	@rm -rf /tmp/rabe-wasm-test

# Clean build artifacts
clean:
	cargo clean

# Install WASM targets (one-time setup)
setup-wasm:
	rustup target add wasm32-unknown-unknown
	rustup target add wasm32-wasip1
	rustup target add wasm32-wasip2

# Show WASM binary sizes
sizes: wasm-cli-release
	@echo "=== WASM Component Sizes ==="
	@ls -lh target/wasm32-wasip2/release/*.wasm 2>/dev/null || echo "No WASM binaries found"

# Help
help:
	@echo "rabe-abe Makefile targets:"
	@echo ""
	@echo "  Native builds:"
	@echo "    native          - Build library (debug)"
	@echo "    native-release  - Build library (release)"
	@echo "    cli             - Build CLI (debug)"
	@echo "    cli-release     - Build CLI (release)"
	@echo "    test            - Run all tests"
	@echo ""
	@echo "  WASM Component builds (WASI Preview 2):"
	@echo "    wasm            - Build library for WASM (debug)"
	@echo "    wasm-release    - Build library for WASM (release)"
	@echo "    wasm-cli        - Build CLI component (debug)"
	@echo "    wasm-cli-release - Build CLI component (release)"
	@echo "    wasm-validate   - Validate WASM component"
	@echo "    wasm-test       - Test WASM CLI with wasmtime"
	@echo ""
	@echo "  Utilities:"
	@echo "    setup-wasm      - Install WASM targets"
	@echo "    sizes           - Show WASM binary sizes"
	@echo "    clean           - Clean build artifacts"
	@echo "    help            - Show this help"
