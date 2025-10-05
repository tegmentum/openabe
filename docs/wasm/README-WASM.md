# OpenABE WebAssembly Build

This directory contains a complete WebAssembly build configuration for OpenABE using WASI-SDK, including full support for **Multi-Authority ABE (MA-ABE)**.

## ✨ Features

- ✅ **CP-ABE** (Ciphertext-Policy Attribute-Based Encryption)
- ✅ **KP-ABE** (Key-Policy Attribute-Based Encryption)
- ✅ **MA-ABE** (Multi-Authority Attribute-Based Encryption)
- ✅ **PK** (Standard Public-Key Encryption)
- ✅ JavaScript/TypeScript bindings
- ✅ Browser and Node.js support
- ✅ Complete key management (export/import/delete)
- ✅ Interactive HTML demos

## 🚀 Quick Start

### 1. Install WASI-SDK

```bash
# macOS
curl -LO https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-21/wasi-sdk-21.0-macos.tar.gz
tar xzf wasi-sdk-21.0-macos.tar.gz
sudo mv wasi-sdk-21.0 /opt/wasi-sdk

# Or use the helper script
./wasm-build.sh --install-sdk
```

### 2. Build Dependencies

```bash
./build-deps-wasm.sh
```

This builds GMP, OpenSSL, and RELIC for WebAssembly.

### 3. Build OpenABE

```bash
./build-openabe-wasm.sh
```

Output: `build-wasm/openabe.wasm`

### 4. (Optional) Build as WebAssembly Component

To create a standards-compliant WebAssembly Component:

```bash
./build-component.sh
```

This creates a component with WIT (WebAssembly Interface Types) that can be used from any language.

Output: `build-wasm/component/openabe.component.wasm`

### 5. (Optional) Build CLI Utilities

To build command-line tools:

```bash
cd cli-wasm
./build-cli.sh
```

This creates WASI-compatible CLI utilities:
- `oabe-setup` - Generate system parameters
- `oabe-keygen` - Generate keys
- `oabe-enc` - Encrypt files
- `oabe-dec` - Decrypt files

## 📚 Examples

### CP-ABE (Single Authority)

```javascript
const cpabe = new OpenABEContext(module, 'CP-ABE');
cpabe.generateParams();
cpabe.keygen('role:admin|dept:engineering', 'alice-key');

const ct = cpabe.encrypt('role:admin and dept:engineering', 'Secret data');
const pt = cpabe.decrypt('alice-key', ct);
```

### PKE (Public-Key Encryption)

```javascript
const pke = new OpenPKEContext(module, 'NIST_P256');

// Generate keypairs
pke.keygen('alice');
pke.keygen('bob');

// Export/import public keys
const alicePubKey = pke.exportPublicKey('alice');
pke.importPublicKey('alice', alicePubKey); // Bob imports Alice's key

// Encrypt to Alice's public key
const ct = pke.encrypt('alice', 'Message for Alice');

// Alice decrypts with her private key
const pt = pke.decrypt('alice', ct);
```

### MA-ABE (Multi-Authority)

```javascript
const maabe = new OpenABEContext(module, 'MA-ABE');
maabe.generateParams();

// Government issues key
maabe.keygen('age:over21|citizenship:us', 'alice_gov', 'government', 'alice');

// University issues key
maabe.keygen('student|dept:cs', 'alice_uni', 'university', 'alice');

// Encrypt with cross-authority policy
const ct = maabe.encrypt('age:over21 and student', 'Multi-authority secret');

// Decrypt with combined keys
const pt = maabe.decrypt('alice_combined', ct);
```

## 🎯 Use Cases

### Multi-Authority ABE Scenarios

1. **Healthcare Data Sharing**
   - Hospital authority: patient records, doctor credentials
   - Insurance authority: coverage, claims
   - Policy: "doctor AND has_insurance_coverage"

2. **Government Services**
   - DMV: driver's license, age verification
   - IRS: tax status
   - Policy: "age:over18 AND tax_status:compliant"

3. **Academic Credentials**
   - University: student status, GPA
   - Employer: work authorization
   - Policy: "(student OR alumni) AND work_authorized"

4. **Financial Services**
   - Bank: account status
   - Credit bureau: credit score
   - Policy: "account:active AND credit_score:good"

## 📁 Project Files

```
openabe-wasm/
├── build-deps-wasm.sh          # Build dependencies script
├── build-openabe-wasm.sh       # Build OpenABE script
├── wasm-build.sh              # Main build orchestrator
├── Makefile.wasm              # WASM-specific Makefile
│
├── wasm-bindings.cpp          # C bindings for WASM
├── wasm-bindings.h            # C bindings header
├── openabe-wrapper.js         # JavaScript wrapper
├── openabe.d.ts              # TypeScript definitions
│
├── example-wasm.html         # CP-ABE/KP-ABE demo
├── example-ma-abe.html       # Multi-Authority ABE demo
├── example-pke.html          # Public-Key Encryption demo
│
├── openabe.wit               # WIT interface definition
├── openabe-cli.wit           # CLI WIT interface
├── WIT_INTERFACE.md          # WIT documentation
├── build-component.sh        # Component build script
│
├── cli-wasm/                 # WASI CLI utilities
│   ├── oabe-setup            # Setup command
│   ├── oabe-keygen           # Key generation
│   ├── oabe-enc              # Encryption
│   ├── oabe-dec              # Decryption
│   ├── build-cli.sh          # Build script
│   ├── test-cli.sh           # Test suite
│   └── README.md             # CLI documentation
│
├── WASM_BUILD.md             # Detailed build documentation
└── README-WASM.md            # This file
```

## 🔑 API Reference

### ABE Functions

```javascript
// Initialize
initOpenABE(module)
shutdownOpenABE(module)

// Create ABE context
new OpenABEContext(module, scheme)  // scheme: 'CP-ABE', 'KP-ABE', 'MA-ABE'

// Setup
generateParams()

// Key generation
keygen(attributes, keyId, authId?, gid?)

// Encryption/Decryption
encrypt(policy, plaintext) → ciphertext
decrypt(keyId, ciphertext) → plaintext

// Parameter export/import
exportPublicParams() → Uint8Array
importPublicParams(params)
exportSecretParams() → Uint8Array
importSecretParams(params, authId?)
```

### PKE Functions

```javascript
// Create PKE context
new OpenPKEContext(module, curve?)  // curve: 'NIST_P256', 'NIST_P384', 'NIST_P521'

// Generate keypair
keygen(keyId)

// Encryption/Decryption
encrypt(receiverId, plaintext) → ciphertext
decrypt(receiverId, ciphertext) → plaintext

// Key export/import
exportPublicKey(keyId) → Uint8Array
importPublicKey(keyId, keyBlob)
exportPrivateKey(keyId) → Uint8Array
importPrivateKey(keyId, keyBlob)
```

### Multi-Authority Specific

```javascript
// Global parameters
exportGlobalParams() → Uint8Array
importGlobalParams(params)

// Authority-specific parameters
importPublicParamsWithAuthority(authId, params)
importSecretParamsWithAuthority(authId, params)

// User key management
exportUserKey(keyId) → Uint8Array
importUserKey(keyId, keyBlob)
deleteKey(keyId) → boolean
```

## 🔬 Interactive Demos

### CP-ABE Demo
Open `example-wasm.html` in a browser to try:
- Parameter generation
- Key generation with attributes
- Policy-based encryption
- Decryption with matching keys
- Parameter export/import

### PKE Demo
Open `example-pke.html` in a browser to try:
- Elliptic curve selection (P-256, P-384, P-521)
- Keypair generation
- Public-key encryption/decryption
- Key export/import
- Alice ↔ Bob communication

### MA-ABE Demo
Open `example-ma-abe.html` in a browser to try:
- Multi-authority setup
- Cross-authority key issuance
- Cross-authority policy encryption
- Multi-key decryption
- Key export/import/delete

### CLI Utilities Demo

Command-line tools for file encryption:

```bash
cd cli-wasm

# CP-ABE example
./oabe-setup -s CP -p org
./oabe-keygen -s CP -p org -i "role:admin|dept:eng" -o alice
./oabe-enc -s CP -p org -e "role:admin and dept:eng" -i file.txt -o file.cpabe
./oabe-dec -s CP -p org -k alice.key -i file.cpabe -o decrypted.txt

# Run full test suite
./test-cli.sh
```

See [cli-wasm/README.md](cli-wasm/README.md) for full documentation.

## 📖 Documentation

- [WASM_BUILD.md](WASM_BUILD.md) - Complete build guide and API documentation
- [WIT_INTERFACE.md](WIT_INTERFACE.md) - WebAssembly Component Model interface
- [openabe.wit](openabe.wit) - WIT interface definition
- [OpenABE API Guide](https://github.com/zeutro/openabe/blob/master/docs/libopenabe-v1.0.0-api-doc.pdf) - Original API documentation
- [OpenABE Design Document](https://github.com/zeutro/openabe/blob/master/docs/libopenabe-v1.0.0-design-doc.pdf) - Cryptographic details

## ⚙️ Technical Details

### Supported Schemes

| Scheme | Description | Use Case |
|--------|-------------|----------|
| CP-ABE | Ciphertext-Policy ABE | Role-based access control |
| KP-ABE | Key-Policy ABE | Content-based access control |
| MA-ABE | Multi-Authority ABE | Cross-organizational sharing |
| PK | Public-Key Encryption | Traditional PKI |

### Dependencies

- **WASI-SDK** v21+ (WebAssembly compiler toolchain)
- **GMP** 6.2.1 (Arbitrary precision arithmetic)
- **OpenSSL** 1.1.1 (Cryptographic functions)
- **RELIC** 0.5.0 (Pairing-based cryptography)

### Build Output

- `build-wasm/install/` - Compiled dependencies
- `build-wasm/obj/` - Object files
- `build-wasm/libopenabe.a` - Static library
- `build-wasm/openabe.wasm` - Core WASM module
- `build-wasm/component/openabe.component.wasm` - WebAssembly Component (optional)

### WebAssembly Component Model

OpenABE can be built as a standards-compliant WebAssembly Component using WIT (WebAssembly Interface Types). This enables:

- **Language Agnostic**: Use from Rust, JavaScript, Python, Go, and more
- **Type Safety**: Strongly-typed interface with automatic binding generation
- **Composability**: Combine with other WebAssembly components
- **Future Proof**: Based on the official WebAssembly Component Model standard

See [WIT_INTERFACE.md](WIT_INTERFACE.md) for details.

## 🛠️ Troubleshooting

**WASI-SDK not found:**
```bash
export WASI_SDK_PATH=/path/to/wasi-sdk
```

**Build errors:**
- Ensure WASI-SDK v16+ is installed
- Ensure CMake 3.10+ is installed
- Check all dependencies built successfully

**Runtime errors:**
- Verify browser supports WebAssembly
- Check console for error messages
- Ensure all exported functions are available

## 📝 License

OpenABE is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

Commercial licenses are available from Zeutro, LLC.

## 🔗 Links

- [OpenABE GitHub](https://github.com/zeutro/openabe)
- [WASI-SDK](https://github.com/WebAssembly/wasi-sdk)
- [WebAssembly](https://webassembly.org/)
- [Zeutro](https://www.zeutro.com)
