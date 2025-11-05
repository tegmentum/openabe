# ABE-CBOR Phase 1: Quick Start Guide

## Overview

This guide covers the first phase of ABE-CBOR implementation: creating specification documents and integrating the CBOR library.

## Prerequisites

- OpenABE repository with MCL backend
- Development environment set up
- Access to write documentation

## Phase 1 Tasks Checklist

### Task 1.1: Create Specification Documents

#### Step 1: Create the CDDL Specification

Create `docs/ABE-CBOR-SPEC.md`:

```bash
touch docs/ABE-CBOR-SPEC.md
```

**Content outline:**
1. Introduction and goals
2. Complete CDDL schema (from design)
3. Data type definitions
4. Encoding rules
5. Validation requirements

**Key sections to include:**
- `ABE-Item` top-level structure
- `Suite` descriptor specification
- `Curve` and `GE` encoding profiles
- All 4 ABE types (MSK, MPK, SK, CT)
- `GroupElems`, `AttrSet`, `Policy` primitives

#### Step 2: Create the Registry Document

Create `docs/ABE-CBOR-REGISTRY.md`:

```bash
touch docs/ABE-CBOR-REGISTRY.md
```

**Registry tables to define:**

1. **Scheme IDs**
   ```
   | ID | Scheme | Description | Status |
   |----|--------|-------------|--------|
   | cpabe-waters | CP-ABE Waters | BSW07 Ciphertext-Policy ABE | stable |
   | kpabe-gpsw | KP-ABE GPSW | GPSW06 Key-Policy ABE | stable |
   ```

2. **Curve IDs**
   ```
   | ID | Curve | Field Bits | Security Level | Status |
   |----|-------|------------|----------------|--------|
   | bls12-381 | BLS12-381 | 381 | 128-bit | recommended |
   | bn254 | BN254 | 254 | 100-bit | legacy |
   ```

3. **GE Encoding IDs**
   ```
   | ID | Format | Description | Byte Size (G1/G2) |
   |----|--------|-------------|-------------------|
   | 0 | IETF-compressed | BLS12-381 IETF draft | 48/96 bytes |
   | 1 | uncompressed | Full coordinates | 96/192 bytes |
   | 2 | MCL-canonical | MCL native format | Variable |
   ```

4. **Hash/KDF IDs**
   ```
   | ID | Algorithm | Output Size | Status |
   |----|-----------|-------------|--------|
   | SHA-256 | SHA-256 | 32 bytes | stable |
   | SHA-384 | SHA-384 | 48 bytes | stable |
   | HKDF-SHA256 | HKDF-SHA256 | Variable | stable |
   ```

#### Step 3: Create Examples Document

Create `docs/ABE-CBOR-EXAMPLES.md`:

```bash
touch docs/ABE-CBOR-EXAMPLES.md
```

**Examples to include:**

1. **Minimal MPK (BLS12-381)**
   - CBOR diagnostic notation
   - Hex encoding
   - Explanation of each field

2. **SK with attributes**
   - Multiple attribute types (string, integer)
   - Sorted attribute set
   - Delegation proof structure

3. **CT with Boolean policy**
   - RPN token list encoding
   - Attribute references
   - Encrypted payload wrapper

4. **CT with MSP policy**
   - Matrix representation
   - Row-to-attribute mapping
   - LSSS structure

### Task 1.2: CBOR Library Integration

#### Step 1: Evaluate CBOR Libraries

**Create evaluation matrix:**

| Library | License | Size | Deterministic | WASM | Active | Score |
|---------|---------|------|---------------|------|--------|-------|
| tinycbor | Apache 2.0 | ~50KB | ✅ | ✅ | ✅ | 5/5 |
| libcbor | MIT | ~100KB | ✅ | ✅ | ✅ | 4/5 |
| cn-cbor | MIT | ~30KB | ⚠️ | ✅ | ⚠️ | 3/5 |

**Recommendation: tinycbor**

#### Step 2: Add tinycbor to Dependencies

```bash
cd deps
git clone https://github.com/intel/tinycbor.git
cd tinycbor
git checkout v0.6.0  # Latest stable release
```

#### Step 3: Update Build Scripts

**Update `Makefile.common`:**

```makefile
# Add CBOR include and library paths
CBOR_ROOT = $(DEPS_ROOT)/tinycbor
CBOR_INCLUDE = $(CBOR_ROOT)/src
CBOR_LIB = $(CBOR_ROOT)/lib

CXXFLAGS += -I$(CBOR_INCLUDE)
LDFLAGS += -L$(CBOR_LIB) -ltinycbor
```

**Update `deps/Makefile`:**

```makefile
.PHONY: tinycbor

tinycbor:
	@echo "Building tinycbor..."
	cd tinycbor && $(MAKE) lib/libtinycbor.a
	mkdir -p $(DEPS_ROOT)/lib
	cp tinycbor/lib/libtinycbor.a $(DEPS_ROOT)/lib/
	mkdir -p $(DEPS_ROOT)/include/tinycbor
	cp tinycbor/src/*.h $(DEPS_ROOT)/include/tinycbor/

all: ... tinycbor

clean:
	...
	cd tinycbor && $(MAKE) clean
```

**Update `build-deps-wasm.sh`:**

```bash
# Add tinycbor build for WASM
echo "[INFO] Building tinycbor for WASM..."
cd deps/tinycbor
emmake make clean
emmake make lib/libtinycbor.a
mkdir -p "${INSTALL_DIR}/lib"
cp lib/libtinycbor.a "${INSTALL_DIR}/lib/"
mkdir -p "${INSTALL_DIR}/include/tinycbor"
cp src/*.h "${INSTALL_DIR}/include/tinycbor/"
cd ../..
```

#### Step 4: Create CBOR Wrapper API

Create `src/include/openabe/cbor/zcbor_wrapper.h`:

```cpp
#ifndef __ZCBOR_WRAPPER_H__
#define __ZCBOR_WRAPPER_H__

#include <openabe/openabe.h>
#include <tinycbor/cbor.h>

namespace oabe {

// CBOR encoding/decoding wrapper
class ZCBOREncoder {
public:
    ZCBOREncoder();
    ~ZCBOREncoder();

    // Start encoding
    void reset();

    // Encode primitives
    void encodeInt(int64_t value);
    void encodeUInt(uint64_t value);
    void encodeString(const std::string& str);
    void encodeBytes(const OpenABEByteString& bytes);
    void encodeBool(bool value);
    void encodeNull();

    // Container operations
    void startMap(size_t entries);
    void endMap();
    void startArray(size_t entries);
    void endArray();

    // Get encoded result
    OpenABEByteString getEncoded() const;

private:
    CborEncoder encoder_;
    uint8_t* buffer_;
    size_t bufferSize_;
};

class ZCBORDecoder {
public:
    ZCBORDecoder(const OpenABEByteString& data);
    ~ZCBORDecoder();

    // Decode primitives
    int64_t decodeInt();
    uint64_t decodeUInt();
    std::string decodeString();
    OpenABEByteString decodeBytes();
    bool decodeBool();

    // Container operations
    size_t enterMap();
    void exitMap();
    size_t enterArray();
    void exitArray();

    // Query operations
    bool hasNext() const;
    CborType peekType() const;

private:
    CborParser parser_;
    CborValue value_;
    const uint8_t* data_;
    size_t dataSize_;
};

} // namespace oabe

#endif // __ZCBOR_WRAPPER_H__
```

Create implementation `src/cbor/zcbor_wrapper.cpp`:

```cpp
#include <openabe/cbor/zcbor_wrapper.h>
#include <memory>
#include <stdexcept>

namespace oabe {

// Initial buffer size for encoding
const size_t INITIAL_BUFFER_SIZE = 4096;

ZCBOREncoder::ZCBOREncoder()
    : buffer_(nullptr), bufferSize_(INITIAL_BUFFER_SIZE) {
    buffer_ = new uint8_t[bufferSize_];
    cbor_encoder_init(&encoder_, buffer_, bufferSize_, 0);
}

ZCBOREncoder::~ZCBOREncoder() {
    delete[] buffer_;
}

void ZCBOREncoder::reset() {
    cbor_encoder_init(&encoder_, buffer_, bufferSize_, 0);
}

void ZCBOREncoder::encodeInt(int64_t value) {
    CborError err = cbor_encode_int(&encoder_, value);
    if (err != CborNoError) {
        throw std::runtime_error("CBOR encode int failed");
    }
}

void ZCBOREncoder::encodeUInt(uint64_t value) {
    CborError err = cbor_encode_uint(&encoder_, value);
    if (err != CborNoError) {
        throw std::runtime_error("CBOR encode uint failed");
    }
}

void ZCBOREncoder::encodeString(const std::string& str) {
    CborError err = cbor_encode_text_string(&encoder_, str.c_str(), str.size());
    if (err != CborNoError) {
        throw std::runtime_error("CBOR encode string failed");
    }
}

void ZCBOREncoder::encodeBytes(const OpenABEByteString& bytes) {
    CborError err = cbor_encode_byte_string(&encoder_, bytes.data(), bytes.size());
    if (err != CborNoError) {
        throw std::runtime_error("CBOR encode bytes failed");
    }
}

// ... implement remaining methods

OpenABEByteString ZCBOREncoder::getEncoded() const {
    size_t encodedSize = cbor_encoder_get_buffer_size(&encoder_, buffer_);
    return OpenABEByteString(buffer_, encodedSize);
}

// Decoder implementation
ZCBORDecoder::ZCBORDecoder(const OpenABEByteString& data)
    : data_(data.data()), dataSize_(data.size()) {
    CborError err = cbor_parser_init(data_, dataSize_, 0, &parser_, &value_);
    if (err != CborNoError) {
        throw std::runtime_error("CBOR parser init failed");
    }
}

// ... implement decoder methods

} // namespace oabe
```

#### Step 5: Add to Build System

Update `src/Makefile`:

```makefile
# Add CBOR source files
OABE_CBOR = cbor/zcbor_wrapper.o

OABE_OBJ_TARGETS = ... $(OABE_CBOR) ...

# Add CBOR library to link
OABELDLIBS += -ltinycbor
```

#### Step 6: Create Initial Test

Create `src/test_cbor_basic.cpp`:

```cpp
#include <gtest/gtest.h>
#include <openabe/cbor/zcbor_wrapper.h>

using namespace oabe;

TEST(CBOR_Basic, EncodeDecodeIntegers) {
    ZCBOREncoder encoder;
    encoder.encodeInt(42);
    encoder.encodeInt(-100);
    encoder.encodeUInt(12345);

    OpenABEByteString encoded = encoder.getEncoded();

    ZCBORDecoder decoder(encoded);
    EXPECT_EQ(decoder.decodeInt(), 42);
    EXPECT_EQ(decoder.decodeInt(), -100);
    EXPECT_EQ(decoder.decodeUInt(), 12345);
}

TEST(CBOR_Basic, EncodeDecodeStrings) {
    ZCBOREncoder encoder;
    encoder.encodeString("hello");
    encoder.encodeString("world");

    OpenABEByteString encoded = encoder.getEncoded();

    ZCBORDecoder decoder(encoded);
    EXPECT_EQ(decoder.decodeString(), "hello");
    EXPECT_EQ(decoder.decodeString(), "world");
}

TEST(CBOR_Basic, EncodeDecodeMap) {
    ZCBOREncoder encoder;
    encoder.startMap(2);
    encoder.encodeInt(0);  // key
    encoder.encodeString("value1");
    encoder.encodeInt(1);  // key
    encoder.encodeString("value2");
    encoder.endMap();

    OpenABEByteString encoded = encoder.getEncoded();

    ZCBORDecoder decoder(encoded);
    size_t entries = decoder.enterMap();
    EXPECT_EQ(entries, 2);
    // ... decode map entries
    decoder.exitMap();
}
```

Build and test:

```bash
cd src
make test_cbor_basic
./test_cbor_basic
```

### Task 1.3: Define OpenABE-Specific Constants

Create `src/include/openabe/cbor/zcbor_constants.h`:

```cpp
#ifndef __ZCBOR_CONSTANTS_H__
#define __ZCBOR_CONSTANTS_H__

#include <cstdint>

namespace oabe {
namespace cbor {

// CBOR tag for ABE items (private-use range)
const uint64_t ABE_CBOR_TAG = 60001;

// ABE item kinds
enum class ABEKind : uint32_t {
    MSK = 1,  // Master Secret Key
    MPK = 2,  // Master Public Key
    SK = 3,   // User Secret Key
    CT = 4    // Ciphertext
};

// Top-level map keys
enum class ABEMapKey : uint32_t {
    KIND = 0,          // ABEKind
    SUITE = 1,         // Suite descriptor
    VERSION = 2,       // Profile version (default: 1)
    AUTH_ID = 3,       // Authority ID (optional)
    META = 4,          // Metadata map (optional)
    BODY = 5           // Kind-specific body (5+)
};

// Suite descriptor keys
enum class SuiteKey : uint32_t {
    SCHEME_ID = 0,     // Scheme identifier string
    CURVE = 1,         // Curve descriptor
    GE = 2,            // Group element encoding
    HASH_KDF = 3       // Hash/KDF suite (optional)
};

// Curve descriptor keys
enum class CurveKey : uint32_t {
    CURVE_ID = 0,      // Curve identifier string
    SECURITY_LEVEL = 1,// Security level in bits (optional)
    PARAMS = 2         // Explicit params (optional)
};

// GE encoding keys
enum class GEKey : uint32_t {
    ENCODING_ID = 0,   // GE encoding format
    ENDIANNESS = 1,    // 0=big, 1=little
    SUBGROUP_CHECK = 2,// Require subgroup check (default: true)
    OPTIONS = 3        // Encoding-specific options (optional)
};

// GE encoding formats
enum class GEEncoding : uint32_t {
    IETF_COMPRESSED = 0,   // BLS12-381 IETF compressed
    UNCOMPRESSED = 1,       // Full coordinate representation
    MCL_CANONICAL = 2       // MCL native format
};

// Attribute types
enum class AttributeType : uint32_t {
    STRING = 0,
    INTEGER = 1,
    BYTES = 2,
    SET = 3,
    RANGE = 4
};

// Policy encoding types
enum class PolicyEncoding : uint32_t {
    BOOL_AST = 0,  // Boolean formula as RPN
    MSP = 1        // LSSS matrix
};

// Boolean AST token types
enum class TokenType : uint32_t {
    ATTR = 0,
    AND = 1,
    OR = 2,
    THRESH = 3,
    NOT = 4
};

// Version constants
const uint32_t ABE_CBOR_VERSION = 1;

// Scheme IDs (from registry)
const char* const SCHEME_CPABE_WATERS = "cpabe-waters";
const char* const SCHEME_KPABE_GPSW = "kpabe-gpsw";

// Curve IDs (from registry)
const char* const CURVE_BLS12_381 = "bls12-381";
const char* const CURVE_BN254 = "bn254";

// Hash/KDF IDs (from registry)
const char* const HASH_SHA256 = "SHA-256";
const char* const HASH_SHA384 = "SHA-384";
const char* const KDF_HKDF_SHA256 = "HKDF-SHA256";

} // namespace cbor
} // namespace oabe

#endif // __ZCBOR_CONSTANTS_H__
```

## Verification Checklist

At the end of Phase 1, you should have:

- [ ] `docs/ABE-CBOR-SPEC.md` - Complete CDDL specification
- [ ] `docs/ABE-CBOR-REGISTRY.md` - Suite/curve/encoding registry
- [ ] `docs/ABE-CBOR-EXAMPLES.md` - Test vectors and examples
- [ ] `deps/tinycbor/` - CBOR library integrated
- [ ] `src/include/openabe/cbor/zcbor_wrapper.h` - CBOR wrapper API
- [ ] `src/cbor/zcbor_wrapper.cpp` - CBOR wrapper implementation
- [ ] `src/include/openabe/cbor/zcbor_constants.h` - OpenABE constants
- [ ] `src/test_cbor_basic.cpp` - Basic CBOR tests passing
- [ ] Build scripts updated for native and WASM
- [ ] All tests passing

## Next Steps

After completing Phase 1:

1. Review specifications with team
2. Get feedback on registry definitions
3. Proceed to Phase 2: Core Serialization Primitives
4. Begin implementing group element encoding

## Troubleshooting

### tinycbor build fails on macOS
```bash
# Install build dependencies
brew install cmake

# Build with explicit toolchain
cd deps/tinycbor
make CC=clang CXX=clang++
```

### WASM build can't find tinycbor
```bash
# Ensure Emscripten environment is active
source $EMSDK/emsdk_env.sh

# Rebuild tinycbor with emmake
cd deps/tinycbor
emmake make clean
emmake make lib/libtinycbor.a
```

### Linker errors with libtinycbor
```bash
# Check library was installed
ls deps/root/lib/libtinycbor.a

# Verify linker flags in Makefile.common
grep tinycbor Makefile.common
```

## Resources

- tinycbor docs: https://intel.github.io/tinycbor/
- CBOR RFC 8949: https://www.rfc-editor.org/rfc/rfc8949.html
- CBOR playground: http://cbor.me/
- CDDL spec: https://www.rfc-editor.org/rfc/rfc8610.html
