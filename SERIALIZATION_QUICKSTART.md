# Standard Serialization - Quick Start Guide

## TL;DR

OpenABE now supports standard serialization formats (SEC1, ZCash, Ethereum) for better interoperability.

## 5-Minute Tutorial

### 1. Basic Usage (Auto-Format)

```cpp
#include <openabe/openabe.h>
#include <openabe/zml/zstandard_serialization.h>

using namespace oabe;

InitializeOpenABE();

// Create pairing
OpenABEPairing pairing("BN254");
G1 g1 = pairing.randomG1(nullptr);

// Serialize (auto-selects best format for curve)
OpenABEByteString data;
StandardPairingSerializer::serializeG1(data, g1);

// Deserialize
auto bgroup = std::dynamic_pointer_cast<BPGroup>(pairing.getGroup());
G1 g1_copy(bgroup);
StandardPairingSerializer::deserializeG1(g1_copy, data);

ShutdownOpenABE();
```

### 2. Ethereum Integration

```cpp
// Serialize for Ethereum smart contract
OpenABEByteString eth_data;
StandardPairingSerializer::serializeG1(eth_data, g1, ETHEREUM_BN254, false);

// eth_data is now 64 bytes: [x (32 bytes)][y (32 bytes)]
// Send to Ethereum smart contract...
```

### 3. ZCash/BLS12-381 Format

```cpp
OpenABEPairing pairing("BLS12-381");  // Or BN382
G1 g1 = pairing.randomG1(nullptr);

// Serialize with compression
OpenABEByteString compressed;
StandardPairingSerializer::serializeG1_ZCash(compressed, g1, true);
// Result: 48 bytes (compressed)

// Or uncompressed
OpenABEByteString uncompressed;
StandardPairingSerializer::serializeG1_ZCash(uncompressed, g1, false);
// Result: 96 bytes
```

### 4. GT Element Serialization

```cpp
// Create GT element
G1 g1 = pairing.randomG1(nullptr);
G2 g2 = pairing.randomG2(nullptr);
GT gt = pairing.pairing(g1, g2);

// Serialize with cyclotomic compression (33% savings)
OpenABEByteString gt_data;
StandardPairingSerializer::serializeGT(gt_data, gt, GT_CYCLOTOMIC_COMPRESSED);
// BN254: 256 bytes instead of 384
// BLS12-381: 384 bytes instead of 576
```

## Format Cheat Sheet

### When to Use Each Format

| Format | Use When | Size (G1) | Compatible With |
|--------|----------|-----------|-----------------|
| **ETHEREUM_BN254** | Talking to Ethereum smart contracts | 64 bytes | EIP-196/197 |
| **ZCASH_BLS12** | Using BLS12-381, need compression | 48-96 bytes | Ethereum 2.0, Filecoin |
| **SEC1_STANDARD** | General compatibility, NIST curves | 33-65 bytes | OpenSSL, Bitcoin libs |
| **AUTO** | Let OpenABE choose | Varies | Best for curve |

### Size Comparison

```
BN254 G1:
  - Ethereum:  64 bytes (uncompressed, no prefix)
  - SEC1:      65 bytes (uncompressed) or 33 bytes (compressed)

BLS12-381 G1:
  - ZCash:     96 bytes (uncompressed) or 48 bytes (compressed)

GT (Fp12):
  - BN254:     384 bytes (full) or 256 bytes (compressed)
  - BLS12-381: 576 bytes (full) or 384 bytes (compressed)
```

## Common Patterns

### Pattern 1: Cross-System Data Exchange

```cpp
// OpenABE → Ethereum
OpenABEByteString eth_format;
StandardPairingSerializer::serializeG1(eth_format, g1, ETHEREUM_BN254, false);
// Send eth_format to Ethereum...

// OpenABE → Python/Rust (ZCash format)
OpenABEByteString zcash_format;
StandardPairingSerializer::serializeG1(zcash_format, g1, ZCASH_BLS12, true);
// Send zcash_format to other system...
```

### Pattern 2: Legacy Data Migration

```cpp
// Read old ciphertext
OpenABEByteString old_data = readFromFile("old_ciphertext.bin");

// Check format
if (StandardPairingSerializer::isLegacyFormat(old_data)) {
    // Convert to standard
    OpenABEByteString new_data;
    LegacySerializer::convertLegacyG1(new_data, old_data, bgroup);

    // Save
    writeToFile("new_ciphertext.bin", new_data);
}
```

### Pattern 3: Network Optimization

```cpp
// For network transfer: use compressed
OpenABEByteString network_data;
StandardPairingSerializer::serializeG1(network_data, g1, ZCASH_BLS12, true);
send_over_network(network_data);  // Smaller size

// For local storage: use uncompressed
OpenABEByteString storage_data;
StandardPairingSerializer::serializeG1(storage_data, g1, ZCASH_BLS12, false);
save_to_disk(storage_data);  // Faster loading
```

## Integration Examples

### Ethereum Smart Contract

```solidity
// Solidity side
contract ABEVerifier {
    function verifyG1(bytes memory g1Data) public pure returns (bool) {
        require(g1Data.length == 64, "Invalid G1 size");
        (uint256 x, uint256 y) = abi.decode(g1Data, (uint256, uint256));

        // Verify on curve: y^2 = x^3 + 3
        uint256 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        uint256 lhs = mulmod(y, y, p);
        uint256 rhs = addmod(mulmod(mulmod(x, x, p), x, p), 3, p);

        return lhs == rhs;
    }
}
```

```cpp
// C++ side (OpenABE)
OpenABEByteString g1_bytes;
StandardPairingSerializer::serializeG1(g1_bytes, g1, ETHEREUM_BN254, false);

// Send g1_bytes (64 bytes) to smart contract
web3.eth.sendTransaction({
    to: contractAddress,
    data: g1_bytes.toHex()
});
```

### Python (py_ecc / ZCash BLS)

```python
# Python side
from py_ecc.bls import G1Compressed

def from_openabe_zcash(data: bytes) -> G1Compressed:
    """Import G1 from OpenABE ZCash format"""
    assert len(data) == 48, "Expected 48 bytes"
    return G1Compressed.from_bytes(data)

def to_openabe_zcash(point: G1Compressed) -> bytes:
    """Export G1 to OpenABE ZCash format"""
    return point.to_bytes()
```

```cpp
// C++ side (OpenABE)
OpenABEByteString zcash_bytes;
StandardPairingSerializer::serializeG1_ZCash(zcash_bytes, g1, true);

// Send zcash_bytes to Python (48 bytes compressed)
```

## Error Handling

```cpp
try {
    StandardPairingSerializer::deserializeG1(g1, data);
} catch (OpenABE_ERROR err) {
    switch (err) {
        case OpenABE_ERROR_SERIALIZATION_FAILED:
            cout << "Invalid serialization format" << endl;
            break;
        case OpenABE_ERROR_NOT_IMPLEMENTED:
            cout << "Feature not yet implemented (e.g., decompression)" << endl;
            break;
        default:
            cout << "Error: " << OpenABE_errorToString(err) << endl;
    }
}
```

## Testing

```bash
# Build and run tests
cd src
make test_standard_serialization
./test_standard_serialization

# Expected output shows:
# - Header serialization ✓
# - Format auto-selection ✓
# - Field element conversion ✓
# - Legacy detection ✓
# - G1 Ethereum format ✓
# - GT sizes ✓
```

## Performance Tips

1. **For speed**: Use uncompressed formats
2. **For size**: Use compressed formats (ZCash, SEC1)
3. **For Ethereum**: Use ETHEREUM_BN254 (gas optimized)
4. **For storage**: Add standard header for future compatibility

## Common Issues

### Issue: Point decompression not implemented
```
Error: OpenABE_ERROR_NOT_IMPLEMENTED
```
**Solution**: Use uncompressed format for now:
```cpp
StandardPairingSerializer::serializeG1(data, g1, ZCASH_BLS12, false);  // uncompressed
```

### Issue: Wrong curve for format
```
Error: Points don't match after round-trip
```
**Solution**: Use AUTO or match format to curve:
```cpp
// BN254 → Ethereum
StandardPairingSerializer::serializeG1(data, g1, ETHEREUM_BN254);

// BLS12-381 → ZCash
StandardPairingSerializer::serializeG1(data, g1, ZCASH_BLS12);
```

### Issue: Legacy data not recognized
```cpp
// Make sure to check format first
if (StandardPairingSerializer::isLegacyFormat(data)) {
    // Use legacy deserialize or convert
    LegacySerializer::convertLegacyG1(new_data, data, bgroup);
}
```

## Next Steps

1. **Read full docs**: `docs/STANDARD_SERIALIZATION.md`
2. **See implementation**: `STANDARD_SERIALIZATION_IMPLEMENTATION.md`
3. **Browse code**: `src/include/openabe/zml/zstandard_serialization.h`
4. **Run tests**: `src/test_standard_serialization.cpp`

## Quick Reference Card

```cpp
// Include
#include <openabe/zml/zstandard_serialization.h>

// Serialize (auto)
StandardPairingSerializer::serializeG1(out, g1);

// Serialize (specific format)
StandardPairingSerializer::serializeG1(out, g1, ETHEREUM_BN254, true);

// Deserialize
StandardPairingSerializer::deserializeG1(g1, in, true);

// GT with compression
StandardPairingSerializer::serializeGT(out, gt, GT_CYCLOTOMIC_COMPRESSED);

// Legacy check
bool legacy = StandardPairingSerializer::isLegacyFormat(data);

// Convert legacy
LegacySerializer::convertLegacyG1(out, in, bgroup);
```

## Support

- Issues: https://github.com/zeutro/openabe/issues
- Docs: https://github.com/zeutro/openabe/docs
- Email: support@zeutro.com

---

**Happy serializing! 🚀**
