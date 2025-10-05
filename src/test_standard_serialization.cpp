///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// Test program for standard serialization formats
///

#include <iostream>
#include <openabe/openabe.h>
#include <openabe/zml/zstandard_serialization.h>

using namespace std;
using namespace oabe;

void test_header() {
    cout << "=== Testing Serialization Header ===" << endl;

    SerializationHeader header1(OpenABE_ELEMENT_G1, OpenABE_BN_P254_ID, ETHEREUM_BN254);
    OpenABEByteString serialized;
    header1.serialize(serialized);

    cout << "Header size: " << serialized.size() << " bytes" << endl;
    cout << "Header hex: " << serialized.toHex() << endl;

    SerializationHeader header2;
    size_t index = 0;
    bool success = header2.deserialize(serialized, &index);

    cout << "Deserialization: " << (success ? "SUCCESS" : "FAILED") << endl;
    cout << "Element type match: " << (header1.elementType == header2.elementType ? "YES" : "NO") << endl;
    cout << "Curve ID match: " << (header1.curveID == header2.curveID ? "YES" : "NO") << endl;
    cout << "Format match: " << (header1.format == header2.format ? "YES" : "NO") << endl;
    cout << endl;
}

void test_format_selection() {
    cout << "=== Testing Format Auto-Selection ===" << endl;

    struct {
        OpenABECurveID curve;
        const char* name;
        SerializationFormat expected;
    } tests[] = {
        {OpenABE_BN_P254_ID, "BN254", ETHEREUM_BN254},
        {OpenABE_BN_P382_ID, "BN382 (BLS12-381 compat)", ZCASH_BLS12},
        {OpenABE_NIST_P256_ID, "NIST P-256", SEC1_STANDARD},
    };

    for (auto& test : tests) {
        SerializationFormat selected = StandardPairingSerializer::selectFormat(test.curve);
        cout << test.name << ": ";
        if (selected == ETHEREUM_BN254) cout << "ETHEREUM_BN254";
        else if (selected == ZCASH_BLS12) cout << "ZCASH_BLS12";
        else if (selected == SEC1_STANDARD) cout << "SEC1_STANDARD";
        else cout << "UNKNOWN";

        cout << (selected == test.expected ? " ✓" : " ✗") << endl;
    }
    cout << endl;
}

void test_field_element_conversion() {
    cout << "=== Testing Field Element Conversion ===" << endl;

    bignum_t elem;
    zml_bignum_init(&elem);

    // Test value: 12345678901234567890
    const char* test_value = "12345678901234567890";
    zml_bignum_fromDec(elem, (char*)test_value);

    OpenABEByteString bytes_be, bytes_le;
    StandardPairingSerializer::field_element_to_bytes(elem, bytes_be, 32, true);
    StandardPairingSerializer::field_element_to_bytes(elem, bytes_le, 32, false);

    cout << "Original: " << test_value << endl;
    cout << "Big-endian (32 bytes): " << bytes_be.toHex() << endl;
    cout << "Little-endian (32 bytes): " << bytes_le.toHex() << endl;

    // Convert back
    bignum_t elem2;
    zml_bignum_init(&elem2);
    StandardPairingSerializer::bytes_to_field_element(elem2, bytes_be, 0, true);

    bool match = (zml_bignum_cmp(elem, elem2) == BN_CMP_EQ);
    cout << "Round-trip conversion: " << (match ? "SUCCESS" : "FAILED") << endl;

    zml_bignum_free(elem);
    zml_bignum_free(elem2);
    cout << endl;
}

void test_g1_ethereum_format() {
    cout << "=== Testing G1 Ethereum BN254 Format ===" << endl;

    try {
        InitializeOpenABE();

        OpenABEPairing pairing("BN254");
        G1 g1 = pairing.randomG1(nullptr);

        cout << "Generated random G1 point" << endl;

        // Serialize to Ethereum format
        OpenABEByteString serialized;
        StandardPairingSerializer::serializeG1(serialized, g1, ETHEREUM_BN254, true);

        cout << "Serialized size (with header): " << serialized.size() << " bytes" << endl;
        cout << "Expected: 9 (header) + 64 (data) = 73 bytes" << endl;

        // Deserialize
        std::shared_ptr<BPGroup> bgroup = std::dynamic_pointer_cast<BPGroup>(pairing.getGroup());
        G1 g1_restored(bgroup);
        StandardPairingSerializer::deserializeG1(g1_restored, serialized, true);

        cout << "Deserialization: SUCCESS" << endl;

        // Compare
        bool equal = (g1 == g1_restored);
        cout << "Points match: " << (equal ? "YES ✓" : "NO ✗") << endl;

        ShutdownOpenABE();
    } catch (OpenABE_ERROR err) {
        cout << "Error: " << OpenABE_errorToString(err) << endl;
    }
    cout << endl;
}

void test_legacy_detection() {
    cout << "=== Testing Legacy Format Detection ===" << endl;

    // Create legacy-style data (starts with element type, no header)
    OpenABEByteString legacy;
    legacy.appendByte(OpenABE_ELEMENT_G1);
    legacy.appendByte(0x01);
    legacy.appendByte(0x23);

    bool is_legacy = StandardPairingSerializer::isLegacyFormat(legacy);
    cout << "Legacy format detected: " << (is_legacy ? "YES ✓" : "NO ✗") << endl;

    // Create standard format data (starts with OABE magic)
    OpenABEByteString standard;
    SerializationHeader header(OpenABE_ELEMENT_G1, OpenABE_BN_P254_ID);
    header.serialize(standard);

    is_legacy = StandardPairingSerializer::isLegacyFormat(standard);
    cout << "Standard format detected correctly: " << (!is_legacy ? "YES ✓" : "NO ✗") << endl;
    cout << endl;
}

void test_gt_serialization_sizes() {
    cout << "=== Testing GT Serialization Sizes ===" << endl;

    struct {
        OpenABECurveID curve;
        const char* name;
        size_t field_size;
    } curves[] = {
        {OpenABE_BN_P254_ID, "BN254", 32},
        {OpenABE_BN_P382_ID, "BN382/BLS12-381", 48},
    };

    for (auto& c : curves) {
        size_t full_size = 12 * c.field_size;
        size_t compressed_size = 8 * c.field_size;

        cout << c.name << ":" << endl;
        cout << "  Full Fp12: " << full_size << " bytes" << endl;
        cout << "  Cyclotomic compressed: " << compressed_size << " bytes ";
        cout << "(" << (compressed_size * 100 / full_size) << "% of full)" << endl;
    }
    cout << endl;
}

void test_cross_format_info() {
    cout << "=== Cross-Format Compatibility Information ===" << endl;
    cout << endl;

    cout << "G1 Point Sizes:" << endl;
    cout << "  SEC1 compressed (BN254):     33 bytes (0x02/0x03 + 32)" << endl;
    cout << "  SEC1 uncompressed (BN254):   65 bytes (0x04 + 32 + 32)" << endl;
    cout << "  ZCash compressed (BLS12-381): 48 bytes (flags + 48)" << endl;
    cout << "  ZCash uncompressed (BLS12-381): 96 bytes (48 + 48)" << endl;
    cout << "  Ethereum (BN254):            64 bytes (32 + 32, no prefix)" << endl;
    cout << endl;

    cout << "G2 Point Sizes:" << endl;
    cout << "  SEC1 uncompressed (BN254):   129 bytes (0x04 + 4*32)" << endl;
    cout << "  ZCash compressed (BLS12-381): 96 bytes" << endl;
    cout << "  ZCash uncompressed (BLS12-381): 192 bytes" << endl;
    cout << "  Ethereum (BN254):            128 bytes (4*32)" << endl;
    cout << endl;

    cout << "GT Serialization:" << endl;
    cout << "  BN254 full Fp12:             384 bytes (12 * 32)" << endl;
    cout << "  BN254 cyclotomic:            256 bytes (8 * 32, 67% of full)" << endl;
    cout << "  BLS12-381 full Fp12:         576 bytes (12 * 48)" << endl;
    cout << "  BLS12-381 cyclotomic:        384 bytes (8 * 48, 67% of full)" << endl;
    cout << endl;

    cout << "Standard Header:" << endl;
    cout << "  Size: 9 bytes" << endl;
    cout << "  Format: [OABE(4)][VER(1)][TYPE(1)][CURVE(1)][FMT(1)][FLAGS(1)]" << endl;
    cout << endl;
}

int main(int argc, char **argv) {
    cout << "╔════════════════════════════════════════════════════════╗" << endl;
    cout << "║   OpenABE Standard Serialization Test Suite           ║" << endl;
    cout << "╚════════════════════════════════════════════════════════╝" << endl;
    cout << endl;

    test_header();
    test_format_selection();
    test_field_element_conversion();
    test_legacy_detection();
    test_g1_ethereum_format();
    test_gt_serialization_sizes();
    test_cross_format_info();

    cout << "╔════════════════════════════════════════════════════════╗" << endl;
    cout << "║   All tests completed                                  ║" << endl;
    cout << "╚════════════════════════════════════════════════════════╝" << endl;

    return 0;
}
