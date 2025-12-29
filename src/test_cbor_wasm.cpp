// Test CBOR serialization for WASM build
// This program verifies that CBOR encoding/decoding works identically in WASM and native builds

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <openabe/openabe.h>
#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_group_elements.h>
#include <openabe/cbor/zcbor_attributes.h>
#include <openabe/cbor/zcbor_policy.h>

using namespace std;
using namespace oabe;
using namespace oabe::cbor;

// Simple test result tracking
int tests_passed = 0;
int tests_failed = 0;

void printHex(const std::vector<uint8_t>& data, size_t max_bytes = 32) {
    for (size_t i = 0; i < std::min(data.size(), max_bytes); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
        if (i < data.size() - 1) std::cout << " ";
    }
    if (data.size() > max_bytes) {
        std::cout << " ... (" << std::dec << data.size() << " bytes total)";
    }
    std::cout << std::dec << std::endl;
}

bool testG1Roundtrip() {
    std::cout << "\nTesting G1 element round-trip..." << std::endl;

    try {
        OpenABEPairing pairing("BLS12_P381");
        OpenABERNG rng;

        // Create random G1 element
        G1 g1_orig = pairing.randomG1(&rng);

        // Encode
        GroupElementSerializer ge_ser(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
        ZCBOREncoder encoder;
        ge_ser.encodeG1(encoder, g1_orig);
        auto encoded = encoder.getEncoded();

        std::cout << "  Encoded size: " << encoded.size() << " bytes" << std::endl;
        std::cout << "  Encoded data: ";
        printHex(encoded);

        // Decode
        ZCBORDecoder decoder(encoded);
        G1 g1_decoded = pairing.initG1();
        ge_ser.decodeG1(decoder, g1_decoded, OpenABE_BLS12_P381_ID);

        // Re-encode
        ZCBOREncoder encoder2;
        ge_ser.encodeG1(encoder2, g1_decoded);
        auto reencoded = encoder2.getEncoded();

        // Verify bit-for-bit match
        if (encoded == reencoded) {
            std::cout << "✓ G1 round-trip successful" << std::endl;
            tests_passed++;
            return true;
        } else {
            std::cout << "❌ G1 round-trip failed: encoding mismatch" << std::endl;
            tests_failed++;
            return false;
        }
    } catch (const std::exception& e) {
        std::cout << "❌ G1 test failed with exception: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool testAttributeRoundtrip() {
    std::cout << "\nTesting attribute round-trip..." << std::endl;

    try {
        // Create string attribute
        AttributeValue attr;
        attr.type = AttributeType::STRING;
        attr.string_value = "test_attribute";

        // Encode
        AttributeSerializer attr_ser;
        ZCBOREncoder encoder;
        attr_ser.encodeAttribute(encoder, attr);
        auto encoded = encoder.getEncoded();

        std::cout << "  Encoded size: " << encoded.size() << " bytes" << std::endl;
        std::cout << "  Encoded data: ";
        printHex(encoded);

        // Decode
        ZCBORDecoder decoder(encoded);
        AttributeValue attr_decoded = attr_ser.decodeAttribute(decoder);

        // Re-encode
        ZCBOREncoder encoder2;
        attr_ser.encodeAttribute(encoder2, attr_decoded);
        auto reencoded = encoder2.getEncoded();

        // Verify bit-for-bit match
        if (encoded == reencoded && attr_decoded.string_value == attr.string_value) {
            std::cout << "✓ Attribute round-trip successful" << std::endl;
            tests_passed++;
            return true;
        } else {
            std::cout << "❌ Attribute round-trip failed" << std::endl;
            tests_failed++;
            return false;
        }
    } catch (const std::exception& e) {
        std::cout << "❌ Attribute test failed with exception: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

bool testPolicyRoundtrip() {
    std::cout << "\nTesting policy round-trip..." << std::endl;

    try {
        // Create simple policy: "attr1 and attr2"
        std::unique_ptr<OpenABEPolicy> policy(new OpenABEPolicy());

        std::unique_ptr<OpenABETreeNode> root(new OpenABETreeNode());
        root->setNodeType(GATE_TYPE_AND);

        std::unique_ptr<OpenABETreeNode> leaf1(new OpenABETreeNode());
        leaf1->setNodeType(GATE_TYPE_LEAF);
        leaf1->setLabel("attr1");

        std::unique_ptr<OpenABETreeNode> leaf2(new OpenABETreeNode());
        leaf2->setNodeType(GATE_TYPE_LEAF);
        leaf2->setLabel("attr2");

        root->addSubnode(leaf1.release());
        root->addSubnode(leaf2.release());
        policy->setRootNode(root.release());

        // Encode
        PolicySerializer pol_ser;
        ZCBOREncoder encoder;
        pol_ser.encodeBooleanAST(encoder, *policy);
        auto encoded = encoder.getEncoded();

        std::cout << "  Encoded size: " << encoded.size() << " bytes" << std::endl;
        std::cout << "  Encoded data: ";
        printHex(encoded);

        // Decode
        ZCBORDecoder decoder(encoded);
        std::unique_ptr<OpenABEPolicy> policy_decoded = pol_ser.decodeBooleanAST(decoder);

        // Re-encode
        ZCBOREncoder encoder2;
        pol_ser.encodeBooleanAST(encoder2, *policy_decoded);
        auto reencoded = encoder2.getEncoded();

        // Verify bit-for-bit match
        if (encoded == reencoded) {
            std::cout << "✓ Policy round-trip successful" << std::endl;
            tests_passed++;
            return true;
        } else {
            std::cout << "❌ Policy round-trip failed" << std::endl;
            tests_failed++;
            return false;
        }
    } catch (const std::exception& e) {
        std::cout << "❌ Policy test failed with exception: " << e.what() << std::endl;
        tests_failed++;
        return false;
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "WASM CBOR Serialization Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    InitializeOpenABE();

    // Run tests
    testG1Roundtrip();
    testAttributeRoundtrip();
    testPolicyRoundtrip();

    // Print summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;
    std::cout << "Total:  " << (tests_passed + tests_failed) << std::endl;

    if (tests_failed == 0) {
        std::cout << "\n✅ All WASM CBOR tests passed!" << std::endl;
        ShutdownOpenABE();
        return 0;
    } else {
        std::cout << "\n❌ Some WASM CBOR tests failed" << std::endl;
        ShutdownOpenABE();
        return 1;
    }
}
