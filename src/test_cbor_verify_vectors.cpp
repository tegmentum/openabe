///
/// Cross-platform test vector verifier for ABE-CBOR
///
/// This program verifies test vectors generated on another platform
/// to ensure cross-platform compatibility.
///

#include <iostream>
#include <fstream>
#include <iomanip>
#include <openabe/openabe.h>
#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_group_elements.h>
#include <openabe/cbor/zcbor_attributes.h>
#include <openabe/cbor/zcbor_policy.h>

using namespace oabe;
using namespace oabe::cbor;

std::vector<uint8_t> readVectorFile(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    in.seekg(0, std::ios::end);
    size_t size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    in.read(reinterpret_cast<char*>(data.data()), size);
    in.close();

    std::cout << "Read " << size << " bytes from " << filename << std::endl;
    return data;
}

void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " (" << data.size() << " bytes):" << std::endl;
    std::cout << "  ";
    for (size_t i = 0; i < data.size() && i < 64; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < data.size()) {
            std::cout << std::endl << "  ";
        }
    }
    if (data.size() > 64) {
        std::cout << std::endl << "  ... (" << (data.size() - 64) << " more bytes)";
    }
    std::cout << std::endl;
}

bool verifyRoundTrip(const std::string& name, const std::vector<uint8_t>& original,
                     const std::vector<uint8_t>& reencoded) {
    if (original.size() != reencoded.size()) {
        std::cout << "❌ " << name << ": Size mismatch (original=" << original.size()
                  << ", reencoded=" << reencoded.size() << ")" << std::endl;
        return false;
    }

    if (original != reencoded) {
        std::cout << "❌ " << name << ": Content mismatch" << std::endl;
        std::cout << "Original:" << std::endl;
        printHex("", original);
        std::cout << "Re-encoded:" << std::endl;
        printHex("", reencoded);
        return false;
    }

    std::cout << "✓ " << name << ": Round-trip successful (" << original.size() << " bytes)" << std::endl;
    return true;
}

int main() {
    std::cout << "=== ABE-CBOR Cross-Platform Test Vector Verifier ===" << std::endl;
    std::cout << std::endl;

    int passed = 0;
    int failed = 0;

    try {
        InitializeOpenABE();
        OpenABEPairing pairing("BLS12_P381");

        GroupElementSerializer ge_ser(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
        AttributeSerializer attr_ser;
        PolicySerializer policy_ser;

        // Vector 1: G1 element
        std::cout << "=== Vector 1: G1 Element ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/g1_element.cbor");
            ZCBORDecoder decoder(data);

            G1 g1 = pairing.initG1();
            ge_ser.decodeG1(decoder, g1, OpenABE_BLS12_P381_ID);

            // Re-encode
            ZCBOREncoder encoder;
            ge_ser.encodeG1(encoder, g1);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("G1 element", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ G1 element: " << e.what() << std::endl;
            failed++;
        }

        // Vector 2: G2 element
        std::cout << "\n=== Vector 2: G2 Element ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/g2_element.cbor");
            ZCBORDecoder decoder(data);

            G2 g2 = pairing.initG2();
            ge_ser.decodeG2(decoder, g2, OpenABE_BLS12_P381_ID);

            // Re-encode
            ZCBOREncoder encoder;
            ge_ser.encodeG2(encoder, g2);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("G2 element", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ G2 element: " << e.what() << std::endl;
            failed++;
        }

        // Vector 3: GT element
        std::cout << "\n=== Vector 3: GT Element ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/gt_element.cbor");
            ZCBORDecoder decoder(data);

            GT gt = pairing.initGT();
            ge_ser.decodeGT(decoder, gt);

            // Re-encode
            ZCBOREncoder encoder;
            ge_ser.encodeGT(encoder, gt);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("GT element", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ GT element: " << e.what() << std::endl;
            failed++;
        }

        // Vector 4: Zr element
        std::cout << "\n=== Vector 4: Zr Element ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/zr_element.cbor");
            ZCBORDecoder decoder(data);

            ZP zr = pairing.initZP();
            ge_ser.decodeZr(decoder, zr, &pairing.order);

            // Re-encode
            ZCBOREncoder encoder;
            ge_ser.encodeZr(encoder, zr);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("Zr element", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ Zr element: " << e.what() << std::endl;
            failed++;
        }

        // Vector 5: String attribute
        std::cout << "\n=== Vector 5: String Attribute ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/attr_string.cbor");
            ZCBORDecoder decoder(data);

            AttributeValue attr = attr_ser.decodeAttribute(decoder);

            // Re-encode
            ZCBOREncoder encoder;
            attr_ser.encodeAttribute(encoder, attr);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("String attribute", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ String attribute: " << e.what() << std::endl;
            failed++;
        }

        // Vector 6: Integer attribute
        std::cout << "\n=== Vector 6: Integer Attribute ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/attr_integer.cbor");
            ZCBORDecoder decoder(data);

            AttributeValue attr = attr_ser.decodeAttribute(decoder);

            // Re-encode
            ZCBOREncoder encoder;
            attr_ser.encodeAttribute(encoder, attr);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("Integer attribute", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ Integer attribute: " << e.what() << std::endl;
            failed++;
        }

        // Vector 7: Bytes attribute
        std::cout << "\n=== Vector 7: Bytes Attribute ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/attr_bytes.cbor");
            ZCBORDecoder decoder(data);

            AttributeValue attr = attr_ser.decodeAttribute(decoder);

            // Re-encode
            ZCBOREncoder encoder;
            attr_ser.encodeAttribute(encoder, attr);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("Bytes attribute", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ Bytes attribute: " << e.what() << std::endl;
            failed++;
        }

        // Vector 8: Attribute list
        std::cout << "\n=== Vector 8: Attribute List ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/attr_list.cbor");
            ZCBORDecoder decoder(data);

            std::vector<AttributeValue> attrs = attr_ser.decodeAttributeList(decoder);

            // Re-encode
            ZCBOREncoder encoder;
            attr_ser.encodeAttributeList(encoder, attrs);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("Attribute list", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ Attribute list: " << e.what() << std::endl;
            failed++;
        }

        // Vector 9: Simple AND policy
        std::cout << "\n=== Vector 9: Simple AND Policy ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/policy_and.cbor");
            ZCBORDecoder decoder(data);

            std::unique_ptr<OpenABEPolicy> policy = policy_ser.decodeBooleanAST(decoder);

            // Re-encode
            ZCBOREncoder encoder;
            policy_ser.encodeBooleanAST(encoder, *policy);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("Policy (A and B)", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ Policy (A and B): " << e.what() << std::endl;
            failed++;
        }

        // Vector 10: Nested policy
        std::cout << "\n=== Vector 10: Nested Policy ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/policy_nested.cbor");
            ZCBORDecoder decoder(data);

            std::unique_ptr<OpenABEPolicy> policy = policy_ser.decodeBooleanAST(decoder);

            // Re-encode
            ZCBOREncoder encoder;
            policy_ser.encodeBooleanAST(encoder, *policy);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("Policy ((A and B) or C)", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ Policy ((A and B) or C): " << e.what() << std::endl;
            failed++;
        }

        // Vector 11: Complex policy
        std::cout << "\n=== Vector 11: Complex Policy ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/policy_complex.cbor");
            ZCBORDecoder decoder(data);

            std::unique_ptr<OpenABEPolicy> policy = policy_ser.decodeBooleanAST(decoder);

            // Re-encode
            ZCBOREncoder encoder;
            policy_ser.encodeBooleanAST(encoder, *policy);
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("Policy ((A and B) or (C and D))", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ Policy ((A and B) or (C and D)): " << e.what() << std::endl;
            failed++;
        }

        // Vector 12: Array of G1 elements
        std::cout << "\n=== Vector 12: Array of Group Elements ===" << std::endl;
        try {
            auto data = readVectorFile("test_vectors/g1_array.cbor");
            ZCBORDecoder decoder(data);

            size_t array_size = decoder.enterArray();
            std::vector<G1> g1_array;
            for (size_t i = 0; i < array_size; i++) {
                G1 g1 = pairing.initG1();
                ge_ser.decodeG1(decoder, g1, OpenABE_BLS12_P381_ID);
                g1_array.push_back(g1);
            }
            decoder.exitArray();

            // Re-encode
            ZCBOREncoder encoder;
            encoder.beginArray(g1_array.size());
            for (const auto& g1 : g1_array) {
                ge_ser.encodeG1(encoder, g1);
            }
            auto reencoded = encoder.getEncoded();

            if (verifyRoundTrip("Array of G1 elements", data, reencoded)) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "❌ Array of G1 elements: " << e.what() << std::endl;
            failed++;
        }

        std::cout << "\n=== Summary ===" << std::endl;
        std::cout << "Passed: " << passed << std::endl;
        std::cout << "Failed: " << failed << std::endl;
        std::cout << "Total:  " << (passed + failed) << std::endl;

        if (failed == 0) {
            std::cout << "\n✅ All cross-platform test vectors verified successfully!" << std::endl;
        } else {
            std::cout << "\n❌ Some test vectors failed verification" << std::endl;
        }

        ShutdownOpenABE();
        return (failed == 0) ? 0 : 1;

    } catch (const std::exception& e) {
        std::cerr << "❌ Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
