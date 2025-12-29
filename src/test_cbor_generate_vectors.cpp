///
/// Cross-platform test vector generator for ABE-CBOR
///
/// This program generates canonical test vectors that can be used
/// to verify cross-platform compatibility between native and WASM builds.
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

void writeVectorFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out.close();
    std::cout << "Wrote " << data.size() << " bytes to " << filename << std::endl;
}

void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " (" << data.size() << " bytes):" << std::endl;
    std::cout << "  ";
    for (size_t i = 0; i < data.size(); i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < data.size()) {
            std::cout << std::endl << "  ";
        }
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "=== ABE-CBOR Cross-Platform Test Vector Generator ===" << std::endl;
    std::cout << std::endl;

    try {
        InitializeOpenABE();
        OpenABEPairing pairing("BLS12_P381");
        OpenABERNG rng;

        GroupElementSerializer ge_ser(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
        AttributeSerializer attr_ser;
        PolicySerializer policy_ser;

        // Vector 1: G1 element
        std::cout << "=== Vector 1: G1 Element ===" << std::endl;
        {
            G1 g1 = pairing.randomG1(&rng);
            ZCBOREncoder encoder;
            ge_ser.encodeG1(encoder, g1);
            auto encoded = encoder.getEncoded();

            printHex("G1 encoding", encoded);
            writeVectorFile("test_vectors/g1_element.cbor", encoded);
        }

        // Vector 2: G2 element
        std::cout << "\n=== Vector 2: G2 Element ===" << std::endl;
        {
            G2 g2 = pairing.randomG2(&rng);
            ZCBOREncoder encoder;
            ge_ser.encodeG2(encoder, g2);
            auto encoded = encoder.getEncoded();

            printHex("G2 encoding", encoded);
            writeVectorFile("test_vectors/g2_element.cbor", encoded);
        }

        // Vector 3: GT element
        std::cout << "\n=== Vector 3: GT Element ===" << std::endl;
        {
            G1 g1 = pairing.randomG1(&rng);
            G2 g2 = pairing.randomG2(&rng);
            GT gt = pairing.pairing(g1, g2);

            ZCBOREncoder encoder;
            ge_ser.encodeGT(encoder, gt);
            auto encoded = encoder.getEncoded();

            printHex("GT encoding", encoded);
            writeVectorFile("test_vectors/gt_element.cbor", encoded);
        }

        // Vector 4: Zr element
        std::cout << "\n=== Vector 4: Zr Element ===" << std::endl;
        {
            ZP zr = pairing.randomZP(&rng);
            ZCBOREncoder encoder;
            ge_ser.encodeZr(encoder, zr);
            auto encoded = encoder.getEncoded();

            printHex("Zr encoding", encoded);
            writeVectorFile("test_vectors/zr_element.cbor", encoded);
        }

        // Vector 5: String attribute
        std::cout << "\n=== Vector 5: String Attribute ===" << std::endl;
        {
            AttributeValue attr("department");
            ZCBOREncoder encoder;
            attr_ser.encodeAttribute(encoder, attr);
            auto encoded = encoder.getEncoded();

            printHex("String attribute", encoded);
            writeVectorFile("test_vectors/attr_string.cbor", encoded);
        }

        // Vector 6: Integer attribute
        std::cout << "\n=== Vector 6: Integer Attribute ===" << std::endl;
        {
            AttributeValue attr(42);
            ZCBOREncoder encoder;
            attr_ser.encodeAttribute(encoder, attr);
            auto encoded = encoder.getEncoded();

            printHex("Integer attribute", encoded);
            writeVectorFile("test_vectors/attr_integer.cbor", encoded);
        }

        // Vector 7: Bytes attribute
        std::cout << "\n=== Vector 7: Bytes Attribute ===" << std::endl;
        {
            std::vector<uint8_t> bytes = {0xDE, 0xAD, 0xBE, 0xEF};
            AttributeValue attr(bytes);
            ZCBOREncoder encoder;
            attr_ser.encodeAttribute(encoder, attr);
            auto encoded = encoder.getEncoded();

            printHex("Bytes attribute", encoded);
            writeVectorFile("test_vectors/attr_bytes.cbor", encoded);
        }

        // Vector 8: Attribute list (sorted)
        std::cout << "\n=== Vector 8: Attribute List ===" << std::endl;
        {
            std::vector<AttributeValue> attrs;
            attrs.push_back(AttributeValue("role"));
            attrs.push_back(AttributeValue(100));
            attrs.push_back(AttributeValue("department"));
            attrs.push_back(AttributeValue(42));

            ZCBOREncoder encoder;
            attr_ser.encodeAttributeList(encoder, attrs);
            auto encoded = encoder.getEncoded();

            printHex("Attribute list (sorted)", encoded);
            writeVectorFile("test_vectors/attr_list.cbor", encoded);
        }

        // Vector 9: Simple AND policy
        std::cout << "\n=== Vector 9: Simple AND Policy ===" << std::endl;
        {
            std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("A and B");

            ZCBOREncoder encoder;
            policy_ser.encodeBooleanAST(encoder, *policy);
            auto encoded = encoder.getEncoded();

            printHex("Policy (A and B)", encoded);
            writeVectorFile("test_vectors/policy_and.cbor", encoded);
        }

        // Vector 10: Nested policy
        std::cout << "\n=== Vector 10: Nested Policy ===" << std::endl;
        {
            std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("(A and B) or C");

            ZCBOREncoder encoder;
            policy_ser.encodeBooleanAST(encoder, *policy);
            auto encoded = encoder.getEncoded();

            printHex("Policy ((A and B) or C)", encoded);
            writeVectorFile("test_vectors/policy_nested.cbor", encoded);
        }

        // Vector 11: Complex policy
        std::cout << "\n=== Vector 11: Complex Policy ===" << std::endl;
        {
            std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("(A and B) or (C and D)");

            ZCBOREncoder encoder;
            policy_ser.encodeBooleanAST(encoder, *policy);
            auto encoded = encoder.getEncoded();

            printHex("Policy ((A and B) or (C and D))", encoded);
            writeVectorFile("test_vectors/policy_complex.cbor", encoded);
        }

        // Vector 12: Array of group elements
        std::cout << "\n=== Vector 12: Array of Group Elements ===" << std::endl;
        {
            std::vector<G1> g1_array;
            for (int i = 0; i < 3; i++) {
                g1_array.push_back(pairing.randomG1(&rng));
            }

            ZCBOREncoder encoder;
            encoder.beginArray(g1_array.size());
            for (const auto& g1 : g1_array) {
                ge_ser.encodeG1(encoder, g1);
            }
            auto encoded = encoder.getEncoded();

            printHex("Array of 3 G1 elements", encoded);
            writeVectorFile("test_vectors/g1_array.cbor", encoded);
        }

        std::cout << "\n✅ All test vectors generated successfully!" << std::endl;
        std::cout << "\nTest vectors are in the 'test_vectors/' directory." << std::endl;
        std::cout << "These can be used to verify cross-platform compatibility." << std::endl;

        ShutdownOpenABE();
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }
}
