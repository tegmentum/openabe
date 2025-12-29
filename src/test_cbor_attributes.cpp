///
/// Test program for ABE-CBOR attribute serialization
///

#include <openabe/openabe.h>
#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_attributes.h>
#include <iostream>
#include <iomanip>
#include <cassert>

using namespace oabe;
using namespace oabe::cbor;

static void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < std::min(data.size(), size_t(64)); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)data[i];
        if (i < data.size() - 1) std::cout << " ";
    }
    if (data.size() > 64) std::cout << " ...";
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "Testing ABE-CBOR Attribute Serialization..." << std::endl;

    try {
        AttributeSerializer serializer;

        std::cout << "\n=== Test 1: String Attribute Round-Trip ===" << std::endl;
        {
            // Create string attribute
            AttributeValue attr_orig("department");

            std::cout << "Original attribute: type=STRING, value=\"department\"" << std::endl;

            // Serialize to CBOR
            ZCBOREncoder encoder;
            serializer.encodeAttribute(encoder, attr_orig);

            auto encoded = encoder.getEncoded();
            printHex("Encoded attribute", encoded);

            // Deserialize from CBOR
            ZCBORDecoder decoder(encoded);
            AttributeValue attr_decoded = serializer.decodeAttribute(decoder);

            std::cout << "Decoded attribute: type=" << attributeTypeToString(attr_decoded.type)
                      << ", value=\"" << attr_decoded.string_value << "\"" << std::endl;

            // Verify they're equal
            assert(attr_orig == attr_decoded);
            std::cout << "✓ String attribute round-trip successful!" << std::endl;
        }

        std::cout << "\n=== Test 2: Integer Attribute Round-Trip ===" << std::endl;
        {
            // Create integer attribute
            AttributeValue attr_orig(42);

            std::cout << "Original attribute: type=INTEGER, value=42" << std::endl;

            // Serialize to CBOR
            ZCBOREncoder encoder;
            serializer.encodeAttribute(encoder, attr_orig);

            auto encoded = encoder.getEncoded();
            printHex("Encoded attribute", encoded);

            // Deserialize from CBOR
            ZCBORDecoder decoder(encoded);
            AttributeValue attr_decoded = serializer.decodeAttribute(decoder);

            std::cout << "Decoded attribute: type=" << attributeTypeToString(attr_decoded.type)
                      << ", value=" << attr_decoded.int_value << std::endl;

            // Verify they're equal
            assert(attr_orig == attr_decoded);
            std::cout << "✓ Integer attribute round-trip successful!" << std::endl;
        }

        std::cout << "\n=== Test 3: Bytes Attribute Round-Trip ===" << std::endl;
        {
            // Create bytes attribute
            std::vector<uint8_t> bytes = {0xDE, 0xAD, 0xBE, 0xEF};
            AttributeValue attr_orig(bytes);

            std::cout << "Original attribute: type=BYTES, value=";
            printHex("", bytes);

            // Serialize to CBOR
            ZCBOREncoder encoder;
            serializer.encodeAttribute(encoder, attr_orig);

            auto encoded = encoder.getEncoded();
            printHex("Encoded attribute", encoded);

            // Deserialize from CBOR
            ZCBORDecoder decoder(encoded);
            AttributeValue attr_decoded = serializer.decodeAttribute(decoder);

            std::cout << "Decoded attribute: type=" << attributeTypeToString(attr_decoded.type) << std::endl;

            // Verify they're equal
            assert(attr_orig == attr_decoded);
            std::cout << "✓ Bytes attribute round-trip successful!" << std::endl;
        }

        std::cout << "\n=== Test 4: Attribute List with Sorting ===" << std::endl;
        {
            // Create unsorted attribute list
            std::vector<AttributeValue> attrs;
            attrs.push_back(AttributeValue("role"));
            attrs.push_back(AttributeValue(100));
            attrs.push_back(AttributeValue("department"));
            attrs.push_back(AttributeValue(42));

            std::cout << "Original attributes (unsorted):" << std::endl;
            for (const auto& attr : attrs) {
                if (attr.type == AttributeType::STRING) {
                    std::cout << "  - STRING: \"" << attr.string_value << "\"" << std::endl;
                } else if (attr.type == AttributeType::INTEGER) {
                    std::cout << "  - INTEGER: " << attr.int_value << std::endl;
                }
            }

            // Serialize to CBOR (will sort automatically)
            ZCBOREncoder encoder;
            serializer.encodeAttributeList(encoder, attrs);

            auto encoded = encoder.getEncoded();
            printHex("Encoded attribute list", encoded);

            // Note: attrs will be sorted after encodeAttributeList
            std::cout << "After sorting:" << std::endl;
            for (const auto& attr : attrs) {
                if (attr.type == AttributeType::STRING) {
                    std::cout << "  - STRING: \"" << attr.string_value << "\"" << std::endl;
                } else if (attr.type == AttributeType::INTEGER) {
                    std::cout << "  - INTEGER: " << attr.int_value << std::endl;
                }
            }

            // Deserialize from CBOR
            ZCBORDecoder decoder(encoded);
            std::vector<AttributeValue> attrs_decoded = serializer.decodeAttributeList(decoder);

            std::cout << "Decoded " << attrs_decoded.size() << " attributes" << std::endl;

            // Verify count matches
            assert(attrs.size() == attrs_decoded.size());
            std::cout << "✓ Attribute list round-trip successful!" << std::endl;
        }

        std::cout << "\n=== Test 5: Range Attribute Round-Trip ===" << std::endl;
        {
            // Create range attribute [18, 65]
            AttributeValue attr_orig;
            attr_orig.type = AttributeType::RANGE;
            attr_orig.range_value.min = 18;
            attr_orig.range_value.max = 65;
            attr_orig.range_value.min_inclusive = true;
            attr_orig.range_value.max_inclusive = true;

            std::cout << "Original attribute: type=RANGE, value=[18, 65]" << std::endl;

            // Serialize to CBOR
            ZCBOREncoder encoder;
            serializer.encodeAttribute(encoder, attr_orig);

            auto encoded = encoder.getEncoded();
            printHex("Encoded attribute", encoded);

            // Deserialize from CBOR
            ZCBORDecoder decoder(encoded);
            AttributeValue attr_decoded = serializer.decodeAttribute(decoder);

            std::cout << "Decoded attribute: type=" << attributeTypeToString(attr_decoded.type)
                      << ", range=[" << attr_decoded.range_value.min
                      << ", " << attr_decoded.range_value.max << "]" << std::endl;

            // Verify they're equal
            assert(attr_orig == attr_decoded);
            std::cout << "✓ Range attribute round-trip successful!" << std::endl;
        }

        std::cout << "\n=== Test 6: UTF-8 Validation ===" << std::endl;
        {
            // Test valid UTF-8 strings
            std::string valid1 = "café";  // UTF-8: café
            std::string valid2 = "日本語";  // Japanese
            std::string valid3 = "Hello, World!";  // ASCII

            assert(AttributeSerializer::isValidUTF8(valid1));
            assert(AttributeSerializer::isValidUTF8(valid2));
            assert(AttributeSerializer::isValidUTF8(valid3));

            std::cout << "✓ Valid UTF-8 strings validated correctly!" << std::endl;

            // Test invalid UTF-8
            std::string invalid = "\xFF\xFE";  // Invalid UTF-8 sequence
            assert(!AttributeSerializer::isValidUTF8(invalid));

            std::cout << "✓ Invalid UTF-8 string rejected correctly!" << std::endl;
        }

        std::cout << "\n✅ All tests passed!" << std::endl;
        return 0;

    } catch (const ZCBORException& e) {
        std::cerr << "❌ CBOR error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }
}
