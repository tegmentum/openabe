///
/// Simple standalone test for CBOR wrapper (no gtest required)
///

#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_constants.h>
#include <iostream>
#include <iomanip>
#include <cassert>

using namespace oabe;
using namespace oabe::cbor;

static void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (size_t i = 0; i < data.size(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)data[i];
        if (i < data.size() - 1) std::cout << " ";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "Testing CBOR wrapper..." << std::endl;
    std::cout << "ABE-CBOR Version: " << ABE_CBOR_VERSION << std::endl;
    std::cout << "ABE-CBOR Tag: " << ABE_CBOR_TAG << std::endl;

    try {
        // Test 1: Encode and decode unsigned integer
        std::cout << "\n[TEST 1] Encode/decode unsigned integer (42)" << std::endl;
        ZCBOREncoder encoder;
        encoder.encodeUInt(42);
        auto encoded = encoder.getEncoded();
        printHex("Encoded", encoded);

        ZCBORDecoder decoder(encoded);
        assert(decoder.isUInt());
        uint64_t value = decoder.decodeUInt();
        assert(value == 42);
        std::cout << "✓ Decoded value: " << value << std::endl;

        // Test 2: Encode and decode text string
        std::cout << "\n[TEST 2] Encode/decode text string (hello)" << std::endl;
        ZCBOREncoder encoder2;
        encoder2.encodeText("hello");
        auto encoded2 = encoder2.getEncoded();
        printHex("Encoded", encoded2);

        ZCBORDecoder decoder2(encoded2);
        assert(decoder2.isText());
        std::string text = decoder2.decodeText();
        assert(text == "hello");
        std::cout << "✓ Decoded text: " << text << std::endl;

        // Test 3: Encode and decode byte string
        std::cout << "\n[TEST 3] Encode/decode byte string" << std::endl;
        ZCBOREncoder encoder3;
        std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04, 0x05};
        encoder3.encodeBytes(bytes);
        auto encoded3 = encoder3.getEncoded();
        printHex("Encoded", encoded3);

        ZCBORDecoder decoder3(encoded3);
        assert(decoder3.isBytes());
        std::vector<uint8_t> decoded_bytes = decoder3.decodeBytes();
        assert(decoded_bytes == bytes);
        std::cout << "✓ Decoded bytes match" << std::endl;

        // Test 4: Constants
        std::cout << "\n[TEST 4] Check constants" << std::endl;
        assert((uint32_t)ABEKind::MSK == 1);
        assert((uint32_t)ABEKind::MPK == 2);
        assert((uint32_t)ABEKind::SK == 3);
        assert((uint32_t)ABEKind::CT == 4);
        std::cout << "✓ ABEKind constants correct" << std::endl;

        assert(std::string(scheme::CPABE_WATERS) == "cpabe-waters");
        assert(std::string(curve::BLS12_381) == "bls12-381");
        std::cout << "✓ Scheme and curve constants correct" << std::endl;

        assert((uint32_t)GEEncoding::IETF_COMPRESSED == 0);
        assert((uint32_t)GEEncoding::UNCOMPRESSED == 1);
        std::cout << "✓ GE encoding constants correct" << std::endl;

        // Test 5: Helper functions
        std::cout << "\n[TEST 5] Check helper functions" << std::endl;
        assert(std::string(abeKindToString(ABEKind::MSK)) == "MSK");
        assert(std::string(abeKindToString(ABEKind::CT)) == "CT");
        std::cout << "✓ abeKindToString works" << std::endl;

        assert(std::string(geEncodingToString(GEEncoding::IETF_COMPRESSED)) == "ietf-compressed");
        std::cout << "✓ geEncodingToString works" << std::endl;

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
