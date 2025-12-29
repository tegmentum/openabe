///
/// Test program for ABE-CBOR group element serialization
///

#include <openabe/openabe.h>
#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_group_elements.h>
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
    std::cout << "Testing ABE-CBOR Group Element Serialization..." << std::endl;

    try {
        // Initialize OpenABE
        InitializeOpenABE();

        // Create pairing object for BLS12-381
        OpenABEPairing pairing("BLS12_P381");
        OpenABERNG rng;

        std::cout << "\n=== Test 1: G1 Element Round-Trip ===" << std::endl;
        {
            // Create random G1 element
            G1 g1_orig = pairing.randomG1(&rng);

            std::cout << "Original G1 element created" << std::endl;

            // Serialize to CBOR
            ZCBOREncoder encoder;
            GroupElementSerializer serializer(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
            serializer.encodeG1(encoder, g1_orig);

            auto encoded = encoder.getEncoded();
            printHex("Encoded G1", encoded);

            // Deserialize from CBOR
            ZCBORDecoder decoder(encoded);
            G1 g1_decoded = pairing.initG1();
            serializer.decodeG1(decoder, g1_decoded, OpenABE_BLS12_P381_ID);

            std::cout << "Decoded G1 element" << std::endl;

            // Verify they're equal
            assert(g1_orig == g1_decoded);
            std::cout << "✓ G1 round-trip successful!" << std::endl;
        }

        std::cout << "\n=== Test 2: G2 Element Round-Trip ===" << std::endl;
        {
            // Create random G2 element
            G2 g2_orig = pairing.randomG2(&rng);

            std::cout << "Original G2 element created" << std::endl;

            // Serialize to CBOR
            ZCBOREncoder encoder;
            GroupElementSerializer serializer(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
            serializer.encodeG2(encoder, g2_orig);

            auto encoded = encoder.getEncoded();
            printHex("Encoded G2", encoded);

            // Deserialize from CBOR
            ZCBORDecoder decoder(encoded);
            G2 g2_decoded = pairing.initG2();
            serializer.decodeG2(decoder, g2_decoded, OpenABE_BLS12_P381_ID);

            std::cout << "Decoded G2 element" << std::endl;

            // Verify they're equal
            assert(g2_orig == g2_decoded);
            std::cout << "✓ G2 round-trip successful!" << std::endl;
        }

        std::cout << "\n=== Test 3: GT Element Round-Trip ===" << std::endl;
        {
            // Create GT element via pairing
            G1 g1 = pairing.randomG1(&rng);
            G2 g2 = pairing.randomG2(&rng);
            GT gt_orig = pairing.pairing(g1, g2);

            std::cout << "Original GT element created" << std::endl;

            // Serialize to CBOR
            ZCBOREncoder encoder;
            GroupElementSerializer serializer(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
            serializer.encodeGT(encoder, gt_orig);

            auto encoded = encoder.getEncoded();
            printHex("Encoded GT", encoded);

            // Deserialize from CBOR
            ZCBORDecoder decoder(encoded);
            GT gt_decoded = pairing.initGT();
            serializer.decodeGT(decoder, gt_decoded);

            std::cout << "Decoded GT element" << std::endl;

            // Verify they're equal
            assert(gt_orig == gt_decoded);
            std::cout << "✓ GT round-trip successful!" << std::endl;
        }

        std::cout << "\n=== Test 4: Zr (Scalar) Element Round-Trip ===" << std::endl;
        {
            // Create random Zr element
            ZP zr_orig = pairing.randomZP(&rng);
            bignum_t order = pairing.order;

            std::cout << "Original Zr element created" << std::endl;

            // Serialize to CBOR
            ZCBOREncoder encoder;
            GroupElementSerializer serializer(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
            serializer.encodeZr(encoder, zr_orig);

            auto encoded = encoder.getEncoded();
            printHex("Encoded Zr", encoded);

            // Deserialize from CBOR
            ZCBORDecoder decoder(encoded);
            ZP zr_decoded;
            serializer.decodeZr(decoder, zr_decoded, &order);

            std::cout << "Decoded Zr element" << std::endl;

            // Verify they're equal
            assert(zr_orig == zr_decoded);
            std::cout << "✓ Zr round-trip successful!" << std::endl;
        }

        std::cout << "\n=== Test 5: Endianness Conversion ===" << std::endl;
        {
            // Test with both endiannesses
            G1 g1 = pairing.randomG1(&rng);

            // Big-endian encoding
            ZCBOREncoder encoder_big;
            GroupElementSerializer serializer_big(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
            serializer_big.encodeG1(encoder_big, g1);
            auto encoded_big = encoder_big.getEncoded();

            // Little-endian encoding
            ZCBOREncoder encoder_little;
            GroupElementSerializer serializer_little(GEEncoding::IETF_COMPRESSED, Endianness::LITTLE);
            serializer_little.encodeG1(encoder_little, g1);
            auto encoded_little = encoder_little.getEncoded();

            printHex("Big-endian G1", encoded_big);
            printHex("Little-endian G1", encoded_little);

            // Decode both
            ZCBORDecoder decoder_big(encoded_big);
            G1 g1_from_big = pairing.initG1();
            serializer_big.decodeG1(decoder_big, g1_from_big, OpenABE_BLS12_P381_ID);

            ZCBORDecoder decoder_little(encoded_little);
            G1 g1_from_little = pairing.initG1();
            serializer_little.decodeG1(decoder_little, g1_from_little, OpenABE_BLS12_P381_ID);

            // Both should equal original
            assert(g1 == g1_from_big);
            assert(g1 == g1_from_little);
            std::cout << "✓ Endianness conversion works correctly!" << std::endl;
        }

        std::cout << "\n=== Test 6: Array of Group Elements ===" << std::endl;
        {
            // Create array of 3 G1 elements
            std::vector<G1> g1_array;
            for (int i = 0; i < 3; i++) {
                G1 g1 = pairing.randomG1(&rng);
                g1_array.push_back(g1);
            }

            // Encode array to CBOR
            ZCBOREncoder encoder;
            encoder.beginArray(g1_array.size());

            GroupElementSerializer serializer(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
            for (const auto& g1 : g1_array) {
                serializer.encodeG1(encoder, g1);
            }

            auto encoded = encoder.getEncoded();
            printHex("Encoded G1 array", encoded);

            // Decode array from CBOR
            ZCBORDecoder decoder(encoded);
            size_t array_len = decoder.enterArray();
            assert(array_len == 3);

            std::vector<G1> g1_decoded_array;
            for (size_t i = 0; i < array_len; i++) {
                G1 g1 = pairing.initG1();
                serializer.decodeG1(decoder, g1, OpenABE_BLS12_P381_ID);
                g1_decoded_array.push_back(g1);
            }

            // Verify all elements match
            for (size_t i = 0; i < g1_array.size(); i++) {
                assert(g1_array[i] == g1_decoded_array[i]);
            }
            std::cout << "✓ Array of G1 elements round-trip successful!" << std::endl;
        }

        std::cout << "\n✅ All tests passed!" << std::endl;

        // Cleanup
        ShutdownOpenABE();
        return 0;

    } catch (const ZCBORException& e) {
        std::cerr << "❌ CBOR error: " << e.what() << std::endl;
        ShutdownOpenABE();
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        ShutdownOpenABE();
        return 1;
    }
}
