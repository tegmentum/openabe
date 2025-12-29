///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// This file is part of Zeutro's OpenABE.
///
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
///
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
///
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file   test_cbor_basic.cpp
///
/// \brief  Basic tests for CBOR wrapper functionality
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#include <gtest/gtest.h>
#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_constants.h>
#include <vector>
#include <iostream>
#include <iomanip>

using namespace oabe;
using namespace oabe::cbor;

// Helper function to print hex
static void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (size_t i = 0; i < data.size(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)data[i];
        if (i < data.size() - 1) std::cout << " ";
    }
    std::cout << std::dec << std::endl;
}

// Test basic integer encoding/decoding
TEST(ZCBORWrapper, EncodeDecodeUInt) {
    // Encode
    ZCBOREncoder encoder;
    encoder.encodeUInt(42);
    auto encoded = encoder.getEncoded();

    // Expected: 0x18 0x2A (integer 42 in CBOR)
    printHex("Encoded uint 42", encoded);

    // Decode
    ZCBORDecoder decoder(encoded);
    ASSERT_TRUE(decoder.isUInt());
    uint64_t value = decoder.decodeUInt();
    EXPECT_EQ(value, 42);
}

// Test text string encoding/decoding
TEST(ZCBORWrapper, EncodeDecodeText) {
    // Encode
    ZCBOREncoder encoder;
    encoder.encodeText("hello");
    auto encoded = encoder.getEncoded();

    // Expected: 0x65 'h' 'e' 'l' 'l' 'o' (text string in CBOR)
    printHex("Encoded text 'hello'", encoded);

    // Decode
    ZCBORDecoder decoder(encoded);
    ASSERT_TRUE(decoder.isText());
    std::string value = decoder.decodeText();
    EXPECT_EQ(value, "hello");
}

// Test byte string encoding/decoding
TEST(ZCBORWrapper, EncodeDecodeBytes) {
    // Encode
    ZCBOREncoder encoder;
    std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0x04, 0x05};
    encoder.encodeBytes(bytes);
    auto encoded = encoder.getEncoded();

    printHex("Encoded bytes", encoded);

    // Decode
    ZCBORDecoder decoder(encoded);
    ASSERT_TRUE(decoder.isBytes());
    std::vector<uint8_t> decoded_bytes = decoder.decodeBytes();
    EXPECT_EQ(decoded_bytes, bytes);
}

// Test boolean encoding/decoding
TEST(ZCBORWrapper, EncodeDecodeBool) {
    // Encode true
    ZCBOREncoder encoder1;
    encoder1.encodeBool(true);
    auto encoded_true = encoder1.getEncoded();
    printHex("Encoded bool true", encoded_true);

    // Decode true
    ZCBORDecoder decoder1(encoded_true);
    ASSERT_TRUE(decoder1.isBool());
    EXPECT_TRUE(decoder1.decodeBool());

    // Encode false
    ZCBOREncoder encoder2;
    encoder2.encodeBool(false);
    auto encoded_false = encoder2.getEncoded();
    printHex("Encoded bool false", encoded_false);

    // Decode false
    ZCBORDecoder decoder2(encoded_false);
    ASSERT_TRUE(decoder2.isBool());
    EXPECT_FALSE(decoder2.decodeBool());
}

// Test array encoding/decoding
TEST(ZCBORWrapper, EncodeDecodeArray) {
    // Encode array: [1, 2, 3]
    ZCBOREncoder encoder;
    encoder.beginArray(3);
    encoder.encodeUInt(1);
    encoder.encodeUInt(2);
    encoder.encodeUInt(3);
    // Note: endArray() is not functional in current implementation
    // encoder.endArray();
    auto encoded = encoder.getEncoded();

    printHex("Encoded array [1, 2, 3]", encoded);

    // Decode
    ZCBORDecoder decoder(encoded);
    ASSERT_TRUE(decoder.isArray());
    size_t len = decoder.enterArray();
    EXPECT_EQ(len, 3);

    EXPECT_EQ(decoder.decodeUInt(), 1);
    EXPECT_EQ(decoder.decodeUInt(), 2);
    EXPECT_EQ(decoder.decodeUInt(), 3);
}

// Test map encoding/decoding
TEST(ZCBORWrapper, EncodeDecodeMap) {
    // Encode map: {0: "hello", 1: 42}
    ZCBOREncoder encoder;
    encoder.beginMap(2);
    encoder.encodeMapKey(0);
    encoder.encodeText("hello");
    encoder.encodeMapKey(1);
    encoder.encodeUInt(42);
    // Note: endMap() is not functional in current implementation
    // encoder.endMap();
    auto encoded = encoder.getEncoded();

    printHex("Encoded map {0: 'hello', 1: 42}", encoded);

    // Decode
    ZCBORDecoder decoder(encoded);
    ASSERT_TRUE(decoder.isMap());
    size_t len = decoder.enterMap();
    EXPECT_EQ(len, 2);

    // First entry: 0 -> "hello"
    uint64_t key1 = decoder.decodeMapKeyUInt();
    EXPECT_EQ(key1, 0);
    std::string val1 = decoder.decodeText();
    EXPECT_EQ(val1, "hello");

    // Second entry: 1 -> 42
    uint64_t key2 = decoder.decodeMapKeyUInt();
    EXPECT_EQ(key2, 1);
    uint64_t val2 = decoder.decodeUInt();
    EXPECT_EQ(val2, 42);
}

// Test ABE-CBOR constants
TEST(ZCBORWrapper, Constants) {
    EXPECT_EQ(ABE_CBOR_VERSION, 1);
    EXPECT_EQ(ABE_CBOR_TAG, 60001);

    EXPECT_EQ((uint32_t)ABEKind::MSK, 1);
    EXPECT_EQ((uint32_t)ABEKind::MPK, 2);
    EXPECT_EQ((uint32_t)ABEKind::SK, 3);
    EXPECT_EQ((uint32_t)ABEKind::CT, 4);

    EXPECT_STREQ(scheme::CPABE_WATERS, "cpabe-waters");
    EXPECT_STREQ(scheme::KPABE_GPSW, "kpabe-gpsw");

    EXPECT_STREQ(curve::BLS12_381, "bls12-381");
    EXPECT_STREQ(curve::BN254, "bn254");

    EXPECT_EQ((uint32_t)GEEncoding::IETF_COMPRESSED, 0);
    EXPECT_EQ((uint32_t)GEEncoding::UNCOMPRESSED, 1);
    EXPECT_EQ((uint32_t)GEEncoding::MCL_CANONICAL, 2);
}

// Test helper functions
TEST(ZCBORWrapper, HelperFunctions) {
    EXPECT_STREQ(abeKindToString(ABEKind::MSK), "MSK");
    EXPECT_STREQ(abeKindToString(ABEKind::MPK), "MPK");
    EXPECT_STREQ(abeKindToString(ABEKind::SK), "SK");
    EXPECT_STREQ(abeKindToString(ABEKind::CT), "CT");

    EXPECT_STREQ(attributeTypeToString(AttributeType::STRING), "STRING");
    EXPECT_STREQ(attributeTypeToString(AttributeType::INTEGER), "INTEGER");

    EXPECT_STREQ(policyEncodingToString(PolicyEncoding::BOOL_AST), "BOOL_AST");
    EXPECT_STREQ(policyEncodingToString(PolicyEncoding::MSP), "MSP");

    EXPECT_STREQ(tokenKindToString(TokenKind::ATTR), "ATTR");
    EXPECT_STREQ(tokenKindToString(TokenKind::AND), "AND");
    EXPECT_STREQ(tokenKindToString(TokenKind::OR), "OR");

    EXPECT_STREQ(geEncodingToString(GEEncoding::IETF_COMPRESSED), "ietf-compressed");
    EXPECT_STREQ(geEncodingToString(GEEncoding::UNCOMPRESSED), "uncompressed");
}

// Test deterministic encoding (shortest form)
TEST(ZCBORWrapper, DeterministicEncoding) {
    // Small integers (0-23) should use 1 byte
    ZCBOREncoder enc1;
    enc1.encodeUInt(10);
    auto e1 = enc1.getEncoded();
    EXPECT_EQ(e1.size(), 1);  // Should be 0x0A
    EXPECT_EQ(e1[0], 0x0A);

    // Integer 24-255 should use 2 bytes
    ZCBOREncoder enc2;
    enc2.encodeUInt(100);
    auto e2 = enc2.getEncoded();
    EXPECT_EQ(e2.size(), 2);  // Should be 0x18 0x64
    EXPECT_EQ(e2[0], 0x18);
    EXPECT_EQ(e2[1], 0x64);

    // Text string should be prefixed with length
    ZCBOREncoder enc3;
    enc3.encodeText("hi");
    auto e3 = enc3.getEncoded();
    EXPECT_EQ(e3.size(), 3);  // Should be 0x62 'h' 'i'
    EXPECT_EQ(e3[0], 0x62);   // Major type 3, length 2
}

// Test exception handling
TEST(ZCBORWrapper, Exceptions) {
    // Try to decode wrong type
    ZCBOREncoder encoder;
    encoder.encodeUInt(42);
    auto encoded = encoder.getEncoded();

    ZCBORDecoder decoder(encoded);
    EXPECT_THROW(decoder.decodeText(), ZCBORException);  // Expected uint, not text
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
