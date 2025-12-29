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
/// \file   zcbor_group_elements.cpp
///
/// \brief  ABE-CBOR v1 group element serialization implementation
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#include <openabe/cbor/zcbor_group_elements.h>
#include <openabe/openabe.h>
#include <cstring>
#include <algorithm>
#include <sstream>

#if defined(BP_WITH_RABE)
#include <rabe_bls12381.h>
#endif

// MCL serialization functions are declared in openabe.h/zelement_bp.h
// We already have access to them through the includes above

namespace oabe {
namespace cbor {

// Maximum buffer size for serialization
constexpr size_t MAX_SERIALIZE_BUFFER = 2048;

// ============================================================================
// Endianness utility functions
// ============================================================================

bool isLittleEndian() {
    uint16_t value = 0x0001;
    return *reinterpret_cast<uint8_t*>(&value) == 0x01;
}

void reverseBytes(uint8_t* data, size_t len) {
    if (data == nullptr || len <= 1) return;

    for (size_t i = 0; i < len / 2; i++) {
        std::swap(data[i], data[len - 1 - i]);
    }
}

// ============================================================================
// Size utility functions
// ============================================================================

size_t getG1Size(GEEncoding encoding, OpenABECurveID curve_id) {
    switch (curve_id) {
        case OpenABE_BLS12_P381_ID:
            switch (encoding) {
                case GEEncoding::IETF_COMPRESSED:
                    return ge_size::bls12_381::G1_COMPRESSED;  // 48 bytes
                case GEEncoding::UNCOMPRESSED:
                    return ge_size::bls12_381::G1_UNCOMPRESSED; // 96 bytes
                case GEEncoding::MCL_CANONICAL:
                    return ge_size::bls12_381::G1_COMPRESSED;  // MCL uses compressed
                default:
                    throw ZCBORException("Unknown GE encoding format");
            }
        case OpenABE_BN_P254_ID:
            // BN254 sizes (G1 is 32-byte field)
            switch (encoding) {
                case GEEncoding::IETF_COMPRESSED:
                case GEEncoding::MCL_CANONICAL:
                    return 33;  // Compressed: 32 bytes + 1 prefix
                case GEEncoding::UNCOMPRESSED:
                    return 65;  // Uncompressed: 2*32 bytes + 1 prefix
                default:
                    throw ZCBORException("Unknown GE encoding format");
            }
        default:
            throw ZCBORException("Unsupported curve for G1 size calculation");
    }
}

size_t getG2Size(GEEncoding encoding, OpenABECurveID curve_id) {
    switch (curve_id) {
        case OpenABE_BLS12_P381_ID:
            switch (encoding) {
                case GEEncoding::IETF_COMPRESSED:
                    return ge_size::bls12_381::G2_COMPRESSED;  // 96 bytes
                case GEEncoding::UNCOMPRESSED:
                    return ge_size::bls12_381::G2_UNCOMPRESSED; // 192 bytes
                case GEEncoding::MCL_CANONICAL:
                    return ge_size::bls12_381::G2_COMPRESSED;  // MCL uses compressed
                default:
                    throw ZCBORException("Unknown GE encoding format");
            }
        case OpenABE_BN_P254_ID:
            // BN254 G2 is over Fp2 (2*32 byte fields)
            switch (encoding) {
                case GEEncoding::IETF_COMPRESSED:
                case GEEncoding::MCL_CANONICAL:
                    return 65;  // Compressed: 64 bytes + 1 prefix
                case GEEncoding::UNCOMPRESSED:
                    return 129; // Uncompressed: 2*64 bytes + 1 prefix
                default:
                    throw ZCBORException("Unknown GE encoding format");
            }
        default:
            throw ZCBORException("Unsupported curve for G2 size calculation");
    }
}

size_t getGTSize(OpenABECurveID curve_id) {
    switch (curve_id) {
        case OpenABE_BLS12_P381_ID:
            // GT is Fp12 for BLS12-381
            return ge_size::bls12_381::GT;  // 576 bytes
        case OpenABE_BN_P254_ID:
            // GT is Fp12 for BN254 (12 * 32-byte fields)
            return 384;  // 12 * 32 bytes
        default:
            throw ZCBORException("Unsupported curve for GT size calculation");
    }
}

size_t getZrSize(OpenABECurveID curve_id) {
    switch (curve_id) {
        case OpenABE_BLS12_P381_ID:
            // Scalar field is 255 bits, rounds to 32 bytes
            return 32;
        case OpenABE_BN_P254_ID:
            // Scalar field is 254 bits, rounds to 32 bytes
            return 32;
        default:
            throw ZCBORException("Unsupported curve for Zr size calculation");
    }
}

// ============================================================================
// GroupElementSerializer implementation
// ============================================================================

GroupElementSerializer::GroupElementSerializer(GEEncoding encoding, Endianness endianness)
    : encoding_(encoding), endianness_(endianness) {
}

void GroupElementSerializer::convertToBigEndian(uint8_t* data, size_t len) {
    // If we want big-endian output and system is little-endian, reverse
    if (endianness_ == Endianness::BIG && isLittleEndian()) {
        reverseBytes(data, len);
    }
    // If we want little-endian output and system is big-endian, reverse
    else if (endianness_ == Endianness::LITTLE && !isLittleEndian()) {
        reverseBytes(data, len);
    }
    // Otherwise no conversion needed
}

void GroupElementSerializer::convertFromBigEndian(uint8_t* data, size_t len) {
    // If input is big-endian and system is little-endian, reverse
    if (endianness_ == Endianness::BIG && isLittleEndian()) {
        reverseBytes(data, len);
    }
    // If input is little-endian and system is big-endian, reverse
    else if (endianness_ == Endianness::LITTLE && !isLittleEndian()) {
        reverseBytes(data, len);
    }
    // Otherwise no conversion needed
}

void GroupElementSerializer::validateSize(size_t expected, size_t actual, const char* group_name) {
    if (expected != actual) {
        std::ostringstream oss;
        oss << "Invalid " << group_name << " size: expected " << expected
            << " bytes, got " << actual << " bytes";
        throw ZCBORException(oss.str());
    }
}

void GroupElementSerializer::encodeG1(ZCBOREncoder& encoder, const G1& element) {
    if (!element.isInit) {
        throw ZCBORException("G1 element not initialized");
    }

    uint8_t buffer[MAX_SERIALIZE_BUFFER];
    memset(buffer, 0, MAX_SERIALIZE_BUFFER);

#if defined(BP_WITH_RABE)
    // Serialize using RABE
    size_t len = rabe_g1_serialize(buffer, MAX_SERIALIZE_BUFFER, element.m_G1.ptr);
    if (len == 0) {
        throw ZCBORException("Failed to serialize G1 element");
    }
#elif defined(BP_WITH_MCL)
    // Serialize using MCL
    size_t len = mclBnG1_serialize(buffer, MAX_SERIALIZE_BUFFER, &element.m_G1);
    if (len == 0) {
        throw ZCBORException("Failed to serialize G1 element");
    }
#else
    throw ZCBORException("No pairing backend configured");
#endif

    // Convert endianness if needed
    convertToBigEndian(buffer, len);

    // Encode as CBOR byte string
    std::vector<uint8_t> bytes(buffer, buffer + len);
    encoder.encodeBytes(bytes);
}

void GroupElementSerializer::encodeG2(ZCBOREncoder& encoder, const G2& element) {
    if (!element.isInit) {
        throw ZCBORException("G2 element not initialized");
    }

    uint8_t buffer[MAX_SERIALIZE_BUFFER];
    memset(buffer, 0, MAX_SERIALIZE_BUFFER);

#if defined(BP_WITH_RABE)
    // Serialize using RABE
    size_t len = rabe_g2_serialize(buffer, MAX_SERIALIZE_BUFFER, element.m_G2.ptr);
    if (len == 0) {
        throw ZCBORException("Failed to serialize G2 element");
    }
#elif defined(BP_WITH_MCL)
    // Serialize using MCL
    // Note: m_G2 is mutable in const G2& for MCL compatibility
    size_t len = mclBnG2_serialize(buffer, MAX_SERIALIZE_BUFFER,
                                    const_cast<mclBnG2*>(&element.m_G2));
    if (len == 0) {
        throw ZCBORException("Failed to serialize G2 element");
    }
#else
    throw ZCBORException("No pairing backend configured");
#endif

    // Convert endianness if needed
    convertToBigEndian(buffer, len);

    // Encode as CBOR byte string
    std::vector<uint8_t> bytes(buffer, buffer + len);
    encoder.encodeBytes(bytes);
}

void GroupElementSerializer::encodeGT(ZCBOREncoder& encoder, const GT& element) {
    if (!element.isInit) {
        throw ZCBORException("GT element not initialized");
    }

    uint8_t buffer[MAX_SERIALIZE_BUFFER];
    memset(buffer, 0, MAX_SERIALIZE_BUFFER);

#if defined(BP_WITH_RABE)
    // Serialize using RABE
    size_t len = rabe_gt_serialize(buffer, MAX_SERIALIZE_BUFFER, element.m_GT.ptr);
    if (len == 0) {
        throw ZCBORException("Failed to serialize GT element");
    }
#elif defined(BP_WITH_MCL)
    // Serialize using MCL
    size_t len = mclBnGT_serialize(buffer, MAX_SERIALIZE_BUFFER, &element.m_GT);
    if (len == 0) {
        throw ZCBORException("Failed to serialize GT element");
    }
#else
    throw ZCBORException("No pairing backend configured");
#endif

    // Convert endianness if needed
    convertToBigEndian(buffer, len);

    // Encode as CBOR byte string
    std::vector<uint8_t> bytes(buffer, buffer + len);
    encoder.encodeBytes(bytes);
}

void GroupElementSerializer::encodeZr(ZCBOREncoder& encoder, const ZP& element) {
    if (!element.isInit) {
        throw ZCBORException("Zr element not initialized");
    }

    // Get ZP as byte string
    OpenABEByteString zp_bytes = element.getByteString();

    // Convert endianness if needed
    std::vector<uint8_t> bytes(zp_bytes.getInternalPtr(),
                               zp_bytes.getInternalPtr() + zp_bytes.size());
    convertToBigEndian(bytes.data(), bytes.size());

    // Encode as CBOR byte string
    encoder.encodeBytes(bytes);
}

void GroupElementSerializer::decodeG1(ZCBORDecoder& decoder, G1& element, uint8_t curve_id) {
    if (!decoder.isBytes()) {
        throw ZCBORException("Expected byte string for G1 element");
    }

    // Decode CBOR byte string
    std::vector<uint8_t> bytes = decoder.decodeBytes();

    // Validate size based on curve
    OpenABECurveID curve = static_cast<OpenABECurveID>(curve_id);
    size_t expected_size = getG1Size(encoding_, curve);
    validateSize(expected_size, bytes.size(), "G1");

    // Convert from big-endian if needed
    convertFromBigEndian(bytes.data(), bytes.size());

#if defined(BP_WITH_RABE)
    // Deserialize using RABE
    if (element.m_G1.ptr == nullptr) {
        element.m_G1.ptr = rabe_g1_new();
    }
    if (rabe_g1_deserialize(element.m_G1.ptr, bytes.data(), bytes.size()) == 0) {
        throw ZCBORException("Failed to deserialize G1 element");
    }
#elif defined(BP_WITH_MCL)
    // Deserialize using MCL
    if (mclBnG1_deserialize(&element.m_G1, bytes.data(), bytes.size()) == 0) {
        throw ZCBORException("Failed to deserialize G1 element");
    }
#else
    throw ZCBORException("No pairing backend configured");
#endif

    element.isInit = true;
}

void GroupElementSerializer::decodeG2(ZCBORDecoder& decoder, G2& element, uint8_t curve_id) {
    if (!decoder.isBytes()) {
        throw ZCBORException("Expected byte string for G2 element");
    }

    // Decode CBOR byte string
    std::vector<uint8_t> bytes = decoder.decodeBytes();

    // Validate size based on curve
    OpenABECurveID curve = static_cast<OpenABECurveID>(curve_id);
    size_t expected_size = getG2Size(encoding_, curve);
    validateSize(expected_size, bytes.size(), "G2");

    // Convert from big-endian if needed
    convertFromBigEndian(bytes.data(), bytes.size());

#if defined(BP_WITH_RABE)
    // Deserialize using RABE
    if (element.m_G2.ptr == nullptr) {
        element.m_G2.ptr = rabe_g2_new();
    }
    if (rabe_g2_deserialize(element.m_G2.ptr, bytes.data(), bytes.size()) == 0) {
        throw ZCBORException("Failed to deserialize G2 element");
    }
#elif defined(BP_WITH_MCL)
    // Deserialize using MCL
    if (mclBnG2_deserialize(&element.m_G2, bytes.data(), bytes.size()) == 0) {
        throw ZCBORException("Failed to deserialize G2 element");
    }
#else
    throw ZCBORException("No pairing backend configured");
#endif

    element.isInit = true;
}

void GroupElementSerializer::decodeGT(ZCBORDecoder& decoder, GT& element) {
    if (!decoder.isBytes()) {
        throw ZCBORException("Expected byte string for GT element");
    }

    // Decode CBOR byte string
    std::vector<uint8_t> bytes = decoder.decodeBytes();

    // Convert from big-endian if needed
    convertFromBigEndian(bytes.data(), bytes.size());

#if defined(BP_WITH_RABE)
    // Deserialize using RABE
    if (element.m_GT.ptr == nullptr) {
        element.m_GT.ptr = rabe_gt_new();
    }
    if (rabe_gt_deserialize(element.m_GT.ptr, bytes.data(), bytes.size()) == 0) {
        throw ZCBORException("Failed to deserialize GT element");
    }
#elif defined(BP_WITH_MCL)
    // Deserialize using MCL
    if (mclBnGT_deserialize(&element.m_GT, bytes.data(), bytes.size()) == 0) {
        throw ZCBORException("Failed to deserialize GT element");
    }
#else
    throw ZCBORException("No pairing backend configured");
#endif

    element.isInit = true;
}

void GroupElementSerializer::decodeZr(ZCBORDecoder& decoder, ZP& element, const void* order_ptr) {
    // Cast order_ptr back to bignum_t (reinterpret_cast for pointer types)
    const bignum_t order = *reinterpret_cast<const bignum_t*>(order_ptr);
    if (!decoder.isBytes()) {
        throw ZCBORException("Expected byte string for Zr element");
    }

    // Decode CBOR byte string
    std::vector<uint8_t> bytes = decoder.decodeBytes();

    // Convert from big-endian if needed
    convertFromBigEndian(bytes.data(), bytes.size());

    // Create OpenABEByteString and deserialize
    OpenABEByteString zp_bytes;
    zp_bytes.appendArray(bytes.data(), bytes.size());

    // Reconstruct ZP from bytes
    ZP temp(bytes.data(), bytes.size(), order);
    element = temp;
    element.isInit = true;
}

} // namespace cbor
} // namespace oabe
