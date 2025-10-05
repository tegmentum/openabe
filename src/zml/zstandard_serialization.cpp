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
/// \file   zstandard_serialization.cpp
///
/// \brief  Implementation of standard serialization formats
///
/// \author Matthew Green and J. Ayo Akinyele
///

#include <openabe/openabe.h>
#include <openabe/zml/zstandard_serialization.h>

namespace oabe {

// ===== SerializationHeader Implementation =====

const uint8_t SerializationHeader::MAGIC[4] = {'O', 'A', 'B', 'E'};

SerializationHeader::SerializationHeader()
    : version(CURRENT_VERSION), elementType(OpenABE_NONE_TYPE),
      curveID(OpenABE_NONE_ID), format(OPENABE_LEGACY), flags(0) {}

SerializationHeader::SerializationHeader(OpenABEElementType type, OpenABECurveID curve,
                                        SerializationFormat fmt, uint8_t f)
    : version(CURRENT_VERSION), elementType(type), curveID(curve), format(fmt), flags(f) {}

void SerializationHeader::serialize(OpenABEByteString& out) const {
    // Magic bytes
    for (int i = 0; i < 4; i++) {
        out.appendByte(MAGIC[i]);
    }
    // Version
    out.appendByte(version);
    // Element type
    out.appendByte(static_cast<uint8_t>(elementType));
    // Curve ID
    out.appendByte(static_cast<uint8_t>(curveID));
    // Format
    out.appendByte(static_cast<uint8_t>(format));
    // Flags
    out.appendByte(flags);
}

bool SerializationHeader::deserialize(OpenABEByteString& in, size_t* index) {
    if (in.size() < (*index) + getHeaderSize()) {
        return false;
    }

    // Check magic
    for (int i = 0; i < 4; i++) {
        if (in.at((*index)++) != MAGIC[i]) {
            *index -= (i + 1);
            return false;
        }
    }

    // Read header fields
    version = in.at((*index)++);
    elementType = static_cast<OpenABEElementType>(in.at((*index)++));
    curveID = static_cast<OpenABECurveID>(in.at((*index)++));
    format = static_cast<SerializationFormat>(in.at((*index)++));
    flags = in.at((*index)++);

    return true;
}

bool SerializationHeader::isStandardFormat() const {
    return format != OPENABE_LEGACY;
}

// ===== StandardPairingSerializer Implementation =====

void StandardPairingSerializer::field_element_to_bytes(const bignum_t elem,
                                                       OpenABEByteString& out,
                                                       size_t field_size,
                                                       bool big_endian) {
    uint8_t buffer[field_size];
    memset(buffer, 0, field_size);

    size_t actual_size = zml_bignum_countbytes(elem);
    size_t offset = (field_size > actual_size) ? (field_size - actual_size) : 0;

    if (big_endian) {
        // Big-endian: pad zeros on left, data on right
        zml_bignum_toBin(elem, buffer + offset, actual_size);
    } else {
        // Little-endian: data on left, pad zeros on right
        zml_bignum_toBin(elem, buffer, actual_size);
    }

    out.appendArray(buffer, field_size);
}

void StandardPairingSerializer::bytes_to_field_element(bignum_t elem,
                                                       const OpenABEByteString& in,
                                                       size_t offset,
                                                       bool big_endian) {
    size_t len = in.size() - offset;
    const uint8_t* data = in.getInternalPtr() + offset;

    if (big_endian) {
        zml_bignum_fromBin(elem, data, len);
    } else {
        // For little-endian, reverse the bytes
        uint8_t reversed[len];
        for (size_t i = 0; i < len; i++) {
            reversed[i] = data[len - 1 - i];
        }
        zml_bignum_fromBin(elem, reversed, len);
    }
}

size_t StandardPairingSerializer::get_field_size(OpenABECurveID curve) {
    switch (curve) {
        case OpenABE_BN_P254_ID:
        case OpenABE_BN_P256_ID:
            return 32;  // 254-256 bits
        case OpenABE_BN_P382_ID:
            return 48;  // ~381-382 bits (BLS12-381 compatible)
        case OpenABE_BN_P638_ID:
            return 80;  // 638 bits
        case OpenABE_NIST_P256_ID:
            return 32;
        case OpenABE_NIST_P384_ID:
            return 48;
        case OpenABE_NIST_P521_ID:
            return 66;  // 521 bits = 65.125 bytes
        default:
            return 32;
    }
}

bool StandardPairingSerializer::y_is_lexicographically_largest(const bignum_t y,
                                                                const bignum_t p) {
    // Y is lexicographically largest if y > (p-1)/2
    bignum_t half_p;
    zml_bignum_init(&half_p);
    zml_bignum_copy(half_p, p);
    zml_bignum_rshift(half_p, 1);  // half_p = p >> 1

    int result = zml_bignum_cmp(y, half_p);
    zml_bignum_free(half_p);

    return (result == BN_CMP_GT);
}

SerializationFormat StandardPairingSerializer::selectFormat(OpenABECurveID curve) {
    switch (curve) {
        case OpenABE_BN_P382_ID:
            return ZCASH_BLS12;  // BLS12-381 compatible
        case OpenABE_BN_P254_ID:
        case OpenABE_BN_P256_ID:
            return ETHEREUM_BN254;  // BN254/BN256
        default:
            return SEC1_STANDARD;
    }
}

bool StandardPairingSerializer::supports_cyclotomic_compression(OpenABECurveID curve) {
    // Cyclotomic compression works for pairing-friendly curves
    switch (curve) {
        case OpenABE_BN_P254_ID:
        case OpenABE_BN_P256_ID:
        case OpenABE_BN_P382_ID:
        case OpenABE_BN_P638_ID:
            return true;
        default:
            return false;
    }
}

bool StandardPairingSerializer::isLegacyFormat(const OpenABEByteString& in) {
    if (in.size() < 4) return true;

    // Check for magic header
    for (int i = 0; i < 4; i++) {
        if (in.at(i) != SerializationHeader::MAGIC[i]) {
            return true;  // No magic = legacy
        }
    }
    return false;
}

// ===== G1 Serialization Implementation =====

void StandardPairingSerializer::serializeG1(OpenABEByteString& out, const G1& point,
                                           SerializationFormat format, bool with_header) {
    out.clear();

    if (format == AUTO) {
        format = selectFormat(point.bgroup->getCurveID());
    }

    if (with_header) {
        SerializationHeader header(OpenABE_ELEMENT_G1, point.bgroup->getCurveID(), format);
        header.serialize(out);
    }

    switch (format) {
        case ZCASH_BLS12:
            serializeG1_ZCash(out, point);
            break;
        case ETHEREUM_BN254:
            serializeG1_Ethereum(out, point);
            break;
        case SEC1_STANDARD:
            serializeG1_SEC1(out, point);
            break;
        default:
            // Fallback to legacy
            g1_convert_to_bytestring(GET_BP_GROUP(point.bgroup), out, point.m_G1);
    }
}

void StandardPairingSerializer::deserializeG1(G1& point, OpenABEByteString& in, bool has_header) {
    size_t index = 0;
    SerializationFormat format = OPENABE_LEGACY;

    if (has_header) {
        SerializationHeader header;
        if (header.deserialize(in, &index)) {
            format = header.format;
        }
    } else if (isLegacyFormat(in)) {
        format = OPENABE_LEGACY;
    }

    OpenABEByteString data;
    data.appendArray(in.getInternalPtr() + index, in.size() - index);

    switch (format) {
        case ZCASH_BLS12:
            deserializeG1_ZCash(point, data);
            break;
        case ETHEREUM_BN254:
            deserializeG1_Ethereum(point, data);
            break;
        case SEC1_STANDARD:
            deserializeG1_SEC1(point, data);
            break;
        default:
            // Legacy format
            g1_convert_to_point(GET_BP_GROUP(point.bgroup), data, point.m_G1);
    }
}

void StandardPairingSerializer::serializeG1_SEC1(OpenABEByteString& out, const G1& point,
                                                 bool compressed) {
    if (isG1AtInfinity(point)) {
        out.appendByte(0x00);  // Point at infinity
        return;
    }

    bignum_t x, y;
    zml_bignum_init(&x);
    zml_bignum_init(&y);

    extractG1Coordinates(point, x, y);
    size_t field_size = get_field_size(point.bgroup->getCurveID());

    if (compressed) {
        // Compressed: 0x02 or 0x03 + x
        bignum_t p;
        zml_bignum_init(&p);
        point.bgroup->getGroupOrder(p);

        bool y_is_even = (zml_bignum_is_even(y) == 1);
        out.appendByte(y_is_even ? 0x02 : 0x03);

        field_element_to_bytes(x, out, field_size, true);
        zml_bignum_free(p);
    } else {
        // Uncompressed: 0x04 + x + y
        out.appendByte(0x04);
        field_element_to_bytes(x, out, field_size, true);
        field_element_to_bytes(y, out, field_size, true);
    }

    zml_bignum_free(x);
    zml_bignum_free(y);
}

void StandardPairingSerializer::deserializeG1_SEC1(G1& point, OpenABEByteString& in) {
    if (in.size() == 0) {
        throw OpenABE_ERROR_SERIALIZATION_FAILED;
    }

    uint8_t prefix = in.at(0);

    if (prefix == 0x00) {
        // Point at infinity
        setG1ToInfinity(point);
        return;
    }

    size_t field_size = get_field_size(point.bgroup->getCurveID());
    bignum_t x, y;
    zml_bignum_init(&x);
    zml_bignum_init(&y);

    if (prefix == 0x04) {
        // Uncompressed
        if (in.size() != 1 + 2 * field_size) {
            zml_bignum_free(x);
            zml_bignum_free(y);
            throw OpenABE_ERROR_SERIALIZATION_FAILED;
        }

        OpenABEByteString x_bytes, y_bytes;
        x_bytes.appendArray(in.getInternalPtr() + 1, field_size);
        y_bytes.appendArray(in.getInternalPtr() + 1 + field_size, field_size);

        bytes_to_field_element(x, x_bytes, 0, true);
        bytes_to_field_element(y, y_bytes, 0, true);

    } else if (prefix == 0x02 || prefix == 0x03) {
        // Compressed - need to decompress (compute y from x)
        if (in.size() != 1 + field_size) {
            zml_bignum_free(x);
            zml_bignum_free(y);
            throw OpenABE_ERROR_SERIALIZATION_FAILED;
        }

        OpenABEByteString x_bytes;
        x_bytes.appendArray(in.getInternalPtr() + 1, field_size);
        bytes_to_field_element(x, x_bytes, 0, true);

        // Compute y from curve equation: y^2 = x^3 + ax + b
        // For BN curves: y^2 = x^3 + 3
        // TODO: Implement point decompression
        throw OpenABE_ERROR_NOT_IMPLEMENTED;
    } else {
        zml_bignum_free(x);
        zml_bignum_free(y);
        throw OpenABE_ERROR_SERIALIZATION_FAILED;
    }

    setG1FromCoordinates(point, x, y);

    zml_bignum_free(x);
    zml_bignum_free(y);
}

void StandardPairingSerializer::serializeG1_ZCash(OpenABEByteString& out, const G1& point,
                                                  bool compressed) {
    size_t field_size = get_field_size(point.bgroup->getCurveID());

    if (isG1AtInfinity(point)) {
        // Compressed infinity: flags=0xC0, rest zeros
        uint8_t flags = SerializationFlags::COMPRESSION_FLAG | SerializationFlags::INFINITY_FLAG;
        out.appendByte(flags);
        for (size_t i = 1; i < field_size; i++) {
            out.appendByte(0x00);
        }
        return;
    }

    bignum_t x, y, p;
    zml_bignum_init(&x);
    zml_bignum_init(&y);
    zml_bignum_init(&p);

    extractG1Coordinates(point, x, y);
    point.bgroup->getGroupOrder(p);

    if (compressed) {
        // ZCash compressed format
        uint8_t flags = SerializationFlags::COMPRESSION_FLAG;
        if (y_is_lexicographically_largest(y, p)) {
            flags |= SerializationFlags::Y_SIGN_FLAG;
        }

        OpenABEByteString x_bytes;
        field_element_to_bytes(x, x_bytes, field_size, true);

        // Set flags in first byte
        x_bytes.data()[0] |= flags;
        out.appendArray(x_bytes.data(), x_bytes.size());
    } else {
        // Uncompressed: x || y
        field_element_to_bytes(x, out, field_size, true);
        field_element_to_bytes(y, out, field_size, true);
    }

    zml_bignum_free(x);
    zml_bignum_free(y);
    zml_bignum_free(p);
}

void StandardPairingSerializer::deserializeG1_ZCash(G1& point, OpenABEByteString& in) {
    size_t field_size = get_field_size(point.bgroup->getCurveID());

    if (in.size() < field_size) {
        throw OpenABE_ERROR_SERIALIZATION_FAILED;
    }

    uint8_t flags = in.at(0);
    bool compressed = (flags & SerializationFlags::COMPRESSION_FLAG) != 0;
    bool at_infinity = (flags & SerializationFlags::INFINITY_FLAG) != 0;

    if (at_infinity) {
        setG1ToInfinity(point);
        return;
    }

    if (compressed) {
        // Extract x with flags masked
        OpenABEByteString x_bytes;
        x_bytes.appendArray(in.getInternalPtr(), field_size);
        x_bytes.data()[0] &= 0x1F;  // Mask off top 3 bits

        bignum_t x;
        zml_bignum_init(&x);
        bytes_to_field_element(x, x_bytes, 0, true);

        // TODO: Decompress point (compute y from x)
        // For now, throw error
        zml_bignum_free(x);
        throw OpenABE_ERROR_NOT_IMPLEMENTED;
    } else {
        // Uncompressed
        if (in.size() != 2 * field_size) {
            throw OpenABE_ERROR_SERIALIZATION_FAILED;
        }

        bignum_t x, y;
        zml_bignum_init(&x);
        zml_bignum_init(&y);

        OpenABEByteString x_bytes, y_bytes;
        x_bytes.appendArray(in.getInternalPtr(), field_size);
        y_bytes.appendArray(in.getInternalPtr() + field_size, field_size);

        bytes_to_field_element(x, x_bytes, 0, true);
        bytes_to_field_element(y, y_bytes, 0, true);

        setG1FromCoordinates(point, x, y);

        zml_bignum_free(x);
        zml_bignum_free(y);
    }
}

void StandardPairingSerializer::serializeG1_Ethereum(OpenABEByteString& out, const G1& point) {
    size_t field_size = 32;  // Ethereum uses 32-byte fields

    if (isG1AtInfinity(point)) {
        // (0, 0) represents infinity
        for (size_t i = 0; i < 64; i++) {
            out.appendByte(0x00);
        }
        return;
    }

    bignum_t x, y;
    zml_bignum_init(&x);
    zml_bignum_init(&y);

    extractG1Coordinates(point, x, y);

    // Uncompressed: x || y (32 + 32 = 64 bytes)
    field_element_to_bytes(x, out, field_size, true);
    field_element_to_bytes(y, out, field_size, true);

    zml_bignum_free(x);
    zml_bignum_free(y);
}

void StandardPairingSerializer::deserializeG1_Ethereum(G1& point, OpenABEByteString& in) {
    if (in.size() != 64) {
        throw OpenABE_ERROR_SERIALIZATION_FAILED;
    }

    bignum_t x, y;
    zml_bignum_init(&x);
    zml_bignum_init(&y);

    OpenABEByteString x_bytes, y_bytes;
    x_bytes.appendArray(in.getInternalPtr(), 32);
    y_bytes.appendArray(in.getInternalPtr() + 32, 32);

    bytes_to_field_element(x, x_bytes, 0, true);
    bytes_to_field_element(y, y_bytes, 0, true);

    // Check for (0,0) = infinity
    if (zml_bignum_is_zero(x) && zml_bignum_is_zero(y)) {
        setG1ToInfinity(point);
    } else {
        setG1FromCoordinates(point, x, y);
    }

    zml_bignum_free(x);
    zml_bignum_free(y);
}

// ===== G2 Serialization Implementation (similar to G1, but with Fp2) =====

void StandardPairingSerializer::serializeG2(OpenABEByteString& out, const G2& point,
                                           SerializationFormat format, bool with_header) {
    out.clear();

    if (format == AUTO) {
        format = selectFormat(point.bgroup->getCurveID());
    }

    if (with_header) {
        SerializationHeader header(OpenABE_ELEMENT_G2, point.bgroup->getCurveID(), format);
        header.serialize(out);
    }

    switch (format) {
        case ZCASH_BLS12:
            serializeG2_ZCash(out, point);
            break;
        case ETHEREUM_BN254:
            serializeG2_Ethereum(out, point);
            break;
        case SEC1_STANDARD:
            serializeG2_SEC1(out, point);
            break;
        default:
            // Fallback to legacy
            g2_convert_to_bytestring(GET_BP_GROUP(point.bgroup), out, point.m_G2);
    }
}

void StandardPairingSerializer::deserializeG2(G2& point, OpenABEByteString& in, bool has_header) {
    size_t index = 0;
    SerializationFormat format = OPENABE_LEGACY;

    if (has_header) {
        SerializationHeader header;
        if (header.deserialize(in, &index)) {
            format = header.format;
        }
    } else if (isLegacyFormat(in)) {
        format = OPENABE_LEGACY;
    }

    OpenABEByteString data;
    data.appendArray(in.getInternalPtr() + index, in.size() - index);

    switch (format) {
        case ZCASH_BLS12:
            deserializeG2_ZCash(point, data);
            break;
        case ETHEREUM_BN254:
            deserializeG2_Ethereum(point, data);
            break;
        case SEC1_STANDARD:
            deserializeG2_SEC1(point, data);
            break;
        default:
            // Legacy format
            g2_convert_to_point(GET_BP_GROUP(point.bgroup), data, point.m_G2);
    }
}

void StandardPairingSerializer::serializeG2_SEC1(OpenABEByteString& out, const G2& point,
                                                 bool compressed) {
    // G2 is over Fp2, so coordinates are pairs of field elements
    // For now, use uncompressed format
    if (isG2AtInfinity(point)) {
        out.appendByte(0x00);
        return;
    }

    bignum_t x[2], y[2];
    for (int i = 0; i < 2; i++) {
        zml_bignum_init(&x[i]);
        zml_bignum_init(&y[i]);
    }

    extractG2Coordinates(point, x, y);
    size_t field_size = get_field_size(point.bgroup->getCurveID());

    out.appendByte(0x04);  // Uncompressed
    // Serialize x = x0 + x1*u
    field_element_to_bytes(x[1], out, field_size, true);  // x1 first (ZCash convention)
    field_element_to_bytes(x[0], out, field_size, true);  // x0 second
    // Serialize y = y0 + y1*u
    field_element_to_bytes(y[1], out, field_size, true);
    field_element_to_bytes(y[0], out, field_size, true);

    for (int i = 0; i < 2; i++) {
        zml_bignum_free(x[i]);
        zml_bignum_free(y[i]);
    }
}

void StandardPairingSerializer::deserializeG2_SEC1(G2& point, OpenABEByteString& in) {
    // Simplified G2 deserialization - uncompressed only
    if (in.at(0) == 0x00) {
        setG2ToInfinity(point);
        return;
    }

    size_t field_size = get_field_size(point.bgroup->getCurveID());
    if (in.size() != 1 + 4 * field_size) {
        throw OpenABE_ERROR_SERIALIZATION_FAILED;
    }

    bignum_t x[2], y[2];
    for (int i = 0; i < 2; i++) {
        zml_bignum_init(&x[i]);
        zml_bignum_init(&y[i]);
    }

    size_t offset = 1;
    OpenABEByteString temp;

    // Read x1, x0, y1, y0
    temp.appendArray(in.getInternalPtr() + offset, field_size);
    bytes_to_field_element(x[1], temp, 0, true);
    offset += field_size;

    temp.clear();
    temp.appendArray(in.getInternalPtr() + offset, field_size);
    bytes_to_field_element(x[0], temp, 0, true);
    offset += field_size;

    temp.clear();
    temp.appendArray(in.getInternalPtr() + offset, field_size);
    bytes_to_field_element(y[1], temp, 0, true);
    offset += field_size;

    temp.clear();
    temp.appendArray(in.getInternalPtr() + offset, field_size);
    bytes_to_field_element(y[0], temp, 0, true);

    setG2FromCoordinates(point, x, y);

    for (int i = 0; i < 2; i++) {
        zml_bignum_free(x[i]);
        zml_bignum_free(y[i]);
    }
}

void StandardPairingSerializer::serializeG2_ZCash(OpenABEByteString& out, const G2& point,
                                                  bool compressed) {
    // Similar to G1 but with Fp2 elements
    // For simplicity, implement uncompressed for now
    serializeG2_SEC1(out, point, false);
}

void StandardPairingSerializer::deserializeG2_ZCash(G2& point, OpenABEByteString& in) {
    deserializeG2_SEC1(point, in);
}

void StandardPairingSerializer::serializeG2_Ethereum(OpenABEByteString& out, const G2& point) {
    if (isG2AtInfinity(point)) {
        // (0,0,0,0) for G2 infinity
        for (size_t i = 0; i < 128; i++) {
            out.appendByte(0x00);
        }
        return;
    }

    bignum_t x[2], y[2];
    for (int i = 0; i < 2; i++) {
        zml_bignum_init(&x[i]);
        zml_bignum_init(&y[i]);
    }

    extractG2Coordinates(point, x, y);

    // Ethereum format: x1 || x0 || y1 || y0 (each 32 bytes)
    field_element_to_bytes(x[1], out, 32, true);
    field_element_to_bytes(x[0], out, 32, true);
    field_element_to_bytes(y[1], out, 32, true);
    field_element_to_bytes(y[0], out, 32, true);

    for (int i = 0; i < 2; i++) {
        zml_bignum_free(x[i]);
        zml_bignum_free(y[i]);
    }
}

void StandardPairingSerializer::deserializeG2_Ethereum(G2& point, OpenABEByteString& in) {
    if (in.size() != 128) {
        throw OpenABE_ERROR_SERIALIZATION_FAILED;
    }

    bignum_t x[2], y[2];
    for (int i = 0; i < 2; i++) {
        zml_bignum_init(&x[i]);
        zml_bignum_init(&y[i]);
    }

    OpenABEByteString temp;
    size_t offset = 0;

    temp.appendArray(in.getInternalPtr() + offset, 32);
    bytes_to_field_element(x[1], temp, 0, true);
    offset += 32;

    temp.clear();
    temp.appendArray(in.getInternalPtr() + offset, 32);
    bytes_to_field_element(x[0], temp, 0, true);
    offset += 32;

    temp.clear();
    temp.appendArray(in.getInternalPtr() + offset, 32);
    bytes_to_field_element(y[1], temp, 0, true);
    offset += 32;

    temp.clear();
    temp.appendArray(in.getInternalPtr() + offset, 32);
    bytes_to_field_element(y[0], temp, 0, true);

    setG2FromCoordinates(point, x, y);

    for (int i = 0; i < 2; i++) {
        zml_bignum_free(x[i]);
        zml_bignum_free(y[i]);
    }
}

// ===== GT Serialization Implementation =====

void StandardPairingSerializer::serializeGT(OpenABEByteString& out, const GT& gt,
                                           GTSerializationMode mode, bool with_header) {
    out.clear();

    if (with_header) {
        uint8_t flags = (mode == GT_CYCLOTOMIC_COMPRESSED) ? SerializationFlags::CYCLOTOMIC_FLAG : 0;
        SerializationHeader header(OpenABE_ELEMENT_GT, gt.bgroup->getCurveID(),
                                  IETF_PAIRING, flags);
        header.serialize(out);
    }

    if (mode == GT_CYCLOTOMIC_COMPRESSED && supports_cyclotomic_compression(gt.bgroup->getCurveID())) {
        serializeGT_Cyclotomic(out, gt);
    } else {
        serializeGT_Full(out, gt);
    }
}

void StandardPairingSerializer::deserializeGT(GT& gt, OpenABEByteString& in, bool has_header) {
    size_t index = 0;
    GTSerializationMode mode = GT_FULL_TOWER;

    if (has_header) {
        SerializationHeader header;
        if (header.deserialize(in, &index)) {
            mode = (header.flags & SerializationFlags::CYCLOTOMIC_FLAG) ?
                   GT_CYCLOTOMIC_COMPRESSED : GT_FULL_TOWER;
        }
    }

    OpenABEByteString data;
    data.appendArray(in.getInternalPtr() + index, in.size() - index);

    if (mode == GT_CYCLOTOMIC_COMPRESSED) {
        deserializeGT_Cyclotomic(gt, data);
    } else {
        deserializeGT_Full(gt, data);
    }
}

void StandardPairingSerializer::serializeGT_Full(OpenABEByteString& out, const GT& gt) {
    if (isGTIdentity(gt)) {
        out.appendByte(SerializationFlags::INFINITY_FLAG);
        size_t field_size = get_field_size(gt.bgroup->getCurveID());
        for (size_t i = 1; i < 12 * field_size; i++) {
            out.appendByte(0x00);
        }
        return;
    }

    // Extract Fp12 tower: 12 Fp elements
    bignum_t tower[12];
    for (int i = 0; i < 12; i++) {
        zml_bignum_init(&tower[i]);
    }

    extractFp12Tower(gt, tower);
    size_t field_size = get_field_size(gt.bgroup->getCurveID());

    // Serialize all 12 Fp elements
    for (int i = 0; i < 12; i++) {
        field_element_to_bytes(tower[i], out, field_size, true);
    }

    for (int i = 0; i < 12; i++) {
        zml_bignum_free(tower[i]);
    }
}

void StandardPairingSerializer::deserializeGT_Full(GT& gt, OpenABEByteString& in) {
    size_t field_size = get_field_size(gt.bgroup->getCurveID());

    if (in.size() < 12 * field_size) {
        throw OpenABE_ERROR_SERIALIZATION_FAILED;
    }

    // Check for identity
    if ((in.at(0) & SerializationFlags::INFINITY_FLAG) != 0) {
        setGTToIdentity(gt);
        return;
    }

    bignum_t tower[12];
    for (int i = 0; i < 12; i++) {
        zml_bignum_init(&tower[i]);
    }

    // Deserialize 12 Fp elements
    for (int i = 0; i < 12; i++) {
        OpenABEByteString elem_bytes;
        elem_bytes.appendArray(in.getInternalPtr() + i * field_size, field_size);
        bytes_to_field_element(tower[i], elem_bytes, 0, true);
    }

    setGTFromFp12Tower(gt, tower);

    for (int i = 0; i < 12; i++) {
        zml_bignum_free(tower[i]);
    }
}

void StandardPairingSerializer::serializeGT_Cyclotomic(OpenABEByteString& out, const GT& gt) {
    if (isGTIdentity(gt)) {
        out.appendByte(SerializationFlags::INFINITY_FLAG);
        size_t field_size = get_field_size(gt.bgroup->getCurveID());
        for (size_t i = 1; i < 8 * field_size; i++) {
            out.appendByte(0x00);
        }
        return;
    }

    // Cyclotomic compression: send only 8 of 12 Fp elements
    // Typically indices 4-11 (g2, g3, g4, g5 if Fp12 = g0+g1w+...+g5w^5 with gi in Fp2)
    bignum_t tower[12];
    for (int i = 0; i < 12; i++) {
        zml_bignum_init(&tower[i]);
    }

    extractFp12Tower(gt, tower);
    size_t field_size = get_field_size(gt.bgroup->getCurveID());

    // Serialize indices 4-11 (8 elements)
    for (int i = 4; i < 12; i++) {
        field_element_to_bytes(tower[i], out, field_size, true);
    }

    for (int i = 0; i < 12; i++) {
        zml_bignum_free(tower[i]);
    }
}

void StandardPairingSerializer::deserializeGT_Cyclotomic(GT& gt, OpenABEByteString& in) {
    size_t field_size = get_field_size(gt.bgroup->getCurveID());

    if (in.size() < 8 * field_size) {
        throw OpenABE_ERROR_SERIALIZATION_FAILED;
    }

    if ((in.at(0) & SerializationFlags::INFINITY_FLAG) != 0) {
        setGTToIdentity(gt);
        return;
    }

    bignum_t tower[12];
    for (int i = 0; i < 12; i++) {
        zml_bignum_init(&tower[i]);
    }

    // Deserialize indices 4-11
    for (int i = 4; i < 12; i++) {
        OpenABEByteString elem_bytes;
        elem_bytes.appendArray(in.getInternalPtr() + (i-4) * field_size, field_size);
        bytes_to_field_element(tower[i], elem_bytes, 0, true);
    }

    // TODO: Reconstruct indices 0-3 using g^(p^6) = g^(-1) relation
    // For now, this is a placeholder - full implementation requires Frobenius map
    throw OpenABE_ERROR_NOT_IMPLEMENTED;

    for (int i = 0; i < 12; i++) {
        zml_bignum_free(tower[i]);
    }
}

// ===== Helper Functions (stubs to be implemented based on backend) =====

void StandardPairingSerializer::extractG1Coordinates(const G1& point, bignum_t x, bignum_t y) {
    // Implementation depends on backend (RELIC vs OpenSSL)
#if defined(BP_WITH_OPENSSL)
    G1_ELEM_get_affine_coordinates(GET_BP_GROUP(point.bgroup), point.m_G1, &x, &y, NULL);
#else
    // RELIC implementation
    ep_norm(const_cast<ep_t>(point.m_G1), point.m_G1);
    fp_prime_back(x, point.m_G1->x);
    fp_prime_back(y, point.m_G1->y);
#endif
}

void StandardPairingSerializer::setG1FromCoordinates(G1& point, const bignum_t x, const bignum_t y) {
#if defined(BP_WITH_OPENSSL)
    G1_ELEM_set_affine_coordinates(GET_BP_GROUP(point.bgroup), point.m_G1, x, y, NULL);
#else
    // RELIC implementation
    fp_prime_conv(point.m_G1->x, x);
    fp_prime_conv(point.m_G1->y, y);
    fp_set_dig(point.m_G1->z, 1);
    point.m_G1->coord = BASIC;
#endif
}

bool StandardPairingSerializer::isG1AtInfinity(const G1& point) {
#if defined(BP_WITH_OPENSSL)
    return G1_ELEM_is_at_infinity(GET_BP_GROUP(point.bgroup), point.m_G1);
#else
    return ep_is_infty(point.m_G1);
#endif
}

void StandardPairingSerializer::setG1ToInfinity(G1& point) {
#if defined(BP_WITH_OPENSSL)
    G1_ELEM_set_to_infinity(GET_BP_GROUP(point.bgroup), point.m_G1);
#else
    ep_set_infty(point.m_G1);
#endif
}

void StandardPairingSerializer::extractG2Coordinates(const G2& point, bignum_t x[2], bignum_t y[2]) {
#if defined(BP_WITH_OPENSSL)
    G2_ELEM_get_affine_coordinates(GET_BP_GROUP(point.bgroup), point.m_G2, x, y, NULL);
#else
    // RELIC implementation for ep2
    ep2_norm(const_cast<ep2_t>(point.m_G2), point.m_G2);
    fp_prime_back(x[0], point.m_G2->x[0]);
    fp_prime_back(x[1], point.m_G2->x[1]);
    fp_prime_back(y[0], point.m_G2->y[0]);
    fp_prime_back(y[1], point.m_G2->y[1]);
#endif
}

void StandardPairingSerializer::setG2FromCoordinates(G2& point, const bignum_t x[2], const bignum_t y[2]) {
#if defined(BP_WITH_OPENSSL)
    G2_ELEM_set_affine_coordinates(GET_BP_GROUP(point.bgroup), point.m_G2, x, y, NULL);
#else
    // RELIC implementation
    fp_prime_conv(point.m_G2->x[0], x[0]);
    fp_prime_conv(point.m_G2->x[1], x[1]);
    fp_prime_conv(point.m_G2->y[0], y[0]);
    fp_prime_conv(point.m_G2->y[1], y[1]);
    fp2_set_dig(point.m_G2->z, 1);
    point.m_G2->coord = BASIC;
#endif
}

bool StandardPairingSerializer::isG2AtInfinity(const G2& point) {
#if defined(BP_WITH_OPENSSL)
    return G2_ELEM_is_at_infinity(GET_BP_GROUP(point.bgroup), point.m_G2);
#else
    return ep2_is_infty(point.m_G2);
#endif
}

void StandardPairingSerializer::setG2ToInfinity(G2& point) {
#if defined(BP_WITH_OPENSSL)
    G2_ELEM_set_to_infinity(GET_BP_GROUP(point.bgroup), point.m_G2);
#else
    ep2_set_infty(point.m_G2);
#endif
}

bool StandardPairingSerializer::isGTIdentity(const GT& gt) {
#if defined(BP_WITH_OPENSSL)
    return GT_is_unity(GET_BP_GROUP(gt.bgroup), gt.m_GT);
#else
    return fp12_is_zero(gt.m_GT) || gt_is_unity(gt.m_GT);
#endif
}

void StandardPairingSerializer::setGTToIdentity(GT& gt) {
    gt.setIdentity();
}

void StandardPairingSerializer::extractFp12Tower(const GT& gt, bignum_t tower[12]) {
    // Extract 12 Fp elements from Fp12
    // Fp12 structure depends on backend
#if !defined(BP_WITH_OPENSSL)
    // RELIC: Fp12 as 2 x Fp6, Fp6 as 3 x Fp2, Fp2 as 2 x Fp
    for (int i = 0; i < 2; i++) {      // Fp12 = Fp6[w]
        for (int j = 0; j < 3; j++) {  // Fp6 = Fp2[v]
            for (int k = 0; k < 2; k++) {  // Fp2 = Fp[u]
                int idx = i * 6 + j * 2 + k;
                fp_prime_back(tower[idx], gt.m_GT[i][j][k]);
            }
        }
    }
#else
    // OpenSSL implementation - TODO
    throw OpenABE_ERROR_NOT_IMPLEMENTED;
#endif
}

void StandardPairingSerializer::setGTFromFp12Tower(GT& gt, const bignum_t tower[12]) {
#if !defined(BP_WITH_OPENSSL)
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 2; k++) {
                int idx = i * 6 + j * 2 + k;
                fp_prime_conv(gt.m_GT[i][j][k], tower[idx]);
            }
        }
    }
#else
    // OpenSSL implementation - TODO
    throw OpenABE_ERROR_NOT_IMPLEMENTED;
#endif
}

// ===== Legacy Serialization Compatibility =====

bool LegacySerializer::detectLegacyFormat(const OpenABEByteString& data) {
    return StandardPairingSerializer::isLegacyFormat(data);
}

OpenABEElementType LegacySerializer::getLegacyElementType(const OpenABEByteString& data) {
    if (data.size() == 0) return OpenABE_NONE_TYPE;
    return static_cast<OpenABEElementType>(data.at(0));
}

void LegacySerializer::convertLegacyG1(OpenABEByteString& out, const OpenABEByteString& in,
                                       std::shared_ptr<BPGroup> bgroup) {
    // Create temporary G1, deserialize from legacy, serialize to standard
    G1 temp(bgroup);
    OpenABEByteString legacy_data = in;
    g1_convert_to_point(GET_BP_GROUP(bgroup), legacy_data, temp.m_G1);
    StandardPairingSerializer::serializeG1(out, temp, AUTO, true);
}

void LegacySerializer::convertLegacyG2(OpenABEByteString& out, const OpenABEByteString& in,
                                       std::shared_ptr<BPGroup> bgroup) {
    G2 temp(bgroup);
    OpenABEByteString legacy_data = in;
    g2_convert_to_point(GET_BP_GROUP(bgroup), legacy_data, temp.m_G2);
    StandardPairingSerializer::serializeG2(out, temp, AUTO, true);
}

void LegacySerializer::convertLegacyGT(OpenABEByteString& out, const OpenABEByteString& in,
                                       std::shared_ptr<BPGroup> bgroup) {
    GT temp(bgroup);
    OpenABEByteString legacy_data = in;
    gt_convert_to_point(GET_BP_GROUP(bgroup), legacy_data, temp.m_GT);
    StandardPairingSerializer::serializeGT(out, temp, GT_CYCLOTOMIC_COMPRESSED, true);
}

} // namespace oabe
