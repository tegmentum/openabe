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
/// \file   zcbor_group_elements.h
///
/// \brief  ABE-CBOR v1 group element serialization
///         Converts MCL group elements (G1, G2, GT, Zr) to CBOR format
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#ifndef __ZCBOR_GROUP_ELEMENTS_H__
#define __ZCBOR_GROUP_ELEMENTS_H__

#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_constants.h>
#include <vector>
#include <cstdint>

// Forward declarations to avoid including zelement_bp.h here
// (which has extern "C" issues with MCL C++ headers)
namespace oabe {
    class G1;
    class G2;
    class GT;
    class ZP;
    enum OpenABECurveID : uint8_t;
}

// No need to include bignum_t here - we use void* for order parameter

namespace oabe {
namespace cbor {

/// \class GroupElementSerializer
/// \brief Serializes pairing group elements to ABE-CBOR v1 format
///
/// This class handles conversion between MCL group elements and CBOR encoding
/// according to the ABE-CBOR v1 specification. It supports multiple encoding
/// formats and endianness conversion.
class GroupElementSerializer {
public:
    /// Constructor
    /// \param encoding The GE encoding format to use (default: IETF compressed)
    /// \param endianness Byte order for serialization (default: big-endian)
    explicit GroupElementSerializer(
        GEEncoding encoding = defaults::GE_ENCODING,
        Endianness endianness = defaults::ENDIANNESS
    );

    /// Serialize a G1 element to CBOR byte string
    /// \param encoder CBOR encoder to use
    /// \param element G1 element to serialize
    /// \throws ZCBORException on serialization failure
    void encodeG1(ZCBOREncoder& encoder, const G1& element);

    /// Serialize a G2 element to CBOR byte string
    /// \param encoder CBOR encoder to use
    /// \param element G2 element to serialize
    /// \throws ZCBORException on serialization failure
    void encodeG2(ZCBOREncoder& encoder, const G2& element);

    /// Serialize a GT element to CBOR byte string
    /// \param encoder CBOR encoder to use
    /// \param element GT element to serialize
    /// \throws ZCBORException on serialization failure
    void encodeGT(ZCBOREncoder& encoder, const GT& element);

    /// Serialize a Zr (scalar) element to CBOR byte string
    /// \param encoder CBOR encoder to use
    /// \param element Zr element to serialize
    /// \throws ZCBORException on serialization failure
    void encodeZr(ZCBOREncoder& encoder, const ZP& element);

    /// Deserialize a G1 element from CBOR byte string
    /// \param decoder CBOR decoder to use
    /// \param element G1 element to populate
    /// \param curve_id Curve identifier (for validation)
    /// \throws ZCBORException on deserialization failure
    void decodeG1(ZCBORDecoder& decoder, G1& element, uint8_t curve_id);

    /// Deserialize a G2 element from CBOR byte string
    /// \param decoder CBOR decoder to use
    /// \param element G2 element to populate
    /// \param curve_id Curve identifier (for validation)
    /// \throws ZCBORException on deserialization failure
    void decodeG2(ZCBORDecoder& decoder, G2& element, uint8_t curve_id);

    /// Deserialize a GT element from CBOR byte string
    /// \param decoder CBOR decoder to use
    /// \param element GT element to populate
    /// \throws ZCBORException on deserialization failure
    void decodeGT(ZCBORDecoder& decoder, GT& element);

    /// Deserialize a Zr (scalar) element from CBOR byte string
    /// \param decoder CBOR decoder to use
    /// \param element Zr element to populate
    /// \param order_ptr Group order as void pointer (cast from bignum_t)
    /// \throws ZCBORException on deserialization failure
    void decodeZr(ZCBORDecoder& decoder, ZP& element, const void* order_ptr);

    /// Get current encoding format
    GEEncoding getEncoding() const { return encoding_; }

    /// Get current endianness
    Endianness getEndianness() const { return endianness_; }

    /// Set encoding format
    void setEncoding(GEEncoding encoding) { encoding_ = encoding; }

    /// Set endianness
    void setEndianness(Endianness endianness) { endianness_ = endianness; }

private:
    GEEncoding encoding_;      ///< Group element encoding format
    Endianness endianness_;    ///< Byte order for serialization

    /// Convert bytes to big-endian if needed
    /// \param data Byte array to convert (in-place)
    /// \param len Length of byte array
    void convertToBigEndian(uint8_t* data, size_t len);

    /// Convert bytes from big-endian if needed
    /// \param data Byte array to convert (in-place)
    /// \param len Length of byte array
    void convertFromBigEndian(uint8_t* data, size_t len);

    /// Validate serialized size for curve and group
    /// \param expected Expected size in bytes
    /// \param actual Actual size in bytes
    /// \param group_name Group name for error message
    /// \throws ZCBORException if sizes don't match
    void validateSize(size_t expected, size_t actual, const char* group_name);
};

/// Utility functions for endianness conversion

/// Reverse byte order of a buffer
/// \param data Buffer to reverse (in-place)
/// \param len Length of buffer
void reverseBytes(uint8_t* data, size_t len);

/// Check if system is little-endian
/// \return true if system is little-endian, false if big-endian
bool isLittleEndian();

/// Get expected serialized size for G1 element
/// \param encoding Encoding format
/// \param curve_id Curve identifier
/// \return Size in bytes
size_t getG1Size(GEEncoding encoding, OpenABECurveID curve_id);

/// Get expected serialized size for G2 element
/// \param encoding Encoding format
/// \param curve_id Curve identifier
/// \return Size in bytes
size_t getG2Size(GEEncoding encoding, OpenABECurveID curve_id);

/// Get expected serialized size for GT element
/// \param curve_id Curve identifier
/// \return Size in bytes
size_t getGTSize(OpenABECurveID curve_id);

/// Get expected serialized size for Zr element
/// \param curve_id Curve identifier
/// \return Size in bytes (field size in bytes)
size_t getZrSize(OpenABECurveID curve_id);

} // namespace cbor
} // namespace oabe

#endif // __ZCBOR_GROUP_ELEMENTS_H__
