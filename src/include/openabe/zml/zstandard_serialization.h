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
/// \file   zstandard_serialization.h
///
/// \brief  Standard serialization formats (SEC1, ZCash BLS12-381, Ethereum BN254, IETF)
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZSTANDARD_SERIALIZATION_H__
#define __ZSTANDARD_SERIALIZATION_H__

#include <openabe/zml/zelement.h>
#include <openabe/zml/zelement_bp.h>

namespace oabe {

/// \brief Serialization format identifiers
typedef enum _SerializationFormat {
    OPENABE_LEGACY = 0x00,      ///< Current OpenABE format (backward compat)
    SEC1_STANDARD = 0x01,        ///< SEC1 v2 (EC points only)
    ZCASH_BLS12 = 0x02,          ///< ZCash format (for BLS12-381)
    ETHEREUM_BN254 = 0x03,       ///< Ethereum format (for BN254)
    IETF_PAIRING = 0x04,         ///< IETF draft (general pairing curves)
    FORMAT_AUTO = 0xFF           ///< Auto-select based on curve
} SerializationFormat;

/// \brief GT serialization mode
typedef enum _GTSerializationMode {
    GT_FULL_TOWER = 0x00,        ///< Full Fp12 representation
    GT_CYCLOTOMIC_COMPRESSED = 0x01  ///< Compressed using cyclotomic subgroup
} GTSerializationMode;

/// \brief Wire format flags (ZCash-style for points)
namespace SerializationFlags {
    const uint8_t COMPRESSION_FLAG = 0x80;  ///< Bit 7: 1 = compressed, 0 = uncompressed
    const uint8_t INFINITY_FLAG = 0x40;     ///< Bit 6: 1 = point at infinity
    const uint8_t Y_SIGN_FLAG = 0x20;       ///< Bit 5: Y-coordinate sign (compressed)
    const uint8_t CYCLOTOMIC_FLAG = 0x10;   ///< Bit 4: Cyclotomic compression (GT)
}

/// \brief Standard serialization header structure
///
/// Format: [MAGIC(4)][VERSION(1)][ELEM_TYPE(1)][CURVE_ID(1)][FORMAT(1)][FLAGS(1)][DATA...]
struct SerializationHeader {
    static const uint8_t MAGIC[4];          ///< {'O', 'A', 'B', 'E'}
    static const uint8_t CURRENT_VERSION = 0x02;  ///< Format version

    uint8_t version;
    OpenABEElementType elementType;
    OpenABECurveID curveID;
    SerializationFormat format;
    uint8_t flags;

    SerializationHeader();
    SerializationHeader(OpenABEElementType type, OpenABECurveID curve,
                       SerializationFormat fmt = FORMAT_AUTO, uint8_t f = 0);

    void serialize(OpenABEByteString& out) const;
    bool deserialize(OpenABEByteString& in, size_t* index);
    bool isStandardFormat() const;
    size_t getHeaderSize() const { return 9; }  // 4 + 1 + 1 + 1 + 1 + 1
};

/// \brief Standard pairing serialization class
class StandardPairingSerializer {
public:
    // ===== Field Element Utilities =====

    /// Convert field element to big-endian bytes
    static void field_element_to_bytes(const bignum_t elem, OpenABEByteString& out,
                                      size_t field_size, bool big_endian = true);

    /// Convert big-endian bytes to field element
    static void bytes_to_field_element(bignum_t elem, OpenABEByteString& in,
                                      size_t offset = 0, bool big_endian = true);

    /// Get field size in bytes for curve
    static size_t get_field_size(OpenABECurveID curve);

    /// Check if Y coordinate is lexicographically largest
    static bool y_is_lexicographically_largest(const bignum_t y, const bignum_t p);

    // ===== G1 Serialization =====

    /// Serialize G1 with automatic format selection
    static void serializeG1(OpenABEByteString& out, const G1& point,
                           SerializationFormat format = FORMAT_AUTO, bool with_header = true);

    /// Deserialize G1
    static void deserializeG1(G1& point, OpenABEByteString& in, bool has_header = true);

    /// SEC1 format for G1
    static void serializeG1_SEC1(OpenABEByteString& out, const G1& point, bool compressed = true);
    static void deserializeG1_SEC1(G1& point, OpenABEByteString& in);

    /// ZCash BLS12-381 format for G1
    static void serializeG1_ZCash(OpenABEByteString& out, const G1& point, bool compressed = true);
    static void deserializeG1_ZCash(G1& point, OpenABEByteString& in);

    /// Ethereum BN254 format for G1
    static void serializeG1_Ethereum(OpenABEByteString& out, const G1& point);
    static void deserializeG1_Ethereum(G1& point, OpenABEByteString& in);

    // ===== G2 Serialization =====

    /// Serialize G2 with automatic format selection
    static void serializeG2(OpenABEByteString& out, const G2& point,
                           SerializationFormat format = FORMAT_AUTO, bool with_header = true);

    /// Deserialize G2
    static void deserializeG2(G2& point, OpenABEByteString& in, bool has_header = true);

    /// SEC1 format for G2
    static void serializeG2_SEC1(OpenABEByteString& out, const G2& point, bool compressed = true);
    static void deserializeG2_SEC1(G2& point, OpenABEByteString& in);

    /// ZCash BLS12-381 format for G2
    static void serializeG2_ZCash(OpenABEByteString& out, const G2& point, bool compressed = true);
    static void deserializeG2_ZCash(G2& point, OpenABEByteString& in);

    /// Ethereum BN254 format for G2
    static void serializeG2_Ethereum(OpenABEByteString& out, const G2& point);
    static void deserializeG2_Ethereum(G2& point, OpenABEByteString& in);

    // ===== GT Serialization =====

    /// Serialize GT with automatic mode selection
    static void serializeGT(OpenABEByteString& out, const GT& gt,
                           GTSerializationMode mode = GT_CYCLOTOMIC_COMPRESSED,
                           bool with_header = true);

    /// Deserialize GT
    static void deserializeGT(GT& gt, OpenABEByteString& in, bool has_header = true);

    /// Full Fp12 tower serialization
    static void serializeGT_Full(OpenABEByteString& out, const GT& gt);
    static void deserializeGT_Full(GT& gt, OpenABEByteString& in);

    /// Cyclotomic compression (8 of 12 Fp elements)
    static void serializeGT_Cyclotomic(OpenABEByteString& out, const GT& gt);
    static void deserializeGT_Cyclotomic(GT& gt, OpenABEByteString& in);

    // ===== Format Utilities =====

    /// Auto-select best format for curve
    static SerializationFormat selectFormat(OpenABECurveID curve);

    /// Check if curve supports cyclotomic compression
    static bool supports_cyclotomic_compression(OpenABECurveID curve);

    /// Detect legacy format (no header)
    static bool isLegacyFormat(const OpenABEByteString& in);

    /// Convert legacy to standard format
    static void convertLegacyToStandard(OpenABEByteString& out, const OpenABEByteString& in,
                                       OpenABEElementType type, OpenABECurveID curve);

private:
    // Internal helpers
    static void extractG1Coordinates(const G1& point, bignum_t x, bignum_t y);
    static void setG1FromCoordinates(G1& point, const bignum_t x, const bignum_t y);
    static bool isG1AtInfinity(const G1& point);
    static void setG1ToInfinity(G1& point);

    static void extractG2Coordinates(const G2& point, bignum_t x[2], bignum_t y[2]);
    static void setG2FromCoordinates(G2& point, const bignum_t x[2], const bignum_t y[2]);
    static bool isG2AtInfinity(const G2& point);
    static void setG2ToInfinity(G2& point);

    static bool isGTIdentity(const GT& gt);
    static void setGTToIdentity(GT& gt);

    // Fp12 tower extraction/reconstruction
    static void extractFp12Tower(const GT& gt, bignum_t tower[12]);
    static void setGTFromFp12Tower(GT& gt, const bignum_t tower[12]);

    // Point decompression helpers
    /// Compute y from x using curve equation: y^2 = x^3 + ax + b
    /// Returns true if successful, false if no square root exists
    static bool decompressG1Point(const G1& point, const bignum_t x, bignum_t y, bool y_bit);

    /// Compute y from x for G2 (Fp2) using curve equation
    static bool decompressG2Point(const G2& point, const bignum_t x[2], bignum_t y[2], bool y_bit);
};

/// \brief Legacy compatibility layer
class LegacySerializer {
public:
    /// Detect if data uses legacy format
    static bool detectLegacyFormat(const OpenABEByteString& data);

    /// Get element type from legacy data
    static OpenABEElementType getLegacyElementType(const OpenABEByteString& data);

    /// Convert legacy G1 to standard format
    static void convertLegacyG1(OpenABEByteString& out, const OpenABEByteString& in,
                               std::shared_ptr<BPGroup> bgroup);

    /// Convert legacy G2 to standard format
    static void convertLegacyG2(OpenABEByteString& out, const OpenABEByteString& in,
                               std::shared_ptr<BPGroup> bgroup);

    /// Convert legacy GT to standard format
    static void convertLegacyGT(OpenABEByteString& out, const OpenABEByteString& in,
                               std::shared_ptr<BPGroup> bgroup);
};

} // namespace oabe

#endif // __ZSTANDARD_SERIALIZATION_H__
