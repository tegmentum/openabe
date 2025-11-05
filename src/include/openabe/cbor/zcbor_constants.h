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
/// \file   zcbor_constants.h
///
/// \brief  Constants and identifiers for ABE-CBOR v1 serialization
///         Based on ABE-CBOR-REGISTRY.md v1.0
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#ifndef __ZCBOR_CONSTANTS_H__
#define __ZCBOR_CONSTANTS_H__

#include <cstdint>
#include <string>

namespace oabe {
namespace cbor {

// ============================================================================
// ABE-CBOR Version
// ============================================================================

/// ABE-CBOR specification version
constexpr uint32_t ABE_CBOR_VERSION = 1;

/// ABE-CBOR CBOR tag (private-use range)
constexpr uint64_t ABE_CBOR_TAG = 60001;

// ============================================================================
// ABE Item Kinds (field key 0)
// ============================================================================

enum class ABEKind : uint32_t {
    MSK = 1,    ///< Master Secret Key
    MPK = 2,    ///< Master Public Key
    SK  = 3,    ///< User Secret Key (attribute key)
    CT  = 4     ///< Ciphertext
};

// ============================================================================
// Map Field Keys
// ============================================================================

namespace field {
    // Top-level ABE-Item fields
    constexpr uint32_t KIND     = 0;  ///< ABE item kind (MSK/MPK/SK/CT)
    constexpr uint32_t SUITE    = 1;  ///< Crypto suite descriptor
    constexpr uint32_t VERSION  = 2;  ///< Profile version (default: 1)
    constexpr uint32_t AUTH_ID  = 3;  ///< Authority ID (MA-ABE/DCPABE)
    constexpr uint32_t META     = 4;  ///< Metadata (free-form)
    constexpr uint32_t BODY     = 5;  ///< Kind-specific body

    // Suite descriptor fields
    namespace suite {
        constexpr uint32_t SCHEME_ID = 0;  ///< Scheme identifier string
        constexpr uint32_t CURVE     = 1;  ///< Curve parameters
        constexpr uint32_t GE        = 2;  ///< Group element encoding
        constexpr uint32_t HASH_KDF  = 3;  ///< Hash/KDF suite (optional)
    }

    // Curve descriptor fields
    namespace curve {
        constexpr uint32_t CURVE_ID      = 0;  ///< Curve identifier string
        constexpr uint32_t SECURITY_LEVEL = 1;  ///< Security level in bits (optional)
        constexpr uint32_t PARAMS        = 2;  ///< Explicit params (optional)
    }

    // GE encoding fields
    namespace ge {
        constexpr uint32_t ENCODING_ID    = 0;  ///< GE encoding format ID
        constexpr uint32_t ENDIANNESS     = 1;  ///< 0=big-endian, 1=little-endian
        constexpr uint32_t SUBGROUP_CHECK = 2;  ///< Require subgroup check on decode
        constexpr uint32_t OPTIONS        = 3;  ///< Per-curve options (optional)
    }

    // Hash/KDF fields
    namespace hash_kdf {
        constexpr uint32_t HASH_ID = 0;  ///< Hash algorithm identifier
        constexpr uint32_t KDF_ID  = 1;  ///< KDF algorithm identifier (optional)
    }

    // Body fields (scheme-specific)
    namespace body {
        constexpr uint32_t GROUP_ELEMS = 0;  ///< Group elements array
        constexpr uint32_t ATTR_SET    = 1;  ///< Attribute set (SK)
        constexpr uint32_t POLICY      = 1;  ///< Access policy (CT)
        constexpr uint32_t DELEG_PROOF = 2;  ///< Delegation proof (SK, optional)
        constexpr uint32_t PAYLOAD     = 2;  ///< Payload wrap (CT, optional)
    }

    // Attribute set fields
    namespace attr_set {
        constexpr uint32_t ATTRIBUTES = 0;  ///< Array of attributes
        constexpr uint32_t METADATA   = 1;  ///< Domain metadata (optional)
    }

    // Attribute fields
    namespace attr {
        constexpr uint32_t TYPE  = 0;  ///< Attribute type
        constexpr uint32_t VALUE = 1;  ///< Attribute value
    }

    // Policy fields
    namespace policy {
        constexpr uint32_t ENCODING = 0;  ///< Policy encoding (0=BoolAST, 1=MSP)
        constexpr uint32_t BODY     = 1;  ///< Policy body
    }

    // Token fields (Boolean AST)
    namespace token {
        constexpr uint32_t KIND    = 0;  ///< Token kind
        constexpr uint32_t PAYLOAD = 1;  ///< Token payload (optional)
    }

    // AttrRef fields
    namespace attr_ref {
        constexpr uint32_t INDEX = 0;  ///< Index into attribute set
    }

    // MSP fields
    namespace msp {
        constexpr uint32_t MATRIX = 0;  ///< Matrix rows
        constexpr uint32_t RHO    = 1;  ///< Row-to-attribute mapping
    }

    // Threshold fields
    namespace threshold {
        constexpr uint32_t K = 0;  ///< Threshold (k)
        constexpr uint32_t N = 1;  ///< Total (n)
    }

    // Range fields
    namespace range {
        constexpr uint32_t MIN           = 0;  ///< Minimum value
        constexpr uint32_t MAX           = 1;  ///< Maximum value
        constexpr uint32_t MIN_INCLUSIVE = 2;  ///< Min inclusive (default: true)
        constexpr uint32_t MAX_INCLUSIVE = 3;  ///< Max inclusive (default: true)
    }
} // namespace field

// ============================================================================
// Attribute Types
// ============================================================================

enum class AttributeType : uint32_t {
    STRING  = 0,  ///< UTF-8 text string (NFC normalized)
    INTEGER = 1,  ///< Signed integer
    BYTES   = 2,  ///< Arbitrary byte string
    SET     = 3,  ///< Set (sorted array)
    RANGE   = 4   ///< Integer range
};

// ============================================================================
// Policy Encoding Types
// ============================================================================

enum class PolicyEncoding : uint32_t {
    BOOL_AST = 0,  ///< Boolean AST (RPN token list)
    MSP      = 1   ///< Monotone Span Program (matrix + rho)
};

// ============================================================================
// Token Kinds (Boolean AST)
// ============================================================================

enum class TokenKind : uint32_t {
    ATTR   = 0,  ///< Attribute reference
    AND    = 1,  ///< Logical AND
    OR     = 2,  ///< Logical OR
    THRESH = 3,  ///< Threshold gate
    NOT    = 4   ///< Logical NOT
};

// ============================================================================
// Endianness
// ============================================================================

enum class Endianness : uint32_t {
    BIG    = 0,  ///< Big-endian (MSB first)
    LITTLE = 1   ///< Little-endian (LSB first)
};

// ============================================================================
// Scheme Identifiers (ABE-CBOR-REGISTRY.md)
// ============================================================================

namespace scheme {
    constexpr const char* CPABE_WATERS      = "cpabe-waters";       ///< CP-ABE Waters (BSW07)
    constexpr const char* KPABE_GPSW        = "kpabe-gpsw";         ///< KP-ABE GPSW (GPSW06)
    constexpr const char* CPABE_WATERS_CCA  = "cpabe-waters-cca";   ///< CP-ABE Waters CCA
    constexpr const char* KPABE_GPSW_CCA    = "kpabe-gpsw-cca";     ///< KP-ABE GPSW CCA
    constexpr const char* MAABE_LU08        = "maabe-lu08";         ///< MA-ABE Lu et al.
    constexpr const char* DCPABE_WATERS11   = "dcpabe-waters11";    ///< Delegated CP-ABE Waters
} // namespace scheme

// ============================================================================
// Curve Identifiers (ABE-CBOR-REGISTRY.md)
// ============================================================================

namespace curve {
    constexpr const char* BLS12_381 = "bls12-381";  ///< BLS12-381 (recommended)
    constexpr const char* BN254     = "bn254";      ///< BN254 (legacy)
    constexpr const char* BLS12_377 = "bls12-377";  ///< BLS12-377 (experimental)
    constexpr const char* BW6_761   = "bw6-761";    ///< BW6-761 (experimental)
} // namespace curve

// ============================================================================
// Group Element Encoding IDs (ABE-CBOR-REGISTRY.md)
// ============================================================================

enum class GEEncoding : uint32_t {
    IETF_COMPRESSED = 0,  ///< IETF compressed point (BLS12-381 only)
    UNCOMPRESSED    = 1,  ///< Full affine coordinates
    MCL_CANONICAL   = 2   ///< MCL library native format
};

// Encoding sizes for BLS12-381
namespace ge_size {
    namespace bls12_381 {
        // IETF compressed
        constexpr size_t G1_COMPRESSED  = 48;   ///< G1 compressed point
        constexpr size_t G2_COMPRESSED  = 96;   ///< G2 compressed point
        constexpr size_t GT             = 576;  ///< GT element (Fp12)

        // Uncompressed
        constexpr size_t G1_UNCOMPRESSED = 96;   ///< G1 uncompressed point
        constexpr size_t G2_UNCOMPRESSED = 192;  ///< G2 uncompressed point
    }
} // namespace ge_size

// ============================================================================
// Hash Function Identifiers (ABE-CBOR-REGISTRY.md)
// ============================================================================

namespace hash {
    constexpr const char* SHA256      = "SHA-256";      ///< SHA-2 256-bit (default)
    constexpr const char* SHA384      = "SHA-384";      ///< SHA-2 384-bit
    constexpr const char* SHA512      = "SHA-512";      ///< SHA-2 512-bit
    constexpr const char* BLAKE2S_256 = "BLAKE2s-256";  ///< BLAKE2s 256-bit
    constexpr const char* BLAKE3      = "BLAKE3";       ///< BLAKE3
} // namespace hash

// ============================================================================
// KDF Identifiers (ABE-CBOR-REGISTRY.md)
// ============================================================================

namespace kdf {
    constexpr const char* HKDF_SHA256   = "HKDF-SHA256";   ///< HKDF-SHA-256 (default)
    constexpr const char* HKDF_SHA384   = "HKDF-SHA384";   ///< HKDF-SHA-384
    constexpr const char* HKDF_SHA512   = "HKDF-SHA512";   ///< HKDF-SHA-512
    constexpr const char* KDF1_SHA256   = "KDF1-SHA256";   ///< KDF1-SHA-256 (legacy)
    constexpr const char* PBKDF2_SHA256 = "PBKDF2-SHA256"; ///< PBKDF2-SHA-256 (not recommended)
} // namespace kdf

// ============================================================================
// Security Levels
// ============================================================================

enum class SecurityLevel : uint32_t {
    BITS_128 = 128,  ///< 128-bit security (BLS12-381)
    BITS_192 = 192,  ///< 192-bit security
    BITS_256 = 256   ///< 256-bit security
};

// ============================================================================
// Default Values
// ============================================================================

namespace defaults {
    constexpr uint32_t VERSION = 1;
    constexpr bool SUBGROUP_CHECK = true;
    constexpr Endianness ENDIANNESS = Endianness::BIG;
    constexpr GEEncoding GE_ENCODING = GEEncoding::IETF_COMPRESSED;
    constexpr const char* CURVE = curve::BLS12_381;
    constexpr const char* HASH = hash::SHA256;
    constexpr const char* KDF = kdf::HKDF_SHA256;
} // namespace defaults

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert ABEKind enum to string
inline const char* abeKindToString(ABEKind kind) {
    switch (kind) {
        case ABEKind::MSK: return "MSK";
        case ABEKind::MPK: return "MPK";
        case ABEKind::SK:  return "SK";
        case ABEKind::CT:  return "CT";
        default: return "UNKNOWN";
    }
}

/// Convert AttributeType enum to string
inline const char* attributeTypeToString(AttributeType type) {
    switch (type) {
        case AttributeType::STRING:  return "STRING";
        case AttributeType::INTEGER: return "INTEGER";
        case AttributeType::BYTES:   return "BYTES";
        case AttributeType::SET:     return "SET";
        case AttributeType::RANGE:   return "RANGE";
        default: return "UNKNOWN";
    }
}

/// Convert PolicyEncoding enum to string
inline const char* policyEncodingToString(PolicyEncoding enc) {
    switch (enc) {
        case PolicyEncoding::BOOL_AST: return "BOOL_AST";
        case PolicyEncoding::MSP:      return "MSP";
        default: return "UNKNOWN";
    }
}

/// Convert TokenKind enum to string
inline const char* tokenKindToString(TokenKind kind) {
    switch (kind) {
        case TokenKind::ATTR:   return "ATTR";
        case TokenKind::AND:    return "AND";
        case TokenKind::OR:     return "OR";
        case TokenKind::THRESH: return "THRESH";
        case TokenKind::NOT:    return "NOT";
        default: return "UNKNOWN";
    }
}

/// Convert GEEncoding enum to string
inline const char* geEncodingToString(GEEncoding enc) {
    switch (enc) {
        case GEEncoding::IETF_COMPRESSED: return "ietf-compressed";
        case GEEncoding::UNCOMPRESSED:    return "uncompressed";
        case GEEncoding::MCL_CANONICAL:   return "mcl-canonical";
        default: return "UNKNOWN";
    }
}

} // namespace cbor
} // namespace oabe

#endif // __ZCBOR_CONSTANTS_H__
