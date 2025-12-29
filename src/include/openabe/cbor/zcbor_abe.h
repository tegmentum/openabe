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
/// \file   zcbor_abe.h
///
/// \brief  ABE-CBOR v1 high-level key and ciphertext serialization
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#ifndef __ZCBOR_ABE_H__
#define __ZCBOR_ABE_H__

#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_constants.h>
#include <openabe/cbor/zcbor_group_elements.h>
#include <openabe/cbor/zcbor_attributes.h>
#include <openabe/cbor/zcbor_policy.h>
#include <openabe/keys/zkey.h>
#include <openabe/utils/zciphertext.h>
#include <string>
#include <vector>
#include <map>

namespace oabe {
namespace cbor {

///
/// ABE-CBOR v1 Format Specification
/// ================================
///
/// Top-Level Structure (CBOR Tag 60001):
/// {
///   0: version (uint),         // ABE-CBOR version (currently 1)
///   1: kind (uint),            // Object kind (MSK=1, MPK=2, SK=3, CT=4)
///   2: scheme (text),          // Scheme name ("cpabe-waters", "kpabe-gpsw")
///   3: curve (text),           // Curve name ("bls12-381", "bn254")
///   4: data (map)              // Scheme-specific data
/// }
///
/// CP-ABE Waters Ciphertext (kind=4):
/// data: {
///   0: C0 (GT element),        // Blinded message
///   1: C1 (G2 element),        // g^s
///   2: policy (RPN tokens),    // Access policy
///   3: C_map (map),            // Attribute -> (G1, G2) pairs
///   4: uid (bytes, optional),  // Unique ID
///   5: sym_ct (bytes)          // Symmetric ciphertext
/// }
///
/// CP-ABE Waters Secret Key (kind=3):
/// data: {
///   0: K (GT element),         // g^{alpha} * h^r
///   1: L (G2 element),         // g^r
///   2: attributes (array),     // User attributes
///   3: K_map (map)             // Attribute -> G1 pairs
/// }
///
/// CP-ABE Waters Master Public Key (kind=2):
/// data: {
///   0: g (GT element),         // Generator
///   1: h (G2 element),         // h = g^beta
///   2: e_gg_alpha (GT element) // e(g,g)^alpha
/// }
///
/// CP-ABE Waters Master Secret Key (kind=1):
/// data: {
///   0: beta (Zr element),      // Secret exponent beta
///   1: g_alpha (G2 element)    // g^alpha
/// }
///

/// \class  ABESerializer
/// \brief  High-level serializer for ABE keys and ciphertexts
class ABESerializer {
public:
    ABESerializer();

    // Serialize OpenABEKey to CBOR (MSK, MPK, SK)
    void serializeKey(ZCBOREncoder& encoder, const OpenABEKey& key);
    std::unique_ptr<OpenABEKey> deserializeKey(ZCBORDecoder& decoder);

    // Serialize OpenABECiphertext to CBOR (CT)
    void serializeCiphertext(ZCBOREncoder& encoder, const OpenABECiphertext& ct);
    std::unique_ptr<OpenABECiphertext> deserializeCiphertext(ZCBORDecoder& decoder);

    // Export/import to/from byte strings (includes CBOR tag)
    void exportKeyToBytes(const OpenABEKey& key, OpenABEByteString& output);
    std::unique_ptr<OpenABEKey> importKeyFromBytes(const OpenABEByteString& input);

    void exportCiphertextToBytes(const OpenABECiphertext& ct, OpenABEByteString& output);
    std::unique_ptr<OpenABECiphertext> importCiphertextFromBytes(const OpenABEByteString& input);

private:
    GroupElementSerializer ge_serializer_;
    AttributeSerializer attr_serializer_;
    PolicySerializer policy_serializer_;

    // Encode top-level ABE-CBOR structure
    void encodeABEHeader(ZCBOREncoder& encoder, ABEKind kind,
                        const std::string& scheme, const std::string& curve);

    // Decode top-level ABE-CBOR structure
    void decodeABEHeader(ZCBORDecoder& decoder, ABEKind& kind,
                        std::string& scheme, std::string& curve);

    // Scheme-specific serialization methods
    void serializeContainer(ZCBOREncoder& encoder, const OpenABEContainer& container);
    void deserializeContainer(ZCBORDecoder& decoder, OpenABEContainer& container,
                             const std::string& scheme);

    // Helper methods for encoding/decoding group element maps
    void encodeGroupElementMap(ZCBOREncoder& encoder,
                              const std::map<std::string, ZObject*>& components,
                              const std::string& prefix);

    void decodeGroupElementMap(ZCBORDecoder& decoder, OpenABEContainer& container,
                              const std::string& prefix, OpenABECurveID curve_id);
};

/// \brief  Convenience functions for direct serialization
void exportABEKeyToBytes(const OpenABEKey& key, std::vector<uint8_t>& output);
std::unique_ptr<OpenABEKey> importABEKeyFromBytes(const std::vector<uint8_t>& input);

void exportABECiphertextToBytes(const OpenABECiphertext& ct, std::vector<uint8_t>& output);
std::unique_ptr<OpenABECiphertext> importABECiphertextFromBytes(const std::vector<uint8_t>& input);

} // namespace cbor
} // namespace oabe

#endif // __ZCBOR_ABE_H__
