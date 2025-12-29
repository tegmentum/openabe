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
/// \file   zcbor_attributes.h
///
/// \brief  ABE-CBOR v1 attribute serialization and canonicalization
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#ifndef __ZCBOR_ATTRIBUTES_H__
#define __ZCBOR_ATTRIBUTES_H__

#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_constants.h>
#include <string>
#include <vector>
#include <cstdint>

namespace oabe {

// Forward declaration
class OpenABEAttributeList;

namespace cbor {

/// \class  AttributeValue
/// \brief  Represents a single attribute value with type information
struct AttributeValue {
    AttributeType type;

    // Value storage (only one is used based on type)
    std::string string_value;      // For STRING
    int64_t int_value;             // For INTEGER
    std::vector<uint8_t> bytes_value;  // For BYTES
    std::vector<AttributeValue> set_value;  // For SET
    struct {
        int64_t min;
        int64_t max;
        bool min_inclusive;
        bool max_inclusive;
    } range_value;  // For RANGE

    // Constructors
    AttributeValue();
    AttributeValue(const std::string& str);
    AttributeValue(int64_t val);
    AttributeValue(const std::vector<uint8_t>& bytes);

    // Comparison for sorting (canonical order)
    bool operator<(const AttributeValue& other) const;
    bool operator==(const AttributeValue& other) const;

    // Get canonical byte representation for sorting
    std::vector<uint8_t> getCanonicalBytes() const;
};

/// \class  AttributeSerializer
/// \brief  Serializes and deserializes ABE attributes with canonicalization
class AttributeSerializer {
public:
    AttributeSerializer();

    // Attribute encoding/decoding
    void encodeAttribute(ZCBOREncoder& encoder, const AttributeValue& attr);
    AttributeValue decodeAttribute(ZCBORDecoder& decoder);

    // Attribute list encoding/decoding (with sorting)
    void encodeAttributeList(ZCBOREncoder& encoder, std::vector<AttributeValue>& attrs);
    std::vector<AttributeValue> decodeAttributeList(ZCBORDecoder& decoder);

    // Convert OpenABEAttributeList to ABE-CBOR format
    std::vector<AttributeValue> fromOpenABEAttributeList(const OpenABEAttributeList& attrList);

    // String canonicalization utilities
    static std::string normalizeUTF8(const std::string& input);
    static bool isValidUTF8(const std::string& input);

private:
    // Encode specific attribute types
    void encodeStringAttribute(ZCBOREncoder& encoder, const std::string& value);
    void encodeIntegerAttribute(ZCBOREncoder& encoder, int64_t value);
    void encodeBytesAttribute(ZCBOREncoder& encoder, const std::vector<uint8_t>& value);
    void encodeSetAttribute(ZCBOREncoder& encoder, const std::vector<AttributeValue>& value);
    void encodeRangeAttribute(ZCBOREncoder& encoder, int64_t min, int64_t max,
                             bool min_inc, bool max_inc);

    // Decode specific attribute types
    std::string decodeStringAttribute(ZCBORDecoder& decoder);
    int64_t decodeIntegerAttribute(ZCBORDecoder& decoder);
    std::vector<uint8_t> decodeBytesAttribute(ZCBORDecoder& decoder);
    std::vector<AttributeValue> decodeSetAttribute(ZCBORDecoder& decoder);
    void decodeRangeAttribute(ZCBORDecoder& decoder, AttributeValue& attr);

    // Sorting and canonicalization
    void sortAttributes(std::vector<AttributeValue>& attrs);
    void removeDuplicates(std::vector<AttributeValue>& attrs);
};

// Utility functions for attribute handling
bool compareAttributesCanonical(const AttributeValue& a, const AttributeValue& b);

} // namespace cbor
} // namespace oabe

#endif // __ZCBOR_ATTRIBUTES_H__
