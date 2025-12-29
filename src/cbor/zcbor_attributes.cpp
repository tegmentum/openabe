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
/// \file   zcbor_attributes.cpp
///
/// \brief  ABE-CBOR v1 attribute serialization implementation
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#include <openabe/cbor/zcbor_attributes.h>
#include <openabe/openabe.h>
#include <algorithm>
#include <sstream>
#include <cstring>

namespace oabe {
namespace cbor {

// ============================================================================
// AttributeValue implementation
// ============================================================================

AttributeValue::AttributeValue() : type(AttributeType::STRING), int_value(0) {
    range_value.min = 0;
    range_value.max = 0;
    range_value.min_inclusive = true;
    range_value.max_inclusive = true;
}

AttributeValue::AttributeValue(const std::string& str)
    : type(AttributeType::STRING), string_value(str), int_value(0) {
}

AttributeValue::AttributeValue(int64_t val)
    : type(AttributeType::INTEGER), int_value(val) {
}

AttributeValue::AttributeValue(const std::vector<uint8_t>& bytes)
    : type(AttributeType::BYTES), bytes_value(bytes), int_value(0) {
}

std::vector<uint8_t> AttributeValue::getCanonicalBytes() const {
    std::vector<uint8_t> result;

    // Add type prefix
    result.push_back(static_cast<uint8_t>(type));

    switch (type) {
        case AttributeType::STRING: {
            const uint8_t* data = reinterpret_cast<const uint8_t*>(string_value.data());
            result.insert(result.end(), data, data + string_value.size());
            break;
        }
        case AttributeType::INTEGER: {
            // Encode integer in big-endian format
            int64_t val = int_value;
            for (int i = 7; i >= 0; i--) {
                result.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
            }
            break;
        }
        case AttributeType::BYTES: {
            result.insert(result.end(), bytes_value.begin(), bytes_value.end());
            break;
        }
        case AttributeType::SET: {
            // For sets, concatenate canonical bytes of all elements
            for (const auto& elem : set_value) {
                auto elem_bytes = elem.getCanonicalBytes();
                result.insert(result.end(), elem_bytes.begin(), elem_bytes.end());
            }
            break;
        }
        case AttributeType::RANGE: {
            // Encode range as min|max|min_inc|max_inc
            for (int i = 7; i >= 0; i--) {
                result.push_back(static_cast<uint8_t>((range_value.min >> (i * 8)) & 0xFF));
            }
            for (int i = 7; i >= 0; i--) {
                result.push_back(static_cast<uint8_t>((range_value.max >> (i * 8)) & 0xFF));
            }
            result.push_back(range_value.min_inclusive ? 1 : 0);
            result.push_back(range_value.max_inclusive ? 1 : 0);
            break;
        }
    }

    return result;
}

bool AttributeValue::operator<(const AttributeValue& other) const {
    // First compare by type
    if (type != other.type) {
        return static_cast<uint32_t>(type) < static_cast<uint32_t>(other.type);
    }

    // Then compare by canonical bytes
    auto this_bytes = getCanonicalBytes();
    auto other_bytes = other.getCanonicalBytes();
    return this_bytes < other_bytes;
}

bool AttributeValue::operator==(const AttributeValue& other) const {
    if (type != other.type) return false;

    switch (type) {
        case AttributeType::STRING:
            return string_value == other.string_value;
        case AttributeType::INTEGER:
            return int_value == other.int_value;
        case AttributeType::BYTES:
            return bytes_value == other.bytes_value;
        case AttributeType::SET:
            return set_value == other.set_value;
        case AttributeType::RANGE:
            return range_value.min == other.range_value.min &&
                   range_value.max == other.range_value.max &&
                   range_value.min_inclusive == other.range_value.min_inclusive &&
                   range_value.max_inclusive == other.range_value.max_inclusive;
    }
    return false;
}

// ============================================================================
// AttributeSerializer implementation
// ============================================================================

AttributeSerializer::AttributeSerializer() {
}

void AttributeSerializer::encodeAttribute(ZCBOREncoder& encoder, const AttributeValue& attr) {
    // Encode as map: {0: type, 1: value}
    encoder.beginMap(2);

    // Key 0: type
    encoder.encodeUInt(0);
    encoder.encodeUInt(static_cast<uint32_t>(attr.type));

    // Key 1: value
    encoder.encodeUInt(1);

    switch (attr.type) {
        case AttributeType::STRING:
            encodeStringAttribute(encoder, attr.string_value);
            break;
        case AttributeType::INTEGER:
            encodeIntegerAttribute(encoder, attr.int_value);
            break;
        case AttributeType::BYTES:
            encodeBytesAttribute(encoder, attr.bytes_value);
            break;
        case AttributeType::SET:
            encodeSetAttribute(encoder, attr.set_value);
            break;
        case AttributeType::RANGE:
            encodeRangeAttribute(encoder, attr.range_value.min, attr.range_value.max,
                               attr.range_value.min_inclusive, attr.range_value.max_inclusive);
            break;
    }
}

AttributeValue AttributeSerializer::decodeAttribute(ZCBORDecoder& decoder) {
    AttributeValue attr;

    // Decode map: {0: type, 1: value}
    size_t map_size = decoder.enterMap();
    if (map_size != 2) {
        throw ZCBORException("Invalid attribute map size");
    }

    // Read type (key 0)
    uint64_t key = decoder.decodeUInt();
    if (key != 0) {
        throw ZCBORException("Expected attribute type at key 0");
    }
    uint64_t type_val = decoder.decodeUInt();
    attr.type = static_cast<AttributeType>(type_val);

    // Read value (key 1)
    key = decoder.decodeUInt();
    if (key != 1) {
        throw ZCBORException("Expected attribute value at key 1");
    }

    switch (attr.type) {
        case AttributeType::STRING:
            attr.string_value = decodeStringAttribute(decoder);
            break;
        case AttributeType::INTEGER:
            attr.int_value = decodeIntegerAttribute(decoder);
            break;
        case AttributeType::BYTES:
            attr.bytes_value = decodeBytesAttribute(decoder);
            break;
        case AttributeType::SET:
            attr.set_value = decodeSetAttribute(decoder);
            break;
        case AttributeType::RANGE:
            decodeRangeAttribute(decoder, attr);
            break;
        default:
            throw ZCBORException("Unknown attribute type");
    }

    // Exit the map container to advance to next element
    decoder.exitMap();

    return attr;
}

void AttributeSerializer::encodeAttributeList(ZCBOREncoder& encoder, std::vector<AttributeValue>& attrs) {
    // Sort attributes by canonical order
    sortAttributes(attrs);

    // Encode as array
    encoder.beginArray(attrs.size());
    for (const auto& attr : attrs) {
        encodeAttribute(encoder, attr);
    }
}

std::vector<AttributeValue> AttributeSerializer::decodeAttributeList(ZCBORDecoder& decoder) {
    std::vector<AttributeValue> attrs;

    size_t array_size = decoder.enterArray();
    for (size_t i = 0; i < array_size; i++) {
        attrs.push_back(decodeAttribute(decoder));
    }

    return attrs;
}

// ============================================================================
// Type-specific encoding methods
// ============================================================================

void AttributeSerializer::encodeStringAttribute(ZCBOREncoder& encoder, const std::string& value) {
    // TODO: Apply UTF-8 NFC normalization
    std::string normalized = normalizeUTF8(value);
    encoder.encodeText(normalized);
}

void AttributeSerializer::encodeIntegerAttribute(ZCBOREncoder& encoder, int64_t value) {
    if (value >= 0) {
        encoder.encodeUInt(static_cast<uint64_t>(value));
    } else {
        encoder.encodeInt(value);
    }
}

void AttributeSerializer::encodeBytesAttribute(ZCBOREncoder& encoder, const std::vector<uint8_t>& value) {
    encoder.encodeBytes(value);
}

void AttributeSerializer::encodeSetAttribute(ZCBOREncoder& encoder, const std::vector<AttributeValue>& value) {
    // Sets are encoded as arrays of attributes
    encoder.beginArray(value.size());
    for (const auto& elem : value) {
        encodeAttribute(encoder, elem);
    }
}

void AttributeSerializer::encodeRangeAttribute(ZCBOREncoder& encoder, int64_t min, int64_t max,
                                              bool min_inc, bool max_inc) {
    // Encode as map: {0: min, 1: max, 2: min_inclusive, 3: max_inclusive}
    encoder.beginMap(4);
    encoder.encodeUInt(0);
    encoder.encodeInt(min);
    encoder.encodeUInt(1);
    encoder.encodeInt(max);
    encoder.encodeUInt(2);
    encoder.encodeBool(min_inc);
    encoder.encodeUInt(3);
    encoder.encodeBool(max_inc);
}

// ============================================================================
// Type-specific decoding methods
// ============================================================================

std::string AttributeSerializer::decodeStringAttribute(ZCBORDecoder& decoder) {
    return decoder.decodeText();
}

int64_t AttributeSerializer::decodeIntegerAttribute(ZCBORDecoder& decoder) {
    // Handle both positive and negative integers
    if (decoder.isUInt()) {
        return static_cast<int64_t>(decoder.decodeUInt());
    } else {
        return decoder.decodeInt();
    }
}

std::vector<uint8_t> AttributeSerializer::decodeBytesAttribute(ZCBORDecoder& decoder) {
    return decoder.decodeBytes();
}

std::vector<AttributeValue> AttributeSerializer::decodeSetAttribute(ZCBORDecoder& decoder) {
    std::vector<AttributeValue> set_elems;
    size_t array_size = decoder.enterArray();
    for (size_t i = 0; i < array_size; i++) {
        set_elems.push_back(decodeAttribute(decoder));
    }
    return set_elems;
}

void AttributeSerializer::decodeRangeAttribute(ZCBORDecoder& decoder, AttributeValue& attr) {
    size_t map_size = decoder.enterMap();
    if (map_size != 4) {
        throw ZCBORException("Invalid range attribute map size");
    }

    // Read min (key 0)
    uint64_t key = decoder.decodeUInt();
    if (key != 0) throw ZCBORException("Expected range min at key 0");
    attr.range_value.min = decoder.decodeInt();

    // Read max (key 1)
    key = decoder.decodeUInt();
    if (key != 1) throw ZCBORException("Expected range max at key 1");
    attr.range_value.max = decoder.decodeInt();

    // Read min_inclusive (key 2)
    key = decoder.decodeUInt();
    if (key != 2) throw ZCBORException("Expected range min_inclusive at key 2");
    attr.range_value.min_inclusive = decoder.decodeBool();

    // Read max_inclusive (key 3)
    key = decoder.decodeUInt();
    if (key != 3) throw ZCBORException("Expected range max_inclusive at key 3");
    attr.range_value.max_inclusive = decoder.decodeBool();

    // Validate range
    if (attr.range_value.min > attr.range_value.max) {
        throw ZCBORException("Invalid range: min > max");
    }

    // Exit the range map
    decoder.exitMap();
}

// ============================================================================
// Sorting and canonicalization
// ============================================================================

void AttributeSerializer::sortAttributes(std::vector<AttributeValue>& attrs) {
    std::sort(attrs.begin(), attrs.end());
}

void AttributeSerializer::removeDuplicates(std::vector<AttributeValue>& attrs) {
    auto last = std::unique(attrs.begin(), attrs.end());
    attrs.erase(last, attrs.end());
}

// ============================================================================
// UTF-8 utilities (basic implementation)
// ============================================================================

bool AttributeSerializer::isValidUTF8(const std::string& input) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(input.data());
    size_t len = input.size();

    for (size_t i = 0; i < len; ) {
        if ((bytes[i] & 0x80) == 0) {
            // 1-byte character (ASCII)
            i++;
        } else if ((bytes[i] & 0xE0) == 0xC0) {
            // 2-byte character
            if (i + 1 >= len || (bytes[i + 1] & 0xC0) != 0x80) return false;
            i += 2;
        } else if ((bytes[i] & 0xF0) == 0xE0) {
            // 3-byte character
            if (i + 2 >= len || (bytes[i + 1] & 0xC0) != 0x80 || (bytes[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((bytes[i] & 0xF8) == 0xF0) {
            // 4-byte character
            if (i + 3 >= len || (bytes[i + 1] & 0xC0) != 0x80 ||
                (bytes[i + 2] & 0xC0) != 0x80 || (bytes[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

std::string AttributeSerializer::normalizeUTF8(const std::string& input) {
    // Basic validation
    if (!isValidUTF8(input)) {
        throw ZCBORException("Invalid UTF-8 string");
    }

    // TODO: Implement full Unicode NFC normalization
    // For now, just return the input if it's valid UTF-8
    // Full NFC normalization requires ICU or utf8proc library
    return input;
}

// ============================================================================
// OpenABEAttributeList conversion
// ============================================================================

std::vector<AttributeValue> AttributeSerializer::fromOpenABEAttributeList(const OpenABEAttributeList& attrList) {
    std::vector<AttributeValue> attrs;

    const std::vector<std::string>* attr_strings = attrList.getAttributeList();
    if (attr_strings == nullptr) {
        return attrs;
    }

    for (const auto& attr_str : *attr_strings) {
        // Parse attribute string
        // OpenABE attributes are typically in format "name" or "name=value"
        // For ABE-CBOR, we'll treat them as string attributes
        AttributeValue attr(attr_str);
        attrs.push_back(attr);
    }

    return attrs;
}

// ============================================================================
// Utility functions
// ============================================================================

bool compareAttributesCanonical(const AttributeValue& a, const AttributeValue& b) {
    return a < b;
}

} // namespace cbor
} // namespace oabe
