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
/// \file   zcbor_wrapper.h
///
/// \brief  C++ wrapper around tinycbor for ABE-CBOR v1 serialization
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#ifndef __ZCBOR_WRAPPER_H__
#define __ZCBOR_WRAPPER_H__

#include <cbor.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

namespace oabe {

/// Forward declarations
class ZCBOREncoder;
class ZCBORDecoder;

///
/// @class ZCBORException
/// @brief Exception class for CBOR encoding/decoding errors
///
class ZCBORException : public std::runtime_error {
public:
    explicit ZCBORException(const std::string& msg)
        : std::runtime_error(msg) {}
    explicit ZCBORException(const char* msg)
        : std::runtime_error(msg) {}
};

///
/// @class ZCBOREncoder
/// @brief CBOR encoder wrapper for deterministic encoding
///
/// Implements ABE-CBOR v1 deterministic encoding rules:
/// - Shortest form encoding for all types
/// - Definite-length encoding (no indefinite lengths)
/// - Sorted integer keys for maps
/// - UTF-8 NFC normalization for strings
///
class ZCBOREncoder {
private:
    std::vector<uint8_t> buffer_;
    CborEncoder encoder_;
    bool finalized_;

public:
    /// Constructor with initial buffer size
    explicit ZCBOREncoder(size_t initial_capacity = 1024);

    /// Destructor
    ~ZCBOREncoder();

    // Delete copy constructor and assignment
    ZCBOREncoder(const ZCBOREncoder&) = delete;
    ZCBOREncoder& operator=(const ZCBOREncoder&) = delete;

    /// Reset encoder state and clear buffer
    void reset();

    /// Get encoded data (finalizes encoding)
    std::vector<uint8_t> getEncoded();

    /// Get encoded data as string (finalizes encoding)
    std::string getEncodedString();

    /// Get buffer size
    size_t size() const { return buffer_.size(); }

    // Primitive encoding methods

    /// Encode unsigned integer (uses shortest form)
    void encodeUInt(uint64_t value);

    /// Encode signed integer (uses shortest form)
    void encodeInt(int64_t value);

    /// Encode byte string (definite length)
    void encodeBytes(const uint8_t* data, size_t len);
    void encodeBytes(const std::vector<uint8_t>& data);

    /// Encode text string (definite length, UTF-8)
    void encodeText(const std::string& text);
    void encodeText(const char* text);

    /// Encode boolean
    void encodeBool(bool value);

    /// Encode null
    void encodeNull();

    /// Encode undefined
    void encodeUndefined();

    // Container encoding methods

    /// Begin encoding a map with known size (sorted keys required)
    /// @param size Number of key-value pairs
    void beginMap(size_t size);

    /// End map encoding
    void endMap();

    /// Begin encoding an array with known size
    /// @param size Number of elements
    void beginArray(size_t size);

    /// End array encoding
    void endArray();

    /// Encode a tag (for semantic tagging)
    /// @param tag Tag value (e.g., 60001 for ABE-CBOR)
    void encodeTag(uint64_t tag);

    // Convenience methods for map entries

    /// Encode map key (integer)
    void encodeMapKey(uint64_t key) { encodeUInt(key); }

    /// Encode map key (string)
    void encodeMapKey(const std::string& key) { encodeText(key); }

    // Helper methods

    /// Reserve buffer space
    void reserve(size_t capacity);

    /// Get underlying CborEncoder (for advanced use)
    CborEncoder* getCborEncoder() { return &encoder_; }
};

///
/// @class ZCBORDecoder
/// @brief CBOR decoder wrapper with validation
///
/// Implements ABE-CBOR v1 decoding with:
/// - Canonical encoding validation
/// - Subgroup membership checks (when applicable)
/// - Error detection and reporting
///
class ZCBORDecoder {
private:
    std::vector<uint8_t> buffer_;
    CborParser parser_;
    CborValue value_;
    bool initialized_;
    std::vector<CborValue> container_stack_;  // Stack for nested containers

    /// Validate canonical encoding
    void validateCanonical(const CborValue* val);

public:
    /// Constructor from byte array
    ZCBORDecoder(const uint8_t* data, size_t len);

    /// Constructor from vector
    explicit ZCBORDecoder(const std::vector<uint8_t>& data);

    /// Constructor from string
    explicit ZCBORDecoder(const std::string& data);

    /// Destructor
    ~ZCBORDecoder();

    // Delete copy constructor and assignment
    ZCBORDecoder(const ZCBORDecoder&) = delete;
    ZCBORDecoder& operator=(const ZCBORDecoder&) = delete;

    /// Reset to start of data
    void reset();

    // Type checking methods

    /// Check if current value is unsigned integer
    bool isUInt() const;

    /// Check if current value is signed integer
    bool isInt() const;

    /// Check if current value is byte string
    bool isBytes() const;

    /// Check if current value is text string
    bool isText() const;

    /// Check if current value is boolean
    bool isBool() const;

    /// Check if current value is null
    bool isNull() const;

    /// Check if current value is undefined
    bool isUndefined() const;

    /// Check if current value is map
    bool isMap() const;

    /// Check if current value is array
    bool isArray() const;

    /// Check if current value is tagged
    bool isTag() const;

    /// Check if at end of container or data
    bool atEnd() const;

    // Decoding methods

    /// Decode unsigned integer
    uint64_t decodeUInt();

    /// Decode signed integer
    int64_t decodeInt();

    /// Decode byte string
    std::vector<uint8_t> decodeBytes();
    void decodeBytes(uint8_t* buffer, size_t* len);

    /// Decode text string
    std::string decodeText();

    /// Decode boolean
    bool decodeBool();

    /// Decode null (advances to next value)
    void decodeNull();

    /// Decode undefined (advances to next value)
    void decodeUndefined();

    // Container decoding methods

    /// Enter map (returns number of entries)
    size_t enterMap();

    /// Exit map
    void exitMap();

    /// Enter array (returns number of elements)
    size_t enterArray();

    /// Exit array
    void exitArray();

    /// Decode tag value
    uint64_t decodeTag();

    /// Decode tag and enter tagged value
    uint64_t decodeTagAndEnter();

    /// Advance to next value in container
    void advance();

    // Map decoding helpers

    /// Decode map key (unsigned integer)
    uint64_t decodeMapKeyUInt();

    /// Decode map key (text string)
    std::string decodeMapKeyText();

    // Validation helpers

    /// Verify that map keys are sorted (for deterministic encoding)
    static void verifySortedMapKeys(const CborValue* map);

    /// Get underlying CborValue (for advanced use)
    CborValue* getCborValue() { return &value_; }

    /// Get error string from CborError
    static std::string getErrorString(CborError err);
};

} // namespace oabe

#endif // __ZCBOR_WRAPPER_H__
