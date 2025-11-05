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
/// \file   zcbor_wrapper.cpp
///
/// \brief  Implementation of C++ wrapper around tinycbor
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#include <openabe/cbor/zcbor_wrapper.h>
#include <cbor.h>
#include <cstring>
#include <algorithm>

namespace oabe {

// ============================================================================
// ZCBOREncoder Implementation
// ============================================================================

ZCBOREncoder::ZCBOREncoder(size_t initial_capacity)
    : finalized_(false) {
    buffer_.reserve(initial_capacity);
    buffer_.resize(initial_capacity);
    cbor_encoder_init(&encoder_, buffer_.data(), buffer_.size(), 0);
}

ZCBOREncoder::~ZCBOREncoder() {
    // Nothing to clean up
}

void ZCBOREncoder::reset() {
    buffer_.clear();
    buffer_.resize(1024);
    cbor_encoder_init(&encoder_, buffer_.data(), buffer_.size(), 0);
    finalized_ = false;
}

void ZCBOREncoder::reserve(size_t capacity) {
    if (capacity > buffer_.capacity()) {
        buffer_.reserve(capacity);
    }
}

std::vector<uint8_t> ZCBOREncoder::getEncoded() {
    if (!finalized_) {
        // Get actual size used
        size_t size = cbor_encoder_get_buffer_size(&encoder_, buffer_.data());
        buffer_.resize(size);
        finalized_ = true;
    }
    return buffer_;
}

std::string ZCBOREncoder::getEncodedString() {
    auto data = getEncoded();
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

// Primitive encoding methods

void ZCBOREncoder::encodeUInt(uint64_t value) {
    CborError err = cbor_encode_uint(&encoder_, value);
    if (err != CborNoError) {
        throw ZCBORException("Failed to encode uint: " +
                           std::string(cbor_error_string(err)));
    }
}

void ZCBOREncoder::encodeInt(int64_t value) {
    CborError err = cbor_encode_int(&encoder_, value);
    if (err != CborNoError) {
        throw ZCBORException("Failed to encode int: " +
                           std::string(cbor_error_string(err)));
    }
}

void ZCBOREncoder::encodeBytes(const uint8_t* data, size_t len) {
    CborError err = cbor_encode_byte_string(&encoder_, data, len);
    if (err != CborNoError) {
        throw ZCBORException("Failed to encode bytes: " +
                           std::string(cbor_error_string(err)));
    }
}

void ZCBOREncoder::encodeBytes(const std::vector<uint8_t>& data) {
    encodeBytes(data.data(), data.size());
}

void ZCBOREncoder::encodeText(const std::string& text) {
    CborError err = cbor_encode_text_string(&encoder_, text.c_str(), text.length());
    if (err != CborNoError) {
        throw ZCBORException("Failed to encode text: " +
                           std::string(cbor_error_string(err)));
    }
}

void ZCBOREncoder::encodeText(const char* text) {
    CborError err = cbor_encode_text_string(&encoder_, text, std::strlen(text));
    if (err != CborNoError) {
        throw ZCBORException("Failed to encode text: " +
                           std::string(cbor_error_string(err)));
    }
}

void ZCBOREncoder::encodeBool(bool value) {
    CborError err = cbor_encode_boolean(&encoder_, value);
    if (err != CborNoError) {
        throw ZCBORException("Failed to encode bool: " +
                           std::string(cbor_error_string(err)));
    }
}

void ZCBOREncoder::encodeNull() {
    CborError err = cbor_encode_null(&encoder_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to encode null: " +
                           std::string(cbor_error_string(err)));
    }
}

void ZCBOREncoder::encodeUndefined() {
    CborError err = cbor_encode_undefined(&encoder_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to encode undefined: " +
                           std::string(cbor_error_string(err)));
    }
}

// Container encoding methods

void ZCBOREncoder::beginMap(size_t size) {
    CborEncoder container;
    CborError err = cbor_encoder_create_map(&encoder_, &container, size);
    if (err != CborNoError) {
        throw ZCBORException("Failed to create map: " +
                           std::string(cbor_error_string(err)));
    }
    encoder_ = container;
}

void ZCBOREncoder::endMap() {
    // Note: In tinycbor, you need to keep track of the parent encoder
    // For now, this is a placeholder - proper implementation would use
    // a stack of encoders
}

void ZCBOREncoder::beginArray(size_t size) {
    CborEncoder container;
    CborError err = cbor_encoder_create_array(&encoder_, &container, size);
    if (err != CborNoError) {
        throw ZCBORException("Failed to create array: " +
                           std::string(cbor_error_string(err)));
    }
    encoder_ = container;
}

void ZCBOREncoder::endArray() {
    // Note: In tinycbor, you need to keep track of the parent encoder
    // For now, this is a placeholder - proper implementation would use
    // a stack of encoders
}

void ZCBOREncoder::encodeTag(uint64_t tag) {
    CborError err = cbor_encode_tag(&encoder_, (CborTag)tag);
    if (err != CborNoError) {
        throw ZCBORException("Failed to encode tag: " +
                           std::string(cbor_error_string(err)));
    }
}

// ============================================================================
// ZCBORDecoder Implementation
// ============================================================================

ZCBORDecoder::ZCBORDecoder(const uint8_t* data, size_t len)
    : buffer_(data, data + len), initialized_(false) {
    CborError err = cbor_parser_init(buffer_.data(), buffer_.size(), 0, &parser_, &value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to initialize CBOR parser: " +
                           std::string(cbor_error_string(err)));
    }
    initialized_ = true;
}

ZCBORDecoder::ZCBORDecoder(const std::vector<uint8_t>& data)
    : ZCBORDecoder(data.data(), data.size()) {
}

ZCBORDecoder::ZCBORDecoder(const std::string& data)
    : ZCBORDecoder(reinterpret_cast<const uint8_t*>(data.data()), data.size()) {
}

ZCBORDecoder::~ZCBORDecoder() {
    // Nothing to clean up
}

void ZCBORDecoder::reset() {
    CborError err = cbor_parser_init(buffer_.data(), buffer_.size(), 0, &parser_, &value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to reset CBOR parser: " +
                           std::string(cbor_error_string(err)));
    }
}

// Type checking methods

bool ZCBORDecoder::isUInt() const {
    return cbor_value_is_unsigned_integer(&value_);
}

bool ZCBORDecoder::isInt() const {
    return cbor_value_is_integer(&value_);
}

bool ZCBORDecoder::isBytes() const {
    return cbor_value_is_byte_string(&value_);
}

bool ZCBORDecoder::isText() const {
    return cbor_value_is_text_string(&value_);
}

bool ZCBORDecoder::isBool() const {
    return cbor_value_is_boolean(&value_);
}

bool ZCBORDecoder::isNull() const {
    return cbor_value_is_null(&value_);
}

bool ZCBORDecoder::isUndefined() const {
    return cbor_value_is_undefined(&value_);
}

bool ZCBORDecoder::isMap() const {
    return cbor_value_is_map(&value_);
}

bool ZCBORDecoder::isArray() const {
    return cbor_value_is_array(&value_);
}

bool ZCBORDecoder::isTag() const {
    return cbor_value_is_tag(&value_);
}

bool ZCBORDecoder::atEnd() const {
    return cbor_value_at_end(&value_);
}

// Decoding methods

uint64_t ZCBORDecoder::decodeUInt() {
    if (!isUInt()) {
        throw ZCBORException("Expected unsigned integer");
    }
    uint64_t value;
    CborError err = cbor_value_get_uint64(&value_, &value);
    if (err != CborNoError) {
        throw ZCBORException("Failed to decode uint: " +
                           std::string(cbor_error_string(err)));
    }
    err = cbor_value_advance(&value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to advance after uint: " +
                           std::string(cbor_error_string(err)));
    }
    return value;
}

int64_t ZCBORDecoder::decodeInt() {
    if (!isInt()) {
        throw ZCBORException("Expected integer");
    }
    int64_t value;
    CborError err = cbor_value_get_int64(&value_, &value);
    if (err != CborNoError) {
        throw ZCBORException("Failed to decode int: " +
                           std::string(cbor_error_string(err)));
    }
    err = cbor_value_advance(&value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to advance after int: " +
                           std::string(cbor_error_string(err)));
    }
    return value;
}

std::vector<uint8_t> ZCBORDecoder::decodeBytes() {
    if (!isBytes()) {
        throw ZCBORException("Expected byte string");
    }

    // Get length first
    size_t len;
    CborError err = cbor_value_get_string_length(&value_, &len);
    if (err != CborNoError) {
        throw ZCBORException("Failed to get byte string length: " +
                           std::string(cbor_error_string(err)));
    }

    // Allocate buffer and read data
    std::vector<uint8_t> result(len);
    err = cbor_value_copy_byte_string(&value_, result.data(), &len, &value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to decode byte string: " +
                           std::string(cbor_error_string(err)));
    }

    return result;
}

void ZCBORDecoder::decodeBytes(uint8_t* buffer, size_t* len) {
    if (!isBytes()) {
        throw ZCBORException("Expected byte string");
    }

    CborError err = cbor_value_copy_byte_string(&value_, buffer, len, &value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to decode byte string: " +
                           std::string(cbor_error_string(err)));
    }
}

std::string ZCBORDecoder::decodeText() {
    if (!isText()) {
        throw ZCBORException("Expected text string");
    }

    // Get length first
    size_t len;
    CborError err = cbor_value_get_string_length(&value_, &len);
    if (err != CborNoError) {
        throw ZCBORException("Failed to get text string length: " +
                           std::string(cbor_error_string(err)));
    }

    // Allocate buffer and read data
    std::vector<char> buffer(len + 1);
    err = cbor_value_copy_text_string(&value_, buffer.data(), &len, &value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to decode text string: " +
                           std::string(cbor_error_string(err)));
    }
    buffer[len] = '\0';

    return std::string(buffer.data());
}

bool ZCBORDecoder::decodeBool() {
    if (!isBool()) {
        throw ZCBORException("Expected boolean");
    }
    bool value;
    CborError err = cbor_value_get_boolean(&value_, &value);
    if (err != CborNoError) {
        throw ZCBORException("Failed to decode boolean: " +
                           std::string(cbor_error_string(err)));
    }
    err = cbor_value_advance(&value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to advance after boolean: " +
                           std::string(cbor_error_string(err)));
    }
    return value;
}

void ZCBORDecoder::decodeNull() {
    if (!isNull()) {
        throw ZCBORException("Expected null");
    }
    CborError err = cbor_value_advance(&value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to advance after null: " +
                           std::string(cbor_error_string(err)));
    }
}

void ZCBORDecoder::decodeUndefined() {
    if (!isUndefined()) {
        throw ZCBORException("Expected undefined");
    }
    CborError err = cbor_value_advance(&value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to advance after undefined: " +
                           std::string(cbor_error_string(err)));
    }
}

// Container decoding methods

size_t ZCBORDecoder::enterMap() {
    if (!isMap()) {
        throw ZCBORException("Expected map");
    }
    size_t length;
    CborError err = cbor_value_get_map_length(&value_, &length);
    if (err != CborNoError) {
        throw ZCBORException("Failed to get map length: " +
                           std::string(cbor_error_string(err)));
    }

    CborValue contents;
    err = cbor_value_enter_container(&value_, &contents);
    if (err != CborNoError) {
        throw ZCBORException("Failed to enter map: " +
                           std::string(cbor_error_string(err)));
    }
    value_ = contents;

    return length;
}

void ZCBORDecoder::exitMap() {
    // Note: tinycbor requires parent value to exit container
    // This is a simplified implementation
    CborError err = cbor_value_advance(&value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to exit map: " +
                           std::string(cbor_error_string(err)));
    }
}

size_t ZCBORDecoder::enterArray() {
    if (!isArray()) {
        throw ZCBORException("Expected array");
    }
    size_t length;
    CborError err = cbor_value_get_array_length(&value_, &length);
    if (err != CborNoError) {
        throw ZCBORException("Failed to get array length: " +
                           std::string(cbor_error_string(err)));
    }

    CborValue contents;
    err = cbor_value_enter_container(&value_, &contents);
    if (err != CborNoError) {
        throw ZCBORException("Failed to enter array: " +
                           std::string(cbor_error_string(err)));
    }
    value_ = contents;

    return length;
}

void ZCBORDecoder::exitArray() {
    // Note: tinycbor requires parent value to exit container
    // This is a simplified implementation
    CborError err = cbor_value_advance(&value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to exit array: " +
                           std::string(cbor_error_string(err)));
    }
}

uint64_t ZCBORDecoder::decodeTag() {
    if (!isTag()) {
        throw ZCBORException("Expected tag");
    }
    CborTag tag;
    CborError err = cbor_value_get_tag(&value_, &tag);
    if (err != CborNoError) {
        throw ZCBORException("Failed to decode tag: " +
                           std::string(cbor_error_string(err)));
    }
    return (uint64_t)tag;
}

uint64_t ZCBORDecoder::decodeTagAndEnter() {
    uint64_t tag = decodeTag();
    CborError err = cbor_value_advance(&value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to advance after tag: " +
                           std::string(cbor_error_string(err)));
    }
    return tag;
}

void ZCBORDecoder::advance() {
    CborError err = cbor_value_advance(&value_);
    if (err != CborNoError) {
        throw ZCBORException("Failed to advance: " +
                           std::string(cbor_error_string(err)));
    }
}

// Map decoding helpers

uint64_t ZCBORDecoder::decodeMapKeyUInt() {
    return decodeUInt();
}

std::string ZCBORDecoder::decodeMapKeyText() {
    return decodeText();
}

// Static helper methods

std::string ZCBORDecoder::getErrorString(CborError err) {
    return std::string(cbor_error_string(err));
}

void ZCBORDecoder::verifySortedMapKeys(const CborValue* map) {
    // TODO: Implement map key sorting verification
    // This requires iterating through the map and checking that
    // integer keys are in ascending order
}

void ZCBORDecoder::validateCanonical(const CborValue* val) {
    // TODO: Implement canonical encoding validation
    // This would check:
    // 1. Shortest form encoding for all types
    // 2. Definite-length encoding (no indefinite lengths)
    // 3. Sorted integer keys for maps
    // 4. UTF-8 validity for strings
}

} // namespace oabe
