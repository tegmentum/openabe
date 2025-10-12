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
/// \file   zpkey.cpp
///
/// \brief  Implementation for storing OpenABE keys for PKSIG schemes.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEPKey class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEPKey class (for loading keys from serialized form).
 *
 */
OpenABEPKey::OpenABEPKey(bool isPrivate, uint8_t curve_id) : OpenABEKey() {
  this->keypair = nullptr;
  this->isPrivate = isPrivate;
  this->curve_id = curve_id;
}

/*!
 * Constructor for the OpenABEPKey class (wraps an existing keypair).
 *
 */
OpenABEPKey::OpenABEPKey(ecdsa_keypair_t kp, bool isPrivate, uint8_t curve_id)
    : OpenABEKey() {
  this->keypair = kp;
  this->isPrivate = isPrivate;
  this->curve_id = curve_id;
}

/*!
 * Destructor for the OpenABEPKey class.
 *
 */
OpenABEPKey::~OpenABEPKey() {
  if (this->keypair != nullptr) {
    ecdsa_keypair_free(this->keypair);
  }
}


OpenABE_ERROR
OpenABEPKey::exportKeyToBytes(OpenABEByteString &output) {
  OpenABE_ERROR result = OpenABE_ERROR_INVALID_INPUT;
  uint8_t buffer[2048];  // Should be large enough for any supported curve
  size_t written = 0;

  if (this->keypair == nullptr) {
    return OpenABE_ERROR_INVALID_INPUT;
  }

  if (this->isPrivate) {
    // Export private key
    written = ecdsa_export_private_key(this->keypair, buffer, sizeof(buffer));
  } else {
    // Export public key
    written = ecdsa_export_public_key(this->keypair, buffer, sizeof(buffer));
  }

  if (written == 0) {
    return OpenABE_ERROR_SERIALIZATION_FAILED;
  }

  // Store the curve_id as the first byte, followed by the key data
  output.clear();
  output.push_back(this->curve_id);
  output.appendArray(buffer, written);

  result = OpenABE_NOERROR;
  return result;
}

OpenABE_ERROR
OpenABEPKey::loadKeyFromBytes(OpenABEByteString &input) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  ecdsa_context_t temp_ctx = nullptr;
  int ret;

  if (input.size() < 2) {
    return OpenABE_ERROR_INVALID_INPUT;
  }

  // First byte is the curve_id
  this->curve_id = input.at(0);

  // Initialize temporary context for the curve
  ret = ecdsa_context_init(&temp_ctx, this->curve_id);
  if (ret != 0) {
    result = OpenABE_ERROR_INVALID_PARAMS;
    goto out;
  }

  // Clean up existing keypair if any
  if (this->keypair != nullptr) {
    ecdsa_keypair_free(this->keypair);
    this->keypair = nullptr;
  }

  // Import key from remaining bytes
  if (this->isPrivate) {
    ret = ecdsa_import_private_key(temp_ctx, &this->keypair,
                                    input.getInternalPtr() + 1, input.size() - 1);
  } else {
    ret = ecdsa_import_public_key(temp_ctx, &this->keypair,
                                   input.getInternalPtr() + 1, input.size() - 1);
  }

  if (ret != 0 || this->keypair == nullptr) {
    result = OpenABE_ERROR_DESERIALIZATION_FAILED;
    goto out;
  }

out:
  if (temp_ctx != nullptr) {
    ecdsa_context_free(temp_ctx);
  }

  return result;
}

}
