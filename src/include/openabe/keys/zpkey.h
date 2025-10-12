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
/// \file   zpkey.h
///
/// \brief  Data structures for storing and manipulating ECDSA
///         signing and verification keys.
///
/// \author J. Ayo Akinyele
///

#ifndef __ZPKEY_H__
#define __ZPKEY_H__

#include <openabe/zml/zecdsa.h>

namespace oabe {

class OpenABEPKey: public OpenABEKey {
private:
  bool isPrivate;
  ecdsa_keypair_t keypair;
  uint8_t curve_id;

public:
  OpenABEPKey(bool isPrivate, uint8_t curve_id);
  OpenABEPKey(ecdsa_keypair_t kp, bool isPrivate, uint8_t curve_id);
  ~OpenABEPKey();

  ecdsa_keypair_t getECDSAKeypair() { return this->keypair; }
  bool hasPrivateKey() const { return this->isPrivate; }
  uint8_t getCurveID() const { return this->curve_id; }

  // pkeyToString (does export)
  OpenABE_ERROR exportKeyToBytes(OpenABEByteString &output);
  // stringToPkey (does import)
  OpenABE_ERROR loadKeyFromBytes(OpenABEByteString &input);
};

}

#endif // __ZPKEY_H__
