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
/// \file       zcrypto_box.cpp
///
/// \brief      Thin wrappers for PKE and ABE scheme contexts.
///
/// \author     J. Ayo Akinyele
///

#include <sstream>
#include <stdexcept>
#include <cassert>
#include <openabe/openabe.h>

#include <openssl/pem.h>
#include <openssl/evp.h>

using namespace std;

namespace oabe {

static const char MASTER_PUBLIC_PARAMS[] = "mpk";
static const char MASTER_SECRET_PARAMS[] = "msk";

static const char PUBLIC_ID[] = "public_";
static const char PRIVATE_ID[] = "private_";

#define OpenABE_PK_PREFIX(a) PUBLIC_ID + a
#define OpenABE_SK_PREFIX(a) PRIVATE_ID + a

OpenABECryptoContext::OpenABECryptoContext(const std::string scheme_id, bool base64encode) {
  scheme_type_ = OpenABE_convertStringToSchemeID(scheme_id);
  if (scheme_type_ == OpenABE_SCHEME_NONE) {
    throw ZCryptoBoxException("Invalid input: unrecognized scheme ID");
  }

  schemeContextCCA_ = OpenABE_createContextABESchemeCCA(scheme_type_);
  if (!schemeContextCCA_) {
    throw ZCryptoBoxException("Unable to create ABE scheme context");
  }

  if (scheme_type_ == OpenABE_SCHEME_CP_WATERS) {
    keyInputType_ = FUNC_ATTRLIST_INPUT;
    encInputType_ = FUNC_POLICY_INPUT;
  } else {
    // OpenABE_SCHEME_KP_GPSW
    keyInputType_ = FUNC_POLICY_INPUT;
    encInputType_ = FUNC_ATTRLIST_INPUT;
  }
  // whether to base-64 encode
  base64Encode_ = base64encode;
  keyManager_.reset(new OpenABEKeystoreManager);
  useKeyManager_ = false;
  debug_ = false;
}

void OpenABECryptoContext::generateParams() {
    schemeContextCCA_->generateParams(DEFAULT_BP_PARAM, MASTER_PUBLIC_PARAMS,
                                      MASTER_SECRET_PARAMS);
}

void OpenABECryptoContext::enableKeyManager(const std::string userId) {
    userId_ = userId;
    useKeyManager_ = true;
}

void OpenABECryptoContext::enableVerbose() {
    debug_ = true;
}

void OpenABECryptoContext::keygen(const std::string &keyInput, const std::string &keyID,
                                  const std::string &authID, const std::string &GID) {
  unique_ptr<OpenABEFunctionInput> keyFuncInput = nullptr;
  if (keyInputType_ == FUNC_POLICY_INPUT) {
    keyFuncInput = createPolicyTree(keyInput);
  } else {
    keyFuncInput = createAttributeList(keyInput);
  }

  string mpkID = MASTER_PUBLIC_PARAMS, mskID = MASTER_SECRET_PARAMS, gpkID = "";
  if (keyFuncInput != nullptr) {
    OpenABE_ERROR result = schemeContextCCA_->keygen(keyFuncInput.get(), keyID,
                                                 mpkID, mskID, gpkID, GID);
    if (result != OpenABE_NOERROR) {
      throw ZCryptoBoxException(OpenABE_errorToString(result));
    }
  } else {
    throw ZCryptoBoxException("Invalid functional input for ABE key");
  }
}

void OpenABECryptoContext::exportPublicParams(string &mpk) {
  return exportUserKey(MASTER_PUBLIC_PARAMS, mpk);
}

void OpenABECryptoContext::exportSecretParams(string &msk) {
  return exportUserKey(MASTER_SECRET_PARAMS, msk);
}

void OpenABECryptoContext::exportUserKey(const string &keyID, string &keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString key;
  if ((result = this->schemeContextCCA_->exportKey(keyID, key)) !=
      OpenABE_NOERROR) {
    throw ZCryptoBoxException(OpenABE_errorToString(result));
  }

  keyBlob = key.toString();
  if (base64Encode_)
    keyBlob = Base64Encode((const uint8_t *)keyBlob.c_str(), keyBlob.size());
}

void OpenABECryptoContext::importPublicParams(const std::string &keyBlob) {
  importPublicParams(MASTER_PUBLIC_PARAMS, keyBlob);
}

void OpenABECryptoContext::importPublicParams(const std::string &authID,
                                    const std::string &keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString key;
  if (base64Encode_)
    key += Base64Decode(keyBlob);
  else
    key += keyBlob;

  string keyID = authID;
  result = schemeContextCCA_->loadMasterPublicParams(keyID, key);
  if (result != OpenABE_NOERROR) {
    throw ZCryptoBoxException(OpenABE_errorToString(result));
  }
}

void OpenABECryptoContext::importSecretParams(const std::string &keyBlob) {
  this->importSecretParams(MASTER_SECRET_PARAMS, keyBlob);
}

void OpenABECryptoContext::importSecretParams(const std::string &authID,
                                    const std::string &keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString key;
  if (base64Encode_)
    key += Base64Decode(keyBlob);
  else
    key += keyBlob;

  string keyID = "";
  keyID = authID;

  result = schemeContextCCA_->loadMasterSecretParams(keyID, key);
  if (result != OpenABE_NOERROR) {
    throw ZCryptoBoxException(OpenABE_errorToString(result));
  }
}

void OpenABECryptoContext::importUserKey(const std::string& keyID, const std::string& keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString key;
  if (base64Encode_)
    key += Base64Decode(keyBlob);
  else
    key += keyBlob;

  if (!useKeyManager_)
      result = schemeContextCCA_->loadUserSecretParams(keyID, key);
  else
      keyManager_->storeWithKeyIDCommand(userId_, keyID, key, 0);

  if (result != OpenABE_NOERROR) {
    throw ZCryptoBoxException(OpenABE_errorToString(result));
  }
}

bool OpenABECryptoContext::deleteKey(const std::string &keyID) {
  return (this->schemeContextCCA_->deleteKey(keyID) == OpenABE_NOERROR);
}

void OpenABECryptoContext::encrypt(const std::string encInput,
                         const std::string &plaintext,
                         std::string &ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  unique_ptr<OpenABECiphertext> ciphertext1 = nullptr, ciphertext2 = nullptr;
  unique_ptr<OpenABEFunctionInput> funcInput = nullptr;

  try {
    OpenABEByteString ct1, ct2, combined;

    if (encInputType_ == FUNC_POLICY_INPUT) {
      funcInput = createPolicyTree(encInput);
    } else {
      funcInput = createAttributeList(encInput);
    }

    if (!funcInput) {
      throw ZCryptoBoxException(OpenABE_errorToString(OpenABE_ERROR_INVALID_INPUT));
    }

    ciphertext1.reset(new OpenABECiphertext);
    ciphertext2.reset(new OpenABECiphertext);

    string mpkID = MASTER_PUBLIC_PARAMS;
    // now we can encrypt
    if ((result = schemeContextCCA_->encrypt(
             mpkID, funcInput.get(), plaintext, ciphertext1.get(),
             ciphertext2.get())) != OpenABE_NOERROR) {
      throw ZCryptoBoxException(OpenABE_errorToString(result));
    }

    // serialize the results
    ciphertext1->exportToBytes(ct1);
    ciphertext2->exportToBytes(ct2);

    // write back to user
    combined.pack(ct1);
    combined.pack(ct2);
    if (base64Encode_) {
      const string ct = combined.toString();
      ciphertext = Base64Encode((const uint8_t *)ct.data(), ct.size());
    } else {
      ciphertext = combined.toString();
    }
  } catch (OpenABE_ERROR &error) {
    if (debug_)
      cerr << "OpenABECryptoContext::encrypt: " << OpenABE_errorToString(error) << endl;
    throw ZCryptoBoxException(OpenABE_errorToString(error));
  }
}

bool OpenABECryptoContext::decrypt(const std::string &keyID,
                         const std::string &ciphertext,
                         std::string &plaintext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  unique_ptr<OpenABECiphertext> ciphertext1 = nullptr, ciphertext2 = nullptr;

  try {
    string pt;
    OpenABEByteString ct, ct1, ct2;
    if (base64Encode_) {
      // base64 decode ...
      string ct_bin = Base64Decode(ciphertext);
      ct += ct_bin;
    } else {
      ct += ciphertext;
    }
    size_t index = 0;
    ct.unpack(&index, ct1);
    ct.unpack(&index, ct2);

    ciphertext1.reset(new OpenABECiphertext);
    ciphertext2.reset(new OpenABECiphertext);

    ciphertext1->loadFromBytes(ct1);
    ciphertext2->loadFromBytes(ct2);

    string mpkID = MASTER_PUBLIC_PARAMS;
    // can now decrypt
    if ((result = schemeContextCCA_->decrypt(
             mpkID, keyID, plaintext, ciphertext1.get(), ciphertext2.get())) !=
        OpenABE_NOERROR) {
      return result;
    }
    return true;
  } catch (OpenABE_ERROR &error) {
    if (debug_)
      cerr << "OpenABECryptoContext::decrypt: " << OpenABE_errorToString(error) << endl;
  }
  return false;
}

bool OpenABECryptoContext::decrypt(const std::string &ciphertext,
                                   std::string &plaintext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEKeyQuery query;
  unique_ptr<OpenABECiphertext> ciphertext1 = nullptr, ciphertext2 = nullptr;
  if (!useKeyManager_) {
    throw ZCryptoBoxException("Key Manager not enabled!");
  }

  try {
    string pt;
    OpenABEByteString ct, ct1, ct2;
    if (base64Encode_) {
      // base64 decode ...
      string ct_bin = Base64Decode(ciphertext);
      ct += ct_bin;
    } else {
      ct += ciphertext;
    }
    size_t index = 0;
    ct.unpack(&index, ct1);
    ct.unpack(&index, ct2);

    ciphertext1.reset(new OpenABECiphertext);
    ciphertext2.reset(new OpenABECiphertext);

    ciphertext1->loadFromBytes(ct1);
    ciphertext2->loadFromBytes(ct2);

    string mpkID = MASTER_PUBLIC_PARAMS;

    query.userId = userId_;
    query.isEfficient = true;

    unique_ptr<OpenABEFunctionInput> funcInput = getFunctionInput(ciphertext1.get());
    const string decKeyId = keyManager_->searchKeyCommand(&query, funcInput.get());
    if (decKeyId == "") {
        throw ZCryptoBoxException("Key Manager could not find an appropriate key to decrypt!");
    }

    // load key in the scheme context
    pair<string,OpenABEByteString> sk = keyManager_->getKeyCommand(userId_, decKeyId);
    if (debug_) { cout << "Found Key: '" << decKeyId << "' => '" << sk.first << "'" << endl; }
    if ((result = schemeContextCCA_->loadUserSecretParams(decKeyId, sk.second)) != OpenABE_NOERROR) {
        return result;
    }

    // can now decrypt
    if ((result = schemeContextCCA_->decrypt(
             mpkID, decKeyId, plaintext, ciphertext1.get(), ciphertext2.get())) !=
        OpenABE_NOERROR) {
      return result;
    }
    return true;
  } catch (OpenABE_ERROR &error) {
    if (debug_)
      cerr << "OpenABECryptoContext::decrypt: " << OpenABE_errorToString(error) << endl;
  }
  return false;
}


}
