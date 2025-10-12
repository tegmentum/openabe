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
/// \file   zcontextpksig.cpp
///
/// \brief  Implementation for OpenABE context PKSIG schemes.
///
/// \author J. Ayo Akinyele
///
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEContextPKSIG class
 ********************************************************************************/
namespace oabe {

// Helper function to map curve name strings to curve IDs
static uint8_t getCurveID(const std::string &groupParams) {
    if (groupParams == "NIST_P256" || groupParams == "secp256r1" || groupParams == "prime256v1") {
        return OpenABE_NIST_P256_ID;
    } else if (groupParams == "NIST_P384" || groupParams == "secp384r1") {
        return OpenABE_NIST_P384_ID;
    } else if (groupParams == "NIST_P521" || groupParams == "secp521r1") {
        return OpenABE_NIST_P521_ID;
    } else if (groupParams == "secp256k1") {
        // MCL secp256k1 - map to P256 ID for now
        // The actual backend selection is done by compile-time flags
        return OpenABE_NIST_P256_ID;
    }

    // Default to P256
    return OpenABE_NIST_P256_ID;
}

/*!
 * Constructor for the OpenABEContextPKSIG base class.
 *
 */
OpenABEContextPKSIG::OpenABEContextPKSIG(): OpenABEContext() {
    this->ecdsa_ctx = nullptr;
    this->curve_id = OpenABE_NIST_P256_ID;  // Default
}

/*!
 * Destructor for the OpenABEContextPKSIG base class.
 *
 */
OpenABEContextPKSIG::~OpenABEContextPKSIG() {
    if(this->ecdsa_ctx != nullptr) {
        ecdsa_context_free(this->ecdsa_ctx);
    }
}

OpenABE_ERROR
OpenABEContextPKSIG::initializeCurve(const std::string groupParams) {
    try {
        if(this->ecdsa_ctx == nullptr) {
            this->curve_id = getCurveID(groupParams);

            int ret = ecdsa_context_init(&this->ecdsa_ctx, this->curve_id);
            if (ret != 0) {
                throw OpenABE_ERROR_INVALID_GROUP_PARAMS;
            }

            ASSERT_NOTNULL(this->ecdsa_ctx);
        }
    } catch(OpenABE_ERROR& error) {
        return error;
    }

    return OpenABE_NOERROR;
}

OpenABE_ERROR
OpenABEContextPKSIG::generateParams(const std::string groupParams) {
    OpenABE_ERROR result  = OpenABE_NOERROR;

    try {
        // Initialize the curve context (if not already)
        this->initializeCurve(groupParams);
    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextPKSIG::keygen(const std::string &pkID, const std::string &skID) {
    OpenABE_ERROR result   = OpenABE_NOERROR;
    ecdsa_keypair_t keypair = nullptr;
    shared_ptr<OpenABEPKey> pubKey = nullptr, privKey = nullptr;

    try {
        ASSERT_NOTNULL(this->ecdsa_ctx);

        // Generate ECDSA keypair using the abstraction layer
        int ret = ecdsa_keygen(this->ecdsa_ctx, &keypair);
        if (ret != 0) {
            throw OpenABE_ERROR_KEYGEN_FAILED;
        }

        // Create separate OpenABEPKey objects for public and private keys
        // Note: We need to duplicate the keypair for the public key since
        // we'll be creating two separate OpenABEPKey objects

        // For the public key, we export and re-import to create a public-only keypair
        uint8_t pub_buf[2048];
        size_t pub_len = ecdsa_export_public_key(keypair, pub_buf, sizeof(pub_buf));
        if (pub_len == 0) {
            throw OpenABE_ERROR_KEYGEN_FAILED;
        }

        ecdsa_keypair_t pub_keypair = nullptr;
        ret = ecdsa_import_public_key(this->ecdsa_ctx, &pub_keypair, pub_buf, pub_len);
        if (ret != 0) {
            throw OpenABE_ERROR_KEYGEN_FAILED;
        }

        // Create the OpenABEPKey objects
        pubKey.reset(new OpenABEPKey(pub_keypair, false, this->curve_id));
        privKey.reset(new OpenABEPKey(keypair, true, this->curve_id));

        // Add the keys to the keystore
        this->getKeystore()->addKey(pkID, pubKey,  KEY_TYPE_PUBLIC);
        this->getKeystore()->addKey(skID, privKey, KEY_TYPE_SECRET);

    } catch(OpenABE_ERROR& error) {
        result = error;
        if (keypair != nullptr) {
            ecdsa_keypair_free(keypair);
        }
    }

    return result;
}


OpenABE_ERROR
OpenABEContextPKSIG::sign(OpenABEPKey *privKey, OpenABEByteString *message, OpenABEByteString *signature) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    uint8_t sig_buf[512];  // Should be large enough for any supported curve
    size_t sig_len = 0;

    try {
        ASSERT_NOTNULL(privKey);
        ASSERT_NOTNULL(message);
        ASSERT_NOTNULL(signature);

        ecdsa_keypair_t keypair = privKey->getECDSAKeypair();
        ASSERT_NOTNULL(keypair);

        // Sign the message using the ECDSA abstraction
        sig_len = ecdsa_sign(keypair,
                             message->getInternalPtr(), message->size(),
                             sig_buf, sizeof(sig_buf));

        if (sig_len == 0) {
            throw OpenABE_ERROR_SIGNATURE_FAILED;
        }

        // Return signature as a OpenABEByteString
        signature->clear();
        signature->appendArray(sig_buf, sig_len);

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextPKSIG::verify(OpenABEPKey *pubKey, OpenABEByteString *message, OpenABEByteString *signature) {
    OpenABE_ERROR result = OpenABE_NOERROR;

    try {
        ASSERT_NOTNULL(pubKey);
        ASSERT_NOTNULL(message);
        ASSERT_NOTNULL(signature);

        ecdsa_keypair_t keypair = pubKey->getECDSAKeypair();
        ASSERT_NOTNULL(keypair);

        // Verify the signature using the ECDSA abstraction
        int ret = ecdsa_verify(keypair,
                               message->getInternalPtr(), message->size(),
                               signature->getInternalPtr(), signature->size());

        if (ret != 1) {
            throw OpenABE_ERROR_VERIFICATION_FAILED;
        }

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

bool
OpenABEContextPKSIG::validateKeypair(ecdsa_keypair_t keypair, bool expectPrivate) {
    if (!keypair) {
        return false;
    }

    // Check if the keypair has a private key component
    bool hasPrivate = (ecdsa_has_private_key(keypair) == 1);

    return (hasPrivate == expectPrivate);
}

bool
OpenABEContextPKSIG::validatePublicKey(const shared_ptr<OpenABEPKey>& key) {
    ASSERT_NOTNULL(key);
    return this->validateKeypair(key->getECDSAKeypair(), false);
}


bool
OpenABEContextPKSIG::validatePrivateKey(const std::shared_ptr<OpenABEPKey>& key) {
    ASSERT_NOTNULL(key);
    return this->validateKeypair(key->getECDSAKeypair(), true);
}


/********************************************************************************
 * Implementation of the OpenABEContextSchemePKSIG class
 ********************************************************************************/

OpenABEContextSchemePKSIG::OpenABEContextSchemePKSIG(unique_ptr<OpenABEContextPKSIG> pksig): ZObject() {
    m_PKSIG = std::move(pksig);
}

OpenABEContextSchemePKSIG::~OpenABEContextSchemePKSIG() {
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::exportKey(const string &keyID, OpenABEByteString &keyBlob) {
    OpenABE_ERROR result = OpenABE_NOERROR;

    try {
        // attempt to export the given keyID to a temp keyBlob output buffer (without a header)
        shared_ptr<OpenABEKey> key = this->m_PKSIG->getKeystore()->getKey(keyID);
        if(key == nullptr) {
            throw OpenABE_ERROR_INVALID_INPUT;
        }

        // convert to pkey
        shared_ptr<OpenABEPKey> pkey = static_pointer_cast<OpenABEPKey>(key);
        ASSERT_NOTNULL(pkey);
        // export key to bytes
        pkey->exportKeyToBytes(keyBlob);
    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::loadPrivateKey(const std::string &keyID, OpenABEByteString &keyBlob) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    shared_ptr<OpenABEPKey> SK = nullptr;
    bool isPrivate = true;

    try {
        if (keyBlob.size() < 2) {
            throw OpenABE_ERROR_INVALID_INPUT;
        }

        // First byte contains the curve_id
        uint8_t curve_id = keyBlob.at(0);

        // Now we can deserialize the key directly
        SK.reset(new OpenABEPKey(isPrivate, curve_id));
        SK->loadKeyFromBytes(keyBlob);

        if(this->m_PKSIG->validatePrivateKey(SK)) {
            // if validation successful, then add to the keystore
            this->m_PKSIG->getKeystore()->addKey(keyID, SK, KEY_TYPE_SECRET);
        }
        else {
            throw OpenABE_ERROR_INVALID_PARAMS;
        }

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::loadPublicKey(const std::string &keyID, OpenABEByteString &keyBlob) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    shared_ptr<OpenABEPKey> PK = nullptr;
    bool isPrivate = false;

    try {
        if (keyBlob.size() < 2) {
            throw OpenABE_ERROR_INVALID_INPUT;
        }

        // First byte contains the curve_id
        uint8_t curve_id = keyBlob.at(0);

        // Now we can deserialize the key directly
        PK.reset(new OpenABEPKey(isPrivate, curve_id));
        PK->loadKeyFromBytes(keyBlob);

        if(this->m_PKSIG->validatePublicKey(PK)) {
            // if validation successful, then add to the keystore
            this->m_PKSIG->getKeystore()->addKey(keyID, PK, KEY_TYPE_PUBLIC);
        }
        else {
            throw OpenABE_ERROR_INVALID_PARAMS;
        }

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::deleteKey(const string &keyID) {
    return this->m_PKSIG->getKeystore()->deleteKey(keyID);
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::generateParams(const std::string groupParams) {
    return this->m_PKSIG->generateParams(groupParams);
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::keygen(const std::string &pkID, const std::string &skID) {
    return this->m_PKSIG->keygen(pkID, skID);
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::sign(const std::string &skID, OpenABEByteString *message, OpenABEByteString *signature) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    shared_ptr<OpenABEPKey> SK = nullptr;

    try {
        ASSERT_NOTNULL(message);
        ASSERT_NOTNULL(signature);

        // load the secret key from the keystore
        SK = static_pointer_cast<OpenABEPKey>(this->m_PKSIG->getKeystore()->getSecretKey(skID));
        ASSERT_NOTNULL(SK);

        // sign the message with the key that was just loaded
        result = this->m_PKSIG->sign(SK.get(), message, signature);
        ASSERT(result == OpenABE_NOERROR, result);

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::verify(const std::string &pkID, OpenABEByteString *message, OpenABEByteString *signature) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    shared_ptr<OpenABEPKey> PK = nullptr;

    try {
        ASSERT_NOTNULL(message);
        ASSERT_NOTNULL(signature);

        // load the public key from the keystore
        PK = static_pointer_cast<OpenABEPKey>(this->m_PKSIG->getKeystore()->getPublicKey(pkID));
        ASSERT_NOTNULL(PK);

        // verify the message and signature against a verification key
        result = this->m_PKSIG->verify(PK.get(), message, signature);

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

}
