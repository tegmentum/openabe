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
/// \file   zcontextcpwaters.cpp
///
/// \brief  Implementation of the Waters '11 CP-ABE scheme.
///
/// \source http://eprint.iacr.org/2008/290.pdf (Appendix A -- Large Universe Construction)
///
/// \author J. Ayo Akinyele
///

#define __ZCONTEXTCPWATERS_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>
#include <openabe/utils/zcryptoutils.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEContextCPWaters class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEContextCPWaters class.
 *
 */
OpenABEContextCPWaters::OpenABEContextCPWaters(unique_ptr<OpenABERNG> rng)
    : OpenABEContextABE() {
  this->debug = false;
  // KEM context will take ownership of the given RNG
  this->m_RNG_ = std::move(rng);
  this->algID = OpenABE_SCHEME_CP_WATERS;
}

/*!
 * Destructor for the OpenABEContextCPWaters class.
 *
 */
OpenABEContextCPWaters::~OpenABEContextCPWaters() {}

/*!
 * Generate scheme public and private parameters for the Waters '11 CP-ABE
 * scheme. This function takes in a specific set of pairing parameters.
 *
 * @param[in] pairingParams     - Identifier for the pairing parameters.
 * @param[in] mpkID             - Identifier to use for the new Master Public Key
 * @param[in] mskID             - Identifier to use for the new Master Secret Key
 * @return                      - An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextCPWaters::generateParams(const string pairingParams,
                                   const string &mpkID, const string &mskID) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> MPK = nullptr, MSK = nullptr;
  OpenABERNG *myRNG = this->getRNG();
  OpenABEByteString k;

  try {
    // Instantiate a OpenABE pairing object with the given parameters
    this->initializeCurve(pairingParams);

    // Make sure these parameter IDs are valid and not already in use
    if (this->getKeystore()->validateNewParamsID(mpkID) == false ||
        this->getKeystore()->validateNewParamsID(mskID) == false) {
      throw OpenABE_ERROR_INVALID_PARAMS_ID;
    }

    // Initialize the elements of the public and secret parameters
    MPK.reset(new OpenABEKey(this->getPairing()->getCurveID(), this->algID, mpkID));
    MSK.reset(new OpenABEKey(this->getPairing()->getCurveID(), this->algID, mskID));

    // Select random generators g1 \in G1, g2 \in G2
    G1 g1 = this->getPairing()->randomG1(myRNG);
    G2 g2 = this->getPairing()->randomG2(myRNG);
    // Select two random elements (a, \alpha) \in ZP
    ZP alpha = this->getPairing()->randomZP(myRNG);
    ZP a = this->getPairing()->randomZP(myRNG);
    // key prefix for hash function
    myRNG->getRandomBytes(&k, HASH_LEN);

    // Compute g1^a, g2^a
    G1 g1a = g1.exp(a);
    G2 g2a = g2.exp(a);

    // Compute g2^alpha (for WASM-compatible encryption)
    G2 g2alpha = g2.exp(alpha);

    // Compute A = e(g1, g2)^\alpha
    GT A = this->getPairing()->pairing(g1, g2).exp(alpha);

    // Add (g1, g2, g1a, g2alpha) to the public params
    MPK->setComponent("g1", &g1);
    MPK->setComponent("g2", &g2);
    MPK->setComponent("g1a", &g1a);
    MPK->setComponent("g2alpha", &g2alpha);  // Added for WASM-compatible encryption
    MPK->setComponent("A", &A);
    MPK->setComponent("k", &k);

    // Add (\alpha and g2a) to the secret params
    MSK->setComponent("alpha", &alpha);
    MSK->setComponent("g2a", &g2a);

    // Add (MPK, MSK) to the keystore
    this->getKeystore()->addKey(mpkID, MPK, KEY_TYPE_PUBLIC);
    this->getKeystore()->addKey(mskID, MSK, KEY_TYPE_SECRET);

  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}


/*!
 * Generate a decryption key for a given function input. This function
 * requires that the master secret parameters are available.
 *
 * @param[in] mpkID     - parameter ID of the Master Public Key
 * @param[in] mskID     - parameter ID of the Master Secret Key
 * @param[in] keyID     - parameter ID of the decryption key to be created
 * @param[in] keyInput  - A OpenABEAttributeList structure for the key to be constructed
 * @return              - An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextCPWaters::generateDecryptionKey(
    OpenABEFunctionInput *keyInput, const string &keyID, const string &mpkID,
    const string &mskID, const string &gpkID = "", const string &GID = "") {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> decKey = nullptr;
  OpenABEAttributeList *attrList = nullptr;
  OpenABERNG *myRNG = this->getRNG();
  OpenABEByteString *k = nullptr;

  try {
    // Ensure that the given input is a OpenABEAttributeList
    if ((attrList = dynamic_cast<OpenABEAttributeList *>(keyInput)) == nullptr) {
      OpenABE_LOG_AND_THROW("Decryption key input must be an Attribute List",
                        OpenABE_ERROR_INVALID_INPUT);
    }

    // Load the master secret and public key
    shared_ptr<OpenABEKey> MPK = this->getKeystore()->getPublicKey(mpkID);
    shared_ptr<OpenABEKey> MSK = this->getKeystore()->getSecretKey(mskID);
    if (MPK == nullptr || MSK == nullptr) {
      throw OpenABE_ERROR_INVALID_PARAMS;
    }
    // retrieve the hash function key prefix
    k = MPK->getByteString("k");
    // Create a new OpenABEKey object for the decryption key
    decKey.reset(
        new OpenABEKey(this->getPairing()->getCurveID(), this->algID, keyID));

    // Add the attribute list to the key
    decKey->setComponent("input", attrList);

    // Select a random element t \in ZP
    ZP t = this->getPairing()->randomZP(myRNG);
    ZP alpha = *(MSK->getZP("alpha"));

    // K = g2^\alpha * (g2^{a})^t
    G2 K = (MPK->getG2("g2")->exp(alpha)) * (MSK->getG2("g2a")->exp(t));
    decKey->setComponent("K", &K);

    // L = g2^t
    G2 L = MPK->getG2("g2")->exp(t);
    decKey->setComponent("L", &L);

    // For each attribute in the attribute list
    string attr, attr_deckey;
    const vector<string> *attrStrings = attrList->getAttributeList();
    for (auto it = attrStrings->begin(); it != attrStrings->end(); ++it) {
      // Compute KX_{attribute} = hash_to_G1(attribute)^t
      attr = *it;
      G1 kx = this->getPairing()->hashToG1(*k, attr).exp(t);
      attr_deckey = OpenABEHashKey(attr);
      decKey->setComponent(OpenABEMakeElementLabel("KX", attr_deckey), &kx);
    }

    // Add the decryption key to the keystore
    this->getKeystore()->addKey(keyID, decKey, KEY_TYPE_SECRET);

  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/*!
 * Generate and encrypt a symmetric key using the key encapsulation mode
 * of the scheme. Return the key and ciphertext.
 *
 * @param   Parameters ID for the public master parameters.
 * @param   Function input for the encryption.
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextCPWaters::encryptKEM(OpenABERNG *rng, const string &mpkID,
                               const OpenABEFunctionInput *encryptInput,
                               uint32_t keyByteLen,
                               const std::shared_ptr<OpenABESymKey> &key,
                               OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABERNG *myRNG = this->getRNG();
  OpenABEByteString *k = nullptr;

  try {
    ASSERT_NOTNULL(key);
    ASSERT_NOTNULL(ciphertext);

    if (rng != nullptr) {
      // use the passed in RNG
      myRNG = rng;
    }
    // Assert that the RNG has been set
    ASSERT_NOTNULL(myRNG);

    // Ensure that the given input is a OpenABEPolicy
    const OpenABEPolicy *policy = dynamic_cast<const OpenABEPolicy *>(encryptInput);
    if (policy == nullptr) {
      OpenABE_LOG_AND_THROW("Encryption input must be a Policy",
                        OpenABE_ERROR_INVALID_INPUT);
    }

    // CRITICAL FIX FOR BUG #15: Policy normalization is handled in the CCA layer
    // The policy passed to this function is already normalized by the CCA generic transform,
    // so we can use it directly. Normalizing again here would be redundant and could
    // potentially affect the deterministic PRNG state.

    // Load the master public key
    shared_ptr<OpenABEKey> MPK = this->getKeystore()->getPublicKey(mpkID);
    if (MPK == nullptr) {
      throw OpenABE_ERROR_INVALID_PARAMS;
    }
    // retrieve the hash function key prefix
    k = MPK->getByteString("k");

    // Select s and compute C = e(g1, g2)^(alpha*s)
    // WASM FIX: Use pairing instead of GT exponentiation to avoid MCL WASM bug
    // Mathematical equivalence: e(g1^s, g2^alpha) = e(g1, g2)^(alpha*s) by bilinearity
    ZP s = this->getPairing()->randomZP(myRNG);

    // Compute g1^s
    G1 g1s = MPK->getG1("g1")->exp(s);

    // Get g2^alpha from MPK (added during setup for WASM compatibility)
    // Note: If using old parameter files without g2alpha, regenerate them with oabe_setup
    G2 *g2alpha = MPK->getG2("g2alpha");

    // Compute C = e(g1^s, g2^alpha) instead of C = A^s
    // This avoids buggy GT exponentiation in MCL WASM build
    GT C(std::dynamic_pointer_cast<BPGroup>(this->getPairing()->getGroup()));
    if (g2alpha != nullptr) {
      // Use WASM-compatible pairing approach
      C = this->getPairing()->pairing(g1s, *g2alpha);
    } else {
      // Fallback to old approach (will fail in WASM but works in native)
      // This is for backward compatibility with old parameter files
      GT A = *(MPK->getGT("A"));
      C = A.exp(s);
    }

#if defined(BP_WITH_MCL)
    if (g2alpha != nullptr) {
      fprintf(stderr, "[ENC_DEBUG] Using WASM-compatible pairing approach: C = e(g1^s, g2^alpha)\n");
    } else {
      fprintf(stderr, "[ENC_DEBUG] Using legacy GT exponentiation: C = A^s (not WASM-compatible)\n");
    }
    fprintf(stderr, "[ENC_DEBUG] C (result): isZero=%d, isOne=%d\n",
            mclBnGT_isZero(&C.m_GT), mclBnGT_isOne(&C.m_GT));
    uint8_t C_bytes[576];
    size_t C_len = mclBnGT_serialize(C_bytes, sizeof(C_bytes), &C.m_GT);
    fprintf(stderr, "[ENC_DEBUG] C serialized (%zu bytes, first 32): ", C_len);
    for (size_t i = 0; i < (C_len < 32 ? C_len : 32); i++) {
        fprintf(stderr, "%02x", C_bytes[i]);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
#endif

    // Use the Linear Secret Sharing Scheme (LSSS) to compute an enumerated list
    // of all
    // attributes and corresponding secret shares of s.
    OpenABELSSS lsss(this->getPairing(), myRNG);
    lsss.shareSecret(policy, s);

    // Allocate the ciphertext object and add the policy and key length
    OpenABEByteString pol;
    pol = policy->toCanonicalString();
    ciphertext->setComponent("policy", &pol);

    // Compute Cprime = g1^s
    G1 Cprime = MPK->getG1("g1")->exp(s);
    ciphertext->setComponent("Cprime", &Cprime);

    // For each element of the LSSS
    ZP ri;
    string attr_key;
    OpenABELSSSRowMap lsssRows = lsss.getRows();
    for (auto it = lsssRows.begin(); it != lsssRows.end(); ++it) {
      // Pick a random value ri.
      ri = this->getPairing()->randomZP(myRNG);
      // Compute D[i] = g2^{ri}
      G2 Di = (MPK->getG2("g2")->exp(ri));
      attr_key = OpenABEHashKey(it->first);
      ciphertext->setComponent(OpenABEMakeElementLabel("D", attr_key), &Di);

      // Compute C[i] = g1a^{share_i} * hash_to_G1(attribute)^{-r}
      G1 hG1 = this->getPairing()->hashToG1(*k, it->second.label());
      G1 Ci = MPK->getG1("g1a")->exp(it->second.element()) * (hG1.exp(-ri));
      ciphertext->setComponent(OpenABEMakeElementLabel("C", attr_key), &Ci);
    }

    // Hash C to obtain the symmetric key result.
    key->hashToSymmetricKey(C, keyByteLen, HASH_FUNCTION_TYPE_SHA256);
    ciphertext->setHeader(this->getPairing()->getCurveID(), this->algID, myRNG);

  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/*!
 * Decrypt a symmetric key using the key encapsulation mode
 * of the scheme. Return the key.
 *
 * @param   Parameters ID for the public master parameters.
 * @param   Identifier for the decryption key to be used.
 * @param   ABE ciphertext.
 * @param   Symmetric key to be returned.
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextCPWaters::decryptKEM(const string &mpkID, const string &keyID,
                               OpenABECiphertext *ciphertext, uint32_t keyByteLen,
                               const std::shared_ptr<OpenABESymKey> &key) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  ZP coeff;
  G1 prod1 = this->getPairing()->initG1();
  G1 *Kx, *Cx;
  G2 *Dx;
  GT prodT = this->getPairing()->initGT();

  try {
    ASSERT_NOTNULL(ciphertext);
    ASSERT_NOTNULL(key);
    // Load the given decryption key
    shared_ptr<OpenABEKey> decKey = this->getKeystore()->getSecretKey(keyID);
    ASSERT_NOTNULL(decKey);
    // Obtain the attribute list from the decryption key
    OpenABEAttributeList *attrList =
        (OpenABEAttributeList *)decKey->getComponent("input");

    // Initialize an LSSS structure. Given an attribute list and policy
    // it will identify the necessary solution and return the appropriate
    // components of the access/policy and secret key along with coefficients.
    // If the policy is not satisfied, it throws an error.
    OpenABELSSS lsss(this->getPairing(), this->getRNG());

    OpenABEByteString *policy_str = ciphertext->getByteString("policy");
    ASSERT_NOTNULL(policy_str);

    unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str->toString());
    lsss.recoverCoefficients(policy.get(), attrList);

    // Compute prod1  = prod_{attr_i \in S} C[attr_i]^{coefficient[attr_i]}
    //         prodT = prod_{attr_i \in S} e(KX[attr_i]^{coefficient[attr_i]},
    //         D[attr_i])
    vector<G1> g1s;
    vector<G2> g2s;
    string attr_key, attr_deckey;
    OpenABELSSSRowMap lsssRows = lsss.getRows();
    for (auto it = lsssRows.begin(); it != lsssRows.end(); ++it) {
      coeff = it->second.element();
      attr_key = OpenABEHashKey(it->first);
      attr_deckey = OpenABEHashKey(it->second.label());

      Kx = decKey->getG1(OpenABEMakeElementLabel("KX", attr_deckey));
      ASSERT_NOTNULL(Kx);
      Cx = ciphertext->getG1(OpenABEMakeElementLabel("C", attr_key));
      ASSERT_NOTNULL(Cx);
      Dx = ciphertext->getG2(OpenABEMakeElementLabel("D", attr_key));
      ASSERT_NOTNULL(Dx);

      // DEBUG: Check elements BEFORE exponentiation
#if defined(BP_WITH_MCL)
      fprintf(stderr, "[DECRYPT_DEBUG] attr_key='%s'\n", attr_key.c_str());
      fprintf(stderr, "[DECRYPT_DEBUG] Kx before exp: isZero=%d\n",
              mclBnG1_isZero(&Kx->m_G1));
      fprintf(stderr, "[DECRYPT_DEBUG] Cx before exp: isZero=%d\n",
              mclBnG1_isZero(&Cx->m_G1));
      fprintf(stderr, "[DECRYPT_DEBUG] Dx: isZero=%d\n",
              mclBnG2_isZero(&Dx->m_G2));
#endif

      prod1 *= (Cx->exp(coeff));
      G1 kx_exp = Kx->exp(coeff);

      // DEBUG: Check result AFTER exponentiation
#if defined(BP_WITH_MCL)
      fprintf(stderr, "[DECRYPT_DEBUG] Kx after exp: isZero=%d\n",
              mclBnG1_isZero(&kx_exp.m_G1));
#endif

      g1s.push_back(kx_exp);
      g2s.push_back(*Dx);
    }

    this->getPairing()->multi_pairing(prodT, g1s, g2s);

    // DEBUG: Log prodT (multi-pairing result)
#if defined(BP_WITH_MCL)
    fprintf(stderr, "[GT_DEBUG] prodT after multi_pairing: isZero=%d, isOne=%d\n",
            mclBnGT_isZero(&prodT.m_GT), mclBnGT_isOne(&prodT.m_GT));
    // Serialize prodT to bytes
    uint8_t prodT_bytes[576];  // GT elements are 576 bytes for BLS12-381
    size_t prodT_len = mclBnGT_serialize(prodT_bytes, sizeof(prodT_bytes), &prodT.m_GT);
    fprintf(stderr, "[GT_DEBUG] prodT serialized (%zu bytes, first 32): ", prodT_len);
    for (size_t i = 0; i < (prodT_len < 32 ? prodT_len : 32); i++) {
        fprintf(stderr, "%02x", prodT_bytes[i]);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
#endif

    G1 *Cprime = ciphertext->getG1("Cprime");
    G2 *K = decKey->getG2("K");
    G2 *L = decKey->getG2("L");
    ASSERT_NOTNULL(Cprime);
    ASSERT_NOTNULL(K);
    ASSERT_NOTNULL(L);

    // DEBUG: Log pairing computations
    GT pairing1 = this->getPairing()->pairing(*Cprime, *K);
#if defined(BP_WITH_MCL)
    fprintf(stderr, "[GT_DEBUG] e(Cprime, K): isZero=%d, isOne=%d\n",
            mclBnGT_isZero(&pairing1.m_GT), mclBnGT_isOne(&pairing1.m_GT));
    uint8_t pairing1_bytes[576];
    size_t pairing1_len = mclBnGT_serialize(pairing1_bytes, sizeof(pairing1_bytes), &pairing1.m_GT);
    fprintf(stderr, "[GT_DEBUG] e(Cprime, K) serialized (%zu bytes, first 32): ", pairing1_len);
    for (size_t i = 0; i < (pairing1_len < 32 ? pairing1_len : 32); i++) {
        fprintf(stderr, "%02x", pairing1_bytes[i]);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
#endif

    GT pairing2 = this->getPairing()->pairing(prod1, *L);
#if defined(BP_WITH_MCL)
    fprintf(stderr, "[GT_DEBUG] e(prod1, L): isZero=%d, isOne=%d\n",
            mclBnGT_isZero(&pairing2.m_GT), mclBnGT_isOne(&pairing2.m_GT));
    uint8_t pairing2_bytes[576];
    size_t pairing2_len = mclBnGT_serialize(pairing2_bytes, sizeof(pairing2_bytes), &pairing2.m_GT);
    fprintf(stderr, "[GT_DEBUG] e(prod1, L) serialized (%zu bytes, first 32): ", pairing2_len);
    for (size_t i = 0; i < (pairing2_len < 32 ? pairing2_len : 32); i++) {
        fprintf(stderr, "%02x", pairing2_bytes[i]);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
#endif

    GT denominator = prodT * pairing2;
#if defined(BP_WITH_MCL)
    fprintf(stderr, "[GT_DEBUG] denominator (prodT * e(prod1, L)): isZero=%d, isOne=%d\n",
            mclBnGT_isZero(&denominator.m_GT), mclBnGT_isOne(&denominator.m_GT));
    uint8_t denom_bytes[576];
    size_t denom_len = mclBnGT_serialize(denom_bytes, sizeof(denom_bytes), &denominator.m_GT);
    fprintf(stderr, "[GT_DEBUG] denominator serialized (%zu bytes, first 32): ", denom_len);
    for (size_t i = 0; i < (denom_len < 32 ? denom_len : 32); i++) {
        fprintf(stderr, "%02x", denom_bytes[i]);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
#endif

    // Now compute final = e(Cprime, K) / (prodT * e(prod1, L))
    GT final = pairing1 / denominator;

    // DEBUG: Log final GT element
#if defined(BP_WITH_MCL)
    fprintf(stderr, "[GT_DEBUG] final GT element: isZero=%d, isOne=%d\n",
            mclBnGT_isZero(&final.m_GT), mclBnGT_isOne(&final.m_GT));
    uint8_t final_bytes[576];
    size_t final_len = mclBnGT_serialize(final_bytes, sizeof(final_bytes), &final.m_GT);
    fprintf(stderr, "[GT_DEBUG] final serialized (%zu bytes, first 64): ", final_len);
    for (size_t i = 0; i < (final_len < 64 ? final_len : 64); i++) {
        fprintf(stderr, "%02x", final_bytes[i]);
    }
    if (final_len > 64) fprintf(stderr, "...");
    fprintf(stderr, "\n");
    fflush(stderr);
#endif

    // Compute key = hash_to_bitstring( prodT );
    key->hashToSymmetricKey(final, keyByteLen, HASH_FUNCTION_TYPE_SHA256);
  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

}
