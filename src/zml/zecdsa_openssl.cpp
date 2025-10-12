///
/// \file   zecdsa_openssl.cpp
///
/// \brief  OpenSSL-based ECDSA implementation for NIST curves.
///
/// \author OpenABE Contributors
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openabe/zml/zecdsa.h>
#include <openabe/utils/zconstants.h>

#if defined(EC_WITH_OPENSSL)

/********************************************************************************
 * Internal Structures
 ********************************************************************************/

struct ecdsa_context_internal {
    EC_GROUP *group;
    uint8_t curve_id;
};

struct ecdsa_keypair_internal {
    EVP_PKEY *pkey;
    bool has_private;
};

/********************************************************************************
 * Utility Functions
 ********************************************************************************/

static int curve_id_to_nid(uint8_t id) {
    switch (id) {
        case OpenABE_NIST_P256_ID:
            return NID_X9_62_prime256v1;
        case OpenABE_NIST_P384_ID:
            return NID_secp384r1;
        case OpenABE_NIST_P521_ID:
            return NID_secp521r1;
        default:
            return 0;
    }
}

/********************************************************************************
 * Context Management
 ********************************************************************************/

extern "C" {

int ecdsa_context_init(ecdsa_context_t *ctx, uint8_t curve_id) {
    int nid = curve_id_to_nid(curve_id);
    if (nid == 0) {
        return -1;
    }

    struct ecdsa_context_internal *internal =
        (struct ecdsa_context_internal *)malloc(sizeof(struct ecdsa_context_internal));
    if (!internal) {
        return -1;
    }

    internal->group = EC_GROUP_new_by_curve_name(nid);
    if (!internal->group) {
        free(internal);
        return -1;
    }

    EC_GROUP_set_asn1_flag(internal->group, OPENSSL_EC_NAMED_CURVE);
    internal->curve_id = curve_id;

    *ctx = (ecdsa_context_t)internal;
    return 0;
}

void ecdsa_context_free(ecdsa_context_t ctx) {
    if (!ctx) return;

    struct ecdsa_context_internal *internal = (struct ecdsa_context_internal *)ctx;
    if (internal->group) {
        EC_GROUP_free(internal->group);
    }
    free(internal);
}

/********************************************************************************
 * Key Management
 ********************************************************************************/

int ecdsa_keygen(ecdsa_context_t ctx, ecdsa_keypair_t *keypair) {
    if (!ctx || !keypair) return -1;

    struct ecdsa_context_internal *ctx_internal = (struct ecdsa_context_internal *)ctx;
    EC_KEY *ec_key = nullptr;
    EVP_PKEY *pkey = nullptr;

    // Create EC_KEY
    ec_key = EC_KEY_new();
    if (!ec_key) {
        return -1;
    }

    // Set the group
    if (EC_KEY_set_group(ec_key, ctx_internal->group) == 0) {
        EC_KEY_free(ec_key);
        return -1;
    }

    // Generate the keypair
    if (!EC_KEY_generate_key(ec_key)) {
        EC_KEY_free(ec_key);
        return -1;
    }

    // Convert to EVP_PKEY
    pkey = EVP_PKEY_new();
    if (!pkey) {
        EC_KEY_free(ec_key);
        return -1;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(ec_key);
        return -1;
    }

    // Create keypair structure
    struct ecdsa_keypair_internal *kp =
        (struct ecdsa_keypair_internal *)malloc(sizeof(struct ecdsa_keypair_internal));
    if (!kp) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    kp->pkey = pkey;
    kp->has_private = true;

    *keypair = (ecdsa_keypair_t)kp;
    return 0;
}

void ecdsa_keypair_free(ecdsa_keypair_t keypair) {
    if (!keypair) return;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;
    if (kp->pkey) {
        EVP_PKEY_free(kp->pkey);
    }
    free(kp);
}

size_t ecdsa_export_public_key(ecdsa_keypair_t keypair, uint8_t *buf, size_t buf_len) {
    if (!keypair || !buf) return 0;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;

    // Use EVP_PKEY serialization
    unsigned char *p = buf;
    int len = i2d_PUBKEY(kp->pkey, &p);

    if (len < 0 || (size_t)len > buf_len) {
        return 0;
    }

    return (size_t)len;
}

size_t ecdsa_export_private_key(ecdsa_keypair_t keypair, uint8_t *buf, size_t buf_len) {
    if (!keypair || !buf) return 0;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;

    if (!kp->has_private) {
        return 0;
    }

    // Use EVP_PKEY serialization
    unsigned char *p = buf;
    int len = i2d_PrivateKey(kp->pkey, &p);

    if (len < 0 || (size_t)len > buf_len) {
        return 0;
    }

    return (size_t)len;
}

int ecdsa_import_public_key(ecdsa_context_t ctx, ecdsa_keypair_t *keypair,
                             const uint8_t *buf, size_t buf_len) {
    if (!ctx || !keypair || !buf) return -1;

    const unsigned char *p = buf;
    EVP_PKEY *pkey = d2i_PUBKEY(nullptr, &p, buf_len);

    if (!pkey) {
        return -1;
    }

    // Create keypair structure
    struct ecdsa_keypair_internal *kp =
        (struct ecdsa_keypair_internal *)malloc(sizeof(struct ecdsa_keypair_internal));
    if (!kp) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    kp->pkey = pkey;
    kp->has_private = false;

    *keypair = (ecdsa_keypair_t)kp;
    return 0;
}

int ecdsa_import_private_key(ecdsa_context_t ctx, ecdsa_keypair_t *keypair,
                              const uint8_t *buf, size_t buf_len) {
    if (!ctx || !keypair || !buf) return -1;

    const unsigned char *p = buf;
    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, buf_len);

    if (!pkey) {
        return -1;
    }

    // Create keypair structure
    struct ecdsa_keypair_internal *kp =
        (struct ecdsa_keypair_internal *)malloc(sizeof(struct ecdsa_keypair_internal));
    if (!kp) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    kp->pkey = pkey;
    kp->has_private = true;

    *keypair = (ecdsa_keypair_t)kp;
    return 0;
}

/********************************************************************************
 * Signing and Verification
 ********************************************************************************/

size_t ecdsa_sign(ecdsa_keypair_t keypair, const uint8_t *msg, size_t msg_len,
                  uint8_t *sig, size_t sig_len) {
    if (!keypair || !msg || !sig) {
        return 0;
    }

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;

    if (!kp->has_private) {
        return 0;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return 0;
    }

    size_t sig_size = 0;

    // Initialize signing
    if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, kp->pkey) != 1) {
        goto cleanup;
    }

    // Update with message
    if (EVP_DigestSignUpdate(md_ctx, msg, msg_len) != 1) {
        goto cleanup;
    }

    // First call to get the signature size
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_size) != 1) {
        sig_size = 0;
        goto cleanup;
    }

    // Check if buffer is large enough
    if (sig_size > sig_len) {
        sig_size = 0;
        goto cleanup;
    }

    // Second call to get the actual signature
    if (EVP_DigestSignFinal(md_ctx, sig, &sig_size) != 1) {
        sig_size = 0;
        goto cleanup;
    }

cleanup:
    EVP_MD_CTX_free(md_ctx);
    return sig_size;
}

int ecdsa_verify(ecdsa_keypair_t keypair, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len) {
    if (!keypair || !msg || !sig) return 0;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return 0;
    }

    int result = 0;

    // Initialize verification
    if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, kp->pkey) != 1) {
        goto cleanup;
    }

    // Update with message
    if (EVP_DigestVerifyUpdate(md_ctx, msg, msg_len) != 1) {
        goto cleanup;
    }

    // Verify signature
    result = (EVP_DigestVerifyFinal(md_ctx, (unsigned char *)sig, sig_len) == 1) ? 1 : 0;

cleanup:
    EVP_MD_CTX_free(md_ctx);
    return result;
}

/********************************************************************************
 * Utility Functions
 ********************************************************************************/

size_t ecdsa_get_max_signature_size(ecdsa_context_t ctx) {
    if (!ctx) return 0;

    struct ecdsa_context_internal *internal = (struct ecdsa_context_internal *)ctx;

    // ECDSA signature is approximately 2 * (field_size + 8) bytes in DER encoding
    // For P-256: ~72 bytes, P-384: ~104 bytes, P-521: ~139 bytes
    int field_bits = EC_GROUP_get_degree(internal->group);
    return (field_bits / 4) + 16; // Conservative estimate
}

int ecdsa_has_private_key(ecdsa_keypair_t keypair) {
    if (!keypair) return 0;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;
    return kp->has_private ? 1 : 0;
}

} // extern "C"

#endif /* EC_WITH_OPENSSL */
