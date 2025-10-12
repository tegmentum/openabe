///
/// \file   zecdsa_mcl.cpp
///
/// \brief  MCL-based ECDSA implementation for secp256k1.
///
/// \author OpenABE Contributors
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openabe/zml/zecdsa.h>
#include <openabe/utils/zconstants.h>

#if defined(EC_WITH_MCL)

#include <mcl/ecdsa.h>

/********************************************************************************
 * Internal Structures
 ********************************************************************************/

struct ecdsa_context_internal {
    uint8_t curve_id;
    bool initialized;
};

struct ecdsa_keypair_internal {
    ecdsaSecretKey secret_key;
    ecdsaPublicKey public_key;
    bool has_private;
};

// Global initialization flag
static bool g_mcl_ecdsa_initialized = false;

/********************************************************************************
 * Context Management
 ********************************************************************************/

extern "C" {

int ecdsa_context_init(ecdsa_context_t *ctx, uint8_t curve_id) {
    // MCL ECDSA only supports secp256k1
    // We'll accept any curve ID but always use secp256k1
    (void)curve_id;

    if (!g_mcl_ecdsa_initialized) {
        if (ecdsaInit() != 0) {
            fprintf(stderr, "MCL ECDSA initialization failed\n");
            return -1;
        }
        g_mcl_ecdsa_initialized = true;
    }

    struct ecdsa_context_internal *internal =
        (struct ecdsa_context_internal *)malloc(sizeof(struct ecdsa_context_internal));
    if (!internal) {
        return -1;
    }

    internal->curve_id = curve_id;
    internal->initialized = true;

    *ctx = (ecdsa_context_t)internal;
    return 0;
}

void ecdsa_context_free(ecdsa_context_t ctx) {
    if (!ctx) return;
    free(ctx);
}

/********************************************************************************
 * Key Management
 ********************************************************************************/

int ecdsa_keygen(ecdsa_context_t ctx, ecdsa_keypair_t *keypair) {
    if (!ctx || !keypair) return -1;

    struct ecdsa_keypair_internal *kp =
        (struct ecdsa_keypair_internal *)malloc(sizeof(struct ecdsa_keypair_internal));
    if (!kp) {
        return -1;
    }

    // Generate secret key
    if (ecdsaSecretKeySetByCSPRNG(&kp->secret_key) != 0) {
        free(kp);
        return -1;
    }

    // Derive public key from secret key
    ecdsaGetPublicKey(&kp->public_key, &kp->secret_key);

    kp->has_private = true;

    *keypair = (ecdsa_keypair_t)kp;
    return 0;
}

void ecdsa_keypair_free(ecdsa_keypair_t keypair) {
    if (!keypair) return;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;

    // Clear secret key memory before freeing
    if (kp->has_private) {
        memset(&kp->secret_key, 0, sizeof(ecdsaSecretKey));
    }

    free(kp);
}

size_t ecdsa_export_public_key(ecdsa_keypair_t keypair, uint8_t *buf, size_t buf_len) {
    if (!keypair || !buf) return 0;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;

    size_t written = ecdsaPublicKeySerialize(buf, buf_len, &kp->public_key);
    return written;
}

size_t ecdsa_export_private_key(ecdsa_keypair_t keypair, uint8_t *buf, size_t buf_len) {
    if (!keypair || !buf) return 0;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;

    if (!kp->has_private) {
        return 0;
    }

    size_t written = ecdsaSecretKeySerialize(buf, buf_len, &kp->secret_key);
    return written;
}

int ecdsa_import_public_key(ecdsa_context_t ctx, ecdsa_keypair_t *keypair,
                             const uint8_t *buf, size_t buf_len) {
    if (!ctx || !keypair || !buf) return -1;

    struct ecdsa_keypair_internal *kp =
        (struct ecdsa_keypair_internal *)malloc(sizeof(struct ecdsa_keypair_internal));
    if (!kp) {
        return -1;
    }

    // Deserialize public key
    if (ecdsaPublicKeyDeserialize(&kp->public_key, buf, buf_len) == 0) {
        free(kp);
        return -1;
    }

    kp->has_private = false;

    *keypair = (ecdsa_keypair_t)kp;
    return 0;
}

int ecdsa_import_private_key(ecdsa_context_t ctx, ecdsa_keypair_t *keypair,
                              const uint8_t *buf, size_t buf_len) {
    if (!ctx || !keypair || !buf) return -1;

    struct ecdsa_keypair_internal *kp =
        (struct ecdsa_keypair_internal *)malloc(sizeof(struct ecdsa_keypair_internal));
    if (!kp) {
        return -1;
    }

    // Deserialize secret key
    if (ecdsaSecretKeyDeserialize(&kp->secret_key, buf, buf_len) == 0) {
        free(kp);
        return -1;
    }

    // Derive public key
    ecdsaGetPublicKey(&kp->public_key, &kp->secret_key);

    kp->has_private = true;

    *keypair = (ecdsa_keypair_t)kp;
    return 0;
}

/********************************************************************************
 * Signing and Verification
 ********************************************************************************/

size_t ecdsa_sign(ecdsa_keypair_t keypair, const uint8_t *msg, size_t msg_len,
                  uint8_t *sig, size_t sig_len) {
    if (!keypair || !msg || !sig) return 0;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;

    if (!kp->has_private) {
        return 0;
    }

    ecdsaSignature signature;

    // Sign the message
    ecdsaSign(&signature, &kp->secret_key, msg, msg_len);

    // Serialize signature
    size_t written = ecdsaSignatureSerialize(sig, sig_len, &signature);

    return written;
}

int ecdsa_verify(ecdsa_keypair_t keypair, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len) {
    if (!keypair || !msg || !sig) return 0;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;

    ecdsaSignature signature;

    // Deserialize signature
    if (ecdsaSignatureDeserialize(&signature, sig, sig_len) == 0) {
        return 0;
    }

    // Verify signature
    int result = ecdsaVerify(&signature, &kp->public_key, msg, msg_len);

    return result;
}

/********************************************************************************
 * Utility Functions
 ********************************************************************************/

size_t ecdsa_get_max_signature_size(ecdsa_context_t ctx) {
    (void)ctx;
    // secp256k1 ECDSA signature is ~72 bytes in DER format
    return 80; // Conservative estimate
}

int ecdsa_has_private_key(ecdsa_keypair_t keypair) {
    if (!keypair) return 0;

    struct ecdsa_keypair_internal *kp = (struct ecdsa_keypair_internal *)keypair;
    return kp->has_private ? 1 : 0;
}

} // extern "C"

#endif /* EC_WITH_MCL */
