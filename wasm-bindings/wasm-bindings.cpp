/**
 * WebAssembly bindings for OpenABE
 *
 * This file provides C-style exported functions that can be called from
 * JavaScript/TypeScript when using the WASM module.
 */

#include <cstring>
#include <string>
#include <memory>
#include "openabe/openabe.h"
#include "openabe/zcrypto_box.h"

// Export functions with C linkage for WASM
extern "C" {

// Memory management helpers
void* wasm_malloc(size_t size) {
    return malloc(size);
}

void wasm_free(void* ptr) {
    free(ptr);
}

// Initialize OpenABE library
int openabe_init() {
    try {
        InitializeOpenABE();
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Shutdown OpenABE library
int openabe_shutdown() {
    try {
        ShutdownOpenABE();
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Create a new crypto context
// scheme_id: "CP-ABE", "KP-ABE", or "PK"
void* openabe_create_context(const char* scheme_id) {
    try {
        std::string scheme(scheme_id);
        oabe::OpenABECryptoContext* ctx = new oabe::OpenABECryptoContext(scheme);
        return static_cast<void*>(ctx);
    } catch (...) {
        return nullptr;
    }
}

// Destroy a crypto context
void openabe_destroy_context(void* ctx) {
    if (ctx != nullptr) {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        delete context;
    }
}

// Generate system parameters
int openabe_generate_params(void* ctx) {
    if (ctx == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        context->generateParams();
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Generate a key
// For CP-ABE: attributes is the attribute list (e.g., "attr1|attr2|attr3")
// For KP-ABE: attributes is the policy (e.g., "attr1 and attr2")
// For MA-ABE: use openabe_keygen_with_authority instead
int openabe_keygen(void* ctx, const char* attributes, const char* key_id) {
    if (ctx == nullptr || attributes == nullptr || key_id == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string attr_str(attributes);
        std::string key_id_str(key_id);
        context->keygen(attr_str, key_id_str);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Generate a key with authority ID (for MA-ABE)
int openabe_keygen_with_authority(void* ctx, const char* attributes,
                                   const char* key_id, const char* auth_id,
                                   const char* gid) {
    if (ctx == nullptr || attributes == nullptr || key_id == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string attr_str(attributes);
        std::string key_id_str(key_id);
        std::string auth_id_str(auth_id ? auth_id : "");
        std::string gid_str(gid ? gid : "");

        context->keygen(attr_str, key_id_str, auth_id_str, gid_str);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Encrypt data
// For CP-ABE: policy is the access policy (e.g., "attr1 and attr2")
// For KP-ABE: policy is the attribute list (e.g., "attr1|attr2|attr3")
// Returns the length of ciphertext (or -1 on error)
int openabe_encrypt(void* ctx, const char* policy,
                    const char* plaintext, size_t pt_len,
                    char* ciphertext_out, size_t* ct_len) {
    if (ctx == nullptr || policy == nullptr || plaintext == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string policy_str(policy);
        std::string pt(plaintext, pt_len);
        std::string ct;

        context->encrypt(policy_str, pt, ct);

        if (ciphertext_out != nullptr && ct_len != nullptr) {
            if (*ct_len >= ct.size()) {
                memcpy(ciphertext_out, ct.data(), ct.size());
                *ct_len = ct.size();
                return ct.size();
            } else {
                // Buffer too small, return required size
                *ct_len = ct.size();
                return -2;
            }
        }

        return ct.size();
    } catch (...) {
        return -1; // Error
    }
}

// Decrypt data
// Returns the length of plaintext (or -1 on error)
int openabe_decrypt(void* ctx, const char* key_id,
                    const char* ciphertext, size_t ct_len,
                    char* plaintext_out, size_t* pt_len) {
    if (ctx == nullptr || key_id == nullptr || ciphertext == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string key_id_str(key_id);
        std::string ct(ciphertext, ct_len);
        std::string pt;

        bool result = context->decrypt(key_id_str, ct, pt);

        if (!result) {
            return -1; // Decryption failed
        }

        if (plaintext_out != nullptr && pt_len != nullptr) {
            if (*pt_len >= pt.size()) {
                memcpy(plaintext_out, pt.data(), pt.size());
                *pt_len = pt.size();
                return pt.size();
            } else {
                // Buffer too small, return required size
                *pt_len = pt.size();
                return -2;
            }
        }

        return pt.size();
    } catch (...) {
        return -1; // Error
    }
}

// Export public parameters
int openabe_export_public_params(void* ctx, char* output, size_t* output_len) {
    if (ctx == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string mpk;
        context->exportPublicParams(mpk);

        if (output != nullptr && output_len != nullptr) {
            if (*output_len >= mpk.size()) {
                memcpy(output, mpk.data(), mpk.size());
                *output_len = mpk.size();
                return mpk.size();
            } else {
                *output_len = mpk.size();
                return -2;
            }
        }

        return mpk.size();
    } catch (...) {
        return -1; // Error
    }
}

// Import public parameters
int openabe_import_public_params(void* ctx, const char* params, size_t params_len) {
    if (ctx == nullptr || params == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string mpk(params, params_len);
        context->importPublicParams(mpk);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Export secret parameters
int openabe_export_secret_params(void* ctx, char* output, size_t* output_len) {
    if (ctx == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string msk;
        context->exportSecretParams(msk);

        if (output != nullptr && output_len != nullptr) {
            if (*output_len >= msk.size()) {
                memcpy(output, msk.data(), msk.size());
                *output_len = msk.size();
                return msk.size();
            } else {
                *output_len = msk.size();
                return -2;
            }
        }

        return msk.size();
    } catch (...) {
        return -1; // Error
    }
}

// Import secret parameters
int openabe_import_secret_params(void* ctx, const char* params, size_t params_len) {
    if (ctx == nullptr || params == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string msk(params, params_len);
        context->importSecretParams(msk);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Multi-authority ABE functions

// Export global parameters (for MA-ABE)
int openabe_export_global_params(void* ctx, char* output, size_t* output_len) {
    if (ctx == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string global_mpk;
        context->exportGlobalParams(global_mpk);

        if (output != nullptr && output_len != nullptr) {
            if (*output_len >= global_mpk.size()) {
                memcpy(output, global_mpk.data(), global_mpk.size());
                *output_len = global_mpk.size();
                return global_mpk.size();
            } else {
                *output_len = global_mpk.size();
                return -2;
            }
        }

        return global_mpk.size();
    } catch (...) {
        return -1; // Error
    }
}

// Import global parameters (for MA-ABE)
int openabe_import_global_params(void* ctx, const char* params, size_t params_len) {
    if (ctx == nullptr || params == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string global_mpk(params, params_len);
        context->importGlobalParams(global_mpk);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Import public parameters with authority ID (for MA-ABE)
int openabe_import_public_params_with_authority(void* ctx, const char* auth_id,
                                                  const char* params, size_t params_len) {
    if (ctx == nullptr || auth_id == nullptr || params == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string auth_id_str(auth_id);
        std::string mpk(params, params_len);
        context->importPublicParams(auth_id_str, mpk);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Import secret parameters with authority ID (for MA-ABE)
int openabe_import_secret_params_with_authority(void* ctx, const char* auth_id,
                                                  const char* params, size_t params_len) {
    if (ctx == nullptr || auth_id == nullptr || params == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string auth_id_str(auth_id);
        std::string msk(params, params_len);
        context->importSecretParams(auth_id_str, msk);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Export user key (for MA-ABE)
int openabe_export_user_key(void* ctx, const char* key_id, char* output, size_t* output_len) {
    if (ctx == nullptr || key_id == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string key_id_str(key_id);
        std::string key_blob;
        context->exportUserKey(key_id_str, key_blob);

        if (output != nullptr && output_len != nullptr) {
            if (*output_len >= key_blob.size()) {
                memcpy(output, key_blob.data(), key_blob.size());
                *output_len = key_blob.size();
                return key_blob.size();
            } else {
                *output_len = key_blob.size();
                return -2;
            }
        }

        return key_blob.size();
    } catch (...) {
        return -1; // Error
    }
}

// Import user key (for MA-ABE)
int openabe_import_user_key(void* ctx, const char* key_id, const char* key_blob, size_t key_len) {
    if (ctx == nullptr || key_id == nullptr || key_blob == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string key_id_str(key_id);
        std::string blob(key_blob, key_len);
        context->importUserKey(key_id_str, blob);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Delete a key
int openabe_delete_key(void* ctx, const char* key_id) {
    if (ctx == nullptr || key_id == nullptr) return -1;

    try {
        oabe::OpenABECryptoContext* context = static_cast<oabe::OpenABECryptoContext*>(ctx);
        std::string key_id_str(key_id);
        bool result = context->deleteKey(key_id_str);
        return result ? 0 : -1;
    } catch (...) {
        return -1; // Error
    }
}

// ============================================================================
// Public-Key Encryption (PKE) Functions
// ============================================================================

// Create a PKE context
// ec_id: "NIST_P256", "NIST_P384", "NIST_P521", etc.
void* openabe_create_pke_context(const char* ec_id) {
    try {
        std::string curve(ec_id ? ec_id : "NIST_P256");
        oabe::OpenPKEContext* ctx = new oabe::OpenPKEContext(curve);
        return static_cast<void*>(ctx);
    } catch (...) {
        return nullptr;
    }
}

// Destroy a PKE context
void openabe_destroy_pke_context(void* ctx) {
    if (ctx != nullptr) {
        oabe::OpenPKEContext* context = static_cast<oabe::OpenPKEContext*>(ctx);
        delete context;
    }
}

// Generate a PKE keypair
int openabe_pke_keygen(void* ctx, const char* key_id) {
    if (ctx == nullptr || key_id == nullptr) return -1;

    try {
        oabe::OpenPKEContext* context = static_cast<oabe::OpenPKEContext*>(ctx);
        std::string key_id_str(key_id);
        context->keygen(key_id_str);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Encrypt with PKE
int openabe_pke_encrypt(void* ctx, const char* receiver_id,
                        const char* plaintext, size_t pt_len,
                        char* ciphertext_out, size_t* ct_len) {
    if (ctx == nullptr || receiver_id == nullptr || plaintext == nullptr) return -1;

    try {
        oabe::OpenPKEContext* context = static_cast<oabe::OpenPKEContext*>(ctx);
        std::string receiver_id_str(receiver_id);
        std::string pt(plaintext, pt_len);
        std::string ct;

        bool result = context->encrypt(receiver_id_str, pt, ct);
        if (!result) return -1;

        if (ciphertext_out != nullptr && ct_len != nullptr) {
            if (*ct_len >= ct.size()) {
                memcpy(ciphertext_out, ct.data(), ct.size());
                *ct_len = ct.size();
                return ct.size();
            } else {
                *ct_len = ct.size();
                return -2;
            }
        }

        return ct.size();
    } catch (...) {
        return -1; // Error
    }
}

// Decrypt with PKE
int openabe_pke_decrypt(void* ctx, const char* receiver_id,
                        const char* ciphertext, size_t ct_len,
                        char* plaintext_out, size_t* pt_len) {
    if (ctx == nullptr || receiver_id == nullptr || ciphertext == nullptr) return -1;

    try {
        oabe::OpenPKEContext* context = static_cast<oabe::OpenPKEContext*>(ctx);
        std::string receiver_id_str(receiver_id);
        std::string ct(ciphertext, ct_len);
        std::string pt;

        bool result = context->decrypt(receiver_id_str, ct, pt);
        if (!result) return -1;

        if (plaintext_out != nullptr && pt_len != nullptr) {
            if (*pt_len >= pt.size()) {
                memcpy(plaintext_out, pt.data(), pt.size());
                *pt_len = pt.size();
                return pt.size();
            } else {
                *pt_len = pt.size();
                return -2;
            }
        }

        return pt.size();
    } catch (...) {
        return -1; // Error
    }
}

// Export PKE public key
int openabe_pke_export_public_key(void* ctx, const char* key_id, char* output, size_t* output_len) {
    if (ctx == nullptr || key_id == nullptr) return -1;

    try {
        oabe::OpenPKEContext* context = static_cast<oabe::OpenPKEContext*>(ctx);
        std::string key_id_str(key_id);
        std::string key_blob;
        context->exportPublicKey(key_id_str, key_blob);

        if (output != nullptr && output_len != nullptr) {
            if (*output_len >= key_blob.size()) {
                memcpy(output, key_blob.data(), key_blob.size());
                *output_len = key_blob.size();
                return key_blob.size();
            } else {
                *output_len = key_blob.size();
                return -2;
            }
        }

        return key_blob.size();
    } catch (...) {
        return -1; // Error
    }
}

// Import PKE public key
int openabe_pke_import_public_key(void* ctx, const char* key_id, const char* key_blob, size_t key_len) {
    if (ctx == nullptr || key_id == nullptr || key_blob == nullptr) return -1;

    try {
        oabe::OpenPKEContext* context = static_cast<oabe::OpenPKEContext*>(ctx);
        std::string key_id_str(key_id);
        std::string blob(key_blob, key_len);
        context->importPublicKey(key_id_str, blob);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

// Export PKE private key
int openabe_pke_export_private_key(void* ctx, const char* key_id, char* output, size_t* output_len) {
    if (ctx == nullptr || key_id == nullptr) return -1;

    try {
        oabe::OpenPKEContext* context = static_cast<oabe::OpenPKEContext*>(ctx);
        std::string key_id_str(key_id);
        std::string key_blob;
        context->exportPrivateKey(key_id_str, key_blob);

        if (output != nullptr && output_len != nullptr) {
            if (*output_len >= key_blob.size()) {
                memcpy(output, key_blob.data(), key_blob.size());
                *output_len = key_blob.size();
                return key_blob.size();
            } else {
                *output_len = key_blob.size();
                return -2;
            }
        }

        return key_blob.size();
    } catch (...) {
        return -1; // Error
    }
}

// Import PKE private key
int openabe_pke_import_private_key(void* ctx, const char* key_id, const char* key_blob, size_t key_len) {
    if (ctx == nullptr || key_id == nullptr || key_blob == nullptr) return -1;

    try {
        oabe::OpenPKEContext* context = static_cast<oabe::OpenPKEContext*>(ctx);
        std::string key_id_str(key_id);
        std::string blob(key_blob, key_len);
        context->importPrivateKey(key_id_str, blob);
        return 0; // Success
    } catch (...) {
        return -1; // Error
    }
}

} // extern "C"
