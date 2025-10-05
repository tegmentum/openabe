/**
 * WebAssembly bindings header for OpenABE
 */

#ifndef WASM_BINDINGS_H
#define WASM_BINDINGS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Memory management
void* wasm_malloc(size_t size);
void wasm_free(void* ptr);

// Library initialization
int openabe_init(void);
int openabe_shutdown(void);

// Context management
void* openabe_create_context(const char* scheme_id);
void openabe_destroy_context(void* ctx);

// Key generation and setup
int openabe_generate_params(void* ctx);
int openabe_keygen(void* ctx, const char* attributes, const char* key_id);
int openabe_keygen_with_authority(void* ctx, const char* attributes,
                                   const char* key_id, const char* auth_id,
                                   const char* gid);

// Encryption/Decryption
int openabe_encrypt(void* ctx, const char* policy,
                    const char* plaintext, size_t pt_len,
                    char* ciphertext_out, size_t* ct_len);

int openabe_decrypt(void* ctx, const char* key_id,
                    const char* ciphertext, size_t ct_len,
                    char* plaintext_out, size_t* pt_len);

// Import/Export parameters
int openabe_export_public_params(void* ctx, char* output, size_t* output_len);
int openabe_import_public_params(void* ctx, const char* params, size_t params_len);
int openabe_export_secret_params(void* ctx, char* output, size_t* output_len);
int openabe_import_secret_params(void* ctx, const char* params, size_t params_len);

// Multi-authority ABE functions
int openabe_export_global_params(void* ctx, char* output, size_t* output_len);
int openabe_import_global_params(void* ctx, const char* params, size_t params_len);
int openabe_import_public_params_with_authority(void* ctx, const char* auth_id,
                                                  const char* params, size_t params_len);
int openabe_import_secret_params_with_authority(void* ctx, const char* auth_id,
                                                  const char* params, size_t params_len);
int openabe_export_user_key(void* ctx, const char* key_id, char* output, size_t* output_len);
int openabe_import_user_key(void* ctx, const char* key_id, const char* key_blob, size_t key_len);
int openabe_delete_key(void* ctx, const char* key_id);

// Public-Key Encryption (PKE) functions
void* openabe_create_pke_context(const char* ec_id);
void openabe_destroy_pke_context(void* ctx);
int openabe_pke_keygen(void* ctx, const char* key_id);
int openabe_pke_encrypt(void* ctx, const char* receiver_id,
                        const char* plaintext, size_t pt_len,
                        char* ciphertext_out, size_t* ct_len);
int openabe_pke_decrypt(void* ctx, const char* receiver_id,
                        const char* ciphertext, size_t ct_len,
                        char* plaintext_out, size_t* pt_len);
int openabe_pke_export_public_key(void* ctx, const char* key_id, char* output, size_t* output_len);
int openabe_pke_import_public_key(void* ctx, const char* key_id, const char* key_blob, size_t key_len);
int openabe_pke_export_private_key(void* ctx, const char* key_id, char* output, size_t* output_len);
int openabe_pke_import_private_key(void* ctx, const char* key_id, const char* key_blob, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif // WASM_BINDINGS_H
