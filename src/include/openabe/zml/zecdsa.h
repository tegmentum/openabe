///
/// \file   zecdsa.h
///
/// \brief  ECDSA abstraction layer that works with both MCL and OpenSSL backends.
///         Provides key generation, signing, and verification operations.
///
/// \author OpenABE Contributors
///

#ifndef __ZECDSA_H__
#define __ZECDSA_H__

#include <stdint.h>
#include <stdlib.h>
#include <openabe/zml/zelement.h>

#ifdef __cplusplus
extern "C" {
#endif

/********************************************************************************
 * ECDSA Types
 ********************************************************************************/

typedef void* ecdsa_context_t;
typedef void* ecdsa_keypair_t;

/********************************************************************************
 * ECDSA Context Management
 ********************************************************************************/

// Initialize ECDSA context for a specific curve
// Returns 0 on success, non-zero on error
int ecdsa_context_init(ecdsa_context_t *ctx, uint8_t curve_id);

// Free ECDSA context
void ecdsa_context_free(ecdsa_context_t ctx);

/********************************************************************************
 * Key Management
 ********************************************************************************/

// Generate a new ECDSA keypair
// Returns 0 on success, non-zero on error
int ecdsa_keygen(ecdsa_context_t ctx, ecdsa_keypair_t *keypair);

// Free a keypair
void ecdsa_keypair_free(ecdsa_keypair_t keypair);

// Export public key to bytes
// Returns number of bytes written, or 0 on error
size_t ecdsa_export_public_key(ecdsa_keypair_t keypair, uint8_t *buf, size_t buf_len);

// Export private key to bytes
// Returns number of bytes written, or 0 on error
size_t ecdsa_export_private_key(ecdsa_keypair_t keypair, uint8_t *buf, size_t buf_len);

// Import public key from bytes
// Returns 0 on success, non-zero on error
int ecdsa_import_public_key(ecdsa_context_t ctx, ecdsa_keypair_t *keypair,
                             const uint8_t *buf, size_t buf_len);

// Import private key from bytes
// Returns 0 on success, non-zero on error
int ecdsa_import_private_key(ecdsa_context_t ctx, ecdsa_keypair_t *keypair,
                              const uint8_t *buf, size_t buf_len);

/********************************************************************************
 * Signing and Verification
 ********************************************************************************/

// Sign a message
// Returns number of signature bytes written, or 0 on error
size_t ecdsa_sign(ecdsa_keypair_t keypair, const uint8_t *msg, size_t msg_len,
                  uint8_t *sig, size_t sig_len);

// Verify a signature
// Returns 1 if signature is valid, 0 if invalid or error
int ecdsa_verify(ecdsa_keypair_t keypair, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len);

/********************************************************************************
 * Utility Functions
 ********************************************************************************/

// Get the maximum signature size for this context
size_t ecdsa_get_max_signature_size(ecdsa_context_t ctx);

// Check if a keypair has a private key component
int ecdsa_has_private_key(ecdsa_keypair_t keypair);

#ifdef __cplusplus
}
#endif

#endif /* __ZECDSA_H__ */
