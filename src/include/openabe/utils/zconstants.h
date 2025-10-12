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
/// \file   zconstants.h
///
/// \brief  Main header file for the Zeutro Functional Encryption Toolkit
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZCONSTANTS_H__
#define __ZCONSTANTS_H__

//
// Constants
//

#define OpenABE_LIBRARY_VERSION      170  // Library version 1.7
#define MIN_BYTE_LEN             32
#define DEFAULT_SECURITY_LEVEL   128
#define DEFAULT_AES_SEC_LEVEL    MIN_BYTE_LEN*8 // AES-256
#define SALT_LEN                 MIN_BYTE_LEN // 256-bits (minimum is 64-bits)
#define HASH_LEN                 MIN_BYTE_LEN // 256-bits
#define SEED_LEN                 MIN_BYTE_LEN
#define UID_LEN                  16 // 128-bit UID length
#define DEFAULT_SYM_KEY_BYTES    MIN_BYTE_LEN  // 256-bit keys
#define DEFAULT_SYM_KEY_BITS     DEFAULT_SYM_KEY_BYTES*8
#define SHA256_LEN               32 // SHA-256
#define OpenABE_KDF_ITERATION_COUNT  10000
#define MAX_BUFFER_SIZE          512
#define MAX_INT_BITS             32  // For numerical attributes (in policy/attribute list)

// Data structures     // OpenABE_ELEMENT_UINT = 0x2D,
typedef enum _OpenABEElementType {
    OpenABE_NONE_TYPE = 0x00,
    OpenABE_ELEMENT_INT = 0xA1,
    OpenABE_ELEMENT_ZP = 0xB1,
    OpenABE_ELEMENT_G1 = 0xB2,
    OpenABE_ELEMENT_G2 = 0xB3,
    OpenABE_ELEMENT_GT = 0xB4,
    OpenABE_ELEMENT_ZP_t = 0xC1,
    OpenABE_ELEMENT_G_t = 0xC2,
    OpenABE_ELEMENT_POLICY = 0x7A,
    OpenABE_ELEMENT_ATTRIBUTES = 0x7C, // this is ATTR_SEP '|' in hex
    OpenABE_ELEMENT_BYTESTRING = 0x1D,
} OpenABEElementType;

/// @typedef    OpenABECurveID
///
/// @brief      Enumeration all the curve identifiers supported

typedef enum _OpenABECurveID {
  OpenABE_NONE_ID = 0x00,
  OpenABE_NIST_P256_ID = 0x32,
  OpenABE_NIST_P384_ID = 0x5A,
  OpenABE_NIST_P521_ID = 0xB7,
  OpenABE_BN_P158_ID = 0x61,
  OpenABE_BN_P254_ID = 0x6F,
  OpenABE_BN_P256_ID = 0x73,
  OpenABE_KSS_508_ID = 0x3C,
  OpenABE_BN_P382_ID = 0xE4,
  OpenABE_BN_P446_ID = 0xE5,
  OpenABE_BN_P638_ID = 0x8D,
  // BLS12 curves
  OpenABE_BLS12_P377_ID = 0xA1,
  OpenABE_BLS12_P381_ID = 0xA2,
  OpenABE_BLS12_P446_ID = 0xA3,
  OpenABE_BLS12_P455_ID = 0xA4,
  OpenABE_BLS12_P638_ID = 0xA5,
  // BLS24 curves
  OpenABE_BLS24_P315_ID = 0xB1,
  OpenABE_BLS24_P317_ID = 0xB2,
  OpenABE_BLS24_P509_ID = 0xB3,
  // BLS48 curves
  OpenABE_BLS48_P575_ID = 0xC1,
  // KSS16 curves
  OpenABE_KSS16_P339_ID = 0xD1
} OpenABECurveID;

// Security level constants (bits of security)
#define OpenABE_SECURITY_WEAK 64
#define OpenABE_SECURITY_LEGACY 80
#define OpenABE_SECURITY_STANDARD 128
#define OpenABE_SECURITY_HIGH 192
#define OpenABE_SECURITY_VERY_HIGH 256

// Data structures

typedef enum _zGroupType {
  GROUP_NONE,
  GROUP_G1,
  GROUP_G2,
  GROUP_GT,
  GROUP_ZP
} zGroupType;

#define NO_COMPRESS 0
#define COMPRESS    1
#define BINARY      2
#define DEC         10
#define HEXADECIMAL 16
#define MAX_BYTES   1024
#define SHA1_BITLEN 160     // only used with PBKDF2
#define SHA2_BITLEN 256
#define HASH_FUNCTION_STRINGS           "0"
#define HASH_FUNCTION_STR_TO_Zr_CRH     "1"
#define HASH_FUNCTION_Zr_TO_G1_ROM      "2"
#define HASH_FUNCTION_Zr_TO_G2_ROM      "3"

// Macros

#ifdef __wasm__
// WASM-compatible versions without exceptions
#define ASSERT_GROUP(G, A, B)   if ( (A) != (G) ||  (B) != (G) ) { fprintf(stderr, "%s:%s:%d: ASSERT_GROUP failed\n", __FILE__, __FUNCTION__, __LINE__); abort(); }
#define ASSERT_RNG(R)			if ( (R) < 1 ) { fprintf(stderr, "%s:%s:%d: ASSERT_RNG failed\n", __FILE__, __FUNCTION__, __LINE__); abort(); }
#define ASSERT_PAIRING(P)       if ( (P) == NULL ) { fprintf(stderr, "%s:%s:%d: ASSERT_PAIRING failed\n", __FILE__, __FUNCTION__, __LINE__); abort(); }
// For functions that return OpenABE_ERROR or bool
#define ASSERT_NOTNULL(A)		if ( (A) == NULL ) { fprintf(stderr, "%s:%s:%d: ASSERT_NOTNULL failed\n", __FILE__, __FUNCTION__, __LINE__); return oabe::OpenABE_ERROR_INVALID_INPUT; }
// For void functions
#define ASSERT_NOTNULL_VOID(A)	if ( (A) == NULL ) { fprintf(stderr, "%s:%s:%d: ASSERT_NOTNULL_VOID failed\n", __FILE__, __FUNCTION__, __LINE__); return; }
#define ASSERT_VOID(A, B)       if ( (A) == false ) { fprintf(stderr, "%s:%s:%d: ASSERT_VOID failed\n", __FILE__, __FUNCTION__, __LINE__); return; }
// For functions that return unique_ptr or raw pointers
#define ASSERT_NOTNULL_PTR(A)   if ( (A) == NULL ) { fprintf(stderr, "%s:%s:%d: ASSERT_NOTNULL_PTR failed\n", __FILE__, __FUNCTION__, __LINE__); return nullptr; }
// For fatal errors that must abort
#define ABORT_ASSERT(A, B)      if ( (A) == false ) { fprintf(stderr, "%s:%s:%d: ABORT_ASSERT failed ('%s')\n", __FILE__, __FUNCTION__, __LINE__, OpenABE_errorToString(B)); abort(); }
#else
#define ASSERT_GROUP(G, A, B)   if ( (A) != (G) ||  (B) != (G) ) throw oabe::OpenABE_ERROR_WRONG_GROUP;
#define ASSERT_RNG(R)			if ( (R) < 1 ) throw oabe::OpenABE_ERROR_RAND_INSUFFICIENT;
#define ASSERT_PAIRING(P)       if ( (P) == NULL ) throw oabe::OpenABE_ERROR_WRONG_GROUP;
#define ASSERT_NOTNULL(A)		if ( (A) == NULL ) throw oabe::OpenABE_ERROR_INVALID_INPUT;
#define ASSERT_NOTNULL_VOID(A)	if ( (A) == NULL ) throw oabe::OpenABE_ERROR_INVALID_INPUT;
#define ASSERT_NOTNULL_PTR(A)	if ( (A) == NULL ) { fprintf(stderr, "%s:%s:%d: ASSERT_NOTNULL_PTR failed\n", __FILE__, __FUNCTION__, __LINE__); return nullptr; }
#define ASSERT_VOID(A, B)       if ( (A) == false ) throw B;
#define ABORT_ASSERT(A, B)      if ( (A) == false ) { fprintf(stderr, "%s:%s:%d: ABORT_ASSERT failed ('%s')\n", __FILE__, __FUNCTION__, __LINE__, OpenABE_errorToString(B)); throw B; }
#endif
#define ASSERT_MESSAGE(A, B, C)  if ( (A) == false ) { string tmp_s = B; fprintf(stderr, "%s:%s:%d: %s - '%s'\n", __FILE__, __FUNCTION__, __LINE__, tmp_s.c_str(), OpenABE_errorToString(C)); throw C; }
#define ASSERT(A, B)			if ( (A) == false ) { fprintf(stderr, "%s:%s:%d: '%s'\n", __FILE__, __FUNCTION__, __LINE__, OpenABE_errorToString(B)); throw B; }
#define THROW_ERROR(B)          fprintf(stderr, "%s:%s:%d: '%s'\n", __FILE__, __FUNCTION__, __LINE__, OpenABE_errorToString(B)); throw B;

#define MALLOC_CHECK_OUT_OF_MEMORY(ptr) \
	if(!ptr) { \
		fprintf(stderr, __FILE__ ": Out of Memory, Line %d\n", __LINE__); \
		exit(1); \
	}

#endif /* ifdef __ZCONSTANTS_H__ */
