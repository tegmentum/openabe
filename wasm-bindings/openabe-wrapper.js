/**
 * JavaScript wrapper for OpenABE WebAssembly module
 */

/**
 * Helper function to allocate and write a string to WASM memory
 */
function allocateString(module, str) {
  const len = module.lengthBytesUTF8(str) + 1;
  const ptr = module._wasm_malloc(len);
  module.stringToUTF8(str, ptr, len);
  return { ptr, len };
}

/**
 * Helper function to read a buffer from WASM memory
 */
function readBuffer(module, ptr, len) {
  return new Uint8Array(module.HEAPU8.buffer, ptr, len);
}

/**
 * OpenABE Context wrapper class
 */
class OpenABEContext {
  constructor(module, scheme) {
    this.module = module;
    const schemeStr = allocateString(module, scheme);
    this.ctx = module._openabe_create_context(schemeStr.ptr);
    module._wasm_free(schemeStr.ptr);

    if (this.ctx === 0) {
      throw new Error('Failed to create OpenABE context');
    }
  }

  generateParams() {
    const result = this.module._openabe_generate_params(this.ctx);
    if (result !== 0) {
      throw new Error('Failed to generate parameters');
    }
  }

  keygen(attributes, keyId, authId = null, gid = null) {
    const attrStr = allocateString(this.module, attributes);
    const keyIdStr = allocateString(this.module, keyId);

    let result;
    if (authId !== null || gid !== null) {
      // Multi-authority keygen
      const authIdStr = authId ? allocateString(this.module, authId) : { ptr: 0 };
      const gidStr = gid ? allocateString(this.module, gid) : { ptr: 0 };

      result = this.module._openabe_keygen_with_authority(
        this.ctx,
        attrStr.ptr,
        keyIdStr.ptr,
        authIdStr.ptr,
        gidStr.ptr
      );

      if (authIdStr.ptr) this.module._wasm_free(authIdStr.ptr);
      if (gidStr.ptr) this.module._wasm_free(gidStr.ptr);
    } else {
      // Standard keygen
      result = this.module._openabe_keygen(this.ctx, attrStr.ptr, keyIdStr.ptr);
    }

    this.module._wasm_free(attrStr.ptr);
    this.module._wasm_free(keyIdStr.ptr);

    if (result !== 0) {
      throw new Error('Failed to generate key');
    }
  }

  encrypt(policy, plaintext) {
    const policyStr = allocateString(this.module, policy);

    let ptPtr, ptLen;
    if (typeof plaintext === 'string') {
      const ptStr = allocateString(this.module, plaintext);
      ptPtr = ptStr.ptr;
      ptLen = ptStr.len - 1; // exclude null terminator
    } else {
      ptLen = plaintext.length;
      ptPtr = this.module._wasm_malloc(ptLen);
      this.module.HEAPU8.set(plaintext, ptPtr);
    }

    // First call to get required size
    const ctLenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[ctLenPtr >> 2] = 0;
    let ctSize = this.module._openabe_encrypt(
      this.ctx,
      policyStr.ptr,
      ptPtr,
      ptLen,
      0,
      ctLenPtr
    );

    if (ctSize < 0) {
      this.module._wasm_free(policyStr.ptr);
      this.module._wasm_free(ptPtr);
      this.module._wasm_free(ctLenPtr);
      throw new Error('Encryption failed');
    }

    // Allocate buffer and encrypt
    const ctPtr = this.module._wasm_malloc(ctSize);
    this.module.HEAPU32[ctLenPtr >> 2] = ctSize;
    const result = this.module._openabe_encrypt(
      this.ctx,
      policyStr.ptr,
      ptPtr,
      ptLen,
      ctPtr,
      ctLenPtr
    );

    const actualCtLen = this.module.HEAPU32[ctLenPtr >> 2];
    const ciphertext = new Uint8Array(actualCtLen);
    ciphertext.set(readBuffer(this.module, ctPtr, actualCtLen));

    // Cleanup
    this.module._wasm_free(policyStr.ptr);
    this.module._wasm_free(ptPtr);
    this.module._wasm_free(ctPtr);
    this.module._wasm_free(ctLenPtr);

    if (result < 0) {
      throw new Error('Encryption failed');
    }

    return ciphertext;
  }

  decrypt(keyId, ciphertext) {
    const keyIdStr = allocateString(this.module, keyId);
    const ctPtr = this.module._wasm_malloc(ciphertext.length);
    this.module.HEAPU8.set(ciphertext, ctPtr);

    // First call to get required size
    const ptLenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[ptLenPtr >> 2] = 0;
    let ptSize = this.module._openabe_decrypt(
      this.ctx,
      keyIdStr.ptr,
      ctPtr,
      ciphertext.length,
      0,
      ptLenPtr
    );

    if (ptSize < 0) {
      this.module._wasm_free(keyIdStr.ptr);
      this.module._wasm_free(ctPtr);
      this.module._wasm_free(ptLenPtr);
      return null; // Decryption failed
    }

    // Allocate buffer and decrypt
    const ptPtr = this.module._wasm_malloc(ptSize);
    this.module.HEAPU32[ptLenPtr >> 2] = ptSize;
    const result = this.module._openabe_decrypt(
      this.ctx,
      keyIdStr.ptr,
      ctPtr,
      ciphertext.length,
      ptPtr,
      ptLenPtr
    );

    const actualPtLen = this.module.HEAPU32[ptLenPtr >> 2];
    const plaintext = new Uint8Array(actualPtLen);
    plaintext.set(readBuffer(this.module, ptPtr, actualPtLen));

    // Cleanup
    this.module._wasm_free(keyIdStr.ptr);
    this.module._wasm_free(ctPtr);
    this.module._wasm_free(ptPtr);
    this.module._wasm_free(ptLenPtr);

    if (result < 0) {
      return null;
    }

    return plaintext;
  }

  exportPublicParams() {
    const lenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[lenPtr >> 2] = 0;

    // Get required size
    const size = this.module._openabe_export_public_params(this.ctx, 0, lenPtr);
    if (size < 0) {
      this.module._wasm_free(lenPtr);
      throw new Error('Failed to export public params');
    }

    // Allocate and export
    const ptr = this.module._wasm_malloc(size);
    this.module.HEAPU32[lenPtr >> 2] = size;
    this.module._openabe_export_public_params(this.ctx, ptr, lenPtr);

    const actualLen = this.module.HEAPU32[lenPtr >> 2];
    const params = new Uint8Array(actualLen);
    params.set(readBuffer(this.module, ptr, actualLen));

    this.module._wasm_free(ptr);
    this.module._wasm_free(lenPtr);

    return params;
  }

  importPublicParams(params) {
    const ptr = this.module._wasm_malloc(params.length);
    this.module.HEAPU8.set(params, ptr);

    const result = this.module._openabe_import_public_params(this.ctx, ptr, params.length);
    this.module._wasm_free(ptr);

    if (result !== 0) {
      throw new Error('Failed to import public params');
    }
  }

  exportSecretParams() {
    const lenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[lenPtr >> 2] = 0;

    // Get required size
    const size = this.module._openabe_export_secret_params(this.ctx, 0, lenPtr);
    if (size < 0) {
      this.module._wasm_free(lenPtr);
      throw new Error('Failed to export secret params');
    }

    // Allocate and export
    const ptr = this.module._wasm_malloc(size);
    this.module.HEAPU32[lenPtr >> 2] = size;
    this.module._openabe_export_secret_params(this.ctx, ptr, lenPtr);

    const actualLen = this.module.HEAPU32[lenPtr >> 2];
    const params = new Uint8Array(actualLen);
    params.set(readBuffer(this.module, ptr, actualLen));

    this.module._wasm_free(ptr);
    this.module._wasm_free(lenPtr);

    return params;
  }

  importSecretParams(params, authId = null) {
    const ptr = this.module._wasm_malloc(params.length);
    this.module.HEAPU8.set(params, ptr);

    let result;
    if (authId !== null) {
      const authIdStr = allocateString(this.module, authId);
      result = this.module._openabe_import_secret_params_with_authority(
        this.ctx,
        authIdStr.ptr,
        ptr,
        params.length
      );
      this.module._wasm_free(authIdStr.ptr);
    } else {
      result = this.module._openabe_import_secret_params(this.ctx, ptr, params.length);
    }

    this.module._wasm_free(ptr);

    if (result !== 0) {
      throw new Error('Failed to import secret params');
    }
  }

  // Multi-authority ABE methods

  exportGlobalParams() {
    const lenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[lenPtr >> 2] = 0;

    const size = this.module._openabe_export_global_params(this.ctx, 0, lenPtr);
    if (size < 0) {
      this.module._wasm_free(lenPtr);
      throw new Error('Failed to export global params');
    }

    const ptr = this.module._wasm_malloc(size);
    this.module.HEAPU32[lenPtr >> 2] = size;
    this.module._openabe_export_global_params(this.ctx, ptr, lenPtr);

    const actualLen = this.module.HEAPU32[lenPtr >> 2];
    const params = new Uint8Array(actualLen);
    params.set(readBuffer(this.module, ptr, actualLen));

    this.module._wasm_free(ptr);
    this.module._wasm_free(lenPtr);

    return params;
  }

  importGlobalParams(params) {
    const ptr = this.module._wasm_malloc(params.length);
    this.module.HEAPU8.set(params, ptr);

    const result = this.module._openabe_import_global_params(this.ctx, ptr, params.length);
    this.module._wasm_free(ptr);

    if (result !== 0) {
      throw new Error('Failed to import global params');
    }
  }

  importPublicParamsWithAuthority(authId, params) {
    const authIdStr = allocateString(this.module, authId);
    const ptr = this.module._wasm_malloc(params.length);
    this.module.HEAPU8.set(params, ptr);

    const result = this.module._openabe_import_public_params_with_authority(
      this.ctx,
      authIdStr.ptr,
      ptr,
      params.length
    );

    this.module._wasm_free(authIdStr.ptr);
    this.module._wasm_free(ptr);

    if (result !== 0) {
      throw new Error('Failed to import public params for authority');
    }
  }

  importSecretParamsWithAuthority(authId, params) {
    const authIdStr = allocateString(this.module, authId);
    const ptr = this.module._wasm_malloc(params.length);
    this.module.HEAPU8.set(params, ptr);

    const result = this.module._openabe_import_secret_params_with_authority(
      this.ctx,
      authIdStr.ptr,
      ptr,
      params.length
    );

    this.module._wasm_free(authIdStr.ptr);
    this.module._wasm_free(ptr);

    if (result !== 0) {
      throw new Error('Failed to import secret params for authority');
    }
  }

  exportUserKey(keyId) {
    const keyIdStr = allocateString(this.module, keyId);
    const lenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[lenPtr >> 2] = 0;

    const size = this.module._openabe_export_user_key(this.ctx, keyIdStr.ptr, 0, lenPtr);
    if (size < 0) {
      this.module._wasm_free(keyIdStr.ptr);
      this.module._wasm_free(lenPtr);
      throw new Error('Failed to export user key');
    }

    const ptr = this.module._wasm_malloc(size);
    this.module.HEAPU32[lenPtr >> 2] = size;
    this.module._openabe_export_user_key(this.ctx, keyIdStr.ptr, ptr, lenPtr);

    const actualLen = this.module.HEAPU32[lenPtr >> 2];
    const keyBlob = new Uint8Array(actualLen);
    keyBlob.set(readBuffer(this.module, ptr, actualLen));

    this.module._wasm_free(keyIdStr.ptr);
    this.module._wasm_free(ptr);
    this.module._wasm_free(lenPtr);

    return keyBlob;
  }

  importUserKey(keyId, keyBlob) {
    const keyIdStr = allocateString(this.module, keyId);
    const ptr = this.module._wasm_malloc(keyBlob.length);
    this.module.HEAPU8.set(keyBlob, ptr);

    const result = this.module._openabe_import_user_key(
      this.ctx,
      keyIdStr.ptr,
      ptr,
      keyBlob.length
    );

    this.module._wasm_free(keyIdStr.ptr);
    this.module._wasm_free(ptr);

    if (result !== 0) {
      throw new Error('Failed to import user key');
    }
  }

  deleteKey(keyId) {
    const keyIdStr = allocateString(this.module, keyId);
    const result = this.module._openabe_delete_key(this.ctx, keyIdStr.ptr);
    this.module._wasm_free(keyIdStr.ptr);

    return result === 0;
  }

  destroy() {
    if (this.ctx !== 0) {
      this.module._openabe_destroy_context(this.ctx);
      this.ctx = 0;
    }
  }
}

/**
 * Initialize OpenABE library
 */
function initOpenABE(module) {
  const result = module._openabe_init();
  if (result !== 0) {
    throw new Error('Failed to initialize OpenABE');
  }
}

/**
 * Shutdown OpenABE library
 */
function shutdownOpenABE(module) {
  module._openabe_shutdown();
}

/**
 * Public-Key Encryption (PKE) context wrapper
 */
class OpenPKEContext {
  constructor(module, curve = 'NIST_P256') {
    this.module = module;
    const curveStr = allocateString(module, curve);
    this.ctx = module._openabe_create_pke_context(curveStr.ptr);
    module._wasm_free(curveStr.ptr);

    if (this.ctx === 0) {
      throw new Error('Failed to create PKE context');
    }
  }

  keygen(keyId) {
    const keyIdStr = allocateString(this.module, keyId);
    const result = this.module._openabe_pke_keygen(this.ctx, keyIdStr.ptr);
    this.module._wasm_free(keyIdStr.ptr);

    if (result !== 0) {
      throw new Error('Failed to generate keypair');
    }
  }

  encrypt(receiverId, plaintext) {
    const receiverIdStr = allocateString(this.module, receiverId);

    let ptPtr, ptLen;
    if (typeof plaintext === 'string') {
      const ptStr = allocateString(this.module, plaintext);
      ptPtr = ptStr.ptr;
      ptLen = ptStr.len - 1;
    } else {
      ptLen = plaintext.length;
      ptPtr = this.module._wasm_malloc(ptLen);
      this.module.HEAPU8.set(plaintext, ptPtr);
    }

    // Get required size
    const ctLenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[ctLenPtr >> 2] = 0;
    let ctSize = this.module._openabe_pke_encrypt(
      this.ctx,
      receiverIdStr.ptr,
      ptPtr,
      ptLen,
      0,
      ctLenPtr
    );

    if (ctSize < 0) {
      this.module._wasm_free(receiverIdStr.ptr);
      this.module._wasm_free(ptPtr);
      this.module._wasm_free(ctLenPtr);
      throw new Error('Encryption failed');
    }

    // Encrypt
    const ctPtr = this.module._wasm_malloc(ctSize);
    this.module.HEAPU32[ctLenPtr >> 2] = ctSize;
    this.module._openabe_pke_encrypt(
      this.ctx,
      receiverIdStr.ptr,
      ptPtr,
      ptLen,
      ctPtr,
      ctLenPtr
    );

    const actualCtLen = this.module.HEAPU32[ctLenPtr >> 2];
    const ciphertext = new Uint8Array(actualCtLen);
    ciphertext.set(readBuffer(this.module, ctPtr, actualCtLen));

    this.module._wasm_free(receiverIdStr.ptr);
    this.module._wasm_free(ptPtr);
    this.module._wasm_free(ctPtr);
    this.module._wasm_free(ctLenPtr);

    return ciphertext;
  }

  decrypt(receiverId, ciphertext) {
    const receiverIdStr = allocateString(this.module, receiverId);
    const ctPtr = this.module._wasm_malloc(ciphertext.length);
    this.module.HEAPU8.set(ciphertext, ctPtr);

    // Get required size
    const ptLenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[ptLenPtr >> 2] = 0;
    let ptSize = this.module._openabe_pke_decrypt(
      this.ctx,
      receiverIdStr.ptr,
      ctPtr,
      ciphertext.length,
      0,
      ptLenPtr
    );

    if (ptSize < 0) {
      this.module._wasm_free(receiverIdStr.ptr);
      this.module._wasm_free(ctPtr);
      this.module._wasm_free(ptLenPtr);
      return null;
    }

    // Decrypt
    const ptPtr = this.module._wasm_malloc(ptSize);
    this.module.HEAPU32[ptLenPtr >> 2] = ptSize;
    this.module._openabe_pke_decrypt(
      this.ctx,
      receiverIdStr.ptr,
      ctPtr,
      ciphertext.length,
      ptPtr,
      ptLenPtr
    );

    const actualPtLen = this.module.HEAPU32[ptLenPtr >> 2];
    const plaintext = new Uint8Array(actualPtLen);
    plaintext.set(readBuffer(this.module, ptPtr, actualPtLen));

    this.module._wasm_free(receiverIdStr.ptr);
    this.module._wasm_free(ctPtr);
    this.module._wasm_free(ptPtr);
    this.module._wasm_free(ptLenPtr);

    return plaintext;
  }

  exportPublicKey(keyId) {
    const keyIdStr = allocateString(this.module, keyId);
    const lenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[lenPtr >> 2] = 0;

    const size = this.module._openabe_pke_export_public_key(this.ctx, keyIdStr.ptr, 0, lenPtr);
    if (size < 0) {
      this.module._wasm_free(keyIdStr.ptr);
      this.module._wasm_free(lenPtr);
      throw new Error('Failed to export public key');
    }

    const ptr = this.module._wasm_malloc(size);
    this.module.HEAPU32[lenPtr >> 2] = size;
    this.module._openabe_pke_export_public_key(this.ctx, keyIdStr.ptr, ptr, lenPtr);

    const actualLen = this.module.HEAPU32[lenPtr >> 2];
    const key = new Uint8Array(actualLen);
    key.set(readBuffer(this.module, ptr, actualLen));

    this.module._wasm_free(keyIdStr.ptr);
    this.module._wasm_free(ptr);
    this.module._wasm_free(lenPtr);

    return key;
  }

  importPublicKey(keyId, keyBlob) {
    const keyIdStr = allocateString(this.module, keyId);
    const ptr = this.module._wasm_malloc(keyBlob.length);
    this.module.HEAPU8.set(keyBlob, ptr);

    const result = this.module._openabe_pke_import_public_key(
      this.ctx,
      keyIdStr.ptr,
      ptr,
      keyBlob.length
    );

    this.module._wasm_free(keyIdStr.ptr);
    this.module._wasm_free(ptr);

    if (result !== 0) {
      throw new Error('Failed to import public key');
    }
  }

  exportPrivateKey(keyId) {
    const keyIdStr = allocateString(this.module, keyId);
    const lenPtr = this.module._wasm_malloc(4);
    this.module.HEAPU32[lenPtr >> 2] = 0;

    const size = this.module._openabe_pke_export_private_key(this.ctx, keyIdStr.ptr, 0, lenPtr);
    if (size < 0) {
      this.module._wasm_free(keyIdStr.ptr);
      this.module._wasm_free(lenPtr);
      throw new Error('Failed to export private key');
    }

    const ptr = this.module._wasm_malloc(size);
    this.module.HEAPU32[lenPtr >> 2] = size;
    this.module._openabe_pke_export_private_key(this.ctx, keyIdStr.ptr, ptr, lenPtr);

    const actualLen = this.module.HEAPU32[lenPtr >> 2];
    const key = new Uint8Array(actualLen);
    key.set(readBuffer(this.module, ptr, actualLen));

    this.module._wasm_free(keyIdStr.ptr);
    this.module._wasm_free(ptr);
    this.module._wasm_free(lenPtr);

    return key;
  }

  importPrivateKey(keyId, keyBlob) {
    const keyIdStr = allocateString(this.module, keyId);
    const ptr = this.module._wasm_malloc(keyBlob.length);
    this.module.HEAPU8.set(keyBlob, ptr);

    const result = this.module._openabe_pke_import_private_key(
      this.ctx,
      keyIdStr.ptr,
      ptr,
      keyBlob.length
    );

    this.module._wasm_free(keyIdStr.ptr);
    this.module._wasm_free(ptr);

    if (result !== 0) {
      throw new Error('Failed to import private key');
    }
  }

  destroy() {
    if (this.ctx !== 0) {
      this.module._openabe_destroy_pke_context(this.ctx);
      this.ctx = 0;
    }
  }
}

// Export for use in Node.js or browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    OpenABEContext,
    OpenPKEContext,
    initOpenABE,
    shutdownOpenABE
  };
}
