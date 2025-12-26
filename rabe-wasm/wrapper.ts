/**
 * OpenABE-RABE TypeScript Wrapper
 *
 * Provides a clean TypeScript API for the RABE WASM module.
 */

// Types for the underlying WASM module
interface WasmResult {
    success: boolean;
    data: string;
    error: string;
}

interface WasmModule {
    test_wasm(): string;
    test_bsw_roundtrip(): WasmResult;
    bsw_setup(): WasmResult;
    bsw_keygen(mpk: string, msk: string, attrs: string): WasmResult;
    bsw_encrypt(mpk: string, policy: string, plaintext: string): WasmResult;
    bsw_decrypt(sk: string, ct: string): WasmResult;
    ac17_cp_setup(): WasmResult;
    ac17_cp_keygen(mpk: string, msk: string, attrs: string): WasmResult;
    ac17_cp_encrypt(mpk: string, policy: string, plaintext: string): WasmResult;
    ac17_cp_decrypt(sk: string, ct: string): WasmResult;
}

// Key types
export interface MasterPublicKey {
    scheme: string;
    data: string;
}

export interface MasterSecretKey {
    scheme: string;
    data: string;
}

export interface UserSecretKey {
    scheme: string;
    attributes: string[];
    data: string;
}

export interface Ciphertext {
    scheme: string;
    policy: string;
    data: string;
}

export interface MasterKeys {
    mpk: MasterPublicKey;
    msk: MasterSecretKey;
}

// Error type
export class AbeError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'AbeError';
    }
}

// ABE Scheme interface
export interface AbeScheme {
    setup(): MasterKeys;
    keygen(mpk: MasterPublicKey, msk: MasterSecretKey, attributes: string[]): UserSecretKey;
    encrypt(mpk: MasterPublicKey, policy: string, plaintext: Uint8Array): Ciphertext;
    decrypt(sk: UserSecretKey, ct: Ciphertext): Uint8Array;
}

// Helper to encode/decode base64
function toBase64(data: Uint8Array): string {
    if (typeof btoa === 'function') {
        // Browser
        return btoa(String.fromCharCode(...data));
    } else {
        // Node.js
        return Buffer.from(data).toString('base64');
    }
}

function fromBase64(str: string): Uint8Array {
    if (typeof atob === 'function') {
        // Browser
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    } else {
        // Node.js
        return new Uint8Array(Buffer.from(str, 'base64'));
    }
}

/**
 * BSW CP-ABE Scheme
 *
 * Implementation of the Bethencourt-Sahai-Waters Ciphertext-Policy ABE scheme.
 */
export class BswCpAbe implements AbeScheme {
    private wasm: WasmModule;

    constructor(wasm: WasmModule) {
        this.wasm = wasm;
    }

    /**
     * Generate master public and secret keys
     */
    setup(): MasterKeys {
        const result = this.wasm.bsw_setup();
        if (!result.success) {
            throw new AbeError(`Setup failed: ${result.error}`);
        }
        return JSON.parse(result.data);
    }

    /**
     * Generate a user secret key for the given attributes
     *
     * @param mpk Master public key
     * @param msk Master secret key
     * @param attributes User attributes (without quotes)
     */
    keygen(mpk: MasterPublicKey, msk: MasterSecretKey, attributes: string[]): UserSecretKey {
        const result = this.wasm.bsw_keygen(
            JSON.stringify(mpk),
            JSON.stringify(msk),
            JSON.stringify(attributes)
        );
        if (!result.success) {
            throw new AbeError(`Keygen failed: ${result.error}`);
        }
        return JSON.parse(result.data);
    }

    /**
     * Encrypt plaintext under an access policy
     *
     * @param mpk Master public key
     * @param policy Access policy (e.g., '"admin" and "developer"')
     * @param plaintext Data to encrypt
     */
    encrypt(mpk: MasterPublicKey, policy: string, plaintext: Uint8Array): Ciphertext {
        const result = this.wasm.bsw_encrypt(
            JSON.stringify(mpk),
            policy,
            toBase64(plaintext)
        );
        if (!result.success) {
            throw new AbeError(`Encrypt failed: ${result.error}`);
        }
        return JSON.parse(result.data);
    }

    /**
     * Decrypt ciphertext using a user secret key
     *
     * @param sk User secret key
     * @param ct Ciphertext
     */
    decrypt(sk: UserSecretKey, ct: Ciphertext): Uint8Array {
        const result = this.wasm.bsw_decrypt(
            JSON.stringify(sk),
            JSON.stringify(ct)
        );
        if (!result.success) {
            throw new AbeError(`Decrypt failed: ${result.error}`);
        }
        return fromBase64(result.data);
    }
}

/**
 * AC17 CP-ABE Scheme
 *
 * Implementation of the Agrawal-Chase 2017 Ciphertext-Policy ABE scheme.
 */
export class Ac17CpAbe implements AbeScheme {
    private wasm: WasmModule;

    constructor(wasm: WasmModule) {
        this.wasm = wasm;
    }

    /**
     * Generate master public and secret keys
     */
    setup(): MasterKeys {
        const result = this.wasm.ac17_cp_setup();
        if (!result.success) {
            throw new AbeError(`Setup failed: ${result.error}`);
        }
        return JSON.parse(result.data);
    }

    /**
     * Generate a user secret key for the given attributes
     */
    keygen(mpk: MasterPublicKey, msk: MasterSecretKey, attributes: string[]): UserSecretKey {
        const result = this.wasm.ac17_cp_keygen(
            JSON.stringify(mpk),
            JSON.stringify(msk),
            JSON.stringify(attributes)
        );
        if (!result.success) {
            throw new AbeError(`Keygen failed: ${result.error}`);
        }
        return JSON.parse(result.data);
    }

    /**
     * Encrypt plaintext under an access policy
     */
    encrypt(mpk: MasterPublicKey, policy: string, plaintext: Uint8Array): Ciphertext {
        const result = this.wasm.ac17_cp_encrypt(
            JSON.stringify(mpk),
            policy,
            toBase64(plaintext)
        );
        if (!result.success) {
            throw new AbeError(`Encrypt failed: ${result.error}`);
        }
        return JSON.parse(result.data);
    }

    /**
     * Decrypt ciphertext using a user secret key
     */
    decrypt(sk: UserSecretKey, ct: Ciphertext): Uint8Array {
        const result = this.wasm.ac17_cp_decrypt(
            JSON.stringify(sk),
            JSON.stringify(ct)
        );
        if (!result.success) {
            throw new AbeError(`Decrypt failed: ${result.error}`);
        }
        return fromBase64(result.data);
    }
}

/**
 * Main OpenABE class
 *
 * Entry point for using ABE schemes.
 */
export class OpenAbe {
    private wasm: WasmModule;

    public readonly bsw: BswCpAbe;
    public readonly ac17: Ac17CpAbe;

    constructor(wasm: WasmModule) {
        this.wasm = wasm;
        this.bsw = new BswCpAbe(wasm);
        this.ac17 = new Ac17CpAbe(wasm);
    }

    /**
     * Test that the WASM module is working
     */
    test(): string {
        return this.wasm.test_wasm();
    }
}

/**
 * Initialize the OpenABE library
 *
 * @param initFn The init function from the WASM module
 * @param wasm The WASM module exports
 */
export async function initOpenAbe(
    initFn: (input?: any) => Promise<any>,
    wasm: WasmModule
): Promise<OpenAbe> {
    await initFn();
    return new OpenAbe(wasm);
}

// Export types for external use
export type { WasmResult, WasmModule };
