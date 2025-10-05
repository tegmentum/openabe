/**
 * OpenABE Web Worker
 * Handles cryptographic operations in a separate thread
 */

// Import the main OpenABE wrapper
importScripts('openabe-wrapper.js');

let wasmModule = null;
let contexts = new Map(); // Store multiple contexts

// Initialize on first message
let initialized = false;

// Message handler
self.onmessage = async function(e) {
    const { jobId, type, ...params } = e.data;

    try {
        // Initialize WASM module if needed
        if (!initialized) {
            await initializeWASM();
            initialized = true;
        }

        let result;

        switch(type) {
            case 'init-context':
                result = await initContext(params);
                break;

            case 'generate-params':
                result = await generateParams(params);
                break;

            case 'keygen':
                result = await keygen(params);
                break;

            case 'encrypt':
                result = await encrypt(params);
                break;

            case 'decrypt':
                result = await decrypt(params);
                break;

            case 'export-params':
                result = await exportParams(params);
                break;

            case 'import-params':
                result = await importParams(params);
                break;

            default:
                throw new Error(`Unknown task type: ${type}`);
        }

        self.postMessage({ jobId, result });

    } catch (error) {
        self.postMessage({
            jobId,
            error: error.message || String(error)
        });
    }
};

// Initialize WASM module
async function initializeWASM() {
    // Fetch and instantiate WASM
    const response = await fetch('openabe.wasm');
    const wasmBytes = await response.arrayBuffer();
    const wasmResult = await WebAssembly.instantiate(wasmBytes);

    wasmModule = wasmResult.instance.exports;
    initOpenABE(wasmModule);
}

// Create a new context
async function initContext({ contextId, scheme, curve }) {
    let context;

    if (scheme === 'PK' || scheme === 'PKE') {
        context = new OpenPKEContext(wasmModule, curve || 'NIST_P256');
    } else {
        context = new OpenABEContext(wasmModule, scheme);
    }

    contexts.set(contextId, context);

    return { contextId, success: true };
}

// Generate parameters
async function generateParams({ contextId }) {
    const ctx = contexts.get(contextId);
    if (!ctx) throw new Error('Context not found');

    ctx.generateParams();

    return { success: true };
}

// Generate key
async function keygen({ contextId, attributes, keyId, authId, gid }) {
    const ctx = contexts.get(contextId);
    if (!ctx) throw new Error('Context not found');

    ctx.keygen(attributes, keyId, authId || null, gid || null);

    return { keyId, success: true };
}

// Encrypt
async function encrypt({ contextId, policy, plaintext }) {
    const ctx = contexts.get(contextId);
    if (!ctx) throw new Error('Context not found');

    // Convert plaintext string to Uint8Array if needed
    let ptData = plaintext;
    if (typeof plaintext === 'string') {
        ptData = new TextEncoder().encode(plaintext);
    }

    const ciphertext = ctx.encrypt(policy, ptData);

    // Convert to transferable array
    return {
        ciphertext: Array.from(ciphertext),
        success: true
    };
}

// Decrypt
async function decrypt({ contextId, keyId, ciphertext }) {
    const ctx = contexts.get(contextId);
    if (!ctx) throw new Error('Context not found');

    // Convert array back to Uint8Array
    const ctData = new Uint8Array(ciphertext);

    const plaintext = ctx.decrypt(keyId, ctData);

    if (plaintext === null) {
        return { success: false, error: 'Decryption failed' };
    }

    return {
        plaintext: Array.from(plaintext),
        success: true
    };
}

// Export parameters
async function exportParams({ contextId, type }) {
    const ctx = contexts.get(contextId);
    if (!ctx) throw new Error('Context not found');

    let params;

    switch(type) {
        case 'public':
            params = ctx.exportPublicParams();
            break;
        case 'secret':
            params = ctx.exportSecretParams();
            break;
        case 'global':
            params = ctx.exportGlobalParams();
            break;
        default:
            throw new Error(`Unknown export type: ${type}`);
    }

    return {
        params: Array.from(params),
        success: true
    };
}

// Import parameters
async function importParams({ contextId, type, params, authId }) {
    const ctx = contexts.get(contextId);
    if (!ctx) throw new Error('Context not found');

    const paramsData = new Uint8Array(params);

    switch(type) {
        case 'public':
            if (authId) {
                ctx.importPublicParamsWithAuthority(authId, paramsData);
            } else {
                ctx.importPublicParams(paramsData);
            }
            break;

        case 'secret':
            if (authId) {
                ctx.importSecretParamsWithAuthority(authId, paramsData);
            } else {
                ctx.importSecretParams(paramsData);
            }
            break;

        case 'global':
            ctx.importGlobalParams(paramsData);
            break;

        default:
            throw new Error(`Unknown import type: ${type}`);
    }

    return { success: true };
}

// Cleanup on termination
self.onclose = function() {
    // Destroy all contexts
    for (const [id, ctx] of contexts) {
        ctx.destroy();
    }
    contexts.clear();

    if (wasmModule) {
        shutdownOpenABE(wasmModule);
    }
};
