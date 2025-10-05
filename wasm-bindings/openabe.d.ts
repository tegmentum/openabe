/**
 * TypeScript definitions for OpenABE WebAssembly module
 */

export interface OpenABEModule {
  // Memory management
  _wasm_malloc(size: number): number;
  _wasm_free(ptr: number): void;

  // Library initialization
  _openabe_init(): number;
  _openabe_shutdown(): number;

  // Context management
  _openabe_create_context(scheme_id: number): number;
  _openabe_destroy_context(ctx: number): void;

  // Key generation and setup
  _openabe_generate_params(ctx: number): number;
  _openabe_keygen(ctx: number, attributes: number, key_id: number): number;

  // Encryption/Decryption
  _openabe_encrypt(
    ctx: number,
    policy: number,
    plaintext: number,
    pt_len: number,
    ciphertext_out: number,
    ct_len: number
  ): number;

  _openabe_decrypt(
    ctx: number,
    key_id: number,
    ciphertext: number,
    ct_len: number,
    plaintext_out: number,
    pt_len: number
  ): number;

  // Import/Export parameters
  _openabe_export_public_params(ctx: number, output: number, output_len: number): number;
  _openabe_import_public_params(ctx: number, params: number, params_len: number): number;
  _openabe_export_secret_params(ctx: number, output: number, output_len: number): number;
  _openabe_import_secret_params(ctx: number, params: number, params_len: number): number;

  // WASM memory access
  HEAPU8: Uint8Array;
  UTF8ToString(ptr: number): string;
  stringToUTF8(str: string, outPtr: number, maxBytesToWrite: number): void;
  lengthBytesUTF8(str: string): number;
}

/**
 * High-level TypeScript wrapper for OpenABE
 */
export class OpenABEContext {
  private module: OpenABEModule;
  private ctx: number;

  constructor(module: OpenABEModule, scheme: 'CP-ABE' | 'KP-ABE' | 'PK');

  generateParams(): void;

  keygen(attributes: string, keyId: string): void;

  encrypt(policy: string, plaintext: string | Uint8Array): Uint8Array;

  decrypt(keyId: string, ciphertext: Uint8Array): Uint8Array | null;

  exportPublicParams(): Uint8Array;

  importPublicParams(params: Uint8Array): void;

  exportSecretParams(): Uint8Array;

  importSecretParams(params: Uint8Array): void;

  destroy(): void;
}

/**
 * Initialize the OpenABE library
 */
export function initOpenABE(module: OpenABEModule): void;

/**
 * Shutdown the OpenABE library
 */
export function shutdownOpenABE(module: OpenABEModule): void;
