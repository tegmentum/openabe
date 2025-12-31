#![no_main]

use libfuzzer_sys::fuzz_target;
use rabe_abe::cbor;

// Fuzz all CBOR decoding paths
// This tests that malformed CBOR doesn't cause panics
fuzz_target!(|data: &[u8]| {
    // Try decoding as various ABE structures
    let _ = cbor::decode_mpk(data);
    let _ = cbor::decode_msk(data);
    let _ = cbor::decode_sk(data);
    let _ = cbor::decode_ciphertext(data);
    let _ = cbor::decode_cca_ciphertext(data);
});
