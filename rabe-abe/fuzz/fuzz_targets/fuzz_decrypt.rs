#![no_main]

use libfuzzer_sys::fuzz_target;
use rabe_abe::cbor;

// Fuzz the ciphertext decoding path
// This tests that malformed ciphertext doesn't cause panics
fuzz_target!(|data: &[u8]| {
    // Try to decode as ciphertext
    let _ = cbor::decode_ciphertext(data);
});
