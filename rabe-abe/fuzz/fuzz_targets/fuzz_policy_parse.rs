#![no_main]

use libfuzzer_sys::fuzz_target;
use rabe_abe::schemes::waters;

// Fuzz the policy parsing path
// This tests that malformed policies don't cause panics
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse the policy string
        let _ = waters::parse_policy(s);
    }
});
