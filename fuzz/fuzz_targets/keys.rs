//! Key parsing, from text a user or a config file supplied.
//!
//! base58 with a checksum is exactly the kind of format where a length or an index goes
//! wrong on malformed input. beem's `base58decode` folded an unknown character's `-1`
//! into the accumulator and decoded to wrong bytes rather than raising
//! (SECURITY_FINDINGS.md finding 11).
#![no_main]

use hivecomb::{PrivateKey, PublicKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = PublicKey::from_bytes(data);

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = PrivateKey::from_wif(text);
        let _ = PublicKey::from_prefixed_any(text);
        let _ = PublicKey::from_hex(text);
        let _ = hivecomb::base58::decode_check(text);

        // A key that parses must render back to the text it came from.
        if let Ok(key) = PublicKey::from_prefixed_any(text) {
            assert_eq!(key.to_string(), text.trim(), "public key did not round trip");
        }
    }
});
