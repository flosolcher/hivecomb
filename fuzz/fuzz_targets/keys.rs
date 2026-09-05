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

        // A key that parses must render back to the text it came from -- under the
        // prefix it came in with.
        //
        // `Display` always renders `STM`, deliberately: a public key is a curve point
        // and does not carry which chain's prefix it was written under, so a testnet
        // `TST...` key round-trips to `STM...` and is not wrong to. Asserting against
        // `to_string` therefore reported a defect against a key that had survived
        // perfectly -- the fuzzer found a valid `TST` key wrapped in whitespace.
        if let Ok(key) = PublicKey::from_prefixed_any(text) {
            let trimmed = text.trim();
            let prefix = ["STM", "TST", "STX"]
                .into_iter()
                .find(|p| trimmed.starts_with(p))
                .expect("from_prefixed_any accepted it, so one of these matched");
            assert_eq!(
                key.to_prefixed(prefix),
                trimmed,
                "public key did not round trip"
            );
        }
    }
});
