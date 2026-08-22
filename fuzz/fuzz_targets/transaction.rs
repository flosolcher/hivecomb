//! Whole transactions off the wire.
//!
//! A transaction can arrive from another client, a cold-signing device, or a file. It
//! is never trusted input. Beyond not panicking, anything that parses must re-serialize
//! to exactly the bytes it came from: the digest is taken over those bytes, so a round
//! trip that changes them changes what a signature covers.
#![no_main]

use hivecomb::{Chain, Transaction};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = Transaction::from_body_bytes(data, Chain::Hive) {
        let reencoded = tx.body_bytes().expect("a parsed transaction must re-serialize");
        assert_eq!(&reencoded[..], data, "round trip changed the signed bytes");

        // And the digest must be reproducible from the same transaction.
        let first = tx.digest(Chain::Hive).expect("digest");
        let second = tx.digest(Chain::Hive).expect("digest");
        assert_eq!(first, second, "digest is not deterministic");
    }
});
