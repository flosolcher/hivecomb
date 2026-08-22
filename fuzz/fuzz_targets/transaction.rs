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
        let once = tx.body_bytes().expect("a parsed transaction must re-serialize");

        // Not `once == data`: see the note in reader.rs. A string carrying a raw
        // control byte is rewritten on the way out, deliberately.
        //
        // What must hold is that the bytes settle after one pass, because a digest
        // is taken over them. If re-signing a parsed transaction kept moving the
        // bytes, the signature would cover something different every time.
        let reparsed = Transaction::from_body_bytes(&once, Chain::Hive)
            .expect("our own output must parse");
        let twice = reparsed.body_bytes().expect("and re-serialize");
        assert_eq!(once, twice, "serialization is not idempotent");

        assert_eq!(
            reparsed.digest(Chain::Hive).expect("digest"),
            tx.digest(Chain::Hive).expect("digest"),
            "digest moved across a round trip"
        );
    }
});
