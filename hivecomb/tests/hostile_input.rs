//! Every parser reachable from untrusted bytes, fed garbage.
//!
//! A node's response, a memo pasted from a comment, a WIF from a config file and a
//! transaction from another client are all attacker-influenced. A parser that panics on
//! one of them is a denial of service in whatever process is doing the parsing — and in
//! a signing service, that process is the one holding the keys.
//!
//! So the contract is: **every one of these returns `Err`, and none of them panic.**
//! Eight `unwrap()` calls survive in non-test code, all of them on `try_into()` after a
//! length has been checked or after `Reader::take` has guaranteed one. This test is the
//! evidence that the reasoning is right, rather than the reasoning itself.
//!
//! Not a fuzzer. It is a deterministic sweep, cheap enough to run on every commit; a
//! real fuzzing target would be a good addition and is not here yet.

use hivecomb::operations::Operation;
use hivecomb::{Chain, PrivateKey, PublicKey, Transaction};

/// A tiny deterministic PRNG. `rand` is a dependency of the crate, but a fixed
/// generator keeps a failure reproducible from the seed printed in the message.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() & 0xff) as u8).collect()
    }
}

/// Random bytes of many lengths, including the boundaries each parser cares about.
fn corpus(seed: u64) -> Vec<Vec<u8>> {
    let mut rng = Rng(seed);
    let mut cases = vec![
        vec![],
        vec![0],
        vec![0xff],
        vec![0x80; 10],   // varint continuation bits, forever
        vec![0xff; 1024], // every length prefix implausibly large
        vec![0x00; 78],   // exactly the memo header length, all zero
    ];
    for len in [
        1, 2, 3, 4, 8, 16, 32, 33, 34, 64, 65, 66, 77, 78, 79, 128, 512,
    ] {
        for _ in 0..24 {
            cases.push(rng.bytes(len));
        }
    }
    cases
}

#[test]
fn no_parser_panics_on_hostile_bytes() {
    for (index, bytes) in corpus(0x5EED_1234).into_iter().enumerate() {
        let ctx = format!("case {index}, {} bytes", bytes.len());

        // A transaction from another client, or a corrupted one.
        let _ = Transaction::from_body_bytes(&bytes, Chain::Hive);

        // An operation off the wire, via the deserializer trait.
        {
            let mut reader = hivecomb::Reader::new(&bytes, Chain::Hive);
            let _ = <Operation as hivecomb::GrapheneDeserialize>::read_from(&mut reader);
        }

        // A public key from a node response.
        let _ = PublicKey::from_bytes(&bytes);

        // Anything that takes text, given bytes that may not even be UTF-8.
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let _ = PublicKey::from_prefixed_any(text);
            let _ = PublicKey::from_hex(text);
            let _ = PrivateKey::from_wif(text);
            let _ = hivecomb::base58::decode_check(text);

            #[cfg(feature = "memo")]
            {
                let _ = hivecomb::memo::decode(&test_key(), text);
                let _ = hivecomb::memo::EncryptedMemo::from_memo_string(text);
                let _ = hivecomb::memo::is_encrypted(text);
            }
        }

        #[cfg(feature = "memo")]
        {
            let _ = hivecomb::memo::EncryptedMemo::from_wire(&bytes);
        }

        // If any of the above panicked we never reach here, and the harness reports
        // which case it was.
        assert!(!ctx.is_empty());
    }
}

#[cfg(feature = "memo")]
fn test_key() -> PrivateKey {
    PrivateKey::from_wif("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")
        .expect("the published test key parses")
}

#[test]
fn truncating_a_valid_transaction_never_panics() {
    // Truncation is the realistic corruption: a short read, a clipped field. Every
    // prefix of a well-formed transaction must be refused rather than misparsed.
    let key = PrivateKey::from_wif("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")
        .expect("test key");
    let block_ref = hivecomb::BlockRef::from_block_id("00000005aabbccdd00000000000000000000abcd")
        .expect("block ref");
    let tx = Transaction::new(
        block_ref,
        vec![Operation::Transfer(hivecomb::operations::Transfer {
            from: "alice".into(),
            to: "bob".into(),
            amount: hivecomb::Amount::parse("1.234 HIVE", Chain::Hive).expect("amount"),
            memo: "a memo long enough to span a few truncation points".into(),
        })],
        60,
    )
    .expect("transaction");

    let signed = tx.clone().sign(&[key], Chain::Hive).expect("sign");
    let full = tx.body_bytes().expect("body bytes");

    for cut in 0..full.len() {
        // Must not panic. Almost all of these are errors; a prefix that happens to be
        // a shorter valid transaction is acceptable, being refused is acceptable, and
        // panicking is not.
        let _ = Transaction::from_body_bytes(&full[..cut], Chain::Hive);
    }

    // And a bit-flip anywhere must not panic either.
    for position in 0..full.len() {
        let mut corrupted = full.clone();
        corrupted[position] ^= 0x01;
        let _ = Transaction::from_body_bytes(&corrupted, Chain::Hive);
    }

    // Sanity: the untouched bytes really are parseable, so the loops above were not
    // vacuously testing a parser that rejects everything.
    let reparsed = Transaction::from_body_bytes(&full, Chain::Hive).expect("round trip");
    assert_eq!(reparsed, signed.transaction);
}
