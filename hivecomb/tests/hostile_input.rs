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

use hivecomb::operations::{BlockId, HexBytes, Operation};
use hivecomb::{
    BlockRef, Chain, ChainId, GrapheneDeserialize, GrapheneSerialize, PrivateKey, PublicKey,
    Signature, Transaction,
};

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

/// Every hex parser, fed text whose byte length is right and whose char boundaries are
/// not.
///
/// Each of these checked `s.len()` -- a count of **bytes** -- and then sliced
/// `&s[i * 2..i * 2 + 2]`, which demands **char boundaries**. One two-byte character in
/// place of two ASCII ones keeps the byte length correct and puts a slice boundary
/// inside it, and the slice panicked. Four of the five checked an exact length first,
/// which is exactly why that check is no protection: 61 ASCII characters plus one
/// two-byte character is still 64 bytes.
///
/// `fuzz/fuzz_targets/keys.rs` found this in `PublicKey::from_hex` on its first real
/// run. The other four were found by looking for the same shape, and this test is here
/// so that neither the shape nor the reasoning has to be trusted again.
#[test]
fn hex_parsers_do_not_panic_on_multibyte_text_of_the_right_byte_length() {
    // U+041E is two bytes, so each of these is the exact byte length its parser demands
    // while being one character short of it.
    // Bound outside the `format!`: the braces of a `\u{..}` escape would be read as
    // a placeholder inside one.
    const TWO_BYTE: char = '\u{041e}';
    let chain_id = format!("{}{TWO_BYTE}b", "a".repeat(61)); //  64 bytes
    let signature = format!("{}{TWO_BYTE}b", "a".repeat(127)); // 130 bytes
    let private_key = format!("{}{TWO_BYTE}b", "a".repeat(61)); //  64 bytes
    let block_id = format!("{}{TWO_BYTE}b", "a".repeat(37)); //  40 bytes
    let public_key = format!("{}{TWO_BYTE}b", "a".repeat(63)); //  66 bytes, even

    assert_eq!(
        chain_id.len(),
        64,
        "the byte-length check must be the one that passes"
    );
    assert_eq!(signature.len(), 130);
    assert_eq!(private_key.len(), 64);
    assert_eq!(block_id.len(), 40);

    assert!(ChainId::from_hex(&chain_id).is_err());
    assert!(Signature::from_hex(&signature).is_err());
    assert!(PrivateKey::from_hex(&private_key).is_err());
    assert!(BlockRef::from_block_id(&block_id).is_err());
    assert!(PublicKey::from_hex(&public_key).is_err());
    assert!(BlockId::from_hex(&block_id).is_err());
    assert!(HexBytes::from_hex(&public_key).is_err());

    // And the same parsers still accept what they should, so the above is not a test of
    // five parsers that now reject everything.
    assert!(ChainId::from_hex(&"ab".repeat(32)).is_ok());
    assert!(BlockRef::from_block_id(&"ab".repeat(20)).is_ok());
    assert!(PrivateKey::from_hex(&"11".repeat(32)).is_ok());
    assert!(BlockId::from_hex(&"ab".repeat(20)).is_ok());
    assert!(HexBytes::from_hex("00ff").is_ok());
}

/// Anything that parses must serialize back, and validity is a separate question.
///
/// The two inputs here are the exact bytes `fuzz_targets/reader.rs` and
/// `fuzz_targets/transaction.rs` crashed on the first time the fuzz jobs ran: a
/// `custom_json` with no auths at all, and an `update_proposal_votes` with no proposal
/// ids. Both parse -- hived's deserializer would take them too -- and both used to fail
/// to re-serialize, because this crate folded hived's `validate()` rules into its
/// serializer. The bytes a digest is taken over were therefore not recoverable from the
/// value they had been parsed into.
///
/// hived keeps the two apart and now so does this: reading and writing are structural,
/// `validate()` is the semantic step, and `Transaction::sign` calls it. So both halves
/// are asserted here -- that the round trip works, and that the operations are still
/// refused where refusing them matters.
#[test]
fn parsing_and_serializing_are_inverses_even_for_operations_hived_would_reject() {
    // custom_json, no required_auths and no required_posting_auths.
    let no_auths: &[u8] = &[
        0x12, 0x00, 0x00, 0x05, 0x61, 0x64, 0x69, 0x63, 0x65, 0x06, 0x6d, 0x79, 0x5f, 0x61, 0x70,
        0x70, 0x07, 0x7b, 0x22, 0x61, 0x22, 0x3a, 0x31, 0x7d,
    ];
    let mut reader = hivecomb::Reader::new(no_auths, Chain::Hive);
    let op = Operation::read_from(&mut reader).expect("this parses; hived parses it too");
    let once = op.to_wire().expect("and must serialize back");
    let reparsed = {
        let mut r = hivecomb::Reader::new(&once, Chain::Hive);
        Operation::read_from(&mut r).expect("our own output must parse")
    };
    assert_eq!(
        once,
        reparsed.to_wire().unwrap(),
        "serialization must settle"
    );
    assert!(
        op.validate().is_err(),
        "and validity is still refused, just not by the serializer"
    );

    // update_proposal_votes with an empty proposal_ids list.
    let no_ids: &[u8] = &[
        0x13, 0x00, 0xaa, 0xbb, 0xcc, 0x13, 0x40, 0xf3, 0x1a, 0x6a, 0x01, 0x2d, 0x05, 0x61, 0x00,
        0x41, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let tx = Transaction::from_body_bytes(no_ids, Chain::Hive).expect("this parses too");
    let body = tx.body_bytes().expect("and must serialize back");
    let again = Transaction::from_body_bytes(&body, Chain::Hive).expect("our own output parses");
    assert_eq!(
        body,
        again.body_bytes().unwrap(),
        "serialization must settle"
    );
    assert_eq!(
        tx.digest(Chain::Hive).unwrap(),
        again.digest(Chain::Hive).unwrap(),
        "and the digest must not move across a round trip"
    );
    assert!(
        tx.validate().is_err(),
        "and validity is still refused, just not by the serializer"
    );
}

/// Serializing settles after one pass, even when a string is rewritten on the way out.
///
/// `write_string` puts every string through hived's transport form, so a name holding a
/// raw control byte goes out as the five characters `u0000`. The `flat_set` and
/// `flat_map` fields were sorted on the strings *as given*, which is not the order the
/// bytes ended up in — so parsing this crate's own output and writing it again produced
/// a different transaction. A re-signed transaction would then cover different bytes
/// from the one that was read.
///
/// Both inputs are the exact bytes `fuzz_targets/transaction.rs` and
/// `fuzz_targets/reader.rs` reported as "serialization is not idempotent", once the
/// validation split let them get past the point where they used to stop.
#[test]
fn serializing_settles_after_one_pass_when_strings_are_rewritten() {
    // custom_json whose required_auths contain control bytes, so their transported order
    // differs from their raw order.
    let tx_bytes: &[u8] = &[
        0x05, 0x16, 0xaa, 0xbb, 0xcc, 0xdd, 0x9f, 0x00, 0x00, 0x00, 0x02, 0x12, 0x21, 0x01, 0x24,
        0x05, 0x22, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let tx = Transaction::from_body_bytes(tx_bytes, Chain::Hive).expect("parses");
    let once = tx.body_bytes().expect("serializes");
    let again = Transaction::from_body_bytes(&once, Chain::Hive).expect("our output parses");
    let twice = again.body_bytes().expect("and serializes");
    assert_eq!(once, twice, "serialization must settle after one pass");
    assert_eq!(
        again.digest(Chain::Hive).unwrap(),
        Transaction::from_body_bytes(&twice, Chain::Hive)
            .unwrap()
            .digest(Chain::Hive)
            .unwrap(),
        "so the digest a signature covers stops moving too"
    );

    // witness_set_properties, whose props are a flat_map with the same problem.
    let op_bytes: &[u8] = &[
        0x2a, 0x00, 0x04, 0x01, 0x31, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];
    let mut r = hivecomb::Reader::new(op_bytes, Chain::Hive);
    let op = Operation::read_from(&mut r).expect("parses");
    let once = op.to_wire().expect("serializes");
    let again = {
        let mut r = hivecomb::Reader::new(&once, Chain::Hive);
        Operation::read_from(&mut r).expect("our output parses")
    };
    assert_eq!(
        once,
        again.to_wire().expect("and serializes"),
        "a flat_map must settle too"
    );
}

/// A public key round-trips under the prefix it arrived with, not under `Display`.
///
/// `Display` renders `STM` whatever the key came in as, because a public key is a curve
/// point and does not carry a chain. That is the intended behaviour and it is asserted
/// here so that it stays intended rather than being rediscovered as a defect —
/// `fuzz_targets/keys.rs` reported exactly that against a valid testnet key.
#[test]
fn a_public_key_keeps_its_prefix_only_when_asked_for_it() {
    let testnet = "TST6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV";
    let key = PublicKey::from_prefixed_any(&format!("  {testnet}   ")).expect("whitespace is fine");
    assert_eq!(key.to_prefixed("TST"), testnet, "under its own prefix");
    assert_eq!(
        key.to_string(),
        testnet.replacen("TST", "STM", 1),
        "and as mainnet by default, which is the documented choice"
    );
}

/// An `Authority`'s account map settles too.
///
/// `Authority::new` is the single chokepoint — both its lists are private and every
/// constructor, binary and JSON, routes through it — and it was sorting `account_auths`
/// by the account as given rather than by the form the bytes carry. So an authority read
/// off the wire came back in a different order than it went out in, and a
/// `request_account_recovery` carrying one serialized to two different transactions on
/// two consecutive passes.
///
/// These are the exact bytes `fuzz_targets/reader.rs` and `fuzz_targets/transaction.rs`
/// reported, on the run after the flat-set ordering was fixed everywhere else. The same
/// defect had three separate homes; this is the third.
#[test]
fn an_authority_account_map_settles_after_one_pass() {
    let op_bytes: &[u8] = &[
        0x98, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x2b, 0x02, 0x05, 0x05, 0x05, 0x02, 0x00, 0x4d,
        0x00, 0x00, 0x07, 0x2b, 0x02, 0x05, 0x05, 0x05, 0x02, 0x00, 0x4d, 0x30, 0x00, 0x00, 0x07,
    ];
    let mut r = hivecomb::Reader::new(op_bytes, Chain::Hive);
    let op = Operation::read_from(&mut r).expect("parses");
    let once = op.to_wire().expect("serializes");
    let again = {
        let mut r = hivecomb::Reader::new(&once, Chain::Hive);
        Operation::read_from(&mut r).expect("our output parses")
    };
    assert_eq!(once, again.to_wire().unwrap(), "an authority must settle");

    let tx_bytes: &[u8] = &[
        0x05, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x74, 0x18, 0x9c, 0x6a, 0x01, 0x2b, 0x05, 0x61, 0x6c,
        0x69, 0x00, 0x00, 0x01, 0x00, 0x00, 0x16, 0x16, 0x03, 0x03, 0x03, 0x03, 0x16, 0x16, 0x16,
        0x16, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x16, 0x16, 0x16, 0x16, 0x16,
        0x16, 0x16, 0x16, 0x16, 0x2a, 0x16, 0x16, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let tx = Transaction::from_body_bytes(tx_bytes, Chain::Hive).expect("parses");
    let once = tx.body_bytes().expect("serializes");
    let again = Transaction::from_body_bytes(&once, Chain::Hive).expect("our output parses");
    assert_eq!(
        once,
        again.body_bytes().unwrap(),
        "and so must a transaction carrying one"
    );
}
