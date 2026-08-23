//! Write a fuzzing corpus of **valid** inputs, so the targets cannot pass vacuously.
//!
//! Every fuzz target here has its assertions behind `if let Ok(..)` — the round-trip
//! and idempotence checks only run for input that parses. Seeded with random bytes
//! alone, a target can therefore report success without ever having executed the thing
//! it exists to check, and "no bug found" becomes indistinguishable from "nothing was
//! tested". That is not a hypothetical: the `transaction` target was seeded with three
//! trivial byte strings, none of which parse as a transaction body.
//!
//! So the corpus starts from bytes this crate produced. libFuzzer mutates outward from
//! them, which both guarantees the interesting branch is reachable and finds more,
//! since a mutated valid transaction is far likelier to stay parseable than random
//! noise is to become so.
//!
//!     cargo run --example emit_fuzz_seeds --no-default-features -- fuzz/corpus
//!
//! It writes one subdirectory per target and prints what it wrote, so a CI log shows
//! the corpus was non-empty rather than leaving it to be assumed.

use std::fs;
use std::path::Path;

use hivecomb::operations::{
    AccountUpdate2, Comment, CustomJson, EscrowTransfer, LimitOrderCreate2, Operation,
    RecurrentTransfer, RecurrentTransferExtension, Transfer, Vote,
};
use hivecomb::types::{GrapheneSerialize, PointInTime};
use hivecomb::{Amount, BlockRef, Chain, PrivateKey, Transaction};

fn main() -> hivecomb::Result<()> {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fuzz/corpus".to_string());
    let root = Path::new(&root);

    // The published test key, used by no Hive account.
    let key = PrivateKey::from_wif("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")?;
    let block_ref = BlockRef::from_block_id("00000005aabbccdd00000000000000000000abcd")?;

    // Operations chosen for the shapes that have actually gone wrong: the two whose
    // field order was reversed, the extension whose width was wrong, a string field
    // carrying a control byte, and an optional-heavy struct.
    let operations: Vec<(&str, Operation)> = vec![
        (
            "vote",
            Operation::Vote(Vote {
                voter: "alice".into(),
                author: "bob".into(),
                permlink: "a-post".into(),
                weight: -10_000,
            }),
        ),
        (
            "transfer",
            Operation::Transfer(Transfer {
                from: "alice".into(),
                to: "bob".into(),
                amount: Amount::parse("1.234 HIVE", Chain::Hive)?,
                memo: "thanks".into(),
            }),
        ),
        (
            "custom-json",
            Operation::CustomJson(CustomJson {
                required_auths: vec![],
                required_posting_auths: vec!["alice".into()],
                id: "my_app".into(),
                json: r#"{"a":1}"#.into(),
            }),
        ),
        (
            "comment-control-bytes",
            Operation::Comment(Comment {
                parent_author: String::new(),
                parent_permlink: "hive-100".into(),
                author: "alice".into(),
                permlink: "p".into(),
                title: "\u{1}\u{8}\u{c}".into(),
                body: "x\u{1}y".into(),
                json_metadata: "{}".into(),
            }),
        ),
        (
            "escrow-transfer",
            Operation::EscrowTransfer(EscrowTransfer {
                from: "aaa".into(),
                to: "bbb".into(),
                hbd_amount: Amount::parse("1.000 HBD", Chain::Hive)?,
                hive_amount: Amount::parse("2.000 HIVE", Chain::Hive)?,
                escrow_id: 0x1122_3344,
                agent: "ccc".into(),
                fee: Amount::parse("0.100 HIVE", Chain::Hive)?,
                json_meta: "JM".into(),
                ratification_deadline: PointInTime::from_unix(1_893_456_000)?,
                escrow_expiration: PointInTime::from_unix(1_927_756_800)?,
            }),
        ),
        (
            "limit-order-create2",
            Operation::LimitOrderCreate2(LimitOrderCreate2 {
                owner: "alice".into(),
                orderid: 1,
                amount_to_sell: Amount::parse("1.000 HIVE", Chain::Hive)?,
                exchange_rate: hivecomb::operations::Price {
                    base: Amount::parse("1.000 HIVE", Chain::Hive)?,
                    quote: Amount::parse("1.000 HBD", Chain::Hive)?,
                },
                fill_or_kill: false,
                expiration: PointInTime::from_unix(1_893_456_000)?,
            }),
        ),
        (
            "recurrent-transfer-pair-id",
            Operation::RecurrentTransfer(RecurrentTransfer {
                from: "alice".into(),
                to: "bob".into(),
                amount: Amount::parse("1.000 HIVE", Chain::Hive)?,
                memo: String::new(),
                recurrence: 24,
                executions: 12,
                extensions: vec![RecurrentTransferExtension::PairId(7)],
            }),
        ),
        (
            "account-update2-optionals",
            Operation::AccountUpdate2(AccountUpdate2 {
                account: "alice".into(),
                owner: None,
                active: None,
                posting: None,
                memo_key: None,
                json_metadata: String::new(),
                posting_json_metadata: "{}".into(),
                extensions: hivecomb::operations::NoExtensions,
            }),
        ),
    ];

    let mut written = 0usize;

    // `reader` and `keys` consume a single serialized operation.
    for target in ["reader"] {
        let dir = root.join(target);
        fs::create_dir_all(&dir).expect("writing the fuzz corpus");
        for (name, op) in &operations {
            let bytes = op.to_wire()?;
            fs::write(dir.join(format!("op-{name}")), &bytes).expect("writing the fuzz corpus");
            written += 1;
        }
    }

    // `transaction` consumes a whole serialized body — the target that was almost
    // certainly never reaching its assertions.
    let dir = root.join("transaction");
    fs::create_dir_all(&dir).expect("writing the fuzz corpus");
    for (name, op) in &operations {
        let tx = Transaction::new(block_ref, vec![op.clone()], 600)?;
        fs::write(dir.join(format!("tx-{name}")), tx.body_bytes()?)
            .expect("writing the fuzz corpus");
        written += 1;
    }
    // And one carrying several operations at once.
    let many = Transaction::new(
        block_ref,
        operations.iter().map(|(_, op)| op.clone()).collect(),
        600,
    )?;
    fs::write(dir.join("tx-many-operations"), many.body_bytes()?).expect("writing the fuzz corpus");
    written += 1;

    // `keys` consumes text: real keys, in the forms it accepts.
    let dir = root.join("keys");
    fs::create_dir_all(&dir).expect("writing the fuzz corpus");
    let public = key.public_key();
    for (name, text) in [
        ("wif", key.to_wif().as_str().to_owned()),
        ("pubkey", public.to_string()),
        ("pubkey-hex", public.to_hex()),
    ] {
        fs::write(dir.join(format!("key-{name}")), text).expect("writing the fuzz corpus");
        written += 1;
    }

    // `memo` consumes an encrypted memo, which no random input will ever resemble.
    #[cfg(feature = "memo")]
    {
        let dir = root.join("memo");
        fs::create_dir_all(&dir).expect("writing the fuzz corpus");
        let encrypted = hivecomb::memo::encode(&key, &public, "hello hive")?;
        fs::write(dir.join("memo-encrypted"), &encrypted).expect("writing the fuzz corpus");
        written += 1;
    }

    println!("wrote {written} seed files under {}", root.display());
    println!("every fuzz target now starts from input this crate produced, so its");
    println!("assertions are reachable rather than merely present");
    Ok(())
}
