//! Sign a transaction with no network access at all.
//!
//! This is the case `hivecomb` exists for: the signing key never touches a machine
//! that talks to a node. The only thing that has to come *from* the chain is a recent
//! block id, and that is public information you can carry across an air gap.
//!
//!     cargo run --example sign_offline --no-default-features
//!
//! Note the `--no-default-features`: this example builds with no HTTP client and no
//! async runtime compiled in at all. If it ever stops doing so, something has pulled a
//! network dependency into the signing path.

use hivecomb::operations::{Operation, Transfer, Vote};
use hivecomb::{Amount, BlockRef, Chain, PrivateKey, Transaction};

fn main() -> hivecomb::Result<()> {
    // Published on purpose, used by no Hive account. Never put a real key in a file
    // that gets committed -- see BROADCAST.md.
    let key = PrivateKey::from_wif("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")?;
    println!("signing with {}", key.public_key());

    // The one input from the chain. `head_block_id` from any node, or from a phone.
    // TaPoS: this binds the transaction to a fork, so it cannot be replayed onto a
    // chain that never contained this block.
    let block_ref = BlockRef::from_block_id("00000005aabbccdd00000000000000000000abcd")?;
    println!("bound to block {}", block_ref.block_num);

    let operations = vec![
        Operation::Vote(Vote {
            voter: "alice".into(),
            author: "bob".into(),
            permlink: "a-post".into(),
            weight: 10_000, // basis points; negative is a downvote
        }),
        Operation::Transfer(Transfer {
            from: "alice".into(),
            to: "bob".into(),
            // Parsed exactly, never through a float. See SECURITY_FINDINGS.md #16.
            amount: Amount::parse("1.234 HIVE", Chain::Hive)?,
            memo: "thanks".into(),
        }),
    ];

    let transaction = Transaction::new(block_ref, operations, 600)?;

    // The digest is sha256(chain_id || serialized_transaction). The chain id is what
    // stops a Hive signature from being valid on any other Graphene chain.
    println!("digest    {}", hex(&transaction.digest(Chain::Hive)?));

    let signed = transaction.sign(&[key], Chain::Hive)?;
    println!("trx_id    {}", signed.transaction.id()?);
    println!("signature {}", signed.signatures[0]);

    // Recovering the signer proves the signature covers exactly these bytes. This is
    // what a node does before it accepts the transaction.
    for public_key in signed.signers(Chain::Hive)? {
        println!("recovered {public_key}");
    }

    // `to_json` gives the exact envelope `condenser_api.broadcast_transaction` wants,
    // so this can be handed to an online machine verbatim.
    let envelope = serde_json::to_string_pretty(&signed.to_json()?)
        .expect("a JSON value always re-serializes");
    println!("\n{envelope}");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
