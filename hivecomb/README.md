# hivecomb

Hive blockchain keys, Graphene serialization and **offline** transaction signing, in
Rust.

```toml
[dependencies]
hivecomb = "0.1"
```

<!-- PRE-RELEASE-NOTICE: delete this block when the first release is published.
     RELEASING.md carries a checklist item for it. -->
> **Not published yet.** This name is reserved for the first release. Until then, build
> from the [repository](https://github.com/flosolcher/hivecomb) — see
> [RELEASING.md](https://github.com/flosolcher/hivecomb/blob/main/RELEASING.md).
<!-- /PRE-RELEASE-NOTICE -->

Rust 1.88+. `#![forbid(unsafe_code)]`. Python and Node.js bindings live in the same
[repository](https://github.com/flosolcher/hivecomb).

---

## Signing needs no network

A transaction needs exactly two things from outside itself: the chain id, which is a
compile-time constant, and a recent block reference, which stays valid far longer than
any submit window. So signing is pure CPU, and the key never has to sit on a machine
that talks to a node.

```rust
use hivecomb::operations::{CustomJson, Operation};
use hivecomb::{BlockRef, Chain, PrivateKey, Transaction};

// A published test key, used by no Hive account.
let key = PrivateKey::from_wif("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")?;

// The only input from the chain. Cache it; refresh it out of band.
let block_ref = BlockRef::from_block_id("00000005aabbccdd00000000000000000000abcd")?;

let tx = Transaction::new(
    block_ref,
    vec![Operation::CustomJson(CustomJson {
        required_auths: vec![],
        required_posting_auths: vec!["alice".into()],
        id: "my_app".into(),
        json: r#"{"hello":"hive"}"#.into(),
    })],
    60, // expires in 60s
)?;

let signed = tx.sign(&[key], Chain::Hive)?;   // no network, ever
let envelope = signed.to_json()?;             // ready to broadcast
# Ok::<(), hivecomb::Error>(())
```

Runnable: `cargo run --example sign_offline --no-default-features`.

## Feature flags

The core stays small. `--no-default-features` builds keys, serialization and signing
with **no HTTP client and no async runtime** compiled in at all.

| feature | |
|---|---|
| `rpc` | JSON-RPC layer: node failover, typed accessors, block streaming |
| `ureq-transport` | a working blocking transport (default) |
| `async` | runtime-agnostic async RPC, including racing one request across nodes |
| `reqwest-transport` | a working async transport, on tokio |
| `memo` | encrypted memos (ECDH + AES-CBC) |
| `bip32` | BIP-32 / BIP-39 hierarchical keys |
| `bip38` | BIP-38 encrypted WIFs |
| `wallet` | encrypted key store: scrypt + AES-256-GCM |

Default: `rpc`, `ureq-transport`, `memo`, `bip38`, `bip32`, `wallet`. Every combination
is checked warning-free in CI.

## What is here

- All **48 signable operations** and **43 virtual** ones, with round-trip wire
  serialization.
- Keys: WIF, BIP-32, BIP-38, BIP-39, brain keys, Hive's master-password scheme.
- Encrypted memos, interoperable with Keychain, hive-js, dhive and beem.
- An encrypted wallet, and a `TaposCache` that refuses to hand out a stale reference.
- `Authority::check`, which answers **three** ways — satisfied, not satisfied, or *not
  from these keys alone*, when an authority defers to accounts that were not looked up.
  Most active Hive accounts share posting rights this way.

## Racing, when a deadline is real

Sequential failover has a worst case of the *sum* of the timeouts. Three sick nodes at
fifteen seconds each is forty-five seconds before the fourth is tried, and a transaction
that misses its window is simply lost. `AsyncNodeClient::race` fires at several nodes at
once and takes the first answer: worst case, one timeout.

Measured with two dead nodes in front of a working one: **878 ms racing, 3,366 ms
sequential.**

## How this is verified

- **Against hived itself.** A node is asked to serialize each operation and the digests
  are compared. 57/57 identical. This found four defects that 295 unit tests and a
  differential oracle against `beem` had all missed.
- **Against beem**, the Python library this reimplements: a 150-case differential digest
  corpus, 0 unexpected divergences.
- **On the live chain.** A transaction signed by this crate was accepted into block
  [109242605](https://hivehub.dev/tx/ebb44fb5dedd544b7deeb62f81660983233a559f), filed
  under the transaction id computed offline.

One accepted transaction is a proof, not a track record. What is and is not established
is written down in
[BROADCAST.md](https://github.com/flosolcher/hivecomb/blob/main/BROADCAST.md), and the
comparison against the other Rust Hive libraries — including where they are ahead — is
in [COMPARISON.md](https://github.com/flosolcher/hivecomb/blob/main/COMPARISON.md).

## Credit

A reimplementation of [`beem`](https://github.com/holgern/beem) by Holger Nahrstaedt,
descending from `python-bitshares` and `python-graphenelib` by Fabian Schuh. The
protocol knowledge is theirs; this is a translation. See
[CREDITS.md](https://github.com/flosolcher/hivecomb/blob/main/CREDITS.md).

MIT.
