![hivecomb](https://raw.githubusercontent.com/flosolcher/hivecomb/main/assets/hivecomb.png)

# hivecomb — Hive keys, serialization and offline signing, in Rust

`hivecomb` is a Rust reimplementation of [beem](https://github.com/holgern/beem), with
Python and Node.js bindings. Version **0.1.0** is on crates.io and PyPI as of
2026-09-05.

**This is a port, not new work.** The protocol knowledge in it — the wire format, the
key derivations, the operation definitions, the signing scheme — was worked out by
other people over roughly a decade:

- **Holger Nahrstaedt**, author of [beem](https://github.com/holgern/beem), the library
  this reimplements. Every serialization rule here was learned by reading beem's source.
- **Fabian Schuh**, author of `python-bitshares` and `python-graphenelib`, which beem
  itself descends from.
- The **hived** maintainers, whose `libraries/protocol` is the authority every byte here
  is checked against.

The conversion to Rust was done by Claude (Anthropic). Full attribution, module by
module, is in [CREDITS.md](https://github.com/flosolcher/hivecomb/blob/main/CREDITS.md).

---

## Why it exists

beem has not been maintained since 2021, and a current install quietly falls onto a
pure-Python ECDSA path — the `secp256k1` binding it prefers raises
`AttributeError: 'PrivateKey' object has no attribute 'ctx'` against any modern version.
It still works. It is just slower than it was designed to be, and it predates every
operation Hive added after hardfork 25.

`hivecomb` is that library rewritten, with the post-HF25 operations added and a set of
defects fixed. It is offered alongside beem, not against it — beem is where all of this
came from.

## Install

```sh
# Python
pip install hivecomb          # keys, signing, memos, every operation

# Rust
cargo add hivecomb
```

**Already have a beem program?** Don't change it:

```sh
pip uninstall -y beem
pip install hivecomb hivecomb-beem
```

`hivecomb-beem` provides the `beem`, `beembase`, `beemapi` and `beemgraphenebase`
package names and the `beempy` console script. Existing `import beem` code keeps
working. It deliberately shadows beem's package names, so do **not** install both.

> The Node.js addon is **not on npm yet** — npm's automated spam filter is holding one
> of the five per-platform binary packages, which blocks the package that depends on
> them. Build it from the repository meanwhile. Nothing about the Rust or Python
> packages is affected.

## Signing never needs the network

This is the part worth knowing even if you use something else.

A Hive transaction needs exactly two things from outside itself: the **chain id**, which
is a compile-time constant, and a **recent block reference**, which stays valid far
longer than any submit window. Nothing else. So the signing key never has to live on a
machine that talks to a node.

```python
import hivecomb

# The only input from the chain. From any node, or carried across an air gap.
ref = hivecomb.BlockRef.from_block_id(head_block_id)

tx = hivecomb.sign_transaction(
    [("custom_json", {
        "required_auths": [],
        "required_posting_auths": ["alice"],
        "id": "my_app",
        "json": {"hello": "hive"},
    })],
    ref,
    [posting_wif],
)
# tx is the exact envelope condenser_api.broadcast_transaction wants
```

`sign_transaction(operations, block_ref, wifs)` returns a dict with `ref_block_num`,
`ref_block_prefix`, `expiration`, `operations`, `extensions`, `signatures` and `trx_id`.
Pass `expiration_seconds=` for a different window, `chain=` for a testnet.

The same thing in Rust:

```rust
use hivecomb::{BlockRef, Chain, PrivateKey, Transaction};
use hivecomb::operations::{CustomJson, Operation};

let key = PrivateKey::from_wif(&posting_wif)?;
let block_ref = BlockRef::from_block_id(&head_block_id)?;   // cached, not fetched here

let tx = Transaction::new(
    block_ref,
    vec![Operation::CustomJson(CustomJson {
        required_auths: vec![],
        required_posting_auths: vec!["alice".into()],
        id: "my_app".into(),
        json: r#"{"hello":"hive"}"#.into(),
    })],
    60,
)?;

let signed = tx.sign(&[key], Chain::Hive)?;   // pure CPU: no network, ever
```

## What is in it

- **48 signable operations** and all **43 virtual** ones, read and written
- Encrypted memos, in the format the rest of the ecosystem uses
- BIP-32, BIP-38, BIP-39, brain keys and Hive's master-password derivation
- An encrypted wallet
- A JSON-RPC client with node failover, and an optional async layer that can race a
  broadcast at several nodes and take the first acceptance
- No Python dependencies at all, where beem pulled in `requests`, `websocket-client`,
  `Click`, `click-shell`, `pycryptodomex` and `prettytable`

Python wheels are `abi3`, so one per platform covers CPython 3.8 and up. The Rust crate
is `#![forbid(unsafe_code)]` and builds with `--no-default-features` down to keys,
serialization and signing with no HTTP client and no executor.

## How it is checked

A test suite written from a belief only tests the belief, so the serialization is
checked against **hived itself** rather than against this project's own assumptions:

- **57 of 57** operations serialize byte-identically to what a live Hive node produces
- **26 of 26** operations are signed with the authority hived actually requires
- 358 unit tests, four `cargo-fuzz` targets, and a differential oracle against beem
- CI runs three Rust toolchains across Linux, macOS and Windows, plus Python 3.8/3.12
  and Node 22/24

That oracle earns its keep. On 2026-08-22 it found four defects that 292 unit tests and
a beem differential oracle had all missed — two of which round-tripped perfectly through
this library's own serializer and deserializer, because **a round-trip test cannot catch
a format that is wrong in both directions**. It also overturned a finding this project
had published against beem, where beem was right and this library was not. That
retraction is still in the repository, with the reasoning left visible.

A transaction signed by this library has been accepted by Hive: block
[109242605](https://hivehub.dev/tx/ebb44fb5dedd544b7deeb62f81660983233a559f).

## What it is not

- **Not production-proven.** One accepted transaction is a proof, not a track record.
  Nothing depends on this yet.
- **Not the only option.** [hive-nectar](https://github.com/srbde/hive-nectar) is the
  maintained Python library and is more mature than this project's Python side by every
  measure that can be counted. [hive-xylem](https://github.com/srbde/hive-xylem) has
  five releases where this has one. In Node,
  [dhive](https://github.com/openhive-network/dhive) serializes large batches faster
  than this does, for structural reasons that are not going away.
  [COMPARISON.md](https://github.com/flosolcher/hivecomb/blob/main/COMPARISON.md)
  measures every one of them with versions stated and the places they win shown as
  plainly as the places they don't.
- **HAF is not implemented.**

## Links

- Source: <https://github.com/flosolcher/hivecomb>
- crates.io: <https://crates.io/crates/hivecomb>
- PyPI: <https://pypi.org/project/hivecomb/> · <https://pypi.org/project/hivecomb-beem/>
- Migrating from beem:
  [MIGRATION.md](https://github.com/flosolcher/hivecomb/blob/main/MIGRATION.md) — what
  is identical, what diverges deliberately, and what is not implemented
- What was wrong in beem, including the retracted finding:
  [SECURITY_FINDINGS.md](https://github.com/flosolcher/hivecomb/blob/main/SECURITY_FINDINGS.md)

MIT licensed, like everything it derives from. Issues and corrections welcome — this is
a translation of other people's work, and the people who did that work know it better
than the translation does.
