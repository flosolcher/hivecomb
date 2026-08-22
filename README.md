# hivecomb

Hive blockchain keys, Graphene serialization and **offline** transaction signing — in
Rust, with Python bindings.

`hivecomb` is a from-scratch reimplementation of [`beem`](https://github.com/holgern/beem),
the Python Hive library by Holger Nahrstaedt, which itself descends from
`python-bitshares` and `python-graphenelib` by Fabian Schuh. The protocol knowledge
here is theirs; see [CREDITS.md](CREDITS.md). This is a translation, not new work.

```rust
use hivecomb::{Chain, PrivateKey, Transaction, BlockRef};
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

```python
import hivecomb

sig = hivecomb.sign_message("login challenge", posting_wif)      # hex, like beem's

tx = hivecomb.sign_transaction(
    [("custom_json", {
        "required_posting_auths": ["alice"],
        "id": "my_app",
        "json": {"hello": "hive"},
    })],
    hivecomb.BlockRef.from_block_id(head_block_id),
    [posting_wif],
)
# tx is ready to POST to network_broadcast_api.broadcast_transaction
```

## Why

Three reasons, in the order they matter.

**1. Signing should not need the network.** A Hive transaction needs exactly two things
from outside itself: the chain id and a recent block reference. The chain id is a
*compile-time constant*. The block reference is valid for far longer than any submit
window, so it can be cached and refreshed in the background.

beem cannot do this. `blockchaininstance.py` calls `get_config` over JSON-RPC on the
way to every signature, partly to look up that constant. When nodes are slow, signing
is slow — and signing usually sits inside somebody's deadline. Removing the round trip
removes an entire class of failure that no amount of retry tuning can remove, because
the retry tuning *is* the workaround.

**2. beem has defects that fail silently.** Twenty-one of them are catalogued in
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) with file, line, and consequence. The ones
that matter most are not crashes — they are the paths that produce a *valid-looking
signature over the wrong bytes*: a bare `except:` that falls back to the pre-hardfork-24
all-zero chain id, a `String` encoder that mangles control characters, monetary amounts
that round-trip through binary `float`, `flat_set` fields serialized in the caller's
order rather than sorted.

**3. beem stopped tracking Hive.** Its classifiers stop at Python 3.9 and its operation
table predates HF25, so it **cannot construct `recurrent_transfer` or
`collateralized_convert` at all**, and every virtual operation id it reports is two
lower than the chain's.

Speed is *not* a reason. ECDSA over secp256k1 is microseconds either way.

## Design rules

- **No silent fallbacks.** Where beem swallowed an error and continued with a default —
  a chain id, an ECDSA backend, a base58 character — `hivecomb` returns an error.
- **Secrets do not render.** `Debug` and `Display` for `PrivateKey` print
  `PrivateKey(<redacted>)`; disclosure requires the explicitly-named `to_wif()` or
  `expose_secret()`, both returning `Zeroizing` wrappers. beem's `__repr__` returned the
  raw private scalar and `__str__` the WIF, so `print(key)` or `log.debug("%r", key)`
  leaked it. No error variant ever carries key material.
- **One crypto backend.** libsecp256k1 via the `secp256k1` crate, constant-time by
  construction. beem selected between four backends at import time inside a bare
  `except:`, and with none installed fell through to pure-Python variable-time ECDSA.
- **Unknown input is refused, never defaulted.**
- **`#![forbid(unsafe_code)]`.**

## Status

Working and tested. **Not yet run against mainnet with real value** — see
[Before you trust it](#before-you-trust-it).

| Area | State |
|---|---|
| base58 / base58check / Graphene check | done |
| WIF, public keys, brain keys, password keys | done |
| Graphene wire types, varint, timestamps | done |
| Assets and amounts (integer, no float) | done |
| Authorities (sorted, deduplicated) | done |
| Operation table, all 93 ids incl. HF25–HF28 | done |
| All 48 constructible operations | done |
| All 43 virtual operations | done — beem models none |
| Binary + JSON deserialization, round-tripped | done |
| Transactions: digest, id, signing, verification | done |
| TaPoS cache with hard staleness refusal | done |
| Encrypted memos | done |
| BIP-32, BIP-38, BIP-39 | done |
| Chain types: Account, Witness, Block, RC, feed | done |
| Mana / voting power / RC arithmetic | done |
| JSON-RPC client with node failover + typed accessors | done |
| Python bindings (PyO3 / abi3) | done — keys, signing, memos, all 48 ops |
| beem-compatible Python layer | done — drop-in, 25 checks |
| beem object wrappers (Account, Market, …) | done |
| `beempy` CLI | done — all 99 commands, plus 7 new |
| Differential oracle vs beem | done, green |
| Live-node fixture tests | done |
| Authority satisfaction checking | done |
| Block streaming, `get_ops_in_block` | done |
| Async API | no — sync, with a pluggable transport |
| Wallet / encrypted key storage | done — scrypt + AES-GCM |

Chain state is modelled as plain data (`hivecomb::chain`), read from the API rather than
constructed. beem's equivalents subclass `dict` and can each reach the network on their
own — which is the design that puts a node call inside the signing path. Here the types
are inert and the client is explicit.

## Layout

```
hivecomb/          the library          — publishable to crates.io
hivecomb-py/       PyO3 bindings        — publishable to PyPI as `hivecomb`
tests/         differential_beem.py — the oracle against beem
SECURITY_FINDINGS.md                — 21 findings, with file:line
CREDITS.md                          — upstream authorship
```

## Building

```bash
cargo test                                 # 262 tests, including 10 against live fixtures
cargo build -p hivecomb --no-default-features  # signing only: no network, no cipher, no scrypt
```

Feature flags keep the core small. `--no-default-features` builds keys, serialization
and signing alone; `memo`, `bip38`, `bip32`, `rpc` and `ureq-transport` are additive.

Python wheels, via [maturin](https://github.com/PyO3/maturin):

```bash
maturin develop          # build and install into the active venv
maturin build --release  # abi3 wheel, CPython 3.8+
```

## Verification

The correctness gate is a **differential digest oracle** against beem. The digest
`sha256(chain_id || serialized_tx)` is fully deterministic and backend-independent, so
every serialization bug lives there.

```
$ python tests/differential_beem.py
digest corpus     : 134 cases
  identical       : 108
  known divergence: 26  (hivecomb is deliberately correct here)
  UNEXPECTED      : 0
public key        : match
cross-verification: ok
```

The 26 divergences are findings [16](SECURITY_FINDINGS.md#16) and
[21](SECURITY_FINDINGS.md#21) — the cases where beem produces bytes hived will not
accept. Everything else is byte-identical, which is the evidence that the port did not
introduce drift of its own.

Signature **byte**-equality is deliberately not the gate. Any canonical signature is
valid and the chain does not care which one it gets, so a byte comparison would be
simultaneously too strict and too weak. What is asserted instead is that each
implementation accepts the other's signatures, and that public key derivation agrees
exactly.

The corpus covers varint boundaries, `int16` boundaries, multi-byte UTF-8, empty and
maximum-length `custom_json` ids, unsorted and duplicated auth sets, and amounts on both
sides of the `2**53` threshold. **It is a floor. Extend it rather than trusting it.**

## Before you trust it

This has not yet signed a transaction that a Hive node accepted. Before putting it in
front of anything valuable:

1. **Broadcast one transaction on a throwaway account.** Serialization can be perfect
   and a transaction still rejected for a reason no offline test models.
2. **Run it alongside your existing signer** and compare, for a period, before letting
   it sign alone.
3. **Extend the corpus** in `tests/differential_beem.py` to cover the operations *you*
   actually send.

The chain id is hardcoded, which is correct today and is exactly the kind of constant
that moves at a hardfork. It lives in one place — `hivecomb/src/chains.rs` — with a comment
saying so. `NodeClient::verify_chain_id` will tell you if a node disagrees.

## Replacing beem

The `python/` directory is a distribution that provides the `beem`,
`beemgraphenebase`, `beembase` and `beemapi` package names, so existing `import beem`
code runs unchanged:

```sh
pip uninstall -y beem
pip install hivecomb hivecomb-beem
```

[MIGRATION.md](MIGRATION.md) is the complete record: every defect fixed and where it is
fixed, every deliberate behavioural divergence, everything `hivecomb` adds that beem cannot
do, and exactly what is not implemented. `python/test_compat.py` runs 25 checks written
against beem's API unmodified, and `python/test_cli.py` runs 21 more over `beempy`.

`beempy commands --new` lists the seven commands beem has no equivalent for.

## Names

Three of the names here are chosen to avoid a collision, and one is chosen to *cause*
one. Worth stating plainly, since both kinds are deliberate.

**The crate is `hivecomb`, not `comb`.** `comb` is taken on crates.io (a Handlebars
CLI) and on PyPI, and in Rust the word already means something else — the most
prominent crate near that name, `honeycomb`, is a parser-combinator library. `hivecomb`
is free on both registries and says what it is.

| | name |
|---|---|
| Rust crate | `hivecomb` — `use hivecomb::{Chain, PrivateKey};` |
| Python module | `hivecomb` — `import hivecomb` |
| PyPI (core) | `hivecomb` |
| PyPI (beem drop-in) | `hivecomb-beem` |
| Repository | [`flosolcher/hivecomb`](https://github.com/flosolcher/hivecomb) |

**The compatibility layer shadows beem on purpose.** `hivecomb-beem` installs packages
called `beem`, `beemgraphenebase`, `beembase` and `beemapi`, and a console script
called `beempy` — because being a drop-in replacement is the whole point. It cannot be
installed alongside beem, and the [migration guide](MIGRATION.md) says so up front.
`beem.__version__` reports `hivecomb-compat-0.1.0` rather than `0.24.26`, so anything
that branches on the version can tell which library it is talking to.

## Other Rust Hive libraries

`hivecomb` is not the first. [COMPARISON.md](COMPARISON.md) measures it against
[`hive-xylem`](https://github.com/srbde/hive-xylem) in both directions, records the
five things `hivecomb` gained from reading it, notes a memo-encryption defect found while
comparing, and answers the maturity question plainly: **xylem is published and `hivecomb`
is not**, and on production exposure neither is mature.

## Licence

MIT, matching beem, python-bitshares and python-graphenelib, whose copyright notices are
reproduced in [LICENSE](LICENSE).
