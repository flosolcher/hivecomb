# Credits

`hivecomb` is a Rust port. It is not original work.

The protocol knowledge, the wire format, the key derivations, the API surface and the
overwhelming majority of the design encoded in this repository were worked out by other
people over roughly a decade. This file records who they are. Where a module in `hivecomb`
corresponds to one of theirs, its documentation says so.

## beem

The direct source of this port.

**[beem](https://github.com/holgern/beem)** — *Unofficial Python Library for HIVE and
STEEM*

- **Holger Nahrstaedt** — author and maintainer of beem.
  <nahrstaedt@gmail.com>

Copyright (c) 2018, 2019 Holger Nahrstaedt. MIT licensed.

beem is the library `hivecomb` reimplements: `beemgraphenebase`, `beembase`, `beemapi`,
`beemstorage` and `beem` itself. Every serialization rule, every operation definition,
every key derivation and the entire signing scheme in this crate were learned by
reading beem's source. Where `hivecomb` diverges, it is documented as a divergence from
beem, and the reasoning is recorded in `SECURITY_FINDINGS.md`.

## python-bitshares and python-graphenelib

beem's own README states that it "is created new from scratch from `python-bitshares`"
and "includes `python-graphenelib`". Those are the upstream of the upstream.

**[python-graphenelib](https://github.com/xeroc/python-graphenelib)** and
**[python-bitshares](https://github.com/xeroc/python-bitshares)**

- **Fabian Schuh** (`xeroc`) — author of python-graphenelib and python-bitshares.

Copyright (c) 2015 Fabian Schuh. MIT licensed.

The base58 handling, the `GrapheneObject` serialization model, the canonical-signature
loop, the brain-key and password-key derivations, the BIP-38 implementation and the
encrypted-memo scheme all originate here. The `_is_canonical` predicate in
`hivecomb/src/sign.rs` is a direct, deliberate port of Fabian Schuh's implementation,
because it encodes a consensus rule that must not drift.

## Graphene and Steem

**[Graphene](https://github.com/cryptonomex/graphene)** — Cryptonomex, and the
BitShares developers, who defined the object model, the binary serialization and the
transaction format that Hive still uses.

**[Steem](https://github.com/steemit/steem)** — Steemit, Inc. and its contributors,
who defined the operation set, the authority model, the asset symbols still present in
the wire format (`STEEM`/`SBD` for what are now `HIVE`/`HBD`), and the chain semantics
Hive inherited at the fork.

## Hive

**[hived](https://github.com/openhive-network/hive)** — the Hive core developers and
the [Hive](https://hive.io) community.

hived is the normative reference for everything in this crate. The operation table in
`hivecomb/src/operations/` is generated against
`libraries/protocol/include/hive/protocol/operations.hpp`; where beem and hived
disagree, hived wins and beem is recorded as a finding. The
[developer documentation](https://developers.hive.io) is the reference for the RPC
layer.

Post-HF25 operations that beem never gained — `recurrent_transfer`,
`collateralized_convert`, and the virtual operations added through HF26–HF28 — come
from hived directly, not from beem.

## Third-party word list

`hivecomb/data/brainkey_words.txt` is the 49,744-word Graphene brain-key dictionary,
carried forward unchanged from python-graphenelib via beem
(`beemgraphenebase/dictionary.py`). It must not be modified: the words and their order
determine which brain keys can be regenerated.

`hivecomb/data/bip39_english.txt` is the standard BIP-39 English word list, carried
forward from beem's `Mnemonic`, which was itself taken from
[python-mnemonic](https://github.com/trezor/python-mnemonic) — copyright (c) 2013
Pavol Rusnak, (c) 2017 mruddy. `hivecomb/src/bip39.rs` is cross-checked against that
implementation's output.

## Honourable mention — hive-nectar

**[hive-nectar](https://github.com/thecrazygm/hive-nectar)** — by **Michael Garcia**
(`thecrazygm`). MIT. 1.0.7 at the time of writing.

beem's actively maintained successor, and the one this project owes the most to after
beem itself. Its own README puts it plainly: *"If you are using beem, Nectar is where
you go next."* For anyone on beem today it is the obvious destination, and it is
published, maintained and in real use where `hivecomb` is none of those things yet.

It deserves saying clearly, because this project's other document about nectar is an
audit and audits only record what is wrong: **nectar independently fixed the whole
crypto-critical set of beem's defects** — the missing comma in the operation id list,
the operation table itself, the pure-Python ECDSA fall-through, the wall-clock nonce,
the all-zero chain id fallback (removed properly, by making `known_chains["HIVE"]` the
real post-HF24 value rather than working around it), the discarded verification result,
and the timezone handling. That was done without reference to this project, and several
of those are the findings `hivecomb` treats as its reason to exist.

The two projects are alternatives rather than rivals, and they differ less than the
obvious framing suggests: **both do their elliptic curve arithmetic in libsecp256k1** —
nectar through `coincurve`, `hivecomb` through the `secp256k1` crate. What differs is
where the protocol logic lives, Python or Rust.

nectar also does not keep beem's package names — it ships `nectar`, `nectarbase`,
`nectarapi`, `nectargraphenebase` and `nectarstorage`, so existing `import beem` code
has to be rewritten. That is a defensible choice, a clean break from a decade of
legacy, and it is the reason `hivecomb-beem` exists as a separate thing rather than
being redundant. See [COMPARISON.md](COMPARISON.md), which
compares the two honestly, including where nectar leads.

## Honourable mention — nectarengine

**[nectarengine](https://github.com/srbde/nectarengine)** — by **SRBDE**. MIT.

A Hive-Engine client: tokens, the market, market pools, NFTs and the NFT market, across
41 write operations and six contracts.

`hivecomb` takes no code from it and ships no Hive-Engine client — that is a separate
chain on its own schedule, and this crate's Hive-Engine story is "it is a `custom_json`,
which we sign correctly". But reading it produced the one thing worth knowing on that
subject, and `hivecomb-py`'s README now says it: the authority a Hive-Engine action
requires **varies by contract action**, Hive validates whichever one you declare, and
the sidechain decides which list it reads. Declare the wrong one and the transaction is
accepted by Hive and silently does nothing. Its split between active and posting is the
best available answer to which is which, because it is maintained against a schema that
moves.

## Honourable mention — other Rust work on Hive

`hivecomb` is not the first Rust library for Hive, and it is better for the ones that came
before it.

**[hive-xylem](https://github.com/srbde/hive-xylem)** — by **SRBDE**, part of a
cross-language suite alongside Pollen (TypeScript), Anther (Go) and Nectar (Python).
MIT/Apache-2.0.

An async-first Hive SDK built on Tokio, published on crates.io while this crate was
not. Reading it directly improved `hivecomb` in five places: authority satisfaction
checking, `get_ops_in_block` (the only route to virtual operations), block streaming in
Rust, exponential backoff on node failover, and a handful of conveniences. Its
async-native design is a real advantage `hivecomb` does not have — see
[COMPARISON.md](COMPARISON.md), which also records a memo-encryption defect found while
comparing, and answers the maturity question honestly rather than flatteringly.

None of its code was copied. What was taken was the knowledge of what a Hive library
ought to be able to do.

**[hive_memo](https://crates.io/crates/hive_memo)** and
**[hive-rs](https://crates.io/crates/hive-rs)** — smaller, focused crates in the same
space, noted so that anyone weighing options can find them.

## Rust dependencies

`hivecomb` binds [libsecp256k1](https://github.com/bitcoin-core/secp256k1) through the
[`secp256k1`](https://crates.io/crates/secp256k1) crate maintained by the rust-bitcoin
project. All curve arithmetic is theirs; none of it is hand-rolled here. The remaining
dependencies — `sha2`, `ripemd`, `bs58`, `zeroize`, `subtle`, `serde`, `time` — are
listed in `Cargo.toml` with their own authors and licences.

## This port

The Rust translation in this repository was produced by Claude (Anthropic). It carries
no independent authorship claim: it is a translation of the work credited above, plus
the corrections recorded in `SECURITY_FINDINGS.md`.

`hivecomb` is released under the MIT licence, matching beem, python-bitshares and
python-graphenelib, and reproduces their copyright notices in `LICENSE`.

## Corrections welcome

If you contributed to beem, python-graphenelib, python-bitshares, Graphene, Steem or
hived and are not named here — or are named incorrectly — please open an issue. This
file is meant to be right, and an omission in it is a bug like any other.
