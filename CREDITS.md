# Credits

`comb` is a Rust port. It is not original work.

The protocol knowledge, the wire format, the key derivations, the API surface and the
overwhelming majority of the design encoded in this repository were worked out by other
people over roughly a decade. This file records who they are. Where a module in `comb`
corresponds to one of theirs, its documentation says so.

## beem

The direct source of this port.

**[beem](https://github.com/holgern/beem)** — *Unofficial Python Library for HIVE and
STEEM*

- **Holger Nahrstaedt** — author and maintainer of beem.
  <nahrstaedt@gmail.com>

Copyright (c) 2018, 2019 Holger Nahrstaedt. MIT licensed.

beem is the library `comb` reimplements: `beemgraphenebase`, `beembase`, `beemapi`,
`beemstorage` and `beem` itself. Every serialization rule, every operation definition,
every key derivation and the entire signing scheme in this crate were learned by
reading beem's source. Where `comb` diverges, it is documented as a divergence from
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
`comb/src/sign.rs` is a direct, deliberate port of Fabian Schuh's implementation,
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
`comb/src/operations/` is generated against
`libraries/protocol/include/hive/protocol/operations.hpp`; where beem and hived
disagree, hived wins and beem is recorded as a finding. The
[developer documentation](https://developers.hive.io) is the reference for the RPC
layer.

Post-HF25 operations that beem never gained — `recurrent_transfer`,
`collateralized_convert`, and the virtual operations added through HF26–HF28 — come
from hived directly, not from beem.

## Third-party word list

`comb/data/brainkey_words.txt` is the 49,744-word Graphene brain-key dictionary,
carried forward unchanged from python-graphenelib via beem
(`beemgraphenebase/dictionary.py`). It must not be modified: the words and their order
determine which brain keys can be regenerated.

beem's `Mnemonic` implementation, which `comb` does not currently port, was itself
taken from [python-mnemonic](https://github.com/trezor/python-mnemonic) —
copyright (c) 2013 Pavol Rusnak, (c) 2017 mruddy.

## Rust dependencies

`comb` binds [libsecp256k1](https://github.com/bitcoin-core/secp256k1) through the
[`secp256k1`](https://crates.io/crates/secp256k1) crate maintained by the rust-bitcoin
project. All curve arithmetic is theirs; none of it is hand-rolled here. The remaining
dependencies — `sha2`, `ripemd`, `bs58`, `zeroize`, `subtle`, `serde`, `time` — are
listed in `Cargo.toml` with their own authors and licences.

## This port

The Rust translation in this repository was produced by Claude (Anthropic). It carries
no independent authorship claim: it is a translation of the work credited above, plus
the corrections recorded in `SECURITY_FINDINGS.md`.

`comb` is released under the MIT licence, matching beem, python-bitshares and
python-graphenelib, and reproduces their copyright notices in `LICENSE`.

## Corrections welcome

If you contributed to beem, python-graphenelib, python-bitshares, Graphene, Steem or
hived and are not named here — or are named incorrectly — please open an issue. This
file is meant to be right, and an omission in it is a bug like any other.
