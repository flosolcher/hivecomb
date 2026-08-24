# hivecomb

[![CI](https://github.com/flosolcher/hivecomb/actions/workflows/ci.yml/badge.svg)](https://github.com/flosolcher/hivecomb/actions/workflows/ci.yml)
[![live oracles](https://github.com/flosolcher/hivecomb/actions/workflows/live-oracles.yml/badge.svg)](https://github.com/flosolcher/hivecomb/actions/workflows/live-oracles.yml)

Hive blockchain keys, Graphene serialization and **offline** transaction signing — in
Rust, with Python and Node.js bindings.

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

```js
import { BlockRef, signTransaction } from 'hivecomb'

const tx = signTransaction(
  [['custom_json', { required_posting_auths: ['alice'],
                     id: 'my_app', json: { hello: 'hive' } }]],
  BlockRef.fromBlockId(headBlockId),
  [postingWif],
)
```

## Install

**Nothing is published yet.** These are the names reserved for the first release; until
then, build from this repository. See [RELEASING.md](RELEASING.md).

```bash
cargo add hivecomb                  # Rust
pip install hivecomb                # Python: keys, signing, memos, all operations
pip install hivecomb-beem           # ...and the beem drop-in, including `beempy`
npm install hivecomb                # Node.js: native addon, TypeScript types included
```

`hivecomb-beem` replaces `beem` in an existing program without changing that program.
Uninstall `beem` first — the package names deliberately collide. See
[MIGRATION.md](MIGRATION.md).

Rust 1.88+, Python 3.8+ (abi3 wheels), Node 20+.

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

**2. beem has defects that fail silently.** Twenty-five of them are catalogued in
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) with file, line, and consequence. The ones
that matter most are not crashes — they are the paths that produce a *valid-looking
signature over the wrong bytes*: a bare `except:` that falls back to the pre-hardfork-24
all-zero chain id, monetary amounts that round-trip through binary `float`, `flat_set`
fields serialized in the caller's order rather than sorted, `escrow_release` missing the
field that names who receives the funds.

One entry in that catalogue is a **retraction**: beem's control-character handling was
listed as a defect and is in fact correct, which `hivecomb` discovered by getting it
wrong. It is left in place, marked, rather than quietly removed.

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
| beem-compatible Python layer | done — drop-in, with its own test suite |
| Node.js addon (napi-rs) | done — native, with TypeScript types |
| beem object wrappers (Account, Market, …) | done |
| `beempy` CLI | done — every beem command, plus 9 new |
| Differential oracle vs beem | done, green |
| Serialization oracle vs **hived itself** | done, green — all 48 operations |
| Live-node fixture tests | done |
| **Transaction accepted by the Hive network** | done — block [109242605](https://hivehub.dev/tx/ebb44fb5dedd544b7deeb62f81660983233a559f) |
| Authority satisfaction checking | done |
| Block streaming, `get_ops_in_block` | done |
| Async RPC layer (`async` feature) | done — runtime-agnostic |
| Concurrent node racing | done — sync and async |
| Wallet / encrypted key storage | done — scrypt + AES-GCM |

Chain state is modelled as plain data (`hivecomb::chain`), read from the API rather than
constructed. beem's equivalents subclass `dict` and can each reach the network on their
own — which is the design that puts a node call inside the signing path. Here the types
are inert and the client is explicit.

## Layout

```
hivecomb/        the library                     — crates.io: hivecomb
hivecomb-py/     PyO3 bindings                   — PyPI: hivecomb
hivecomb-node/   napi-rs addon                   — npm: hivecomb
python/          the beem drop-in and beempy     — PyPI: hivecomb-beem

hivecomb/examples/                  runnable: sign_offline, and the rest
tests/  differential_beem.py          the oracle against beem
        hived_serialization_oracle.py the oracle against hived itself
        hived_authority_oracle.py     which key each operation must be signed with
        hived_broadcast_check.py      the one thing that needs a real account
        bench_vs_nectar.py            timings against hive-nectar, same interpreter

README.md            you are here
CONTRIBUTING.md      how to verify a change — read before touching serialization
SECURITY.md          how to report a defect that could cost someone funds
MIGRATION.md         replacing beem: what is identical, what diverges, what is missing
SECURITY_FINDINGS.md what was wrong in beem, with file:line — and one retraction
BROADCAST.md         what is proven against the live chain, and what is not
COMPARISON.md        hivecomb against the other Rust Hive libraries, honestly
CHANGELOG.md         what changed
RELEASING.md         how a release happens, and what is not set up yet
CREDITS.md           upstream authorship
```

## Building

```bash
cargo test --all-features                  # 324 unit tests + 10 live-node fixtures
cargo build -p hivecomb --no-default-features  # signing only: no network, no cipher, no scrypt
```

```bash
cargo run --example sign_offline --no-default-features
```

That example builds and signs with no HTTP client and no async runtime compiled in at
all — if it ever stops doing so, something has pulled a network dependency into the
signing path.

It is also the recipe for an offline signer on a machine with no Python:

```bash
cargo build --release --example sign_offline --no-default-features
# target/release/examples/sign_offline — 1.7 MB, no network dependency
```

There is no `hivecomb` CLI binary published, deliberately — `beempy` covers the command
line for anyone who has Python, and 1.7 MB of statically linked signing is a hundred
lines of `clap` away for anyone who does not. See [COMPARISON.md](COMPARISON.md).

Feature flags keep the core small. `--no-default-features` builds keys, serialization
and signing alone — no HTTP client, no executor. `memo`, `bip38`, `bip32`, `wallet`,
`rpc`, `ureq-transport`, `async` and `reqwest-transport` are additive, and every
combination is checked warning-free.

### Racing nodes

Sequential failover has a worst case of *the sum of the timeouts*: three sick nodes at
fifteen seconds each is forty-five seconds before the fourth is tried. Racing has a
worst case of **one**, which is the difference between a transaction landing inside its
window and being lost:

```rust
// Rust, async feature: fire at three nodes, take the first acceptance.
let client = AsyncNodeClient::new(ReqwestTransport::new()?, nodes)?;
client.broadcast_raced(&signed, 3).await?;
```

```sh
# beempy: same property, threads rather than asyncio, so beem's sync world is intact.
beempy --race 3 customjson my_app '{"hello":"hive"}'
```

Safe for reads unconditionally, and safe for broadcasting an *already-signed*
transaction because the chain deduplicates by transaction id. Measured against two dead
nodes: 878 ms racing, 3,366 ms sequential.

Python wheels, via [maturin](https://github.com/PyO3/maturin):

```bash
maturin develop          # build and install into the active venv
maturin build --release  # abi3 wheel, CPython 3.8+
```

## Speed, against beem

Both libraries signing identical operations, same machine, same interpreter, pinned
to one core. Medians of seven one-second windows, with the **payload varied on every
call** — signing grinds until the signature is canonical, and how many attempts that
takes depends on the digest, so a fixed payload measures one payload's luck over and
over. CPython 3.12, beem 0.24.26 on the `ecdsa` backend a default install selects.

Reproduce with `tests/bench_vs_beem.py`.

|  | hivecomb | beem 0.24.26 | |
|---|---|---|---|
| sign a message | 72.9 µs | 24.4 ms | ~335× |
| sign a `custom_json` | 90.5 µs | 27.9 ms | ~308× |
| sign a `transfer` | 90.1 µs | 26.5 ms | ~294× |
| serialize and digest, no signing | **9.8 µs** | **65.2 µs** | **~6.6×** |

Both produce the same digest — `cef35a5b34…` — which is checked before anything is
timed, and a mismatch aborts the run rather than printing a table. A benchmark of two
implementations that disagree measures nothing.

**Those ratios need three caveats, and they matter more than the numbers.**

**It is beem's ECDSA backend, not Python, that costs 30 ms.** beem picks a backend at
import. On the `cryptography` one it grinds for a canonical signature and derives the
recovery parameter by recovering the public key **in pure Python** on every attempt.
That loop is the 30 ms. The gap in the last row — serialization only, no cryptography —
is the honest measure of Rust against Python here, and it is ~8×, not ~300×.

**beem's fast backend no longer works.** It prefers `secp256k1` when importable, which
would close most of the gap. Installed against a current binding (0.14.0) it raises
`AttributeError: 'PrivateKey' object has no attribute 'ctx'` — beem was pinned to an API
that has since changed, and has not been maintained since 2021. So the slow path is not
a strawman; it is what an install gets today.

**beem had to be handed the right chain id to compare at all.** Its
`known_chains["HIVE"]` is the all-zero pre-hardfork-24 value
([finding 5](SECURITY_FINDINGS.md#5)), so out of the box it signs against a chain that
has not existed since 2020. The benchmark passes the real chain id explicitly, exactly
as [the differential oracle](tests/differential_beem.py) does.

Reproduce with [`tests/bench_vs_beem.py`](tests/bench_vs_beem.py). There is also
[`tests/bench_vs_nectar.py`](tests/bench_vs_nectar.py) against beem's maintained
successor, where the gap is much smaller — 2–7× — because nectar hands its curve
arithmetic to the same C library this crate does.

## Verification

There are two digest oracles, and the second one matters more.

### Against hived itself

`condenser_api.get_transaction_hex` makes a node serialize a transaction and return the
bytes, so hived can be asked directly whether `hivecomb`'s wire format is its own. It
costs nothing, needs no account and writes nothing to the chain.

```
$ python tests/hived_serialization_oracle.py
57 cases: 57 identical, 0 differ, 0 errored
```

This is the authority. On 2026-08-22 it found four defects that the beem oracle and the
whole unit-test suite had
all missed — three field-order or width errors (`escrow_transfer`, `limit_order_create2`,
the HF28 `pair_id`, which hived declares `uint8_t`), and one JSON shape hived rejects
outright. Every one of them would have produced a transaction the chain refuses.

It also **overturned a published finding**: [8](SECURITY_FINDINGS.md#8) claimed beem's
`unicodify` corrupts signed bytes, and the truth is the reverse — it models hived's JSON
parser exactly, and `hivecomb` was the one that had it wrong. That finding is retracted
in place rather than deleted.

The lesson is worth stating plainly, because the failure was structural: round-trip
tests cannot catch a format that is wrong in both directions, and a unit test written
from a belief tests the belief. Only an external authority helps.

### Against beem

The digest `sha256(chain_id || serialized_tx)` is deterministic and backend-independent,
so every serialization bug lives there. beem remains useful as a second opinion on the
operations it supports.

```
$ python tests/differential_beem.py
digest corpus     : 150 cases
  identical       : 124
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

### Four implementations agree on the digest

`sha256(chain_id || serialized_tx)` for the same transaction, computed independently by
**hived** (via `condenser_api.get_transaction_hex`), **beem**, **hive-nectar** and
**dhive** — all four byte-identical to `hivecomb`. Two of those were checked by other
people on their own inputs, not by this project.

That is worth more than any test count here: a serialization bug that four independent
implementations share is a specification problem, not a `hivecomb` problem.

### By someone who is not the author

An outside integrator replaced beem with `hivecomb` in a production application and
built their **own** digest gate to check it — ten `custom_json` cases whose shapes came
from that application's real payloads: long id strings, forty-element arrays,
two-hundred-character fields, multi-byte UTF-8, nested and mixed types, integers either
side of 2⁵³. Compared against beem byte for byte, through their own framing layer.
**Green.** They also verified signatures recover to the right key and refuse a
different message, and completed an end-to-end broadcast the chain accepted.

Two things about that, because the distinction matters more than the headline.

**Ten cases, not a hundred and fifty.** They also ran the corpus in this repository and
it passed, but that is this project's harness and this project's corpus — running it
elsewhere is not independent validation and is not claimed as such. What is independent
is the ten: a corpus written by someone else, from payload shapes this project had
never seen.

**They found no defect in `hivecomb`, and that is weak evidence.** Ten cases of a single
operation type is a narrow slice; their own report says so. Four defects were found
during that work and all four were in their code. The
[hived oracle](tests/hived_serialization_oracle.py) remains the stronger gate, because
it covers every operation and compares against the chain's own software rather than
against another implementation.

What the integration did surface is the more useful kind of finding: `custom_json`
payloads handed over as a dict were framed as raw UTF-8 here and `\uXXXX`-escaped by
beem, so the same logical payload signed different bytes. Both valid, neither a bug,
and invisible to any test using ASCII — it took someone diffing the two on real data.
That is now [documented](MIGRATION.md), and it is why the API ships type stubs it did
not have before.

## Before you trust it

Serialization is proven against hived, and the signing path is proven on the live
network: a `custom_json` signed by `hivecomb` was accepted into **block
[109242605](https://hivehub.dev/tx/ebb44fb5dedd544b7deeb62f81660983233a559f)** on 2026-08-22, and the transaction id the chain
filed it under is the one `hivecomb` computed offline. [BROADCAST.md](BROADCAST.md)
records what each stage establishes.

That is the floor, not the ceiling. One accepted transaction is not production
exposure, and it proves the signature path for one operation, not all 48.

Before putting this in front of anything valuable:

1. **Broadcast one transaction of your own.** `tests/hived_broadcast_check.py`, posting
   key only. Its `--dry-run` has a node verify the signature without writing anything.
2. **Run it alongside your existing signer** and compare, for a period, before letting
   it sign alone.
3. **Extend both corpora** to cover the operations *you* actually send.

The chain id is hardcoded, which is correct today and is exactly the kind of constant
that moves at a hardfork. It lives in one place — `hivecomb/src/chains.rs` — with a comment
saying so. `NodeClient::verify_chain_id` will tell you if a node disagrees.

## Node.js

```js
import { PrivateKey, BlockRef, signTransaction } from 'hivecomb'

const tx = signTransaction(
  [['custom_json', { required_posting_auths: ['alice'], id: 'my_app', json: { hello: 'hive' } }]],
  BlockRef.fromBlockId(headBlockId),
  [postingWif],
)
```

A native addon (napi-rs) with TypeScript definitions, in `hivecomb-node/`. It is the
signing and serialization core, not an RPC client — `dhive` and `hive-js` already do
that, and this is meant to sit underneath one of them. The addon carries no HTTP client,
since Node has its own.

Keys are redacted in `toString`, template literals, `JSON.stringify` and `util.inspect`,
each covered by a test.

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
do, and exactly what is not implemented. `python/test_compat.py` runs beem's own API
unmodified through the layer, and `python/test_cli.py` covers `beempy` offline.

`beempy commands --new` lists the nine commands beem has no equivalent for.

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
| npm | `hivecomb` — `import { PrivateKey } from 'hivecomb'` |
| Repository | [`flosolcher/hivecomb`](https://github.com/flosolcher/hivecomb) |

**The compatibility layer shadows beem on purpose.** `hivecomb-beem` installs packages
called `beem`, `beemgraphenebase`, `beembase` and `beemapi`, and a console script
called `beempy` — because being a drop-in replacement is the whole point. It cannot be
installed alongside beem, and the [migration guide](MIGRATION.md) says so up front.
`beem.__version__` reports `hivecomb-compat-0.1.0` rather than `0.24.26`, so anything
that branches on the version can tell which library it is talking to.

## Other Rust Hive libraries

`hivecomb` is not the first. [COMPARISON.md](COMPARISON.md) sets it beside
[`hive-xylem`](https://github.com/srbde/hive-xylem) in Rust,
[`hive-nectar`](https://github.com/srbde/hive-nectar) in Python and
[`dhive`](https://github.com/openhive-network/dhive) in Node. Each section leads with
what this project **took** from that library — six things from xylem, the disclosure
route and the signed-message envelope from nectar, the node health tracker's design from
dhive — then what the measurements show, then where the other one is ahead.

It answers the maturity question plainly rather than burying it: **xylem is published
and `hivecomb` is not**, nectar is more mature than this project's Python side by every
measure that can be counted, and on production exposure `hivecomb` is the least proven
of the four.

## Licence

MIT, matching beem, python-bitshares and python-graphenelib, whose copyright notices are
reproduced in [LICENSE](LICENSE).
