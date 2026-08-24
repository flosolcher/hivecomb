# Changelog

Notable changes to `hivecomb`, the Rust crate, the Python module and the Node addon,
which share a version number and are released together.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the caveat that
`0.x` makes no compatibility promise: while the major version is zero, a minor bump may
break the API. The one thing that will not change quietly is **the bytes that get
signed** — a change there is a breaking change regardless of what the version number
would otherwise say, and it will be called out here in its own section.

> While 0.1.0 is unreleased, everything lands in its section below. An
> `[Unreleased]` heading comes back above it once 0.1.0 ships — see
> [RELEASING.md](RELEASING.md).

## [0.1.0] — unreleased

First release. Nothing is published to crates.io, PyPI or npm yet, so this section
describes the initial contents rather than a delta.

### What it is

A Rust port of [`beem`](https://github.com/holgern/beem) 0.24.26, with the defects
`beem` carries fixed, the operations added since it stopped tracking Hive, and bindings
so it can replace `beem` in an existing Python program without changing that program.

- **Rust crate** (`hivecomb`) — keys, Graphene serialization, signing, 48 signable and
  43 virtual operations, encrypted memos, BIP-32/38/39, brain and password keys, an
  encrypted wallet, a JSON-RPC client with node failover, an optional runtime-agnostic
  `async` layer with request racing, and chain types read as plain data.
  `#![forbid(unsafe_code)]`. Builds with `--no-default-features` into keys,
  serialization and signing with no HTTP client and no executor.
- **Python module** (`hivecomb`, PyO3/abi3) — keys, signing, memos and all operations.
- **beem-compatible layer** — `import beem` keeps working. See
  [MIGRATION.md](MIGRATION.md) for what is identical, what diverges deliberately, and
  what is not implemented (which raises rather than silently doing something else).
- **`beempy` CLI** — every `beem` command, plus nine that `beem` did not have.
- **Node addon** (napi-rs) with TypeScript types.

### Fixed, relative to beem

Twenty-five findings are catalogued with file, line and consequence in
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md). The ones that change signed bytes or
disclose keys:

- a missing comma in `operationids.py` that concatenated two operation names and shifted
  every id after it, so post-HF25 operations serialized under the wrong id
- an operation table that could not encode `recurrent_transfer` or
  `collateralized_convert` at all, and had every virtual operation id off by two
- a bare `except:` falling back to the pre-hardfork-24 all-zero chain id, producing a
  signature valid on no chain
- a pure-Python ECDSA fall-through with variable-time scalar multiplication
- nonces drawn from the wall clock
- `flat_set` fields serialized in the caller's order rather than sorted, so hived
  reconstructs different bytes and the signature does not verify
- `escrow_release` missing `agent` and `receiver` — the field naming who gets the funds
- `escrow_dispute` missing `agent`; `custom_binary` serializing 2 of 6 fields
- monetary amounts round-tripped through binary `float`, plus a mutated process-global
  decimal context (measured: `50000000000.123456 VESTS` off by four units)
- memos written without the varint length prefix the rest of the ecosystem writes
- a wallet keyed by unsalted SHA-256 under unauthenticated AES-CBC
- private keys rendering themselves as the secret in `__repr__`

### Retracted

- **Finding 8 was wrong.** `beem`'s `unicodify()` was published here as a
  High-severity defect that corrupts signed bytes. It is correct: hived parses JSON-RPC
  with `fc`, which does not decode `\uXXXX`, `\b` or `\f` but strips the backslash and
  keeps the rest literally, so the node serializes the expanded text. Measured against a
  live node, the affected set is character-for-character the one `beem` lists.
  `hivecomb` wrote raw UTF-8 on the strength of that finding and therefore signed bytes
  hived does not compute. `types::hived_transport_form` now applies the same transform.
  The finding is retracted in place rather than deleted.

### Fixed in hivecomb itself, found by asking hived

`tests/hived_serialization_oracle.py` asks a node to serialize each operation and
compares digests. It found four defects that the whole unit-test suite and a 134-case differential
oracle against `beem` had all missed. Each would have produced a transaction the chain
rejects:

- `escrow_transfer` field order — the amounts precede `escrow_id` and `agent`, and
  `json_meta` sits between `fee` and the two deadlines
- `limit_order_create2` — `exchange_rate` precedes `fill_or_kill`, the reverse of what
  the sibling operation suggests
- `recurrent_transfer`'s HF28 `pair_id` is `uint8_t`, not `u16` (hived truncates rather
  than rejecting: 258 serializes as `0x02`)
- that extension's JSON must be `{"type", "value"}`; hived refuses the `[tag, value]`
  array outright, so it could not be broadcast at all

The two field-order defects round-tripped perfectly through `hivecomb`'s own serializer
and deserializer. A round-trip test cannot catch a format that is wrong in both
directions.

`Hive.finalizeOp` also accepted a `permission` argument and never used it, signing with
whatever keys the constructor was given and never consulting the wallet. `beem` selected
the key by role, so a wallet user calling `hive.transfer()` got the posting key and a
rejection.

`pbkdf2` was declared with `default-features = false`, dropping the `hmac` feature that
provides `pbkdf2_hmac`. It built only because `scrypt` — pulled in by `wallet` and
`bip38`, both on by default — enabled it through feature unification, so
`--features bip32` alone did not compile.

### Added, relative to beem

Operations `beem` predates, all reachable from Rust, Python, the beem layer and the CLI:
`recurrent_transfer` (with the HF28 `pair_id`), `collateralized_convert`,
`claim_account`, `create_claimed_account`, `account_update2`, `create_proposal`,
`update_proposal`, `update_proposal_votes`, `remove_proposal`,
`witness_set_properties`, and the virtual operations through id 92.

Beyond `beem`: three-way authority satisfaction checking that reports *inconclusive*
rather than false when an authority depends on accounts not looked up; block streaming;
`get_ops_in_block`; exponential backoff; an async layer with request racing across nodes
(measured 878 ms against 3,366 ms with two dead nodes in front of a working one); and an
encrypted key store using scrypt and AES-256-GCM.

### Performance

Signing is dominated by elliptic curve arithmetic, and was dominated by
*setup* for it: `Secp256k1::new()` and `signing_only()` build precomputation
tables on every call, and four hot paths called them per operation. Using the
process-wide context instead, measured through the Python module:

| | before | after | |
|---|---|---|---|
| `sign_transaction` (one `custom_json`) | 117.3 µs | **51.5 µs** | 2.3× |
| parse a WIF and derive the public key | 62.3 µs | **24.1 µs** | 2.6× |
| `sign_message` | 105.1 µs | **69.1 µs** | 1.5× |
| `transaction_digest` (no signing) | 8.8 µs | 7.5 µs | — |

All three bindings share this core, so all three benefit.

**The Node addon was paying more to return a transaction than to sign one.** Measured
against dhive 1.3.6, `signTransaction` with 50 operations cost 508 µs against dhive's
236 — and signing accounted for 239 µs of that, so the return path outweighed the
elliptic curve work. Two causes: `operation_from_json` deep-copied every operation's
JSON tree on a vector it already owned, and the result was built as a
`serde_json::Value` that napi then walked node by node. The copy is gone and the result
is rendered straight to a JSON string for V8's own parser.

Operations may now also be passed as a pre-stringified JSON array (`operations: string
| Array<any>`) — one string crosses the boundary once, where an array is converted field
by field. Worth 25–30%.

| `signTransaction`, ops | dhive 1.3.6 | before | after |
|---|---|---|---|
| 1 | 123.3 µs | 94.5 µs | **88.5 µs** |
| 10 | 149.9 µs | 157.1 µs | **133.3 µs** |
| 50 | 242.1 µs | 449.4 µs | 344.3 µs |

hivecomb now wins signing up to about fifteen operations in one transaction, where it
previously crossed over at about five. Beyond that dhive still wins, and the reason is
structural: hivecomb's serializer is only ~1.4× faster than dhive's JavaScript, which is
not enough headroom to also pay for crossing the boundary. The win at ordinary sizes is
the curve arithmetic — 71 µs against dhive's 103 for one signature. The public API and
`index.d.ts` are unchanged.

What this deliberately does *not* do is echo back the caller's own operations array,
which would be faster still and wrong: hivecomb normalises operations on the way in, so
the array handed back must be the one that was actually signed.


### Added — opt-in node health tracking

`NodeClient::with_health_tracking` and `AsyncNodeClient::with_health_tracking`. Both
clients walk their node list from the front on every call, which is predictable and is
the right mechanism for an application with failover policy of its own — but in a
long-running process a dead first node then costs its full timeout on *every* call,
forever.

With health tracking on, the client remembers consecutive failures per node, failures
per node *and method*, and head block staleness, and sorts the list accordingly. Head
blocks are read from responses that already carry one; no extra request is issued, since
a library that health-checks on its own initiative is spending the caller's rate limit
on a decision the caller did not ask for. `AsyncNodeClient::race` spends its slots on
the healthiest nodes rather than the first ones.

Two properties are worth stating because they are easy to get wrong, and one of them was
got wrong first:

- **Health reorders the node list and never removes a node.** When every node is
  cooling, the call still tries all of them. A tracker that can exclude a node can turn
  a partial outage into a total one.
- **A whole-node cooldown requires failures across more than one method.** Otherwise a
  node that merely lacks one API — a partial node, which operators do run — crosses the
  node-wide threshold as well and gets cooled entirely, making per-method tracking
  decorative in the case it exists for.

The Python compatibility layer has its own pure-stdlib client rather than a binding to
the Rust one, and it gained the same feature with the same rules — plus one decision the
Rust client does not have to make: a JSON-RPC *protocol* error is not counted against the
node, because the node answered and the request was what was wrong.

Off by default everywhere, so nothing changes for callers who do not ask for it, and
beem's behaviour is what the default still gives.

### Fixed — `AsyncNodeClient` was only cloneable for cloneable transports

It holds its transport behind an `Arc` precisely so that cloning shares one transport,
but `#[derive(Clone)]` adds a `T: Clone` bound regardless. A caller whose transport was
not itself `Clone` — an ordinary connection-pool wrapper, say — could not clone the
client at all. The impl is now written out by hand without the bound.

### Known behaviour worth stating

**Serializing is not the inverse of parsing, for strings carrying control bytes.** A
string field holding a raw byte below `0x20` reads back as that byte and writes out as
the five characters `u0000`, because hived's JSON parser does the same and those are
the bytes a signature must cover. It settles after one pass. A transaction parsed from
*foreign binary* and re-signed therefore does not sign the bytes it arrived as; bytes
that came from hived cannot contain such a character in the first place. Found by
cargo-fuzz on its first run.

### Requirements

Rust **1.88** or newer. That floor comes from dependencies rather than from this
crate's own code — several are on edition 2024, which Cargo below 1.85 cannot parse at
all — and it applies even with `--no-default-features`. CI builds and tests against it,
so it is a measured number, not an aspiration.

Python 3.8+ (abi3), Node 20+.

### Hardening

- Key generation draws from `OsRng` rather than `thread_rng`, matching BIP-39
  entropy. One source for every secret this crate creates.
- Every parser reachable from untrusted bytes is swept with hostile input — 414
  cases plus every truncation and every single-bit corruption of a well-formed
  transaction. All return an error; none panic. A parser that panics is a denial
  of service in the process holding the keys.
- The operation table has one owner. It previously existed in both Rust and the
  beem-compatible Python layer, agreeing on all 93 ids by luck rather than by
  construction — which is structurally the defect catalogued as findings 1 and 2
  in beem. Python now derives its table from
  `hivecomb.operation_names()`.
- [SECURITY.md](SECURITY.md) sets out how to report a defect, what is in scope,
  and what is known not to be sound (the master-password and brain-key schemes,
  which are Hive's design and cannot be changed).

### Verified by someone else

An outside integrator replaced beem with this library in a production application,
built their own ten-case digest gate from that application's real `custom_json` payload
shapes, and reproduced digest equality with beem byte for byte. They found no defect
here; four they did find were in their own code. That is a narrow slice — one operation
type — and weak evidence of absence, but it is the first check of this crate's
serialization written by someone other than its author.

Their report produced three fixes: the JSON framing divergence recorded above, type
stubs, and an explicit `__all__`.

### Type stubs, and an explicit `__all__`

The wheel ships `__init__.pyi` and a `py.typed` marker **inside the package**, so a
consumer's type checker resolves the module rather than seeing `Any`. A test asserts the
stub against the module's own `__text_signature__`: a stub that has drifted is worse
than none, because it type-checks code that fails at runtime.

`__all__` is declared explicitly and is identical however the package is installed.
Derived automatically it carried `__doc__` and `__version__`, so `from hivecomb import *`
would have rebound the importer's docstring — and `dir()` differed by one between a bare
`.so` and a wheel, because Python binds a submodule on its parent. **Bind capability
checks to `__all__`, not `dir()`.**

**Stubs do not replace a runtime capability check.** Stubs are checked against the path
at type-check time; a capability check runs against the `.so` actually loaded, and only
that catches a stale installed build — source updated, package not reinstalled.

### Verified

- **hived serialization oracle** — 57 cases, all 48 operations, 57 identical
- **hived authority oracle** — 26 operations, 26 agree on the required authority
- **differential oracle against beem** — 150 cases, 124 identical, 26 deliberate
  divergences, 0 unexpected
- 295 Rust unit tests, 10 live-node fixture tests, 30 Python compatibility checks,
  24 CLI checks, 28 Node tests, clippy clean across feature combinations
- **accepted by the Hive network** — block
  [109242605](https://hivehub.dev/tx/ebb44fb5dedd544b7deeb62f81660983233a559f), a
  `custom_json` under posting authority. The chain filed it under the transaction id
  `hivecomb` computed offline.

One accepted transaction is not production exposure. See [BROADCAST.md](BROADCAST.md)
for what each stage establishes and what it does not.

[Unreleased]: https://github.com/flosolcher/hivecomb/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/flosolcher/hivecomb/releases/tag/v0.1.0
