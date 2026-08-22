# Changelog

Notable changes to `hivecomb`, the Rust crate, the Python module and the Node addon,
which share a version number and are released together.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the caveat that
`0.x` makes no compatibility promise: while the major version is zero, a minor bump may
break the API. The one thing that will not change quietly is **the bytes that get
signed** — a change there is a breaking change regardless of what the version number
would otherwise say, and it will be called out here in its own section.

## [Unreleased]

Nothing yet.

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
compares digests. It found four defects that 292 unit tests and a 134-case differential
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
