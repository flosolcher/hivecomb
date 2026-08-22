# Replacing beem with hivecomb

This document is the complete record of how `hivecomb` relates to `beem`:

1. [Installing it as a drop-in](#1-installing-it-as-a-drop-in)
2. [What was fixed](#2-what-was-fixed) — every defect, and where the fix lives
3. [Deliberate divergences](#3-deliberate-divergences) — where behaviour differs on
   purpose, including the cases where beem was not wrong
4. [Additions](#4-additions) — what `hivecomb` does that beem cannot
5. [Coverage](#5-coverage) — what is implemented, what raises, what is not planned
6. [The native API](#6-the-native-api) — what to use once you are no longer porting

For how `hivecomb` compares to the other Rust Hive libraries — and an honest answer to
which is more mature — see [COMPARISON.md](COMPARISON.md).

Nothing here silently does something different from what you asked. Every gap raises
`NotImplementedError` naming an alternative; every divergence is listed below.

---

## 1. Installing it as a drop-in

The `python/` directory of this repository is a distribution that **provides the
`beem`, `beemgraphenebase`, `beembase` and `beemapi` package names**, implemented on
top of the `hivecomb` extension module. Installing it in place of beem makes existing
`import beem` code work unchanged.

```sh
pip uninstall -y beem
pip install maturin
maturin build --release          # builds the hivecomb extension module
pip install target/wheels/hivecomb-*.whl
pip install ./python             # the beem-compatible layer
```

Verify:

```python
import beem, beemgraphenebase
print(beem.__version__)          # hivecomb-compat-0.1.0, not 0.24.26
```

The version string is deliberately **not** `0.24.26`: anything that branches on the
version should be able to tell it is talking to hivecomb.

The `beempy` console script is installed too, so existing invocations keep working.

Nothing else changes. This keeps working verbatim:

```python
from beem import Hive
from beemgraphenebase.ecdsasig import sign_message

signature = sign_message(challenge, posting_wif)        # returns bytes, as before
hive = Hive(node=nodes, keys=[posting_wif], nobroadcast=True)
tx = hive.custom_json("my_app", {"hello": "hive"}, required_posting_auths=["alice"])
```

`python/test_compat.py` is exactly that: code written against beem's API, run through
the layer without modification. `python/test_cli.py` covers `beempy` offline.

### The one thing to check before you switch

**Signing no longer contacts a node**, so `Hive` needs a block reference from
somewhere. It fetches one on first use and caches it (default 180 s), refreshing when
it goes stale. If your process signs after a long idle period, that first signature
costs one round trip; call `hive.refresh_block_ref()` from a background task to remove
even that.

The cache **refuses** rather than serving a stale reference — signing against an
expired one produces a transaction the relay accepts and the chain rejects, which is
exactly the kind of silent failure this port exists to remove.

---

## 2. What was fixed

Every defect found in beem 0.24.26, with severity, and where `hivecomb` addresses it. Full
detail, with file and line, is in [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md).

| # | Sev | What beem does | Where `hivecomb` fixes it | Covered by |
|---|---|---|---|---|
| [1](SECURITY_FINDINGS.md#1) | Critical | Missing comma concatenates two operation names, shifting every HF25 id | `operations/ids.rs` — one table, index-is-id asserted | unit test |
| [2](SECURITY_FINDINGS.md#2) | Critical | Table cannot encode `recurrent_transfer`/`collateralized_convert`; all virtual ids off by two | `operations/ids.rs` — full 0–92 table from hived | unit test |
| [3](SECURITY_FINDINGS.md#3) | High | Silent fall-through to variable-time pure-Python ECDSA (Minerva) | `sign.rs` — one libsecp256k1 path | by construction |
| [4](SECURITY_FINDINGS.md#4) | High | `struct.pack("d", time.time())` as ECDSA nonce entropy | `sign.rs` — RFC 6979 + counter | unit test |
| [5](SECURITY_FINDINGS.md#5) | High | Bare `except:` falls back to the pre-HF24 all-zero chain id | `chains.rs`, `transaction.rs` — constant, no fallback, zero id refused | unit test |
| [6](SECURITY_FINDINGS.md#6) | Medium | `verify_message` cannot verify; a discarded result hides that | `sign.rs` — `recover` and `verify` separated and honestly named | unit test |
| [7](SECURITY_FINDINGS.md#7) | High | `Signed_Transaction.verify()` collects all four recovery candidates | `transaction.rs` — one key per signature, verified | unit test |
| [8](SECURITY_FINDINGS.md#8) | High | `String` mangles control characters into literal text | `types.rs` — raw UTF-8, length in bytes | unit test + oracle |
| [9](SECURITY_FINDINGS.md#9) | High | `repr()`/`str()` of a private key return the secret | `keys/private.rs` — redacted; export is explicit | unit test |
| [10](SECURITY_FINDINGS.md#10) | Medium | Invalid base58 decodes to wrong bytes instead of erroring | `base58.rs` — strict alphabet | unit test |
| [11](SECURITY_FINDINGS.md#11) | Medium | WIF version byte discarded unchecked | `base58.rs` — version required | unit test |
| [12](SECURITY_FINDINGS.md#12) | Medium | Length checks use bare `assert`, stripped under `python -O` | everywhere — checked `Result` | by construction |
| [13](SECURITY_FINDINGS.md#13) | Medium | Private scalar never range-checked | `keys/private.rs` — `SecretKey` enforces it | unit test |
| [14](SECURITY_FINDINGS.md#14) | Medium | Biased brain-key words; index one past the end | `keys/derive.rs` — rejection sampling | unit test |
| [15](SECURITY_FINDINGS.md#15) | Medium | Unauthenticated AES-CBC memos; unpad fails open | `memo.rs` — padding validated, constant-time checksum | unit test |
| [16](SECURITY_FINDINGS.md#16) | Medium | Amounts round-trip through `float`; global decimal context mutated | `asset.rs` — integer units throughout | oracle |
| [17](SECURITY_FINDINGS.md#17) | Medium | Timezone-aware datetimes read as though UTC | `types.rs` — strict UTC parsing | unit test |
| [18](SECURITY_FINDINGS.md#18) | Low | `is` used to compare integers | `operations/ids.rs` — `enum` | by construction |
| [19](SECURITY_FINDINGS.md#19) | Low | `init_aes` defined three times; broken import path | `memo.rs` — one definition | by construction |
| [20](SECURITY_FINDINGS.md#20) | Low | Master password stretched with one unsalted SHA-256 | `keys/derive.rs` — unchanged (protocol), but explicit | documented |
| [21](SECURITY_FINDINGS.md#21) | High | `flat_set` fields serialized in caller order, not sorted | `operations/mod.rs`, `authority.rs` — sorted, deduped | oracle |
| [22](SECURITY_FINDINGS.md#22) | Critical | `escrow_release` omits `agent` and `receiver`; `escrow_dispute` omits `agent` | `operations/mod.rs` — all fields | unit test |
| [23](SECURITY_FINDINGS.md#23) | High | `custom_binary` serializes 2 of 6 fields, mistypes `id` | `operations/mod.rs` — all six | unit test |
| [24](SECURITY_FINDINGS.md#24) | Medium | Memos omit the varint length prefix the ecosystem writes | `memo.rs` — prefix written, lenient read | unit test + interop |
| [25](SECURITY_FINDINGS.md#25) | High | Key store: unsalted SHA-256, unauthenticated AES-CBC | `wallet.rs` — scrypt + AES-256-GCM | unit test |

**"Oracle"** means the fix is verified by `tests/differential_beem.py`, which compares
`sha256(chain_id || serialized_tx)` against beem byte for byte over a generated corpus.

### Fixes you get without changing any code

Through the compatibility layer, findings 1–5, 7–8, 10–19 and 21–25 apply
automatically: they are all below the API surface. Finding 9 does **not** — see the
next section.

---

## 3. Deliberate divergences

Behaviour that differs on purpose. Some fix a defect; some are choices where beem was
not wrong, just different.

### 3.1 Secrets still render in the compatibility layer

`repr(PrivateKey)` returns the raw scalar and `str(PrivateKey)` returns the WIF —
matching beem, which is finding 9 reproduced **on purpose**. Real code depends on both
(`str(key)` to recover a WIF, `repr(key)` inside beem's own internals), and a drop-in
that changed them would not be a drop-in.

```sh
export COMB_COMPAT_REDACT_KEYS=1     # once you have checked your code
```

The native `hivecomb` API and the Rust API redact by default. This is the only place in
the project where a known defect is reproduced, and it is opt-out rather than opt-in
only because compatibility is the stated goal.

### 3.2 `verify_message` returns one key, not four

beem's `Signed_Transaction.verify()` looped over all four recovery parameters and
appended every candidate that did not raise (finding 7). `hivecomb` returns exactly one
key per signature.

Also note what `verify_message` can and cannot do — in beem and here alike. Recovery
answers *"which key would have produced this?"*, so a tampered signature does not fail;
it recovers a **different** key. The only real check is comparing:

```python
assert verify_message(msg, sig) == bytes(expected_pubkey)
```

### 3.3 Unknown options are refused, not ignored

`Hive(**kwargs)` raises `NotImplementedError` for an option it does not implement.
beem accepted a long tail of constructor arguments and quietly ignored the ones it did
not use. Silently dropping a setting the caller asked for is how a transaction ends up
doing something other than what was intended.

Options that describe machinery `hivecomb` does not have — `appbase`, `use_condenser`,
`data_refresh_time_seconds`, node-ranking settings — are accepted and ignored, because
there is genuinely nothing to configure.

### 3.4 Excess precision on an amount is an error

```python
hive.transfer("bob", "1.2345", "HIVE", account="alice")   # raises
```

HIVE has three decimals. beem's `ROUND_DOWN` quantize silently made this `1.234 HIVE`.
Quietly dropping a digit from a monetary amount transfers a different sum than the
caller asked for, so `hivecomb` refuses.

### 3.5 `flat_set` fields are sorted

`required_auths`, `required_posting_auths` and `proposal_ids` are sorted and
deduplicated before serialization, because hived declares them as `flat_set` and
re-serializes them sorted when computing the digest it verifies against. beem passed
the caller's order through, so an unsorted list produced a signature that does not
verify (finding 21).

If you were passing a sorted list already, nothing changes. If you were not, your
transactions were being rejected.

### 3.6 Memos carry a varint length prefix

`hivecomb` writes the prefix that hive-js, dhive, Keychain and HiveSigner all write; beem
did not (finding 24). Memos written by either are readable by both, **except** a memo
whose first byte reads as a valid length for the rest — those are genuinely ambiguous,
and `hivecomb` resolves them the way every other client does.

### 3.7 `Steem` is not supported

beem targeted both chains. `hivecomb` targets Hive. The Steem entry in beem's chain table
carries the all-zero chain id, which is the same trap as finding 5.

### 3.8 Timestamps must be UTC

`PointInTime` parses `YYYY-MM-DDTHH:MM:SS` and accepts a trailing `Z`. Any other
offset is refused rather than guessed at (finding 17).

hived's "never" sentinel — `time_point_sec::maximum()`, rendered as
`1969-12-31T23:59:59` because the formatter prints a `uint32` as a signed `int32` — is
parsed and round-tripped correctly. It appears in `next_vesting_withdrawal`,
`governance_vote_expiration_ts` and `last_owner_update`.

### 3.9 Serialization happens in Rust

beem's operation classes had `__bytes__` and produced Graphene binary in Python. Here
they are constructors and validators; `bytes(op)` raises. Python-side wire encoding is
exactly where findings 8, 22 and 23 lived.

### 3.10 `beempy` confirms before spending, and refuses to assume

Commands that move value — `transfer`, `powerdown`, `convert`,
`collateralizedconvert`, `recurrenttransfer`, `buy`, `sell`, `changerecovery` — ask
before broadcasting. With no terminal they refuse rather than assuming yes; set
`COMB_ASSUME_YES=1` to opt in for scripts.

`--dry-run` builds and signs without broadcasting, and prints the transaction.

### 3.11 `beempy` does not silently drop a flag

`beempy --account alice transfer bob 1.000 HIVE` uses `alice`. argparse applies
subparser defaults over the parent namespace, so the naive arrangement loses the value
— which is the same class of bug as the rest of this document, in the CLI rather than
the protocol.

### 3.12 Filtered history reports when it stopped looking

`beempy history --type transfer` pages until it has enough matches, bounded by
`--scan` (default 10,000 entries, since each batch is a round trip). If it hits the
bound it says so, rather than presenting a short list as though it were complete.

### 3.13 The RPC layer uses only the standard library

beem pulled in `requests` and `websocket-client`, and its CLI added Click, click-shell
and prettytable. The compatibility layer uses `urllib` and `argparse` and formats its
own tables, so it adds no dependencies beyond `hivecomb` itself. WebSocket transport is not
supported — every public Hive node serves HTTP JSON-RPC.

---

## 4. Additions

Things `hivecomb` does that beem cannot.

### 4.1 Operations beem cannot build

beem's operation table predates HF25, so `Operation.__init__` raises
`ValueError("Unknown operation")` for both of these:

```python
from beembase.operations import Recurrent_transfer, Collateralized_convert

hive.recurrent_transfer("bob", "1.000", "HIVE", recurrence=24, executions=12,
                        account="alice", pair_id=3)     # pair_id is HF28
hive.collateralized_convert("1.000", requestid=1, account="alice")
```

The `pair_id` extension (HF28) lets one account run several concurrent recurrent
transfers to the same recipient. beem predates it entirely.

### 4.2 The 43 virtual operations

beem models none of them — it returns the raw dictionary and leaves callers to reach in
by key. `hivecomb` has all 43 as types, including everything added since HF25:
`limit_order_cancelled`, `producer_missed`, `proposal_fee`, `proxy_cleared`,
`escrow_approved`, `escrow_rejected`, `expired_account_notification`,
`collateralized_convert_immediate_conversion`, `fill_recurrent_transfer`,
`failed_recurrent_transfer`, `declined_voting_rights`.

```rust
use hivecomb::operations::AnyOperation;
let op = AnyOperation::from_json(&entry["op"])?;   // signed or virtual, either way
```

### 4.3 Operations beem has no class for

`witness_block_approve`, `reset_account`, `set_reset_account` — present for
completeness and for reading historical blocks.

### 4.4 Offline signing

The chain id is a compile-time constant and the block reference is cached with an
explicit staleness bound, so producing a signature is pure CPU. beem called
`get_config` over JSON-RPC on the way to every signature.

### 4.5 Reading the wire format

`hivecomb` deserializes Graphene binary as well as writing it, so a transaction or block
can be decoded, and every operation round-trips through both binary and JSON. beem's
deserializer was a separate module sharing no code with its serializer.

### 4.6 Post-HF25 chain state

`governance_vote_expiration_ts`, `open_recurrent_transfers` and
`previous_owner_update` are modelled, with `Account::governance_votes_expired()` to
compute expiry locally.

### 4.7 Mana and RC arithmetic without a round trip

The chain stores mana at the last update and lets clients extrapolate:

```rust
account.voting_power(now);     // percentage, no network call
account.downvote_power(now);
rc_account.percentage(now);
```

The intermediate is `i128` — `current * 100 / max` overflows `i64` for any real VESTS
balance, which Python never had to think about.

### 4.8 BIP-32 / BIP-39 / BIP-38

Validated against the reference vectors. Hive's BIP-48 paths
(`m/48'/13'/<role>'/<account>'/<key>'`) are built in:

```python
key = hivecomb.PrivateKey.from_mnemonic(mnemonic, "posting", account_index=0)
```

BIP-38 output matches beem byte for byte, so existing `6P...` keys are readable.

### 4.9 An authenticated key store

`hivecomb::wallet` uses scrypt and AES-256-GCM, so a tampered wallet file fails
authentication rather than decrypting to something.

### 4.10 `beempy` commands beem has no equivalent for

`beempy commands --new` lists them:

| command | what it does |
|---|---|
| `recurrenttransfer` | set up a recurrent transfer (HF25), with `--pair-id` (HF28) |
| `collateralizedconvert` | convert HIVE to HBD immediately against collateral (HF25) |
| `mnemonic` | generate a BIP-39 phrase and derive all four Hive role keys from it |
| `bip38` | encrypt or decrypt a key under a passphrase |
| `decodetx` | decode a transaction to JSON |
| `virtualops` | stream virtual operations, which beem's table cannot name correctly |
| `opsinblock` | every operation recorded for a block, virtual included |
| `verifyauthority` | check whether keys satisfy an account's authority, offline |
| `commands` | list every command, or just the new ones |

### 4.11 Offline authority checking

Given a set of public keys, does it satisfy an account's authority? Offline, with no
round trip:

```python
report = account.verify_account_authority([pubkey], role="posting")
report["satisfied"]            # definitely satisfied, from keys alone
report["conclusive"]           # False => depends on accounts not looked up
report["unresolved_accounts"]  # the delegations that were not followed
```

`beempy verifyauthority <account> <PUBKEY>` does the same from the shell.

The three-way answer matters. An authority can delegate to another account, and
following that means fetching *its* authority. Reporting such a case as a plain "no"
is quietly wrong for any account that shares posting rights — which on Hive is most of
them. beem's method of this name asked the node to verify a whole transaction, which
needs a round trip and says nothing about why.

### 4.12 Reaching virtual operations at all

Virtual operations are emitted by consensus, not carried in a transaction, so they are
**not in `block_api.get_block`**. `Blockchain.get_ops_in_block(n, only_virtual=True)`
and `beempy opsinblock N --virtual` use the endpoint that has them.

### 4.13 Racing nodes on broadcast

```python
hive = Hive(node=nodes, keys=[wif], race_width=3)   # or per call:
hive.broadcast(signed, race_width=3)
```

```sh
beempy --race 3 customjson my_app '{"hello":"hive"}'
```

The same signed transaction goes to three nodes at once and the first acceptance wins,
so a sick node costs one timeout instead of delaying the whole failover chain.
Measured against two dead nodes: 878 ms racing, 3,366 ms sequential.

Safe because the chain deduplicates by transaction id — the same signed bytes arriving
at three nodes are accepted once. It would *not* be safe to sign per node: different
expirations mean different ids and both would land, which is why this takes one
already-signed transaction.

Default is 1, which is beem's behaviour exactly. Reads are left to ordinary failover,
since racing costs the public nodes N times the requests and only a broadcast is
usually on a deadline.

**Python stays synchronous**, deliberately: beem is synchronous and a drop-in must be.
Racing uses threads rather than asyncio, so nothing about the execution model changes.
The Rust side has an async equivalent behind the `async` feature.

### 4.14 Unknown fields survive

Every chain type carries an `extra` map, so a hardfork that adds a field does not
silently lose it.

### 4.15 A differential oracle

`tests/differential_beem.py` compares digests against beem byte for byte over a
generated corpus. `hivecomb/tests/live_fixtures.rs` parses real captured node responses.

---

## 5. Coverage

### Implemented

| Module | Status |
|---|---|
| `beemgraphenebase.account` | `PrivateKey`, `PublicKey`, `PasswordKey`, `BrainKey`, `Mnemonic` |
| `beemgraphenebase.ecdsasig` | `sign_message`, `verify_message` |
| `beembase.operationids` | full corrected table, `getOperationNameForId`, `isVirtualOperation` |
| `beembase.operations` | 30 operation builders, including the two beem cannot make |
| `beembase.signedtransactions` | `Signed_Transaction`: digest, id, sign, verify |
| `beemapi.noderpc` | `NodeRPC` with failover and attribute proxying |
| `beem.Hive` | `custom_json`, `transfer`, `vote`, `post`, `reply`, `comment_options`, `delete_comment`, `claim_account`, `create_claimed_account`, `witness_feed_publish`, `decline_voting_rights`, `finalizeOp`, `broadcast`, `recurrent_transfer`, `collateralized_convert`, chain-id checks, TaPoS |
| `beem.account` | `Account`, `Accounts` — balances, Hive Power, mana, RC, history, follows, delegations, broadcasts |
| `beem.comment` | `Comment`, `RecentReplies`, `RecentByPath` |
| `beem.witness` | `Witness`, `Witnesses`, `WitnessesVotedByAccount` |
| `beem.block` | `Block`, `BlockHeader` |
| `beem.blockchain` | `Blockchain` — block iteration, `ops`, `stream`, chain-wide lookups |
| `beem.vote` | `Vote`, `ActiveVotes`, `AccountVotes` |
| `beem.market` | `Market` — ticker, order book, trades, buy/sell/cancel |
| `beem.price` | `Price`, `Order`, `FilledOrder` |
| `beem.amount` | `Amount` — integer units, no float, no global decimal context |
| `beem.memo` | `Memo` |
| `beem.wallet` | `Wallet` — scrypt + AES-256-GCM |
| `beem.rc` | `RC` |
| `beem.community` | `Community`, `Communities` |
| `beem.discussions` | the ranked and account-post listings |
| `beem.nodelist` | `NodeList`, ranking by measured latency |
| `beem.transactionbuilder` | `TransactionBuilder` |
| `beem.exceptions` | the full hierarchy, names unchanged |
| `beem.cli` (`beempy`) | every beem command registered, plus 9 new; see below |

### Raises `NotImplementedError`, naming an alternative

| What | Why | Instead |
|---|---|---|
| `PublicKey.address`, `Address` | Graphene addresses are unused in Hive's protocol | the prefixed key form |
| `PrivateKey.bitcoin` | internal to BIP-38 | `PrivateKey.to_bip38()` |
| `PrivateKey.child` | non-hardened derivation | `hivecomb.PrivateKey.from_mnemonic()` |
| `BrainKey.suggest` | beem's generator was biased (finding 14) | `hivecomb.generate_mnemonic()` |
| `Mnemonic.to_seed` | | `hivecomb.PrivateKey.from_mnemonic()` |
| `bytes(Operation)`, `bytes(Signed_Transaction)` | Python-side wire encoding is where findings 8, 22, 23 lived | `Hive.finalizeOp`, `hivecomb.sign_transaction` |
| `Hive.sign` on a prebuilt tx | | `finalizeOp`, or `hivecomb.sign_transaction` |
| `beem.Steem` | see §3.7 | — |
| `recover_public_key`, `recoverPubkeyParameter` | beem's multi-backend machinery | `verify_message` |

### `beempy` commands that are registered but decline

Each prints why and names an alternative. They are registered rather than missing, so a
script that calls one gets an explanation instead of "unknown command".

| command | why |
|---|---|
| `uploadimage` | it posted to a third-party image host, which is not this library's job |
| `download` | it fetched post bodies for offline editing; the API does that directly |
| `draw` | it drew ASCII charts; pipe `pricehistory` into a plotting tool |
| `importaccount` | deriving a wallet's keys from a master password should be a deliberate act — use `passwordgen` then `addkey` |
| `newaccount`, `changekeys`, `updatememokey`, `allow`, `disallow` | authority changes are owner-level and irreversible; build them explicitly so every field is visible |
| `beneficiaries` | set them when posting, with `post --beneficiary` |
| `witnessupdate`, `witnesscreate`, `witnessdisable`, `witnessenable` | `witness_set_properties` encodes each value as the binary form of its own type, which this layer does not build; use hivecomb's `WitnessProperty` helpers |
| `addtoken`, `deltoken`, `listtoken` | they served beem's HiveSigner integration, which this layer does not provide |

### Not ported

`beem.Snapshot`, `beem.conveyor`, `beem.hivesigner`, `beem.imageuploader`,
`beem.profile`, `beem.asciichart`, `beemstorage`.

The RPC surface is reachable through `rpc.call(method, params)` exactly as beem's
`__getattr__` proxy made it, so anything hived exposes is still available untyped. If
you depend on one of these, open an issue.

---

## 6. The native API

Once you are no longer porting, the native surface is smaller and safer. In Python:

```python
import hivecomb

key = hivecomb.PrivateKey(wif)
print(repr(key))                         # <PrivateKey redacted>

sig = hivecomb.sign_message("challenge", wif)                  # hex
tx  = hivecomb.sign_transaction(operations, block_ref, [wif])  # no network

cache = hivecomb.TaposCache(max_age_seconds=180)
cache.store_block_id(head_block_id)                        # from a background task
tx = hivecomb.sign_transaction(ops, cache.block_ref(), [wif])  # raises if stale

memo = hivecomb.encode_memo(from_wif, to_pubkey, "hello")
```

In Node:

```js
import { PrivateKey, BlockRef, signTransaction, encodeMemo } from 'hivecomb'
```

Same surface, same guarantees — see `hivecomb-node/README.md`. The three bindings pin a
shared digest vector in their own test suites, so a drift in any one is caught
independently.

In Rust, see the [README](README.md) and the module documentation. The core builds
with `--no-default-features` into keys, serialization and signing alone — no network,
no cipher, no scrypt.
