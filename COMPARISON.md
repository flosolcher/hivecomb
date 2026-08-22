# hivecomb and the other Rust Hive libraries

`hivecomb` is not the first Rust library for Hive. This document says what the others do,
what `hivecomb` took from looking at them, and — since the question deserves a straight
answer — **which is actually more mature**.

Everything here was measured on 2026-08-22 against
[`hive-xylem` 0.1.6](https://github.com/srbde/hive-xylem) at commit
`2026-07-18`. Numbers move; re-measure before relying on them.

---

## The libraries

| crate | version | downloads | what it is |
|---|---|---|---|
| [`hive-xylem`](https://github.com/srbde/hive-xylem) | 0.1.6 | 99 | An async Rust SDK by SRBDE, part of a cross-language suite (Pollen/TS, Anther/Go, Nectar/Python) |
| [`hive_memo`](https://crates.io/crates/hive_memo) | 0.1.2 | 3,225 | Memo encryption and decryption only |
| [`hive-rs`](https://crates.io/crates/hive-rs) | 0.1.0 | 28 | A client library, described as a 1:1 port |
| `hivecomb` | 0.1.0 | unpublished | This crate |

`hive-xylem` is the closest comparison: a general-purpose SDK with overlapping goals.

---

## Is xylem more mature than hivecomb?

**On the one measure that matters most — production exposure — neither is mature, and
xylem is slightly ahead of hivecomb.** It is published on crates.io with five releases;
`hivecomb` is not published and has never had a transaction accepted by a Hive node. 99
downloads is not adoption, but it is more than zero.

On every other measure, `hivecomb` is substantially larger and more verified. Both facts
are true at once, and neither cancels the other.

| | hive-xylem | hivecomb |
|---|---|---|
| Rust source | 4,556 lines | 14,343 lines |
| Tests | 48 | 286 |
| Published | crates.io, 5 releases | no |
| Signable operations | 17 structs | **48** (all non-virtual except the two obsolete mining ops) |
| Virtual operations | none modelled | **43** |
| Wire deserialization | partial (strings, varints, ops) | full, with round-trip tests over every operation |
| Differential testing | none | against beem, 134-case digest corpus |
| Live-node fixture tests | none | 10 |
| Key derivation | WIF only | WIF, BIP-32, BIP-38, BIP-39, brain keys, password keys |
| Encrypted key store | none | scrypt + AES-256-GCM |
| Async | **native (Tokio)** | no — sync, with a pluggable transport |
| HAF client | minimal (reputation) | no |
| Other-language bindings | separate sibling projects | Python module, beem drop-in, `beempy` CLI |
| `unsafe` | none | none (`#![forbid(unsafe_code)]`) |
| `unwrap`/`expect` outside tests | 9 | 8 |

### The fair summary

xylem is a competently built, focused library. Its async-first design is a real
advantage `hivecomb` does not have, its code is clean, and it avoids `unsafe` entirely. If
you are writing a Tokio service and need transfers, votes, comments and `custom_json`,
it will do that today and it is a `cargo add` away.

`hivecomb` covers far more of the protocol, is verified against a reference implementation
rather than against its own expectations, and reaches Python. It is also unpublished
and unproven. **Breadth and testing are not the same thing as maturity**, and it would
be dishonest to present them as such.

---

## What hivecomb changed after reading xylem

Five gaps, all now closed. Each was written independently rather than copied; xylem is
MIT/Apache-2.0, so copying would have been permitted, but the rest of this crate is
written to its own conventions.

### 1. Authority satisfaction — `Authority::check`

Given a set of public keys, does it satisfy an authority? `hivecomb` had
`is_satisfiable()` (*can* these weights ever reach the threshold) but not *do these
keys reach it*.

xylem's `verify_authority` counts `key_auths` and **ignores `account_auths`**, so an
authority satisfied through a delegated account reports `false`. `hivecomb`'s version
reports that case as *inconclusive* instead:

```rust
let check = account.posting.check(&keys);
check.satisfied            // definitely satisfied, from keys alone
check.is_conclusive()      // false => depends on accounts not looked up
check.unresolved_accounts  // the delegations that were not followed
```

That distinction is not academic. Checked against `@hiveio`'s live posting authority,
which delegates to `@threespeak` and `@vimm.app`, a stranger's key gives
`satisfied: false, conclusive: false` — because the honest answer is "not from these
keys alone", not "no". Most active Hive accounts share posting rights this way.

Exposed as `hivecomb.check_authority()` in Python, `Account.verify_account_authority()` in
the beem layer, and `beempy verifyauthority`.

### 2. `get_ops_in_block` — the only route to virtual operations

Virtual operations are emitted by consensus, not carried in a transaction, so they are
**not in `block_api.get_block` at all**. Filtering a block's transactions for them
returns nothing rather than erroring — which is exactly what `beempy virtualops` did
before this was found.

Added as `NodeClient::ops_in_block` / `ops_in_block_range` in Rust,
`Blockchain.get_ops_in_block` in Python, and `beempy opsinblock --virtual`.

### 3. Block streaming in Rust

`hivecomb` had streaming in Python but not in Rust. `NodeClient::stream_blocks` is a lazy
iterator with `StreamMode::Irreversible` (the default worth having: about a minute
behind, but the blocks cannot be orphaned) and `StreamMode::Head`.

It **yields an error item rather than ending** when a call fails, so a transient outage
does not silently terminate a stream — which is the kind of failure that looks like
"the chain went quiet".

### 4. Exponential backoff

`NodeClient` tried each node once per call. It can now retry the whole list with
backoff, capped at 30s. The default is still **one pass**, because a call on a deadline
— a submit window — should fail fast and let the caller decide; multiple passes suit a
background task. Same in the Python client.

### 5. Reputation, and follow/mute helpers

Small conveniences xylem had that `hivecomb` only had on the Python side.

---

## A defect found in xylem while comparing

Reported here because it is verifiable and because it affects interoperability. It is
not a criticism of the project — it is the kind of thing differential testing exists to
catch, and `hivecomb` found two of its own the same way.

**`src/memo.rs` derives the ECDH shared secret from the wrong 32 bytes.**

```rust
let shared_point = secp256k1::ecdh::shared_secret_point(&recipient_pub, &sender_priv);
let shared_x = &shared_point[1..33]; // skip prefix byte to get X-coordinate
```

`shared_secret_point` returns **64 bytes — `X || Y`**, with no prefix byte. (It is
`PublicKey::serialize_uncompressed` that returns 65 bytes with a leading `0x04`; the
comment looks like it was written for that.) So `[1..33]` takes the last 31 bytes of X
plus the first byte of Y.

Verified against the `secp256k1` crate directly:

```
shared_secret_point len = 64
bytes[0..32]  (X) = cb5c6c7aab2bd72f4bd4458b9cc43d66a25b6ccbe9973cf06204ffc187f18f79
bytes[1..33]      = 5c6c7aab2bd72f4bd4458b9cc43d66a25b6ccbe9973cf06204ffc187f18f792e
true X            = cb5c6c7aab2bd72f4bd4458b9cc43d66a25b6ccbe9973cf06204ffc187f18f79
```

The consequence is that xylem derives a shared secret no other Hive client computes, so
its encrypted memos cannot be read by Keychain, hive-js, dhive, beem or `hivecomb`, and it
cannot read theirs. The fix is `&shared_point[0..32]`.

Everything else in that module is right, including the part beem gets wrong: xylem
**does** write the varint length prefix before encrypting, which
[finding 24](SECURITY_FINDINGS.md#24) shows beem omits.

---

## What hivecomb deliberately does not do

**Async.** `hivecomb` is synchronous, with a `Transport` trait as the only network seam.
That keeps the signing core free of a runtime — it builds with
`--no-default-features` into keys, serialization and signing with no HTTP client at all
— and lets a caller bring their own. The cost is real: there is no `async fn` API, and
wrapping a sync client in `spawn_blocking` is not the same thing as being async-native.
**If you need that today, xylem is the better fit.**

**HAF.** The Hive Application Framework is a Postgres-backed REST layer whose endpoints
vary by deployed app. `hivecomb`'s `NodeClient::call` reaches anything hived exposes over
JSON-RPC, but HAF is a different protocol and a moving target. xylem ships a minimal
client (reputation lookups); `hivecomb` ships none rather than a half-one.

---

## Credit

`hive-xylem` is credited in [CREDITS.md](CREDITS.md). The comparison sharpened five
parts of this crate, and finding a bug in someone else's careful work is a reason to
say so publicly rather than quietly.
