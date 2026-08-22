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
`hivecomb` is not published. 99 downloads is not adoption, but it is more than zero.

`hivecomb` has now had a transaction accepted by the Hive network — block
[109242605](https://hivehub.dev/tx/ebb44fb5dedd544b7deeb62f81660983233a559f), 2026-08-22 — so the signing path is no longer
unproven. One accepted transaction is not production exposure either, and it would be
dishonest to present it as such.

On every other measure, `hivecomb` is substantially larger and more verified. Both facts
are true at once, and neither cancels the other.

| | hive-xylem | hivecomb |
|---|---|---|
| Rust source | 4,556 lines | 15,619 lines |
| Tests | 48 | 305 |
| Published | crates.io, 5 releases | no |
| Signable operations | 17 structs | **48** (all non-virtual except the two obsolete mining ops) |
| Virtual operations | none modelled | **43** |
| Wire deserialization | partial (strings, varints, ops) | full, with round-trip tests over every operation |
| Differential testing | none | against beem (150 cases) **and against hived itself** (57) |
| Live-node fixture tests | none | 10 |
| Key derivation | WIF only | WIF, BIP-32, BIP-38, BIP-39, brain keys, password keys |
| Encrypted key store | none | scrypt + AES-256-GCM |
| Async | native, Tokio-locked | optional `async` feature, runtime-agnostic |
| Concurrency across nodes | batched range fetches | batched fetches **and** request racing |
| Failover | sequential, with backoff | sequential (default) or raced |
| HAF client | minimal (reputation) | no |
| Other-language bindings | separate sibling projects | Python module, beem drop-in, `beempy` CLI |
| `unsafe` | none | none (`#![forbid(unsafe_code)]`) |
| `unwrap`/`expect` outside tests | 9 | 8 |

### The fair summary

xylem is a competently built, focused library. Its code is clean, it avoids `unsafe`
entirely, and it is async from the ground up rather than as a feature. If you are
writing a Tokio service and need transfers, votes, comments and `custom_json`, it will
do that today and it is a `cargo add` away.

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

### 6. An async layer — but for a different reason, and doing more

Reading xylem prompted the question, and the answer turned out to be more specific than
"Rust services are async".

Signing in `hivecomb` needs no network, so async buys nothing there. It buys something
on **broadcast**, which is a real call and is often inside a deadline. Sequential
failover — what `hivecomb` did and what **xylem also does** — has a worst case of *the
sum of the timeouts*. Three sick nodes at fifteen seconds each is forty-five seconds
before the fourth is even tried, and a transaction that misses its window is simply
lost.

Racing removes that: fire at several nodes at once, take the first answer, worst case
one timeout. `AsyncNodeClient::race` is it, and expressing it is the reason the layer is
async at all.

Two differences from xylem's async design:

* **Runtime-agnostic.** The trait uses `-> impl Future` rather than a boxed
  `#[async_trait]`, and the retry backoff takes a caller-supplied sleep, so tokio,
  async-std and smol all work. xylem is Tokio-locked. `hivecomb`'s `async` feature pulls
  in `futures-util` and no executor at all; `reqwest-transport` is the opt-in
  batteries-included path.
* **Racing the same request across nodes**, which xylem does not do. It uses
  concurrency well elsewhere — `get_ops_in_block_range` fans out with a semaphore-bounded
  `join_all`, the same shape as `hivecomb`'s `AsyncNodeClient::blocks` — but its
  *failover* is still one node at a time (`client.rs:60`, a loop over the node list with
  rotation and backoff). So it keeps the sum-of-timeouts worst case that async was the
  opportunity to remove.

Measured with two dead nodes in front of a working one, through the Python client's
threaded equivalent: **878 ms racing against 3,366 ms sequential.** The Rust tests
assert the same property on a paused virtual clock — one timeout versus the sum.

The sync path keeps sequential failover as its default, and the core still builds with
`--no-default-features` into keys, serialization and signing with no HTTP client and no
executor.

---

## A defect found in xylem while comparing

Reported here because it is verifiable and because it affects interoperability. It is
not a criticism of the project — it is the kind of thing differential testing exists to
catch, and `hivecomb` found two of its own the same way.

> **Reported upstream:** [srbde/hive-xylem#9](https://github.com/srbde/hive-xylem/issues/9),
> filed before this section was published. It is a correctness and interoperability
> defect, not a key-disclosure or signature-forgery one.

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

## The Python comparison: hive-nectar

The Rust comparison above is only half the picture, because `hivecomb` also ships a
Python module and a beem-compatible layer. The other library in that space is
[hive-nectar](https://github.com/thecrazygm/hive-nectar) 1.0.7, by Michael Garcia.

It is worth being precise about the relationship, because the obvious framing — pure
Python against Rust — is wrong.

**Both libraries do their elliptic curve arithmetic in the same C library.** nectar
depends on [`coincurve`](https://github.com/ofek/coincurve) `>= 20`, a binding to
libsecp256k1, imported unconditionally with no fallback; `hivecomb` uses the
`secp256k1` Rust crate, which links the same library. A signature costs about the same
in both, because in both it is the same C code doing the work.

What differs is everything around it. nectar builds and serializes operations in
Python; `hivecomb` does it in Rust and hands Python a finished envelope. So any speed
difference is in serialization, object construction and interpreter overhead — not in
the cryptography, where there is nothing to win.

Both also ship compiled artifacts: `coincurve` and `cryptography` are wheels per
platform, exactly as `hivecomb` is. "No toolchain needed" is true of neither.

These are **alternatives, not rivals**. The real distinction is where the protocol
logic lives — readable and patchable in place in nectar, faster and memory-safe in
`hivecomb` — and which of those matters more depends on who is holding it.

**nectar is more mature than `hivecomb`'s Python side by every measure that can be
counted.** It is published, at 1.0.7 rather than 0.1.0, and takes roughly 700 downloads
a month against this project's zero. It is beem's designated successor and says so.

| | hive-nectar | hivecomb + hivecomb-beem |
|---|---|---|
| published | PyPI, 1.0.7 | no |
| downloads / month | ~700 | 0 |
| keeps beem's package names | **no** — `import beem` must be rewritten | **yes** — `import beem` unchanged |
| protocol logic | Python | Rust |
| elliptic curve arithmetic | libsecp256k1 (via `coincurve`) | libsecp256k1 (via `secp256k1`) |
| compiled artifacts | `coincurve`, `cryptography` | the `hivecomb` wheel |
| Python | 3.10+ | 3.8+ |
| HAF client | yes | no |
| `AccountSnapshot` | yes (1,023 lines) | no |
| signed-message envelope (`Message`) | yes, V1 and V2 | no |
| image upload | yes | no |
| verified against hived itself | no | 57/57 operations |
| beem's crypto-critical defects | fixed | fixed |
| beem's serialization defects | 13 carried forward | fixed |

### Measured, on the same machine in the same interpreter

Both libraries installed side by side on CPython 3.12, signing identical operations
from identical inputs. Median of seven one-second windows, because signature grinding
— retrying until the signature is canonical — makes any single window noisy.

|  | hivecomb | hive-nectar | |
|---|---|---|---|
| sign a message (raw ECDSA) | 74 µs | 155 µs | 2.1× |
| sign a `custom_json` | 75 µs | 260 µs | 3.5× |
| sign a `transfer` | 116 µs | 275 µs | 2.4× |
| serialize and digest, no signing | **8.7 µs** | **65 µs** | **7.4×** |

The last row is the honest one, and it is the only one that measures what actually
differs. Both libraries hand the elliptic curve arithmetic to libsecp256k1, so the
signature itself costs the same in each; the gap in the signing rows is the work
*around* it — decoding the WIF, hashing, and grinding for a canonical signature — done
in Rust rather than in Python. The gap in the last row is serialization alone, with no
cryptography in it at all, and that is where a compiled core is worth something.

Before any of it was timed, both were asked for the digest of the same transaction:

```
hivecomb cef35a5b34e7ee9297de5153b363668245793c8ba719762ccacdde9fd85ad3d6
nectar   cef35a5b34e7ee9297de5153b363668245793c8ba719762ccacdde9fd85ad3d6
```

That is a third independent implementation agreeing with `hivecomb` and with hived, and
it is worth more than the timings: a benchmark of two things that disagree measures
nothing.

### Would implementing the missing features make hivecomb more mature?

No, and the question is worth separating into two.

**Faster: already true, and measurably.** The table above is what it is regardless of
which features exist.

**More mature: not something that can be written.** Maturity here is a track record —
downloads, years, bug reports from people who were not the author, the accumulated
evidence of having survived contact with real use. nectar has roughly 700 downloads a
month; `hivecomb` has none, has been accepted by the Hive network exactly once, and has
no user who is not its author. Implementing HAF, `AccountSnapshot` and `Message` would
close the *feature* gap and leave the maturity gap exactly where it is.

What `hivecomb` can claim, and does, is **verification depth**: every operation checked
byte for byte against hived itself, which no other Hive library in any language appears
to do. That is a different axis from maturity and should not be presented as the same
one. A library can be thoroughly verified and still unproven in production — this one
is exactly that.

### Which one fits

**nectar** if you are writing new Python, can change your imports, and want a maintained
library with the broader API surface — HAF, snapshots, signed messages, discussions. It
is the safer default today, and this project would say so to anyone asking.

**`hivecomb-beem`** if you have an existing beem program you cannot rewrite — that is
the case it exists for, and nectar does not cover it. Also if you want the protocol
logic in Rust: verified byte for byte against hived, about 19,000 signed transactions a
second, and no possibility of a memory-safety bug in the part that handles keys. Not,
however, because the cryptography is faster; it is the same library underneath.

### What this project found in nectar, and what nectar found first

An audit of nectar 1.0.7 at commit `06f743d` is in
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md), which records which of beem's defects
survive into it — thirteen do, including `escrow_release` missing the field naming who
receives the funds, `custom_binary` serializing two of six fields, and unsorted
`flat_set` auth lists. Those are reported to its maintainer rather than only published
here.

It is worth stating the other direction with equal weight. Nectar **independently fixed
the entire crypto-critical set** before this project existed, and did the chain-id fix
more thoroughly than a workaround. And one finding this project published against beem
— that `unicodify` corrupts control characters — was **wrong**; beem and nectar are both
right, and `hivecomb` had "fixed" correct behaviour into a real bug of its own. That
retraction is in [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md#8).

## What hivecomb deliberately does not do

**Async by default.** `hivecomb`'s core is synchronous and its async layer is a feature,
where xylem is async throughout. That is a deliberate trade: the signing core stays free
of a runtime and builds with `--no-default-features` into keys, serialization and
signing with no HTTP client and no executor. The cost is that the two clients are
separate types rather than one, and a caller who wants everything async gets an async
*RPC* layer over a sync core rather than an async library.

If "the whole SDK is `async fn`" is what you want, xylem is still the closer fit.

**HAF.** The Hive Application Framework is a Postgres database that a hived node syncs
blocks into, with applications running as schemas beside it. What a *remote* consumer
can reach is not the database — it is whatever REST endpoints an operator chooses to
expose in front of it, and those vary by deployed app. Both nectar's HAF client and
xylem's are HTTP clients for exactly that: nectar's `utils/haf.py` is `httpx2` against
`api.hive.blog` and `api.syncad.com`, with no SQL in it at all.

This matters because the obvious next suggestion — that `hivecomb` should ship
"high-throughput SQL/Postgres streaming connectors for indexing pipelines" — describes
something a client library cannot offer. SQL access to HAF means **running your own HAF
node**; there is no remote SQL endpoint to connect to. And someone who runs their own
HAF node writes SQL against their own schema directly, with `sqlx` or `psycopg`, and
does not want a transaction-signing library in that path.

So `hivecomb` ships no HAF client rather than a half-one. `NodeClient::call` reaches
anything hived exposes over JSON-RPC, and a REST endpoint is an HTTP request the caller
can make with whatever client they already have.

The thing that would change this is a use case, not an argument: if someone building on
HAF finds they are re-deriving Hive types that this crate already models — `Account`,
`Block`, the operation enum — then mapping those onto HAF's stable core tables is worth
doing, behind a feature flag, for that person. Until then it is a dependency on Postgres
in a library whose signing path deliberately has no network dependency at all.

---

## Credit

`hive-xylem` is credited in [CREDITS.md](CREDITS.md). The comparison sharpened five
parts of this crate, and finding a bug in someone else's careful work is a reason to
say so publicly rather than quietly.
