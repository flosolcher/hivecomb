# Comparisons

`hivecomb` is a port. The protocol knowledge in it was worked out by other people over
roughly a decade, and [CREDITS.md](CREDITS.md) records who. This document sets it beside
three libraries it came from or sits next to — [`hive-xylem`](https://github.com/srbde/hive-xylem)
in Rust, [`hive-nectar`](https://github.com/srbde/hive-nectar) in Python and
[`dhive`](https://github.com/openhive-network/dhive) in Node — and for each one says what
this project took from it, where each is ahead, and what the measurements show.

## How to read this

A comparison document written by one of the projects being compared is worth reading
sceptically, so here are the rules it is written under.

**Every claim about another project links to the evidence for it.** A count of defects,
a "does not have this", a benchmark — each says where it comes from and how to check it.
Claims about someone else's code that cannot be checked do not belong here.

**This project has already got one of those wrong.** [Finding 8](SECURITY_FINDINGS.md#8)
was published as a High-severity defect in beem's string serialization. It was wrong —
beem was right and this crate was not — and it was retracted, in place, with the
reasoning left visible rather than deleted. It was never sent to nectar, which had
inherited the same code, because the retraction happened first. That is the standard the
rest of this document is trying to meet, and the reason the claims here are checked
against the other library rather than reasoned about.

**Where another project is ahead, it says so.** xylem is published and this crate is not.
nectar is more mature than this project's Python side by every measure that can be
counted. dhive beats hivecomb at serializing large batches, and the reason is structural
rather than fixable. Those are in here as plainly as the rest.

**Feature counts are not maturity.** The tables below count operations, tests and lines,
because those are what can be counted. Production exposure is what actually separates a
mature library from a thorough one, and on that measure this crate is the least proven of
the four.

## How the measurements were taken

Every benchmark here is reproducible from a script in `tests/`, named in its section.

Runs are pinned to one core, and both sides are measured in the same process on the same
inputs, alternating so that CPU frequency drift hits both equally. The payload varies on
every iteration: signing grinds until the signature is canonical, and how many attempts
that takes depends on the digest, so a fixed payload measures one payload's luck — and
taking medians over a fixed payload makes that result *stable*, which hides the bias
rather than removing it.

Two estimators appear, and the difference matters when reading across sections:

| section | estimator | why |
|---|---|---|
| Python (beem, nectar) | median of seven one-second windows | matches how those harnesses have always reported |
| Node (dhive) | minimum of 11–15 interleaved windows | interference can only make a window slower, so the fastest is closest to the true cost |

**Do not compare a number from one table against a number from another.** They answer
the same question with different estimators on different runtimes.

The machine's CPU governor is `powersave`, which is not fixable without root, so the Node
harness prints its own window spread (3–8% on the runs quoted) rather than asking to be
trusted. Nothing here was measured on a quiet, tuned benchmarking machine, and none of
these gaps is small enough for that to change the ordering.

**Before any timing, both sides are checked to produce the same result.** A benchmark of
two implementations that disagree measures nothing. Every harness aborts on a mismatch
rather than printing a table.

---

## Rust: hive-xylem

Measured on 2026-08-22 against [`hive-xylem` 0.1.6](https://github.com/srbde/hive-xylem)
at commit `2026-07-18`. Numbers move; re-measure before relying on them.

### The libraries

| crate | version | downloads | what it is |
|---|---|---|---|
| [`hive-xylem`](https://github.com/srbde/hive-xylem) | 0.1.6 | 99 | An async Rust SDK by SRBDE, part of a cross-language suite (Pollen/TS, Anther/Go, Nectar/Python) |
| [`hive_memo`](https://crates.io/crates/hive_memo) | 0.1.2 | 3,225 | Memo encryption and decryption only |
| [`hive-rs`](https://crates.io/crates/hive-rs) | 0.1.0 | 28 | A client library, described as a 1:1 port |
| `hivecomb` | 0.1.0 | unpublished | This crate |

`hive-xylem` is the closest comparison: a general-purpose SDK with overlapping goals.

---

### Measured, against every Rust library named here

For a long time this document carried timings for the Python and Node libraries and none
for the Rust ones, which is not a fair way to present a comparison whatever the intent.
These are the Rust numbers, for everything named above.

Same machine, same task, pinned to one core and run under a memory cap. Every version
below is **read from the installed package at run time and printed with the results**,
never written into this table by hand — a table naming a version it did not measure is
worse than one with no version at all. Minimum of fifteen interleaved windows — each library gets a window in turn, rather than all of one
library's windows and then the next, because this machine's governor ramps the clock
during a run and whoever went first would be measured cold. The payload varies every
iteration. Reproduce with [`benches/rust-libraries`](benches/rust-libraries).

Before anything is timed, all three are required to produce the **same transaction
digest** for the same transaction. They do. That is worth more than the timings: it is
the value the chain signs, so it means three independently written serializers agree byte
for byte, and it is the check that makes the rest of the table meaningful.

| microseconds | hivecomb 0.1.0 | hive-xylem 0.1.6 | hive-rs 0.1.0 | spread |
|---|---|---|---|---|
| serialize + digest, 1 transfer | 1.06 | 1.87 | 1.39 | 2% |
| serialize + digest, 10 `custom_json` | 4.61 | 7.05 | 4.57 | 5% |
| sign a transfer | 68.79 | 68.17 | 102.70 | 5% |
| encrypt a memo | 70.14 | `hive_memo` 0.1.2: 151.63 | — | 4% |

**How to read this, because the numbers mislead if taken flat.**

The `spread` column is `(median − minimum) / minimum` across that row. **A difference
smaller than the spread is not a difference** — so the 10-operation row and the signing
row are ties, not wins for anybody.

Most of the digest rows is work every library does identically. The CPU here has no SHA
extensions, so SHA-256 runs in software at about 180 MB/s: roughly 1.9 µs of a 344-byte
digest, against 0.8 µs to serialize it. That shared cost is why the digest rows converge
as the payload grows, and it means these rows say less about the three serializers than
their spread suggests. On a CPU with SHA-NI the whole column would move, for all of them.

The signing row is dominated by elliptic curve arithmetic, which all three hand to
libsecp256k1 — so it is close, and it should be. `hive-xylem`'s API takes the WIF and
chain id as strings and therefore re-parses both on every call, which is 1.34 µs of its
figure and an API choice rather than an implementation one; it is measured separately in
the harness so a reader can account for it.

`hive_memo` does memo encryption only, so it appears in one row and cannot appear in the
others. `hive-rs` and `hive-xylem` are general-purpose SDKs and `hive_memo` is a focused
library, which is a reasonable thing to be.

### What hivecomb took from xylem

Reading xylem changed six things here. They are listed before the comparison table
below because they are the part of this section that cost someone else effort: each
was a gap in this crate that xylem had already thought about, and finding them is why
the comparison was worth doing at all.

Each was written independently rather than copied. xylem is MIT/Apache-2.0 so copying
would have been permitted; the rest of this crate is written to its own conventions.

#### 1. Authority satisfaction — `Authority::check`

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

#### 2. `get_ops_in_block` — the only route to virtual operations

Virtual operations are emitted by consensus, not carried in a transaction, so they are
**not in `block_api.get_block` at all**. Filtering a block's transactions for them
returns nothing rather than erroring — which is exactly what `beempy virtualops` did
before this was found.

Added as `NodeClient::ops_in_block` / `ops_in_block_range` in Rust,
`Blockchain.get_ops_in_block` in Python, and `beempy opsinblock --virtual`.

#### 3. Block streaming in Rust

`hivecomb` had streaming in Python but not in Rust. `NodeClient::stream_blocks` is a lazy
iterator with `StreamMode::Irreversible` (the default worth having: about a minute
behind, but the blocks cannot be orphaned) and `StreamMode::Head`.

It **yields an error item rather than ending** when a call fails, so a transient outage
does not silently terminate a stream — which is the kind of failure that looks like
"the chain went quiet".

#### 4. Exponential backoff

`NodeClient` tried each node once per call. It can now retry the whole list with
backoff, capped at 30s. The default is still **one pass**, because a call on a deadline
— a submit window — should fail fast and let the caller decide; multiple passes suit a
background task. Same in the Python client.

#### 5. Reputation, and follow/mute helpers

Small conveniences xylem had that `hivecomb` only had on the Python side.

#### 6. An async layer — but for a different reason, and doing more

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

### Is xylem more mature than hivecomb?

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
| Rust source | 4,556 lines | 17,177 lines |
| Tests | 48 | 356 |
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

### A defect found in xylem while comparing

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

## Python: hive-nectar

The Rust comparison above is only half the picture, because `hivecomb` also ships a
Python module and a beem-compatible layer. The other library in that space is
[hive-nectar](https://github.com/srbde/hive-nectar) 1.0.7, by Michael Garcia.

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

### Measured, against the Python libraries

Same method, one interpreter, `custom_json` operations. Reproduce with
[`benches/python-libraries`](benches/python-libraries).

All three produce the same digest, at one operation and at ten, before anything is timed.

| microseconds | hivecomb 0.1.0 | beem 0.24.26 | hive-nectar 1.0.7 | spread |
|---|---|---|---|---|
| serialize + digest, 1 op | 10.16 | 66.60 | 68.06 | 3% |
| serialize + digest, 10 ops | 84.60 | 312.04 | 309.08 | 8% |
| sign, 1 op | 89.74 | 21,678 | 261.50 | 7% |
| sign, 10 ops | 191.61 | 19,460 | 509.21 | 8% |

beem and hive-nectar build and serialize in Python where this crate does it in Rust, so
the digest rows measure that and little else. The signing rows are about the ECDSA
backend rather than the language: hive-nectar reaches libsecp256k1 through `coincurve`
and hivecomb through Rust, and they are within 3× of each other. beem's figure is its
pure-Python fallback, which is what a current install gets because the binding it prefers
no longer matches the API it was written against — the gap there is a consequence of the
library being unmaintained since 2021, not of Python.

beem is handed the real chain id explicitly, because its own `known_chains["HIVE"]` is
the pre-hardfork-24 all-zero value; without that it would be signing against a different
chain and the comparison would measure different work.

[`lighthive`](https://pypi.org/project/lighthive/) 0.4.3 is named here without a row. It
serializes by asking a Hive node for the transaction hex and signs what comes back, so it
has no local serializer to measure and does not sign offline. That is a deliberate design
— it keeps the library small and defers to the node, which is authoritative about the
wire format — and it puts lighthive on a different axis rather than below anything.

### Measured, against the Node libraries

Reproduce with [`benches/node-libraries`](benches/node-libraries). All four that expose a
digest produce the same one. `@hiveio/hive-js` has no digest entry point, so it is gated
differently: its signature is recovered under another library and must yield the right
public key, which it does.

| microseconds | hivecomb 0.1.0 | dhive 1.3.6 | hive-tx 7.2.1 | hive-pollen 1.0.0 | hive-js 2.0.9 | spread |
|---|---|---|---|---|---|---|
| serialize + digest, 1 op | 9.28 | 8.70 | 43.80 | 10.53 | — | 9% |
| serialize + digest, 10 ops | 43.36 | 21.81 | 255.58 | 42.61 | — | 6% |
| sign, 1 op | 85.40 | 124.48 | 779.72 | 1,534.89 | 136,004 | 7% |
| sign, 10 ops | 126.36 | 152.95 | 961.65 | 1,612.96 | 117,195 | 7% |

**The signing spread is a design choice, not a quality difference,** and reading it
without that is misleading. These libraries obtain secp256k1 differently:
`@hiveio/dhive` binds the native `secp256k1` package; `hivecomb` links libsecp256k1
through Rust; `hive-pollen` uses `@noble/curves`, an audited pure-JavaScript library;
`hive-tx` has **no runtime dependencies at all** and inlines its crypto, which is exactly
what lets it run unchanged in browsers, workers and serverless runtimes; `@hiveio/hive-js`
uses `ecurve`/`bigi` bigint arithmetic. A library that chooses portability over a native
binding pays for it in a microbenchmark, and that is the choice working as intended.

The digest rows are the honest comparison of the serializers, and dhive is ahead of this
crate at ten operations — the same structural result described in [the Node section
below](#node-dhive), where it is measured in more detail.

### What hivecomb took from nectar

**How the beem findings get disclosed.** An earlier draft of
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) argued that publishing was the only option
because beem has no maintainer to report to. nectar carries beem's package layout
forward and is actively maintained, so there *is* somewhere for those findings to go.
The document was rewritten around that, and the surviving findings were reported to
nectar rather than only published here. That correction came from reading nectar.

**The signed-message envelope.** `python/beem/message.py` was written to match, and
`tests/nectar_message_interop.py` checks it against nectar rather than against this
project's own expectations.

**A finding withdrawn before it was sent.** [Finding 8](SECURITY_FINDINGS.md#8) had been
published against beem and was about to be reported to nectar as an inherited defect.
Checking it against hived first showed it was wrong in both projects' favour — see
[what nectar found first](#what-this-project-found-in-nectar-and-what-nectar-found-first)
below.

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
| signed-message envelope (`Message`) | yes, V1 and V2 | yes, V1 and V2 |
| image upload | yes | no |
| verified against hived itself | no | 57/57 operations |
| beem's crypto-critical defects | [fixed independently, and first](SECURITY_FINDINGS.md#the-findings-outlive-beem-so-there-is-someone-to-tell) | fixed |

Both libraries inherit beem's serialization behaviour in places, and
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md#the-findings-outlive-beem-so-there-is-someone-to-tell)
records which of beem's issues survive into each — thirteen into nectar, none into this
crate, which had the advantage of being written after the audit rather than before it.
Those were reported to nectar's maintainer rather than only published here, and nectar
had already fixed the entire crypto-critical set independently, before this project
existed. A table row is the wrong shape for that, which is why it is a paragraph.

The `Message` row is checked rather than asserted: `tests/nectar_message_interop.py`
loads both libraries in one interpreter and compares the V1 envelope constants, which
are what decide whether a message signed by one verifies under the other. They are
identical. The V2 payload is the same list in the same order with the same JSON
separators, with one difference in the signed bytes: nectar stamps an offset-aware
timestamp (`+00:00`), where beem used a naive `utcnow()` and this project keeps that
rendering. Neither is wrong and signatures still verify across the two, because the
verifier reads the timestamp out of the payload it was given.

### Measured

Both libraries installed side by side on CPython 3.12, signing identical operations from
identical inputs. Method as described in
[How the measurements were taken](#how-the-measurements-were-taken): pinned, varying
payload, **median** of seven one-second windows.

Reproduce with `tests/bench_vs_nectar.py`, which checks both produce the same digest
before timing anything and aborts if they do not.

|  | hivecomb | hive-nectar | |
|---|---|---|---|
| sign a message (raw ECDSA) | 75.6 µs | 155.8 µs | 2.1× |
| sign a `custom_json` | 176.6 µs | 450.9 µs | 2.6× |
| sign a `transfer` | 158.9 µs | 476.7 µs | 3.0× |
| serialize and digest, no signing | **14.7 µs** | **121.1 µs** | **8.2×** |

The last row is the one that measures what actually differs *against Python*. Both
libraries hand the elliptic curve arithmetic to libsecp256k1, so the signature itself
costs the same in each; the gap in the signing rows is the work *around* it — decoding
the WIF, hashing, and grinding for a canonical signature — done in Rust rather than in
Python. The gap in the last row is serialization alone, with no cryptography in it.

**Do not carry that conclusion to JavaScript. It inverts.** See below.

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

## Node: dhive

Measured against [`@hiveio/dhive`](https://github.com/openhive-network/dhive) 1.3.6 on
Node 22, same process, same key, a real `custom_json` payload. Method as described in
[How the measurements were taken](#how-the-measurements-were-taken), with the **minimum**
window as the estimator — so these numbers are not comparable against the Python tables
above, which use a median.

Two things are checked before anything is timed: that both produce the same digest, and
that **dhive itself recovers the correct public key from hivecomb's signature**. The two
do *not* produce identical signature bytes, and that is correct rather than a defect —
any canonical signature over the digest is valid and the two grind to different ones, so
byte-equality would be the wrong test. Each library is individually deterministic, which
makes the difference look like a bug until you check where it comes from; an evaluator
confirmed it independently, over an identical digest, with both signatures recovering the
same key.

That is the level a gate belongs at. **Recovery is the property with teeth** — it is what
makes a signature interoperable — and equality is strictly stronger than correctness here,
so a gate built on it fires on two correct implementations. Three separate false alarms
across these runs all came from comparing unequal inputs (a differing expiration, a
`signMessage` that hashes its argument where the comparison did not) and every one of them
looked exactly like an interop failure. Aligning the inputs before believing the output is
the whole discipline.

### What hivecomb took from dhive

**The node health tracker.** `NodeClient` walked its node list from the front on every
call and remembered nothing, so a dead first node cost its full timeout on every request
for the life of the process. dhive's `NodeHealthTracker` had already worked out what is
worth remembering — consecutive failures per node, failures per node *and* API, and how
far behind the head a node has fallen — and what the thresholds should be. That design,
and its default numbers, are dhive's; the implementation here is independent and
[diverges in two places](#the-gap-that-was-worth-closing-node-health) that are argued
rather than assumed.

**A measurement that overturned this document's own advice.** An outside evaluator
benchmarking dhive against this crate measured the crossover point and found the adoption
niche recorded here was backwards — see
[what that means for a JavaScript adopter](#what-that-means-for-a-javascript-adopter).

### Signing a transaction — the call an application actually makes

|  ops | dhive 1.3.2 | dhive 1.3.6 | hivecomb | |
|---|---|---|---|---|
| 1 | 119.8 µs | 121.0 µs | **88.7 µs** | **hivecomb 1.36×** |
| 2 | 124.2 µs | 126.7 µs | **93.4 µs** | **hivecomb 1.36×** |
| 5 | 132.5 µs | 134.3 µs | **107.6 µs** | **hivecomb 1.25×** |
| 8 | 137.9 µs | 137.7 µs | **121.7 µs** | **hivecomb 1.13×** |
| 10 | 145.3 µs | 145.0 µs | **130.3 µs** | **hivecomb 1.11×** |
| 15 | 151.5 µs | 152.4 µs | 154.4 µs | dhive 1.01× |
| 20 | 167.3 µs | 165.4 µs | 179.7 µs | dhive 1.08× |
| 50 | 230.2 µs | 232.9 µs | 331.2 µs | dhive 1.43× |

**hivecomb is faster at small transactions and slower at large ones. Where exactly the
two cross over depends on the machine**, so treat the number as a range rather than a constant:
**between about 6 and 15 operations**. The table above crosses at 12–15; an independent
evaluator running the same method on different hardware measured the crossing between 5
and 8, with a faster dhive and a slower hivecomb at n=50 both pushing it left.

Essentially every real Hive transaction is one to four operations, so the common case is
comfortably on the winning side of that range whichever end you land on. The crossover is
stated here rather than left for someone to discover.

Both dhive versions are in the table because the disagreement between those two runs
looked at first like a dhive regression between 1.3.2 and 1.3.6. Measured on one machine
in one run, it is not: the two versions are within noise of each other at every size. The
difference is the hardware.

### The end-to-end task: producing the body you POST

The table above returns a JavaScript object, which is what dhive returns too. But a
signed transaction's destination is almost always an HTTP request body, and the object is
not that — the caller's next act is `JSON.stringify`. hivecomb renders the transaction to
JSON internally, has V8 parse it into an object to cross the boundary, and then the caller
serializes it straight back. Two of those three steps are loss, and they scale with the
operation count.

`signTransactionJson` stops at the string. Same work, same signature over the same digest;
it shares transaction building and key decoding with `signTransaction`, so the two cannot
drift apart.

Measured to the same finish line for both libraries — the JSON body an application would
POST, so dhive pays for its own `JSON.stringify` exactly as a real caller would:

|  ops | dhive 1.3.6 | hivecomb, object | hivecomb, JSON string | |
|---|---|---|---|---|
| 1 | 123.7 µs | 89.8 µs | **82.2 µs** | **hivecomb 1.50×** |
| 2 | 127.3 µs | 92.5 µs | **85.4 µs** | **hivecomb 1.49×** |
| 5 | 135.1 µs | 108.8 µs | **98.0 µs** | **hivecomb 1.38×** |
| 10 | 151.8 µs | 134.0 µs | **116.3 µs** | **hivecomb 1.30×** |
| 20 | 177.3 µs | 188.7 µs | **156.7 µs** | **hivecomb 1.13×** |
| 50 | 254.8 µs | 342.0 µs | 273.7 µs | dhive 1.07× |
| 200 | 650.9 µs | 1097.3 µs | 861.7 µs | dhive 1.32× |

On the task that actually gets performed, **the crossover moves out to somewhere between
twenty and forty operations** — 35–40 on this machine, 20–30 on the evaluator's, the same
hardware spread as the object API — and fifty operations goes from a 1.34× loss to a
near-tie. Reach for `signTransactionJson` when the result is going on the wire, and
`signTransaction` when you need to inspect or modify it.

The improvement itself is not machine-dependent: both runs found the text form faster at
every size measured, including at one operation, where there is almost nothing to marshal
and the saving is the object allocation and the caller's `JSON.stringify` rather than
anything proportional.

What the text form deliberately does *not* do is echo back the caller's own operations
array, which would be faster still and wrong: hivecomb normalises operations on the way in,
so what it renders is what was signed.

### Many signatures, rather than many operations

"Many" has two meanings here and they point opposite ways. Many operations under one key is
the case above. Many *signatures* over one transaction — multiple authorities, or a
multi-signature account — is the case where signing dominates, and signing is where this
crate's curve arithmetic shows:

|  keys | dhive 1.3.6 | hivecomb | |
|---|---|---|---|
| 1 | 120.8 µs | **82.6 µs** | **hivecomb 1.46×** |
| 2 | 226.1 µs | **152.7 µs** | **hivecomb 1.48×** |
| 3 | 335.5 µs | **223.5 µs** | **hivecomb 1.50×** |
| 5 | 556.7 µs | **359.0 µs** | **hivecomb 1.55×** |
| 8 | 879.8 µs | **569.2 µs** | **hivecomb 1.55×** |

The margin *grows* with the signature count, toward the 1.67× floor below, because each
extra signature adds curve arithmetic and nothing else. There is no crossover on this axis.
Independently reproduced: 1.48× at one key, 1.66× at three, 1.55× at eight — landing just
under the floor, which is the consistency check you would want on the whole model.

Reproduce with the harnesses named in
[How the measurements were taken](#how-the-measurements-were-taken); every one checks that
dhive recovers the correct public key from each hivecomb signature before timing anything.

### Why: the advantage is the curve, not the serializer

|  | dhive | hivecomb | |
|---|---|---|---|
| one signature, raw ECDSA over a 32-byte digest | 103.9 µs | **62.0 µs** | **hivecomb 1.67×** |
| overhead above that floor, at 1 operation | 17.5 µs | 23.4 µs | dhive 1.34× |

**The advantage is the curve arithmetic, and it is partly given back.** libsecp256k1
through Rust is 1.67× faster at the signature itself; hivecomb then spends about 6 µs
more than dhive on everything around it — building the transaction, crossing the napi
boundary, rendering the result. Net at one operation: 1.36×.

An earlier version of this table reported the floor as 1.45× and the overhead as
"identical, 18.9 against 19.0". Both were wrong, and for the same reason: hivecomb's
floor was measured with `signMessage`, which hashes its input, against dhive's
`key.sign(digest)`, which does not. A sha256 was being counted on one side only, which
understated the floor advantage and inflated hivecomb's apparent overhead into a false
match. An evaluator flagged the subtraction as not cleanly separable; isolating the hash
confirmed it and moved both numbers. The row above signs an identical pre-hashed digest
on both sides.

### Serialization alone, with no signing, is a loss

|  ops | dhive 1.3.6 | hivecomb | |
|---|---|---|---|
| 1 | 8.3 µs | 11.5 µs | dhive 1.38× |
| 10 | 21.4 µs | 46.6 µs | dhive 2.18× |
| 50 | 69.8 µs | 216.6 µs | dhive 3.10× |
| 200 | 235.1 µs | 891.4 µs | dhive 3.79× |

This is the **opposite** of the Python result, where serialization is where a compiled
core pays. The reason is arithmetic rather than mystery: measured directly, hivecomb's
Rust serializer is only about **1.4× faster than dhive's JavaScript** — dhive's
serializer is good — and 1.4× is not enough headroom to also pay for marshalling
operations across the napi boundary. Crossing costs more than compiling saves.

Two rounds of work went into narrowing this and are worth recording, because both were
real and neither was sufficient:

* `operation_from_json` deep-copied every operation's JSON tree before converting it,
  on a vector the function already owned. Removing the copy cut the 200-operation
  digest from 6.3× slower to 3.8×.
* Operations may be passed as a pre-stringified JSON array instead of a JS array. One
  string crosses once, where an array is converted field by field. Worth 25–30%.

A third change mattered more than either, and it was on the way *out* rather than in:
`signTransaction` built a `serde_json::Value` of the whole signed transaction and let
napi walk that tree node by node. At 50 operations the return path cost more than the
elliptic curve work did — signing was 239 µs of a 508 µs call. Rendering straight to a
JSON string and letting V8's `JSON.parse` do the rest took it to 344 µs.

What that change deliberately does *not* do is hand back the operations array the caller
passed in. That would be faster still and it would be wrong: hivecomb normalises
operations on the way in — an object-valued `json_metadata` becomes the JSON *string*
the signature actually covers — so echoing the caller's own array could return a
transaction that does not match what was signed. In a signing library that trade is not
available.

### What dhive has that hivecomb does not

Speed is not the only axis, so the surface was compared too. Most of dhive's API has an
equivalent here — `RCAPI` against `rc_accounts`/`has_rc_for` (which does the same mana
regeneration arithmetic as `calculateRCMana`), `AccountByKeyAPI` against
`accounts_by_key`, `getVestingSharePrice`/`getVests` against `vests_to_hive` and
`chain::manabar`, `Blockchain` streaming against `stream_blocks` with the same
irreversible-by-default choice. hivecomb additionally has `transaction_status`,
`ops_in_block_range`, node racing, TaPoS caching, BIP-32/38/39 and brain keys, and a
local `Authority::check` that answers "will these keys satisfy this account" without a
round trip.

Three real gaps remain. A fourth — stateful node health tracking — is what this
comparison was worth doing for, and it has since been implemented; see below.

**1. The Hivemind/bridge API.** `getRankedPosts`, `getAccountPosts`, `getCommunity`,
`listCommunities`, `listAllSubscriptions`, `getAccountNotifications` — the social and
community layer. hivecomb has none of it. This is a scope decision rather than an
oversight: `bridge` is the API a content application needs, and this crate is a keys,
serialization and signing core. It is recorded here so nobody has to discover it.

**2. Two database calls.** `get_vesting_delegations` and `get_chain_properties` have no
wrapper, though `call` reaches both. `verify_authority` also has none, which is
deliberate — `Authority::check` answers the same question locally.

**3. `hivecomb-node` is signing-only.** dhive ships a `Client`, failover, streaming and
per-operation broadcast helpers (`vote`, `transfer`, `comment`, `json`,
`delegateVestingShares`). The Node addon deliberately exposes none of that; the Rust
crate and the Python layer do. A JavaScript caller replacing dhive wholesale needs an
RPC client from somewhere else, and that is the single biggest practical reason not to
reach for the addon.

### The gap that was worth closing: node health

dhive's `NodeHealthTracker` remembers which nodes failed and for which API, cools a
failing node down, and deprioritises nodes behind the best-known head. hivecomb's
failover was *stateless* — `call` walked the node list from the front on every request.
It failed over correctly and named every node that failed, but it remembered nothing, so
a dead first node cost its full timeout on **every call for the life of the process**.

`NodeClient::with_health_tracking` and `AsyncNodeClient::with_health_tracking` now close
it — as does `NodeClient(health=HealthPolicy())` in the Python layer, which has its own
client rather than a binding to the Rust one — tracking the same three things dhive found worth tracking: consecutive failures per
node, failures per node *and method*, and head block staleness. It is opt-in, because
the stateless default is the right mechanism for an application that has failover policy
of its own, and imposing one would fight it.

Two differences from dhive are deliberate:

* **Health reorders the node list; it never removes a node.** When every node is
  cooling, the call still tries every node, in the order least likely to waste time. A
  tracker that can exclude a node is a tracker that can turn a partial outage into a
  total one.
* **A whole-node cooldown requires failures across more than one method.** dhive counts
  consecutive failures regardless of which API they came from, which means a node that
  is merely missing one API crosses the node-wide threshold too and gets cooled
  entirely. That makes per-API tracking decorative in the exact case it exists for — a
  partial node, which is a normal thing for an operator to run. Here, failing broadly
  marks a node broken and failing narrowly marks a method unavailable there.

**What it costs when nothing is wrong.** The reordering runs on every call, so the happy
path matters more than the pathological one. Six healthy nodes, minimum of seven windows,
pinned: **0.20 µs** in Rust and **5.1 µs** in the Python layer for the complete per-call
overhead — ordering plus recording the success plus noting the head block. Against a
20 ms RPC round trip that is 0.001% and 0.026%. It is not a consideration.

**It demotes for failing, never for being slow.** Measured with
`cargo run --release --example bench_health --features rpc`, forty calls over three nodes
with the first misbehaving and a 200 ms timeout:

| the first node | tracking off | tracking on | |
|---|---|---|---|
| refuses immediately | 1.35 µs | 0.76 µs | −0.6 µs |
| hangs until the timeout | 200,116 µs | 10,006 µs | **20× faster** |
| answers, but takes 150 ms | 150,204 µs | 150,266 µs | **no change** |

The middle row is what the feature is for and it delivers — the bad node goes from being
reached on all forty calls to two. The last row is the limitation, stated plainly because
the intuition runs the other way: **a node that is merely slow is reached on every call
and costs its full latency every time**, and nothing here notices. A node degrading to
seconds while still answering is both commoner and more expensive than one that refuses
outright, so if that is the shape of the problem, cap it with a timeout or rank by
observed latency — which this deliberately does not do.

**A node one or two blocks behind is not demoted.** The threshold is thirty blocks, about
ninety seconds of chain, and it is deliberately generous: this only reorders a list, and
shuffling a usable node backwards on weak evidence costs more than leaving it alone. Raise
`stale_block_threshold` to disable the check in practice if even that is too eager.

Observations are also **aged forward at the block rate before being compared**, with the
credit kept fractional and only the resulting gap floored. That combination makes the
apparent gap between nodes that are genuinely in sync **exactly zero**, at any latency —
a derived bound rather than a measured one. An earlier version floored each projection
individually, which discarded the very term that cancels and left a residual block. Two nodes
are essentially never observed at the same instant, and the chain keeps producing blocks in
between, so comparing raw numbers measures the gap between the *observations* rather than
between the nodes. Without that correction a node that is perfectly current gets judged
stale for not having been asked recently — forty blocks of drift inside the default
two-minute window, against a thirty-block threshold, which is not a corner case. The
correction errs toward not demoting, and there is a test for each direction: a current node
with an old reading stays put, and a node hundreds of blocks behind is still caught.

Staleness is observed from responses that already carry a head block rather than probed
for. A library that issues its own health checks is spending the caller's rate limit on
a decision the caller did not ask for.

### What that means for a JavaScript adopter

Take `hivecomb-node` when **signing is your bottleneck**: a service signing many
transactions a second, each the ordinary one to four operations, or anything signing with
**several keys at once**. Both are on the winning side and the second one widens with
scale — 1.50× at one key, 1.55× at eight. If the result is going onto the wire, use
`signTransactionJson` and the margin at one operation is 1.50× rather than 1.38×.

Do not take it for a **latency-bound** path. An evaluator's verdict on their trading bot
was no, and the arithmetic is worth repeating: their path is dominated by a mandatory
three-block wait, about nine seconds of consensus, plus REST latency. Signing is ~123 µs
of a >9,000 ms path, so saving 40 µs is roughly 0.0004% — unmeasurable. The addon is
also signing-only with no network layer, so it does not touch the part that actually
costs them.

Do not take it to **serialize without signing**. dhive wins that at every size and the
gap widens: 1.38× at one operation, 3.79× at two hundred. Rust cannot pay for the
boundary crossing there because there is no cryptography for it to win back.

Above about forty operations in a single transaction, dhive wins the signing case too. In
practice that shape barely exists — Hive transactions are one to four operations — but the
crossover is real and the tables above give it rather than leaving it to be discovered.

Two corrections worth recording, because the advice in this section has now been wrong
twice. The first version recommended batch signing as the adoption niche; that was a guess
contributed in good faith by an evaluator who then measured it and found it backwards, and
they asked for their guess to be replaced with their measurement. The second version put
the crossover at fifteen operations as though it were a constant; two runs on different
hardware disagreed (12–15 here, 5–8 there) against the same dhive version, so it is a
range and depends on the machine. Both replacements came from someone re-running the
numbers rather than from re-reading the code.

## What hivecomb deliberately does not do

**Async by default.** `hivecomb`'s core is synchronous and its async layer is a feature,
where xylem is async throughout. That is a deliberate trade: the signing core stays free
of a runtime and builds with `--no-default-features` into keys, serialization and
signing with no HTTP client and no executor. The cost is that the two clients are
separate types rather than one, and a caller who wants everything async gets an async
*RPC* layer over a sync core rather than an async library.

If "the whole SDK is `async fn`" is what you want, xylem is still the closer fit.

**A standalone CLI binary, and an npm one.** `beempy` already covers the command-line
surface, and it is not a duplicate of anything: `cli.py` is 2,000 lines of argument
parsing, output formatting and config UX with **no** cryptography or serialization in
it — all of that is delegated to the Rust core through the extension module. The sharing
that matters already happens at the right layer.

A native Rust CLI would therefore not remove duplication; it would add a third
argument-parsing surface. What it *would* add is a single static binary: the
`sign_offline` example builds to **1.7 MB with no network dependency at all**, against
roughly a gigabyte of Python runtime for the `beempy` path. For signing on an air-gapped
machine with no interpreter, that is a real difference and it is the purest expression
of what this crate is for.

It is still not built, for the same reason HAF is not: nobody has asked. The recipe is
two commands (below), the library already exposes everything a CLI would call, and a
third release artifact across five platforms is a standing cost. The thing that would
change it is someone signing on a machine where Python is genuinely unavailable or
unwanted — a use case, not an argument.

An **npm** CLI is a clearer no. The Node addon deliberately ships no HTTP client, so a
CLI over it would need one added for the sole purpose of the CLI, and Node is a heavier
runtime than the static binary it would be competing with.

**Hive-Engine, and sidechains generally.** A Hive-Engine operation is a `custom_json`
with the id `ssc-mainnet-hive`, so signing one needs nothing this crate lacks — and
`hivecomb-py`'s README carries the recipe with the two traps spelled out. What it does
not ship is a client: 41 write operations across six contracts, a second RPC network,
and a token-precision lookup that cannot happen in an offline signing path anyway.
[nectarengine](https://github.com/srbde/nectarengine) by SRBDE covers that ground, and
covers it for a schema that moves independently of Hive's.

One thing from reading it is worth repeating because it is a silent failure: Hive
validates whichever authority a `custom_json` declares, and the sidechain decides which
list it actually reads. Declare `required_posting_auths` where the contract wants
`required_auths` and the transaction is accepted by Hive and does nothing on
Hive-Engine. Most actions want active; several NFT actions want posting.

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

All three are credited in [CREDITS.md](CREDITS.md), which is where the credit properly
lives; this is what each comparison specifically gave back to this crate.

**`hive-xylem`** sharpened six parts of it, and comparing against it turned up a defect
in someone else's careful work — a reason to say so publicly, and upstream first, rather
than quietly.

**`hive-nectar`** changed how this project discloses the beem findings, supplied the
reference for the signed-message envelope, and independently fixed beem's entire
crypto-critical set before this project existed. It is also the library that would have
received a finding that turned out to be wrong, had the retraction not come first.

**`dhive`** contributed the design of the node health tracker, and an outside evaluator
measuring against it corrected an adoption recommendation this document had published.

None of this is a scoreboard. Three of the four libraries here are maintained by people
who were solving these problems before this one existed, and the fourth is unpublished.
