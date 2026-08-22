# Contributing

The verification story here is unusual, and it is the part worth reading before you
change anything.

## The one rule

**If you touch serialization, ask hived — not the test suite.**

```sh
cargo build --release -p hivecomb-py
mkdir -p dist && cp target/release/libhivecomb.so dist/hivecomb.so
PYTHONPATH=dist python3 tests/hived_serialization_oracle.py
```

That asks a live node to serialize every operation and compares digests. It needs no
account, no key and no broadcast, and it is the authority on whether the bytes are
right.

This is not belt-and-braces. On 2026-08-22 it found four defects that 292 unit tests and
a 134-case differential oracle against `beem` had all missed — two field orders, an
integer width, and a JSON shape hived rejects outright. Every one would have produced a
transaction the chain refuses.

Two of them round-tripped perfectly through this crate's own serializer and
deserializer, which is the lesson: **a round-trip test cannot catch a format that is
wrong in both directions.** Neither can a unit test written from the same belief as the
code. Only an external authority can.

## Running everything

```sh
cargo test --workspace --all-features        # 295 unit + 10 fixtures + doctests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo build -p hivecomb --no-default-features   # the core must stay runtime-free

# Python
PYTHONPATH=dist:python python3 python/test_compat.py
PYTHONPATH=dist:python python3 python/test_cli.py

# Node
cd hivecomb-node && npm install && npm run build && npm test

# Against a live node (no account needed)
PYTHONPATH=dist python3 tests/hived_serialization_oracle.py
PYTHONPATH=dist python3 tests/hived_authority_oracle.py

# Against beem — needs a Python that has beem installed
PYTHONPATH=dist python3.8 tests/differential_beem.py
```

CI runs all of the offline ones on Linux, macOS and Windows, at stable and at the 1.88
MSRV. The live oracles run on a schedule instead, so a slow public node never fails a
pull request.

### Fuzzing

Four coverage-guided targets cover every parser that takes untrusted bytes. They run on
the daily schedule, not per commit — the per-commit version of the same contract is
`hivecomb/tests/hostile_input.rs`, a fixed corpus.

```sh
cargo install cargo-fuzz          # needs a nightly toolchain
cd fuzz && cargo fuzz run reader -- -max_total_time=60
```

Targets: `reader`, `transaction`, `memo`, `keys`. Two of them assert more than "did not
panic": anything that parses must **re-serialize to exactly the bytes it came from**,
because the digest is taken over those bytes and a lossy round trip changes what a
signature covers.

The fuzz crate is outside the workspace on purpose, so nightly never leaks into the
library's stable, MSRV-pinned build.

## Conventions

- **`#![forbid(unsafe_code)]`.** Not negotiable in the core.
- **Comments explain why, not what.** The reader can see what the line does. What they
  cannot see is that `escrow_transfer` puts `json_meta` between the fee and the
  deadlines because hived does, or that `unicodify`'s missing backslashes are correct.
- **A divergence from `beem` gets documented.** If you deliberately behave differently,
  say so in [MIGRATION.md](MIGRATION.md) and, if it is because `beem` is wrong, in
  [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) with file and line.
- **`missing_docs` is on.** `operations/` and `chain/` are exempted because their fields
  are hived's schema name-for-name; everywhere else, public items carry docs.
- **The three bindings share a pinned digest vector.** If you change what gets signed,
  the Rust, Python and Node suites all fail together — that is intentional, and the fix
  is never to update the vector without understanding why it moved.

## The changelog

Update [CHANGELOG.md](CHANGELOG.md) **in the same commit as the change**, not
afterwards. Not for tidiness: the reason a change matters is only in your head while
you are making it. Reconstructed from `git log` a week later you get a list of what
changed, which is not the same thing — "use the process-wide secp256k1 context" is
what happened, and "signing is 2.3× faster" is what a reader needs.

Only user-visible changes. CI fixes, refactors and new tests do not belong there
unless they change what someone can rely on.

While 0.1.0 is unreleased, entries go in its section; `[Unreleased]` returns above it
after the first release.

## Adding an operation

1. The struct in `hivecomb/src/operations/mod.rs`, in **hived's field order**. Verify it
   against a node rather than against the JSON field order, which can differ.
2. The serializer and deserializer arms — both, and they are separate from the struct
   declaration, so changing only the struct silently changes nothing.
3. The id in `hivecomb/src/operations/ids.rs`.
4. A case in `tests/hived_serialization_oracle.py`, and one in
   `tests/differential_beem.py` if `beem` supports it.
5. Expose it in `hivecomb-py`, `hivecomb-node`, the beem layer and `beempy`, and
   document it in [MIGRATION.md](MIGRATION.md).

## Security

Do not open a public issue for a defect that could be exploited. See
[SECURITY.md](SECURITY.md).

## Credit

This is a translation of other people's protocol work. If you add something that came
from reading another implementation, credit it in [CREDITS.md](CREDITS.md) — including
the ones this project competes with.
