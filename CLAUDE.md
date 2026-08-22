# Working on hivecomb

Notes for Claude Code and other agents. Deliberately short: the reasoning lives in the
documents this points at, and a second copy of it here would drift from them. If
something below contradicts `CONTRIBUTING.md`, that file wins.

## The rule that matters most

**Do not trust this repository's test suite about serialization. Ask hived.**

```sh
cargo build --release -p hivecomb-py
mkdir -p dist && cp target/release/libhivecomb.so dist/hivecomb.so
PYTHONPATH=dist python3 tests/hived_serialization_oracle.py     # 57 cases, no account needed
PYTHONPATH=dist python3 tests/hived_authority_oracle.py         # 26 operations, no key needed
```

Both are free, need no account and write nothing to the chain.

On 2026-08-22 that oracle found four defects the 292 unit tests and the beem
differential oracle had all missed, and overturned a finding this project had published
against beem — a "fix" that had turned correct behaviour into a real bug here. Two of
the four round-tripped perfectly through this crate's own serializer and deserializer.

The lesson generalises: **a round-trip test cannot catch a format that is wrong in both
directions, and a test written from a belief tests the belief.** When a claim can be
checked against an authority, check it there before writing it down — especially a claim
about someone else's project.

## Running things

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo build -p hivecomb --no-default-features    # the core must stay runtime-free

PYTHONPATH=dist:python python3 python/test_compat.py     # set COMB_CONFIG to a temp path
PYTHONPATH=dist:python python3 python/test_cli.py
cd hivecomb-node && npm run build && npm test

PYTHONPATH=dist python3.8 tests/differential_beem.py     # python3.8 is the one with beem
```

`python/test_cli.py` mutates whatever `COMB_CONFIG` points at — always set it.

## Conventions

- **Commit and push.** Florian's standing instruction: after committing, push.
- **Credit.** This is a translation of other people's protocol work. Credit goes to the
  original maintainers, the conversion is attributed to Claude, and **Florian takes no
  authorship credit** — see `CREDITS.md`.
- **The changelog is updated in the same commit as the change**, for user-visible
  changes only.
- **Never put a private key in a file inside the repo.** `.env`, `*.wif` and
  `wallet.json` are gitignored as a backstop, not a plan. `@noc-dev` is the unfunded
  throwaway used for live checks; its posting key lives outside the working tree.
- **Comments explain why.** What the line does is visible; that `escrow_transfer` puts
  `json_meta` between the fee and the deadlines because hived does, is not.

## Where things are written down

| | |
|---|---|
| `CONTRIBUTING.md` | how to verify a change; read before touching serialization |
| `BROADCAST.md` | what is proven against the live chain, and what is not |
| `SECURITY_FINDINGS.md` | what was wrong in beem — including one **retracted** finding |
| `MIGRATION.md` | the beem drop-in: identical, divergent, and missing |
| `COMPARISON.md` | against the other Rust Hive libraries, including where they lead |
| `RELEASING.md` | how a release happens, and what is not set up yet |
| `SECURITY.md` | how to report a defect |

## Traps that have already cost time

- A job-level `permissions:` block in a GitHub workflow **replaces** the workflow-level
  one. Declaring `id-token: write` alone drops `contents: read`, and checkout then fails
  with "Repository not found".
- `cp` is aliased to `cp -i` here; use `command cp -f`.
- `grep -c` exits non-zero on zero matches, which breaks `&&` chains.
- The brain-key and BIP-39 word lists are pinned by SHA-256 and marked `-text` in
  `.gitattributes`. Never let a rename sweep or a line-ending conversion touch them.
- CI's clippy is usually newer than the local one, so `cargo clippy` passing here does
  not mean CI passes.
