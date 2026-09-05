<img src="https://raw.githubusercontent.com/flosolcher/hivecomb/main/assets/hivecomb.svg" alt="hivecomb" width="96">

# hivecomb-beem

A `beem`-compatible API for Hive, implemented on [`hivecomb`](https://github.com/flosolcher/hivecomb).

This distribution **provides the `beem`, `beemgraphenebase`, `beembase` and `beemapi`
package names, and the `beempy` console script**. Installing it in place of beem makes
existing `import beem` code and existing `beempy` invocations work unchanged, with the
defects catalogued in [SECURITY_FINDINGS.md](../SECURITY_FINDINGS.md) fixed underneath
and the post-HF25 operations beem never gained made available.

```sh
pip uninstall -y beem
pip install hivecomb hivecomb-beem
```

It deliberately shadows beem's package names, so **do not install it alongside beem**.

## What you get for switching

Speed, measured on the same machine with both libraries signing identical operations,
pinned to one core, payload varied on every call (CPython 3.12, minimum of nine
interleaved one-second windows on a CPU clock, beem 0.24.26 on the `cryptography`
backend a default install selects):

| | hivecomb-beem | beem 0.24.26 | |
|---|---|---|---|
| sign a message | 70.2 µs | 20.2 ms | ~288× |
| sign a `custom_json` | 89.3 µs | 20.6 ms | ~231× |
| sign a `transfer` | 87.0 µs | 20.6 ms | ~237× |
| serialize and digest, no signing | **10.2 µs** | **64.8 µs** | **~6.3×** |

beem is the least favourable comparison in the set, because it is unmaintained; the
project's [COMPARISON.md](https://github.com/flosolcher/hivecomb/blob/main/COMPARISON.md)
measures every Python, Rust and Node Hive library it names, including
[hive-nectar](https://github.com/srbde/hive-nectar), where the gap is far smaller.

The signing rows are that wide because of *which* backend beem ends up on, not because
Python is slow. beem prefers `secp256k1` and falls back to `cryptography`, and on the
fallback it derives each signature's recovery parameter by recovering the public key in
pure Python, inside a loop that retries until the signature is canonical. The
`secp256k1` path would close most of the gap — but installed against a current binding
it raises `AttributeError: 'PrivateKey' object has no attribute 'ctx'`, because beem was
pinned to an API that changed and has not been maintained since 2021. The fallback is
what you actually get.

The last row is the fair one: serialization alone, no cryptography, ~6×.

**And correctness, which matters more.** beem 0.24.26's `known_chains["HIVE"]` is the
all-zero pre-hardfork-24 chain id, so it signs against a chain that has not existed
since 2020 unless you override it. That and twenty-four other findings are catalogued
with file and line in
[SECURITY_FINDINGS.md](https://github.com/flosolcher/hivecomb/blob/main/SECURITY_FINDINGS.md)
— including one that turned out to be **wrong**, marked as retracted, because a
catalogue you cannot check is not worth much.

Full detail — what was fixed, what diverges on purpose, what was added, what is not
implemented — is in [MIGRATION.md](../MIGRATION.md).

## Tests

```sh
python test_compat.py    # beem's API, run unmodified
python test_cli.py       # beempy, offline
```

## Two things to know before switching

* **Signing no longer contacts a node.** `Hive` caches a block reference and refuses to
  serve a stale one. Call `hive.refresh_block_ref()` from a background task if you sign
  after long idle periods.
* **`repr()` and `str()` of a private key still return the secret**, matching beem,
  because real code depends on it. Set `COMB_COMPAT_REDACT_KEYS=1` once you have checked
  yours does not.

## beempy

Every one of beem's commands is registered. The ten this layer does not provide say so
and name an alternative rather than failing obscurely.

`beempy commands` lists everything; `beempy commands --new` lists the nine that have no
beem equivalent — `recurrenttransfer`, `collateralizedconvert`, `mnemonic`, `bip38`,
`decodetx`, `virtualops`, `opsinblock`, `verifyauthority` and `commands` itself.
