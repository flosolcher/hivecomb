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
