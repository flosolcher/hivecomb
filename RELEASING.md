# Releasing

Four artifacts share one version number and go out from one tag:

| registry | package | what it is |
|---|---|---|
| crates.io | `hivecomb` | the Rust library |
| PyPI | `hivecomb` | the extension module (abi3 wheels, CPython 3.8+) |
| PyPI | `hivecomb-beem` | the beem drop-in and `beempy`, pure Python |
| npm | `hivecomb` | the addon, plus five per-platform packages |

`.github/workflows/release.yml` does all of it. **It defaults to a dry run**, because
publishing is irreversible in a way most CI is not: crates.io cannot unpublish at all,
npm only within 72 hours and under conditions, and PyPI never reuses a filename.

---

## One-time setup, none of which is done yet

- [ ] **crates.io** — create a scoped publish token, add it as the repository secret
      `CARGO_REGISTRY_TOKEN`.
- [ ] **npm** — create an automation token, add it as `NPM_TOKEN`.
- [ ] **PyPI** — configure *trusted publishing* for **both** projects, `hivecomb` and
      `hivecomb-beem`, each pointing at this repository, workflow `release.yml`, and
      environment `release`. Nothing is stored in GitHub for PyPI; the workflow
      authenticates with a short-lived OIDC token.
- [ ] **A `release` environment** in repository settings. Adding required reviewers to
      it means a human approves before anything is uploaded, which is worth having for
      an action that cannot be undone.
- [ ] **Name squatting is not a risk here but availability is** — re-check that
      `hivecomb` is still free on all three registries immediately before the first
      release.

## Before each release

- [ ] CI green on `main`.
- [ ] The live oracles green — they are scheduled, so check the last run rather than
      assuming. A red serialization oracle means the chain and this library disagree,
      which is a reason not to ship.
- [ ] `CHANGELOG.md` has a `## [x.y.z]` section describing the release. The workflow
      refuses to proceed without it.
- [ ] The version matches in **three** places: `Cargo.toml` (workspace),
      `hivecomb-node/package.json`, and `python/pyproject.toml`. The workflow checks
      this too, but fixing it before tagging is cheaper than a failed release run.
- [ ] Delete the pre-release notices. Each package landing page carries a block
      marked `<!-- PRE-RELEASE-NOTICE ... -->` saying the name is not published yet;
      those pages become crates.io, PyPI and npm, where the statement would be false.
      Find them with `grep -rl PRE-RELEASE-NOTICE .`
- [ ] Rehearse: **Actions → release → Run workflow**, dry run **true**. This builds
      every wheel, every addon, installs a wheel and checks the cross-binding digest
      vector, and runs `cargo publish --dry-run` and `npm publish --dry-run` — without
      uploading anything.

## Releasing

```bash
git tag v0.1.0
git push origin v0.1.0
```

A tag push is the only thing that publishes. Everything else is a rehearsal.

## Afterwards

- [ ] `cargo add hivecomb`, `pip install hivecomb hivecomb-beem` and `npm i hivecomb`
      in a scratch directory, on a machine that is not this one.
- [ ] Check the beem drop-in on a real program: `pip uninstall beem` first, since the
      package names deliberately collide.
- [ ] Add the `## [Unreleased]` heading back to `CHANGELOG.md`.

---

## What is still missing for a 1.0

Not blockers for 0.1.0, but the honest list:

- **Production exposure.** One transaction has been accepted by the network
  ([BROADCAST.md](BROADCAST.md)). That is a proof, not a track record.
- **No downstream users.** Nothing has depended on this yet.
- **The Node addon has no cross-binding CI against Python and Rust** beyond the shared
  pinned digest vector.
- **HAF** is not implemented; see [COMPARISON.md](COMPARISON.md).
