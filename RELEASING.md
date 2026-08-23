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

Do these in order. Step 1 has to come first because everything else names it.

### 1. The `release` environment, in GitHub

`Settings → Environments → New environment`, named exactly **`release`** — the workflow
gates four jobs on that name (`crate`, `pypi`, `pypi-shim`, `npm`), and PyPI's trusted
publisher will be configured against it.

Add **yourself as a required reviewer**. Publishing cannot be undone: crates.io never
unpublishes, npm only within 72 hours and under conditions, PyPI never reuses a
filename. A human approval step in front of an irreversible upload is worth the extra
click.

### 2. crates.io

1. Log in at crates.io with GitHub.
2. `Account Settings → API Tokens → New Token`.
3. Scopes: **`publish-new`** and **`publish-update`**. Leave the crate scope
   unrestricted for the first release — you cannot scope a token to a crate that does
   not exist yet. After 0.1.0 is out, replace it with one scoped to `hivecomb` alone.
4. Add it as an **environment secret** — `Settings → Environments → release →
   Add environment secret` — named **`CARGO_REGISTRY_TOKEN`**.

   **A secret, not a variable.** GitHub environments hold both, and the difference
   matters here: secret values are never returned by the API and are automatically
   masked to `***` in workflow logs. Variable values are returned by the API and are
   printed verbatim. Once this repository is public its workflow logs are public and
   permanent, so one `set -x`, one crashing tool that dumps its environment, or one
   `curl -v` would put a publish token where anyone can read it. Revoking the token
   afterwards does not remove the log entry.

   **An environment secret, not a repository secret.** Repository secrets are readable
   by every workflow, including `ci.yml`, which runs on pull requests and has no
   business holding a publish token. Environment secrets are readable only by jobs
   that declare `environment: release` — which is exactly the four publish jobs.

### 3. npm

1. Account at npmjs.com. Enable 2FA — then set its **mode** deliberately, because the
   default blocks CI.

   `Account → Two-Factor Authentication` offers roughly two levels:

   * **Authorization and writes** — 2FA is required to publish as well as to log in.
     A CI job cannot satisfy this: it hangs waiting for a one-time password nobody
     can type.
   * **Authorization only** — 2FA guards login and account changes; publishing is
     authorised by the token alone. **This is the one CI needs.**

   Be clear about what that trades: on "authorization only" the npm token becomes the
   sole credential for publishing, so its scope and its expiry are the compensating
   control rather than paperwork. Keep 2FA itself on — this is about which *actions*
   it gates, not about turning it off.

   There is a second, per-package switch of the same kind, which only appears once a
   package exists. If a later publish starts demanding an OTP even though the account
   setting is right, check the package's own settings.
2. `Access Tokens → Generate New Token`. npm has retired Classic tokens in favour of
   **Granular Access Tokens**, so that is what you get. Settings that matter:

   | field | value |
   |---|---|
   | Token name | `hivecomb-release` |
   | Allowed IP ranges | **leave empty** — GitHub-hosted runners have no stable IPs, and a range here locks CI out |
   | Packages and scopes | **Read and write**, **All packages** |
   | Organizations | No access |
   | Expiration | the longest offered |

   **"All packages" is forced, not lazy.** A granular token can only select packages
   that already exist, and none of these do yet. It is also not one package: napi
   publishes **six** — `hivecomb` plus `hivecomb-linux-x64-gnu`,
   `hivecomb-linux-arm64-gnu`, `hivecomb-darwin-x64`, `hivecomb-darwin-arm64` and
   `hivecomb-win32-x64-msvc`. After the first release, regenerate the token scoped to
   those six by name.

   **Granular tokens expire.** Classic automation tokens did not; these must, and the
   default is 30 days. The pipeline will work now and fail months later with an auth
   error at the worst possible moment. Record the expiry date next to this checklist
   and rotate before it:

       npm token expires: ____________  (set at creation)

3. Add it as an **environment secret** on `release`, named **`NPM_TOKEN`** — a
   secret rather than a variable, and on the environment rather than the repository,
   for the reasons in step 2.
4. Verify it before relying on it. The `npm` job runs `npm whoami` first, but that
   only happens once Actions can run; locally:

       read -rs TOK   # paste, Enter -- not echoed, not in shell history
       NODE_AUTH_TOKEN=$TOK npm whoami --registry=https://registry.npmjs.org
       unset TOK

Nothing needs claiming ahead of time — the first publish creates `hivecomb` and the five
per-platform packages (`hivecomb-linux-x64-gnu` and friends) together.

### 4. PyPI — two projects, no token at all

`hivecomb` and `hivecomb-beem` are separate PyPI projects and each needs its own
publisher. Neither stores anything in GitHub: the workflow authenticates with a
short-lived OIDC token, which is why there is no `PYPI_TOKEN` anywhere.

For **each** of the two, go to `Your projects → Publishing → Add a new pending
publisher` and fill in:

| field | value |
|---|---|
| PyPI Project Name | `hivecomb` — then repeat for `hivecomb-beem` |
| Owner | `flosolcher` |
| Repository name | `hivecomb` |
| Workflow name | `release.yml` |
| Environment name | `release` |

"Pending" is correct: it lets the project be created by the first publish. Get the
environment name right — a mismatch fails at upload with a confusing OIDC error rather
than a helpful one.

### 5. Check the names are still free

All four were free on 2026-08-23. Re-check immediately before releasing, because none of
this reserves anything:

```bash
curl -s -o /dev/null -w "%{http_code} crates\n" https://crates.io/api/v1/crates/hivecomb
curl -s -o /dev/null -w "%{http_code} pypi\n"   https://pypi.org/pypi/hivecomb/json
curl -s -o /dev/null -w "%{http_code} shim\n"   https://pypi.org/pypi/hivecomb-beem/json
curl -s -o /dev/null -w "%{http_code} npm\n"    https://registry.npmjs.org/hivecomb
```

404 means free. crates.io answers 403 to a bare request — check it in a browser.

### 6. Rehearse before trusting any of it

`Actions → release → Run workflow`, dry run **true**. It builds every wheel and every
addon, installs a wheel and checks the cross-binding digest vector against it, and
**verifies both tokens are accepted** — `crates.io/api/v1/me` and `npm whoami` — before
running `cargo publish --dry-run` and `npm publish --dry-run`.

The token checks are there deliberately. Neither `--dry-run` authenticates, so without
them a rehearsal would say nothing about your credentials and the first real release
would be the first time they were tested.

The one thing a rehearsal cannot check is **PyPI**: trusted publishing mints its token
at upload, so a misconfigured publisher only shows up on the real run — as an OIDC error
that does not name the mismatched field. Re-read the table in step 4 before tagging;
the environment name is the usual culprit.

## Before each release

- [ ] **CI green on `main`, on a run that includes the commit you are tagging.**
      Not "it passed last week". Local passing is weak evidence here: CI has caught
      a false MSRV, macOS PyO3 linking, a PowerShell-hostile glob, clippy lints from
      a newer toolchain, CRLF corruption of the SHA-pinned word lists, a broken
      feature flag and two dependency advisories — none of which reproduced on the
      development machine. Do not publish on local evidence alone.
- [ ] If Actions is unavailable (billing, quota), that is a **blocker**, not an
      inconvenience. Publishing three artifacts across five platforms without a
      cross-platform run is how the first user finds the bug.
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
