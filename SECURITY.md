# Security policy

`hivecomb` signs blockchain transactions and handles private keys. A defect here can
cost someone their funds, so please report one privately and give it time to be fixed.

## Reporting

**Use GitHub's private vulnerability reporting**, from the Security tab of this
repository. It creates a private thread visible only to the maintainers.

If that is unavailable, email **fs@monacofriends.com**. Say "hivecomb security" in the
subject.

Please do not open a public issue for anything that could be exploited before it is
fixed.

### What helps

- The version, or the commit.
- What an attacker gets: a wrong signature, a disclosed key, a transaction that does
  something other than what was asked.
- A reproduction. A failing test, or a digest that differs from hived's, is ideal — see
  `tests/hived_serialization_oracle.py`, which asks a node directly and needs no
  account.
- Whether it is reachable from the Python or Node bindings as well as from Rust.

You will get an acknowledgement within **72 hours** and an assessment within **7 days**.
If a fix is going to take longer than that, you will be told why.

## What counts

**In scope** — anything that changes the bytes that get signed, or that could expose a
private key:

- serialization that disagrees with hived, so a signature covers content the caller did
  not intend
- a signature that verifies when it should not, or a recovered key that is not the
  signer
- weak or predictable key derivation, nonces, or randomness
- a private key reaching a log line, a `Debug` output, an error message or a panic
  message
- the wallet or BIP-38 key store being decryptable, or tamperable without detection
- memo encryption producing a shared secret an attacker can derive

**Also in scope, lower severity** — denial of service in a parser (a panic on hostile
input from a node reaches production as a crash), and dependency advisories that this
crate actually exercises.

**Out of scope**

- Weaknesses in Hive itself, or in hived. Report those to
  [the Hive project](https://github.com/openhive-network/hive).
- The master-password and brain-key schemes being weak. They are: one unsalted SHA-256,
  no work factor. That is Hive's design, it is documented as weak where it is
  implemented, and it cannot be changed without breaking compatibility with every
  existing account.
- Anything requiring an attacker who already has the private key.

## Known limits, stated up front

Read [BROADCAST.md](BROADCAST.md) before trusting this with value. In short: the wire
format is verified against hived itself and one transaction has been accepted by the
network, but **this library has no production track record**. It has never been audited
by anyone other than its authors and the tooling described in
[SECURITY_FINDINGS.md](SECURITY_FINDINGS.md).

That document also contains a **retracted** finding — a defect published against `beem`
that turned out to be correct behaviour, which this project had then "fixed" into a real
bug of its own. It is left in place deliberately. Treat the rest of it as findings that
have been checked, not as findings that are certainly right.

## Disclosure

Coordinated. A fix, a release, and then a public advisory crediting the reporter unless
they would rather not be named. If a report turns out to affect other Hive libraries —
several share ancestry with `beem` — we will tell you before contacting them, and will
not name you to them without asking.
