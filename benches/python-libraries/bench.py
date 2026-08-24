#!/usr/bin/env python3
"""hivecomb against the other Python Hive libraries, on identical work.

    ./run.sh

The documentation carried timings for some of the libraries it names and none for
others. Publishing a partial set is not a fair way to present a comparison whatever the
intent, so this measures all of them in one run, in one interpreter, on one core.

These are real projects solving the same problem, published and in use while this one is
not. The numbers are here so a reader can judge for themselves, not as a verdict on
anyone's work.

# What is checked before anything is timed

Every library must produce the **same transaction digest** for the same transaction.
That is the value the chain signs, so agreement means the serializers agree byte for
byte. A mismatch stops the run: timing implementations that are not doing the same work
measures nothing.

# Versions

Read from the installed distributions at run time and printed with the results, never
written by hand. A table naming a version it did not actually measure is worse than one
with no version at all.

# One library that cannot appear here, and why

`lighthive` signs by asking a Hive node to serialize the transaction
(`condenser_api.get_transaction_hex`) and signing the hex it gets back. It therefore has
no local serializer to measure and cannot sign offline at all. That is a deliberate
design — it keeps the library small and defers to the node, which is authoritative about
the wire format — but it puts lighthive on a different axis from everything below, so it
is named here rather than given a misleading row.
"""

import statistics
import sys
import time
from importlib.metadata import version

# beem's own known_chains["HIVE"] carries the pre-hardfork-24 all-zero chain id, so it
# has to be handed the real one explicitly or it would sign against a chain that has not
# existed since 2020 — and the comparison would be measuring different work. nectar fixed
# this in its own table and takes the name directly.
HIVE_CHAIN_ID = "beeab0de" + "00" * 28
BEEM_CHAIN = {
    "chain_id": HIVE_CHAIN_ID,
    "prefix": "STM",
    "chain_assets": [
        {"asset": "@@000000013", "symbol": "HBD", "precision": 3, "id": 0},
        {"asset": "@@000000021", "symbol": "HIVE", "precision": 3, "id": 1},
        {"asset": "@@000000037", "symbol": "VESTS", "precision": 6, "id": 2},
    ],
}
WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
REF_NUM, REF_PREFIX = 5, 3721182122
EXPIRATION = "2026-08-22T14:30:00"


def ops(n, i):
    return [
        [
            "custom_json",
            {
                "required_auths": [],
                # A distinct account per operation: hived allows five custom
                # operations per *account* per block and refuses the whole
                # transaction beyond that.
                "required_posting_auths": ["alice%d" % k],
                "id": "my_app",
                "json": '{"n":%d,"k":%d}' % (i, k),
            },
        ]
        for k in range(n)
    ]


# --- the libraries, each in its own idiom -----------------------------------

import hivecomb  # noqa: E402
from beembase.signedtransactions import Signed_Transaction as BeemTx  # noqa: E402
from beembase.operations import Custom_json as BeemCustomJson  # noqa: E402
from nectarbase.signedtransactions import Signed_Transaction as NectarTx  # noqa: E402
from nectarbase.operations import Custom_json as NectarCustomJson  # noqa: E402

REF = hivecomb.BlockRef.from_parts(REF_NUM, REF_PREFIX)


def comb_digest(n, i):
    return hivecomb.transaction_digest([("custom_json", o[1]) for o in ops(n, i)], REF, EXPIRATION)


def _graphene_digest(tx_cls, op_cls, n, i, chain):
    t = tx_cls(
        ref_block_num=REF_NUM,
        ref_block_prefix=REF_PREFIX,
        expiration=EXPIRATION,
        operations=[["custom_json", op_cls(o[1]).json()] for o in ops(n, i)],
    )
    t.deriveDigest(chain)  # sets t.digest rather than returning it
    return t.digest


def beem_digest(n, i):
    return _graphene_digest(BeemTx, BeemCustomJson, n, i, BEEM_CHAIN)


def nectar_digest(n, i):
    return _graphene_digest(NectarTx, NectarCustomJson, n, i, "HIVE")


def comb_sign(n, i):
    return hivecomb.sign_transaction([("custom_json", o[1]) for o in ops(n, i)], REF, [WIF])


def _graphene_sign(tx_cls, op_cls, n, i, chain):
    t = tx_cls(
        ref_block_num=REF_NUM,
        ref_block_prefix=REF_PREFIX,
        expiration=EXPIRATION,
        operations=[["custom_json", op_cls(o[1]).json()] for o in ops(n, i)],
    )
    t.sign([WIF], chain=chain)
    return t


def beem_sign(n, i):
    return _graphene_sign(BeemTx, BeemCustomJson, n, i, BEEM_CHAIN)


def nectar_sign(n, i):
    return _graphene_sign(NectarTx, NectarCustomJson, n, i, "HIVE")


NAMES = ["hivecomb", "beem", "hive-nectar"]
DIGESTERS = {"hivecomb": comb_digest, "beem": beem_digest, "hive-nectar": nectar_digest}
SIGNERS = {"hivecomb": comb_sign, "beem": beem_sign, "hive-nectar": nectar_sign}


# --- timing ------------------------------------------------------------------


def bench_all(warm_s, window_s, windows, cases):
    """Time-boxed, interleaved windows.

    Interleaved because this machine's governor ramps the clock during a run, so
    whichever library went first would be measured cold. Time-boxed because these span
    two orders of magnitude and no single iteration count serves both ends.
    """
    for fn in cases.values():
        started = time.perf_counter()
        i = 0
        while True:
            fn(i)
            i += 1
            if time.perf_counter() - started >= warm_s:
                break

    samples = {name: [] for name in cases}
    for _ in range(windows):
        for name, fn in cases.items():
            started = time.perf_counter()
            n = 0
            while True:
                fn(n)
                n += 1
                if time.perf_counter() - started >= window_s:
                    break
            samples[name].append((time.perf_counter() - started) / n * 1e6)

    out = {}
    for name, s in samples.items():
        s.sort()
        best = s[0]
        out[name] = (best, (statistics.median(s) - best) / best if best else 0.0)
    return out


def report(label, results):
    spread = max(sp for _, sp in results.values())
    cells = "".join(f"{results[n][0]:>13.2f}" if n in results else f"{'—':>13}" for n in NAMES)
    print(f"  {label:<28}{cells}  {spread * 100:>5.0f}%")


def main():
    print("hivecomb against the other Python Hive libraries\n")
    print("  measured versions")
    print(f"    {'hivecomb':<14} {getattr(hivecomb, '__version__', 'from source')}")
    for dist in ("beem", "hive-nectar", "lighthive"):
        try:
            print(f"    {dist:<14} {version(dist)}")
        except Exception:
            print(f"    {dist:<14} not installed")

    print("\n  gate: identical transaction, identical digest?")
    agreed = True
    for n in (1, 10):
        seen = {name: fn(n, 7).hex() for name, fn in DIGESTERS.items()}
        first = next(iter(seen.values()))
        ok = all(d == first for d in seen.values())
        agreed &= ok
        print(f"    {n:>3} operation(s): {'MATCH  ' if ok else 'DIFFER '} {first[:24]}")
        if not ok:
            for name, d in seen.items():
                print(f"        {name:<14} {d}")
    if not agreed:
        print("\nThe libraries do not agree on what to sign. Nothing was timed:")
        print("a benchmark of implementations that disagree measures nothing.")
        return 1

    header = "".join(f"{n:>13}" for n in NAMES)
    print(f"\n  {'microseconds':<28}{header}  spread")
    print("  " + "-" * (28 + len(NAMES) * 13 + 8))

    for n, label in ((1, "serialize + digest, 1 op"), (10, "serialize + digest, 10 ops")):
        report(label, bench_all(0.3, 0.4, 9, {k: (lambda i, f=f, n=n: f(n, i)) for k, f in DIGESTERS.items()}))
    for n, label in ((1, "sign, 1 op"), (10, "sign, 10 ops")):
        report(label, bench_all(0.3, 0.6, 7, {k: (lambda i, f=f, n=n: f(n, i)) for k, f in SIGNERS.items()}))

    print(
        """
  Reading these: the spread column is (median - minimum) / minimum across the
  row. A difference smaller than the spread is not a difference.

  beem and hive-nectar build and serialize operations in Python; hivecomb does
  it in Rust and hands Python a finished result, so the digest rows measure
  that difference and little else. The signing rows are dominated by
  secp256k1: hive-nectar and hivecomb both reach libsecp256k1 (through
  coincurve and through Rust), while beem falls back to a pure-Python path on
  a current install because the binding it prefers no longer matches the API
  it was written against.

  lighthive is not in this table: it serializes by asking a Hive node for the
  transaction hex and signs what comes back, so it has no local serializer to
  measure and does not sign offline. That is a deliberate design rather than
  an omission."""
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
