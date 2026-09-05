#!/usr/bin/env python3
"""Time hivecomb against beem 0.24.26, in one interpreter, on identical inputs.

Needs a Python that has beem installed -- 3.8 is the newest it supports:

    PYTHONPATH=<dir with hivecomb.so> python3.8 tests/bench_vs_beem.py

Two things this does that a naive benchmark would not, and both change the result:

* It hands beem the **real chain id**. beem's known_chains["HIVE"] is the all-zero
  pre-hardfork-24 value (SECURITY_FINDINGS.md finding 5), so out of the box it signs
  against a chain that has not existed since 2020, and the two digests would differ
  for a reason that has nothing to do with speed.
* It checks that both produce the same digest before timing anything. A benchmark of
  two implementations that disagree measures nothing.

The signing rows are dominated by beem's ECDSA backend rather than by Python. On the
`cryptography` backend it grinds for a canonical signature and derives the recovery
parameter by recovering the public key in pure Python each time. Its faster `secp256k1`
path raises AttributeError against current bindings, so that slow path is what an
install gets. The row worth reading is the last one -- serialization with no
cryptography in it.
"""

import itertools
import statistics, time, hivecomb
from beembase.operations import Custom_json, Transfer
from beembase.signedtransactions import Signed_Transaction
from beemgraphenebase.ecdsasig import sign_message as beem_sign
import beemgraphenebase.ecdsasig as _e

WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
N, P, E = 5, 3721182122, "2026-08-22T14:30:00"
CJ = {"required_auths": [], "required_posting_auths": ["alice"], "id": "my_app", "json": '{"a":1}'}
TR = {"from": "alice", "to": "bob", "amount": "1.234 HIVE", "memo": "thanks"}
REF = hivecomb.BlockRef.from_parts(N, P)

# Signing grinds until the signature is canonical, and how many attempts that takes
# depends on the digest. A fixed payload therefore repeats one payload's grind count
# for the whole run -- taking medians over many windows makes the result *stable*,
# which is precisely what hides the bias rather than removing it. Pointed out by an
# evaluator whose Node harness varies the payload per iteration; these did not.
#
# So each call now gets a distinct payload, and the reported figure is an average over
# the grind distribution rather than a confident measurement of one sample.
_counter = itertools.count()


def cj(i=None):
    """A custom_json whose payload differs on every call."""
    n = next(_counter) if i is None else i
    return {
        "required_auths": [],
        "required_posting_auths": ["alice"],
        "id": "my_app",
        "json": '{"n":%d}' % n,
    }


def tr(i=None):
    """A transfer whose memo differs on every call."""
    n = next(_counter) if i is None else i
    return {"from": "alice", "to": "bob", "amount": "1.234 HIVE", "memo": "m%d" % n}


# beem's known_chains["HIVE"] carries the pre-HF24 all-zero chain id, so it must be
# given the real one or it signs against a chain that has not existed since 2020.
# The differential oracle does the same; this keeps the comparison honest.
HIVE_CHAIN = {"chain_id": "beeab0de" + "00" * 28, "prefix": "STM",
              "chain_assets": [
                  {"asset": "@@000000013", "symbol": "HBD", "precision": 3, "id": 0},
                  {"asset": "@@000000021", "symbol": "HIVE", "precision": 3, "id": 1},
                  {"asset": "@@000000037", "symbol": "VESTS", "precision": 6, "id": 2}]}
print(f"  beem {__import__('beem').__version__}, ECDSA backend: {_e.SECP256K1_MODULE}")

def btx(cls, f, i):
    t = Signed_Transaction(ref_block_num=N, ref_block_prefix=P, expiration=E,
                           operations=[[i, cls(f).json()]])
    t.sign([WIF], chain=HIVE_CHAIN); return t

def bdig(cls, f, i):
    t = Signed_Transaction(ref_block_num=N, ref_block_prefix=P, expiration=E,
                           operations=[[i, cls(f).json()]])
    t.deriveDigest(HIVE_CHAIN)      # sets t.digest rather than returning it
    return t.digest

def bench_pair(a, b, reps=9, secs=1.0):
    """Minimum of interleaved windows, on a CPU clock.

    Three deliberate choices, each fixing something the earlier median-of-windows
    version got wrong:

    *Interleaved* -- each side gets a window in turn, rather than all of one side's
    windows and then the other's. This machine's governor ramps the clock during a
    run, so whoever went first was measured cold.

    *Minimum* rather than median -- interference can only ever make a window slower,
    so the fastest window is the closest estimate of the true cost. The spread
    between minimum and median is returned alongside, as the yardstick for the
    comparison: a difference smaller than the spread is not a difference.

    *`process_time`* rather than `perf_counter` -- a CPU clock does not tick while
    this process is descheduled, so a neighbour taking the core is subtracted out
    instead of being charged to whichever library was in its window.
    """
    a(); b()
    sa, sb = [], []
    for _ in range(reps):
        for fn, out in ((a, sa), (b, sb)):
            n = 0
            t0 = time.process_time()
            while time.process_time() - t0 < secs:
                fn(); n += 1
            out.append((time.process_time() - t0) / n * 1e6)
    best_a, best_b = min(sa), min(sb)
    spread = max((statistics.median(s) - min(s)) / min(s) for s in (sa, sb))
    return best_a, best_b, spread

# Agreement before timing: a benchmark of two things that disagree measures nothing.
ours = hivecomb.transaction_digest([("custom_json", CJ)], REF, E).hex()
try:
    theirs = bdig(Custom_json, CJ, "custom_json").hex()
except Exception as exc:
    theirs = f"error: {exc}"
print(f"  digest hivecomb {ours[:32]}")
print(f"  digest beem     {theirs[:32]}")
print(f"  {'MATCH' if ours == theirs else 'DIFFER'}\n")
if ours != theirs:
    # Printing DIFFER and then timing anyway makes this a check that cannot fail:
    # the run still produces a confident-looking table comparing two things that do
    # not compute the same digest.
    raise SystemExit("hivecomb and beem disagree on the digest; the timings would be "
                     "meaningless, so nothing was run")

cases = [
    ("sign a message (raw ECDSA)", lambda: hivecomb.sign_message("challenge", WIF),
                                   lambda: beem_sign("challenge", WIF)),
    ("sign a custom_json", lambda: hivecomb.sign_transaction([("custom_json", cj())], REF, [WIF]),
                          lambda: btx(Custom_json, cj(), "custom_json")),
    ("sign a transfer", lambda: hivecomb.sign_transaction([("transfer", tr())], REF, [WIF]),
                       lambda: btx(Transfer, tr(), "transfer")),
    ("serialize + digest, no signing",
     lambda: hivecomb.transaction_digest([("custom_json", cj())], REF, E),
     lambda: bdig(Custom_json, cj(), "custom_json")),
]
print(f"  {'':34} {'hivecomb':>10} {'beem':>10} {'ratio':>8} {'spread':>8}")
for label, a, b in cases:
    x, y, spread = bench_pair(a, b)
    print(f"  {label:34} {x:9.1f}us {y:9.1f}us {y/x:7.1f}x {spread*100:7.0f}%")
