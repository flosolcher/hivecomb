#!/usr/bin/env python3
"""Time hivecomb against hive-nectar, in one interpreter, on identical inputs.

Both hand their elliptic curve arithmetic to libsecp256k1 -- nectar through
`coincurve`, hivecomb through the `secp256k1` crate -- so the signature itself costs
about the same in each. What differs is the work around it, and serialization most of
all. The numbers this prints are the ones in COMPARISON.md.

nectar needs Python 3.10+ and does not build on 3.14, so it wants its own environment:

    uv venv --python 3.12 /tmp/nectar312
    VIRTUAL_ENV=/tmp/nectar312 uv pip install hive-nectar
    cargo build --release -p hivecomb-py
    cp target/release/libhivecomb.so \\
       "$(/tmp/nectar312/bin/python -c 'import site;print(site.getsitepackages()[0])')/hivecomb.so"
    /tmp/nectar312/bin/python tests/bench_vs_nectar.py

It checks that both produce the same digest before timing anything: a benchmark of two
implementations that disagree measures nothing.

Medians of several timed windows, because signature grinding -- retrying until the
signature is canonical -- makes any single window bimodal.
"""

import itertools
import statistics, time, hivecomb
from nectarbase.operations import Custom_json, Transfer
from nectarbase.signedtransactions import Signed_Transaction
from nectargraphenebase.ecdsasig import sign_message as nectar_sign

WIF="5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
N,P,E = 5,3721182122,"2026-08-22T14:30:00"
CJ={"required_auths":[],"required_posting_auths":["alice"],"id":"my_app","json":'{"a":1}'}
TR={"from":"alice","to":"bob","amount":"1.234 HIVE","memo":"thanks"}
REF=hivecomb.BlockRef.from_parts(N,P)

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
    return {"required_auths": [], "required_posting_auths": ["alice"],
            "id": "my_app", "json": '{"n":%d}' % n}


def tr(i=None):
    """A transfer whose memo differs on every call."""
    n = next(_counter) if i is None else i
    return {"from": "alice", "to": "bob", "amount": "1.234 HIVE", "memo": "m%d" % n}


def ntx(cls,f,i):
    t=Signed_Transaction(ref_block_num=N,ref_block_prefix=P,expiration=E,
                         operations=[[i,cls(f).json()]]); t.sign([WIF],chain="HIVE"); return t
def ndig(cls,f,i):
    t=Signed_Transaction(ref_block_num=N,ref_block_prefix=P,expiration=E,
                         operations=[[i,cls(f).json()]])
    t.deriveDigest("HIVE")   # sets t.digest rather than returning it, as beem does
    return t.digest

def med(fn, reps=7, secs=1.0):
    """Median of several timed windows: signature grinding retries until the
    signature is canonical, so any single window is noisy."""
    out=[]
    for _ in range(reps):
        fn(); n=0; t0=time.perf_counter()
        while time.perf_counter()-t0 < secs: fn(); n+=1
        out.append((time.perf_counter()-t0)/n*1e6)
    return statistics.median(out)

# Agreement before timing. The docstring above has always promised this check and
# the file has never actually contained it -- a benchmark of two implementations that
# disagree measures nothing, and a promise of a check is not a check. CJ and TR are
# the fixed pair kept for exactly this: the timed calls vary their payload, but the
# comparison needs one input both sides see identically.
for label, op, cls, fixed in (("custom_json", "custom_json", Custom_json, CJ),
                              ("transfer", "transfer", Transfer, TR)):
    ours = hivecomb.transaction_digest([(op, fixed)], REF, E).hex()
    theirs = ndig(cls, fixed, op).hex()
    print(f"  digest {label:12} hivecomb {ours[:24]} nectar {theirs[:24]} "
          f"{'MATCH' if ours == theirs else 'DIFFER'}")
    if ours != theirs:
        raise SystemExit(f"hivecomb and nectar disagree on the {label} digest; "
                         "the timings below would be meaningless, so nothing was run")
print()

cases=[
 ("sign a message (raw ECDSA)", lambda: hivecomb.sign_message("challenge",WIF),
                                lambda: nectar_sign("challenge",WIF)),
 ("sign a custom_json",         lambda: hivecomb.sign_transaction([("custom_json",cj())],REF,[WIF]),
                                lambda: ntx(Custom_json,cj(),"custom_json")),
 ("sign a transfer",            lambda: hivecomb.sign_transaction([("transfer",tr())],REF,[WIF]),
                                lambda: ntx(Transfer,tr(),"transfer")),
 ("serialize + digest, no signing", lambda: hivecomb.transaction_digest([("custom_json",cj())],REF,E),
                                lambda: ndig(Custom_json,cj(),"custom_json")),
]
print(f"  {'':34} {'hivecomb':>10} {'nectar':>10} {'ratio':>8}")
for label, ours, theirs in cases:
    a, b = med(ours), med(theirs)
    print(f"  {label:34} {a:9.1f}us {b:9.1f}us {b/a:7.1f}x")
