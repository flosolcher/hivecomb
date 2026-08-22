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

import statistics, time, hivecomb
from nectarbase.operations import Custom_json, Transfer
from nectarbase.signedtransactions import Signed_Transaction
from nectargraphenebase.ecdsasig import sign_message as nectar_sign

WIF="5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
N,P,E = 5,3721182122,"2026-08-22T14:30:00"
CJ={"required_auths":[],"required_posting_auths":["alice"],"id":"my_app","json":'{"a":1}'}
TR={"from":"alice","to":"bob","amount":"1.234 HIVE","memo":"thanks"}
REF=hivecomb.BlockRef.from_parts(N,P)

def ntx(cls,f,i):
    t=Signed_Transaction(ref_block_num=N,ref_block_prefix=P,expiration=E,
                         operations=[[i,cls(f).json()]]); t.sign([WIF],chain="HIVE"); return t
def ndig(cls,f,i):
    return Signed_Transaction(ref_block_num=N,ref_block_prefix=P,expiration=E,
                              operations=[[i,cls(f).json()]]).deriveDigest("HIVE")

def med(fn, reps=7, secs=1.0):
    """Median of several timed windows: signature grinding retries until the
    signature is canonical, so any single window is noisy."""
    out=[]
    for _ in range(reps):
        fn(); n=0; t0=time.perf_counter()
        while time.perf_counter()-t0 < secs: fn(); n+=1
        out.append((time.perf_counter()-t0)/n*1e6)
    return statistics.median(out)

cases=[
 ("sign a message (raw ECDSA)", lambda: hivecomb.sign_message("challenge",WIF),
                                lambda: nectar_sign("challenge",WIF)),
 ("sign a custom_json",         lambda: hivecomb.sign_transaction([("custom_json",CJ)],REF,[WIF]),
                                lambda: ntx(Custom_json,CJ,"custom_json")),
 ("sign a transfer",            lambda: hivecomb.sign_transaction([("transfer",TR)],REF,[WIF]),
                                lambda: ntx(Transfer,TR,"transfer")),
 ("serialize + digest, no signing", lambda: hivecomb.transaction_digest([("custom_json",CJ)],REF,E),
                                lambda: ndig(Custom_json,CJ,"custom_json")),
]
print(f"  {'':34} {'hivecomb':>10} {'nectar':>10} {'ratio':>8}")
for label, ours, theirs in cases:
    a, b = med(ours), med(theirs)
    print(f"  {label:34} {a:9.1f}us {b:9.1f}us {b/a:7.1f}x")
