#!/usr/bin/env python3
"""Differential oracle: compare `comb` against `beem` on the bytes that matter.

This is the Tier 1 gate. The digest `sha256(chain_id || serialized_tx)` is fully
deterministic and backend-independent, so **every serialization bug lives here**:
varint encoding, field order, the ref-block derivation, JSON payload framing,
expiration handling, amount precision.

Signature byte-equality is deliberately *not* the gate. Any canonical signature is
valid, the chain does not care which one it gets, and beem's several signing
backends need not converge on the same one. A byte-comparison would be
simultaneously too strict (rejecting a correct signature) and too weak (saying
nothing about serialization). What is checked instead is that each side verifies
the other's signatures.

Run with a Python that has both `beem` and `comb` importable:

    python tests/differential_beem.py

Exit status is 0 when every divergence is one of the KNOWN_DIVERGENCES below —
cases where `comb` is deliberately different because `beem` is wrong.
"""

import itertools
import json
import struct
import sys

try:
    import comb
except ImportError:
    sys.exit("comb is not importable; build it with `maturin develop` first")

try:
    from beembase.signedtransactions import Signed_Transaction
    from beembase.objects import Amount as BeemAmount
    from beemgraphenebase.account import PrivateKey as BeemPrivateKey
    from beemgraphenebase.ecdsasig import sign_message as beem_sign
    from beemgraphenebase.ecdsasig import verify_message as beem_verify
except ImportError:
    sys.exit("beem is not importable; this harness compares against it")

from binascii import hexlify

WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
BLOCK_ID = "00000005aabbccdd00000000000000000000abcd"
EXPIRATION = "2026-08-22T14:30:00"

# beem's own chain dict. Note that we must pass the *live* chain id explicitly:
# `known_chains["HIVE"]` in beem is the pre-HF24 all-zero value, and only
# `known_chains["HIVE2"]` is correct. See SECURITY_FINDINGS.md finding 5.
HIVE_CHAIN = {
    "chain_id": "beeab0de" + "00" * 28,
    "prefix": "STM",
    "min_version": "0.24.0",
    "chain_assets": [
        {"asset": "@@000000013", "symbol": "HBD", "precision": 3, "id": 0},
        {"asset": "@@000000021", "symbol": "HIVE", "precision": 3, "id": 1},
        {"asset": "@@000000037", "symbol": "VESTS", "precision": 6, "id": 2},
    ],
}

BLOCK_REF = comb.BlockRef.from_block_id(BLOCK_ID)


def beem_digest(ops):
    tx = Signed_Transaction(
        ref_block_num=BLOCK_REF.ref_block_num,
        ref_block_prefix=BLOCK_REF.ref_block_prefix,
        expiration=EXPIRATION,
        operations=ops,
    )
    tx.deriveDigest(HIVE_CHAIN)
    return tx.digest


def comb_digest(ops):
    return comb.transaction_digest(ops, BLOCK_REF, EXPIRATION)


def corpus():
    """Operations chosen to stress the encoders rather than the happy path."""
    payloads = [
        "{}",
        "[]",
        '{"a":1}',
        '{"n":-1}',
        '{"u":"é中文\U0001f41d"}',            # multi-byte UTF-8
        json.dumps({"k": "v" * 500}, separators=(",", ":")),  # past a 1-byte varint
        json.dumps({"k": "v" * 20000}, separators=(",", ":")),  # past a 2-byte varint
        json.dumps({"nested": {"deep": {"deeper": [1, 2, 3]}}}, separators=(",", ":")),
    ]
    ids = ["x", "sm_team_reveal", "a" * 32]                   # 32 is hived's limit
    auth_sets = [
        ([], ["alice"]),
        ([], ["alice", "bob"]),
        (["alice"], []),
        ([], ["zulu", "alpha", "mike"]),                      # deliberately unsorted
        (["a", "b", "c"], []),
    ]
    for payload, ident, (active, posting) in itertools.product(payloads, ids, auth_sets):
        yield "custom_json", {
            "required_auths": active,
            "required_posting_auths": posting,
            "id": ident,
            "json": payload,
        }

    for weight in [0, 1, -1, 10000, -10000, 32767, -32768]:   # int16 boundaries
        yield "vote", {
            "voter": "alice",
            "author": "bob",
            "permlink": "a-post",
            "weight": weight,
        }

    amounts = [
        ("0.001 HIVE", ""),                                   # smallest unit
        ("1.000 HIVE", "thanks"),
        ("0.000001 VESTS", "v"),
        ("2.500 HBD", "é\U0001f41d"),                    # unicode memo
        ("1000000.000 HBD", "x" * 200),
        ("9007199254740.993 HIVE", "big"),                    # past 2**53 units
        ("50000000000.123456 VESTS", "whale"),                # past 2**53 units
    ]
    for amount, memo in amounts:
        yield "transfer", {"from": "alice", "to": "bob", "amount": amount, "memo": memo}


def is_known_divergence(op_type, fields):
    """Cases where comb deliberately differs because beem is wrong."""
    if op_type == "custom_json":
        # hived declares required_auths / required_posting_auths as `flat_set`, which
        # deserializes into sorted order. hived then re-serializes from that object to
        # compute the digest it verifies against. beem serializes the caller's order
        # verbatim, so an unsorted auth list yields a signature over bytes hived will
        # not reconstruct. comb sorts. See SECURITY_FINDINGS.md finding 21.
        for key in ("required_auths", "required_posting_auths"):
            values = fields.get(key, [])
            if list(values) != sorted(values):
                return "unsorted flat_set (finding 21)"
    if op_type == "transfer":
        # beem parses amounts via `float()`, losing precision past the double's
        # 53-bit mantissa. See SECURITY_FINDINGS.md finding 16.
        text = fields["amount"].split()[0]
        if int(text.replace(".", "")) > 2 ** 53:
            return "amount past 2**53 units (finding 16)"
    return None


def main():
    matched = diverged_known = diverged_unknown = 0
    problems = []

    for op_type, fields in corpus():
        beem_ops = [[op_type, dict(fields)]]
        try:
            expected = beem_digest(beem_ops)
        except Exception as exc:  # beem cannot even build it
            problems.append(f"beem raised on {op_type} {str(fields)[:80]}: {exc}")
            continue
        actual = comb_digest([(op_type, fields)])

        if expected == actual:
            matched += 1
            continue
        reason = is_known_divergence(op_type, fields)
        if reason:
            diverged_known += 1
        else:
            diverged_unknown += 1
            problems.append(
                f"UNEXPECTED divergence on {op_type} {str(fields)[:100]}\n"
                f"    beem {hexlify(expected).decode()}\n"
                f"    comb {hexlify(actual).decode()}"
            )

    # Public key derivation must agree exactly.
    beem_pub = format(BeemPrivateKey(WIF).pubkey, "STM")
    comb_pub = str(comb.PrivateKey(WIF).public_key())
    if beem_pub != comb_pub:
        problems.append(f"public key mismatch: beem {beem_pub} vs comb {comb_pub}")

    # Tier 2: each side must accept the other's signatures.
    for message in [b"hello hive", b"", b"\x00\x01\x02", "unicode é\U0001f41d".encode()]:
        comb_sig = comb.sign_message(message, WIF)
        beem_sig = hexlify(beem_sign(message, WIF)).decode()
        if hexlify(beem_verify(message, bytes.fromhex(comb_sig))).decode() != repr(
            BeemPrivateKey(WIF).pubkey
        ):
            problems.append(f"beem rejected comb's signature over {message!r}")
        if not comb.verify_message(message, beem_sig, comb.PrivateKey(WIF).public_key()):
            problems.append(f"comb rejected beem's signature over {message!r}")

    total = matched + diverged_known + diverged_unknown
    print(f"digest corpus     : {total} cases")
    print(f"  identical       : {matched}")
    print(f"  known divergence: {diverged_known}  (comb is deliberately correct here)")
    print(f"  UNEXPECTED      : {diverged_unknown}")
    print(f"public key        : {'match' if beem_pub == comb_pub else 'MISMATCH'}")
    print(f"cross-verification: {'ok' if not any('signature' in p for p in problems) else 'FAILED'}")

    if problems:
        print("\nProblems:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("\nAll divergences accounted for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
