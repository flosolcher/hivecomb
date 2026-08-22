#!/usr/bin/env python3
"""Drop-in compatibility tests.

Runs code written against beem's API through the compatibility layer, without
changing a line of it. Where behaviour deliberately differs from beem, the test
says so and asserts the *new* behaviour, with a comment explaining why.

Run with `hivecomb` importable:

    PYTHONPATH=python:<dir containing hivecomb.so> python3 python/test_compat.py

Network tests are skipped unless COMB_COMPAT_LIVE=1 is set.
"""

import json
import os
import sys
import traceback

PASS, FAIL = [], []


def check(name):
    def wrap(fn):
        try:
            fn()
            PASS.append(name)
        except Exception as exc:  # noqa: BLE001 - this is the reporter
            FAIL.append((name, exc, traceback.format_exc()))
        return fn

    return wrap


# --------------------------------------------------------------------------
# Exactly the imports beem code writes.
# --------------------------------------------------------------------------
from beem import Hive                                       # noqa: E402
from beembase.operationids import operations                 # noqa: E402
from beembase.operations import (                            # noqa: E402
    Collateralized_convert,
    Custom_json,
    Recurrent_transfer,
    Transfer,
    Vote,
)
from beemgraphenebase.account import (                       # noqa: E402
    BrainKey,
    PasswordKey,
    PrivateKey,
    PublicKey,
)
from beemgraphenebase.ecdsasig import sign_message, verify_message  # noqa: E402

# A fixed test key, published on purpose. Checked against
# account_by_key_api.get_key_references on 2026-08-22: no Hive account uses it.
# It must never hold value.
WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
PUB = "STM6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
BLOCK_ID = "00000005aabbccdd00000000000000000000abcd"


# --------------------------------------------------------------------------
# beemgraphenebase.account -- unchanged beem semantics
# --------------------------------------------------------------------------
@check("PrivateKey: construct, pubkey, str/repr match beem")
def _():
    key = PrivateKey(WIF)
    assert str(key.pubkey) == PUB, str(key.pubkey)
    assert format(key.pubkey, "STM") == PUB
    # beem's str() is the WIF and repr() is the raw scalar hex. Reproduced on
    # purpose so that a drop-in is actually a drop-in -- see finding 9.
    assert str(key) == WIF
    assert len(repr(key)) == 64 and int(repr(key), 16) > 0
    assert format(key, "wif") == WIF
    assert len(bytes(key)) == 32


@check("PrivateKey: round-trips through PublicKey and compares")
def _():
    key = PrivateKey(WIF)
    assert PublicKey(PUB) == key.pubkey
    assert PublicKey(str(key.pubkey)) == key.pubkey
    assert PrivateKey(WIF) == key
    assert PrivateKey(PrivateKey(WIF)) == key


@check("PrivateKey: generates, and derives by sequence")
def _():
    fresh = PrivateKey()
    assert str(fresh) != WIF
    derived = PrivateKey(WIF).derive_private_key(0)
    assert derived != PrivateKey(WIF)
    assert PrivateKey(WIF).derive_private_key(0) == derived


@check("PrivateKey: rejects a corrupted WIF (beem's assert was -O-strippable)")
def _():
    bad = WIF[:-1] + ("a" if WIF[-1] != "a" else "b")
    try:
        PrivateKey(bad)
    except Exception:
        return
    raise AssertionError("a corrupted WIF must be rejected")


@check("PasswordKey: derives deterministically per role")
def _():
    posting = PasswordKey("alice", "hunter2", role="posting").get_private()
    active = PasswordKey("alice", "hunter2", role="active").get_private()
    assert posting != active
    assert PasswordKey("alice", "hunter2", role="posting").get_private() == posting
    assert str(PasswordKey("alice", "hunter2", "posting").get_public()).startswith("STM")


@check("BrainKey: derives, and advances its sequence")
def _():
    brain = BrainKey("SOME BRAIN KEY WORDS HERE")
    first = brain.get_private()
    next(brain)
    assert brain.get_private() != first
    assert BrainKey("SOME  BRAIN\tKEY WORDS HERE").get_brainkey() == brain.get_brainkey()


# --------------------------------------------------------------------------
# beemgraphenebase.ecdsasig
# --------------------------------------------------------------------------
@check("sign_message: returns bytes, verifies, matches beem's shape")
def _():
    signature = sign_message("hello hive", WIF)
    assert isinstance(signature, bytes), type(signature)
    assert len(signature) == 65
    recovered = verify_message("hello hive", signature)
    assert isinstance(recovered, bytes)
    assert recovered.hex() == repr(PrivateKey(WIF).pubkey)


@check("sign_message: accepts bytes as well as str")
def _():
    assert sign_message(b"bytes input", WIF) == sign_message("bytes input", WIF)


@check("verify_message: a tampered signature recovers a DIFFERENT key, so comparing catches it")
def _():
    # Recovery answers "which key made this?", so a tampered signature does not
    # fail -- it recovers another key. That is true of beem and of hivecomb alike,
    # and is why the only real check is comparing against an expected key.
    expected = bytes.fromhex(repr(PrivateKey(WIF).pubkey))
    good = sign_message("hello hive", WIF)
    assert verify_message("hello hive", good) == expected

    tampered = bytearray(good)
    tampered[40] ^= 0xFF
    try:
        recovered = verify_message("hello hive", bytes(tampered))
    except Exception:
        return  # malformed enough to be rejected outright, which is also fine
    assert recovered != expected, "a tampered signature must not recover the signer"


@check("verify_message: a malformed signature raises rather than being carried forward")
def _():
    for bad in (b"", b"\x00" * 65, bytes([0]) + bytes(64)):
        try:
            verify_message("hello hive", bad)
        except Exception:
            continue
        raise AssertionError(f"malformed signature {bad[:4]!r} should be rejected")


@check("verify_message: returns ONE key, not beem's four candidates")
def _():
    result = verify_message("hello hive", sign_message("hello hive", WIF))
    assert isinstance(result, bytes) and len(result) == 33


# --------------------------------------------------------------------------
# beembase.operationids -- the table beem got wrong
# --------------------------------------------------------------------------
@check("operationids: FIXED -- post-HF25 operations exist and virtual ids are the chain's")
def _():
    assert operations["collateralized_convert"] == 48
    assert operations["recurrent_transfer"] == 49
    # beem reports each of these two lower, because two non-virtual operations
    # are missing from its table (finding 2).
    assert operations["fill_convert_request"] == 50
    assert operations["producer_reward"] == 64
    assert operations["declined_voting_rights"] == 92
    # beem's misspelling still resolves.
    assert operations["recurring_transfer"] == 49


# --------------------------------------------------------------------------
# beembase.operations
# --------------------------------------------------------------------------
@check("operations: build and render like beem's")
def _():
    op = Custom_json(
        required_auths=[],
        required_posting_auths=["alice"],
        id="my_app_action",
        json={"trx_id": "abc"},
    )
    name, fields = op.json()
    assert name == "custom_json"
    assert fields["json"] == '{"trx_id":"abc"}'
    assert op.opId == 18
    # Indexable and iterable like beem's two-element form.
    assert op[0] == "custom_json"
    assert list(op) == [name, fields]


@check("operations: validate rather than silently accept")
def _():
    for build in (
        lambda: Vote(voter="a", author="b", permlink="p", weight=99999),
        lambda: Custom_json(id="x" * 33, json="{}", required_posting_auths=["a"]),
        lambda: Custom_json(id="x", json="{}"),  # no auths at all
        lambda: Transfer(**{"from": "a"}),  # missing fields
    ):
        try:
            build()
        except Exception:
            continue
        raise AssertionError("invalid operation should have been refused")


@check("operations: ADDITION -- recurrent_transfer, which beem cannot build")
def _():
    op = Recurrent_transfer(
        **{
            "from": "alice",
            "to": "bob",
            "amount": "1.000 HIVE",
            "recurrence": 24,
            "executions": 12,
            "memo": "rent",
        }
    )
    name, fields = op.json()
    assert name == "recurrent_transfer"
    assert fields["recurrence"] == 24 and fields["executions"] == 12
    assert op.opId == 49

    # HF28 pair_id extension.
    paired = Recurrent_transfer(
        **{
            "from": "alice", "to": "bob", "amount": "1.000 HIVE",
            "recurrence": 24, "executions": 12, "pair_id": 7,
        }
    )
    assert paired.json()[1]["extensions"] == [[1, {"pair_id": 7}]]

    # hived's own minimums are enforced.
    try:
        Recurrent_transfer(**{"from": "a", "to": "b", "amount": "1.000 HIVE",
                              "recurrence": 1, "executions": 12})
    except ValueError:
        pass
    else:
        raise AssertionError("a sub-24h recurrence should be refused")


@check("operations: ADDITION -- collateralized_convert, which beem cannot build")
def _():
    op = Collateralized_convert(owner="alice", requestid=1, amount="1.000 HIVE")
    assert op.json()[0] == "collateralized_convert"
    assert op.opId == 48


# --------------------------------------------------------------------------
# beem.Hive -- offline construction
# --------------------------------------------------------------------------
@check("Hive: constructs, and reports the chain id WITHOUT a node call")
def _():
    hive = Hive(node="https://invalid.example", keys=[WIF], nobroadcast=True)
    # This is the whole point: beem fetched the chain id over JSON-RPC.
    assert hive.get_chain_id() == "beeab0de" + "00" * 28
    assert len(hive.wifs) == 1


@check("Hive: custom_json signs offline against a supplied block reference")
def _():
    import hivecomb

    hive = Hive(node="https://invalid.example", keys=[WIF], nobroadcast=True)
    hive._tapos.store_block_id(BLOCK_ID)  # stand in for a background refresh
    tx = hive.custom_json(
        "my_app_action",
        {"trx_id": "abc"},
        required_posting_auths=["alice"],
    )
    assert tx["operations"][0][0] == "custom_json"
    assert len(tx["signatures"]) == 1
    assert len(tx["trx_id"]) == 40
    assert tx["ref_block_num"] == hivecomb.BlockRef.from_block_id(BLOCK_ID).ref_block_num


@check("Hive: transfer and vote build the right operations")
def _():
    hive = Hive(node="https://invalid.example", keys=[WIF], nobroadcast=True)
    hive._tapos.store_block_id(BLOCK_ID)

    tx = hive.transfer("bob", "1.000", "HIVE", "thanks", account="alice")
    name, fields = tx["operations"][0]
    assert name == "transfer" and fields["amount"] == "1.000 HIVE"
    assert fields["memo"] == "thanks"

    tx = hive.vote(100, account="alice", author="bob", permlink="a-post")
    name, fields = tx["operations"][0]
    assert name == "vote" and fields["weight"] == 10000

    tx = hive.vote(-50, "@bob/a-post", account="alice")
    assert tx["operations"][0][1]["weight"] == -5000


@check("Hive: ADDITION -- recurrent_transfer and collateralized_convert broadcast paths")
def _():
    hive = Hive(node="https://invalid.example", keys=[WIF], nobroadcast=True)
    hive._tapos.store_block_id(BLOCK_ID)

    tx = hive.recurrent_transfer("bob", "1.000", "HIVE", 24, 12, account="alice", pair_id=3)
    name, fields = tx["operations"][0]
    assert name == "recurrent_transfer"
    assert fields["extensions"] == [[1, {"pair_id": 3}]]

    tx = hive.collateralized_convert("1.000", requestid=1, account="alice")
    assert tx["operations"][0][0] == "collateralized_convert"


@check("Hive: amounts do not round-trip through float")
def _():
    hive = Hive(node="https://invalid.example", keys=[WIF], nobroadcast=True)
    hive._tapos.store_block_id(BLOCK_ID)
    # Past 2**53 smallest units: beem's float() path loses digits (finding 16).
    tx = hive.transfer("bob", "50000000000.123456", "VESTS", account="alice")
    assert tx["operations"][0][1]["amount"] == "50000000000.123456 VESTS"


@check("Hive: DIVERGENCE -- unknown constructor options are refused, not ignored")
def _():
    try:
        Hive(node="https://invalid.example", keys=[WIF], no_such_option=True)
    except NotImplementedError as exc:
        assert "no_such_option" in str(exc)
        return
    raise AssertionError("an unknown option should be reported")


@check("Hive: a stale TaPoS reference is refused rather than served")
def _():
    import hivecomb
    import time as _time

    hive = Hive(node="https://invalid.example", keys=[WIF], nobroadcast=True,
                tapos_max_age=0)
    hive._tapos.store_block_id(BLOCK_ID)
    _time.sleep(1.1)
    try:
        hive._tapos.block_ref()
    except RuntimeError:
        return
    raise AssertionError("a stale block reference must be refused")


# --------------------------------------------------------------------------
# beem.Steem
# --------------------------------------------------------------------------
@check("Steem: refused with a clear reason rather than signing against a zero chain id")
def _():
    from beem import Steem

    try:
        Steem()
    except NotImplementedError:
        return
    raise AssertionError("Steem should be refused")


# --------------------------------------------------------------------------
# ADDITION -- authority checking (offline)
# --------------------------------------------------------------------------
@check("ADDITION: check_authority reports weight, not just yes/no")
def _():
    import hivecomb

    key_a = str(PrivateKey(WIF).pubkey)
    other = str(PrivateKey().pubkey)
    authority = {
        "weight_threshold": 2,
        "account_auths": [],
        "key_auths": [[key_a, 1], [other, 1]],
    }
    one = hivecomb.check_authority(authority, [key_a])
    assert one["satisfied"] is False
    assert one["weight"] == 1 and one["threshold"] == 2 and one["shortfall"] == 1
    assert one["conclusive"] is True, "no delegations, so this is a real no"
    assert one["matched_keys"] == [key_a]

    both = hivecomb.check_authority(authority, [key_a, other])
    assert both["satisfied"] is True and both["shortfall"] == 0


@check("ADDITION: a delegated authority is inconclusive, not a plain no")
def _():
    import hivecomb

    key_a = str(PrivateKey(WIF).pubkey)
    authority = {
        "weight_threshold": 1,
        "account_auths": [["bot", 1]],
        "key_auths": [[key_a, 1]],
    }
    stranger = hivecomb.check_authority(authority, [str(PrivateKey().pubkey)])
    assert stranger["satisfied"] is False
    assert stranger["conclusive"] is False, (
        "the answer depends on @bot's authority, which was not fetched -- "
        "collapsing that to 'no' is what makes an offline check quietly wrong"
    )
    assert [tuple(a) for a in stranger["unresolved_accounts"]] == [("bot", 1)]

    holder = hivecomb.check_authority(authority, [key_a])
    assert holder["satisfied"] and holder["conclusive"]


@check("ADDITION: check_authority refuses a malformed authority")
def _():
    import hivecomb

    for bad in (
        {"weight_threshold": 0, "key_auths": [], "account_auths": []},
        {"key_auths": [], "account_auths": []},
        {"weight_threshold": 1, "key_auths": [["not-a-key", 1]], "account_auths": []},
    ):
        try:
            hivecomb.check_authority(bad, [])
        except Exception:
            continue
        raise AssertionError(f"should have refused {bad}")


@check("cross-binding vector: same digest as the Rust and Node suites")
def _():
    import hivecomb

    ref = hivecomb.BlockRef.from_block_id("00000005aabbccdd00000000000000000000abcd")
    ops = [("custom_json", {"required_auths": [], "required_posting_auths": ["alice"],
                            "id": "my_app", "json": '{"a":1}'})]
    digest = hivecomb.transaction_digest(ops, ref, "2026-08-22T14:30:00").hex()
    assert digest == "cef35a5b34e7ee9297de5153b363668245793c8ba719762ccacdde9fd85ad3d6", digest
    assert hivecomb.transaction_id(ops, ref, "2026-08-22T14:30:00") == \
        "8e4d2bb0d665a855512abf702c2b8e1ad9f6719e"


# --------------------------------------------------------------------------
# Gaps must be loud
# --------------------------------------------------------------------------
@check("gaps raise NotImplementedError naming an alternative")
def _():
    key = PrivateKey(WIF)
    for call in (
        lambda: key.pubkey.address,
        lambda: key.bitcoin,
        lambda: BrainKey("a b c").suggest(),
    ):
        try:
            call()
        except NotImplementedError as exc:
            assert "MIGRATION.md" in str(exc), str(exc)
            continue
        raise AssertionError("a gap must raise NotImplementedError")


# --------------------------------------------------------------------------
def main():
    print(f"hivecomb compatibility layer: {len(PASS) + len(FAIL)} checks\n")
    for name in PASS:
        print(f"  ok    {name}")
    for name, exc, tb in FAIL:
        print(f"  FAIL  {name}\n        {type(exc).__name__}: {exc}")
        if os.environ.get("COMB_COMPAT_VERBOSE"):
            print(tb)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
