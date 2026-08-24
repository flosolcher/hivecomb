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
import hivecomb                                             # noqa: E402
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
    # The object form, not [[1, {"pair_id": 3}]]. hived rejects the array form for this
    # extension outright ("Bad Cast: ... got array_type"), so a transaction carrying it
    # cannot be broadcast. The binary encoding is the same either way, which is why the
    # array form survived until a node was asked. See BROADCAST.md.
    assert fields["extensions"] == [
        {"type": "recurrent_transfer_pair_id", "value": {"pair_id": 3}}
    ]

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


@check("Hive: finalizeOp permission selects the key rather than being ignored")
def _():
    # beem chose the signing key by role. Accepting `permission` and ignoring it
    # would sign a transfer with whatever key was loaded, which fails at
    # broadcast for anyone relying on a wallet instead of explicit keys. With no
    # keys and no wallet the error must name the role it looked for.
    hive = Hive(node="https://invalid.example", nobroadcast=True)
    hive._tapos.store_block_id(BLOCK_ID)
    try:
        hive.finalizeOp(
            ("transfer", {"from": "alice", "to": "bob",
                          "amount": "1.000 HIVE", "memo": ""}),
            account="alice", permission="active",
        )
    except ValueError as exc:
        assert "active" in str(exc), str(exc)
    else:
        raise AssertionError("signing with no key available should fail")

    # An explicit key still wins over anything a wallet might hold.
    tx = hive.finalizeOp(
        ("transfer", {"from": "alice", "to": "bob",
                      "amount": "1.000 HIVE", "memo": ""}),
        account="alice", permission="active", keys=[WIF],
    )
    assert len(tx["signatures"]) == 1


@check("beem.message: ADDITION -- the signed-message envelope beem had")
def _():
    from beem.message import Message, MessageV1, MessageV2

    # The envelope is a de-facto Hive standard, so the markers and the signed
    # payload layout have to match beem's character for character. A signature over
    # a differently-shaped payload is one no other client will accept.
    assert MessageV1.MESSAGE_SPLIT == (
        "-----BEGIN HIVE SIGNED MESSAGE-----",
        "-----BEGIN META-----",
        "-----BEGIN SIGNATURE-----",
        "-----END HIVE SIGNED MESSAGE-----",
    )

    memo_key = str(hivecomb.PrivateKey(WIF).public_key())
    meta = {"timestamp": "2026-08-22T14:30:00", "block": 109242605,
            "memokey": memo_key, "account": "alice"}
    payload = MessageV1.SIGNED_MESSAGE_META.format(message="hello hive", meta=meta)

    # What gets signed is the message plus four key=value lines, in this order.
    assert payload == (
        "hello hive\n"
        "account=alice\n"
        f"memokey={memo_key}\n"
        "block=109242605\n"
        "timestamp=2026-08-22T14:30:00"
    ), repr(payload)

    # Verified interoperable with hive-nectar in both directions on 2026-08-22:
    # nectar verified this signature, and hivecomb recovered the signer of nectar's.
    signature = hivecomb.sign_message(payload, WIF)
    assert str(hivecomb.recover_message(payload, signature)) == memo_key

    envelope = MessageV1.SIGNED_MESSAGE_ENCAPSULATED.format(
        MESSAGE_SPLIT=MessageV1.MESSAGE_SPLIT, message="hello hive",
        meta=meta, signature=signature,
    )
    for marker in MessageV1.MESSAGE_SPLIT:
        assert marker in envelope

    # Message dispatches across both formats, as beem's did.
    assert issubclass(Message, MessageV1) and issubclass(Message, MessageV2)


@check("beem.exceptions: every type beem defined is present")
def _():
    import beem.exceptions as exc
    # Code that catches a beem exception type must keep working, including the four
    # that were missing until beem.message needed one of them.
    for name in ("InvalidMessageSignature", "BatchedCallsNotSupported",
                 "BlockWaitTimeExceeded", "VestingBalanceDoesNotExistsException",
                 "AccountDoesNotExistsException", "WrongMemoKey",
                 "InvalidMemoKeyException", "MissingKeyError"):
        assert hasattr(exc, name), name
        assert issubclass(getattr(exc, name), Exception)


@check("type stubs match the module they describe")
def _():
    # A stub that has drifted is worse than no stub: it type-checks code that will
    # fail at runtime. So this asserts the .pyi against the real module rather than
    # trusting it. Added after an integrator reported having to cast the module to
    # `object` because no stubs shipped.
    import ast
    import os

    # python-src/hivecomb/__init__.pyi, because PEP 561 needs the stubs inside the
    # importable package rather than wherever the repo happens to keep them.
    stub_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "python-src", "hivecomb", "__init__.pyi",
    )
    if not os.path.exists(stub_path):
        raise AssertionError(f"no stub at {stub_path}")

    tree = ast.parse(open(stub_path, encoding="utf-8").read())
    stub_names, stub_sigs = set(), {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            stub_names.add(node.name)
        elif isinstance(node, ast.FunctionDef):
            stub_names.add(node.name)
            args = [a.arg for a in node.args.args]
            stub_sigs[node.name] = args

    # `__all__`, not `dir()`. Python binds a submodule on its parent at import, so a
    # wheel-installed `hivecomb` also has `hivecomb.hivecomb` in `dir()` while a bare
    # `.so` on PYTHONPATH does not — an integrator pinning on a capability tuple saw
    # 20 names in one layout and 21 in the other. `__all__` is declared explicitly in
    # the extension and is identical either way, which is what a consumer should bind
    # to and therefore what this asserts.
    assert hasattr(hivecomb, "__all__"), "the extension must declare __all__"
    real = set(hivecomb.__all__)
    assert "__doc__" not in real and "__version__" not in real, (
        "__all__ must not carry dunders — `from hivecomb import *` would rebind them"
    )
    # TypedDicts and aliases in the stub are not module attributes; ignore those.
    helpers = {"SignedTransaction", "AuthorityCheck", "Operation"}

    missing = real - stub_names
    assert not missing, f"module exports these, the stub does not describe them: {sorted(missing)}"

    extra = stub_names - real - helpers
    assert not extra, f"stub describes these, the module does not export them: {sorted(extra)}"

    # And the free functions' parameter names must match the real signatures.
    for name, args in stub_sigs.items():
        obj = getattr(hivecomb, name, None)
        if obj is None or not callable(obj):
            continue
        sig = getattr(obj, "__text_signature__", None)
        if not sig:
            continue
        realargs = [
            a.split("=")[0].strip()
            for a in sig.strip("()").split(",")
            if a.strip() and a.strip() != "$self"
        ]
        assert args == realargs, f"{name}: stub says {args}, module says {realargs}"


# --------------------------------------------------------------------------
# Node health tracking. An addition, not a beem compatibility feature -- beem
# has no equivalent -- so the first check here is that the default is unchanged.


@check("health tracking is off unless asked for")
def _health_off_by_default():
    from hivecomb_compat import NodeClient

    client = NodeClient(nodes=["https://a", "https://b"])
    assert client.health is None
    assert list(client._call_order("x")) == [0, 1]


@check("health: a healthy list keeps the configured order")
def _health_healthy_order():
    from hivecomb_compat import HealthPolicy, HealthTracker

    t = HealthTracker(3, HealthPolicy())
    assert t.order("x") == [0, 1, 2]


@check("health: a failing node sorts last")
def _health_failing_sorts_last():
    from hivecomb_compat import HealthPolicy, HealthTracker

    t = HealthTracker(3, HealthPolicy(api_failures_before_cooldown=2))
    t.record_failure(0, "x")
    assert t.order("x") == [0, 1, 2], "one failure is below the threshold"
    t.record_failure(0, "x")
    assert t.order("x") == [1, 2, 0]
    t.record_success(0, "x")
    assert t.order("x") == [0, 1, 2], "one success clears it"


@check("health: one failing method never cools the whole node")
def _health_one_method():
    # The rule that makes per-method tracking worth having: a node serving
    # everything but one API stays first choice for everything else.
    from hivecomb_compat import HealthPolicy, HealthTracker

    t = HealthTracker(2, HealthPolicy(failures_before_cooldown=2))
    for _ in range(20):
        t.record_failure(0, "account_history_api.get_ops_in_block")
    assert not t.snapshot()[0]["in_cooldown"]
    assert t.order("database_api.get_accounts") == [0, 1]
    assert t.order("account_history_api.get_ops_in_block") == [1, 0]


@check("health: failing across methods does cool the whole node")
def _health_two_methods():
    from hivecomb_compat import HealthPolicy, HealthTracker

    t = HealthTracker(2, HealthPolicy(failures_before_cooldown=2))
    t.record_failure(0, "a.one")
    t.record_failure(0, "b.two")
    assert t.snapshot()[0]["in_cooldown"]
    assert t.order("c.never_failed") == [1, 0]


@check("health: a node behind the head sorts after current ones")
def _health_stale():
    from hivecomb_compat import HealthPolicy, HealthTracker

    t = HealthTracker(3, HealthPolicy())
    t.observe_head_block(0, 1_000)
    t.observe_head_block(1, 1_100)
    t.observe_head_block(2, 1_100)
    assert t.order("x") == [1, 2, 0]
    assert t.snapshot()[0]["stale"] and not t.snapshot()[1]["stale"]


@check("health: reordering never drops a node")
def _health_never_drops():
    # The safety property. If every node is unwell the call must still try every
    # one of them -- a tracker that can exclude a node can turn a partial outage
    # into a total one.
    from hivecomb_compat import HealthPolicy, HealthTracker

    t = HealthTracker(3, HealthPolicy(failures_before_cooldown=1))
    for i in range(3):
        t.record_failure(i, "a.one")
        t.record_failure(i, "b.two")
    assert sorted(t.order("a.one")) == [0, 1, 2]


@check("health: a dead first node stops being tried first")
def _health_client_skips_dead_node():
    # Through the client itself rather than the tracker, with the network stubbed.
    import hivecomb_compat
    from hivecomb_compat import HealthPolicy, NodeClient

    seen = []

    class Response:
        def __init__(self, body):
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        url = request.full_url
        seen.append(url)
        if url == "https://a":
            raise OSError("refused")
        return Response(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode())

    real = hivecomb_compat.urllib.request.urlopen
    hivecomb_compat.urllib.request.urlopen = fake_urlopen
    try:
        client = NodeClient(
            nodes=["https://a", "https://b", "https://c"],
            health=HealthPolicy(api_failures_before_cooldown=2),
        )
        for _ in range(5):
            client.call("x")
    finally:
        hivecomb_compat.urllib.request.urlopen = real

    assert seen == [
        "https://a", "https://b",   # call 1
        "https://a", "https://b",   # call 2, threshold crossed
        "https://b", "https://b", "https://b",
    ], seen

    # And the default keeps beem's behaviour: the dead node every time.
    seen.clear()
    hivecomb_compat.urllib.request.urlopen = fake_urlopen
    try:
        plain = NodeClient(nodes=["https://a", "https://b", "https://c"])
        for _ in range(3):
            plain.call("x")
    finally:
        hivecomb_compat.urllib.request.urlopen = real
    assert seen.count("https://a") == 3, seen


@check("health: a protocol error is not counted against the node")
def _health_rpc_error_not_a_node_fault():
    # The node answered; the request was bad. Counting it would cool the whole
    # list for one malformed call.
    import hivecomb_compat
    from hivecomb_compat import HealthPolicy, NodeClient, RPCError

    class Response:
        def __init__(self, body):
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        return Response(
            json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"message": "bad", "code": -32000}}).encode()
        )

    real = hivecomb_compat.urllib.request.urlopen
    hivecomb_compat.urllib.request.urlopen = fake_urlopen
    try:
        client = NodeClient(nodes=["https://a", "https://b"], health=HealthPolicy())
        for _ in range(4):
            try:
                client.call("x")
            except RPCError:
                pass
    finally:
        hivecomb_compat.urllib.request.urlopen = real

    report = client.health.snapshot()
    assert report[0]["consecutive_failures"] == 0, report
    assert not report[0]["in_cooldown"], report


@check("health: the head block is observed from a response that carries one")
def _health_observes_head_block():
    import hivecomb_compat
    from hivecomb_compat import HealthPolicy, NodeClient

    class Response:
        def __init__(self, body):
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        return Response(
            json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"head_block_number": 109242605}}).encode()
        )

    real = hivecomb_compat.urllib.request.urlopen
    hivecomb_compat.urllib.request.urlopen = fake_urlopen
    try:
        client = NodeClient(nodes=["https://a", "https://b"], health=HealthPolicy())
        client.call("database_api.get_dynamic_global_properties")
    finally:
        hivecomb_compat.urllib.request.urlopen = real

    assert client.health.snapshot()[0]["head_block"] == 109242605


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
