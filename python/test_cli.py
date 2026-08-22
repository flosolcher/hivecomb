#!/usr/bin/env python3
"""beempy tests that need no network.

Everything here is offline: argument parsing, key derivation, transaction
construction under ``--dry-run``, and the refusals. Commands that read chain
state are exercised by hand against a live node; these are the ones that must
keep working without one.

    PYTHONPATH=python:<dir with hivecomb.so> python3 python/test_cli.py
"""

import io
import json
import os
import sys
import tempfile
import traceback
from contextlib import redirect_stdout, redirect_stderr

# Always isolate: `setdefault` would let an inherited COMB_CONFIG leak in, and
# the config tests below mutate it -- so a developer with the variable exported
# saw four unrelated failures depending on what they had run before.
_SCRATCH = tempfile.mkdtemp(prefix="beempy-test-")
os.environ["COMB_CONFIG"] = os.path.join(_SCRATCH, "config.json")
os.environ["COMB_WALLET"] = os.path.join(_SCRATCH, "wallet.json")
os.environ["COMB_ASSUME_YES"] = "1"
os.environ.pop("COMB_WIF", None)
os.environ.pop("COMB_WALLET_PASSPHRASE", None)

from beem.cli import COMMANDS, build_parser, main  # noqa: E402

WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
PUB = "STM6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"

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


def run(argv, expect_exit=0):
    """Run beempy and capture what it printed."""
    stdout, stderr = io.StringIO(), io.StringIO()
    code = 0
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
    except SystemExit as exc:
        code = exc.code or 0
    text = stdout.getvalue() + stderr.getvalue()
    if expect_exit is not None and code != expect_exit:
        raise AssertionError(f"{argv} exited {code}, expected {expect_exit}\n{text}")
    return text


# ---------------------------------------------------------------------------


@check("every command parses and has help")
def _():
    parser = build_parser()
    for name, spec in COMMANDS.items():
        assert spec["help"], f"{name} has no help text"
        # The subparser must exist and be reachable.
        assert name in parser._subparsers._group_actions[0].choices, name


@check("beem's command names are all present")
def _():
    # The 99 commands beem's cli.py registered, minus the ones documented as
    # unavailable -- which are still registered, so they can explain themselves.
    beem_commands = """
        set nextnode pingnode about currentnode updatenodes config createwallet
        walletinfo parsewif addkey delkey keygen passwordgen addtoken deltoken
        listkeys listtoken listaccounts upvote delete downvote transfer powerup
        powerdown delegate listdelegations powerdownroute changerecovery convert
        changewalletpassphrase power balance interest followlist follower
        following muter muting notifications permissions allow disallow
        claimaccount changekeys newaccount setprofile delprofile importaccount
        updatememokey beneficiaries message decrypt encrypt uploadimage download
        createpost post reply approvewitness disapprovewitness setproxy delproxy
        sign broadcast stream ticker pricehistory tradehistory orderbook buy sell
        cancel openorders reblog follow mute unfollow witnessupdate witnessdisable
        witnessenable witnesscreate witnessproperties witnessfeed witness
        witnesses votes curation rewards pending claimreward customjson verify
        chainconfig info userdata history featureflags draw
    """.split()
    missing = [c for c in beem_commands if c not in COMMANDS]
    assert not missing, f"missing beem commands: {missing}"


@check("commands beem lacks are registered and marked new")
def _():
    for name in ("recurrenttransfer", "collateralizedconvert", "mnemonic",
                 "bip38", "decodetx", "virtualops", "opsinblock",
                 "verifyauthority", "commands"):
        assert name in COMMANDS, f"{name} is not registered"
        assert COMMANDS[name]["new"], f"{name} should be marked new"


@check("a global flag is not clobbered by the subcommand that repeats it")
def _():
    # argparse applies subparser defaults over the parent namespace, so
    # `beempy --account alice transfer ...` would otherwise lose the account.
    parser = build_parser()
    assert parser.parse_args(
        ["--account", "alice", "transfer", "bob", "1.000", "HIVE"]
    ).account == "alice"
    assert parser.parse_args(
        ["transfer", "bob", "1.000", "HIVE", "--account", "carol"]
    ).account == "carol"
    assert parser.parse_args(
        ["--account", "alice", "transfer", "bob", "1.000", "HIVE", "--account", "carol"]
    ).account == "carol"


@check("about and featureflags run offline")
def _():
    text = run(["about"])
    assert "hivecomb-compat" in text and "beeab0de" in text
    text = run(["featureflags"])
    assert "93" in text and "recurrent_transfer" in text


@check("parsewif derives the public key without storing anything")
def _():
    assert PUB in run(["parsewif", WIF])


@check("parsewif refuses a corrupted key")
def _():
    bad = WIF[:-1] + ("a" if WIF[-1] != "a" else "b")
    text = run(["parsewif", bad], expect_exit=1)
    assert "not a usable key" in text


@check("mnemonic generates a checksummed phrase and all four role keys")
def _():
    import hivecomb

    text = run(["mnemonic", "--words", "12"])
    phrase = text.splitlines()[0].strip()
    assert len(phrase.split()) == 12
    assert hivecomb.validate_mnemonic(phrase)
    for role in ("owner", "active", "posting", "memo"):
        assert role in text
    # ...and the keys shown are the ones the phrase derives.
    expected = str(hivecomb.PrivateKey.from_mnemonic(phrase, "posting", 0).public_key())
    assert expected in text


@check("commands --new lists exactly the commands beem lacks")
def _():
    text = run(["commands", "--new"])
    listed = {
        line.split()[0]
        for line in text.splitlines()[2:]
        if line.strip() and not line.startswith(("-", "These"))
    }
    expected = {name for name, spec in COMMANDS.items() if spec["new"]}
    assert listed == expected, f"listed {sorted(listed)}, expected {sorted(expected)}"
    # A command beem does have must not be in there.
    assert "transfer" not in listed and "upvote" not in listed


@check("dry-run custom_json signs offline and reports a transaction id")
def _():
    text = run([
        "--key", WIF, "--account", "alice", "--dry-run",
        "customjson", "my_app", '{"hello":"hive"}',
    ])
    assert "dry run" in text
    payload = json.loads(text[text.index("{"):])
    assert payload["operations"][0][0] == "custom_json"
    assert payload["operations"][0][1]["required_posting_auths"] == ["alice"]
    assert len(payload["signatures"]) == 1
    assert len(payload["trx_id"]) == 40


@check("dry-run recurrent_transfer carries the HF28 pair_id")
def _():
    text = run([
        "--key", WIF, "--account", "alice", "--dry-run",
        "recurrenttransfer", "bob", "1.000", "HIVE", "24", "12", "rent",
        "--pair-id", "3",
    ])
    payload = json.loads(text[text.index("{"):])
    name, fields = payload["operations"][0]
    assert name == "recurrent_transfer"
    assert fields["recurrence"] == 24 and fields["executions"] == 12
    assert fields["extensions"] == [[1, {"pair_id": 3}]]


@check("recurrent_transfer enforces hived's own minimums before signing")
def _():
    for bad in (["bob", "1.000", "HIVE", "1", "12"], ["bob", "1.000", "HIVE", "24", "1"]):
        text = run(
            ["--key", WIF, "--account", "alice", "--dry-run", "recurrenttransfer"] + bad,
            expect_exit=1,
        )
        assert "hived requires" in text


@check("dry-run collateralized_convert builds the HF25 operation")
def _():
    text = run([
        "--key", WIF, "--account", "alice", "--dry-run",
        "collateralizedconvert", "1.000", "--request-id", "7",
    ])
    payload = json.loads(text[text.index("{"):])
    name, fields = payload["operations"][0]
    assert name == "collateralized_convert"
    assert fields["requestid"] == 7 and fields["amount"] == "1.000 HIVE"


@check("amounts past 2**53 units survive the CLI")
def _():
    text = run([
        "--key", WIF, "--account", "alice", "--dry-run",
        "delegate", "bob", "50000000000.123456",
    ])
    payload = json.loads(text[text.index("{"):])
    assert payload["operations"][0][1]["vesting_shares"] == "50000000000.123456 VESTS"


@check("excess precision is refused rather than truncated")
def _():
    text = run(
        ["--key", WIF, "--account", "alice", "--dry-run",
         "transfer", "bob", "1.2345", "HIVE"],
        expect_exit=1,
    )
    assert "decimal places" in text


@check("a bad identifier is reported, not guessed at")
def _():
    text = run(["--key", WIF, "--account", "alice", "--dry-run",
                "upvote", "not-an-identifier"], expect_exit=1)
    assert "@author/permlink" in text


@check("custom_json refuses a payload that is not JSON")
def _():
    text = run(["--key", WIF, "--account", "alice", "--dry-run",
                "customjson", "my_app", "not json"], expect_exit=1)
    assert "not valid JSON" in text


@check("signing without a key says so instead of failing obscurely")
def _():
    os.environ.pop("COMB_WIF", None)
    text = run(["--account", "alice", "--dry-run",
                "customjson", "my_app", "{}"], expect_exit=1)
    assert "no signing key" in text or "createwallet" in text


@check("commands beem had but this layer does not provide explain themselves")
def _():
    for name in ("uploadimage", "download", "draw", "newaccount", "changekeys",
                 "allow", "disallow", "beneficiaries", "importaccount",
                 "updatememokey"):
        text = run([name], expect_exit=1)
        assert "not available" in text, f"{name}: {text}"
        assert "MIGRATION.md" in text, f"{name} should point at the docs"


@check("config round-trips through set")
def _():
    run(["set", "default_account", "alice"])
    assert "alice" in run(["config"])
    run(["set", "nodes", "https://a.example", "https://b.example"])
    text = run(["currentnode"])
    assert "https://a.example" in text and "https://b.example" in text
    # nextnode rotates rather than dropping.
    run(["nextnode"])
    assert run(["currentnode"]).index("https://b.example") < run(["currentnode"]).index("https://a.example")


@check("an unknown config key is refused")
def _():
    text = run(["set", "nonsense", "1"], expect_exit=1)
    assert "unknown key" in text


def report():
    print(f"beempy: {len(PASS) + len(FAIL)} checks\n")
    for name in PASS:
        print(f"  ok    {name}")
    for name, exc, tb in FAIL:
        print(f"  FAIL  {name}\n        {type(exc).__name__}: {exc}")
        if os.environ.get("COMB_COMPAT_VERBOSE"):
            print(tb)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(report())
