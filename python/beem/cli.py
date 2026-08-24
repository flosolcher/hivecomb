"""beempy — the command line interface.

Drop-in for `beem.cli`, backed by `hivecomb`. Installed as the ``beempy`` console
script.

Two departures from beem's CLI, both deliberate:

* **Zero dependencies.** beem's CLI needed Click, click-shell and prettytable.
  This uses `argparse` and formats its own tables, so installing the
  compatibility layer pulls in nothing beyond `hivecomb`.
* **Commands for what hivecomb adds.** beem's 99 commands are here; so are commands
  for the operations and features beem has no way to reach — ``recurrenttransfer``,
  ``collateralizedconvert``, ``mnemonic``, ``bip38``, ``decodetx`` and
  ``virtualops``. ``beempy commands --new`` lists them.

Configuration lives in ``~/.config/hivecomb/config.json`` (override with
``COMB_CONFIG``). Keys come from the wallet, or from ``--key`` / the
``COMB_WIF`` environment variable when you are not using one.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import hivecomb

from hivecomb_compat import DEFAULT_NODES, NodeClient, RPCError

__all__ = ["cli", "main"]

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def out(*parts, **kwargs):
    print(*parts, **kwargs)


def die(message, code=1):
    print(f"beempy: {message}", file=sys.stderr)
    raise SystemExit(code)


def table(headers, rows, aligns=None):
    """Print an aligned table.

    beem used prettytable. Formatting it here keeps the dependency list empty,
    which matters for a library whose whole point is a small live footprint.
    """
    rows = [[("" if cell is None else str(cell)) for cell in row] for row in rows]
    headers = [str(h) for h in headers]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))
    aligns = aligns or ["<"] * len(headers)

    def line(cells):
        return "  ".join(
            f"{cell:{aligns[i]}{widths[i]}}" for i, cell in enumerate(cells[: len(widths)])
        )

    out(line(headers))
    out("  ".join("-" * width for width in widths))
    for row in rows:
        out(line(row))


def emit_json(value):
    out(json.dumps(value, indent=2, default=str, sort_keys=True))


def ask_passphrase(prompt="Wallet passphrase: ", confirm=False):
    """Read a passphrase without echoing it.

    Falls back to stdin when there is no terminal, so the CLI is usable from a
    script — but says so, because a passphrase on a pipe is visible to anything
    that can read the process's file descriptors.
    """
    env = os.environ.get("COMB_WALLET_PASSPHRASE")
    if env:
        return env
    if not sys.stdin.isatty():
        out("beempy: reading passphrase from stdin (not a terminal)", file=sys.stderr)
        return sys.stdin.readline().rstrip("\n")
    passphrase = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat: ") != passphrase:
        die("passphrases do not match")
    return passphrase


def confirm(prompt):
    """Ask before doing something that costs money or cannot be undone."""
    if os.environ.get("COMB_ASSUME_YES"):
        return True
    if not sys.stdin.isatty():
        die(f"{prompt} — refusing to assume yes without a terminal; set COMB_ASSUME_YES=1")
    return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def config_path():
    override = os.environ.get("COMB_CONFIG")
    if override:
        return Path(override)
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "hivecomb" / "config.json"


DEFAULT_CONFIG = {
    "nodes": list(DEFAULT_NODES),
    "default_account": "",
    "expiration": 60,
    "tapos_max_age": 180,
}


def load_config():
    path = config_path()
    config = dict(DEFAULT_CONFIG)
    if path.exists():
        try:
            config.update(json.loads(path.read_text()))
        except ValueError as exc:
            die(f"{path} is not valid JSON: {exc}")
    return config


def save_config(config):
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, sort_keys=True))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


# ---------------------------------------------------------------------------
# Chain access
# ---------------------------------------------------------------------------


def make_hive(args, keys=None, nobroadcast=None):
    """A `Hive` instance from the config and the shared flags."""
    from .hive import Hive

    config = load_config()
    nodes = args.node or config["nodes"]
    return Hive(
        node=nodes,
        keys=keys or [],
        nobroadcast=args.dry_run if nobroadcast is None else nobroadcast,
        expiration=config.get("expiration", 60),
        tapos_max_age=config.get("tapos_max_age", 180),
        # Reads are left to ordinary failover: racing costs the public nodes N
        # times the requests, and only a broadcast is usually on a deadline.
        race_width=getattr(args, "race", 1),
    )


def rpc_for(args):
    config = load_config()
    return NodeClient(args.node or config["nodes"])


def resolve_account(args, required=True):
    name = getattr(args, "account", None) or load_config().get("default_account")
    if not name and required:
        die("no account given; pass --account or set one with `beempy set default_account <name>`")
    return (name or "").lstrip("@")


def signing_keys(args, account=None, role="posting"):
    """The WIFs to sign with.

    Order: ``--key``, then ``COMB_WIF``, then the wallet. Explicit beats
    ambient, so a key on the command line is never silently overridden by one in
    a store.
    """
    if getattr(args, "key", None):
        return list(args.key)
    env = os.environ.get("COMB_WIF")
    if env:
        return [k.strip() for k in env.split(",") if k.strip()]

    from .wallet import Wallet, default_wallet_path

    if not default_wallet_path().exists():
        die(
            "no signing key: pass --key WIF, set COMB_WIF, or create a wallet "
            "with `beempy createwallet`"
        )
    wallet = Wallet()
    wallet.unlock(ask_passphrase())
    try:
        return [wallet.getKeyForAccount(account, role)]
    except Exception as exc:
        die(f"no {role} key for {account} in the wallet: {exc}")


def broadcast_result(result, args):
    """Report what happened to a transaction."""
    if args.dry_run:
        out("dry run — not broadcast")
        emit_json(result)
        return
    trx_id = result.get("trx_id") if isinstance(result, dict) else None
    out(f"broadcast: {trx_id}" if trx_id else "broadcast")


# ---------------------------------------------------------------------------
# Command registry
# ---------------------------------------------------------------------------

COMMANDS = {}


def command(name, help_text, group="general", new=False):
    """Register a subcommand.

    ``new=True`` marks a command that has no beem equivalent, so
    ``beempy commands --new`` can list what this implementation adds.
    """

    def register(fn):
        # Arguments are read at parser-build time, not here, so `@arg` and
        # `@command` can be written in either order. Reading them now would
        # capture whatever `@arg` decorators had already run, which depends on
        # how they happen to be stacked.
        COMMANDS[name] = {"fn": fn, "help": help_text, "group": group, "new": new}
        return fn

    return register


def arg(*names, **kwargs):
    """Declare an argument for the command below it."""

    def attach(fn):
        if not hasattr(fn, "_args"):
            fn._args = []
        fn._args.insert(0, (names, kwargs))
        return fn

    return attach


# ---------------------------------------------------------------------------
# Nodes and configuration
# ---------------------------------------------------------------------------


@command("about", "show version and build information", group="config")
def cmd_about(args):
    from . import __version__
    from .wallet import default_wallet_path

    wallet = default_wallet_path()
    table(
        ["property", "value"],
        [
            ("beempy (hivecomb compatibility layer)", __version__),
            ("hivecomb extension module", hivecomb.__version__),
            ("chain id", hivecomb.chain_id()),
            ("config", config_path()),
            ("wallet", f"{wallet}{'' if wallet.exists() else ' (none)'}"),
        ],
    )
    out("\nA Rust reimplementation of beem. See MIGRATION.md for what differs,")
    out("and COMPARISON.md for how it stands against the other Rust Hive libraries.")


@command("config", "show the current configuration", group="config")
def cmd_config(args):
    config = load_config()
    table(
        ["key", "value"],
        [(k, ", ".join(v) if isinstance(v, list) else v) for k, v in sorted(config.items())],
    )
    out(f"\nstored in {config_path()}")


@arg("key", help="configuration key")
@arg("value", nargs="+", help="value; repeat for a list, e.g. nodes")
@command("set", "set a configuration value", group="config")
def cmd_set(args):
    config = load_config()
    if args.key not in DEFAULT_CONFIG:
        die(f"unknown key {args.key!r}; known: {', '.join(sorted(DEFAULT_CONFIG))}")
    if args.key == "nodes":
        config["nodes"] = list(args.value)
    elif args.key in {"expiration", "tapos_max_age"}:
        config[args.key] = int(args.value[0])
    else:
        config[args.key] = args.value[0]
    out(f"{args.key} = {config[args.key]}  ({save_config(config)})")


@command("currentnode", "show the configured nodes, best first", group="config")
def cmd_currentnode(args):
    config = load_config()
    table(["#", "node"], list(enumerate(config["nodes"], 1)))


@command("nextnode", "move the first node to the end of the list", group="config")
def cmd_nextnode(args):
    config = load_config()
    if len(config["nodes"]) < 2:
        die("fewer than two nodes are configured")
    config["nodes"] = config["nodes"][1:] + config["nodes"][:1]
    save_config(config)
    out(f"now trying {config['nodes'][0]} first")


@arg("--sort", action="store_true", help="reorder the config by measured speed")
@command("pingnode", "measure each node's response time", group="config")
def cmd_pingnode(args):
    config = load_config()
    rows = []
    for node in config["nodes"]:
        started = time.time()
        try:
            NodeClient([node], timeout=5, num_retries=1).call(
                "database_api.get_dynamic_global_properties", {}
            )
            rows.append((node, f"{(time.time() - started) * 1000:.0f} ms", "ok"))
        except Exception as exc:
            rows.append((node, "-", f"{type(exc).__name__}"))
    table(["node", "latency", "status"], rows)
    if args.sort:
        ranked = [r[0] for r in sorted(rows, key=lambda r: float(r[1].split()[0]) if r[2] == "ok" else 1e9)]
        config["nodes"] = ranked
        save_config(config)
        out(f"\nreordered; now trying {ranked[0]} first")


@command("updatenodes", "measure every known node and keep the ones that answer", group="config")
def cmd_updatenodes(args):
    from .nodelist import NodeList

    nodes = NodeList()
    nodes.update_nodes()
    working = [n["url"] for n in nodes if n.get("score", 0) > 0]
    if not working:
        die("no node answered")
    config = load_config()
    config["nodes"] = working
    save_config(config)
    table(["node", "score"], [(n["url"], n["score"]) for n in nodes])
    out(f"\nkept {len(working)} of {len(nodes)}")


@command("chainconfig", "show the node's chain configuration", group="config")
def cmd_chainconfig(args):
    emit_json(rpc_for(args).call("database_api.get_config", {}))


@command("info", "show chain state, or look up an account, block or post", group="config")
@arg("objects", nargs="*", help="account, block number or @author/permlink")
def cmd_info(args):
    hive = make_hive(args)
    if not args.objects:
        from .amount import Amount

        props = hive.get_dynamic_global_properties()

        def amount(field):
            """Render an amount field, whichever shape the node sent."""
            value = props.get(field)
            return str(Amount(value)) if value is not None else None

        rows = [
            ("head block", props["head_block_number"]),
            ("irreversible", props.get("last_irreversible_block_num")),
            ("time", props["time"]),
            ("witness", props["current_witness"]),
            ("HIVE supply", amount("current_supply")),
            ("HBD supply", amount("current_hbd_supply")),
            ("vesting fund", amount("total_vesting_fund_hive")),
            ("vesting shares", amount("total_vesting_shares")),
            ("HBD interest", f"{props.get('hbd_interest_rate', 0) / 100:.2f}%"),
            ("chain id (local)", hivecomb.chain_id()),
        ]
        table(["property", "value"], rows)
        return
    for item in args.objects:
        _describe(hive, item)


def _describe(hive, item):
    from .account import Account
    from .block import Block
    from .comment import Comment

    text = str(item)
    if text.isdigit():
        block = Block(int(text), blockchain_instance=hive)
        out(f"block {block.block_num} at {block.time}, {len(block.operations)} operations")
        table(["op", "count"], sorted(block.ops_statistics().items(), key=lambda kv: -kv[1]))
        return
    if "/" in text:
        post = Comment(text, blockchain_instance=hive)
        out(f"{post.authorperm}\n  {post.title}\n  payout {post.reward}  votes {len(post.get_votes())}")
        return
    Account(text.lstrip("@"), blockchain_instance=hive).print_info()


@command("featureflags", "show which chain features this build knows about", group="config")
def cmd_featureflags(args):
    from beembase.operationids import FIRST_VIRTUAL_OP, ops

    rows = [
        ("operations known", len(ops)),
        ("signable operations", FIRST_VIRTUAL_OP),
        ("virtual operations", len(ops) - FIRST_VIRTUAL_OP),
        ("recurrent_transfer (HF25)", "yes — beem cannot build it"),
        ("collateralized_convert (HF25)", "yes — beem cannot build it"),
        ("recurrent pair_id (HF28)", "yes"),
        ("offline signing", "yes — chain id is a local constant"),
        ("memo varint prefix", "yes — beem omits it"),
        ("wallet KDF", "scrypt + AES-256-GCM"),
        ("node racing", "yes — `--race N` on broadcast"),
        ("async (Rust only)", "yes — `async` feature, runtime-agnostic"),
    ]
    table(["feature", "state"], rows)


# ---------------------------------------------------------------------------
# Wallet and keys
# ---------------------------------------------------------------------------


@command("createwallet", "create the encrypted key store", group="wallet")
def cmd_createwallet(args):
    from .wallet import Wallet, default_wallet_path

    path = default_wallet_path()
    if path.exists():
        die(f"{path} already exists; refusing to overwrite a key store")
    passphrase = ask_passphrase("New wallet passphrase: ", confirm=True)
    if len(passphrase) < 8:
        die("choose a longer passphrase; scrypt raises the cost per guess but is not a substitute for entropy")
    Wallet().create(passphrase)
    out(f"created {path}")
    out("Encrypted with scrypt (N=2^15) and AES-256-GCM. Keep a backup of the passphrase:")
    out("there is no recovery path, by design.")


@command("walletinfo", "show the key store's state", group="wallet")
def cmd_walletinfo(args):
    from .wallet import Wallet, default_wallet_path

    path = default_wallet_path()
    if not path.exists():
        out(f"no wallet at {path}")
        return
    wallet = Wallet()
    rows = [("path", path), ("keys", len(wallet.getPublicKeys())), ("locked", "yes")]
    table(["property", "value"], rows)
    accounts = wallet.getAccounts()
    if accounts:
        out("\naccounts (readable while locked):")
        table(["account", "roles"], [(a, ", ".join(sorted(set(r)))) for a, r in wallet._wallet.index().items()] if wallet._wallet else [])


@arg("--account", help="tag the key with this account")
@arg("--role", choices=["owner", "active", "posting", "memo"], help="tag the key with this role")
@command("addkey", "add a private key to the store", group="wallet")
def cmd_addkey(args):
    from .wallet import Wallet

    wallet = Wallet()
    wallet.unlock(ask_passphrase())
    wif = ask_passphrase("WIF: ")
    public = wallet.addPrivateKey(wif, account=args.account, role=args.role)
    out(f"added {public}")


@arg("pubkeys", nargs="+", help="public keys to remove")
@command("delkey", "remove keys from the store", group="wallet")
def cmd_delkey(args):
    from .wallet import Wallet

    if not confirm(f"Remove {len(args.pubkeys)} key(s)?"):
        die("cancelled", code=0)
    wallet = Wallet()
    wallet.unlock(ask_passphrase())
    for pub in args.pubkeys:
        wallet.removePrivateKeyFromPublicKey(pub)
        out(f"removed {pub}")


@command("listkeys", "list the public keys in the store", group="wallet")
def cmd_listkeys(args):
    from .wallet import Wallet, default_wallet_path

    if not default_wallet_path().exists():
        die("no wallet; create one with `beempy createwallet`")
    table(["public key"], [(k,) for k in Wallet().getPublicKeys()])


@command("listaccounts", "list the accounts the store knows about", group="wallet")
def cmd_listaccounts(args):
    from .wallet import Wallet, default_wallet_path

    if not default_wallet_path().exists():
        die("no wallet; create one with `beempy createwallet`")
    wallet = Wallet()
    index = wallet._wallet.index() if wallet._wallet else {}
    if not index:
        wallet_open = hivecomb.Wallet.open(str(wallet.path))
        index = wallet_open.index()
    table(["account", "roles"], [(a, ", ".join(sorted(set(r)))) for a, r in sorted(index.items())])


@command("changewalletpassphrase", "re-encrypt the store under a new passphrase", group="wallet")
def cmd_changewalletpassphrase(args):
    from .wallet import Wallet

    wallet = Wallet()
    wallet.unlock(ask_passphrase("Current passphrase: "))
    new = ask_passphrase("New passphrase: ", confirm=True)
    wallet.changePassphrase(new)
    out("re-encrypted with a fresh salt; the old passphrase no longer opens it")


@arg("wif", nargs="?", help="the WIF to inspect; prompted for if omitted")
@command("parsewif", "show the public key for a WIF, without storing it", group="wallet")
def cmd_parsewif(args):
    wif = args.wif or ask_passphrase("WIF: ")
    try:
        key = hivecomb.PrivateKey(wif)
    except ValueError as exc:
        die(f"not a usable key: {exc}")
    out(f"public key  {key.public_key()}")


@arg("--role", default="posting", choices=["owner", "active", "posting", "memo"])
@arg("--account", help="account name, for the password derivation")
@command("keygen", "derive or generate a key", group="wallet")
def cmd_keygen(args):
    out("Choose how to derive the key:")
    out("  1  random (recommended)")
    out("  2  from a BIP-39 mnemonic")
    out("  3  from an account name and master password (Hive's scheme; weak)")
    choice = input("[1] ").strip() or "1"

    if choice == "1":
        key = hivecomb.PrivateKey.generate()
    elif choice == "2":
        mnemonic = ask_passphrase("Mnemonic: ")
        if not hivecomb.validate_mnemonic(mnemonic):
            die("that mnemonic fails its checksum or contains a word outside the BIP-39 list")
        account_index = int(input("Account index [0]: ").strip() or "0")
        key = hivecomb.PrivateKey.from_mnemonic(mnemonic, args.role, account_index)
    elif choice == "3":
        if not args.account:
            die("--account is required for password derivation")
        out("Note: this is one unsalted SHA-256 with no work factor. It is Hive's")
        out("scheme, not a good one. Prefer option 1 or 2 for anything that holds value.")
        password = ask_passphrase("Master password: ")
        key = hivecomb.PrivateKey.from_password(args.account, args.role, password)
    else:
        die("unknown choice")

    out(f"\nrole        {args.role}")
    out(f"public key  {key.public_key()}")
    out(f"private key {key.to_wif()}")
    out("\nStore it now. This is the only time it is printed.")


@arg("--words", type=int, default=24, choices=[12, 15, 18, 21, 24])
@command("mnemonic", "generate a BIP-39 mnemonic and its Hive role keys", group="wallet", new=True)
def cmd_mnemonic(args):
    """Not in beem: its brain-key generator was biased, and its BIP-39 support
    never derived Hive role keys."""
    strength = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}[args.words]
    phrase = hivecomb.generate_mnemonic(strength)
    out(phrase)
    out("")
    rows = []
    for role in ("owner", "active", "posting", "memo"):
        key = hivecomb.PrivateKey.from_mnemonic(phrase, role, 0)
        rows.append((role, str(key.public_key()), key.to_wif()))
    table(["role", "public key", "private key"], rows)
    out("\nDerived at m/48'/13'/<role>'/0'/0', the path Hive wallets use.")
    out("Write the mnemonic down. Every key above comes back from it; nothing else does.")


@arg("--decrypt", action="store_true", help="decrypt a 6P... key instead")
@arg("key", nargs="?", help="the WIF to encrypt, or the 6P key to decrypt")
@command("bip38", "encrypt or decrypt a key under a passphrase", group="wallet", new=True)
def cmd_bip38(args):
    """Not exposed by beem's CLI, though its library had the primitive."""
    value = args.key or ask_passphrase("Key: ")
    passphrase = ask_passphrase("BIP-38 passphrase: ", confirm=not args.decrypt)
    if args.decrypt:
        try:
            out(hivecomb.PrivateKey.from_bip38(value, passphrase).to_wif())
        except ValueError as exc:
            die(str(exc))
    else:
        out(hivecomb.PrivateKey(value).to_bip38(passphrase))


@command("passwordgen", "derive role keys from an account name and master password", group="wallet")
def cmd_passwordgen(args):
    account = input("Account: ").strip()
    if not account:
        die("an account name is required")
    password = ask_passphrase("Master password: ")
    out("\nThis scheme is one unsalted SHA-256 with no work factor. It is Hive's,")
    out("not beem's and not hivecomb's, and it cannot be changed without breaking")
    out("compatibility. Prefer `beempy mnemonic` for a new account.\n")
    rows = []
    for role in ("owner", "active", "posting", "memo"):
        key = hivecomb.PrivateKey.from_password(account, role, password)
        rows.append((role, str(key.public_key()), key.to_wif()))
    table(["role", "public key", "private key"], rows)


@command("addtoken", "store an API token", group="wallet")
@arg("name")
@arg("token", nargs="?")
def cmd_addtoken(args):
    die(
        "token storage is not implemented; it served beem's HiveSigner integration, "
        "which this layer does not provide. See MIGRATION.md."
    )


@command("deltoken", "remove an API token", group="wallet")
@arg("name")
def cmd_deltoken(args):
    die("token storage is not implemented; see MIGRATION.md")


@command("listtoken", "list stored API tokens", group="wallet")
def cmd_listtoken(args):
    die("token storage is not implemented; see MIGRATION.md")


# ---------------------------------------------------------------------------
# Account information
# ---------------------------------------------------------------------------


@arg("accounts", nargs="*", help="accounts to show; defaults to the configured one")
@command("balance", "show an account's balances", group="account")
def cmd_balance(args):
    from .account import Account

    hive = make_hive(args)
    names = args.accounts or [resolve_account(args)]
    rows = []
    for name in names:
        account = Account(name.lstrip("@"), blockchain_instance=hive)
        rows.append(
            (
                account.name,
                account.get_balance("available", "HIVE"),
                account.get_balance("available", "HBD"),
                account.get_token_power(),
                account.get_balance("savings", "HIVE"),
                account.get_balance("savings", "HBD"),
            )
        )
    table(["account", "HIVE", "HBD", "hive power", "sav HIVE", "sav HBD"], rows)


@arg("accounts", nargs="*")
@command("power", "show voting, downvote and resource-credit levels", group="account")
def cmd_power(args):
    from .account import Account

    hive = make_hive(args)
    names = args.accounts or [resolve_account(args)]
    rows = []
    for name in names:
        account = Account(name.lstrip("@"), blockchain_instance=hive)
        rc = account.get_rc_manabar()
        rows.append(
            (
                account.name,
                f"{account.get_voting_power():.2f}%",
                f"{account.get_downvoting_power():.2f}%",
                f"{rc['current_pct']:.2f}%",
                account.get_token_power(),
            )
        )
    table(["account", "voting", "downvote", "rc", "hive power"], rows)


@arg("accounts", nargs="*")
@command("interest", "show HBD savings interest state", group="account")
def cmd_interest(args):
    from .account import Account

    hive = make_hive(args)
    rows = []
    for name in args.accounts or [resolve_account(args)]:
        account = Account(name.lstrip("@"), blockchain_instance=hive)
        rows.append(
            (
                account.name,
                account.get("savings_hbd_balance"),
                account.get("savings_hbd_last_interest_payment"),
                account.get("savings_hbd_seconds_last_update"),
            )
        )
    table(["account", "savings HBD", "last payment", "last update"], rows)


@arg("account", nargs="?")
@arg("--limit", type=int, default=20)
@arg("--type", dest="op_type", help="only this operation type")
@arg("--json", dest="as_json", action="store_true")
@arg("--scan", type=int, help="how many entries to read looking for matches")
@command("history", "show an account's operation history, newest first", group="account")
def cmd_history(args):
    from .account import Account

    hive = make_hive(args)
    account = Account(
        (args.account or resolve_account(args)).lstrip("@"), blockchain_instance=hive
    )
    only = [args.op_type] if args.op_type else None
    scan = args.scan or (10_000 if only else args.limit)
    entries = list(account.history_reverse(limit=args.limit, only_ops=only, max_scan=scan))
    if args.as_json:
        emit_json(entries)
        return
    rows = [
        (
            entry["index"],
            entry.get("timestamp", ""),
            entry["type"],
            _summarise(entry),
        )
        for entry in entries
    ]
    table(["#", "when", "type", "detail"], rows)
    if getattr(account, "last_scan_exhausted", False):
        out(
            f"\nstopped after reading {scan} entries without finding "
            f"{args.limit}; raise --scan to look further back"
        )


def _summarise(entry):
    """One line describing a history entry."""
    kind = entry.get("type")
    if kind == "transfer":
        return f"{entry.get('from')} -> {entry.get('to')}  {entry.get('amount')}  {entry.get('memo','')[:30]}"
    if kind == "vote":
        return f"{entry.get('voter')} on @{entry.get('author')}/{entry.get('permlink')} at {entry.get('weight',0)/100:.0f}%"
    if kind == "custom_json":
        return f"id={entry.get('id')} {str(entry.get('json'))[:40]}"
    if kind in {"claim_reward_balance"}:
        return f"{entry.get('reward_hive')} {entry.get('reward_hbd')} {entry.get('reward_vests')}"
    if kind == "producer_reward":
        return f"{entry.get('producer')} {entry.get('vesting_shares')}"
    if kind in {"recurrent_transfer", "fill_recurrent_transfer"}:
        return (
            f"{entry.get('from')} -> {entry.get('to')} {entry.get('amount')} "
            f"every {entry.get('recurrence', '?')}h, {entry.get('remaining_executions', entry.get('executions', '?'))} left"
        )
    interesting = {k: v for k, v in entry.items()
                   if k not in {"type", "index", "block", "timestamp", "trx_id"}}
    return str(interesting)[:70]


@arg("account", nargs="?")
@command("permissions", "show an account's authorities", group="account")
def cmd_permissions(args):
    from .account import Account

    hive = make_hive(args)
    account = Account(
        (args.account or resolve_account(args)).lstrip("@"), blockchain_instance=hive
    )
    rows = []
    for role in ("owner", "active", "posting"):
        authority = account.get(role, {})
        for name, weight in authority.get("account_auths", []):
            rows.append((role, authority.get("weight_threshold"), f"@{name}", weight))
        for key, weight in authority.get("key_auths", []):
            rows.append((role, authority.get("weight_threshold"), key, weight))
    rows.append(("memo", "", account.get("memo_key"), ""))
    table(["role", "threshold", "entry", "weight"], rows)


@arg("account", nargs="?")
@command("votes", "show the witnesses an account votes for", group="account")
def cmd_votes(args):
    from .account import Account

    hive = make_hive(args)
    account = Account(
        (args.account or resolve_account(args)).lstrip("@"), blockchain_instance=hive
    )
    witnesses = account.get("witness_votes", [])
    proxy = account.get("proxy") or ""
    if proxy:
        out(f"proxied to @{proxy}")
    expiry = account.governance_vote_expiration
    if expiry:
        state = "EXPIRED" if account.governance_votes_expired() else "expires"
        out(f"governance votes {state} {expiry}")
    else:
        out("governance votes do not expire")
    table(["witness"], [(w,) for w in witnesses] or [("(none)",)])


@arg("account", nargs="?")
@arg("--limit", type=int, default=20)
@command("rewards", "show unclaimed rewards", group="account")
def cmd_rewards(args):
    from .account import Account

    hive = make_hive(args)
    rows = []
    for name in [args.account or resolve_account(args)]:
        account = Account(name.lstrip("@"), blockchain_instance=hive)
        rewards = account.reward_balances
        rows.append((account.name, rewards[0], rewards[1], rewards[2]))
    table(["account", "HIVE", "HBD", "VESTS"], rows)


@arg("account", nargs="?")
@command("pending", "show pending rewards and payouts", group="account")
def cmd_pending(args):
    cmd_rewards(args)


@arg("account", nargs="?")
@arg("--limit", type=int, default=20)
@command("curation", "show recent curation rewards", group="account")
def cmd_curation(args):
    from .account import Account

    hive = make_hive(args)
    account = Account(
        (args.account or resolve_account(args)).lstrip("@"), blockchain_instance=hive
    )
    entries = list(
        account.history_reverse(
            limit=args.limit, only_ops=["curation_reward"], max_scan=10_000
        )
    )
    table(
        ["when", "reward", "author", "permlink"],
        [
            (e.get("timestamp"), e.get("reward"), e.get("author"), e.get("permlink"))
            for e in entries
        ],
    )


@arg("account", nargs="?")
@command("follower", "list an account's followers", group="account")
def cmd_follower(args):
    _follow_listing(args, "get_followers")


@arg("account", nargs="?")
@command("following", "list the accounts an account follows", group="account")
def cmd_following(args):
    _follow_listing(args, "get_following")


@arg("account", nargs="?")
@command("muter", "list the accounts muting this one", group="account")
def cmd_muter(args):
    _follow_listing(args, "get_muters")


@arg("account", nargs="?")
@command("muting", "list the accounts this one mutes", group="account")
def cmd_muting(args):
    _follow_listing(args, "get_mutings")


def _follow_listing(args, method):
    from .account import Account

    hive = make_hive(args)
    account = Account(
        (args.account or resolve_account(args)).lstrip("@"), blockchain_instance=hive
    )
    names = getattr(account, method)(limit=100)
    table(["account"], [(n,) for n in names] or [("(none)",)])


@arg("account", nargs="?")
@arg("--what", default="blog", choices=["blog", "ignore"])
@command("followlist", "list follows of a given kind", group="account")
def cmd_followlist(args):
    _follow_listing(args, "get_following" if args.what == "blog" else "get_mutings")


@arg("account", nargs="?")
@arg("--limit", type=int, default=20)
@command("notifications", "show an account's notifications", group="account")
def cmd_notifications(args):
    from .account import Account

    hive = make_hive(args)
    account = Account(
        (args.account or resolve_account(args)).lstrip("@"), blockchain_instance=hive
    )
    items = account.get_notifications(limit=args.limit) or []
    table(
        ["when", "type", "msg"],
        [(i.get("date"), i.get("type"), i.get("msg")) for i in items],
    )


@arg("account", nargs="?")
@command("userdata", "show an account's profile metadata", group="account")
def cmd_userdata(args):
    from .account import Account

    hive = make_hive(args)
    account = Account(
        (args.account or resolve_account(args)).lstrip("@"), blockchain_instance=hive
    )
    emit_json(account.profile)


@arg("account", nargs="?")
@command("listdelegations", "show outgoing vesting delegations", group="account")
def cmd_listdelegations(args):
    from .account import Account

    hive = make_hive(args)
    account = Account(
        (args.account or resolve_account(args)).lstrip("@"), blockchain_instance=hive
    )
    delegations = account.get_vesting_delegations()
    table(
        ["delegatee", "vesting shares", "since"],
        [(d["delegatee"], d["vesting_shares"], d.get("min_delegation_time")) for d in delegations],
    )


# ---------------------------------------------------------------------------
# Broadcasting
# ---------------------------------------------------------------------------


def _broadcast(args, ops, role="posting", account=None):
    """Sign and broadcast, honouring --dry-run."""
    account = account or resolve_account(args)
    keys = signing_keys(args, account=account, role=role)
    hive = make_hive(args, keys=keys)
    result = hive.finalizeOp(ops, account=account)
    broadcast_result(result, args)
    return result


@arg("identifier", help="@author/permlink")
@arg("--weight", type=float, default=100.0, help="vote weight in percent")
@arg("--account")
@command("upvote", "upvote a post", group="broadcast")
def cmd_upvote(args):
    author, permlink = _split(args.identifier)
    account = resolve_account(args)
    _broadcast(
        args,
        ("vote", {
            "voter": account,
            "author": author,
            "permlink": permlink,
            "weight": int(abs(args.weight) * 100),
        }),
        account=account,
    )


@arg("identifier")
@arg("--weight", type=float, default=100.0)
@arg("--account")
@command("downvote", "downvote a post", group="broadcast")
def cmd_downvote(args):
    author, permlink = _split(args.identifier)
    account = resolve_account(args)
    _broadcast(
        args,
        ("vote", {
            "voter": account,
            "author": author,
            "permlink": permlink,
            "weight": -int(abs(args.weight) * 100),
        }),
        account=account,
    )


@arg("identifier")
@arg("--account")
@command("delete", "delete a post or comment", group="broadcast")
def cmd_delete(args):
    author, permlink = _split(args.identifier)
    _broadcast(args, ("delete_comment", {"author": author, "permlink": permlink}))


@arg("to")
@arg("amount")
@arg("asset", nargs="?", default="HIVE", choices=["HIVE", "HBD"])
@arg("memo", nargs="?", default="")
@arg("--account")
@command("transfer", "transfer HIVE or HBD", group="broadcast")
def cmd_transfer(args):
    account = resolve_account(args)
    amount = _amount(args.amount, args.asset)
    if not confirm(f"Send {amount} to @{args.to}?"):
        die("cancelled", code=0)
    _broadcast(
        args,
        ("transfer", {
            "from": account,
            "to": args.to.lstrip("@"),
            "amount": amount,
            "memo": args.memo,
        }),
        role="active",
        account=account,
    )


@arg("to")
@arg("amount")
@arg("asset", choices=["HIVE", "HBD"])
@arg("recurrence", type=int, help="hours between executions; at least 24")
@arg("executions", type=int, help="total executions; at least 2")
@arg("memo", nargs="?", default="")
@arg("--pair-id", type=int, help="HF28: run several concurrent transfers to one recipient")
@arg("--account")
@command("recurrenttransfer", "set up a recurrent transfer (HF25)", group="broadcast", new=True)
def cmd_recurrenttransfer(args):
    """Not available in beem: the operation is absent from its id table."""
    account = resolve_account(args)
    amount = _amount(args.amount, args.asset)
    if args.recurrence < 24:
        die("hived requires a recurrence of at least 24 hours")
    if args.executions < 2:
        die("hived requires at least 2 executions")
    total = f"{args.executions} x {amount}"
    if not confirm(f"Send {amount} to @{args.to} every {args.recurrence}h, {total} in all?"):
        die("cancelled", code=0)
    fields = {
        "from": account,
        "to": args.to.lstrip("@"),
        "amount": amount,
        "memo": args.memo,
        "recurrence": args.recurrence,
        "executions": args.executions,
    }
    if args.pair_id is not None:
        fields["extensions"] = [[1, {"pair_id": args.pair_id}]]
    _broadcast(args, ("recurrent_transfer", fields), role="active", account=account)


@arg("amount")
@arg("--request-id", type=int)
@arg("--account")
@command("collateralizedconvert", "convert HIVE to HBD immediately against collateral (HF25)",
         group="broadcast", new=True)
def cmd_collateralizedconvert(args):
    """Not available in beem: the operation is absent from its id table."""
    account = resolve_account(args)
    amount = _amount(args.amount, "HIVE")
    if not confirm(f"Collateralized-convert {amount}?"):
        die("cancelled", code=0)
    _broadcast(
        args,
        ("collateralized_convert", {
            "owner": account,
            "requestid": args.request_id if args.request_id is not None else int(time.time()),
            "amount": amount,
        }),
        role="active",
        account=account,
    )


@arg("amount")
@arg("--request-id", type=int)
@arg("--account")
@command("convert", "convert HBD to HIVE over 3.5 days", group="broadcast")
def cmd_convert(args):
    account = resolve_account(args)
    amount = _amount(args.amount, "HBD")
    if not confirm(f"Convert {amount} over 3.5 days?"):
        die("cancelled", code=0)
    _broadcast(
        args,
        ("convert", {
            "owner": account,
            "requestid": args.request_id if args.request_id is not None else int(time.time()),
            "amount": amount,
        }),
        role="active",
        account=account,
    )


@arg("amount")
@arg("--to", help="power up to another account")
@arg("--account")
@command("powerup", "convert HIVE to Hive Power", group="broadcast")
def cmd_powerup(args):
    account = resolve_account(args)
    amount = _amount(args.amount, "HIVE")
    _broadcast(
        args,
        ("transfer_to_vesting", {
            "from": account,
            "to": (args.to or account).lstrip("@"),
            "amount": amount,
        }),
        role="active",
        account=account,
    )


@arg("amount", help="VESTS to power down, or 0 to stop")
@arg("--account")
@command("powerdown", "start or stop a power-down", group="broadcast")
def cmd_powerdown(args):
    account = resolve_account(args)
    amount = _amount(args.amount, "VESTS")
    if not confirm(f"Power down {amount} over 13 weeks?"):
        die("cancelled", code=0)
    _broadcast(
        args,
        ("withdraw_vesting", {"account": account, "vesting_shares": amount}),
        role="active",
        account=account,
    )


@arg("to")
@arg("percentage", type=float)
@arg("--auto-vest", action="store_true")
@arg("--account")
@command("powerdownroute", "route part of a power-down to another account", group="broadcast")
def cmd_powerdownroute(args):
    account = resolve_account(args)
    _broadcast(
        args,
        ("set_withdraw_vesting_route", {
            "from_account": account,
            "to_account": args.to.lstrip("@"),
            "percent": int(args.percentage * 100),
            "auto_vest": args.auto_vest,
        }),
        role="active",
        account=account,
    )


@arg("to")
@arg("amount", help="VESTS to delegate, or 0 to revoke")
@arg("--account")
@command("delegate", "delegate Hive Power", group="broadcast")
def cmd_delegate(args):
    account = resolve_account(args)
    amount = _amount(args.amount, "VESTS")
    _broadcast(
        args,
        ("delegate_vesting_shares", {
            "delegator": account,
            "delegatee": args.to.lstrip("@"),
            "vesting_shares": amount,
        }),
        role="active",
        account=account,
    )


@arg("--account")
@command("claimreward", "claim pending rewards", group="broadcast")
def cmd_claimreward(args):
    from .account import Account

    account_name = resolve_account(args)
    hive = make_hive(args)
    account = Account(account_name, blockchain_instance=hive)
    rewards = account.reward_balances
    if all(r is None or r.units() == 0 for r in rewards):
        out("nothing to claim")
        return
    _broadcast(
        args,
        ("claim_reward_balance", {
            "account": account_name,
            "reward_hive": str(rewards[0]),
            "reward_hbd": str(rewards[1]),
            "reward_vests": str(rewards[2]),
        }),
        account=account_name,
    )


@arg("id", help=f"the custom_json id, at most {hivecomb.MAX_CUSTOM_ID_LEN} bytes")
@arg("json_data", help="the payload, as JSON")
@arg("--active", action="store_true", help="sign with the active authority instead")
@arg("--account")
@command("customjson", "broadcast a custom_json operation", group="broadcast")
def cmd_customjson(args):
    account = resolve_account(args)
    try:
        payload = json.loads(args.json_data)
    except ValueError as exc:
        die(f"payload is not valid JSON: {exc}")
    fields = {
        "id": args.id,
        "json": payload,
        "required_auths": [account] if args.active else [],
        "required_posting_auths": [] if args.active else [account],
    }
    _broadcast(args, ("custom_json", fields),
               role="active" if args.active else "posting", account=account)


@arg("witness")
@arg("--account")
@command("approvewitness", "vote for a witness", group="broadcast")
def cmd_approvewitness(args):
    account = resolve_account(args)
    _broadcast(
        args,
        ("account_witness_vote", {
            "account": account, "witness": args.witness.lstrip("@"), "approve": True
        }),
        role="active",
        account=account,
    )


@arg("witness")
@arg("--account")
@command("disapprovewitness", "remove a witness vote", group="broadcast")
def cmd_disapprovewitness(args):
    account = resolve_account(args)
    _broadcast(
        args,
        ("account_witness_vote", {
            "account": account, "witness": args.witness.lstrip("@"), "approve": False
        }),
        role="active",
        account=account,
    )


@arg("proxy")
@arg("--account")
@command("setproxy", "proxy governance votes to another account", group="broadcast")
def cmd_setproxy(args):
    account = resolve_account(args)
    _broadcast(
        args,
        ("account_witness_proxy", {"account": account, "proxy": args.proxy.lstrip("@")}),
        role="active",
        account=account,
    )


@arg("--account")
@command("delproxy", "clear the governance vote proxy", group="broadcast")
def cmd_delproxy(args):
    account = resolve_account(args)
    _broadcast(
        args,
        ("account_witness_proxy", {"account": account, "proxy": ""}),
        role="active",
        account=account,
    )


@arg("other")
@arg("--account")
@command("follow", "follow an account", group="broadcast")
def cmd_follow(args):
    _follow_op(args, ["blog"])


@arg("other")
@arg("--account")
@command("unfollow", "stop following an account", group="broadcast")
def cmd_unfollow(args):
    _follow_op(args, [])


@arg("other")
@arg("--account")
@command("mute", "mute an account", group="broadcast")
def cmd_mute(args):
    _follow_op(args, ["ignore"])


def _follow_op(args, what):
    account = resolve_account(args)
    payload = ["follow", {
        "follower": account,
        "following": args.other.lstrip("@"),
        "what": what,
    }]
    _broadcast(
        args,
        ("custom_json", {
            "id": "follow",
            "json": payload,
            "required_auths": [],
            "required_posting_auths": [account],
        }),
        account=account,
    )


@arg("identifier")
@arg("--account")
@command("reblog", "reblog a post", group="broadcast")
def cmd_reblog(args):
    author, permlink = _split(args.identifier)
    account = resolve_account(args)
    payload = ["reblog", {"account": account, "author": author, "permlink": permlink}]
    _broadcast(
        args,
        ("custom_json", {
            "id": "reblog",
            "json": payload,
            "required_auths": [],
            "required_posting_auths": [account],
        }),
        account=account,
    )


@arg("title")
@arg("body", help="the post body, or - to read stdin")
@arg("--tags", nargs="*", default=[])
@arg("--community")
@arg("--permlink")
@arg("--beneficiary", nargs="*", default=[], metavar="ACCOUNT:PERCENT")
@arg("--account")
@command("post", "publish a post", group="broadcast")
def cmd_post(args):
    account = resolve_account(args)
    body = sys.stdin.read() if args.body == "-" else args.body
    beneficiaries = []
    for entry in args.beneficiary:
        if ":" not in entry:
            die(f"beneficiary {entry!r} must be ACCOUNT:PERCENT")
        name, percent = entry.split(":", 1)
        beneficiaries.append({"account": name.lstrip("@"), "weight": int(float(percent) * 100)})
    keys = signing_keys(args, account=account, role="posting")
    hive = make_hive(args, keys=keys)
    result = hive.post(
        args.title, body, author=account, permlink=args.permlink,
        tags=args.tags, community=args.community,
        beneficiaries=beneficiaries or None,
    )
    broadcast_result(result, args)


@arg("identifier", help="the post to reply to")
@arg("body", help="the reply body, or - to read stdin")
@arg("--account")
@command("reply", "reply to a post", group="broadcast")
def cmd_reply(args):
    account = resolve_account(args)
    body = sys.stdin.read() if args.body == "-" else args.body
    keys = signing_keys(args, account=account, role="posting")
    hive = make_hive(args, keys=keys)
    result = hive.post(
        "", body, author=account, reply_identifier=args.identifier
    )
    broadcast_result(result, args)


@arg("title")
@arg("body", help="the post body, or - to read stdin")
@arg("--tags", nargs="*", default=[])
@arg("--community")
@arg("--permlink")
@arg("--beneficiary", nargs="*", default=[], metavar="ACCOUNT:PERCENT")
@arg("--account")
@command("createpost", "publish a post (alias for `post`)", group="broadcast")
def cmd_createpost(args):
    cmd_post(args)


@arg("--fee", default="0.000 HIVE")
@arg("--account")
@command("claimaccount", "claim an account creation token", group="broadcast")
def cmd_claimaccount(args):
    account = resolve_account(args)
    _broadcast(
        args,
        ("claim_account", {"creator": account, "fee": args.fee, "extensions": []}),
        role="active",
        account=account,
    )


@arg("profile", help="profile fields as JSON, e.g. '{\"name\":\"Alice\"}'")
@arg("--account")
@command("setprofile", "update the account profile", group="broadcast")
def cmd_setprofile(args):
    account = resolve_account(args)
    try:
        profile = json.loads(args.profile)
    except ValueError as exc:
        die(f"profile is not valid JSON: {exc}")
    _broadcast(
        args,
        ("account_update2", {
            "account": account,
            "json_metadata": "",
            "posting_json_metadata": {"profile": profile},
            "extensions": [],
        }),
        account=account,
    )


@arg("--account")
@command("delprofile", "clear the account profile", group="broadcast")
def cmd_delprofile(args):
    account = resolve_account(args)
    _broadcast(
        args,
        ("account_update2", {
            "account": account,
            "json_metadata": "",
            "posting_json_metadata": {"profile": {}},
            "extensions": [],
        }),
        account=account,
    )


@arg("new_recovery_account")
@arg("--account")
@command("changerecovery", "change the recovery account (takes effect after 30 days)",
         group="broadcast")
def cmd_changerecovery(args):
    account = resolve_account(args)
    if not confirm(f"Set @{args.new_recovery_account} as recovery account for @{account}?"):
        die("cancelled", code=0)
    _broadcast(
        args,
        ("change_recovery_account", {
            "account_to_recover": account,
            "new_recovery_account": args.new_recovery_account.lstrip("@"),
            "extensions": [],
        }),
        role="owner",
        account=account,
    )


def _split(identifier):
    text = str(identifier).lstrip("@")
    if "/" not in text:
        die(f"{identifier!r} is not an @author/permlink identifier")
    author, permlink = text.split("/", 1)
    return author, permlink


def _amount(value, asset):
    """Render an amount for an operation, refusing excess precision."""
    from .amount import Amount
    from .exceptions import AssetDoesNotExistsException, InvalidAssetException

    try:
        if isinstance(value, str) and " " in value:
            return str(Amount(value))
        return str(Amount(value, asset))
    except (InvalidAssetException, AssetDoesNotExistsException) as exc:
        die(str(exc))


# ---------------------------------------------------------------------------
# Market
# ---------------------------------------------------------------------------


@command("ticker", "show the internal market ticker", group="market")
def cmd_ticker(args):
    from .market import Market

    ticker = Market(blockchain_instance=make_hive(args)).ticker()
    table(
        ["field", "value"],
        [
            ("latest", f"{ticker['latest']:.6f}"),
            ("highest bid", f"{ticker['highest_bid']:.6f}"),
            ("lowest ask", f"{ticker['lowest_ask']:.6f}"),
            ("24h change", f"{ticker['percent_change']:.2f}%"),
            ("24h HIVE", ticker["hive_volume"]),
            ("24h HBD", ticker["hbd_volume"]),
        ],
    )


@arg("--limit", type=int, default=10)
@command("orderbook", "show the internal market order book", group="market")
def cmd_orderbook(args):
    from .market import Market

    book = Market(blockchain_instance=make_hive(args)).orderbook(limit=args.limit)
    rows = []
    for i in range(max(len(book["bids"]), len(book["asks"]))):
        bid = book["bids"][i] if i < len(book["bids"]) else None
        ask = book["asks"][i] if i < len(book["asks"]) else None
        rows.append(
            (
                f"{bid['price']:.6f}" if bid else "",
                str(bid["hive"]) if bid else "",
                f"{ask['price']:.6f}" if ask else "",
                str(ask["hive"]) if ask else "",
            )
        )
    table(["bid", "bid size", "ask", "ask size"], rows)


@arg("--limit", type=int, default=20)
@command("tradehistory", "show recent trades", group="market")
def cmd_tradehistory(args):
    from .market import Market

    trades = Market(blockchain_instance=make_hive(args)).recent_trades(limit=args.limit)
    table(
        ["when", "paid", "received"],
        [(t.time, str(t.quote), str(t.base)) for t in trades],
    )


@arg("--days", type=int, default=7)
@command("pricehistory", "show the witness price feed history", group="market")
def cmd_pricehistory(args):
    from .price import Price

    feed = rpc_for(args).call("database_api.get_feed_history", {})
    median = Price(feed["current_median_history"])
    out(f"current median  {median}")
    history = feed.get("price_history", [])[-args.days * 24 :]
    if history:
        rates = [float(Price(entry)) for entry in history]
        table(
            ["window", "value"],
            [
                ("points", len(rates)),
                ("min", f"{min(rates):.6f}"),
                ("max", f"{max(rates):.6f}"),
                ("mean", f"{sum(rates) / len(rates):.6f}"),
            ],
        )


@arg("price", type=float, help="HBD per HIVE")
@arg("amount", type=float, help="HIVE to buy")
@arg("--account")
@command("buy", "place a buy order on the internal market", group="market")
def cmd_buy(args):
    _order(args, buying=True)


@arg("price", type=float, help="HBD per HIVE")
@arg("amount", type=float, help="HIVE to sell")
@arg("--account")
@command("sell", "place a sell order on the internal market", group="market")
def cmd_sell(args):
    _order(args, buying=False)


def _order(args, buying):
    from .market import Market

    account = resolve_account(args)
    keys = signing_keys(args, account=account, role="active")
    hive = make_hive(args, keys=keys)
    market = Market(blockchain_instance=hive)
    verb = "Buy" if buying else "Sell"
    if not confirm(f"{verb} {args.amount} HIVE at {args.price} HBD each?"):
        die("cancelled", code=0)
    fn = market.buy if buying else market.sell
    broadcast_result(fn(args.price, args.amount, account=account), args)


@arg("orderids", nargs="+", type=int)
@arg("--account")
@command("cancel", "cancel open orders", group="market")
def cmd_cancel(args):
    account = resolve_account(args)
    for orderid in args.orderids:
        _broadcast(
            args,
            ("limit_order_cancel", {"owner": account, "orderid": orderid}),
            role="active",
            account=account,
        )


@arg("account", nargs="?")
@command("openorders", "show open orders", group="market")
def cmd_openorders(args):
    from .market import Market

    hive = make_hive(args)
    name = (args.account or resolve_account(args)).lstrip("@")
    orders = Market(blockchain_instance=hive).accountopenorders(account=name)
    table(
        ["id", "for sale", "wants", "created"],
        [
            (o.order.get("orderid"), str(o.base), str(o.quote), o.order.get("created"))
            for o in orders
        ],
    )


# ---------------------------------------------------------------------------
# Witnesses
# ---------------------------------------------------------------------------


@arg("name")
@command("witness", "show one witness", group="witness")
def cmd_witness(args):
    from .witness import Witness

    Witness(args.name.lstrip("@"), blockchain_instance=make_hive(args)).print()


@arg("--limit", type=int, default=30)
@command("witnesses", "list witnesses by vote", group="witness")
def cmd_witnesses(args):
    from .witness import Witnesses

    Witnesses(limit=args.limit, blockchain_instance=make_hive(args)).printAsTable()


@arg("base", help="HBD per HIVE, e.g. '0.250 HBD'")
@arg("--quote", default="1.000 HIVE")
@arg("--account")
@command("witnessfeed", "publish a witness price feed", group="witness")
def cmd_witnessfeed(args):
    account = resolve_account(args)
    _broadcast(
        args,
        ("feed_publish", {
            "publisher": account,
            "exchange_rate": {"base": args.base, "quote": args.quote},
        }),
        role="active",
        account=account,
    )


@arg("--account")
@command("witnessdisable", "stop producing blocks", group="witness")
def cmd_witnessdisable(args):
    die(
        "retiring a witness publishes the null signing key through "
        "witness_set_properties, whose values are binary-encoded per property. "
        "This layer does not build them; use hivecomb's WitnessProperty helpers. "
        "See MIGRATION.md."
    )


@arg("--account")
@command("witnessenable", "resume producing blocks", group="witness")
def cmd_witnessenable(args):
    cmd_witnessdisable(args)


@arg("--account")
@command("witnessupdate", "update witness properties", group="witness")
def cmd_witnessupdate(args):
    cmd_witnessdisable(args)


@arg("--account")
@command("witnesscreate", "register as a witness", group="witness")
def cmd_witnesscreate(args):
    cmd_witnessdisable(args)


@arg("--account")
@command("witnessproperties", "show a witness's published properties", group="witness")
def cmd_witnessproperties(args):
    from .witness import Witness

    name = (args.account or resolve_account(args)).lstrip("@")
    witness = Witness(name, blockchain_instance=make_hive(args))
    emit_json(witness.get("props", {}))


# ---------------------------------------------------------------------------
# Crypto and transactions
# ---------------------------------------------------------------------------


@arg("message", nargs="?", help="the message to sign; read from stdin if omitted")
@arg("--account")
@command("message", "sign a message with an account's posting key", group="crypto")
def cmd_message(args):
    account = resolve_account(args)
    text = args.message if args.message is not None else sys.stdin.read()
    keys = signing_keys(args, account=account, role="posting")
    out(hivecomb.sign_message(text, keys[0]))


@arg("message")
@arg("signature", help="the 130-character hex signature")
@arg("--pubkey", help="require this key; otherwise the signer is printed")
@command("verify", "verify a signed message", group="crypto")
def cmd_verify(args):
    try:
        signer = hivecomb.recover_message(args.message, args.signature)
    except ValueError as exc:
        die(f"signature is not usable: {exc}")
    if args.pubkey:
        if str(signer) != args.pubkey:
            die(f"signed by {signer}, not {args.pubkey}")
        out("ok")
    else:
        out(str(signer))
        out("\nNote: recovery answers 'which key made this?'. A tampered signature")
        out("recovers a different key rather than failing, so compare against the")
        out("key you expected -- pass --pubkey to have that checked here.")


@arg("to", help="recipient account or memo public key")
@arg("message")
@arg("--account")
@command("encrypt", "encrypt a memo to an account", group="crypto")
def cmd_encrypt(args):
    from .account import Account

    account = resolve_account(args)
    hive = make_hive(args)
    if args.to.startswith(("STM", "TST", "STX")):
        recipient = args.to
    else:
        recipient = Account(args.to.lstrip("@"), blockchain_instance=hive)["memo_key"]
    keys = signing_keys(args, account=account, role="memo")
    out(hivecomb.encode_memo(keys[0], recipient, args.message))


@arg("memo", help="the #-prefixed memo")
@arg("--account")
@command("decrypt", "decrypt a memo", group="crypto")
def cmd_decrypt(args):
    account = resolve_account(args, required=False)
    keys = signing_keys(args, account=account, role="memo")
    try:
        out(hivecomb.decode_memo(keys[0], args.memo))
    except ValueError as exc:
        die(str(exc))


@arg("file", nargs="?", help="a JSON transaction; read from stdin if omitted")
@arg("--account")
@command("sign", "sign a transaction from JSON", group="crypto")
def cmd_sign(args):
    raw = Path(args.file).read_text() if args.file else sys.stdin.read()
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        die(f"not valid JSON: {exc}")
    ops = payload.get("operations")
    if not ops:
        die("the transaction has no operations")
    account = resolve_account(args, required=False)
    keys = signing_keys(args, account=account, role="active")
    hive = make_hive(args, keys=keys, nobroadcast=True)
    emit_json(hive.finalizeOp([(op[0], op[1]) for op in ops], account=account))


@arg("file", nargs="?", help="a signed JSON transaction; read from stdin if omitted")
@command("broadcast", "broadcast a signed transaction", group="crypto")
def cmd_broadcast(args):
    raw = Path(args.file).read_text() if args.file else sys.stdin.read()
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        die(f"not valid JSON: {exc}")
    payload.pop("trx_id", None)
    rpc_for(args).call("network_broadcast_api.broadcast_transaction", {"trx": payload})
    out("broadcast")


@arg("hex_or_file", help="hex-encoded transaction, or a file containing one")
@command("decodetx", "decode a hex transaction to JSON", group="crypto", new=True)
def cmd_decodetx(args):
    """Not in beem's CLI: its deserializer was a separate module that shared no
    code with its serializer, and was never wired to the command line."""
    value = args.hex_or_file
    path = Path(value)
    if path.exists():
        value = path.read_text().strip()
    emit_json(rpc_for(args).call("condenser_api.get_transaction", [value]))


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


@arg("--ops", nargs="*", default=[], help="only these operation types")
@arg("--start", type=int, help="start at this block; defaults to the head")
@arg("--stop", type=int)
@arg("--json", dest="as_json", action="store_true")
@command("stream", "stream operations as blocks arrive", group="stream")
def cmd_stream(args):
    from .blockchain import Blockchain

    chain = Blockchain(blockchain_instance=make_hive(args))
    try:
        for operation in chain.stream(opNames=args.ops or None, start=args.start,
                                      stop=args.stop):
            if args.as_json:
                emit_json(operation)
            else:
                out(f"{operation['block_num']}  {operation['type']:<26}  {_summarise(operation)}")
    except KeyboardInterrupt:
        out("\nstopped")


@arg("--ops", nargs="*", default=[])
@arg("--start", type=int)
@arg("--stop", type=int)
@command("virtualops", "stream virtual operations, which beem cannot name correctly",
         group="stream", new=True)
def cmd_virtualops(args):
    """Not in beem's CLI. beem's operation table reports every virtual id two
    lower than the chain's, so it cannot filter on them reliably."""
    from beembase.operationids import FIRST_VIRTUAL_OP, ops as OP_NAMES
    from .blockchain import Blockchain

    virtual = set(OP_NAMES[FIRST_VIRTUAL_OP:])
    unknown = set(args.ops) - virtual
    if unknown:
        die(f"{sorted(unknown)} are not virtual operations; known: {sorted(virtual)}")
    chain = Blockchain(blockchain_instance=make_hive(args))
    try:
        for operation in chain.virtual_ops(
            start=args.start, stop=args.stop, opNames=args.ops or None
        ):
            out(f"{operation['block_num']}  {operation['type']:<40}  {_summarise(operation)}")
    except KeyboardInterrupt:
        out("\nstopped")


@arg("account")
@arg("keys", nargs="+", metavar="PUBKEY", help="public keys to test")
@arg("--role", default="posting", choices=["owner", "active", "posting", "memo"])
@command("verifyauthority", "check whether keys satisfy an account's authority",
         group="account", new=True)
def cmd_verifyauthority(args):
    """Not a beem command. beem's library asked the *node* to verify a whole
    transaction, which needs a round trip and says nothing about why."""
    from .account import Account

    hive = make_hive(args)
    account = Account(args.account.lstrip("@"), blockchain_instance=hive)
    report = account.verify_account_authority(args.keys, role=args.role)

    table(
        ["property", "value"],
        [
            ("account", f"@{account.name}"),
            ("role", args.role),
            ("satisfied", "yes" if report["satisfied"] else "no"),
            ("weight", f"{report['weight']} of {report['threshold']} needed"),
            ("shortfall", report["shortfall"]),
            ("matched keys", len(report["matched_keys"])),
        ],
    )
    if report["matched_keys"]:
        out("\nmatched:")
        for key in report["matched_keys"]:
            out(f"  {key}")
    if not report["conclusive"]:
        out("\nINCONCLUSIVE — this authority also delegates to other accounts,")
        out("whose own authorities were not fetched. 'no' here means 'not from")
        out("these keys alone', not 'no'.")
        table(["delegated to", "weight"], report["unresolved_accounts"])


@arg("block", type=int)
@arg("--virtual", action="store_true", help="only operations the chain emitted")
@arg("--json", dest="as_json", action="store_true")
@command("opsinblock", "show every operation recorded for a block", group="stream", new=True)
def cmd_opsinblock(args):
    """Not a beem command. This is the only way to reach virtual operations:
    they are emitted by consensus, not carried in a transaction, so they are not
    in `block_api.get_block` at all."""
    from .blockchain import Blockchain

    chain = Blockchain(blockchain_instance=make_hive(args))
    operations = chain.get_ops_in_block(args.block, only_virtual=args.virtual)
    if args.as_json:
        emit_json(operations)
        return
    if not operations:
        out(f"block {args.block} has no {'virtual ' if args.virtual else ''}operations")
        return
    table(
        ["kind", "type", "detail"],
        [
            ("virtual" if op.get("virtual_op") else "signed", op["type"], _summarise(op))
            for op in operations
        ],
    )


@arg("--new", action="store_true", help="only commands beem does not have")
@command("commands", "list every command", group="general", new=True)
def cmd_commands(args):
    rows = [
        (name, spec["group"], "new" if spec["new"] else "", spec["help"])
        for name, spec in sorted(COMMANDS.items())
        if spec["new"] or not args.new
    ]
    table(["command", "group", "", "description"], rows)
    if args.new:
        out("\nThese have no beem equivalent. See MIGRATION.md for why.")


# ---------------------------------------------------------------------------
# Commands beem had that this layer does not provide
# ---------------------------------------------------------------------------


def _unavailable(what, reason):
    def handler(args):
        die(f"{what} is not available: {reason} See MIGRATION.md.")

    return handler


for _name, _reason in [
    ("uploadimage", "it posted to a third-party image host, which is not this library's job."),
    ("download", "it fetched post bodies for offline editing, which the API does directly."),
    ("draw", "it drew ASCII charts; pipe `beempy pricehistory --json` into a plotting tool."),
    ("importaccount", "importing from a master password derives keys that a wallet should "
                      "not hold; use `beempy passwordgen` and `beempy addkey` deliberately."),
    ("newaccount", "account creation needs a claimed token and four authorities; build it "
                   "with Hive.create_claimed_account so the keys are explicit."),
    ("changekeys", "changing authorities is owner-level and irreversible; build it with "
                   "beembase.operations.Account_update2 so every field is visible."),
    ("updatememokey", "same reason as changekeys."),
    ("allow", "authority changes are owner-level; build them explicitly."),
    ("disallow", "authority changes are owner-level; build them explicitly."),
    ("beneficiaries", "set them when posting, with `beempy post --beneficiary`."),
]:
    COMMANDS[_name] = {
        "fn": _unavailable(_name, _reason),
        "help": f"(not available) {_reason.split(';')[0]}",
        "group": "unavailable",
        "new": False,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        prog="beempy",
        description="Command line interface for Hive, backed by hivecomb.",
        epilog="`beempy commands` lists everything; `beempy commands --new` lists "
               "what hivecomb adds over beem.",
    )
    parser.add_argument("--node", action="append", help="node URL; repeat for several")
    parser.add_argument("--key", action="append", help="signing WIF; repeat for several")
    parser.add_argument("--account", help="the account to act as")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and sign, but do not broadcast")
    parser.add_argument("--race", type=int, default=1, metavar="N",
                        help="broadcast to N nodes at once and take the first "
                             "acceptance; a sick node then costs one timeout "
                             "instead of delaying the whole failover chain")
    parser.add_argument("--version", action="store_true", help="print the version and exit")

    # Flags the top-level parser owns. A subcommand that declares one of these
    # must not reset it: argparse applies subparser defaults over the namespace
    # the parent already filled, so `beempy --account alice transfer ...` would
    # silently lose the account. SUPPRESS makes the subcommand's copy set the
    # value only when it is actually given.
    global_dests = {action.dest for action in parser._actions}

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name, spec in sorted(COMMANDS.items()):
        sub = subparsers.add_parser(name, help=spec["help"], description=spec["fn"].__doc__)
        for names, kwargs in getattr(spec["fn"], "_args", []):
            kwargs = dict(kwargs)
            dest = kwargs.get("dest") or names[0].lstrip("-").replace("-", "_")
            if dest in global_dests and "default" not in kwargs:
                kwargs["default"] = argparse.SUPPRESS
            sub.add_argument(*names, **kwargs)
        sub.set_defaults(_handler=spec["fn"])
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        from . import __version__

        out(__version__)
        return 0
    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    try:
        args._handler(args)
    except SystemExit:
        raise
    except RPCError as exc:
        die(str(exc))
    except KeyboardInterrupt:
        out("\ninterrupted")
        return 130
    except NotImplementedError as exc:
        die(str(exc))
    except Exception as exc:  # noqa: BLE001 - the CLI is the boundary
        die(f"{type(exc).__name__}: {exc}")
    return 0


def cli(argv=None):
    """The console-script entry point, named as beem's was."""
    raise SystemExit(main(argv))


if __name__ == "__main__":
    cli()
