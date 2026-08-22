#!/usr/bin/env python3
"""Broadcast one real transaction to Hive and confirm the chain kept it.

This is the last thing hivecomb cannot prove offline: that a *signature* over
the digest is accepted. Serialization is already proven for free against hived
itself (tests/hived_serialization_oracle.py); this proves the other half.

It broadcasts a `custom_json` under **posting** authority with an id no
application consumes. That is deliberate:

  - posting authority cannot move funds, so the key you use here risks nothing
    of value even if it leaks;
  - `custom_json` costs no HIVE, only resource credits, so the account needs no
    balance at all;
  - the id is inert, so nothing downstream acts on it.

It signs, broadcasts, waits for the transaction to appear in a block, and then
checks that the transaction id the chain filed it under is the one hivecomb
computed locally. That last step is what makes this a proof rather than a
smoke test — a matching trx_id means the node's bytes were hivecomb's bytes.

    HIVE_ACCOUNT=someaccount HIVE_POSTING_WIF=5... \
        PYTHONPATH=<dir with hivecomb.so> python3 tests/hived_broadcast_check.py

Pass --dry-run to build and sign without broadcasting, and to have a node
verify the signature via `database_api.verify_authority` — which checks the
signature without writing anything to the chain.
"""

import json
import os
import sys
import time
import urllib.request

try:
    import hivecomb
except ImportError:
    sys.exit("hivecomb is not importable; build it first")

NODES = [
    "https://api.hive.blog",
    "https://api.deathwing.me",
    "https://api.openhive.network",
]
TIMEOUT = 30
CUSTOM_JSON_ID = "hivecomb_validation"
CONFIRM_ATTEMPTS = 20
CONFIRM_INTERVAL = 3


def call(method, params, node=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    failures = []
    for candidate in [node] if node else NODES:
        try:
            request = urllib.request.Request(
                candidate, data=body.encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": "hivecomb-broadcast-check"},
            )
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                payload = json.load(response)
        except Exception as exc:  # noqa: BLE001 - collected and reported
            failures.append(f"{candidate}: {exc}")
            continue
        if payload.get("error"):
            message = payload["error"]
            raise RuntimeError(message.get("message", json.dumps(message)))
        return payload["result"]
    raise RuntimeError("no node answered: " + "; ".join(failures))


def main():
    dry_run = "--dry-run" in sys.argv

    account = os.environ.get("HIVE_ACCOUNT")
    wif = os.environ.get("HIVE_POSTING_WIF")
    if not account or not wif:
        sys.exit("set HIVE_ACCOUNT and HIVE_POSTING_WIF in the environment "
                 "(a POSTING key — never an active or owner key)")

    # Refuse to run with a key that cannot be the posting key, so a
    # copy-pasted active key does not get used by accident.
    derived = str(hivecomb.PrivateKey(wif).public_key())
    posting = call("condenser_api.get_accounts", [[account]])
    if not posting:
        sys.exit(f"account @{account} does not exist")
    posting_keys = [k for k, _ in posting[0]["posting"]["key_auths"]]
    active_keys = [k for k, _ in posting[0]["active"]["key_auths"]]
    owner_keys = [k for k, _ in posting[0]["owner"]["key_auths"]]
    if derived in owner_keys or derived in active_keys:
        sys.exit(f"{derived} is @{account}'s OWNER or ACTIVE key. Refusing. "
                 "This check needs the posting key only.")
    if derived not in posting_keys:
        sys.exit(f"{derived} is not in @{account}'s posting authority "
                 f"(expected one of {posting_keys})")
    print(f"key {derived} is @{account}'s posting key\n")

    # TaPoS from the head block, and an expiration inside the chain's window.
    props = call("condenser_api.get_dynamic_global_properties", [])
    ref = hivecomb.BlockRef.from_block_id(props["head_block_id"])
    print(f"head block {props['head_block_number']} ({props['head_block_id']})")

    payload = json.dumps({"hivecomb": hivecomb.__version__ if hasattr(
        hivecomb, "__version__") else "0.1.0", "purpose": "wire format validation"},
        separators=(",", ":"))
    ops = [("custom_json", {
        "required_auths": [],
        "required_posting_auths": [account],
        "id": CUSTOM_JSON_ID,
        "json": payload,
    })]

    tx = hivecomb.sign_transaction(ops, ref, [wif])
    local_trx_id = tx["trx_id"]
    envelope = {k: v for k, v in tx.items() if k != "trx_id"}
    print(f"signed locally, trx_id {local_trx_id}")

    # A node's own view of the bytes, as a cross-check before anything is sent.
    node_hex = call("condenser_api.get_transaction_hex", [envelope])
    print(f"node serialized it to {len(node_hex) // 2} bytes")

    verified = call("database_api.verify_authority", {"trx": envelope})
    print(f"database_api.verify_authority -> {verified['valid']}")
    if not verified["valid"]:
        sys.exit("the node rejected the signature; nothing was broadcast")

    if dry_run:
        print("\n--dry-run: the node verified the signature and nothing was sent.")
        print("The signature is valid against the chain's own authority check.")
        return 0

    print("\nbroadcasting...")
    call("condenser_api.broadcast_transaction", [envelope])
    print("accepted into the mempool")

    # Accepted is not the same as included. Wait for a block to carry it.
    for attempt in range(CONFIRM_ATTEMPTS):
        time.sleep(CONFIRM_INTERVAL)
        try:
            found = call("condenser_api.get_transaction", [local_trx_id])
        except RuntimeError:
            print(f"  not in a block yet ({(attempt + 1) * CONFIRM_INTERVAL}s)")
            continue
        print(f"\nincluded in block {found['block_num']}")
        print(f"chain filed it under trx_id {found['transaction_id']}")
        if found["transaction_id"] != local_trx_id:
            print(f"*** MISMATCH: hivecomb computed {local_trx_id}")
            return 1
        print("\nThe chain's transaction id equals the one hivecomb computed "
              "offline.\nSerialization, digest, signature and broadcast are "
              "proven end to end.")
        return 0

    print(f"\nNot included after {CONFIRM_ATTEMPTS * CONFIRM_INTERVAL}s. It was "
          "accepted into the mempool, so the signature was valid; check "
          f"https://hivehub.dev/tx/{local_trx_id}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
