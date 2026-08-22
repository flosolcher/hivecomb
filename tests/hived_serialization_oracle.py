#!/usr/bin/env python3
"""Verify hivecomb's serialization against **hived itself**, for free.

`condenser_api.get_transaction_hex` makes a node serialize a transaction and hand
back the bytes. That is the authority — not beem, not a fixture, not this
project's own expectations — and it costs nothing: no account, no keys with
value, no broadcast, nothing written to the chain.

For each operation we build it, ask a node to serialize it, and check that
`sha256(chain_id || hived's bytes)` equals the digest hivecomb computed
independently. If those agree, hivecomb's wire format *is* hived's, because a
single differing byte anywhere changes the hash.

What this does **not** prove is that a signature over that digest is accepted —
that needs one real broadcast. See BROADCAST.md.

    PYTHONPATH=<dir with hivecomb.so> python3 tests/hived_serialization_oracle.py
"""

import hashlib
import json
import sys
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
TIMEOUT = 25

# Published on purpose, used by no Hive account, must never hold value.
WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
PUBKEY = "STM6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
BLOCK_ID = "00000005aabbccdd00000000000000000000abcd"
SIGNATURE_LEN = 65

CHAIN_ID = bytes.fromhex(hivecomb.chain_id())
REF = hivecomb.BlockRef.from_block_id(BLOCK_ID)


def call(method, params):
    """Call the first node that answers."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    failures = []
    for node in NODES:
        try:
            request = urllib.request.Request(
                node, data=body.encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": "hivecomb-serialization-oracle"},
            )
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                payload = json.load(response)
        except Exception as exc:  # noqa: BLE001 - collected and reported
            failures.append(f"{node}: {exc}")
            continue
        if payload.get("error"):
            raise RuntimeError(payload["error"].get("message", payload["error"]))
        return payload["result"]
    raise RuntimeError("; ".join(failures))


def authority(key=PUBKEY):
    return {"weight_threshold": 1, "account_auths": [], "key_auths": [[key, 1]]}


def cases():
    """One of every operation hivecomb can build, with awkward values where they matter."""
    return [
        ("vote", {"voter": "alice", "author": "bob", "permlink": "a-post", "weight": 10000}),
        ("vote (downvote, negative int16)",
         {"voter": "alice", "author": "bob", "permlink": "p", "weight": -10000},
         "vote"),
        ("comment", {"parent_author": "", "parent_permlink": "hive-100",
                     "author": "alice", "permlink": "p", "title": "T",
                     "body": "B", "json_metadata": "{}"}),
        ("comment (unicode body)",
         {"parent_author": "", "parent_permlink": "t", "author": "a", "permlink": "p",
          "title": "unicode é 中文 🐝", "body": "🐝" * 50, "json_metadata": "{}"},
         "comment"),
        ("comment (control characters)",
         {"parent_author": "", "parent_permlink": "t", "author": "a", "permlink": "p",
          "title": "", "body": "xy", "json_metadata": "{}"},
         "comment"),
        ("transfer", {"from": "alice", "to": "bob", "amount": "1.234 HIVE", "memo": "hi"}),
        ("transfer (HBD)", {"from": "a", "to": "b", "amount": "2.500 HBD", "memo": ""},
         "transfer"),
        ("transfer (large, past 2**53 units)",
         {"from": "a", "to": "b", "amount": "9007199254740.993 HIVE", "memo": ""},
         "transfer"),
        ("transfer_to_vesting", {"from": "a", "to": "b", "amount": "1.000 HIVE"}),
        ("withdraw_vesting", {"account": "a", "vesting_shares": "1.000000 VESTS"}),
        ("withdraw_vesting (large VESTS)",
         {"account": "a", "vesting_shares": "123456789012.345678 VESTS"},
         "withdraw_vesting"),
        ("limit_order_create",
         {"owner": "a", "orderid": 1, "amount_to_sell": "1.000 HIVE",
          "min_to_receive": "1.000 HBD", "fill_or_kill": False,
          "expiration": "2026-08-22T14:30:00"}),
        ("limit_order_cancel", {"owner": "a", "orderid": 1}),
        ("feed_publish", {"publisher": "a",
                          "exchange_rate": {"base": "0.250 HBD", "quote": "1.000 HIVE"}}),
        ("convert", {"owner": "a", "requestid": 1, "amount": "1.000 HBD"}),
        ("account_create",
         {"fee": "3.000 HIVE", "creator": "a", "new_account_name": "b",
          "owner": authority(), "active": authority(), "posting": authority(),
          "memo_key": PUBKEY, "json_metadata": "{}"}),
        ("account_update",
         {"account": "a", "owner": None, "active": authority(), "posting": None,
          "memo_key": PUBKEY, "json_metadata": "{}"}),
        ("witness_update",
         {"owner": "a", "url": "https://example.org", "block_signing_key": PUBKEY,
          "props": {"account_creation_fee": "3.000 HIVE", "maximum_block_size": 65536,
                    "hbd_interest_rate": 1000},
          "fee": "0.000 HIVE"}),
        ("account_witness_vote", {"account": "a", "witness": "w", "approve": True}),
        ("account_witness_proxy", {"account": "a", "proxy": "p"}),
        ("custom", {"required_auths": ["a"], "id": 1, "data": "deadbeef"}),
        ("witness_block_approve",
         {"witness": "a", "block_id": "00000005aabbccdd00000000000000000000abcd"}),
        ("delete_comment", {"author": "a", "permlink": "p"}),
        ("custom_json", {"required_auths": [], "required_posting_auths": ["alice"],
                         "id": "my_app", "json": '{"a":1}'}),
        ("custom_json (multiple auths, unsorted input)",
         {"required_auths": [], "required_posting_auths": ["zulu", "alpha", "mike"],
          "id": "x", "json": "{}"},
         "custom_json"),
        ("comment_options",
         {"author": "a", "permlink": "p", "max_accepted_payout": "1000000.000 HBD",
          "percent_hbd": 10000, "allow_votes": True, "allow_curation_rewards": True,
          "extensions": []}),
        ("comment_options (beneficiaries)",
         {"author": "a", "permlink": "p", "max_accepted_payout": "1000000.000 HBD",
          "percent_hbd": 10000, "allow_votes": True, "allow_curation_rewards": True,
          "extensions": [[0, {"beneficiaries": [{"account": "b", "weight": 500}]}]]},
         "comment_options"),
        ("set_withdraw_vesting_route",
         {"from_account": "a", "to_account": "b", "percent": 10000, "auto_vest": False}),
        ("limit_order_create2",
         {"owner": "a", "orderid": 1, "amount_to_sell": "1.000 HIVE",
          "fill_or_kill": False,
          "exchange_rate": {"base": "1.000 HIVE", "quote": "1.000 HBD"},
          "expiration": "2026-08-22T14:30:00"}),
        ("claim_account", {"creator": "a", "fee": "0.000 HIVE", "extensions": []}),
        ("create_claimed_account",
         {"creator": "a", "new_account_name": "b", "owner": authority(),
          "active": authority(), "posting": authority(), "memo_key": PUBKEY,
          "json_metadata": "{}", "extensions": []}),
        ("request_account_recovery",
         {"recovery_account": "a", "account_to_recover": "b",
          "new_owner_authority": authority(), "extensions": []}),
        ("recover_account",
         {"account_to_recover": "a", "new_owner_authority": authority(),
          "recent_owner_authority": authority(), "extensions": []}),
        ("change_recovery_account",
         {"account_to_recover": "a", "new_recovery_account": "b", "extensions": []}),
        ("escrow_transfer",
         {"from": "a", "to": "b", "agent": "c", "escrow_id": 1,
          "hbd_amount": "1.000 HBD", "hive_amount": "2.000 HIVE", "fee": "0.100 HIVE",
          "ratification_deadline": "2026-08-22T14:30:00",
          "escrow_expiration": "2026-08-23T14:30:00", "json_meta": "{}"}),
        ("escrow_dispute", {"from": "a", "to": "b", "agent": "c", "who": "a",
                            "escrow_id": 1}),
        ("escrow_release",
         {"from": "a", "to": "b", "agent": "c", "who": "a", "receiver": "b",
          "escrow_id": 1, "hbd_amount": "1.000 HBD", "hive_amount": "2.000 HIVE"}),
        ("escrow_approve", {"from": "a", "to": "b", "agent": "c", "who": "c",
                            "escrow_id": 1, "approve": True}),
        ("transfer_to_savings", {"from": "a", "to": "b", "amount": "1.000 HIVE",
                                 "memo": ""}),
        ("transfer_from_savings", {"from": "a", "request_id": 1, "to": "b",
                                   "amount": "1.000 HIVE", "memo": ""}),
        ("cancel_transfer_from_savings", {"from": "a", "request_id": 1}),
        ("custom_binary",
         {"required_owner_auths": [], "required_active_auths": ["a"],
          "required_posting_auths": [], "required_auths": [], "id": "app",
          "data": "dead"}),
        ("decline_voting_rights", {"account": "a", "decline": True}),
        ("reset_account", {"reset_account": "a", "account_to_reset": "b",
                           "new_owner_authority": authority()}),
        ("set_reset_account", {"account": "a", "current_reset_account": "b",
                               "reset_account": "c"}),
        ("claim_reward_balance",
         {"account": "a", "reward_hive": "1.000 HIVE", "reward_hbd": "2.000 HBD",
          "reward_vests": "3.000000 VESTS"}),
        ("delegate_vesting_shares",
         {"delegator": "a", "delegatee": "b", "vesting_shares": "1.000000 VESTS"}),
        ("account_create_with_delegation",
         {"fee": "3.000 HIVE", "delegation": "0.000000 VESTS", "creator": "a",
          "new_account_name": "b", "owner": authority(), "active": authority(),
          "posting": authority(), "memo_key": PUBKEY, "json_metadata": "{}",
          "extensions": []}),
        ("witness_set_properties",
         {"owner": "a",
          "props": [["account_creation_fee", "b80b00000000000003535445454d0000"],
                    ["maximum_block_size", "00000100"]],
          "extensions": []}),
        ("account_update2",
         {"account": "a", "owner": None, "active": None, "posting": None,
          "memo_key": None, "json_metadata": "{}", "posting_json_metadata": "{}",
          "extensions": []}),
        ("create_proposal",
         {"creator": "a", "receiver": "b", "start_date": "2026-08-22T14:30:00",
          "end_date": "2026-09-22T14:30:00", "daily_pay": "10.000 HBD",
          "subject": "s", "permlink": "p", "extensions": []}),
        ("update_proposal_votes",
         {"voter": "a", "proposal_ids": [1, 2, 3], "approve": True, "extensions": []}),
        ("remove_proposal",
         {"proposal_owner": "a", "proposal_ids": [1], "extensions": []}),
        ("update_proposal",
         {"proposal_id": 1, "creator": "a", "daily_pay": "10.000 HBD", "subject": "s",
          "permlink": "p", "extensions": []}),
        ("collateralized_convert", {"owner": "a", "requestid": 1,
                                    "amount": "1.000 HIVE"}),
        ("recurrent_transfer",
         {"from": "a", "to": "b", "amount": "1.000 HIVE", "memo": "rent",
          "recurrence": 24, "executions": 12, "extensions": []}),
        ("recurrent_transfer (HF28 pair_id)",
         {"from": "a", "to": "b", "amount": "1.000 HIVE", "memo": "",
          "recurrence": 24, "executions": 12,
          "extensions": [[1, {"pair_id": 7}]]},
         "recurrent_transfer"),
    ]


def main():
    print(f"chain id {hivecomb.chain_id()}")
    print(f"asking {NODES[0]} to serialize each operation\n")

    ok = mismatch = errored = 0
    problems = []

    for case in cases():
        label, fields = case[0], case[1]
        op_name = case[2] if len(case) > 2 else label

        try:
            tx = hivecomb.sign_transaction([(op_name, fields)], REF, [WIF])
            payload = {k: v for k, v in tx.items() if k != "trx_id"}
            full = bytes.fromhex(call("condenser_api.get_transaction_hex", [payload]))
            # body || varint(signature count) || signatures. One signature here, and
            # a count below 128 is a single varint byte.
            body = full[: -(1 + SIGNATURE_LEN)]
            theirs = hashlib.sha256(CHAIN_ID + body).hexdigest()
            ours = hivecomb.transaction_digest(
                [(op_name, fields)], REF, tx["expiration"]
            ).hex()
        except Exception as exc:  # noqa: BLE001 - reported per case
            errored += 1
            problems.append(f"{label}: {type(exc).__name__}: {exc}")
            print(f"  ERR   {label}")
            continue

        if theirs == ours:
            ok += 1
            print(f"  ok    {label}")
        else:
            mismatch += 1
            problems.append(f"{label}\n      hived    {theirs}\n      hivecomb {ours}")
            print(f"  DIFFER {label}")

    total = ok + mismatch + errored
    print(f"\n{total} cases: {ok} identical, {mismatch} differ, {errored} errored")
    if problems:
        print("\nProblems:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("\nhivecomb's wire format is hived's, byte for byte.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
