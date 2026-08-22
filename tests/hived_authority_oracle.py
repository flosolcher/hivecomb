#!/usr/bin/env python3
"""Ask hived which authority each operation requires, and check we agree.

Signing is authority-blind: the digest, the curve and the signature format are
identical whether a posting, active or owner key is used. So a broadcast under
one authority proves the signing path for all of them, and there is no reason
to put an active key on disk to test the active path.

What *is* authority-specific is the library's choice of which key to sign with.
`beempy transfer` has to reach for the active key and `beempy vote` for the
posting key, and getting that wrong produces a transaction the chain rejects --
or worse, prompts a user for a more privileged key than the operation needs.

`database_api.get_potential_signatures` answers this without a private key: give
it an unsigned transaction and it returns the public keys that could sign it.
Matching those against the account's own key_auths says which authority hived
wants. That is the authority on the question, and it costs nothing.

    PYTHONPATH=<dir with hivecomb.so> python3 tests/hived_authority_oracle.py

The account is only read, never signed for. It needs no balance and no keys on
this machine.
"""

import json
import os
import sys
import urllib.request

try:
    import hivecomb
except ImportError:
    sys.exit("hivecomb is not importable; build it first")

NODES = [
    "https://api.hive.blog",
    "https://api.openhive.network",
    "https://api.deathwing.me",
]
TIMEOUT = 30
ACCOUNT = os.environ.get("HIVE_ACCOUNT", "noc-dev")

# Published on purpose, used by no Hive account. Only shapes the envelope; the
# signature is stripped before the transaction is sent.
THROWAWAY_WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"

# What the beem-compatible layer signs each operation with. Kept here rather than
# imported so that a change in one is not silently mirrored by the other.
OUR_CHOICE = {
    "vote": "posting",
    "comment": "posting",
    "delete_comment": "posting",
    "comment_options": "posting",
    "custom_json/posting": "posting",
    "claim_reward_balance": "posting",
    "transfer": "active",
    "custom_json/active": "active",
    "transfer_to_vesting": "active",
    "withdraw_vesting": "active",
    "delegate_vesting_shares": "active",
    "recurrent_transfer": "active",
    "account_witness_vote": "active",
    "account_witness_proxy": "active",
    "limit_order_create": "active",
    "limit_order_cancel": "active",
    "convert": "active",
    "collateralized_convert": "active",
    "transfer_to_savings": "active",
    "transfer_from_savings": "active",
    "claim_account": "active",
    "create_proposal": "active",
    "update_proposal_votes": "active",
    "remove_proposal": "active",
    "decline_voting_rights": "owner",
    "change_recovery_account": "owner",
}


# `database_api` speaks NAI assets ({"amount","precision","nai"}); `condenser_api`
# speaks the legacy "1.000 HIVE" string. hivecomb emits the legacy form because that
# is what beem and the CLI use, so it has to be converted for this one API.
NAI = {"HIVE": ("@@000000021", 3), "HBD": ("@@000000013", 3),
       "VESTS": ("@@000000037", 6), "STEEM": ("@@000000021", 3),
       "SBD": ("@@000000013", 3)}


def to_nai(value):
    """Rewrite legacy asset strings to NAI objects, recursively."""
    if isinstance(value, str):
        parts = value.split()
        if len(parts) == 2 and parts[1] in NAI and parts[0].replace(".", "").isdigit():
            nai, precision = NAI[parts[1]]
            units = int(parts[0].replace(".", ""))
            # Guard against a symbol whose precision does not match the text.
            decimals = len(parts[0].split(".")[1]) if "." in parts[0] else 0
            if decimals != precision:
                units = int(round(float(parts[0]) * 10 ** precision))
            return {"amount": str(units), "precision": precision, "nai": nai}
        return value
    if isinstance(value, dict):
        return {k: to_nai(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_nai(v) for v in value]
    return value


def call(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    failures = []
    for node in NODES:
        try:
            request = urllib.request.Request(
                node, data=body.encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": "hivecomb-authority-oracle"},
            )
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                payload = json.load(response)
        except Exception as exc:  # noqa: BLE001 - retried across nodes
            failures.append(f"{node}: {exc}")
            continue
        if payload.get("error"):
            raise RuntimeError(payload["error"].get("message", "?"))
        return payload["result"]
    raise RuntimeError("no node answered: " + "; ".join(failures))


def cases(account):
    """One transaction per operation, shaped so `account` is the one authorizing."""
    zero_vests = "0.000000 VESTS"
    return {
        "vote": ("vote", {"voter": account, "author": "a", "permlink": "p",
                          "weight": 1}),
        "comment": ("comment", {"parent_author": "", "parent_permlink": "t",
                                "author": account, "permlink": "p", "title": "",
                                "body": "b", "json_metadata": "{}"}),
        "delete_comment": ("delete_comment", {"author": account, "permlink": "p"}),
        "comment_options": ("comment_options", {
            "author": account, "permlink": "p",
            "max_accepted_payout": "1000000.000 HBD", "percent_hbd": 10000,
            "allow_votes": True, "allow_curation_rewards": True, "extensions": []}),
        "custom_json/posting": ("custom_json", {
            "required_auths": [], "required_posting_auths": [account],
            "id": "x", "json": "{}"}),
        "claim_reward_balance": ("claim_reward_balance", {
            "account": account, "reward_hive": "0.000 HIVE",
            "reward_hbd": "0.000 HBD", "reward_vests": zero_vests}),
        "transfer": ("transfer", {"from": account, "to": "a",
                                  "amount": "0.001 HIVE", "memo": ""}),
        "custom_json/active": ("custom_json", {
            "required_auths": [account], "required_posting_auths": [],
            "id": "x", "json": "{}"}),
        "transfer_to_vesting": ("transfer_to_vesting", {
            "from": account, "to": "a", "amount": "0.001 HIVE"}),
        "withdraw_vesting": ("withdraw_vesting", {
            "account": account, "vesting_shares": zero_vests}),
        "delegate_vesting_shares": ("delegate_vesting_shares", {
            "delegator": account, "delegatee": "a", "vesting_shares": zero_vests}),
        "recurrent_transfer": ("recurrent_transfer", {
            "from": account, "to": "a", "amount": "0.001 HIVE", "memo": "",
            "recurrence": 24, "executions": 2, "extensions": []}),
        "account_witness_vote": ("account_witness_vote", {
            "account": account, "witness": "a", "approve": True}),
        "account_witness_proxy": ("account_witness_proxy", {
            "account": account, "proxy": "a"}),
        "limit_order_create": ("limit_order_create", {
            "owner": account, "orderid": 1, "amount_to_sell": "0.001 HIVE",
            "min_to_receive": "0.001 HBD", "fill_or_kill": False,
            "expiration": "2030-01-01T00:00:00"}),
        "limit_order_cancel": ("limit_order_cancel", {"owner": account,
                                                      "orderid": 1}),
        "convert": ("convert", {"owner": account, "requestid": 1,
                                "amount": "0.001 HBD"}),
        "collateralized_convert": ("collateralized_convert", {
            "owner": account, "requestid": 1, "amount": "0.001 HIVE"}),
        "transfer_to_savings": ("transfer_to_savings", {
            "from": account, "to": "a", "amount": "0.001 HIVE", "memo": ""}),
        "transfer_from_savings": ("transfer_from_savings", {
            "from": account, "request_id": 1, "to": "a",
            "amount": "0.001 HIVE", "memo": ""}),
        "claim_account": ("claim_account", {
            "creator": account, "fee": "0.000 HIVE", "extensions": []}),
        "create_proposal": ("create_proposal", {
            "creator": account, "receiver": "a",
            "start_date": "2030-01-01T00:00:00", "end_date": "2030-02-01T00:00:00",
            "daily_pay": "1.000 HBD", "subject": "s", "permlink": "p",
            "extensions": []}),
        "update_proposal_votes": ("update_proposal_votes", {
            "voter": account, "proposal_ids": [1], "approve": True,
            "extensions": []}),
        "remove_proposal": ("remove_proposal", {
            "proposal_owner": account, "proposal_ids": [1], "extensions": []}),
        "decline_voting_rights": ("decline_voting_rights", {
            "account": account, "decline": True}),
        "change_recovery_account": ("change_recovery_account", {
            "account_to_recover": account, "new_recovery_account": "a",
            "extensions": []}),
    }


def main():
    accounts = call("condenser_api.get_accounts", [[ACCOUNT]])
    if not accounts:
        sys.exit(f"account @{ACCOUNT} does not exist")
    account = accounts[0]
    roles = {
        role: {key for key, _ in account[role]["key_auths"]}
        for role in ("owner", "active", "posting")
    }
    if not all(roles.values()):
        sys.exit(f"@{ACCOUNT} does not declare all three key authorities")

    props = call("condenser_api.get_dynamic_global_properties", [])
    ref = hivecomb.BlockRef.from_block_id(props["head_block_id"])

    print(f"asking hived which authority each operation needs, via @{ACCOUNT}")
    print("(no private key is used; the transactions are never signed or sent)\n")

    agreed = disagreed = errored = 0
    problems = []

    for label, (op_name, fields) in cases(ACCOUNT).items():
        try:
            tx = hivecomb.sign_transaction([(op_name, fields)], ref, [THROWAWAY_WIF])
            envelope = {k: v for k, v in tx.items() if k != "trx_id"}
            # database_api speaks appbase form, not condenser's [name, {...}] pairs.
            envelope["operations"] = [
                {"type": f"{name}_operation", "value": to_nai(value)}
                for name, value in envelope["operations"]
            ]
            envelope["signatures"] = []
            result = call("database_api.get_potential_signatures", {"trx": envelope})
            keys = set(result.get("keys", []))
        except Exception as exc:  # noqa: BLE001 - reported per case
            errored += 1
            problems.append(f"{label}: {type(exc).__name__}: {exc}")
            print(f"  ERR   {label}")
            continue

        matched = [role for role, role_keys in roles.items() if keys & role_keys]
        # An owner key satisfies active, and active satisfies posting, so hived can
        # legitimately return several. The least-privileged match is the requirement.
        for candidate in ("posting", "active", "owner"):
            if candidate in matched:
                theirs = candidate
                break
        else:
            theirs = f"none ({sorted(keys)[:1]})"

        ours = OUR_CHOICE.get(label)
        if ours is None:
            print(f"  ----  {label}: hived says {theirs}, we express no choice")
            continue
        if ours == theirs:
            agreed += 1
            print(f"  ok    {label:26} {theirs}")
        else:
            disagreed += 1
            problems.append(f"{label}: hived requires {theirs}, we sign with {ours}")
            print(f"  WRONG {label:26} hived={theirs} ours={ours}")

    total = agreed + disagreed + errored
    print(f"\n{total} operations: {agreed} agree, {disagreed} disagree, "
          f"{errored} errored")
    if problems:
        print("\nProblems:")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("\nEvery operation is signed with the authority hived asks for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
