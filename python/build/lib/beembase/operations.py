"""Operation builders.

Drop-in for `beembase.operations`. Each class takes the same keyword arguments
beem's did and renders to the ``[name, {fields}]`` JSON form, which is what
`hivecomb` signs and what `network_broadcast_api` accepts.

beem's classes were serializers: they produced Graphene binary directly. Here
serialization happens in Rust, so these are constructors and validators only.
That is why they have no ``__bytes__``: producing wire bytes in Python is
exactly where beem's escrow and ``custom_binary`` operations dropped fields
(findings 22 and 23), and where a second encoder can drift from the one that
actually signs.

Operations beem could not build at all — ``Collateralized_convert`` and
``Recurrent_transfer`` — are here and work.
"""

from __future__ import annotations

import json

from hivecomb_compat import not_implemented

from .operationids import getOperationIdForName, isVirtualOperation

__all__ = [
    "Operation",
    "Vote",
    "Comment",
    "Transfer",
    "Transfer_to_vesting",
    "Withdraw_vesting",
    "Custom_json",
    "Delete_comment",
    "Comment_options",
    "Claim_reward_balance",
    "Delegate_vesting_shares",
    "Account_witness_vote",
    "Account_witness_proxy",
    "Convert",
    "Collateralized_convert",
    "Recurrent_transfer",
    "Recurring_transfer",
    "Transfer_to_savings",
    "Transfer_from_savings",
    "Cancel_transfer_from_savings",
    "Limit_order_create",
    "Limit_order_cancel",
    "Claim_account",
    "Account_update2",
    "Decline_voting_rights",
    "Feed_publish",
    "Set_withdraw_vesting_route",
    "Create_proposal",
    "Update_proposal",
    "Update_proposal_votes",
    "Remove_proposal",
]


class Operation:
    """Base for the operation builders.

    Instances render to ``[name, {fields}]`` via :meth:`json`, and compare and
    iterate like the two-element sequence beem's did.
    """

    #: hived's name for this operation, without the ``_operation`` suffix.
    op_name = None
    #: Fields that must be supplied.
    required = ()
    #: Fields with defaults, applied when absent.
    defaults = {}

    def __init__(self, *args, **kwargs):
        if len(args) == 1 and not kwargs and isinstance(args[0], dict):
            kwargs = dict(args[0])
        kwargs.pop("prefix", None)
        kwargs.pop("json_str", None)

        missing = [name for name in self.required if name not in kwargs]
        if missing:
            raise ValueError(f"{self.op_name} is missing {missing}")

        fields = dict(self.defaults)
        fields.update(kwargs)
        self.data = self.validate(fields)

    def validate(self, fields):
        """Hook for per-operation checks. Returns the fields to use."""
        return fields

    @property
    def name(self):
        return self.op_name

    @property
    def opId(self):
        return getOperationIdForName(self.op_name)

    def json(self):
        return [self.op_name, self.data]

    def toJson(self):
        return self.json()

    def __iter__(self):
        return iter(self.json())

    def __getitem__(self, index):
        return self.json()[index]

    def __len__(self):
        return 2

    def __eq__(self, other):
        if isinstance(other, Operation):
            return self.json() == other.json()
        if isinstance(other, (list, tuple)):
            return self.json() == list(other)
        return NotImplemented

    def __repr__(self):
        return f"{type(self).__name__}({self.data!r})"

    def __str__(self):
        return json.dumps(self.json())

    def __bytes__(self):
        raise not_implemented(
            f"bytes({type(self).__name__})",
            "Graphene serialization happens in Rust. Sign with Hive.finalizeOp "
            "or hivecomb.sign_transaction, which serialize correctly.",
        )


def _json_string(value):
    """Render a JSON payload as the string that will be signed.

    A string passes through untouched. Anything else is dumped with compact
    separators and **`ensure_ascii=False`** — raw UTF-8 rather than beem's
    `\\uXXXX` escapes.

    That is a deliberate divergence: the string is stored on chain verbatim and
    resource credits are charged by the byte, so escaping costs about 50% more for
    a payload with non-ASCII and buys nothing. It also matches `JSON.stringify`,
    and therefore hive-js and dhive. See `beem.Hive._json_field` for the full note,
    and MIGRATION.md for the divergence.
    """
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


class Vote(Operation):
    op_name = "vote"
    required = ("voter", "author", "permlink", "weight")

    def validate(self, fields):
        fields["weight"] = int(fields["weight"])
        if not -10000 <= fields["weight"] <= 10000:
            raise ValueError("vote weight must be between -10000 and 10000")
        return fields


class Comment(Operation):
    op_name = "comment"
    required = ("parent_permlink", "author", "permlink", "title", "body")
    defaults = {"parent_author": "", "json_metadata": ""}

    def validate(self, fields):
        fields["json_metadata"] = _json_string(fields.get("json_metadata", ""))
        return fields


class Transfer(Operation):
    op_name = "transfer"
    required = ("from", "to", "amount")
    defaults = {"memo": ""}


class Transfer_to_vesting(Operation):
    op_name = "transfer_to_vesting"
    required = ("from", "to", "amount")


class Withdraw_vesting(Operation):
    op_name = "withdraw_vesting"
    required = ("account", "vesting_shares")


class Custom_json(Operation):
    op_name = "custom_json"
    required = ("id", "json")
    defaults = {"required_auths": [], "required_posting_auths": []}

    def validate(self, fields):
        if len(fields["id"]) > 32:
            raise ValueError("custom_json id is longer than hived's 32-byte limit")
        if not fields["required_auths"] and not fields["required_posting_auths"]:
            raise ValueError(
                "custom_json needs at least one required_auths or "
                "required_posting_auths entry"
            )
        fields["json"] = _json_string(fields["json"])
        return fields


class Delete_comment(Operation):
    op_name = "delete_comment"
    required = ("author", "permlink")


class Comment_options(Operation):
    op_name = "comment_options"
    required = ("author", "permlink", "max_accepted_payout", "percent_hbd")
    defaults = {"allow_votes": True, "allow_curation_rewards": True, "extensions": []}

    def validate(self, fields):
        # beem accepted `percent_steem_dollars` as an alias; keep it working.
        if "percent_steem_dollars" in fields:
            fields["percent_hbd"] = fields.pop("percent_steem_dollars")
        beneficiaries = fields.pop("beneficiaries", None)
        if beneficiaries:
            fields["extensions"] = [[0, {"beneficiaries": beneficiaries}]]
        return fields


class Claim_reward_balance(Operation):
    op_name = "claim_reward_balance"
    required = ("account", "reward_hive", "reward_hbd", "reward_vests")

    def validate(self, fields):
        # beem used the pre-rename names on the Steem branch.
        for old, new in (("reward_steem", "reward_hive"), ("reward_sbd", "reward_hbd")):
            if old in fields:
                fields[new] = fields.pop(old)
        return fields


class Delegate_vesting_shares(Operation):
    op_name = "delegate_vesting_shares"
    required = ("delegator", "delegatee", "vesting_shares")


class Account_witness_vote(Operation):
    op_name = "account_witness_vote"
    required = ("account", "witness", "approve")


class Account_witness_proxy(Operation):
    op_name = "account_witness_proxy"
    required = ("account", "proxy")


class Convert(Operation):
    op_name = "convert"
    required = ("owner", "requestid", "amount")


class Collateralized_convert(Operation):
    """``collateralized_convert`` (HF25).

    **beem cannot build this**: the operation is absent from its id table, so
    ``Operation.__init__`` raises ``ValueError("Unknown operation")``.
    """

    op_name = "collateralized_convert"
    required = ("owner", "requestid", "amount")


class Recurrent_transfer(Operation):
    """``recurrent_transfer`` (HF25), with the HF28 ``pair_id`` extension.

    **beem cannot build this**: absent from its id table. Its unreachable
    ``Recurring_transfer`` class also misspells the name, omits ``extensions``,
    and types ``recurrence``/``executions`` as signed where hived uses
    ``uint16_t``.
    """

    op_name = "recurrent_transfer"
    required = ("from", "to", "amount", "recurrence", "executions")
    defaults = {"memo": "", "extensions": []}

    def validate(self, fields):
        fields["recurrence"] = int(fields["recurrence"])
        fields["executions"] = int(fields["executions"])
        if fields["recurrence"] < 24:
            raise ValueError("hived requires a recurrence of at least 24 hours")
        if fields["executions"] < 2:
            raise ValueError("hived requires at least 2 executions")
        pair_id = fields.pop("pair_id", None)
        if pair_id is not None:
            fields["extensions"] = [[1, {"pair_id": int(pair_id)}]]
        return fields


#: beem's spelling, kept as an alias. The wire name is hived's.
Recurring_transfer = Recurrent_transfer


class Transfer_to_savings(Operation):
    op_name = "transfer_to_savings"
    required = ("from", "to", "amount")
    defaults = {"memo": ""}


class Transfer_from_savings(Operation):
    op_name = "transfer_from_savings"
    required = ("from", "request_id", "to", "amount")
    defaults = {"memo": ""}


class Cancel_transfer_from_savings(Operation):
    op_name = "cancel_transfer_from_savings"
    required = ("from", "request_id")


class Limit_order_create(Operation):
    op_name = "limit_order_create"
    required = ("owner", "orderid", "amount_to_sell", "min_to_receive", "expiration")
    defaults = {"fill_or_kill": False}


class Limit_order_cancel(Operation):
    op_name = "limit_order_cancel"
    required = ("owner", "orderid")


class Claim_account(Operation):
    op_name = "claim_account"
    required = ("creator", "fee")
    defaults = {"extensions": []}


class Account_update2(Operation):
    op_name = "account_update2"
    required = ("account",)
    defaults = {"json_metadata": "", "posting_json_metadata": "", "extensions": []}

    def validate(self, fields):
        for key in ("json_metadata", "posting_json_metadata"):
            fields[key] = _json_string(fields.get(key, ""))
        return fields


class Decline_voting_rights(Operation):
    op_name = "decline_voting_rights"
    required = ("account", "decline")


class Feed_publish(Operation):
    op_name = "feed_publish"
    required = ("publisher", "exchange_rate")


class Set_withdraw_vesting_route(Operation):
    op_name = "set_withdraw_vesting_route"
    required = ("from_account", "to_account", "percent")
    defaults = {"auto_vest": False}


class Create_proposal(Operation):
    op_name = "create_proposal"
    required = ("creator", "receiver", "start_date", "end_date", "daily_pay", "subject", "permlink")
    defaults = {"extensions": []}


class Update_proposal(Operation):
    op_name = "update_proposal"
    required = ("proposal_id", "creator", "daily_pay", "subject", "permlink")
    defaults = {"extensions": []}


class Update_proposal_votes(Operation):
    op_name = "update_proposal_votes"
    required = ("voter", "proposal_ids", "approve")
    defaults = {"extensions": []}


class Remove_proposal(Operation):
    op_name = "remove_proposal"
    required = ("proposal_owner", "proposal_ids")
    defaults = {"extensions": []}
