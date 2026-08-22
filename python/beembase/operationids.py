"""Operation ids.

Drop-in for `beembase.operationids`, with the table corrected.

beem shipped two lists and used the wrong one:

* The active ``ops`` list predates HF25. It contains neither
  ``collateralized_convert`` (48) nor ``recurrent_transfer`` (49), so beem cannot
  construct either operation — and because those two non-virtual operations are
  missing, **every virtual operation id it reports is two lower than the
  chain's**. ``fill_convert_request`` is 50 on chain and 48 in beem;
  ``producer_reward`` is 64 on chain and 62 in beem.
* The ``ops_HF25`` list, which the file invites you to enable, contains a
  **missing comma**::

      'convert',
      'collateralized_convert'      # <- no comma
      'account_create',

  Python concatenates adjacent string literals, so that is the single element
  ``'collateralized_convertaccount_create'``. The list loses two names, gains one
  nonsense name, and shifts every id from index 10 onward by one. It also inserts
  the new operations in the middle rather than appending them, renumbering
  everything after — the opposite of what hived did.

Both are findings 1 and 2. The table below is generated from hived's
``operations.hpp`` and matches the chain.

Note that ``ops`` and ``ops_HF25`` are the same list here. There is no second
list to fall out of sync with.
"""

from __future__ import annotations

#: Every operation, indexed by its id in hived's static variant.
ops = [
    "vote",
    "comment",
    "transfer",
    "transfer_to_vesting",
    "withdraw_vesting",
    "limit_order_create",
    "limit_order_cancel",
    "feed_publish",
    "convert",
    "account_create",
    "account_update",
    "witness_update",
    "account_witness_vote",
    "account_witness_proxy",
    "pow",
    "custom",
    "witness_block_approve",
    "delete_comment",
    "custom_json",
    "comment_options",
    "set_withdraw_vesting_route",
    "limit_order_create2",
    "claim_account",
    "create_claimed_account",
    "request_account_recovery",
    "recover_account",
    "change_recovery_account",
    "escrow_transfer",
    "escrow_dispute",
    "escrow_release",
    "pow2",
    "escrow_approve",
    "transfer_to_savings",
    "transfer_from_savings",
    "cancel_transfer_from_savings",
    "custom_binary",
    "decline_voting_rights",
    "reset_account",
    "set_reset_account",
    "claim_reward_balance",
    "delegate_vesting_shares",
    "account_create_with_delegation",
    "witness_set_properties",
    "account_update2",
    "create_proposal",
    "update_proposal_votes",
    "remove_proposal",
    "update_proposal",
    "collateralized_convert",
    "recurrent_transfer",
    # Virtual operations follow. The chain emits these; they cannot be signed.
    "fill_convert_request",
    "author_reward",
    "curation_reward",
    "comment_reward",
    "liquidity_reward",
    "interest",
    "fill_vesting_withdraw",
    "fill_order",
    "shutdown_witness",
    "fill_transfer_from_savings",
    "hardfork",
    "comment_payout_update",
    "return_vesting_delegation",
    "comment_benefactor_reward",
    "producer_reward",
    "clear_null_account_balance",
    "proposal_pay",
    "dhf_funding",
    "hardfork_hive",
    "hardfork_hive_restore",
    "delayed_voting",
    "consolidate_treasury_balance",
    "effective_comment_vote",
    "ineffective_delete_comment",
    "dhf_conversion",
    "expired_account_notification",
    "changed_recovery_account",
    "transfer_to_vesting_completed",
    "pow_reward",
    "vesting_shares_split",
    "account_created",
    "fill_collateralized_convert_request",
    "system_warning",
    "fill_recurrent_transfer",
    "failed_recurrent_transfer",
    "limit_order_cancelled",
    "producer_missed",
    "proposal_fee",
    "collateralized_convert_immediate_conversion",
    "escrow_approved",
    "escrow_rejected",
    "proxy_cleared",
    "declined_voting_rights",
]

#: beem shipped this as a separate, broken list. Kept as an alias so code that
#: imports it keeps working, and correct because it is the same table.
ops_HF25 = ops

#: The lowest virtual operation id.
FIRST_VIRTUAL_OP = 50

operations = {name: index for index, name in enumerate(ops)}

#: beem's spelling of ``recurrent_transfer``, accepted as an alias.
operations["recurring_transfer"] = operations["recurrent_transfer"]


def getOperationNameForId(i):
    """Convert an operation id into its name.

    beem compared with ``is`` rather than ``==`` (finding 18), which worked only
    because CPython interns small integers.
    """
    i = int(i)
    if 0 <= i < len(ops):
        return ops[i]
    return "Unknown Operation ID %d" % i


def getOperationIdForName(name):
    """Convert an operation name into its id."""
    name = name.replace("_operation", "")
    if name not in operations:
        raise ValueError(f"unknown operation {name!r}")
    return operations[name]


def isVirtualOperation(name_or_id):
    """Whether the chain emits this operation rather than accepting it."""
    if isinstance(name_or_id, str):
        name_or_id = getOperationIdForName(name_or_id)
    return int(name_or_id) >= FIRST_VIRTUAL_OP
