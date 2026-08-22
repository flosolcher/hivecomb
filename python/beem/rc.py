"""Resource credits.

Drop-in for `beem.rc.RC`.

The cost model here is an **estimate from observed averages**, not hived's exact
formula, and says so: hived's cost depends on live pool state, and a number that
looks exact but is not is worse than one that admits it. Use
:meth:`RC.get_resource_pool` for the authoritative state.
"""

from __future__ import annotations

from .instance import BlockchainInstance

__all__ = ["RC"]

#: Rough RC cost per operation, in RC. Order-of-magnitude guidance for deciding
#: whether an account can act, not a substitute for the chain's own accounting.
TYPICAL_COSTS = {
    "comment": 1_500_000_000,
    "vote": 300_000_000,
    "transfer": 700_000_000,
    "custom_json": 300_000_000,
    "claim_reward_balance": 400_000_000,
    "transfer_to_vesting": 700_000_000,
    "recurrent_transfer": 1_000_000_000,
}


class RC:
    """Resource-credit lookups and rough cost estimates."""

    def __init__(self, **kwargs):
        self._instance = BlockchainInstance(**kwargs)

    @property
    def blockchain(self):
        return self._instance.blockchain

    def get_resource_params(self):
        return self.blockchain.rpc.call("rc_api.get_resource_params", {})

    def get_resource_pool(self):
        return self.blockchain.rpc.call("rc_api.get_resource_pool", {})

    def get_rc_accounts(self, accounts):
        if isinstance(accounts, str):
            accounts = [accounts]
        result = self.blockchain.rpc.call(
            "rc_api.find_rc_accounts", {"accounts": list(accounts)}
        )
        return result.get("rc_accounts", [])

    def estimate_cost(self, operation_name, count=1):
        """A rough RC cost for ``count`` operations of that kind.

        Returns ``None`` for an operation with no estimate rather than guessing.
        """
        cost = TYPICAL_COSTS.get(operation_name)
        return cost * count if cost is not None else None

    def can_afford(self, account, operation_name, count=1):
        """Whether an account's current RC covers that many operations.

        ``None`` when there is no estimate for the operation.
        """
        needed = self.estimate_cost(operation_name, count)
        if needed is None:
            return None
        from .account import Account

        name = getattr(account, "name", str(account))
        acct = Account(name, blockchain_instance=self.blockchain)
        return acct.get_rc_manabar()["current_mana"] >= needed

    # beem's names for the same estimates.
    def comment(self, *args, **kwargs):
        return self.estimate_cost("comment")

    def vote(self, *args, **kwargs):
        return self.estimate_cost("vote")

    def transfer(self, *args, **kwargs):
        return self.estimate_cost("transfer")

    def custom_json(self, *args, **kwargs):
        return self.estimate_cost("custom_json")

    def __repr__(self):
        return "<RC>"
