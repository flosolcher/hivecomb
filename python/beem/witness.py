"""Witnesses.

Drop-in for `beem.witness`.

A retired witness publishes the **null key** — 33 zero bytes, which is not a
point on secp256k1. Anything that insists on parsing it as a public key fails, so
:attr:`Witness.signing_key` stays a string and :meth:`Witness.is_active` compares
against :data:`NULL_KEY`.
"""

from __future__ import annotations

from .amount import Amount
from .exceptions import WitnessDoesNotExistsException
from .instance import BlockchainInstance
from .price import Price

__all__ = ["Witness", "Witnesses", "WitnessesVotedByAccount", "WitnessesRankedByVote",
           "ListWitnesses", "NULL_KEY"]

#: The key a witness publishes to stop producing blocks.
NULL_KEY = "STM1111111111111111111111111111111114T1Anm"


class Witness(dict):
    """A Hive witness."""

    def __init__(self, owner, lazy=False, full=False, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        if isinstance(owner, dict):
            super().__init__(owner)
            self.owner = owner.get("owner", "")
        else:
            self.owner = str(owner).lstrip("@")
            super().__init__()
            if not lazy:
                self.refresh()

    @property
    def blockchain(self):
        return self._instance.blockchain

    def refresh(self):
        result = self.blockchain.rpc.call(
            "condenser_api.get_witness_by_account", [self.owner]
        )
        if not result:
            raise WitnessDoesNotExistsException(f"witness {self.owner!r} does not exist")
        self.clear()
        # dict.update explicitly: `update` on this class is the witness-update
        # broadcast, matching beem's API, so the mapping method is shadowed.
        dict.update(self, result)
        return self

    def json(self):
        return dict(self)

    @property
    def account(self):
        from .account import Account

        return Account(self.owner, blockchain_instance=self.blockchain)

    @property
    def signing_key(self):
        return self.get("signing_key", NULL_KEY)

    @property
    def is_active(self):
        """Whether the witness is still producing.

        A witness retires by publishing the null key.
        """
        return self.signing_key != NULL_KEY

    def get_votes_sum(self):
        """Total vote weight.

        hived sends this as a string because it exceeds JSON's 53-bit safe
        integer range; parsing it as a float would lose the low digits.
        """
        return int(self.get("votes", 0) or 0)

    @property
    def hbd_exchange_rate(self):
        feed = self.get("hbd_exchange_rate") or self.get("sbd_exchange_rate")
        return Price(feed) if feed else None

    def feed_publish(self, base, quote="1.000 HIVE", account=None, **kwargs):
        """Publish a price feed."""
        account = account or self.owner
        return self.blockchain.finalizeOp(
            (
                "feed_publish",
                {
                    "publisher": account,
                    "exchange_rate": {
                        "base": str(Amount(base, "HBD") if not isinstance(base, str) or " " not in base else base),
                        "quote": str(quote),
                    },
                },
            ),
            account=account,
            **kwargs,
        )

    def update(self, *args, **kwargs):
        """Publish witness properties, or update the mapping.

        This name is overloaded because beem overloaded it: ``update()`` is the
        witness-update broadcast, and :meth:`dict.update` is shadowed. Called
        with a single mapping — ``witness.update({...})`` — it behaves as
        :meth:`dict.update` does, so the shadowing does not bite ordinary use.
        """
        if args and isinstance(args[0], dict) and not kwargs:
            return dict.update(self, args[0])

        signing_key = kwargs.pop("signing_key", args[0] if args else None)
        url = kwargs.pop("url", args[1] if len(args) > 1 else None)
        props = kwargs.pop("props", args[2] if len(args) > 2 else None)
        account = kwargs.pop("account", None) or self.owner

        properties = []
        if signing_key is not None:
            properties.append(("key", signing_key))
        if url is not None:
            properties.append(("url", url))
        if props:
            properties.extend(sorted(props.items()))
        if not properties:
            raise ValueError("nothing to update")

        raise NotImplementedError(
            "witness_set_properties encodes each value as the binary form of its "
            "own type, which this layer does not build. Use comb's "
            "WitnessProperty helpers with Hive.finalizeOp; see MIGRATION.md."
        )

    def print(self):
        state = "active" if self.is_active else "DISABLED"
        print(
            f"@{self.owner}  {state}\n"
            f"  votes    {self.get_votes_sum()}\n"
            f"  missed   {self.get('total_missed', 0)}\n"
            f"  version  {self.get('running_version', '?')}\n"
            f"  url      {self.get('url', '')}"
        )

    def __repr__(self):
        return f"<Witness {self.owner}>"


class Witnesses(list):
    """The witnesses ranked by vote."""

    def __init__(self, limit=100, lazy=False, **kwargs):
        instance = BlockchainInstance(**kwargs)
        result = instance.blockchain.rpc.call(
            "condenser_api.get_witnesses_by_vote", ["", limit]
        )
        super().__init__(
            Witness(raw, blockchain_instance=instance.blockchain) for raw in result or []
        )

    def printAsTable(self, sort_key="votes", reverse=True):
        rows = sorted(
            self, key=lambda w: w.get_votes_sum(), reverse=reverse
        )
        width = max((len(w.owner) for w in rows), default=10)
        print(f"{'witness'.ljust(width)}  {'votes':>22}  missed  version")
        for witness in rows:
            print(
                f"{witness.owner.ljust(width)}  {witness.get_votes_sum():>22}  "
                f"{witness.get('total_missed', 0):>6}  {witness.get('running_version', '?')}"
            )


class WitnessesRankedByVote(Witnesses):
    """Alias for :class:`Witnesses`, matching beem."""


class ListWitnesses(Witnesses):
    """Alias for :class:`Witnesses`, matching beem."""


class WitnessesVotedByAccount(list):
    """The witnesses an account votes for."""

    def __init__(self, account, lazy=False, **kwargs):
        from .account import Account

        instance = BlockchainInstance(**kwargs)
        acct = Account(account, blockchain_instance=instance.blockchain)
        names = acct.get("witness_votes", [])
        super().__init__(
            Witness(name, blockchain_instance=instance.blockchain) for name in names
        )
