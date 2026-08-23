"""The shared blockchain instance.

Drop-in for `beem.instance`. beem's wrappers each reach for a global `Hive`
when none is passed, so the same mechanism is here.

That global is exactly the design that puts a node call in unexpected places —
an `Account` object that can fetch on attribute access. `hivecomb`'s wrappers fetch
only when you construct or refresh them, and never while signing.
"""

from __future__ import annotations

_shared = None


def set_shared_blockchain_instance(instance):
    """Install the instance the wrappers use when none is given."""
    global _shared
    _shared = instance
    return _shared


def shared_blockchain_instance():
    """The shared instance, creating a default one if needed."""
    global _shared
    if _shared is None:
        from .hive import Hive

        _shared = Hive()
    return _shared


def clear_shared_blockchain_instance():
    """Drop the shared instance."""
    global _shared
    _shared = None


# beem's older spellings.
set_shared_steem_instance = set_shared_blockchain_instance
shared_steem_instance = shared_blockchain_instance
set_shared_hive_instance = set_shared_blockchain_instance
shared_hive_instance = shared_blockchain_instance


class SharedInstance:
    """Holds the shared instance, as beem's did."""

    instance = None
    config = {}


class BlockchainInstance:
    """Mixin giving a wrapper its `blockchain_instance`.

    Accepts the several keyword names beem used for the same thing:
    ``blockchain_instance``, ``steem_instance``, ``hive_instance``.
    """

    def __init__(self, *args, **kwargs):
        self._blockchain = (
            kwargs.get("blockchain_instance")
            or kwargs.get("steem_instance")
            or kwargs.get("hive_instance")
            or None
        )

    @property
    def blockchain(self):
        if self._blockchain is None:
            self._blockchain = shared_blockchain_instance()
        return self._blockchain

    # beem exposed the same object under three names.
    steem = blockchain
    hive = blockchain

    @property
    def rpc(self):
        return self.blockchain.rpc
