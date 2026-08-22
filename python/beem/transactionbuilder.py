"""Building transactions by hand.

Drop-in for `beem.transactionbuilder.TransactionBuilder`, for the case where you
want several operations in one transaction.

**Signing never contacts a node.** The block reference comes from the `Hive`
instance's cache. beem's builder called `get_config` on the way to every
signature.
"""

from __future__ import annotations

import comb

from .exceptions import MissingKeyError
from .instance import BlockchainInstance

__all__ = ["TransactionBuilder"]


class TransactionBuilder(dict):
    """Accumulate operations, then sign and broadcast them together."""

    def __init__(self, tx=None, expiration=None, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        self.expiration = expiration
        self.ops = []
        self.wifs = []
        self._signed = None
        super().__init__(tx or {})
        if tx and "operations" in tx:
            self.ops = [_as_pair(op) for op in tx["operations"]]

    @property
    def blockchain(self):
        return self._instance.blockchain

    # -- building ----------------------------------------------------------

    def appendOps(self, ops, append_to=None):
        """Add one operation or a list of them."""
        if isinstance(ops, tuple) and len(ops) == 2 and isinstance(ops[0], str):
            ops = [ops]
        elif not isinstance(ops, list):
            ops = [ops]
        for op in ops:
            self.ops.append(_as_pair(op))
        return self

    appendOp = appendOps

    def appendWif(self, wif):
        """Add a signing key directly."""
        if wif:
            self.wifs.append(str(wif))
        return self

    def appendSigner(self, account, permission):
        """Add the key for an account's role, from the wallet.

        Needs a wallet; pass keys with :meth:`appendWif` if you are not using
        one.
        """
        wallet = getattr(self.blockchain, "wallet", None)
        if wallet is None:
            raise MissingKeyError(
                "no wallet is configured; use appendWif(wif) to sign directly"
            )
        name = getattr(account, "name", str(account))
        self.appendWif(wallet.getKeyForAccount(name, permission))
        return self

    def clear(self):
        self.ops = []
        self.wifs = []
        self._signed = None
        super().clear()
        return self

    # -- signing -----------------------------------------------------------

    def sign(self, reconstruct_tx=True, **kwargs):
        """Sign the accumulated operations. No network access."""
        if not self.ops:
            raise ValueError("no operations to sign")
        wifs = self.wifs or list(getattr(self.blockchain, "wifs", []))
        if not wifs:
            raise MissingKeyError("no signing keys available")
        self._signed = comb.sign_transaction(
            self.ops,
            self.blockchain._block_ref(),
            wifs,
            expiration_seconds=self.expiration or self.blockchain.expiration,
            chain=self.blockchain.chain,
        )
        self.update(self._signed)
        return self

    def broadcast(self, max_block_age=-1):
        """Broadcast, signing first if needed."""
        if self._signed is None:
            self.sign()
        if self.blockchain.nobroadcast:
            return self._signed
        return self.blockchain.broadcast(self._signed)

    def verify_authority(self):
        """Ask the node whether the signatures satisfy the required authority."""
        if self._signed is None:
            self.sign()
        payload = {k: v for k, v in self._signed.items() if k != "trx_id"}
        return self.blockchain.rpc.call(
            "database_api.verify_authority", {"trx": payload}
        )

    def json(self):
        return dict(self._signed) if self._signed else {"operations": self.ops}

    def get_parent(self):
        return self.blockchain

    def __repr__(self):
        return f"<TransactionBuilder ops={len(self.ops)} signed={self._signed is not None}>"


def _as_pair(op):
    if hasattr(op, "json"):
        op = op.json()
    if isinstance(op, (list, tuple)) and len(op) == 2:
        return (op[0], dict(op[1]))
    if isinstance(op, dict) and "type" in op:
        return (op["type"].replace("_operation", ""), dict(op["value"]))
    raise ValueError(f"cannot read {op!r} as an operation")
