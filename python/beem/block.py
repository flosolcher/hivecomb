"""Blocks.

Drop-in for `beem.block`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .exceptions import BlockDoesNotExistsException
from .instance import BlockchainInstance

__all__ = ["Block", "BlockHeader"]


def normalize_operation(operation):
    """Normalise either JSON operation shape to ``[name, fields]``.

    `block_api` sends ``{"type": "vote_operation", "value": {...}}``;
    `condenser_api` sends ``["vote", {...}]``.
    """
    if isinstance(operation, dict) and "type" in operation:
        return [str(operation["type"]).replace("_operation", ""), operation.get("value", {})]
    if isinstance(operation, (list, tuple)) and len(operation) == 2:
        return [operation[0], operation[1]]
    raise ValueError(f"cannot read {operation!r} as an operation")


def _block_num_from_id(block_id):
    """A block id embeds its own number big-endian in its first four bytes."""
    return int(block_id[:8], 16)


class Block(dict):
    """A block, with its transactions."""

    def __init__(self, block, only_ops=False, only_virtual_ops=False, lazy=False, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        self.only_virtual_ops = only_virtual_ops
        if isinstance(block, dict):
            super().__init__(block)
            self.identifier = block.get("block_id", "")
        else:
            self.identifier = int(block)
            super().__init__()
            if not lazy:
                self.refresh()

    @property
    def blockchain(self):
        return self._instance.blockchain

    def refresh(self):
        result = self.blockchain.rpc.call(
            "block_api.get_block", {"block_num": int(self.identifier)}
        )
        block = (result or {}).get("block")
        if not block:
            raise BlockDoesNotExistsException(f"block {self.identifier} is not available")
        self.clear()
        self.update(block)
        return self

    def json(self):
        return dict(self)

    @property
    def block_num(self):
        block_id = self.get("block_id")
        if block_id:
            return _block_num_from_id(block_id)
        previous = self.get("previous")
        if previous:
            return _block_num_from_id(previous) + 1
        return int(self.identifier)

    @property
    def time(self):
        stamp = self.get("timestamp")
        if not stamp:
            return None
        return datetime.strptime(str(stamp).rstrip("Z"), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )

    @property
    def transactions(self):
        return self.get("transactions", [])

    json_transactions = transactions

    @property
    def operations(self):
        """Every operation in the block, flattened across its transactions.

        Normalised to ``[name, fields]``. `block_api` returns the appbase
        ``{"type": "vote_operation", "value": {...}}`` shape while
        `condenser_api` returns the two-element form, and code that assumes one
        of them silently reads the wrong thing from the other.
        """
        out = []
        for transaction in self.transactions:
            for operation in transaction.get("operations", []):
                out.append(normalize_operation(operation))
        return out

    @property
    def json_operations(self):
        """Operations exactly as the node sent them, un-normalised."""
        out = []
        for transaction in self.transactions:
            out.extend(transaction.get("operations", []))
        return out

    def ops_statistics(self, add_to=None):
        """Count operations by type."""
        counts = dict(add_to or {})
        for name, _ in self.operations:
            counts[name] = counts.get(name, 0) + 1
        return counts

    def __repr__(self):
        return f"<Block {self.block_num}>"


class BlockHeader(dict):
    """A block header, without its transactions."""

    def __init__(self, block, lazy=False, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        if isinstance(block, dict):
            super().__init__(block)
            self.identifier = 0
        else:
            self.identifier = int(block)
            super().__init__()
            if not lazy:
                self.refresh()

    @property
    def blockchain(self):
        return self._instance.blockchain

    def refresh(self):
        result = self.blockchain.rpc.call(
            "block_api.get_block_header", {"block_num": int(self.identifier)}
        )
        header = (result or {}).get("header")
        if not header:
            raise BlockDoesNotExistsException(f"block {self.identifier} is not available")
        self.clear()
        self.update(header)
        return self

    @property
    def block_num(self):
        previous = self.get("previous")
        return _block_num_from_id(previous) + 1 if previous else int(self.identifier)

    @property
    def time(self):
        stamp = self.get("timestamp")
        if not stamp:
            return None
        return datetime.strptime(str(stamp).rstrip("Z"), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )

    def json(self):
        return dict(self)

    def __repr__(self):
        return f"<BlockHeader {self.block_num}>"
