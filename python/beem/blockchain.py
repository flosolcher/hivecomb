"""The chain itself.

Drop-in for `beem.blockchain.Blockchain`: block iteration, operation streaming
and a few chain-wide lookups.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from .block import Block
from .instance import BlockchainInstance

__all__ = ["Blockchain"]

#: Seconds between blocks.
BLOCK_INTERVAL = 3


class Blockchain:
    """Iterate blocks and operations."""

    def __init__(self, mode="irreversible", max_block_wait_repetition=None, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        if mode not in {"irreversible", "head"}:
            raise ValueError("mode must be 'irreversible' or 'head'")
        self.mode = mode

    @property
    def blockchain(self):
        return self._instance.blockchain

    @property
    def rpc(self):
        return self.blockchain.rpc

    def is_irreversible_mode(self):
        return self.mode == "irreversible"

    # -- head --------------------------------------------------------------

    def get_current_block_num(self):
        props = self.blockchain.get_dynamic_global_properties()
        key = (
            "last_irreversible_block_num"
            if self.is_irreversible_mode()
            else "head_block_number"
        )
        return int(props[key])

    def get_current_block(self, only_ops=False, only_virtual_ops=False):
        return Block(
            self.get_current_block_num(),
            only_ops=only_ops,
            only_virtual_ops=only_virtual_ops,
            blockchain_instance=self.blockchain,
        )

    def get_estimated_block_num(self, date, estimate_start_block=0, accurate=True):
        """Estimate the block number at ``date`` from the three-second interval."""
        props = self.blockchain.get_dynamic_global_properties()
        head_num = int(props["head_block_number"])
        head_time = datetime.strptime(
            str(props["time"]).rstrip("Z"), "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=timezone.utc)
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        delta = (head_time - date).total_seconds()
        return max(1, int(head_num - delta / BLOCK_INTERVAL))

    def block_time(self, block_num):
        return Block(block_num, blockchain_instance=self.blockchain).time

    block_timestamp = block_time

    def participation_rate(self):
        props = self.blockchain.get_dynamic_global_properties()
        count = props.get("participation_count")
        return (int(count) / 128 * 100) if count is not None else None

    # -- iteration ---------------------------------------------------------

    def blocks(self, start=None, stop=None, max_batch_size=None, threading=False,
               thread_num=8, only_ops=False, only_virtual_ops=False):
        """Yield blocks from ``start`` to ``stop``.

        With no ``stop``, follows the head indefinitely, sleeping between polls
        rather than spinning.
        """
        current = start if start is not None else self.get_current_block_num()
        while stop is None or current <= stop:
            head = self.get_current_block_num()
            if current > head:
                if stop is not None:
                    break
                time.sleep(BLOCK_INTERVAL)
                continue
            for number in range(current, min(head, stop if stop is not None else head) + 1):
                yield Block(
                    number,
                    only_ops=only_ops,
                    only_virtual_ops=only_virtual_ops,
                    blockchain_instance=self.blockchain,
                )
            current = min(head, stop if stop is not None else head) + 1

    def ops(self, start=None, stop=None, only_virtual_ops=False, **kwargs):
        """Yield every operation in a block range."""
        for block in self.blocks(start=start, stop=stop, **kwargs):
            for name, value in block.operations:
                record = dict(value)
                record.update(
                    {
                        "type": name,
                        "block_num": block.block_num,
                        "timestamp": block.get("timestamp"),
                    }
                )
                yield record

    def stream(self, opNames=None, raw_ops=False, start=None, stop=None, **kwargs):
        """Stream operations, optionally filtered by name.

        ``opNames`` accepts virtual operation names too, which beem could not
        name correctly: its table reports every virtual id two lower than the
        chain's.
        """
        wanted = set(opNames or [])
        for operation in self.ops(start=start, stop=stop, **kwargs):
            if wanted and operation["type"] not in wanted:
                continue
            yield operation

    def wait_for_and_get_block(self, block_number, blocks_waiting_for=None):
        """Block until ``block_number`` exists, then return it."""
        while self.get_current_block_num() < block_number:
            time.sleep(BLOCK_INTERVAL)
        return Block(block_number, blockchain_instance=self.blockchain)

    def ops_statistics(self, start, stop=None, add_to_ops_stat=None, verbose=False):
        counts = dict(add_to_ops_stat or {})
        for block in self.blocks(start=start, stop=stop):
            counts = block.ops_statistics(add_to=counts)
        return counts

    # -- lookups -----------------------------------------------------------

    def get_transaction(self, transaction_id):
        return self.rpc.call("condenser_api.get_transaction", [transaction_id])

    def get_transaction_hex(self, transaction):
        return self.rpc.call("condenser_api.get_transaction_hex", [transaction])

    def is_transaction_existing(self, transaction_id):
        try:
            return bool(self.get_transaction(transaction_id))
        except Exception:
            return False

    def get_account_count(self):
        return self.rpc.call("condenser_api.get_account_count", [])

    def get_all_accounts(self, start="", stop="", steps=1000, limit=None, **kwargs):
        """Yield every account name, paging through the index."""
        cursor = start
        seen = 0
        while True:
            names = self.rpc.call(
                "condenser_api.lookup_accounts", [cursor, min(steps, 1000)]
            )
            if not names:
                return
            for name in names:
                if name == cursor:
                    continue
                if stop and name > stop:
                    return
                yield name
                seen += 1
                if limit and seen >= limit:
                    return
            if len(names) < steps:
                return
            cursor = names[-1]

    def get_similar_account_names(self, name, limit=5):
        return self.rpc.call("condenser_api.lookup_accounts", [name, limit])

    def get_account_reputations(self, start="", stop="", limit=1000, **kwargs):
        return self.rpc.call(
            "reputation_api.get_account_reputations",
            {"account_lower_bound": start, "limit": limit},
        )

    def find_rc_accounts(self, accounts):
        if isinstance(accounts, str):
            accounts = [accounts]
        result = self.rpc.call("rc_api.find_rc_accounts", {"accounts": list(accounts)})
        return result.get("rc_accounts", [])

    def hash_op(self, event):
        """A stable hash of an operation, for de-duplication."""
        import hashlib
        import json as _json

        return hashlib.sha256(
            _json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def __repr__(self):
        return f"<Blockchain mode={self.mode}>"
