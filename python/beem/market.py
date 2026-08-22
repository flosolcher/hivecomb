"""The internal HIVE/HBD market.

Drop-in for `beem.market.Market`.
"""

from __future__ import annotations

import time

from .amount import Amount
from .instance import BlockchainInstance
from .price import FilledOrder, Order, Price

__all__ = ["Market"]


class Market(dict):
    """The internal market between HIVE and HBD."""

    def __init__(self, base=None, quote=None, **kwargs):
        self._instance = BlockchainInstance(**kwargs)
        super().__init__({"base": base or "HBD", "quote": quote or "HIVE"})

    @property
    def blockchain(self):
        return self._instance.blockchain

    @property
    def rpc(self):
        return self.blockchain.rpc

    def get_string(self, separator=":"):
        return f"{self['base']}{separator}{self['quote']}"

    def ticker(self, raw_data=False):
        """Current prices and 24-hour volume."""
        data = self.rpc.call("condenser_api.get_ticker", [])
        if raw_data:
            return data
        return {
            "latest": Price(float(data["latest"]), base=Amount(1, "HBD"), quote=Amount(1, "HIVE"))
            if False
            else float(data["latest"]),
            "lowest_ask": float(data["lowest_ask"]),
            "highest_bid": float(data["highest_bid"]),
            "percent_change": float(data["percent_change"]),
            "hbd_volume": Amount(data.get("sbd_volume") or data.get("hbd_volume")),
            "hive_volume": Amount(data.get("steem_volume") or data.get("hive_volume")),
        }

    def volume24h(self, raw_data=False):
        data = self.rpc.call("condenser_api.get_volume", [])
        if raw_data:
            return data
        return {
            "HBD": Amount(data.get("sbd_volume") or data.get("hbd_volume")),
            "HIVE": Amount(data.get("steem_volume") or data.get("hive_volume")),
        }

    def orderbook(self, limit=25, raw_data=False):
        data = self.rpc.call("condenser_api.get_order_book", [limit])
        if raw_data:
            return data
        return {
            "bids": [
                {
                    "price": float(entry["real_price"]),
                    "hive": Amount(entry["steem"] / 1000, "HIVE"),
                    "hbd": Amount(entry["sbd"] / 1000, "HBD"),
                }
                for entry in data.get("bids", [])
            ],
            "asks": [
                {
                    "price": float(entry["real_price"]),
                    "hive": Amount(entry["steem"] / 1000, "HIVE"),
                    "hbd": Amount(entry["sbd"] / 1000, "HBD"),
                }
                for entry in data.get("asks", [])
            ],
        }

    def recent_trades(self, limit=25, raw_data=False):
        data = self.rpc.call("condenser_api.get_recent_trades", [limit])
        if raw_data:
            return data
        return [FilledOrder(entry) for entry in data or []]

    trades = recent_trades

    def trade_history(self, start=None, stop=None, limit=25, raw_data=False):
        return self.recent_trades(limit=limit, raw_data=raw_data)

    def market_history(self, bucket_seconds=300, start_age=3600, end_age=0, raw_data=False):
        now = int(time.time())
        return self.rpc.call(
            "condenser_api.get_market_history",
            [
                bucket_seconds,
                _iso(now - start_age),
                _iso(now - end_age),
            ],
        )

    def market_history_buckets(self):
        return self.rpc.call("condenser_api.get_market_history_buckets", [])

    def accountopenorders(self, account=None, raw_data=False):
        if account is None:
            raise ValueError("accountopenorders needs an account")
        name = getattr(account, "name", str(account))
        data = self.rpc.call("condenser_api.get_open_orders", [name])
        if raw_data:
            return data
        return [Order(entry) for entry in data or []]

    # -- trading -----------------------------------------------------------

    def buy(self, price, amount, expiration=None, killfill=False, account=None,
            orderid=None, **kwargs):
        """Buy HIVE with HBD at ``price`` HBD per HIVE."""
        return self._order(
            account, amount_to_sell=Amount(float(price) * float(amount), "HBD"),
            min_to_receive=Amount(amount, "HIVE"), expiration=expiration,
            killfill=killfill, orderid=orderid, **kwargs
        )

    def sell(self, price, amount, expiration=None, killfill=False, account=None,
             orderid=None, **kwargs):
        """Sell HIVE for HBD at ``price`` HBD per HIVE."""
        return self._order(
            account, amount_to_sell=Amount(amount, "HIVE"),
            min_to_receive=Amount(float(price) * float(amount), "HBD"),
            expiration=expiration, killfill=killfill, orderid=orderid, **kwargs
        )

    def _order(self, account, amount_to_sell, min_to_receive, expiration, killfill,
               orderid, **kwargs):
        if account is None:
            raise ValueError("an order needs an account")
        name = getattr(account, "name", str(account))
        seconds = int(expiration if expiration else 7 * 24 * 3600)
        return self.blockchain.finalizeOp(
            (
                "limit_order_create",
                {
                    "owner": name,
                    "orderid": int(orderid if orderid is not None else time.time()),
                    "amount_to_sell": str(amount_to_sell),
                    "min_to_receive": str(min_to_receive),
                    "fill_or_kill": bool(killfill),
                    "expiration": _iso(int(time.time()) + seconds),
                },
            ),
            account=name,
            **kwargs,
        )

    def cancel(self, orderNumbers, account=None, **kwargs):
        if account is None:
            raise ValueError("cancel needs an account")
        name = getattr(account, "name", str(account))
        numbers = orderNumbers if isinstance(orderNumbers, (list, tuple)) else [orderNumbers]
        results = []
        for number in numbers:
            results.append(
                self.blockchain.finalizeOp(
                    ("limit_order_cancel", {"owner": name, "orderid": int(number)}),
                    account=name,
                    **kwargs,
                )
            )
        return results if len(results) > 1 else results[0]

    def hive_usd_implied(self):
        """HIVE in USD, implied by the market price and the HBD peg."""
        return self.ticker()["latest"]

    steem_usd_implied = hive_usd_implied

    def __repr__(self):
        return f"<Market {self.get_string()}>"


def _iso(unixtime):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(unixtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
