"""Prices.

Drop-in for `beem.price.Price`. A ratio of two :class:`~beem.amount.Amount`
values, e.g. ``0.250 HBD / 1.000 HIVE``.

Arithmetic is done on exact :class:`~decimal.Decimal` values rather than floats.
"""

from __future__ import annotations

from decimal import Decimal

from .amount import Amount
from .exceptions import InvalidAssetException

__all__ = ["Price", "Order", "FilledOrder"]


class Price(dict):
    """The price of ``base`` expressed per unit of ``quote``."""

    def __init__(self, price=None, base=None, quote=None, base_asset=None, **kwargs):
        if isinstance(price, Price):
            base, quote = price["base"], price["quote"]
        elif isinstance(price, dict) and "base" in price:
            base, quote = Amount(price["base"]), Amount(price["quote"])
        elif isinstance(price, str) and base is None:
            # "0.250 HBD/HIVE"
            value, pair = price.split(" ", 1) if " " in price else (price, "")
            if "/" not in pair:
                raise InvalidAssetException(f"cannot read {price!r} as a price")
            base_symbol, quote_symbol = pair.split("/", 1)
            base = Amount(value, base_symbol.strip())
            quote = Amount(1, quote_symbol.strip())
        elif price is not None and base is not None and quote is None:
            raise InvalidAssetException("Price(value, base=, quote=) needs both sides")

        if base is None or quote is None:
            raise InvalidAssetException("a price needs a base and a quote")

        base = base if isinstance(base, Amount) else Amount(base)
        quote = quote if isinstance(quote, Amount) else Amount(quote)
        super().__init__({"base": base, "quote": quote})

    @property
    def base(self):
        return self["base"]

    @property
    def quote(self):
        return self["quote"]

    def symbols(self):
        return (self.base.symbol, self.quote.symbol)

    def as_base(self, symbol):
        """This price with ``symbol`` as the base, inverting if needed."""
        if symbol == self.base.symbol:
            return self
        if symbol == self.quote.symbol:
            return self.invert()
        raise InvalidAssetException(f"{symbol} is not part of this price")

    def as_quote(self, symbol):
        if symbol == self.quote.symbol:
            return self
        if symbol == self.base.symbol:
            return self.invert()
        raise InvalidAssetException(f"{symbol} is not part of this price")

    def invert(self):
        return Price(base=self.quote, quote=self.base)

    def json(self):
        return {"base": str(self.base), "quote": str(self.quote)}

    def copy(self):
        return Price(base=self.base, quote=self.quote)

    def __float__(self):
        if self.quote.units() == 0:
            raise ZeroDivisionError("price has a zero quote")
        return float(self.base.amount_decimal / self.quote.amount_decimal)

    def _ratio(self):
        if self.quote.units() == 0:
            raise ZeroDivisionError("price has a zero quote")
        return self.base.amount_decimal / self.quote.amount_decimal

    def __repr__(self):
        return f"<Price {self.base} / {self.quote}>"

    def __str__(self):
        return f"{self._ratio()} {self.base.symbol}/{self.quote.symbol}"

    def __mul__(self, other):
        if isinstance(other, Amount):
            if other.symbol == self.quote.symbol:
                units = int(Decimal(other.units()) * self._ratio()
                            * Decimal(10) ** (self.base.precision - other.precision))
                return Amount(Decimal(units).scaleb(-self.base.precision), self.base.symbol)
            raise InvalidAssetException(
                f"cannot apply a {self.base.symbol}/{self.quote.symbol} price to "
                f"{other.symbol}"
            )
        return Price(base=self.base * other, quote=self.quote)

    def __truediv__(self, other):
        if isinstance(other, Price):
            return self._ratio() / other._ratio()
        return Price(base=self.base / other, quote=self.quote)

    def _cmp(self, other):
        other = other if isinstance(other, Price) else Price(other)
        return self._ratio(), other._ratio()

    def __eq__(self, other):
        try:
            a, b = self._cmp(other)
        except Exception:
            return NotImplemented
        return a == b

    def __lt__(self, other):
        a, b = self._cmp(other)
        return a < b

    def __le__(self, other):
        a, b = self._cmp(other)
        return a <= b

    def __gt__(self, other):
        a, b = self._cmp(other)
        return a > b

    def __ge__(self, other):
        a, b = self._cmp(other)
        return a >= b

    def __hash__(self):
        return hash((self.base.symbol, self.quote.symbol, str(self._ratio())))


class Order(Price):
    """An open order on the internal market."""

    def __init__(self, base, quote=None, **kwargs):
        if isinstance(base, dict) and "sell_price" in base:
            data = base["sell_price"]
            super().__init__(base=Amount(data["base"]), quote=Amount(data["quote"]))
            self.order = base
        else:
            super().__init__(base=base, quote=quote)
            self.order = {}

    def __repr__(self):
        return f"<Order {self.base} for {self.quote}>"


class FilledOrder(Price):
    """A completed trade."""

    def __init__(self, order, **kwargs):
        if isinstance(order, dict) and "current_pays" in order:
            super().__init__(
                base=Amount(order["open_pays"]), quote=Amount(order["current_pays"])
            )
            self.time = order.get("date")
            self.order = order
        else:
            raise InvalidAssetException("FilledOrder needs a fill_order record")

    def __repr__(self):
        return f"<FilledOrder {self.base} for {self.quote} at {self.time}>"
