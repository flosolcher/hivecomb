"""Amounts.

Drop-in for `beem.amount.Amount`.

**Fixed relative to beem.** beem's `Amount` converted through ``float()`` before
reaching ``Decimal`` and mutated the *process-global* decimal rounding context as
a side effect of formatting (finding 16). This one holds an integer count of the
asset's smallest unit — the same representation the chain uses — and touches
neither float nor global state.
"""

from __future__ import annotations

from decimal import Decimal

from .exceptions import AssetDoesNotExistsException, InvalidAssetException

__all__ = ["Amount"]

#: Decimal places per asset, and the symbol each uses in the binary format.
#: Hive kept Steem's wire symbols through the rename.
ASSETS = {
    "HIVE": (3, "STEEM", "@@000000021"),
    "HBD": (3, "SBD", "@@000000013"),
    "VESTS": (6, "VESTS", "@@000000037"),
    # Legacy spellings still returned by some endpoints.
    "STEEM": (3, "STEEM", "@@000000021"),
    "SBD": (3, "SBD", "@@000000013"),
}

NAI_TO_SYMBOL = {
    "@@000000021": "HIVE",
    "@@000000013": "HBD",
    "@@000000037": "VESTS",
}


class Amount:
    """A quantity of a Hive asset.

    Accepts every form beem did: ``Amount("1.234 HIVE")``,
    ``Amount(1.234, "HIVE")``, ``Amount({"amount": "1234", "precision": 3,
    "nai": "@@000000021"})``, and another ``Amount``.
    """

    def __init__(self, amount=None, asset=None, **kwargs):
        kwargs.pop("blockchain_instance", None)
        kwargs.pop("steem_instance", None)
        kwargs.pop("hive_instance", None)

        if isinstance(amount, Amount):
            self.symbol = amount.symbol
            self.precision = amount.precision
            self._units = amount._units
            return

        if isinstance(amount, dict):
            nai = amount.get("nai")
            symbol = NAI_TO_SYMBOL.get(nai)
            if symbol is None:
                raise AssetDoesNotExistsException(f"unknown NAI {nai!r}")
            self.symbol = symbol
            self.precision = int(amount["precision"])
            # hived sends the count as a string precisely so it survives JSON's
            # 53-bit limit -- the same limit that corrupts beem's float path.
            self._units = int(amount["amount"])
            return

        if isinstance(amount, str) and asset is None:
            text = amount.strip()
            if " " not in text:
                raise InvalidAssetException(f"{amount!r} has no asset symbol")
            number, symbol = text.rsplit(" ", 1)
            self.symbol, self.precision = _resolve(symbol)
            self._units = _to_units(number, self.precision)
            return

        if amount is None:
            raise InvalidAssetException("Amount() needs a value")

        self.symbol, self.precision = _resolve(str(asset))
        self._units = _to_units(amount, self.precision)

    # -- accessors ---------------------------------------------------------

    @property
    def amount(self):
        """The value as a :class:`float`.

        Provided because beem's callers expect it. **Do not compute a transfer
        from it** — use :attr:`amount_decimal` or :meth:`units`, which are exact.
        """
        return float(self.amount_decimal)

    @property
    def amount_decimal(self):
        """The value as an exact :class:`~decimal.Decimal`."""
        return Decimal(self._units).scaleb(-self.precision)

    def units(self):
        """The integer count of the asset's smallest unit."""
        return self._units

    @property
    def asset(self):
        return {"symbol": self.symbol, "precision": self.precision}

    def json(self):
        """The NAI object form `database_api` uses."""
        return {
            "amount": str(self._units),
            "precision": self.precision,
            "nai": ASSETS[self.symbol][2],
        }

    def tuple(self):
        return (self.amount, self.symbol)

    # -- rendering ---------------------------------------------------------

    def __str__(self):
        sign = "-" if self._units < 0 else ""
        magnitude = abs(self._units)
        scale = 10 ** self.precision
        whole, frac = divmod(magnitude, scale)
        if self.precision == 0:
            return f"{sign}{whole} {self.symbol}"
        return f"{sign}{whole}.{frac:0{self.precision}d} {self.symbol}"

    def __repr__(self):
        return f"<Amount {self}>"

    def __float__(self):
        return self.amount

    def __int__(self):
        return self._units

    # -- arithmetic --------------------------------------------------------

    def _same(self, other):
        other = other if isinstance(other, Amount) else Amount(other, self.symbol)
        if other.symbol != self.symbol:
            raise InvalidAssetException(f"cannot combine {self.symbol} and {other.symbol}")
        return other

    def _from_units(self, units):
        result = Amount.__new__(Amount)
        result.symbol = self.symbol
        result.precision = self.precision
        result._units = units
        return result

    def __add__(self, other):
        return self._from_units(self._units + self._same(other)._units)

    def __sub__(self, other):
        return self._from_units(self._units - self._same(other)._units)

    def __mul__(self, other):
        if isinstance(other, Amount):
            raise InvalidAssetException("cannot multiply two amounts")
        return self._from_units(int(Decimal(self._units) * Decimal(str(other))))

    def __truediv__(self, other):
        if isinstance(other, Amount):
            return self.amount_decimal / self._same(other).amount_decimal
        return self._from_units(int(Decimal(self._units) / Decimal(str(other))))

    def __neg__(self):
        return self._from_units(-self._units)

    def __abs__(self):
        return self._from_units(abs(self._units))

    def __eq__(self, other):
        try:
            return self._units == self._same(other)._units
        except (InvalidAssetException, AssetDoesNotExistsException):
            return NotImplemented

    def __lt__(self, other):
        return self._units < self._same(other)._units

    def __le__(self, other):
        return self._units <= self._same(other)._units

    def __gt__(self, other):
        return self._units > self._same(other)._units

    def __ge__(self, other):
        return self._units >= self._same(other)._units

    def __hash__(self):
        return hash((self.symbol, self._units))


def _resolve(symbol):
    symbol = str(symbol).upper()
    if symbol in NAI_TO_SYMBOL:
        symbol = NAI_TO_SYMBOL[symbol]
    if symbol not in ASSETS:
        raise AssetDoesNotExistsException(f"unknown asset {symbol!r}")
    precision = ASSETS[symbol][0]
    # Normalise the legacy spellings to the modern ones.
    if symbol == "STEEM":
        symbol = "HIVE"
    elif symbol == "SBD":
        symbol = "HBD"
    return symbol, precision


def _to_units(value, precision):
    """Convert a decimal value to integer units, exactly.

    Excess precision is an error rather than a silent truncation: quietly
    dropping a digit from a monetary amount transfers a different sum than the
    caller asked for. beem's ``ROUND_DOWN`` quantize did exactly that.
    """
    if isinstance(value, int):
        return value * 10 ** precision
    decimal_value = Decimal(str(value).strip())
    scaled = decimal_value.scaleb(precision)
    if scaled != scaled.to_integral_value():
        raise InvalidAssetException(
            f"{value} has more than {precision} decimal places for this asset"
        )
    return int(scaled)
