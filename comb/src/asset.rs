//! Assets and amounts.
//!
//! # Representation
//!
//! An [`Amount`] is an `i64` count of the asset's **smallest unit**, plus a precision
//! and a symbol. That is exactly how the chain represents it, so no conversion happens
//! anywhere: `1.234 HIVE` is stored as `1234` with precision `3`.
//!
//! beem instead stored a decimal amount and converted at the boundaries with:
//!
//! ```python
//! def value_to_decimal(value, decimal_places):
//!     decimal.getcontext().rounding = decimal.ROUND_DOWN
//!     return decimal.Decimal(str(float(value))).quantize(...)
//! ```
//!
//! Two problems, in two lines. `float(value)` pushes a monetary amount through an
//! IEEE-754 double before it reaches `Decimal` — which is the one thing `Decimal`
//! exists to avoid. And assigning to `decimal.getcontext()` mutates the **process
//! global** decimal context as a side effect of formatting an amount, silently
//! switching every unrelated `Decimal` operation in the host application to
//! `ROUND_DOWN`.
//!
//! Parsing here goes straight from the decimal string to an integer, with no floating
//! point step and no global state.
//!
//! # Wire format
//!
//! The legacy asset encoding is 16 bytes: `int64` amount, `uint8` precision, then a
//! 7-byte NUL-padded symbol. Hive kept Steem's binary symbols through the rename, so
//! `HIVE` goes on the wire as `STEEM` and `HBD` as `SBD`. That mapping lives in
//! [`crate::chains`], not inline at a call site.

use crate::chains::Chain;
use crate::error::{Error, Result};
use crate::types::{write_i64, write_raw, write_u8, GrapheneSerialize};
use std::fmt;

/// Width of the symbol field in the legacy asset encoding.
const SYMBOL_FIELD_LEN: usize = 7;

/// A quantity of a Hive asset, held as an integer count of its smallest unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount {
    /// Count of the smallest unit, e.g. 1234 for `1.234 HIVE`.
    units: i64,
    /// Decimal places, e.g. 3 for HIVE.
    precision: u8,
    /// Display symbol, e.g. `HIVE`.
    symbol: &'static str,
    /// Symbol as written in the legacy binary encoding, e.g. `STEEM`.
    wire_symbol: &'static str,
}

impl Amount {
    /// Build from a raw unit count and a symbol on the given chain.
    pub fn from_units(units: i64, symbol: &str, chain: Chain) -> Result<Self> {
        let asset = chain.asset(symbol)?;
        Ok(Amount {
            units,
            precision: asset.precision,
            symbol: asset.symbol,
            wire_symbol: asset.wire_symbol,
        })
    }

    /// Parse Hive's textual amount form, `"1.234 HIVE"`.
    ///
    /// The decimal string is converted to an integer directly. A value with more
    /// decimal places than the asset allows is an **error**, not a silent truncation:
    /// quietly dropping a digit from a monetary amount transfers a different sum than
    /// the caller asked for.
    pub fn parse(s: &str, chain: Chain) -> Result<Self> {
        let s = s.trim();
        let (number, symbol) = s
            .rsplit_once(char::is_whitespace)
            .ok_or_else(|| Error::field(format!("amount {s:?} has no symbol")))?;
        let number = number.trim();
        let symbol = symbol.trim();
        let asset = chain.asset(symbol)?;

        let (negative, digits) = match number.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, number.strip_prefix('+').unwrap_or(number)),
        };

        let (int_part, frac_part) = match digits.split_once('.') {
            Some((i, f)) => (i, f),
            None => (digits, ""),
        };

        if int_part.is_empty() && frac_part.is_empty() {
            return Err(Error::field(format!("amount {s:?} has no digits")));
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit())
            || !frac_part.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::field(format!(
                "amount {s:?} is not a decimal number"
            )));
        }
        if frac_part.len() > usize::from(asset.precision) {
            return Err(Error::field(format!(
                "{} has precision {}, but {s:?} carries {} decimal places",
                asset.symbol,
                asset.precision,
                frac_part.len()
            )));
        }

        // Right-pad the fraction to the asset's precision, then read the whole thing
        // as one integer. No float, no rounding, no global context.
        let mut combined = String::with_capacity(int_part.len() + usize::from(asset.precision));
        combined.push_str(int_part);
        combined.push_str(frac_part);
        for _ in frac_part.len()..usize::from(asset.precision) {
            combined.push('0');
        }

        let magnitude: i64 = combined
            .parse()
            .map_err(|_| Error::field(format!("amount {s:?} does not fit in a 64-bit integer")))?;
        let units = if negative {
            magnitude
                .checked_neg()
                .ok_or_else(|| Error::field("amount overflows i64"))?
        } else {
            magnitude
        };

        Ok(Amount {
            units,
            precision: asset.precision,
            symbol: asset.symbol,
            wire_symbol: asset.wire_symbol,
        })
    }

    /// The raw unit count.
    pub fn units(&self) -> i64 {
        self.units
    }

    /// The asset's decimal places.
    pub fn precision(&self) -> u8 {
        self.precision
    }

    /// The display symbol, e.g. `HIVE`.
    pub fn symbol(&self) -> &'static str {
        self.symbol
    }

    /// The symbol used in the legacy binary encoding, e.g. `STEEM`.
    pub fn wire_symbol(&self) -> &'static str {
        self.wire_symbol
    }

    /// Whether this is exactly zero.
    pub fn is_zero(&self) -> bool {
        self.units == 0
    }

    /// Add two amounts of the same asset. Refuses a mismatch rather than coercing.
    pub fn checked_add(&self, other: &Amount) -> Result<Amount> {
        self.require_same_asset(other)?;
        let units = self
            .units
            .checked_add(other.units)
            .ok_or_else(|| Error::field("amount addition overflows i64"))?;
        Ok(Amount { units, ..*self })
    }

    /// Subtract two amounts of the same asset.
    pub fn checked_sub(&self, other: &Amount) -> Result<Amount> {
        self.require_same_asset(other)?;
        let units = self
            .units
            .checked_sub(other.units)
            .ok_or_else(|| Error::field("amount subtraction overflows i64"))?;
        Ok(Amount { units, ..*self })
    }

    fn require_same_asset(&self, other: &Amount) -> Result<()> {
        if self.symbol != other.symbol {
            return Err(Error::field(format!(
                "cannot combine {} and {}",
                self.symbol, other.symbol
            )));
        }
        Ok(())
    }

    /// The NAI-style JSON form used by `database_api`:
    /// `{"amount": "1234", "precision": 3, "nai": "@@000000021"}`.
    pub fn to_nai_json(&self, chain: Chain) -> Result<serde_json::Value> {
        let asset = chain.asset(self.symbol)?;
        Ok(serde_json::json!({
            "amount": self.units.to_string(),
            "precision": self.precision,
            "nai": asset.nai,
        }))
    }
}

impl fmt::Display for Amount {
    /// Render as `"1.234 HIVE"`, always with exactly `precision` decimal places.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let negative = self.units < 0;
        let magnitude = self.units.unsigned_abs();
        let scale = 10u64.pow(u32::from(self.precision));
        let whole = magnitude / scale;
        let frac = magnitude % scale;
        if negative {
            f.write_str("-")?;
        }
        if self.precision == 0 {
            write!(f, "{whole} {}", self.symbol)
        } else {
            write!(
                f,
                "{whole}.{frac:0width$} {sym}",
                frac = frac,
                width = usize::from(self.precision),
                sym = self.symbol
            )
        }
    }
}

impl GrapheneSerialize for Amount {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        let symbol = self.wire_symbol.as_bytes();
        // beem built this as `self.symbol + "\x00" * (7 - len(self.symbol))`, which for
        // a symbol longer than 7 characters yields a negative repeat count, so Python
        // appends nothing and silently emits a field of the wrong length. Check it.
        if symbol.len() > SYMBOL_FIELD_LEN {
            return Err(Error::ser(format!(
                "asset symbol {:?} is {} bytes, which does not fit the {SYMBOL_FIELD_LEN}-byte field",
                self.wire_symbol,
                symbol.len()
            )));
        }
        write_i64(out, self.units);
        write_u8(out, self.precision);
        let mut field = [0u8; SYMBOL_FIELD_LEN];
        field[..symbol.len()].copy_from_slice(symbol);
        write_raw(out, &field);
        Ok(())
    }
}

impl crate::reader::GrapheneDeserialize for Amount {
    /// Read the 16-byte legacy asset: `int64` units, `uint8` precision, 7-byte
    /// NUL-padded symbol.
    ///
    /// The symbol is resolved against the reader's chain and cross-checked: an asset
    /// whose declared precision disagrees with the chain's is refused rather than
    /// silently reinterpreted, because that mismatch means the bytes are not the asset
    /// they claim to be.
    fn read_from(r: &mut crate::reader::Reader<'_>) -> Result<Self> {
        let units = r.i64()?;
        let precision = r.u8()?;
        let raw = r.raw(SYMBOL_FIELD_LEN)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(SYMBOL_FIELD_LEN);
        if raw[end..].iter().any(|&b| b != 0) {
            return Err(Error::ser("asset symbol has data after its NUL terminator"));
        }
        let symbol = std::str::from_utf8(&raw[..end])
            .map_err(|_| Error::ser("asset symbol is not valid UTF-8"))?;
        let asset = r.chain().asset(symbol)?;
        if asset.precision != precision {
            return Err(Error::ser(format!(
                "asset {symbol} declares precision {precision}, but the chain uses {}",
                asset.precision
            )));
        }
        Ok(Amount {
            units,
            precision,
            symbol: asset.symbol,
            wire_symbol: asset.wire_symbol,
        })
    }
}

/// Amounts arrive from the API in two different shapes, and both are accepted.
///
/// `condenser_api` and the legacy forms send the textual `"1.234 HIVE"`. `database_api`
/// and `account_history_api` in appbase mode send the NAI object
/// `{"amount": "1234", "precision": 3, "nai": "@@000000021"}`. beem handled both too,
/// but by branching on `isinstance` inside `Amount.__init__` across four cases.
///
/// Deserialization resolves symbols against **Hive mainnet**. For a testnet, decode
/// the raw JSON and use [`Amount::from_units`] with the right chain.
impl<'de> serde::Deserialize<'de> for Amount {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;

        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Text(String),
            Nai {
                amount: NaiAmount,
                precision: u8,
                nai: String,
            },
        }

        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum NaiAmount {
            // hived sends the unit count as a string to survive JSON's 53-bit number
            // limit -- the same limit that corrupts beem's float parsing (finding 16).
            Text(String),
            Number(i64),
        }

        match Repr::deserialize(d)? {
            Repr::Text(text) => Amount::parse(&text, Chain::Hive).map_err(D::Error::custom),
            Repr::Nai {
                amount,
                precision,
                nai,
            } => {
                let units = match amount {
                    NaiAmount::Text(t) => t.parse::<i64>().map_err(D::Error::custom)?,
                    NaiAmount::Number(n) => n,
                };
                let asset = Chain::Hive.asset(&nai).map_err(D::Error::custom)?;
                if asset.precision != precision {
                    return Err(D::Error::custom(format!(
                        "asset {nai} declares precision {precision}, chain uses {}",
                        asset.precision
                    )));
                }
                Ok(Amount {
                    units,
                    precision,
                    symbol: asset.symbol,
                    wire_symbol: asset.wire_symbol,
                })
            }
        }
    }
}

/// Amounts render in Hive's textual form, `"1.234 HIVE"`, which is what
/// `condenser_api` and `network_broadcast_api` accept.
impl serde::Serialize for Amount {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_without_touching_floats() {
        let a = Amount::parse("1.234 HIVE", Chain::Hive).unwrap();
        assert_eq!(a.units(), 1234);
        assert_eq!(a.precision(), 3);
        assert_eq!(a.symbol(), "HIVE");
        assert_eq!(a.to_string(), "1.234 HIVE");
    }

    #[test]
    fn parses_values_a_float_would_corrupt() {
        // 0.1 + 0.2 style trouble, and a magnitude beyond a double's 53-bit mantissa.
        for (text, units) in [
            ("0.001 HIVE", 1i64),
            ("0.007 HIVE", 7),
            ("9007199254740.993 HIVE", 9_007_199_254_740_993),
            ("0.000001 VESTS", 1),
            ("123456789.123456 VESTS", 123_456_789_123_456),
        ] {
            let a = Amount::parse(text, Chain::Hive).unwrap();
            assert_eq!(a.units(), units, "parsing {text}");
            assert_eq!(a.to_string(), text, "rendering {text}");
        }
    }

    #[test]
    fn pads_short_fractions_to_full_precision() {
        assert_eq!(
            Amount::parse("1.5 HIVE", Chain::Hive).unwrap().units(),
            1500
        );
        assert_eq!(Amount::parse("1 HIVE", Chain::Hive).unwrap().units(), 1000);
        assert_eq!(Amount::parse("1. HIVE", Chain::Hive).unwrap().units(), 1000);
    }

    #[test]
    fn refuses_excess_precision_instead_of_truncating() {
        // beem's ROUND_DOWN quantize would silently turn this into 1.234 HIVE.
        let e = Amount::parse("1.2345 HIVE", Chain::Hive).unwrap_err();
        assert!(format!("{e}").contains("precision"));
        assert!(Amount::parse("0.0000001 VESTS", Chain::Hive).is_err());
    }

    #[test]
    fn handles_negatives_and_zero() {
        let neg = Amount::parse("-1.234 HIVE", Chain::Hive).unwrap();
        assert_eq!(neg.units(), -1234);
        assert_eq!(neg.to_string(), "-1.234 HIVE");
        let zero = Amount::parse("0.000 HIVE", Chain::Hive).unwrap();
        assert!(zero.is_zero());
        assert_eq!(zero.to_string(), "0.000 HIVE");
    }

    #[test]
    fn rejects_junk() {
        for bad in [
            "HIVE",
            "1.2.3 HIVE",
            "abc HIVE",
            "1.234 DOGE",
            "1.234",
            "- HIVE",
            "",
        ] {
            assert!(
                Amount::parse(bad, Chain::Hive).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn serializes_with_the_legacy_wire_symbol() {
        // The rename never reached the binary format: HIVE is STEEM on the wire.
        let a = Amount::parse("1.000 HIVE", Chain::Hive).unwrap();
        let wire = a.to_wire().unwrap();
        assert_eq!(wire.len(), 16);
        assert_eq!(&wire[0..8], &1000i64.to_le_bytes());
        assert_eq!(wire[8], 3, "precision");
        assert_eq!(&wire[9..16], b"STEEM\0\0");

        let hbd = Amount::parse("2.500 HBD", Chain::Hive).unwrap();
        assert_eq!(&hbd.to_wire().unwrap()[9..16], b"SBD\0\0\0\0");

        let vests = Amount::parse("1.000000 VESTS", Chain::Hive).unwrap();
        let w = vests.to_wire().unwrap();
        assert_eq!(w[8], 6);
        assert_eq!(&w[9..16], b"VESTS\0\0");
    }

    #[test]
    fn arithmetic_refuses_mismatched_assets() {
        let hive = Amount::parse("1.000 HIVE", Chain::Hive).unwrap();
        let hbd = Amount::parse("1.000 HBD", Chain::Hive).unwrap();
        assert!(hive.checked_add(&hbd).is_err());
        assert_eq!(hive.checked_add(&hive).unwrap().units(), 2000);
        assert_eq!(hive.checked_sub(&hive).unwrap().units(), 0);
    }

    #[test]
    fn accepts_the_wire_symbol_as_input_too() {
        // Account history still returns legacy symbols in places.
        let a = Amount::parse("1.000 STEEM", Chain::Hive).unwrap();
        assert_eq!(a.symbol(), "HIVE");
    }

    #[test]
    fn wire_round_trip() {
        use crate::reader::{GrapheneDeserialize, Reader};
        for text in [
            "1.234 HIVE",
            "-1.234 HIVE",
            "0.000 HBD",
            "9007199254740.993 HIVE",
            "123456789012.345678 VESTS",
        ] {
            let a = Amount::parse(text, Chain::Hive).unwrap();
            let wire = a.to_wire().unwrap();
            let mut r = Reader::new(&wire, Chain::Hive);
            let back = Amount::read_from(&mut r).unwrap();
            r.expect_end().unwrap();
            assert_eq!(back, a, "round trip of {text}");
            assert_eq!(back.to_string(), text);
        }
    }

    #[test]
    fn a_mismatched_precision_is_refused_on_read() {
        use crate::reader::{GrapheneDeserialize, Reader};
        let mut wire = Amount::parse("1.000 HIVE", Chain::Hive)
            .unwrap()
            .to_wire()
            .unwrap();
        wire[8] = 6; // claim VESTS precision on a STEEM symbol
        let mut r = Reader::new(&wire, Chain::Hive);
        assert!(Amount::read_from(&mut r).is_err());
    }

    #[test]
    fn an_unknown_symbol_is_refused_on_read() {
        use crate::reader::{GrapheneDeserialize, Reader};
        let mut wire = Amount::parse("1.000 HIVE", Chain::Hive)
            .unwrap()
            .to_wire()
            .unwrap();
        wire[9..16].copy_from_slice(b"DOGE\0\0\0");
        let mut r = Reader::new(&wire, Chain::Hive);
        assert!(Amount::read_from(&mut r).is_err());
    }

    #[test]
    fn json_accepts_both_the_textual_and_nai_forms() {
        let from_text: Amount = serde_json::from_str(r#""1.234 HIVE""#).unwrap();
        assert_eq!(from_text.units(), 1234);

        let from_nai: Amount =
            serde_json::from_str(r#"{"amount":"1234","precision":3,"nai":"@@000000021"}"#).unwrap();
        assert_eq!(from_nai, from_text);

        // A numeric (rather than string) amount is also accepted.
        let numeric: Amount =
            serde_json::from_str(r#"{"amount":1234,"precision":3,"nai":"@@000000021"}"#).unwrap();
        assert_eq!(numeric, from_text);
    }

    #[test]
    fn json_keeps_full_precision_on_large_nai_amounts() {
        // hived sends the unit count as a string precisely so it survives JSON's
        // 53-bit number limit. This is the value beem's float path corrupts.
        let big: Amount = serde_json::from_str(
            r#"{"amount":"123456789012345678","precision":6,"nai":"@@000000037"}"#,
        )
        .unwrap();
        assert_eq!(big.units(), 123_456_789_012_345_678);
        assert_eq!(big.to_string(), "123456789012.345678 VESTS");
    }

    #[test]
    fn json_rejects_a_mismatched_precision_or_unknown_nai() {
        assert!(serde_json::from_str::<Amount>(
            r#"{"amount":"1","precision":9,"nai":"@@000000021"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Amount>(
            r#"{"amount":"1","precision":3,"nai":"@@999999999"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Amount>(r#""1.234 DOGE""#).is_err());
    }

    #[test]
    fn nai_json_form() {
        let a = Amount::parse("1.234 HIVE", Chain::Hive).unwrap();
        let j = a.to_nai_json(Chain::Hive).unwrap();
        assert_eq!(j["amount"], "1234");
        assert_eq!(j["precision"], 3);
        assert_eq!(j["nai"], "@@000000021");
    }
}
