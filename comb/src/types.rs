//! Graphene wire-format primitives.
//!
//! Everything Hive signs is a byte string produced by these encoders, so a divergence
//! here does not fail loudly — it produces a valid-looking signature over the wrong
//! bytes, which the chain then rejects. That makes this the highest-risk module in the
//! crate and the one the differential digest oracle in `tests/` targets hardest.
//!
//! # Fixes relative to beem
//!
//! ### `String` no longer mangles control characters
//!
//! beem's `String.__bytes__` ran the payload through `unicodify()`:
//!
//! ```python
//! if (o <= 7) or (o == 11) or (o > 13 and o < 32):
//!     r.append("u%04x" % o)      # note: no backslash
//! elif o == 8:  r.append("b")    # note: no backslash
//! elif o == 12: r.append("f")    # note: no backslash
//! ```
//!
//! Those branches are missing their backslash, so a `0x01` byte was serialized as the
//! four *literal* characters `u0001`, and a backspace as the letter `b`. hived does no
//! such thing: a Graphene string is a varint length followed by the raw UTF-8 bytes.
//! Any `custom_json` payload or memo containing a control character therefore
//! serialized to different bytes in beem than on chain. We write the raw bytes.
//!
//! ### Length prefixes count bytes, and are bounded
//!
//! beem computed `varint(len(d))` where `d` was already the encoded bytes, which is
//! correct, but nothing anywhere bounded the length. A `String` longer than
//! `u32::MAX` would silently truncate through the varint. We return an error.
//!
//! ### Timestamps are parsed strictly, in UTC
//!
//! beem's `PointInTime` appended the literal text `"UTC"` to the input and parsed with
//! `%Y-%m-%dT%H:%M:%S%Z`, and in the `datetime` branch called `timegm(d.timetuple())`,
//! which reads a *timezone-aware, non-UTC* datetime as though its wall-clock fields
//! were UTC. That silently shifts a transaction's expiration by the UTC offset. Here
//! there is one representation — seconds since the Unix epoch, UTC — and parsing is
//! strict.
//!
//! ### Validation is not `assert`
//!
//! beem validated hash lengths with bare `assert` statements (`Sha256`, `Ripemd160`,
//! `Sha1` in `types.py`). Python strips those under `-O`, so the length checks vanish
//! in an optimised deployment. These are ordinary checked errors.

use crate::error::{Error, Result};
use time::{
    format_description::BorrowedFormatItem, macros::format_description, OffsetDateTime,
    PrimitiveDateTime,
};

/// The timestamp format Hive uses in JSON: `2026-08-22T14:30:00`, always UTC.
const HIVE_TIME_FORMAT: &[BorrowedFormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");

/// Anything that can be written in Graphene wire format.
pub trait GrapheneSerialize {
    /// Append this value's wire encoding to `out`.
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()>;

    /// Encode this value to a fresh buffer.
    fn to_wire(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.append_to(&mut out)?;
        Ok(out)
    }
}

/// Write a LEB128 varint.
///
/// Graphene's `unsigned_int` is a 7-bit-per-byte little-endian varint. hived caps it
/// at 32 bits; we take `u32` so the cap is in the type.
pub fn write_varint32(out: &mut Vec<u8>, mut n: u32) {
    while n >= 0x80 {
        out.push(((n & 0x7f) as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// Read a LEB128 varint, returning the value and the number of bytes consumed.
///
/// Unlike beem's `varintdecode`, this refuses an over-long encoding rather than
/// silently wrapping.
pub fn read_varint32(data: &[u8]) -> Result<(u32, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        if shift > 28 {
            return Err(Error::ser("varint32 is longer than 5 bytes"));
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            if result > u32::MAX as u64 {
                return Err(Error::ser("varint32 overflows 32 bits"));
            }
            return Ok((result as u32, i + 1));
        }
        shift += 7;
    }
    Err(Error::ser("truncated varint32"))
}

/// Write a length prefix, refusing lengths that do not fit the wire format.
fn write_len(out: &mut Vec<u8>, len: usize, what: &str) -> Result<()> {
    let len = u32::try_from(len)
        .map_err(|_| Error::ser(format!("{what} is longer than u32::MAX bytes")))?;
    write_varint32(out, len);
    Ok(())
}

pub fn write_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

pub fn write_bool(out: &mut Vec<u8>, v: bool) {
    out.push(u8::from(v));
}

pub fn write_i16(out: &mut Vec<u8>, v: i16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn write_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Write a Graphene string: varint byte length, then the raw UTF-8 bytes.
///
/// No escaping, no transformation. See the module docs for what beem did instead.
pub fn write_string(out: &mut Vec<u8>, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    write_len(out, bytes.len(), "string")?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Write a length-prefixed byte buffer.
pub fn write_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<()> {
    write_len(out, b.len(), "buffer")?;
    out.extend_from_slice(b);
    Ok(())
}

/// Write a fixed-width byte array with no length prefix (hashes, chain ids).
pub fn write_raw(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(b);
}

/// Write an array: varint element count, then each element.
pub fn write_array<T: GrapheneSerialize>(out: &mut Vec<u8>, items: &[T]) -> Result<()> {
    write_len(out, items.len(), "array")?;
    for item in items {
        item.append_to(out)?;
    }
    Ok(())
}

/// Write an `optional<T>`: a presence byte, then the value if present.
///
/// beem's `Optional.__bytes__` treated "serializes to zero bytes" as absent, which
/// conflates an empty value with a missing one. Presence here is exactly `Some`/`None`.
pub fn write_optional<T: GrapheneSerialize>(out: &mut Vec<u8>, v: Option<&T>) -> Result<()> {
    match v {
        None => {
            out.push(0);
            Ok(())
        }
        Some(inner) => {
            out.push(1);
            inner.append_to(out)
        }
    }
}

/// Write a static_variant: varint type tag, then the value.
pub fn write_static_variant<T: GrapheneSerialize>(
    out: &mut Vec<u8>,
    tag: u32,
    value: &T,
) -> Result<()> {
    write_varint32(out, tag);
    value.append_to(out)
}

/// A point in time on the Graphene wire: `uint32` seconds since the Unix epoch, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PointInTime(u32);

impl PointInTime {
    /// Construct from whole seconds since the Unix epoch.
    pub fn from_unix(secs: i64) -> Result<Self> {
        u32::try_from(secs)
            .map(PointInTime)
            .map_err(|_| Error::Time(format!("{secs} is outside the uint32 epoch range")))
    }

    /// Seconds since the Unix epoch.
    pub fn unix(&self) -> u32 {
        self.0
    }

    /// Parse Hive's JSON timestamp form, `YYYY-MM-DDTHH:MM:SS`, interpreted as UTC.
    ///
    /// A trailing `Z` is accepted because some nodes emit it; any other timezone
    /// suffix is refused rather than guessed at.
    pub fn parse(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        let core = trimmed.strip_suffix('Z').unwrap_or(trimmed);
        let dt = PrimitiveDateTime::parse(core, HIVE_TIME_FORMAT).map_err(|e| {
            Error::Time(format!("could not parse {core:?} as a Hive timestamp: {e}"))
        })?;
        Self::from_unix(dt.assume_utc().unix_timestamp())
    }

    /// The current time plus `seconds`, for use as a transaction expiration.
    pub fn now_plus(seconds: u32) -> Result<Self> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        Self::from_unix(now + i64::from(seconds))
    }

    /// Render in Hive's JSON timestamp form.
    pub fn to_iso(&self) -> Result<String> {
        let dt = OffsetDateTime::from_unix_timestamp(i64::from(self.0))
            .map_err(|e| Error::Time(e.to_string()))?;
        dt.format(HIVE_TIME_FORMAT)
            .map_err(|e| Error::Time(e.to_string()))
    }
}

impl GrapheneSerialize for PointInTime {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_u32(out, self.0);
        Ok(())
    }
}

/// Timestamps render in Hive's JSON form, `2026-08-22T14:30:00`.
impl serde::Serialize for PointInTime {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        s.serialize_str(&self.to_iso().map_err(S::Error::custom)?)
    }
}

impl GrapheneSerialize for String {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_string(out, self)
    }
}

impl GrapheneSerialize for u8 {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_u8(out, *self);
        Ok(())
    }
}

impl GrapheneSerialize for u16 {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_u16(out, *self);
        Ok(())
    }
}

impl GrapheneSerialize for u32 {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_u32(out, *self);
        Ok(())
    }
}

impl GrapheneSerialize for u64 {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_u64(out, *self);
        Ok(())
    }
}

impl<T: GrapheneSerialize> GrapheneSerialize for &T {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        (*self).append_to(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_matches_graphene_vectors() {
        let cases: &[(u32, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (300, &[0xac, 0x02]),
            (16383, &[0xff, 0x7f]),
            (16384, &[0x80, 0x80, 0x01]),
            (u32::MAX, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
        ];
        for (n, expected) in cases {
            let mut out = Vec::new();
            write_varint32(&mut out, *n);
            assert_eq!(&out[..], *expected, "varint({n})");
            assert_eq!(read_varint32(&out).unwrap(), (*n, expected.len()));
        }
    }

    #[test]
    fn varint_rejects_overlong_and_truncated() {
        assert!(read_varint32(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]).is_err());
        assert!(read_varint32(&[0x80]).is_err());
        assert!(read_varint32(&[]).is_err());
    }

    #[test]
    fn control_characters_are_written_verbatim() {
        // The regression test for beem's `unicodify`. A 0x01 byte must occupy exactly
        // one byte on the wire; beem expanded it to the five bytes `u0001` and then
        // length-prefixed *that*.
        let mut out = Vec::new();
        write_string(&mut out, "\u{1}").unwrap();
        assert_eq!(out, vec![0x01, 0x01]);

        let mut out = Vec::new();
        write_string(&mut out, "\u{8}").unwrap(); // backspace; beem wrote the letter 'b'
        assert_eq!(out, vec![0x01, 0x08]);

        let mut out = Vec::new();
        write_string(&mut out, "\u{c}").unwrap(); // form feed; beem wrote the letter 'f'
        assert_eq!(out, vec![0x01, 0x0c]);
    }

    #[test]
    fn string_length_counts_utf8_bytes_not_chars() {
        let mut out = Vec::new();
        // 'é' is two bytes, '🐝' is four.
        write_string(&mut out, "é🐝").unwrap();
        assert_eq!(out[0], 6);
        assert_eq!(out.len(), 7);
    }

    #[test]
    fn empty_string_is_a_single_zero() {
        let mut out = Vec::new();
        write_string(&mut out, "").unwrap();
        assert_eq!(out, vec![0x00]);
    }

    #[test]
    fn optional_distinguishes_empty_from_absent() {
        let mut absent = Vec::new();
        write_optional::<String>(&mut absent, None).unwrap();
        assert_eq!(absent, vec![0x00]);

        let mut empty = Vec::new();
        write_optional(&mut empty, Some(&String::new())).unwrap();
        // Present, with a zero-length string: beem collapsed this to `absent`.
        assert_eq!(empty, vec![0x01, 0x00]);
    }

    #[test]
    fn timestamps_parse_as_utc() {
        let t = PointInTime::parse("2026-08-22T14:30:00").unwrap();
        assert_eq!(t.unix(), 1787409000);
        assert_eq!(t.to_iso().unwrap(), "2026-08-22T14:30:00");
        // A trailing Z is the same instant, not an hour off.
        assert_eq!(PointInTime::parse("2026-08-22T14:30:00Z").unwrap(), t);
    }

    #[test]
    fn timestamps_serialize_little_endian_u32() {
        let t = PointInTime::from_unix(1).unwrap();
        assert_eq!(t.to_wire().unwrap(), vec![0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn timestamps_reject_junk_and_out_of_range() {
        assert!(PointInTime::parse("not a time").is_err());
        assert!(PointInTime::parse("2026-08-22 14:30:00").is_err());
        assert!(PointInTime::parse("2026-08-22T14:30:00+02:00").is_err());
        assert!(PointInTime::from_unix(-1).is_err());
        assert!(PointInTime::from_unix(i64::from(u32::MAX) + 1).is_err());
    }

    #[test]
    fn arrays_are_length_prefixed() {
        let mut out = Vec::new();
        write_array(&mut out, &["a".to_string(), "bb".to_string()]).unwrap();
        assert_eq!(out, vec![0x02, 0x01, b'a', 0x02, b'b', b'b']);
    }
}
