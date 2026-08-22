//! Reading the Graphene wire format.
//!
//! The counterpart to [`crate::types`]. Having both directions is worth more than the
//! sum of the parts: a **round-trip property test** — serialize, deserialize,
//! serialize again, compare — catches encoder bugs that no hand-written expectation
//! will, because it exercises every field of every operation without anyone having to
//! remember to write an assertion for it.
//!
//! beem has an asymmetric story here. It serializes through `GrapheneObject` and
//! deserializes, partially, through a separate `unsignedtransactions.py` that shares no
//! code with it, so the two can and do disagree.
//!
//! # Reading is where hostile input arrives
//!
//! Serialization takes values the caller built. Deserialization takes **bytes off the
//! network**. Every read here is bounds-checked and every length is validated against
//! the remaining buffer before allocating, so a truncated or malicious payload produces
//! an error rather than a panic or a multi-gigabyte allocation.

use crate::chains::Chain;
use crate::error::{Error, Result};
use crate::types::PointInTime;

/// A cursor over Graphene-encoded bytes.
#[derive(Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    chain: Chain,
}

/// Anything that can be read back from the Graphene wire format.
pub trait GrapheneDeserialize: Sized {
    /// Read one value, advancing the reader past its bytes.
    fn read_from(r: &mut Reader<'_>) -> Result<Self>;
}

impl<'a> Reader<'a> {
    /// A reader over `data`, resolving assets against `chain`.
    pub fn new(data: &'a [u8], chain: Chain) -> Self {
        Reader {
            data,
            pos: 0,
            chain,
        }
    }

    /// The chain whose asset table this reader resolves symbols against.
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Whether every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Current offset, for error messages.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Fail unless the whole buffer was consumed.
    ///
    /// Trailing bytes mean the sender and this decoder disagree about the shape of the
    /// message, which is exactly the condition that must not be ignored.
    pub fn expect_end(&self) -> Result<()> {
        if !self.is_empty() {
            return Err(Error::ser(format!(
                "{} trailing bytes after the decoded value",
                self.remaining()
            )));
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::ser(format!(
                "unexpected end of input at offset {}: wanted {n} bytes, {} remain",
                self.pos,
                self.remaining()
            )));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a bool. Any byte other than `0` or `1` is an error, as in hived.
    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            // hived writes exactly 0 or 1. Anything else means we are misaligned.
            other => Err(Error::ser(format!(
                "bool at offset {} is {other}, expected 0 or 1",
                self.pos - 1
            ))),
        }
    }

    /// Read a little-endian unsigned 16-bit integer.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    /// Read a little-endian signed 16-bit integer.
    pub fn i16(&mut self) -> Result<i16> {
        Ok(i16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    /// Read a little-endian unsigned 32-bit integer.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    /// Read a little-endian unsigned 64-bit integer.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// Read a little-endian signed 64-bit integer.
    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// Read a fixed-width byte array with no length prefix.
    pub fn raw(&mut self, n: usize) -> Result<Vec<u8>> {
        Ok(self.take(n)?.to_vec())
    }

    /// Read a LEB128 varint.
    pub fn varint32(&mut self) -> Result<u32> {
        let (value, used) = crate::types::read_varint32(&self.data[self.pos..])?;
        self.pos += used;
        Ok(value)
    }

    /// Read a varint length, checked against what is actually left.
    ///
    /// This is the allocation guard: a corrupt or hostile length of 4 billion must not
    /// become a 4 GB `Vec::with_capacity` before the read fails.
    fn length(&mut self, what: &str) -> Result<usize> {
        let len = self.varint32()? as usize;
        if len > self.remaining() {
            return Err(Error::ser(format!(
                "{what} claims {len} bytes but only {} remain",
                self.remaining()
            )));
        }
        Ok(len)
    }

    /// Read a length-prefixed byte buffer.
    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.length("buffer")?;
        self.raw(len)
    }

    /// Read a length-prefixed UTF-8 string.
    pub fn string(&mut self) -> Result<String> {
        let len = self.length("string")?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| Error::ser(format!("string is not valid UTF-8: {e}")))
    }

    /// Read a `uint32` timestamp.
    pub fn point_in_time(&mut self) -> Result<PointInTime> {
        PointInTime::from_unix(i64::from(self.u32()?))
    }

    /// Read a length-prefixed array.
    ///
    /// The count is checked against the remaining bytes before allocating: every
    /// element occupies at least one byte, so a count larger than the buffer is
    /// impossible and is refused rather than reserved for.
    pub fn array<T: GrapheneDeserialize>(&mut self) -> Result<Vec<T>> {
        let count = self.length("array")?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(T::read_from(self)?);
        }
        Ok(out)
    }

    /// Read an array with an explicit element reader, for types needing context.
    pub fn array_with<T>(
        &mut self,
        mut read: impl FnMut(&mut Reader<'_>) -> Result<T>,
    ) -> Result<Vec<T>> {
        let count = self.length("array")?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(read(self)?);
        }
        Ok(out)
    }

    /// Read an `optional<T>`: a presence byte, then the value if present.
    pub fn optional<T: GrapheneDeserialize>(&mut self) -> Result<Option<T>> {
        if self.bool()? {
            Ok(Some(T::read_from(self)?))
        } else {
            Ok(None)
        }
    }

    /// Read an optional with an explicit reader.
    pub fn optional_with<T>(
        &mut self,
        read: impl FnOnce(&mut Reader<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        if self.bool()? {
            Ok(Some(read(self)?))
        } else {
            Ok(None)
        }
    }
}

impl GrapheneDeserialize for String {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        r.string()
    }
}

impl GrapheneDeserialize for u16 {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        r.u16()
    }
}

impl GrapheneDeserialize for u64 {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        r.u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{write_array, write_string, write_varint32, GrapheneSerialize};

    #[test]
    fn reads_primitives_back() {
        let mut buf = Vec::new();
        crate::types::write_u8(&mut buf, 7);
        crate::types::write_u16(&mut buf, 1000);
        crate::types::write_i16(&mut buf, -1000);
        crate::types::write_u32(&mut buf, 70000);
        crate::types::write_i64(&mut buf, -1234567890123);
        write_string(&mut buf, "héllo 🐝").unwrap();
        crate::types::write_bool(&mut buf, true);

        let mut r = Reader::new(&buf, Chain::Hive);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u16().unwrap(), 1000);
        assert_eq!(r.i16().unwrap(), -1000);
        assert_eq!(r.u32().unwrap(), 70000);
        assert_eq!(r.i64().unwrap(), -1234567890123);
        assert_eq!(r.string().unwrap(), "héllo 🐝");
        assert!(r.bool().unwrap());
        r.expect_end().unwrap();
    }

    #[test]
    fn truncated_input_errors_rather_than_panics() {
        for len in 0..4 {
            let buf = vec![0xffu8; len];
            let mut r = Reader::new(&buf, Chain::Hive);
            assert!(r.u32().is_err(), "u32 from {len} bytes must fail");
        }
        let mut r = Reader::new(&[], Chain::Hive);
        assert!(r.u8().is_err());
        assert!(r.string().is_err());
    }

    #[test]
    fn an_oversized_length_is_refused_before_allocating() {
        // varint for 4_000_000_000, then nothing. A naive decoder would try to
        // reserve four gigabytes.
        let mut buf = Vec::new();
        write_varint32(&mut buf, 4_000_000_000);
        let mut r = Reader::new(&buf, Chain::Hive);
        let err = r.string().unwrap_err();
        assert!(format!("{err}").contains("only"));

        let mut buf = Vec::new();
        write_varint32(&mut buf, u32::MAX);
        let mut r = Reader::new(&buf, Chain::Hive);
        assert!(r.array::<String>().is_err());
    }

    #[test]
    fn trailing_bytes_are_an_error() {
        let buf = [1u8, 2, 3];
        let mut r = Reader::new(&buf, Chain::Hive);
        r.u8().unwrap();
        assert!(r.expect_end().is_err());
    }

    #[test]
    fn a_bool_that_is_not_zero_or_one_is_a_misalignment() {
        let buf = [7u8];
        let mut r = Reader::new(&buf, Chain::Hive);
        assert!(r.bool().is_err());
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        let buf = [2u8, 0xff, 0xfe];
        let mut r = Reader::new(&buf, Chain::Hive);
        assert!(r.string().is_err());
    }

    #[test]
    fn arrays_and_optionals_round_trip() {
        let mut buf = Vec::new();
        write_array(&mut buf, &["a".to_string(), "bb".to_string()]).unwrap();
        crate::types::write_optional(&mut buf, Some(&"x".to_string())).unwrap();
        crate::types::write_optional::<String>(&mut buf, None).unwrap();

        let mut r = Reader::new(&buf, Chain::Hive);
        assert_eq!(r.array::<String>().unwrap(), vec!["a", "bb"]);
        assert_eq!(r.optional::<String>().unwrap().as_deref(), Some("x"));
        assert_eq!(r.optional::<String>().unwrap(), None);
        r.expect_end().unwrap();
    }

    #[test]
    fn timestamps_round_trip() {
        let t = PointInTime::from_unix(1_700_000_000).unwrap();
        let buf = t.to_wire().unwrap();
        let mut r = Reader::new(&buf, Chain::Hive);
        assert_eq!(r.point_in_time().unwrap(), t);
    }
}
