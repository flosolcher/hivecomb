//! Hex decoding for the fixed-width values Hive carries as text.
//!
//! Deliberately byte-oriented, and that is the whole point of the module existing.
//!
//! Five public parsers -- chain ids, signatures, private keys, public keys and block ids
//! -- each checked `s.len()`, which counts **bytes**, and then sliced
//! `&s[i * 2..i * 2 + 2]`, which demands **char boundaries**. Any multi-byte character
//! made the two disagree, and the slice panicked rather than returning an error. Four of
//! the five checked an exact length first, which does not help: 61 ASCII characters plus
//! one two-byte character is still 64 bytes.
//!
//! That is a denial of service in whatever parses untrusted text -- for
//! `BlockRef::from_block_id`, a block id straight out of a node response, and in a
//! signing service, the process holding the keys. `fuzz/fuzz_targets/keys.rs` found it
//! in `PublicKey::from_hex`; the other four were the same shape.
//!
//! Hex is ASCII by definition, so working in bytes loses nothing: a non-ASCII byte is
//! simply not a hex digit, and is reported as such.

/// Why a hex string could not be decoded.
///
/// Deliberately not an [`crate::Error`]: each caller reports these in its own words and
/// under its own variant, and a shared error type here would flatten that.
#[derive(Debug)]
pub(crate) enum HexError {
    /// Not twice the expected byte count.
    ///
    /// Every caller checks the length itself first, so that it can say what it expected
    /// in its own words; this is the backstop that keeps the decode total rather than a
    /// second opinion worth reporting.
    Length,
    /// Something in it was not a hex digit.
    NotHex,
}

/// Decode ASCII hex into `out`, whose length fixes how many bytes are expected.
pub(crate) fn decode_exact(s: &str, out: &mut [u8]) -> Result<(), HexError> {
    let s = s.as_bytes();
    if s.len() != out.len() * 2 {
        return Err(HexError::Length);
    }
    // `as_chunks` rather than `chunks_exact(2)`: the pair is a `[u8; 2]`, so indexing it
    // is checked at compile time. The remainder is empty, the length having just been
    // established as even.
    let (pairs, _remainder) = s.as_chunks::<2>();
    for (byte, pair) in out.iter_mut().zip(pairs) {
        *byte = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(())
}

/// Decode ASCII hex of any even length.
pub(crate) fn decode_vec(s: &str) -> Result<Vec<u8>, HexError> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return Err(HexError::Length);
    }
    let (pairs, _remainder) = s.as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| Ok(digit(pair[0])? * 16 + digit(pair[1])?))
        .collect()
}

fn digit(b: u8) -> Result<u8, HexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HexError::NotHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_multibyte_character_is_an_error_rather_than_a_panic() {
        // The exact shape that panicked: the right number of *bytes*, but a two-byte
        // character straddling the boundary a slice would have cut on.
        let s = format!("{}\u{041e}b", "a".repeat(61));
        assert_eq!(s.len(), 64, "the byte-length check must be the passing one");
        let mut out = [0u8; 32];
        assert!(matches!(decode_exact(&s, &mut out), Err(HexError::NotHex)));
        assert!(matches!(decode_vec(&s), Err(HexError::NotHex)));
    }

    #[test]
    fn ordinary_hex_still_decodes_in_both_cases() {
        let mut out = [0u8; 4];
        assert!(decode_exact("DeadBeef", &mut out).is_ok());
        assert_eq!(out, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode_vec("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert_eq!(decode_vec("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn lengths_and_non_digits_are_told_apart() {
        let mut out = [0u8; 2];
        assert!(matches!(decode_exact("aabb", &mut out), Ok(())));
        assert!(matches!(
            decode_exact("aa", &mut out),
            Err(HexError::Length)
        ));
        assert!(matches!(
            decode_exact("aabbcc", &mut out),
            Err(HexError::Length)
        ));
        assert!(matches!(
            decode_exact("aagg", &mut out),
            Err(HexError::NotHex)
        ));
        assert!(matches!(decode_vec("abc"), Err(HexError::Length)));
    }
}
