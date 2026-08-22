//! Base58 with the two checksum schemes Graphene uses.
//!
//! Hive inherits two different "base58 with a checksum" conventions from Graphene:
//!
//! * **base58check** — `sha256(sha256(payload))[..4]`, used for WIF private keys
//!   (this is the Bitcoin convention);
//! * **Graphene check** — `ripemd160(payload)[..4]`, used for prefixed public keys
//!   such as `STM7...`.
//!
//! # Fixes relative to beem
//!
//! * `beemgraphenebase.base58.base58decode` looked characters up with
//!   `BASE58_ALPHABET.find(c)`, which returns `-1` for a character that is not in the
//!   alphabet and then folded that `-1` into the accumulator. Invalid input therefore
//!   decoded to *wrong bytes* rather than raising. Here, invalid input is an error.
//! * Both checksum comparisons are constant time. beem compared with `==` on `bytes`,
//!   which short-circuits on the first differing byte.
//! * `base58CheckDecode(s, skip_first_bytes=True)` dropped the first byte without ever
//!   checking it was the expected `0x80` version. A key encoded under a different
//!   version byte was accepted as a Hive WIF. Here the version byte is returned to the
//!   caller so it can be checked, and [`decode_check_version`] checks it for you.

use crate::error::{Error, Result};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Encode raw bytes as base58 (no checksum).
pub fn encode(data: &[u8]) -> String {
    bs58::encode(data).into_string()
}

/// Decode a base58 string. Rejects any character outside the alphabet.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() {
        return Err(Error::Base58("empty string".into()));
    }
    Ok(bs58::decode(s).into_vec()?)
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

fn ripemd160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(data).into()
}

/// Append a Bitcoin-style `sha256d` checksum and base58-encode.
pub fn encode_check(payload: &[u8]) -> String {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(payload);
    out.extend_from_slice(&sha256d(payload)[..4]);
    encode(&out)
}

/// Decode a base58check string, verifying the `sha256d` checksum in constant time.
///
/// Returns the payload *including* any leading version byte. Unlike beem, nothing is
/// silently stripped — see [`decode_check_version`] when a version byte is expected.
pub fn decode_check(s: &str) -> Result<Vec<u8>> {
    let raw = decode(s)?;
    if raw.len() < 5 {
        return Err(Error::Base58(format!(
            "base58check payload too short: {} bytes",
            raw.len()
        )));
    }
    let (payload, checksum) = raw.split_at(raw.len() - 4);
    let expected = sha256d(payload);
    if checksum.ct_eq(&expected[..4]).unwrap_u8() != 1 {
        return Err(Error::Checksum("base58check (sha256d)"));
    }
    Ok(payload.to_vec())
}

/// Decode a base58check string and require an exact version byte.
///
/// This is the check beem never performed: `base58CheckDecode` discarded byte 0
/// unconditionally, so a Bitcoin mainnet WIF (`0x80`) and, say, a testnet key
/// (`0xef`) were treated identically.
pub fn decode_check_version(s: &str, version: u8) -> Result<Vec<u8>> {
    let payload = decode_check(s)?;
    let (&got, rest) = payload
        .split_first()
        .ok_or_else(|| Error::Base58("base58check payload has no version byte".into()))?;
    if got != version {
        return Err(Error::Key(format!(
            "unexpected version byte 0x{got:02x}, expected 0x{version:02x}"
        )));
    }
    Ok(rest.to_vec())
}

/// Append a Graphene-style `ripemd160` checksum and base58-encode.
pub fn encode_gph_check(payload: &[u8]) -> String {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(payload);
    out.extend_from_slice(&ripemd160(payload)[..4]);
    encode(&out)
}

/// Decode a Graphene-checksummed base58 string, verifying in constant time.
pub fn decode_gph_check(s: &str) -> Result<Vec<u8>> {
    let raw = decode(s)?;
    if raw.len() < 5 {
        return Err(Error::Base58(format!(
            "graphene base58 payload too short: {} bytes",
            raw.len()
        )));
    }
    let (payload, checksum) = raw.split_at(raw.len() - 4);
    let expected = ripemd160(payload);
    if checksum.ct_eq(&expected[..4]).unwrap_u8() != 1 {
        return Err(Error::Checksum("graphene base58 (ripemd160)"));
    }
    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // '0', 'O', 'I' and 'l' are excluded from the base58 alphabet. beem folded
        // `find() == -1` into the accumulator and produced bytes anyway.
        for bad in ["0OIl", "STM0", "5J*", "abc def"] {
            assert!(decode(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(decode("").is_err());
    }

    #[test]
    fn check_roundtrip() {
        let payload = [0x80u8; 33];
        let s = encode_check(&payload);
        assert_eq!(decode_check(&s).unwrap(), payload);
    }

    #[test]
    fn gph_check_roundtrip() {
        let payload = [7u8; 33];
        let s = encode_gph_check(&payload);
        assert_eq!(decode_gph_check(&s).unwrap(), payload);
    }

    #[test]
    fn detects_corrupted_checksum() {
        let payload = [1u8; 33];
        let mut raw = payload.to_vec();
        raw.extend_from_slice(&[0, 0, 0, 0]);
        let s = encode(&raw);
        assert!(matches!(decode_check(&s), Err(Error::Checksum(_))));
    }

    #[test]
    fn version_byte_is_enforced() {
        let mut payload = vec![0xefu8];
        payload.extend_from_slice(&[9u8; 32]);
        let s = encode_check(&payload);
        // The raw decode still works...
        assert_eq!(decode_check(&s).unwrap().len(), 33);
        // ...but asking for the Hive/Bitcoin 0x80 version is refused.
        assert!(decode_check_version(&s, 0x80).is_err());
        assert!(decode_check_version(&s, 0xef).is_ok());
    }

    #[test]
    fn known_wif_vector() {
        // Bitcoin BIP-32 style test vector: version 0x80 + 32 zero bytes.
        let mut payload = vec![0x80u8];
        payload.extend_from_slice(&[0u8; 32]);
        let wif = encode_check(&payload);
        assert!(wif.starts_with('5'));
        assert_eq!(decode_check_version(&wif, 0x80).unwrap(), vec![0u8; 32]);
    }
}
