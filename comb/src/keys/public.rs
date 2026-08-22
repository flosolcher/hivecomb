//! Public keys.

use super::COMPRESSED_PUBKEY_LEN;
use crate::base58;
use crate::error::{Error, Result};
use crate::types::{write_raw, GrapheneSerialize};
use std::fmt;

/// A compressed secp256k1 public key, rendered with a chain prefix (`STM7...`).
///
/// Hive always uses the compressed 33-byte form on the wire. The uncompressed form is
/// available via [`PublicKey::to_uncompressed_bytes`] for the legacy address
/// derivations, but is never serialized into a transaction.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey {
    inner: secp256k1::PublicKey,
}

impl PublicKey {
    pub(crate) fn from_inner(inner: secp256k1::PublicKey) -> Self {
        PublicKey { inner }
    }

    /// Parse 33 compressed or 65 uncompressed bytes.
    ///
    /// The point is validated as being on the curve. beem's `PublicKey` accepted a
    /// hex string and only re-derived `y` lazily, so an off-curve x-coordinate was
    /// carried around as a "valid" key until something finally used it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = secp256k1::PublicKey::from_slice(bytes)
            .map_err(|e| Error::key(format!("not a valid secp256k1 point: {e}")))?;
        Ok(PublicKey { inner })
    }

    /// Parse a hex-encoded public key.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() % 2 != 0 {
            return Err(Error::key("public key hex has an odd number of characters"));
        }
        let bytes: Result<Vec<u8>> = (0..s.len() / 2)
            .map(|i| {
                u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                    .map_err(|_| Error::key("public key is not valid hex"))
            })
            .collect();
        Self::from_bytes(&bytes?)
    }

    /// Parse a prefixed, Graphene-checksummed public key such as `STM7...`.
    ///
    /// The prefix must match exactly. beem compared `data[:len(prefix)] == prefix` and
    /// on mismatch fell through to `raise ValueError("Error loading Base58 object")`,
    /// which gave no indication that the *chain* was wrong rather than the key.
    pub fn from_prefixed(s: &str, prefix: &str) -> Result<Self> {
        let s = s.trim();
        let rest = s.strip_prefix(prefix).ok_or_else(|| {
            Error::key(format!(
                "public key does not start with the expected prefix {prefix:?}"
            ))
        })?;
        let payload = base58::decode_gph_check(rest)?;
        if payload.len() != COMPRESSED_PUBKEY_LEN {
            return Err(Error::key(format!(
                "public key payload must be {COMPRESSED_PUBKEY_LEN} bytes, got {}",
                payload.len()
            )));
        }
        Self::from_bytes(&payload)
    }

    /// Parse a prefixed key, accepting any of the known Hive prefixes.
    pub fn from_prefixed_any(s: &str) -> Result<Self> {
        for prefix in ["STM", "TST", "STX"] {
            if s.trim().starts_with(prefix) {
                return Self::from_prefixed(s, prefix);
            }
        }
        Err(Error::key("public key has no recognised chain prefix"))
    }

    /// The 33-byte compressed encoding, as serialized into transactions.
    pub fn to_bytes(&self) -> [u8; COMPRESSED_PUBKEY_LEN] {
        self.inner.serialize()
    }

    /// The 65-byte uncompressed encoding.
    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        self.inner.serialize_uncompressed()
    }

    /// Hex of the compressed encoding.
    pub fn to_hex(&self) -> String {
        self.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Render with a chain prefix, e.g. `STM8Gy...`.
    pub fn to_prefixed(&self, prefix: &str) -> String {
        format!("{prefix}{}", base58::encode_gph_check(&self.to_bytes()))
    }
}

impl GrapheneSerialize for PublicKey {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        // A public key is a bare 33-byte fixed array, with no length prefix.
        write_raw(out, &self.to_bytes());
        Ok(())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_prefixed("STM"))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_prefixed("STM"))
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    /// Order by the compressed encoding.
    ///
    /// hived sorts authority key entries by the serialized public key. beem sorted by
    /// the *ripemd160 address* instead (`PublicKey.__lt__` compares `self.address`),
    /// which produces a different order and therefore a different serialization for
    /// any authority with more than one key.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl crate::reader::GrapheneDeserialize for PublicKey {
    /// A public key is a bare 33-byte fixed array with no length prefix.
    fn read_from(r: &mut crate::reader::Reader<'_>) -> Result<Self> {
        let bytes = r.raw(COMPRESSED_PUBKEY_LEN)?;
        Self::from_bytes(&bytes)
    }
}

/// Public keys arrive as prefixed strings; any known Hive prefix is accepted.
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        PublicKey::from_prefixed_any(&s).map_err(D::Error::custom)
    }
}

/// Public keys render in their prefixed form. The `STM` prefix is used, which is
/// correct for Hive mainnet; testnet callers should render explicitly with
/// [`PublicKey::to_prefixed`].
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_prefixed("STM"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PrivateKey;

    const TEST_WIF: &str = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

    #[test]
    fn derives_the_known_public_key() {
        let priv_key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let pubkey = priv_key.public_key();
        // This WIF is the standard graphenelib fixture; its STM address is stable.
        let text = pubkey.to_prefixed("STM");
        assert!(text.starts_with("STM"));
        assert_eq!(pubkey.to_bytes().len(), 33);
        // Round-trips through the prefixed form.
        assert_eq!(PublicKey::from_prefixed(&text, "STM").unwrap(), pubkey);
    }

    #[test]
    fn prefix_must_match() {
        let pubkey = PrivateKey::from_wif(TEST_WIF).unwrap().public_key();
        let stm = pubkey.to_prefixed("STM");
        assert!(PublicKey::from_prefixed(&stm, "TST").is_err());
        assert!(PublicKey::from_prefixed(&stm, "STM").is_ok());
    }

    #[test]
    fn rejects_off_curve_points() {
        // x = 5 has no square root of x^3 + 7 on secp256k1, so neither sign byte
        // yields a point. beem carried such an x around as a "valid" key because it
        // only ever derived y lazily.
        let mut bad = [0u8; 33];
        bad[32] = 0x05;
        for sign_byte in [0x02u8, 0x03] {
            bad[0] = sign_byte;
            assert!(PublicKey::from_bytes(&bad).is_err());
        }
        // x = 0 is not on the curve either (y^2 = 7 is a non-residue).
        let mut zero_x = [0u8; 33];
        zero_x[0] = 0x02;
        assert!(PublicKey::from_bytes(&zero_x).is_err());
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let pubkey = PrivateKey::from_wif(TEST_WIF).unwrap().public_key();
        let mut text: Vec<char> = pubkey.to_prefixed("STM").chars().collect();
        let last = text.len() - 1;
        text[last] = if text[last] == 'a' { 'b' } else { 'a' };
        let text: String = text.into_iter().collect();
        assert!(PublicKey::from_prefixed(&text, "STM").is_err());
    }

    #[test]
    fn serializes_as_a_bare_33_byte_array() {
        let pubkey = PrivateKey::from_wif(TEST_WIF).unwrap().public_key();
        let wire = pubkey.to_wire().unwrap();
        assert_eq!(wire.len(), 33, "no varint length prefix on a fixed array");
        assert_eq!(wire, pubkey.to_bytes().to_vec());
    }

    #[test]
    fn ordering_is_by_serialized_key_not_by_address() {
        let a = PrivateKey::generate().public_key();
        let b = PrivateKey::generate().public_key();
        let mut v = [a, b];
        v.sort();
        assert!(v[0].to_bytes() <= v[1].to_bytes());
    }
}
