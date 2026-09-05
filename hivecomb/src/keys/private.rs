//! Private keys.

use super::{PublicKey, COMPRESSED_PUBKEY_LEN, SECRET_KEY_LEN, WIF_VERSION};
use crate::base58;
use crate::error::{Error, Result};
use secp256k1::SecretKey;
use std::fmt;
use zeroize::Zeroizing;

/// A secp256k1 private key, as used for Hive's owner/active/posting/memo roles.
///
/// The inner scalar is validated on construction and zeroized on drop. Neither
/// `Debug` nor `Display` will render it; see the [module docs](super) for why that is
/// a deliberate departure from beem.
#[derive(Clone)]
pub struct PrivateKey {
    inner: SecretKey,
}

impl PrivateKey {
    /// Build from 32 raw scalar bytes.
    ///
    /// Rejects zero and any value at or above the curve order. beem accepted both:
    /// its only check was `assert len(repr(wif)) == 64`, which Python strips under
    /// `-O` and which says nothing about the value being a usable secret.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_LEN {
            return Err(Error::key(format!(
                "private key must be {SECRET_KEY_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let inner = SecretKey::from_slice(bytes)
            .map_err(|_| Error::key("scalar is zero or not below the curve order"))?;
        Ok(PrivateKey { inner })
    }

    /// Parse a 64-character hex scalar.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != SECRET_KEY_LEN * 2 {
            return Err(Error::key(format!(
                "hex private key must be {} characters, got {}",
                SECRET_KEY_LEN * 2,
                s.len()
            )));
        }
        let mut buf = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        crate::hex::decode_exact(s, &mut *buf)
            .map_err(|_| Error::key("private key is not valid hex"))?;
        Self::from_bytes(&*buf)
    }

    /// Parse a WIF-encoded private key, e.g. `5J...`.
    ///
    /// The version byte is checked, the checksum is verified in constant time, and
    /// the resulting scalar is range-checked.
    ///
    /// Hive uses only uncompressed-form WIFs (leading `5`). A compressed-form WIF
    /// (`K`/`L`, carrying a trailing `0x01` flag) is *rejected* rather than silently
    /// truncated: beem's `Base58` accepted it and stripped the flag with
    /// `base58CheckDecode(data)[:-2]`, so a Bitcoin-style compressed key would be
    /// accepted and produce a key for a different address than the user expects.
    pub fn from_wif(wif: &str) -> Result<Self> {
        let wif = wif.trim();
        match wif.chars().next() {
            Some('5') => {}
            Some(c @ ('K' | 'L')) => {
                return Err(Error::key(format!(
                    "WIF starts with '{c}', which is a Bitcoin compressed-form key; \
                     Hive keys start with '5'"
                )))
            }
            Some(c) => return Err(Error::key(format!("WIF must start with '5', got '{c}'"))),
            None => return Err(Error::key("empty WIF")),
        }
        let payload = Zeroizing::new(base58::decode_check_version(wif, WIF_VERSION)?);
        if payload.len() != SECRET_KEY_LEN {
            return Err(Error::key(format!(
                "WIF payload must be {SECRET_KEY_LEN} bytes, got {}",
                payload.len()
            )));
        }
        Self::from_bytes(&payload)
    }

    /// Accept either a WIF or a bare hex scalar.
    ///
    /// beem's `Base58` decided between these by testing `all(c in string.hexdigits)`
    /// *first*, which also matches the empty string and can misclassify input. Here
    /// the discrimination is explicit and unambiguous.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.starts_with('5') && s.len() >= 50 {
            Self::from_wif(s)
        } else {
            Self::from_hex(s)
        }
    }

    /// Generate a new random key from the OS CSPRNG.
    ///
    /// `OsRng` rather than `thread_rng`. `thread_rng` is a CSPRNG and would be
    /// defensible, but it is a userspace generator seeded once per thread, and this is
    /// long-lived key material that may guard funds for years. `OsRng` goes to
    /// `getrandom` every time, which is also what BIP-39 entropy uses here — one
    /// source for every secret this crate creates, rather than two.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let (inner, _) = secp256k1::SECP256K1.generate_keypair(&mut OsRng);
        PrivateKey { inner }
    }

    /// The matching compressed public key.
    pub fn public_key(&self) -> PublicKey {
        // The process-wide context: `signing_only()` rebuilt the precomputation
        // tables on every call, and this is called for every key, every signature
        // check and every authority comparison.
        let pk = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &self.inner);
        PublicKey::from_inner(pk)
    }

    /// Export as a WIF string.
    ///
    /// Deliberately named so that every disclosure of the secret is visible at the
    /// call site. The result is wrapped in [`Zeroizing`] so it is wiped when dropped.
    pub fn to_wif(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new(Vec::with_capacity(1 + SECRET_KEY_LEN));
        payload.push(WIF_VERSION);
        payload.extend_from_slice(&self.inner.secret_bytes());
        Zeroizing::new(base58::encode_check(&payload))
    }

    /// Export the raw 32-byte scalar.
    pub fn expose_secret(&self) -> Zeroizing<[u8; SECRET_KEY_LEN]> {
        Zeroizing::new(self.inner.secret_bytes())
    }

    /// The underlying `secp256k1` key, for the signing path.
    pub(crate) fn inner(&self) -> &SecretKey {
        &self.inner
    }

    /// Derive a child key as `sha256(sha512("<wif> <sequence>"))`.
    ///
    /// This reproduces Graphene's `derive_private_key` so that keys generated by
    /// existing wallets remain reachable. It is **not** a hardened derivation and is
    /// kept only for compatibility; prefer BIP-32/BIP-39 for new wallets.
    pub fn derive_sequence(&self, sequence: u32) -> Result<Self> {
        use sha2::{Digest, Sha256, Sha512};
        let wif = self.to_wif();
        let encoded = Zeroizing::new(format!("{} {}", *wif, sequence));
        let outer = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(encoded.as_bytes())));
        let scalar = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(*outer)));
        Self::from_bytes(&*scalar)
    }
}

/// Redacted. See the [module docs](super) — beem's `__repr__` returned the raw scalar.
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

/// Redacted. beem's `__str__` returned the WIF, so any f-string leaked the key.
impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

impl PartialEq for PrivateKey {
    /// Constant-time comparison; `secp256k1::SecretKey` compares its bytes with
    /// `subtle` internally.
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for PrivateKey {}

impl Drop for PrivateKey {
    /// Overwrite the key material rather than leaving it in freed memory.
    ///
    /// # This was wrong, and the wrong version looked right
    ///
    /// The first implementation did:
    ///
    /// ```ignore
    /// let mut bytes = self.inner.secret_bytes();
    /// bytes.zeroize();
    /// ```
    ///
    /// `secret_bytes()` returns `[u8; 32]` **by value**, so that zeroed a copy which was
    /// about to be dropped anyway and left the real storage inside `SecretKey`
    /// untouched. It read as though zeroization were handled, and its comment claimed
    /// "the storage we own", which was the part that was not true.
    ///
    /// `non_secure_erase` operates on the key in place. It writes `1` rather than `0`,
    /// because an all-zero scalar is not a valid secp256k1 key and the crate keeps the
    /// type's invariant even while erasing. Its name is the crate's own honesty: nothing
    /// stops a compiler eliding a write to memory that is never read again, so this is
    /// best-effort rather than a guarantee.
    fn drop(&mut self) {
        self.inner.non_secure_erase();
    }
}

impl std::str::FromStr for PrivateKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Sanity: a compressed public key is always 33 bytes.
const _: () = assert!(COMPRESSED_PUBKEY_LEN == 33);

#[cfg(test)]
mod tests {

    /// `Drop` erases in place, asserted against the source because it cannot be run.
    ///
    /// The effect of `Drop` is invisible: by the time it has finished, the value is
    /// gone and the memory is not ours to inspect. So the behavioural tests below cover
    /// the *primitive*, and reverting `Drop` itself to the broken form — zeroing the
    /// copy that `secret_bytes()` returns — fails none of them.
    ///
    /// A decision that is documented but not asserted is one edit from being silently
    /// reversed, and this one was already made wrongly once. So this reads the source.
    /// It is a crude test and it is the only kind available here; the alternative is a
    /// comment and a hope.
    #[test]
    fn drop_erases_in_place_rather_than_zeroing_a_copy() {
        let source = include_str!("private.rs");
        let start = source
            .find("impl Drop for PrivateKey {")
            .expect("the Drop impl must exist");
        let body = &source[start..];
        let body = &body[..body.find("\n}").expect("impl must be closed")];
        let body = &body[body.find("fn drop").expect("must define drop")..];

        assert!(
            body.contains("non_secure_erase"),
            "Drop must erase the key in place"
        );
        assert!(
            !body.contains("secret_bytes"),
            "secret_bytes() returns [u8; 32] BY VALUE -- zeroing it erases a temporary \
             and leaves the key in memory. That was the original bug and it read as \
             though zeroization were handled."
        );
    }

    /// The erase actually overwrites the key, rather than a copy of it.
    ///
    /// `Drop` cannot be observed from a test — by the time it has run the value is
    /// gone — so this exercises the primitive `Drop` relies on. That is the part that
    /// was wrong before: the old implementation called `secret_bytes()`, which returns
    /// by value, and zeroed a temporary while the real storage survived. A test of the
    /// mechanism catches that; a test of `Drop` could not have.
    #[test]
    fn erasing_a_key_overwrites_the_key_and_not_a_copy() {
        let key = PrivateKey::from_wif(TEST_WIF).expect("published test key");
        let before = key.to_wif().as_str().to_owned();

        let mut inner = key.inner;
        let original = inner.secret_bytes();
        inner.non_secure_erase();
        let after = inner.secret_bytes();

        assert_ne!(
            original, after,
            "non_secure_erase must change the key material"
        );
        assert!(
            after.iter().all(|b| *b == 1),
            "secp256k1 erases to 1, since an all-zero scalar is not a valid key: {after:?}"
        );

        // And erasing that copy left the original untouched, which is what makes the
        // distinction visible at all.
        assert_eq!(key.to_wif().as_str(), before);
    }
    use super::*;

    /// A fixed key used throughout these tests.
    ///
    /// It is published here on purpose and must never hold value. Checked against
    /// `account_by_key_api.get_key_references` on 2026-08-22: **no Hive account uses
    /// it.** Do not fund it, and do not copy it into anything that will.
    const TEST_WIF: &str = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

    #[test]
    fn wif_roundtrip() {
        let k = PrivateKey::from_wif(TEST_WIF).unwrap();
        assert_eq!(&*k.to_wif(), TEST_WIF);
    }

    #[test]
    fn secrets_do_not_render() {
        let k = PrivateKey::from_wif(TEST_WIF).unwrap();
        let shown = format!("{k:?} {k}");
        assert!(!shown.contains(TEST_WIF));
        assert!(!shown.to_lowercase().contains("4c0b"));
        assert_eq!(shown, "PrivateKey(<redacted>) PrivateKey(<redacted>)");
    }

    #[test]
    fn rejects_zero_and_overflowing_scalars() {
        assert!(PrivateKey::from_bytes(&[0u8; 32]).is_err());
        // The curve order itself is out of range.
        let n = hex_lit("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert!(PrivateKey::from_bytes(&n).is_err());
        assert!(PrivateKey::from_bytes(&[0xffu8; 32]).is_err());
    }

    #[test]
    fn rejects_wrong_lengths() {
        assert!(PrivateKey::from_bytes(&[1u8; 31]).is_err());
        assert!(PrivateKey::from_bytes(&[1u8; 33]).is_err());
        assert!(PrivateKey::from_hex("00").is_err());
    }

    #[test]
    fn rejects_bitcoin_compressed_wif() {
        // Compressed-form WIFs carry a trailing 0x01 flag. beem stripped it silently
        // via `base58CheckDecode(data)[:-2]` and carried on with the wrong key.
        let mut payload = vec![WIF_VERSION];
        payload.extend_from_slice(&[7u8; 32]);
        payload.push(0x01);
        let compressed = crate::base58::encode_check(&payload);
        assert!(compressed.starts_with('K') || compressed.starts_with('L'));
        assert!(PrivateKey::from_wif(&compressed).is_err());
    }

    #[test]
    fn rejects_corrupted_wif() {
        let mut bad: Vec<char> = TEST_WIF.chars().collect();
        bad[10] = if bad[10] == 'a' { 'b' } else { 'a' };
        let bad: String = bad.into_iter().collect();
        assert!(PrivateKey::from_wif(&bad).is_err());
    }

    #[test]
    fn generated_keys_are_distinct_and_valid() {
        let a = PrivateKey::generate();
        let b = PrivateKey::generate();
        assert_ne!(a, b);
        assert_eq!(a.expose_secret().len(), 32);
    }

    #[test]
    fn parse_accepts_wif_and_hex() {
        let from_wif = PrivateKey::from_wif(TEST_WIF).unwrap();
        let hex: String = from_wif
            .expose_secret()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(PrivateKey::parse(&hex).unwrap(), from_wif);
        assert_eq!(PrivateKey::parse(TEST_WIF).unwrap(), from_wif);
    }

    fn hex_lit(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
}
