//! Encrypted memos.
//!
//! A Hive memo beginning with `#` is encrypted to the recipient's memo key. The scheme
//! is ECDH over secp256k1 to a shared secret, then AES-256-CBC.
//!
//! # What this format guarantees, and what it does not
//!
//! **Confidentiality, not integrity.** The 4-byte `check` field is a checksum *of the
//! derived key*, not of the ciphertext — it tells you that you used the right key, and
//! nothing about whether the message was modified in transit. There is no MAC. The
//! ciphertext is malleable and the decrypt path is a textbook padding-oracle shape.
//!
//! That is Hive's format, not a choice made here, and `hivecomb` must stay wire-compatible
//! with it. What `hivecomb` does differently is **fail closed**: invalid padding is an
//! error rather than silently-returned plaintext, and the key checksum is compared in
//! constant time. beem's `_unpad` returned the input unchanged when the padding did not
//! validate, handing padded bytes back as though they were the message.
//!
//! Do not use a Hive memo to carry anything whose modification would matter.
//!
//! # The varint prefix, and why beem's memos are not interoperable
//!
//! The reference implementations — `hive-js`, `dhive`, Hive Keychain, HiveSigner —
//! encrypt the memo as a **Graphene string**: a varint byte length followed by the
//! UTF-8 bytes. `hive-js/src/auth/memo.js` writes it with `mbuf.writeVString(memo)`
//! before handing the buffer to AES.
//!
//! beem's `encode_memo` does not:
//!
//! ```python
//! raw = py23_bytes(message, "utf8")
//! raw = _pad(raw, 16)          # no varint prefix
//! ```
//!
//! while its `decode_memo` *does* try to strip one, with a heuristic its own comment
//! flags as broken (`# remove the varint prefix (FIXME, long messages!)`). So beem
//! encodes in one format and decodes in another. Both sides usually get away with it
//! because the fallback paths happen to fire — but a message whose first byte is a
//! plausible length that fits the buffer is mis-parsed by everyone.
//!
//! `hivecomb` writes the prefix, as the ecosystem does. [`decode`] accepts memos without
//! one so that anything beem produced can still be read.

use crate::error::{Error, Result};
use crate::keys::{PrivateKey, PublicKey};
use crate::types::{read_varint32, write_varint32, GrapheneSerialize};
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type Encryptor = cbc::Encryptor<aes::Aes256>;
type Decryptor = cbc::Decryptor<aes::Aes256>;

/// AES block size, which is also the padding granularity.
const BLOCK: usize = 16;

/// The ECDH shared secret: `sha512(x)` where `x` is the 32-byte affine X coordinate of
/// `priv * pub`.
fn shared_secret(private: &PrivateKey, public: &PublicKey) -> Result<Zeroizing<[u8; 64]>> {
    // `mul_tweak` returns the scaled point; it does not mutate in place.
    let point = public
        .inner_ref()
        .mul_tweak(
            secp256k1::SECP256K1,
            &secp256k1::Scalar::from(*private.inner()),
        )
        .map_err(|e| Error::Memo(format!("ECDH failed: {e}")))?;
    // serialize_uncompressed is 0x04 || X(32) || Y(32); the secret is sha512(X).
    let uncompressed = Zeroizing::new(point.serialize_uncompressed());
    let x = &uncompressed[1..33];
    Ok(Zeroizing::new(Sha512::digest(x).into()))
}

/// Derive the AES key, IV and key-checksum for one memo.
///
/// `encryption_key = sha512(nonce_le_u64 || shared_secret)`; key is its first 32 bytes,
/// IV the next 16, and `check` is the first four bytes of `sha256(encryption_key)` read
/// as a little-endian `u32`.
fn derive(secret: &[u8; 64], nonce: u64) -> (Zeroizing<[u8; 32]>, [u8; 16], u32) {
    let mut hasher = Sha512::new();
    hasher.update(nonce.to_le_bytes());
    hasher.update(secret);
    let encryption_key = Zeroizing::new(<[u8; 64]>::from(hasher.finalize()));

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&encryption_key[0..32]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&encryption_key[32..48]);

    let digest = Sha256::digest(*encryption_key);
    let check = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    (key, iv, check)
}

/// Append the padding Graphene memos use: `n` bytes of value `n`, where `n` is
/// `1..=BLOCK`. This is PKCS#7, and unlike beem's version a full extra block is added
/// when the input is already aligned, which is what keeps unpadding unambiguous.
fn pad(data: &mut Vec<u8>) {
    let n = BLOCK - (data.len() % BLOCK);
    data.extend(std::iter::repeat(n as u8).take(n));
}

/// Strip and **validate** the padding.
///
/// beem's `_unpad` returned the input unchanged when validation failed, so a wrong key
/// or a corrupted ciphertext produced padded bytes presented as the message.
fn unpad(data: &[u8]) -> Result<&[u8]> {
    let n = *data
        .last()
        .ok_or_else(|| Error::Memo("empty plaintext".into()))? as usize;
    if n == 0 || n > BLOCK || n > data.len() {
        return Err(Error::Memo("invalid padding".into()));
    }
    let (message, padding) = data.split_at(data.len() - n);
    if padding.iter().any(|&b| b as usize != n) {
        return Err(Error::Memo("invalid padding".into()));
    }
    Ok(message)
}

/// The wire structure of an encrypted memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMemo {
    /// The sender's memo public key.
    pub from: PublicKey,
    /// The recipient's memo public key.
    pub to: PublicKey,
    /// The per-message nonce. Reusing one with the same key pair repeats key *and* IV.
    pub nonce: u64,
    /// Checksum of the derived key — **not** of the message.
    pub check: u32,
    /// The AES-CBC ciphertext.
    pub encrypted: Vec<u8>,
}

impl EncryptedMemo {
    /// Serialize to the Graphene structure carried inside the base58 body.
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(33 + 33 + 8 + 4 + 4 + self.encrypted.len());
        self.from.append_to(&mut out)?;
        self.to.append_to(&mut out)?;
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.check.to_le_bytes());
        write_varint32(
            &mut out,
            u32::try_from(self.encrypted.len())
                .map_err(|_| Error::Memo("ciphertext is implausibly long".into()))?,
        );
        out.extend_from_slice(&self.encrypted);
        Ok(out)
    }

    /// Parse the Graphene structure.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 33 + 33 + 8 + 4 {
            return Err(Error::Memo(format!(
                "encrypted memo is {} bytes, too short for its header",
                bytes.len()
            )));
        }
        let from = PublicKey::from_bytes(&bytes[0..33])?;
        let to = PublicKey::from_bytes(&bytes[33..66])?;
        let nonce = u64::from_le_bytes(bytes[66..74].try_into().unwrap());
        let check = u32::from_le_bytes(bytes[74..78].try_into().unwrap());
        let (len, used) = read_varint32(&bytes[78..])?;
        let start = 78 + used;
        let len = len as usize;
        if bytes.len() < start + len {
            return Err(Error::Memo(
                "encrypted memo claims more ciphertext than it carries".into(),
            ));
        }
        Ok(EncryptedMemo {
            from,
            to,
            nonce,
            check,
            encrypted: bytes[start..start + len].to_vec(),
        })
    }

    /// Render as the `#`-prefixed base58 string that goes in a memo field.
    pub fn to_memo_string(&self) -> Result<String> {
        Ok(format!("#{}", crate::base58::encode(&self.to_wire()?)))
    }

    /// Parse a `#`-prefixed memo string.
    pub fn from_memo_string(memo: &str) -> Result<Self> {
        let body = memo
            .strip_prefix('#')
            .ok_or_else(|| Error::Memo("an encrypted memo must start with '#'".into()))?;
        Self::from_wire(&crate::base58::decode(body)?)
    }
}

/// Whether a memo field holds an encrypted memo.
pub fn is_encrypted(memo: &str) -> bool {
    memo.starts_with('#')
}

/// Encrypt `message` from `from_key` to `to_key`, generating a random nonce.
pub fn encode(from_key: &PrivateKey, to_key: &PublicKey, message: &str) -> Result<String> {
    use rand::RngCore;
    let mut nonce_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    encode_with_nonce(from_key, to_key, message, u64::from_le_bytes(nonce_bytes))
}

/// Encrypt with an explicit nonce.
///
/// Exposed for reproducible tests and for interoperating with an existing record.
/// **Never reuse a nonce with the same key pair**: the key and IV are both derived from
/// it, so a repeat encrypts two messages under identical parameters.
pub fn encode_with_nonce(
    from_key: &PrivateKey,
    to_key: &PublicKey,
    message: &str,
    nonce: u64,
) -> Result<String> {
    let message = message.strip_prefix('#').unwrap_or(message);
    let secret = shared_secret(from_key, to_key)?;
    let (key, iv, check) = derive(&secret, nonce);

    // The plaintext is a Graphene string: varint length, then the UTF-8 bytes. This is
    // the prefix beem omits; see the module docs.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(message.len() + 8));
    write_varint32(
        &mut plaintext,
        u32::try_from(message.len()).map_err(|_| Error::Memo("memo is too long".into()))?,
    );
    plaintext.extend_from_slice(message.as_bytes());
    pad(&mut plaintext);

    let encrypted =
        Encryptor::new((&*key).into(), &iv.into()).encrypt_padded_vec_mut::<NoPadding>(&plaintext);

    EncryptedMemo {
        from: from_key.public_key(),
        to: *to_key,
        nonce,
        check,
        encrypted,
    }
    .to_memo_string()
}

/// Decrypt a `#`-prefixed memo with either side's memo key.
///
/// The same shared secret is reachable from the sender's key and the recipient's, so
/// whichever of the two you hold works.
pub fn decode(key: &PrivateKey, memo: &str) -> Result<String> {
    let parsed = EncryptedMemo::from_memo_string(memo)?;
    let own = key.public_key();

    // Pick the counterparty from whichever end we are.
    let counterparty = if own == parsed.to {
        parsed.from
    } else if own == parsed.from {
        parsed.to
    } else {
        return Err(Error::Memo(
            "this key is neither the sender nor the recipient of the memo".into(),
        ));
    };

    let secret = shared_secret(key, &counterparty)?;
    let (aes_key, iv, check) = derive(&secret, parsed.nonce);

    // Constant-time: this checksum distinguishes a wrong key from a right one.
    if check
        .to_le_bytes()
        .ct_eq(&parsed.check.to_le_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(Error::Memo(
            "checksum mismatch: wrong key for this memo".into(),
        ));
    }
    if parsed.encrypted.is_empty() || parsed.encrypted.len() % BLOCK != 0 {
        return Err(Error::Memo(format!(
            "ciphertext is {} bytes, not a whole number of AES blocks",
            parsed.encrypted.len()
        )));
    }

    let plaintext = Zeroizing::new(
        Decryptor::new((&*aes_key).into(), &iv.into())
            .decrypt_padded_vec_mut::<NoPadding>(&parsed.encrypted)
            .map_err(|e| Error::Memo(format!("decryption failed: {e}")))?,
    );
    let unpadded = unpad(&plaintext)?;

    // Reference implementations write a varint length prefix. beem does not, so try
    // the prefix first and fall back to treating the whole buffer as the message —
    // which is what lets a beem-produced memo still be read.
    if let Ok((len, used)) = read_varint32(unpadded) {
        let len = len as usize;
        if used + len == unpadded.len() {
            if let Ok(text) = std::str::from_utf8(&unpadded[used..]) {
                return Ok(text.to_string());
            }
        }
    }
    std::str::from_utf8(unpadded)
        .map(str::to_string)
        .map_err(|e| Error::Memo(format!("decrypted memo is not valid UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed test keys, published on purpose. Checked on 2026-08-22: no Hive
    // account uses either. They must never hold value.
    fn alice() -> PrivateKey {
        PrivateKey::from_wif("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3").unwrap()
    }

    fn bob() -> PrivateKey {
        PrivateKey::from_wif("5J4KCbg1G3my9b9hCaQXnHSm6vrwW9xQTJS6ZciW2Kek7cCkCEk").unwrap()
    }

    #[test]
    fn ecdh_is_symmetric() {
        let a = shared_secret(&alice(), &bob().public_key()).unwrap();
        let b = shared_secret(&bob(), &alice().public_key()).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn round_trips_from_either_side() {
        let memo = encode(&alice(), &bob().public_key(), "Hello Hive memo").unwrap();
        assert!(memo.starts_with('#'));
        assert!(is_encrypted(&memo));
        assert_eq!(decode(&bob(), &memo).unwrap(), "Hello Hive memo");
        // The sender can read it back too.
        assert_eq!(decode(&alice(), &memo).unwrap(), "Hello Hive memo");
    }

    #[test]
    fn round_trips_awkward_messages() {
        for message in [
            "",
            "a",
            "x".repeat(15).as_str(),
            "x".repeat(16).as_str(),
            "x".repeat(17).as_str(),
            "unicode é 中文 🐝",
            "with\nnewlines\tand\ttabs",
            "\u{1}\u{8}\u{c}control chars",
            "x".repeat(2000).as_str(),
        ] {
            let memo = encode(&alice(), &bob().public_key(), message).unwrap();
            assert_eq!(
                decode(&bob(), &memo).unwrap(),
                message,
                "failed on {message:?}"
            );
        }
    }

    #[test]
    fn the_plaintext_carries_a_varint_length_prefix() {
        // The interop property beem breaks. Decrypt manually and inspect.
        let message = "Hello";
        let memo = encode_with_nonce(&alice(), &bob().public_key(), message, 1234).unwrap();
        let parsed = EncryptedMemo::from_memo_string(&memo).unwrap();
        let secret = shared_secret(&bob(), &parsed.from).unwrap();
        let (key, iv, _) = derive(&secret, parsed.nonce);
        let plain = Decryptor::new((&*key).into(), &iv.into())
            .decrypt_padded_vec_mut::<NoPadding>(&parsed.encrypted)
            .unwrap();
        let unpadded = unpad(&plain).unwrap();
        assert_eq!(
            unpadded[0],
            message.len() as u8,
            "first byte is the varint length"
        );
        assert_eq!(&unpadded[1..], message.as_bytes());
    }

    #[test]
    fn a_memo_without_the_varint_prefix_still_decodes() {
        // beem-format compatibility: encrypt a bare, padded message with no prefix.
        let message = "beem wrote this";
        let nonce = 99u64;
        let secret = shared_secret(&alice(), &bob().public_key()).unwrap();
        let (key, iv, check) = derive(&secret, nonce);
        let mut plaintext = message.as_bytes().to_vec();
        pad(&mut plaintext);
        let encrypted = Encryptor::new((&*key).into(), &iv.into())
            .encrypt_padded_vec_mut::<NoPadding>(&plaintext);
        let memo = EncryptedMemo {
            from: alice().public_key(),
            to: bob().public_key(),
            nonce,
            check,
            encrypted,
        }
        .to_memo_string()
        .unwrap();
        assert_eq!(decode(&bob(), &memo).unwrap(), message);
    }

    #[test]
    fn messages_whose_first_byte_looks_like_a_length_survive() {
        // The case where beem's missing prefix actually corrupts. `"\x05hello"` is six
        // bytes whose first byte, read as a varint, is exactly the length of the rest.
        // Without a real prefix, every standards-compliant decoder — hive-js, dhive,
        // Keychain — strips that first byte as a length and returns "hello". beem
        // does this to its own memos: encode then decode loses the byte.
        //
        // With the prefix written, the length is unambiguous.
        for message in ["\u{5}hello", "\u{3}abc", "\u{1}z", "\u{b}hello world"] {
            let memo = encode(&alice(), &bob().public_key(), message).unwrap();
            assert_eq!(
                decode(&bob(), &memo).unwrap(),
                message,
                "lost the leading byte of {message:?}"
            );
        }
    }

    #[test]
    fn the_wrong_key_is_refused() {
        let memo = encode(&alice(), &bob().public_key(), "secret").unwrap();
        let stranger = PrivateKey::generate();
        let err = decode(&stranger, &memo).unwrap_err();
        assert!(format!("{err}").contains("neither the sender nor the recipient"));
    }

    #[test]
    fn a_corrupted_checksum_is_refused() {
        let memo = encode(&alice(), &bob().public_key(), "secret").unwrap();
        let mut parsed = EncryptedMemo::from_memo_string(&memo).unwrap();
        parsed.check ^= 1;
        let tampered = parsed.to_memo_string().unwrap();
        assert!(decode(&bob(), &tampered).is_err());
    }

    #[test]
    fn invalid_padding_is_an_error_not_a_silent_pass_through() {
        // beem's `_unpad` returned the input unchanged here, handing padded bytes back
        // as the message.
        assert!(unpad(&[]).is_err());
        assert!(unpad(&[0u8; 16]).is_err(), "a zero pad length is invalid");
        assert!(
            unpad(&[17u8; 16]).is_err(),
            "a pad longer than the block is invalid"
        );
        let mut bad = [3u8; 16];
        bad[15] = 3;
        bad[14] = 3;
        bad[13] = 9; // inconsistent
        assert!(unpad(&bad).is_err());
        // A valid pad still works.
        let mut good = vec![b'a'; 14];
        pad(&mut good);
        assert_eq!(unpad(&good).unwrap(), b"aaaaaaaaaaaaaa");
    }

    #[test]
    fn padding_always_adds_at_least_one_byte() {
        for len in 0..40usize {
            let mut data = vec![7u8; len];
            pad(&mut data);
            assert_eq!(data.len() % BLOCK, 0);
            assert!(data.len() > len, "padding must never be empty");
            assert_eq!(unpad(&data).unwrap().len(), len);
        }
    }

    #[test]
    fn malformed_memo_strings_are_refused() {
        assert!(EncryptedMemo::from_memo_string("no hash prefix").is_err());
        assert!(EncryptedMemo::from_memo_string("#").is_err());
        assert!(EncryptedMemo::from_memo_string("#notbase58!!!").is_err());
        assert!(EncryptedMemo::from_memo_string("#abc").is_err());
    }

    #[test]
    fn a_truncated_ciphertext_is_refused() {
        let memo = encode(&alice(), &bob().public_key(), "secret").unwrap();
        let mut parsed = EncryptedMemo::from_memo_string(&memo).unwrap();
        parsed.encrypted.truncate(parsed.encrypted.len() - 1);
        let broken = parsed.to_memo_string().unwrap();
        assert!(decode(&bob(), &broken).is_err());
    }

    #[test]
    fn distinct_nonces_give_distinct_ciphertexts() {
        let a = encode(&alice(), &bob().public_key(), "same message").unwrap();
        let b = encode(&alice(), &bob().public_key(), "same message").unwrap();
        assert_ne!(a, b, "a fresh nonce must be drawn each time");
    }

    #[test]
    fn a_leading_hash_in_the_message_is_not_doubled() {
        let memo = encode(&alice(), &bob().public_key(), "#already marked").unwrap();
        assert_eq!(decode(&bob(), &memo).unwrap(), "already marked");
    }
}
