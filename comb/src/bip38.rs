//! BIP-38 encrypted private keys, in the Graphene variant.
//!
//! A passphrase-encrypted WIF, so a key can be stored or written down without being
//! usable on its own. Graphene fixes the flag byte to `0xc0` — non-EC-multiplied,
//! uncompressed — and derives the salt from the key's Bitcoin address, exactly as
//! BIP-38 specifies for that mode.
//!
//! # Cost
//!
//! Key stretching is scrypt with `N = 16384, r = 8, p = 8`, which is BIP-38's
//! parameter set. That is roughly 128 MB of memory and a noticeable fraction of a
//! second per attempt — the point being that an attacker who obtains the encrypted key
//! pays that cost per guess. It is enormously better than the unsalted single SHA-256
//! behind [`crate::keys::PasswordKey`], but it is a 2013 parameter set: choose a
//! passphrase with real entropy rather than relying on the work factor alone.
//!
//! # Fixes relative to beem
//!
//! * **The prefix bytes are checked.** beem's `decrypt` did `d = d[2:]  # remove
//!   trailing 0x01 and 0x42` without ever verifying they were `0x01 0x42`, so a
//!   corrupted or foreign payload was carried forward and failed later with a confusing
//!   message.
//! * **The base58 checksum is verified.** beem called `base58decode` — the *unchecked*
//!   decoder — so a typo in an encrypted key was not caught here at all, only much
//!   later by the address comparison.
//! * **The salt is compared in constant time.**
//! * The length of the payload is validated before slicing, rather than producing
//!   short slices that silently misalign the halves.

use crate::base58;
use crate::error::{Error, Result};
use crate::keys::PrivateKey;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// scrypt cost parameter.
const SCRYPT_LOG_N: u8 = 14; // N = 16384
/// scrypt block size parameter.
const SCRYPT_R: u32 = 8;
/// scrypt parallelisation parameter.
const SCRYPT_P: u32 = 8;

/// BIP-38 prefix bytes.
const PREFIX: [u8; 2] = [0x01, 0x42];
/// Graphene forces this flag byte: non-EC-multiplied, uncompressed.
const FLAG_BYTE: u8 = 0xc0;
/// Prefix + flag + salt + two 16-byte halves.
const PAYLOAD_LEN: usize = 2 + 1 + 4 + 16 + 16;

/// The Bitcoin address of a key, which BIP-38 uses to derive the salt.
///
/// `base58check(0x00 || ripemd160(sha256(uncompressed_pubkey)))`. Graphene uses the
/// **uncompressed** form here even though it uses compressed keys everywhere else.
fn bitcoin_address(key: &PrivateKey) -> String {
    let uncompressed = key.public_key().to_uncompressed_bytes();
    let sha = Sha256::digest(uncompressed);
    let ripe = <ripemd::Ripemd160 as Digest>::digest(sha);
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00);
    payload.extend_from_slice(&ripe);
    base58::encode_check(&payload)
}

/// Derive the 64-byte scrypt output for a passphrase and salt.
fn stretch(passphrase: &str, salt: &[u8; 4]) -> Result<Zeroizing<[u8; 64]>> {
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 64)
        .map_err(|e| Error::key(format!("bad scrypt parameters: {e}")))?;
    let mut out = Zeroizing::new([0u8; 64]);
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut *out)
        .map_err(|e| Error::key(format!("scrypt failed: {e}")))?;
    Ok(out)
}

/// The salt: the first four bytes of `sha256(sha256(address))`.
fn salt_for(key: &PrivateKey) -> [u8; 4] {
    let address = bitcoin_address(key);
    let first = Sha256::digest(address.as_bytes());
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

/// Encrypt a private key under a passphrase.
///
/// The result is a base58check string beginning with `6P`.
pub fn encrypt(key: &PrivateKey, passphrase: &str) -> Result<Zeroizing<String>> {
    if passphrase.is_empty() {
        return Err(Error::key("BIP-38 passphrase is empty"));
    }
    let salt = salt_for(key);
    let stretched = stretch(passphrase, &salt)?;
    let (half1, half2) = stretched.split_at(32);

    let secret = key.expose_secret();
    let cipher = aes::Aes256::new_from_slice(half2)
        .map_err(|e| Error::key(format!("AES init failed: {e}")))?;

    // Each 16-byte half of the secret is XORed with the matching half of the first
    // derived block, then encrypted with AES-256-ECB.
    let mut encrypted = Zeroizing::new([0u8; 32]);
    for block in 0..2 {
        let mut buf = Zeroizing::new([0u8; 16]);
        for i in 0..16 {
            buf[i] = secret[block * 16 + i] ^ half1[block * 16 + i];
        }
        cipher.encrypt_block((&mut *buf).into());
        encrypted[block * 16..(block + 1) * 16].copy_from_slice(&*buf);
    }

    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    payload.extend_from_slice(&PREFIX);
    payload.push(FLAG_BYTE);
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&*encrypted);
    Ok(Zeroizing::new(base58::encode_check(&payload)))
}

/// Decrypt a BIP-38 key.
///
/// Fails with a checksum error on a mistyped key, and with a salt mismatch on a wrong
/// passphrase — the two are distinguishable, which is a usability property, not a
/// security one: the salt check is what BIP-38 provides and it leaks only whether the
/// passphrase was right.
pub fn decrypt(encrypted_key: &str, passphrase: &str) -> Result<PrivateKey> {
    let payload = Zeroizing::new(base58::decode_check(encrypted_key.trim())?);
    if payload.len() != PAYLOAD_LEN {
        return Err(Error::key(format!(
            "BIP-38 payload must be {PAYLOAD_LEN} bytes, got {}",
            payload.len()
        )));
    }
    // beem sliced these off with `d = d[2:]` and never checked them.
    if payload[0..2] != PREFIX {
        return Err(Error::key(format!(
            "not a BIP-38 key: prefix is 0x{:02x}{:02x}, expected 0x0142",
            payload[0], payload[1]
        )));
    }
    if payload[2] != FLAG_BYTE {
        return Err(Error::key(format!(
            "unsupported BIP-38 flag byte 0x{:02x}; Graphene keys use 0x{FLAG_BYTE:02x}",
            payload[2]
        )));
    }

    let mut salt = [0u8; 4];
    salt.copy_from_slice(&payload[3..7]);
    let stretched = stretch(passphrase, &salt)?;
    let (half1, half2) = stretched.split_at(32);

    let cipher = aes::Aes256::new_from_slice(half2)
        .map_err(|e| Error::key(format!("AES init failed: {e}")))?;

    let mut secret = Zeroizing::new([0u8; 32]);
    for block in 0..2 {
        let mut buf = Zeroizing::new([0u8; 16]);
        buf.copy_from_slice(&payload[7 + block * 16..7 + (block + 1) * 16]);
        cipher.decrypt_block((&mut *buf).into());
        for i in 0..16 {
            secret[block * 16 + i] = buf[i] ^ half1[block * 16 + i];
        }
    }

    let key = PrivateKey::from_bytes(&*secret)?;

    // BIP-38's own integrity check: the salt must match the recovered key's address.
    if salt_for(&key).ct_eq(&salt).unwrap_u8() != 1 {
        return Err(Error::key("BIP-38 salt mismatch: wrong passphrase"));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_WIF: &str = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    #[test]
    fn round_trips() {
        let encrypted = encrypt(&key(), "correct horse battery staple").unwrap();
        assert!(encrypted.starts_with("6P"), "got {}", *encrypted);
        let back = decrypt(&encrypted, "correct horse battery staple").unwrap();
        assert_eq!(back, key());
    }

    #[test]
    fn matches_beems_output_byte_for_byte() {
        // BIP-38 non-EC-multiply is deterministic -- the salt comes from the address,
        // not from randomness -- so byte-equality is a legitimate gate here, unlike
        // for signatures. This value was produced by beem 0.24.26.
        let encrypted = encrypt(&key(), "correct horse battery staple").unwrap();
        assert_eq!(
            &*encrypted,
            "6PRWaUZmruY6rjNSJZ8G9yzdeU72VZmLgxMjADM7wuDaYknZCjot2JNmAc"
        );
        // ...and comb reads beem's back.
        assert_eq!(
            decrypt(
                "6PRWaUZmruY6rjNSJZ8G9yzdeU72VZmLgxMjADM7wuDaYknZCjot2JNmAc",
                "correct horse battery staple"
            )
            .unwrap(),
            key()
        );
    }

    #[test]
    fn the_wrong_passphrase_is_refused() {
        let encrypted = encrypt(&key(), "right").unwrap();
        let err = decrypt(&encrypted, "wrong").unwrap_err();
        assert!(format!("{err}").contains("wrong passphrase"));
    }

    #[test]
    fn a_mistyped_key_fails_the_checksum() {
        // beem used the unchecked base58 decoder here, so this was not caught at all.
        let encrypted = encrypt(&key(), "pass").unwrap();
        let mut chars: Vec<char> = encrypted.chars().collect();
        let i = chars.len() - 5;
        chars[i] = if chars[i] == 'a' { 'b' } else { 'a' };
        let broken: String = chars.into_iter().collect();
        assert!(matches!(decrypt(&broken, "pass"), Err(Error::Checksum(_))));
    }

    #[test]
    fn a_foreign_prefix_is_refused() {
        // beem's `d = d[2:]  # remove trailing 0x01 and 0x42` never checked them.
        let mut payload = vec![0x02, 0x43, FLAG_BYTE];
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(&[0u8; 32]);
        let encoded = base58::encode_check(&payload);
        let err = decrypt(&encoded, "pass").unwrap_err();
        assert!(format!("{err}").contains("prefix"));
    }

    #[test]
    fn an_unsupported_flag_byte_is_refused() {
        let mut payload = vec![PREFIX[0], PREFIX[1], 0xe0];
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(&[0u8; 32]);
        let encoded = base58::encode_check(&payload);
        let err = decrypt(&encoded, "pass").unwrap_err();
        assert!(format!("{err}").contains("flag byte"));
    }

    #[test]
    fn a_short_payload_is_refused_before_slicing() {
        let encoded = base58::encode_check(&[PREFIX[0], PREFIX[1], FLAG_BYTE, 0, 0]);
        assert!(decrypt(&encoded, "pass").is_err());
    }

    #[test]
    fn an_empty_passphrase_is_refused() {
        assert!(encrypt(&key(), "").is_err());
    }

    #[test]
    fn encryption_is_deterministic_for_a_given_key_and_passphrase() {
        // BIP-38 non-EC-multiply has no randomness: the salt comes from the address.
        let a = encrypt(&key(), "same").unwrap();
        let b = encrypt(&key(), "same").unwrap();
        assert_eq!(&*a, &*b);
    }

    #[test]
    fn distinct_keys_encrypt_differently() {
        let other = PrivateKey::generate();
        assert_ne!(
            &*encrypt(&key(), "p").unwrap(),
            &*encrypt(&other, "p").unwrap()
        );
    }

    #[test]
    fn the_encrypted_form_does_not_contain_the_key() {
        let encrypted = encrypt(&key(), "passphrase").unwrap();
        assert!(!encrypted.contains(TEST_WIF));
    }
}
