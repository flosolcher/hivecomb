//! BIP-39 mnemonic seed phrases.
//!
//! The modern replacement for Graphene's brain keys. A mnemonic is a checksummed
//! encoding of entropy, stretched into a 64-byte seed by PBKDF2-HMAC-SHA512 with 2048
//! iterations — so unlike [`crate::keys::PasswordKey`], guessing it costs real work.
//!
//! Combine with [`crate::bip32`] to derive Hive role keys.
//!
//! # Fixes relative to beem
//!
//! beem's `Mnemonic` is a copy of Trezor's `python-mnemonic` (credited in
//! `CREDITS.md`) and is essentially correct. Two things are tightened here:
//!
//! * **The checksum is verified on use, not just on request.** beem exposes `check()`
//!   as a separate call, and `MnemonicKey.set_mnemonic` does not call it — so a
//!   mistyped word silently derives a different, empty wallet. [`Mnemonic::parse`]
//!   validates, and there is no way to reach [`Mnemonic::to_seed`] without it.
//! * **The word list is searched exactly.** beem's `to_entropy` falls back to
//!   `wordlist.index(word)` after a binary search, and its `expand_word` accepts unique
//!   *prefixes*. Accepting an abbreviation where a word was meant is not a kindness in
//!   a function that decides which wallet you open.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// The BIP-39 English word list, 2048 words.
static WORDS: &str = include_str!("../data/bip39_english.txt");

/// Number of words in the list. Each word therefore carries 11 bits.
pub const WORDLIST_LEN: usize = 2048;

/// PBKDF2 iteration count fixed by BIP-39.
pub const PBKDF2_ROUNDS: u32 = 2048;

fn wordlist() -> Vec<&'static str> {
    WORDS.lines().collect()
}

/// A validated BIP-39 mnemonic.
///
/// Holding one is proof the checksum passed. The phrase is zeroized on drop and does
/// not render — it is key material.
#[derive(Clone)]
pub struct Mnemonic {
    phrase: Zeroizing<String>,
    entropy: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mnemonic(<redacted>, {} words)", self.word_count())
    }
}

impl Mnemonic {
    /// Generate a new mnemonic from OS randomness.
    ///
    /// `strength` is in bits and must be one of 128, 160, 192, 224 or 256 — giving 12,
    /// 15, 18, 21 or 24 words.
    pub fn generate(strength: usize) -> Result<Self> {
        use rand::RngCore;
        if !matches!(strength, 128 | 160 | 192 | 224 | 256) {
            return Err(Error::key(format!(
                "strength must be 128, 160, 192, 224 or 256 bits, got {strength}"
            )));
        }
        let mut entropy = Zeroizing::new(vec![0u8; strength / 8]);
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        Self::from_entropy(&entropy)
    }

    /// Build from raw entropy.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(Error::key(format!(
                "entropy must be 16, 20, 24, 28 or 32 bytes, got {}",
                entropy.len()
            )));
        }
        let checksum_bits = entropy.len() * 8 / 32;
        let checksum = Sha256::digest(entropy);

        // Concatenate entropy and its checksum, then read out 11 bits per word.
        let mut bits = Vec::with_capacity(entropy.len() * 8 + checksum_bits);
        for byte in entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1 == 1);
            }
        }
        for i in 0..checksum_bits {
            bits.push((checksum[i / 8] >> (7 - i % 8)) & 1 == 1);
        }

        let words = wordlist();
        let phrase = bits
            .chunks(11)
            .map(|chunk| {
                let idx = chunk
                    .iter()
                    .fold(0usize, |acc, &b| (acc << 1) | usize::from(b));
                words[idx]
            })
            .collect::<Vec<_>>()
            .join(" ");

        Ok(Mnemonic {
            phrase: Zeroizing::new(phrase),
            entropy: Zeroizing::new(entropy.to_vec()),
        })
    }

    /// Parse and **validate** a mnemonic phrase.
    ///
    /// Every word must be in the list exactly — no prefixes — and the checksum must
    /// match. There is no way to obtain a `Mnemonic` that skipped this.
    pub fn parse(phrase: &str) -> Result<Self> {
        let normalized = normalize(phrase);
        let given: Vec<&str> = normalized.split(' ').filter(|w| !w.is_empty()).collect();
        if !matches!(given.len(), 12 | 15 | 18 | 21 | 24) {
            return Err(Error::key(format!(
                "a mnemonic must be 12, 15, 18, 21 or 24 words, got {}",
                given.len()
            )));
        }

        let words = wordlist();
        let mut bits = Vec::with_capacity(given.len() * 11);
        for word in &given {
            let idx = words
                .binary_search(word)
                // Deliberately does not name the word: a mnemonic is key material and
                // errors get logged.
                .map_err(|_| {
                    Error::key("mnemonic contains a word that is not in the BIP-39 list")
                })?;
            for i in (0..11).rev() {
                bits.push((idx >> i) & 1 == 1);
            }
        }

        let entropy_bits = given.len() * 11 * 32 / 33;
        let mut entropy = Zeroizing::new(vec![0u8; entropy_bits / 8]);
        for (i, bit) in bits[..entropy_bits].iter().enumerate() {
            if *bit {
                entropy[i / 8] |= 1 << (7 - i % 8);
            }
        }

        let expected = Sha256::digest(&*entropy);
        for (i, bit) in bits[entropy_bits..].iter().enumerate() {
            if ((expected[i / 8] >> (7 - i % 8)) & 1 == 1) != *bit {
                return Err(Error::Checksum("BIP-39 mnemonic"));
            }
        }

        Ok(Mnemonic {
            phrase: Zeroizing::new(given.join(" ")),
            entropy,
        })
    }

    /// The normalised phrase. This is secret material.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// The entropy the phrase encodes.
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// Number of words.
    pub fn word_count(&self) -> usize {
        self.phrase.split(' ').count()
    }

    /// Stretch to the 64-byte BIP-32 seed.
    ///
    /// `PBKDF2-HMAC-SHA512(phrase, "mnemonic" || passphrase, 2048)`. Both inputs are
    /// NFKD-normalised, as BIP-39 requires — which matters for any passphrase that is
    /// not pure ASCII, since otherwise the same typed passphrase can produce two
    /// different seeds on two machines.
    pub fn to_seed(&self, passphrase: &str) -> Zeroizing<[u8; 64]> {
        let salt = Zeroizing::new(format!("mnemonic{}", normalize(passphrase)));
        let mut seed = Zeroizing::new([0u8; 64]);
        pbkdf2::pbkdf2_hmac::<Sha512>(
            self.phrase.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ROUNDS,
            &mut *seed,
        );
        seed
    }
}

/// NFKD-normalise and collapse whitespace, as BIP-39 specifies.
fn normalize(s: &str) -> String {
    s.nfkd()
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a word is in the BIP-39 English list.
pub fn is_bip39_word(word: &str) -> bool {
    wordlist().binary_search(&word).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_the_standard_one() {
        let words = wordlist();
        assert_eq!(words.len(), WORDLIST_LEN);
        assert_eq!(words[0], "abandon");
        assert_eq!(words[WORDLIST_LEN - 1], "zoo");
        // The list must be sorted, since parsing binary-searches it.
        assert!(
            words.windows(2).all(|w| w[0] < w[1]),
            "wordlist must be sorted"
        );
    }

    #[test]
    fn official_bip39_test_vector() {
        // From the BIP-39 reference vectors: all-zero entropy, passphrase "TREZOR".
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(
            m.phrase(),
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
        );
        assert_eq!(
            hex(&*m.to_seed("TREZOR")),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn official_bip39_test_vectors() {
        // The reference vectors, passphrase "TREZOR". Cross-checked against beem's
        // implementation, which is Trezor's python-mnemonic.
        let cases: &[(&[u8], &str, &str, &str)] = &[
            (
                &[0xffu8; 16],
                "zoo",
                "wrong",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
            ),
            (
                &[0xffu8; 32],
                "zoo",
                "vote",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
            ),
            (
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                "abandon",
                "buyer",
                "f9bc537d3c2e74f58b7531ed7370d580114de81533720dba2a041ba9fd2d7821f0f7d55447e9f09e1e0730ee76a102073819929131a0349c502227c90699e7d0",
            ),
        ];
        for (entropy, first, last, seed) in cases {
            let m = Mnemonic::from_entropy(entropy).unwrap();
            let words: Vec<&str> = m.phrase().split(' ').collect();
            assert_eq!(words[0], *first);
            assert_eq!(*words.last().unwrap(), *last);
            assert_eq!(hex(&*m.to_seed("TREZOR")), *seed);
            // ...and the phrase parses back to the same entropy.
            assert_eq!(Mnemonic::parse(m.phrase()).unwrap().entropy(), *entropy);
        }
    }

    #[test]
    fn generate_and_parse_round_trip() {
        for strength in [128, 160, 192, 224, 256] {
            let m = Mnemonic::generate(strength).unwrap();
            assert_eq!(m.word_count(), strength / 32 * 3);
            let back = Mnemonic::parse(m.phrase()).unwrap();
            assert_eq!(back.phrase(), m.phrase());
            assert_eq!(back.entropy(), m.entropy());
            assert_eq!(*back.to_seed(""), *m.to_seed(""));
        }
    }

    #[test]
    fn a_bad_checksum_is_refused() {
        // Valid words, wrong checksum: swap the last word.
        let bad = "abandon abandon abandon abandon abandon abandon \
                   abandon abandon abandon abandon abandon abandon";
        assert!(matches!(Mnemonic::parse(bad), Err(Error::Checksum(_))));
    }

    #[test]
    fn an_unknown_word_is_refused_without_naming_it() {
        let bad = "abandon abandon abandon abandon abandon abandon \
                   abandon abandon abandon abandon abandon notaword";
        let err = Mnemonic::parse(bad).unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("not in the BIP-39 list"));
        assert!(
            !text.contains("notaword"),
            "an error must not echo mnemonic words"
        );
    }

    #[test]
    fn prefixes_are_not_accepted_as_words() {
        // beem's `expand_word` accepts a unique prefix. Deciding which wallet to open
        // is not the place for autocomplete.
        let bad = "aban abandon abandon abandon abandon abandon \
                   abandon abandon abandon abandon abandon about";
        assert!(Mnemonic::parse(bad).is_err());
    }

    #[test]
    fn wrong_word_counts_are_refused() {
        assert!(Mnemonic::parse("abandon about").is_err());
        assert!(Mnemonic::parse("").is_err());
        assert!(Mnemonic::generate(64).is_err());
        assert!(Mnemonic::from_entropy(&[0u8; 15]).is_err());
    }

    #[test]
    fn whitespace_is_normalised() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let messy = format!("  {}  ", m.phrase().replace(' ', "\t\n "));
        assert_eq!(Mnemonic::parse(&messy).unwrap().phrase(), m.phrase());
    }

    #[test]
    fn the_passphrase_changes_the_seed() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_ne!(*m.to_seed(""), *m.to_seed("TREZOR"));
    }

    #[test]
    fn a_mnemonic_does_not_render() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let shown = format!("{m:?}");
        assert!(!shown.contains("abandon"));
        assert!(shown.contains("redacted"));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
