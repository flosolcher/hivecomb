//! Deriving keys from passwords and brain keys.
//!
//! Both schemes here are defined by the Graphene/Hive ecosystem, not chosen by this
//! crate. They are reproduced exactly so that keys created by existing wallets remain
//! reachable — but two of their properties are genuine weaknesses that callers should
//! know about, and one outright bug is fixed.
//!
//! # The password scheme is weak by construction
//!
//! [`PasswordKey`] is `sha256(account || role || password)`: one unsalted, unstretched
//! SHA-256 over a human-chosen password. There is no work factor, so an attacker who
//! knows an account's public key can test password guesses at raw SHA-256 speed —
//! billions per second on commodity GPUs. That is a property of Hive's master-password
//! scheme, not of this implementation, and it cannot be fixed without breaking
//! compatibility. It is documented here, and [`PasswordKey::new`] takes a
//! deliberately-named argument to make the choice visible at the call site.
//!
//! Prefer storing an explicit posting/active key. Do not derive from a
//! human-memorable password for anything that holds value.
//!
//! # The brain-key suggester was biased; it is fixed here
//!
//! beem's `BrainKey.suggest` picked each word with:
//!
//! ```python
//! num = int.from_bytes(os.urandom(2), byteorder="little")   # 0 .. 65535
//! rndMult = num / 2 ** 16                                   # float in [0, 1)
//! wIdx = int(round(len(dict_lines) * rndMult))              # 0 .. 49744
//! ```
//!
//! Three defects compound:
//!
//! 1. **Scaling bias.** 65536 equiprobable draws are mapped onto 49744 words. Because
//!    65536 is not a multiple of 49744, some words are selected by two source values
//!    and others by one — roughly a 2:1 probability ratio across the dictionary.
//! 2. **Half-width end buckets.** `round()` sends only `[0, 0.5)` of a bucket to index
//!    0 and only `[n-0.5, n)` to the last index, so the extreme words are half as
//!    likely as the rest.
//! 3. **Out-of-range index.** `round(49744 * rndMult)` can return `49744`, one past
//!    the end, which is an `IndexError` — an outright crash roughly once every 130k
//!    words drawn.
//!
//! The measurable cost of (1) and (2) is entropy: an unbiased draw from 49744 words is
//! 15.60 bits, and the biased draw is lower, so a 16-word "249-bit" brain key carries
//! meaningfully less than advertised. [`BrainKey::suggest`] uses rejection sampling and
//! is exactly uniform.

use super::PrivateKey;
use crate::error::{Error, Result};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

/// The Graphene brain-key word list: 49,744 lowercase English words.
static BRAINKEY_WORDS: &str = include_str!("../../data/brainkey_words.txt");

/// Number of words in the brain-key dictionary.
pub const BRAINKEY_WORD_COUNT: usize = 49_744;

/// A Hive authority role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Full control, including changing the other keys. Should live offline.
    Owner,
    /// Moves funds and changes account settings.
    Active,
    /// Posts, votes and `custom_json`. Cannot touch funds, which is why it is the
    /// only one that belongs in a running service.
    Posting,
    /// Encrypts and decrypts memos. Not a signing key.
    Memo,
}

impl Role {
    /// The literal used in the derivation string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Active => "active",
            Role::Posting => "posting",
            Role::Memo => "memo",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "owner" => Ok(Role::Owner),
            "active" => Ok(Role::Active),
            "posting" => Ok(Role::Posting),
            "memo" => Ok(Role::Memo),
            other => Err(Error::Unknown {
                kind: "role",
                name: other.to_string(),
            }),
        }
    }
}

/// Collapse all runs of whitespace to a single space and trim the ends.
///
/// Graphene normalises seeds this way before hashing. Getting it wrong produces a
/// different — and therefore inaccessible — key, so it is shared by both schemes.
fn normalize(seed: &str) -> String {
    seed.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Derives a role key from an account name and master password.
///
/// See this module's documentation for why this scheme is weak. It is provided for
/// compatibility with Hive's account creation flow, which defines it.
pub struct PasswordKey {
    account: String,
    role: Role,
    password: Zeroizing<String>,
}

/// Redacted: this type holds a master password, which derives every role key.
impl std::fmt::Debug for PasswordKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordKey")
            .field("account", &self.account)
            .field("role", &self.role)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl PasswordKey {
    /// Build a deriver.
    ///
    /// `i_understand_this_is_unstretched` must be `true`. It exists so that choosing
    /// an unstretched password-derived key is a visible decision at the call site
    /// rather than an accident.
    pub fn new(
        account: &str,
        role: Role,
        password: &str,
        i_understand_this_is_unstretched: bool,
    ) -> Result<Self> {
        if !i_understand_this_is_unstretched {
            return Err(Error::key(
                "PasswordKey derives a key with a single unsalted SHA-256 and no work \
                 factor; pass `true` to acknowledge, or use an explicit WIF instead",
            ));
        }
        if password.is_empty() {
            return Err(Error::key("password is empty"));
        }
        Ok(PasswordKey {
            account: account.to_string(),
            role,
            password: Zeroizing::new(password.to_string()),
        })
    }

    /// Derive the private key.
    pub fn private_key(&self) -> Result<PrivateKey> {
        let seed = Zeroizing::new(normalize(&format!(
            "{}{}{}",
            self.account,
            self.role.as_str(),
            *self.password
        )));
        let scalar = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(seed.as_bytes())));
        PrivateKey::from_bytes(&*scalar)
    }
}

/// A Graphene brain key: a passphrase plus a sequence number.
pub struct BrainKey {
    phrase: Zeroizing<String>,
    sequence: u32,
}

/// Redacted: the phrase *is* the key material.
impl std::fmt::Debug for BrainKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrainKey")
            .field("phrase", &"<redacted>")
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl BrainKey {
    /// Wrap an existing brain key phrase.
    ///
    /// The phrase is normalised on the way in, matching Graphene.
    pub fn new(phrase: &str, sequence: u32) -> Result<Self> {
        let normalized = normalize(phrase);
        if normalized.is_empty() {
            return Err(Error::key("brain key phrase is empty"));
        }
        Ok(BrainKey {
            phrase: Zeroizing::new(normalized),
            sequence,
        })
    }

    /// The normalised phrase.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// The current sequence number.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Advance to the next sequence number.
    pub fn next_sequence(&mut self) {
        self.sequence = self.sequence.saturating_add(1);
    }

    /// Derive the key for the current sequence: `sha256(sha512("<phrase> <sequence>"))`.
    pub fn private_key(&self) -> Result<PrivateKey> {
        let encoded = Zeroizing::new(format!("{} {}", *self.phrase, self.sequence));
        let outer = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(encoded.as_bytes())));
        let scalar = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(*outer)));
        PrivateKey::from_bytes(&*scalar)
    }

    /// Derive the sequence-less "blind" key: `sha256(phrase)`.
    pub fn blind_private_key(&self) -> Result<PrivateKey> {
        let scalar = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(self.phrase.as_bytes())));
        PrivateKey::from_bytes(&*scalar)
    }

    /// Suggest a new brain key of `word_count` words, drawn uniformly at random.
    ///
    /// Uses OS randomness with rejection sampling, so every word in the dictionary is
    /// exactly equally likely. See this module's documentation for the bias this replaces.
    ///
    /// Hive wallets conventionally use 16 words (~249.6 bits). Fewer than 12 is
    /// refused.
    pub fn suggest(word_count: usize) -> Result<String> {
        use rand::RngCore;

        if word_count < 12 {
            return Err(Error::key(format!(
                "a brain key of {word_count} words carries too little entropy; use at least 12"
            )));
        }
        let words: Vec<&str> = BRAINKEY_WORDS.lines().collect();
        if words.len() != BRAINKEY_WORD_COUNT {
            return Err(Error::key(format!(
                "brain key dictionary has {} words, expected {BRAINKEY_WORD_COUNT}",
                words.len()
            )));
        }

        let n = words.len() as u32;
        // Largest multiple of `n` that fits in u32; draws at or above it are rejected
        // so the remaining range divides evenly and the modulo is unbiased.
        let limit = u32::MAX - (u32::MAX % n) - (n - 1);

        let mut rng = rand::rngs::OsRng;
        let mut out = Vec::with_capacity(word_count);
        for _ in 0..word_count {
            let idx = loop {
                let v = rng.next_u32();
                if v < limit {
                    break (v % n) as usize;
                }
            };
            out.push(words[idx].to_ascii_uppercase());
        }
        Ok(out.join(" "))
    }

    /// Entropy in bits of a brain key with `word_count` uniformly-drawn words.
    pub fn entropy_bits(word_count: usize) -> f64 {
        (BRAINKEY_WORD_COUNT as f64).log2() * word_count as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_is_the_expected_size() {
        assert_eq!(BRAINKEY_WORDS.lines().count(), BRAINKEY_WORD_COUNT);
    }

    #[test]
    fn dictionary_content_is_pinned() {
        // The words and their order decide which brain keys can be regenerated,
        // so any change to this file loses somebody's account. A project-wide
        // rename really did rewrite the word "comb" here once; this is the guard
        // that would have caught it.
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(BRAINKEY_WORDS.as_bytes());
        assert_eq!(
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "79712a3a4f237913598f981ada879afc11fecd7f8e01052349a23682e74b06be",
            "the brain-key dictionary has been modified; it must match beem's exactly"
        );
        // A spot check that reads as English, so a corrupted file is obvious.
        let words: Vec<&str> = BRAINKEY_WORDS.lines().collect();
        assert_eq!(words[0], "a");
        assert!(words.contains(&"comb"));
        assert!(words.contains(&"zymurgy"));
    }

    #[test]
    fn normalization_matches_graphene() {
        assert_eq!(normalize("  a \t b \n\n c  "), "a b c");
        assert_eq!(normalize("single"), "single");
        assert_eq!(normalize("   "), "");
    }

    #[test]
    fn password_key_is_deterministic_and_role_dependent() {
        let posting = PasswordKey::new("alice", Role::Posting, "hunter2", true)
            .unwrap()
            .private_key()
            .unwrap();
        let active = PasswordKey::new("alice", Role::Active, "hunter2", true)
            .unwrap()
            .private_key()
            .unwrap();
        let again = PasswordKey::new("alice", Role::Posting, "hunter2", true)
            .unwrap()
            .private_key()
            .unwrap();
        assert_eq!(posting, again);
        assert_ne!(posting, active);
    }

    #[test]
    fn password_key_requires_the_acknowledgement() {
        assert!(PasswordKey::new("alice", Role::Posting, "hunter2", false).is_err());
        assert!(PasswordKey::new("alice", Role::Posting, "", true).is_err());
    }

    #[test]
    fn brain_key_is_deterministic_across_sequences() {
        let mut bk = BrainKey::new("SOME BRAIN KEY WORDS HERE", 0).unwrap();
        let k0 = bk.private_key().unwrap();
        bk.next_sequence();
        let k1 = bk.private_key().unwrap();
        assert_ne!(k0, k1);
        assert_eq!(
            BrainKey::new("SOME BRAIN KEY WORDS HERE", 0)
                .unwrap()
                .private_key()
                .unwrap(),
            k0
        );
    }

    #[test]
    fn brain_key_normalizes_whitespace() {
        let a = BrainKey::new("ONE  TWO\tTHREE", 0).unwrap();
        let b = BrainKey::new(" ONE TWO THREE ", 0).unwrap();
        assert_eq!(a.phrase(), b.phrase());
        assert_eq!(a.private_key().unwrap(), b.private_key().unwrap());
    }

    #[test]
    fn suggest_produces_the_requested_word_count() {
        let s = BrainKey::suggest(16).unwrap();
        assert_eq!(s.split(' ').count(), 16);
        assert_eq!(s, s.to_uppercase());
        assert_ne!(s, BrainKey::suggest(16).unwrap());
    }

    #[test]
    fn suggest_refuses_low_entropy_word_counts() {
        assert!(BrainKey::suggest(4).is_err());
        assert!(BrainKey::suggest(11).is_err());
        assert!(BrainKey::suggest(12).is_ok());
    }

    #[test]
    fn suggest_never_goes_out_of_range() {
        // beem's `int(round(n * rndMult))` could return `n` itself. Draw enough words
        // that the old code would have been overwhelmingly likely to fault.
        for _ in 0..20 {
            let s = BrainKey::suggest(64).unwrap();
            assert_eq!(s.split(' ').count(), 64);
        }
    }

    #[test]
    fn entropy_matches_the_dictionary() {
        let bits = BrainKey::entropy_bits(16);
        assert!(
            (bits - 249.6).abs() < 0.5,
            "16 words is about 249.6 bits, got {bits}"
        );
    }
}
