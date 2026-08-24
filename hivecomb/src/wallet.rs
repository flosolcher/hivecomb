//! An encrypted key store.
//!
//! Holds Hive private keys on disk under a passphrase, indexed by public key and by
//! account/role. Unlocking derives a key from the passphrase; locking wipes it.
//!
//! # This is not beem's format, deliberately
//!
//! beem stores keys in SQLite, encrypted with a random master password, which is itself
//! encrypted with `AESCipher(sha256(user_password))`. That construction has three
//! problems, and reproducing it for wire compatibility would mean reproducing all
//! three:
//!
//! 1. **No key derivation.** `AESCipher.__init__` is
//!    `self.key = hashlib.sha256(key).digest()` — one unsalted SHA-256 of the
//!    passphrase, no work factor. An attacker with the wallet file tests guesses at
//!    raw SHA-256 speed.
//! 2. **No salt.** Two users with the same passphrase get the same encryption key, so
//!    one precomputed table attacks every wallet at once.
//! 3. **No authentication.** AES-CBC with no MAC. Nothing detects a modified wallet
//!    file, and the decrypt path is a padding-oracle shape.
//!
//! `hivecomb` uses **scrypt** for the passphrase (salted, with a real work factor) and
//! **AES-256-GCM** for every ciphertext, so tampering is detected rather than
//! decrypted. The file is JSON, versioned, and documented below.
//!
//! To migrate an existing beem wallet, export the keys with `beempy listkeys` /
//! `beempy getkey` and [`Wallet::add_key`] them here. There is deliberately no reader
//! for the old format: it would mean shipping the weak construction to read files this
//! crate should be helping people leave.
//!
//! # What a passphrase buys you
//!
//! scrypt at `N = 32768, r = 8, p = 1` costs 32 MiB (`128 * r * N`) and a few milliseconds per
//! guess. That is a meaningful multiplier, not a substitute for entropy. A six-word
//! diceware passphrase is fine; a dictionary word is not, whatever the work factor.

use crate::error::{Error, Result};
use crate::keys::{PrivateKey, PublicKey, Role};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Current on-disk format version.
pub const FORMAT_VERSION: u32 = 1;

/// scrypt cost parameter (N = 2^15).
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// A stored key: the encrypted WIF plus enough metadata to find it again.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKey {
    /// The public key, in prefixed form. Not secret, and the primary index.
    public_key: String,
    /// The account this key belongs to, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    /// The role, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    /// Base64 AES-256-GCM nonce, unique per key.
    nonce: String,
    /// Base64 ciphertext of the WIF, with the GCM tag appended.
    ciphertext: String,
}

/// The on-disk file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    /// scrypt salt, base64. Random per wallet — this is what beem lacks.
    salt: String,
    scrypt_log_n: u8,
    scrypt_r: u32,
    scrypt_p: u32,
    /// A known plaintext encrypted under the derived key, so a wrong passphrase is
    /// detected before any key is touched.
    check_nonce: String,
    check_ciphertext: String,
    keys: Vec<StoredKey>,
}

const CHECK_PLAINTEXT: &[u8] = b"hivecomb wallet v1";

fn b64(data: &[u8]) -> String {
    // A small, dependency-free base64. Not performance-critical: this runs once per
    // key, not per byte of a stream.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn unb64(text: &str) -> Result<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = text
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c).ok_or_else(|| Error::key("wallet contains invalid base64"))?
                << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// An encrypted key store.
///
/// Created locked. [`Wallet::unlock`] holds the derived key in memory until
/// [`Wallet::lock`] wipes it or the wallet is dropped.
pub struct Wallet {
    path: PathBuf,
    file: WalletFile,
    cipher: Option<Aes256Gcm>,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("path", &self.path)
            .field("keys", &self.file.keys.len())
            .field("unlocked", &self.cipher.is_some())
            .finish()
    }
}

impl Wallet {
    /// Create a new wallet at `path`, encrypted under `passphrase`.
    ///
    /// Refuses to overwrite an existing file — losing a key store to a mistyped path
    /// is not recoverable.
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(Error::key(format!(
                "{} already exists; refusing to overwrite a key store",
                path.display()
            )));
        }
        if passphrase.is_empty() {
            return Err(Error::key("wallet passphrase is empty"));
        }

        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
        let cipher = Aes256Gcm::new_from_slice(&*key)
            .map_err(|e| Error::key(format!("AES-GCM init failed: {e}")))?;

        let (check_nonce, check_ciphertext) = encrypt_with(&cipher, CHECK_PLAINTEXT)?;
        let file = WalletFile {
            version: FORMAT_VERSION,
            salt: b64(&salt),
            scrypt_log_n: SCRYPT_LOG_N,
            scrypt_r: SCRYPT_R,
            scrypt_p: SCRYPT_P,
            check_nonce,
            check_ciphertext,
            keys: Vec::new(),
        };

        let wallet = Wallet {
            path,
            file,
            cipher: Some(cipher),
        };
        wallet.save()?;
        Ok(wallet)
    }

    /// Open an existing wallet, locked.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error::key(format!("could not read {}: {e}", path.display())))?;
        let file: WalletFile = serde_json::from_str(&text)
            .map_err(|e| Error::key(format!("{} is not a hivecomb wallet: {e}", path.display())))?;
        if file.version != FORMAT_VERSION {
            return Err(Error::key(format!(
                "wallet format version {} is not supported by this build (expected {FORMAT_VERSION})",
                file.version
            )));
        }
        Ok(Wallet {
            path,
            file,
            cipher: None,
        })
    }

    /// Whether the wallet is locked.
    pub fn is_locked(&self) -> bool {
        self.cipher.is_none()
    }

    /// Unlock with a passphrase.
    ///
    /// Verifies against a known plaintext, so a wrong passphrase is reported as such
    /// rather than surfacing later as a corrupt key.
    pub fn unlock(&mut self, passphrase: &str) -> Result<()> {
        let salt = unb64(&self.file.salt)?;
        let key = derive_key(
            passphrase,
            &salt,
            self.file.scrypt_log_n,
            self.file.scrypt_r,
            self.file.scrypt_p,
        )?;
        let cipher = Aes256Gcm::new_from_slice(&*key)
            .map_err(|e| Error::key(format!("AES-GCM init failed: {e}")))?;

        let plaintext = decrypt_with(&cipher, &self.file.check_nonce, &self.file.check_ciphertext)
            .map_err(|_| Error::key("wrong wallet passphrase"))?;
        if plaintext.ct_eq(CHECK_PLAINTEXT).unwrap_u8() != 1 {
            return Err(Error::key("wrong wallet passphrase"));
        }

        self.cipher = Some(cipher);
        Ok(())
    }

    /// Lock the wallet, dropping the derived key.
    pub fn lock(&mut self) {
        self.cipher = None;
    }

    fn cipher(&self) -> Result<&Aes256Gcm> {
        self.cipher
            .as_ref()
            .ok_or_else(|| Error::key("wallet is locked"))
    }

    /// Add a key, optionally tagging it with the account and role it belongs to.
    ///
    /// Adding a key that is already present replaces its metadata rather than storing
    /// a duplicate.
    pub fn add_key(
        &mut self,
        key: &PrivateKey,
        account: Option<&str>,
        role: Option<Role>,
    ) -> Result<PublicKey> {
        let cipher = self.cipher()?;
        let public = key.public_key();
        let public_text = public.to_prefixed("STM");
        let wif = key.to_wif();
        let (nonce, ciphertext) = encrypt_with(cipher, wif.as_bytes())?;

        let entry = StoredKey {
            public_key: public_text.clone(),
            account: account.map(str::to_owned),
            role: role.map(|r| r.as_str().to_owned()),
            nonce,
            ciphertext,
        };
        match self
            .file
            .keys
            .iter_mut()
            .find(|k| k.public_key == public_text)
        {
            Some(existing) => *existing = entry,
            None => self.file.keys.push(entry),
        }
        self.save()?;
        Ok(public)
    }

    /// The public keys held.
    pub fn public_keys(&self) -> Vec<String> {
        self.file
            .keys
            .iter()
            .map(|k| k.public_key.clone())
            .collect()
    }

    /// Number of keys held. Available while locked.
    pub fn len(&self) -> usize {
        self.file.keys.len()
    }

    /// Whether the wallet holds no keys.
    pub fn is_empty(&self) -> bool {
        self.file.keys.is_empty()
    }

    /// Accounts and roles this wallet knows about, whether or not it is unlocked.
    pub fn index(&self) -> BTreeMap<String, Vec<String>> {
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for key in &self.file.keys {
            if let Some(account) = &key.account {
                out.entry(account.clone())
                    .or_default()
                    .push(key.role.clone().unwrap_or_else(|| "unknown".into()));
            }
        }
        out
    }

    /// Retrieve the private key for a public key.
    pub fn key_for_public(&self, public: &PublicKey) -> Result<PrivateKey> {
        let wanted = public.to_prefixed("STM");
        let entry = self
            .file
            .keys
            .iter()
            .find(|k| k.public_key == wanted)
            .ok_or_else(|| Error::key("wallet holds no key for that public key"))?;
        self.decrypt_entry(entry)
    }

    /// Retrieve the private key for an account and role.
    pub fn key_for_role(&self, account: &str, role: Role) -> Result<PrivateKey> {
        let entry = self
            .file
            .keys
            .iter()
            .find(|k| {
                k.account.as_deref() == Some(account) && k.role.as_deref() == Some(role.as_str())
            })
            .ok_or_else(|| {
                Error::key(format!(
                    "wallet holds no {} key for {account}",
                    role.as_str()
                ))
            })?;
        self.decrypt_entry(entry)
    }

    fn decrypt_entry(&self, entry: &StoredKey) -> Result<PrivateKey> {
        let cipher = self.cipher()?;
        let wif = Zeroizing::new(decrypt_with(cipher, &entry.nonce, &entry.ciphertext)?);
        let text =
            std::str::from_utf8(&wif).map_err(|_| Error::key("stored key is not valid UTF-8"))?;
        PrivateKey::from_wif(text)
    }

    /// Remove a key. Returns whether one was removed.
    pub fn remove_key(&mut self, public: &PublicKey) -> Result<bool> {
        let wanted = public.to_prefixed("STM");
        let before = self.file.keys.len();
        self.file.keys.retain(|k| k.public_key != wanted);
        let removed = self.file.keys.len() != before;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Re-encrypt the whole wallet under a new passphrase.
    ///
    /// Requires the wallet to be unlocked, since every key must be decrypted and
    /// re-encrypted. A new salt is drawn, so the old derived key is useless afterwards.
    pub fn change_passphrase(&mut self, new_passphrase: &str) -> Result<()> {
        if new_passphrase.is_empty() {
            return Err(Error::key("wallet passphrase is empty"));
        }
        // Decrypt everything first: if any key fails, nothing is written.
        let mut plain: Vec<(StoredKey, Zeroizing<String>)> =
            Vec::with_capacity(self.file.keys.len());
        for entry in &self.file.keys {
            let key = self.decrypt_entry(entry)?;
            plain.push((entry.clone(), key.to_wif()));
        }

        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let derived = derive_key(new_passphrase, &salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
        let cipher = Aes256Gcm::new_from_slice(&*derived)
            .map_err(|e| Error::key(format!("AES-GCM init failed: {e}")))?;

        let mut keys = Vec::with_capacity(plain.len());
        for (entry, wif) in plain {
            let (nonce, ciphertext) = encrypt_with(&cipher, wif.as_bytes())?;
            keys.push(StoredKey {
                nonce,
                ciphertext,
                ..entry
            });
        }
        let (check_nonce, check_ciphertext) = encrypt_with(&cipher, CHECK_PLAINTEXT)?;

        self.file.salt = b64(&salt);
        self.file.scrypt_log_n = SCRYPT_LOG_N;
        self.file.scrypt_r = SCRYPT_R;
        self.file.scrypt_p = SCRYPT_P;
        self.file.check_nonce = check_nonce;
        self.file.check_ciphertext = check_ciphertext;
        self.file.keys = keys;
        self.cipher = Some(cipher);
        self.save()
    }

    /// Write the wallet to disk.
    ///
    /// Writes to a temporary file and renames, so an interrupted write cannot leave a
    /// truncated key store.
    fn save(&self) -> Result<()> {
        let text = serde_json::to_string_pretty(&self.file)
            .map_err(|e| Error::key(format!("could not encode wallet: {e}")))?;
        let temp = self.path.with_extension("tmp");
        std::fs::write(&temp, text)
            .map_err(|e| Error::key(format!("could not write {}: {e}", temp.display())))?;
        restrict_permissions(&temp)?;
        std::fs::rename(&temp, &self.path)
            .map_err(|e| Error::key(format!("could not replace {}: {e}", self.path.display())))?;
        Ok(())
    }
}

/// Make a wallet file readable only by its owner.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        Error::key(format!(
            "could not set permissions on {}: {e}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = scrypt::Params::new(log_n, r, p, 32)
        .map_err(|e| Error::key(format!("bad scrypt parameters: {e}")))?;
    let mut out = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut *out)
        .map_err(|e| Error::key(format!("scrypt failed: {e}")))?;
    Ok(out)
}

/// Encrypt under a fresh random nonce, returning both base64-encoded.
fn encrypt_with(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<(String, String)> {
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::key("wallet encryption failed"))?;
    Ok((b64(&nonce_bytes), b64(&ciphertext)))
}

/// Decrypt, verifying the GCM tag. A modified wallet file fails here.
fn decrypt_with(cipher: &Aes256Gcm, nonce_b64: &str, ciphertext_b64: &str) -> Result<Vec<u8>> {
    let nonce_bytes = unb64(nonce_b64)?;
    if nonce_bytes.len() != 12 {
        return Err(Error::key("wallet entry has a malformed nonce"));
    }
    let ciphertext = unb64(ciphertext_b64)?;
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| {
            Error::key("wallet entry failed authentication: wrong passphrase or tampered file")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed key used throughout these tests.
    ///
    /// It is published here on purpose and must never hold value. Checked against
    /// `account_by_key_api.get_key_references` on 2026-08-22: **no Hive account uses
    /// it.** Do not fund it, and do not copy it into anything that will.
    const TEST_WIF: &str = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

    /// A scratch path that cleans itself up.
    struct TempPath(PathBuf);

    impl TempPath {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            p.push(format!("hivecomb-wallet-test-{tag}-{unique}.json"));
            TempPath(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(self.0.with_extension("tmp"));
        }
    }

    fn key() -> PrivateKey {
        PrivateKey::from_wif(TEST_WIF).unwrap()
    }

    #[test]
    fn base64_round_trips() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
            assert_eq!(unb64(&b64(&data)).unwrap(), data, "length {len}");
        }
        assert!(unb64("not valid!!").is_err());
    }

    #[test]
    fn create_add_and_retrieve() {
        let temp = TempPath::new("basic");
        let mut wallet = Wallet::create(temp.path(), "a strong passphrase").unwrap();
        assert!(wallet.is_empty());

        let public = wallet
            .add_key(&key(), Some("alice"), Some(Role::Posting))
            .unwrap();
        assert_eq!(wallet.len(), 1);
        assert_eq!(wallet.key_for_public(&public).unwrap(), key());
        assert_eq!(wallet.key_for_role("alice", Role::Posting).unwrap(), key());
    }

    #[test]
    fn reopening_requires_the_passphrase() {
        let temp = TempPath::new("reopen");
        {
            let mut wallet = Wallet::create(temp.path(), "correct").unwrap();
            wallet
                .add_key(&key(), Some("alice"), Some(Role::Active))
                .unwrap();
        }
        let mut wallet = Wallet::open(temp.path()).unwrap();
        assert!(wallet.is_locked());
        assert_eq!(wallet.len(), 1, "the index is readable while locked");

        // Locked: no key material.
        let public = key().public_key();
        assert!(wallet.key_for_public(&public).is_err());

        // Wrong passphrase is reported as such, not as a corrupt key.
        let err = wallet.unlock("wrong").unwrap_err();
        assert!(format!("{err}").contains("wrong wallet passphrase"));

        wallet.unlock("correct").unwrap();
        assert!(!wallet.is_locked());
        assert_eq!(wallet.key_for_public(&public).unwrap(), key());
    }

    #[test]
    fn locking_drops_access() {
        let temp = TempPath::new("lock");
        let mut wallet = Wallet::create(temp.path(), "pass").unwrap();
        let public = wallet.add_key(&key(), None, None).unwrap();
        assert!(wallet.key_for_public(&public).is_ok());
        wallet.lock();
        assert!(wallet.is_locked());
        assert!(wallet.key_for_public(&public).is_err());
    }

    #[test]
    fn a_tampered_wallet_fails_authentication() {
        // This is what beem's unauthenticated AES-CBC cannot do.
        let temp = TempPath::new("tamper");
        {
            let mut wallet = Wallet::create(temp.path(), "pass").unwrap();
            wallet
                .add_key(&key(), Some("alice"), Some(Role::Posting))
                .unwrap();
        }
        let text = std::fs::read_to_string(temp.path()).unwrap();
        let mut file: serde_json::Value = serde_json::from_str(&text).unwrap();
        // Flip a character of the stored ciphertext.
        let ct = file["keys"][0]["ciphertext"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = ct.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        file["keys"][0]["ciphertext"] = serde_json::Value::String(chars.into_iter().collect());
        std::fs::write(temp.path(), serde_json::to_string(&file).unwrap()).unwrap();

        let mut wallet = Wallet::open(temp.path()).unwrap();
        wallet.unlock("pass").unwrap();
        let err = wallet.key_for_role("alice", Role::Posting).unwrap_err();
        assert!(format!("{err}").contains("authentication"));
    }

    #[test]
    fn two_wallets_with_the_same_passphrase_use_different_salts() {
        // beem derives the same key for both, so one table attacks every wallet.
        let a = TempPath::new("salt-a");
        let b = TempPath::new("salt-b");
        Wallet::create(a.path(), "same passphrase").unwrap();
        Wallet::create(b.path(), "same passphrase").unwrap();
        let fa: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(a.path()).unwrap()).unwrap();
        let fb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(b.path()).unwrap()).unwrap();
        assert_ne!(fa["salt"], fb["salt"]);
    }

    #[test]
    fn the_wif_does_not_appear_in_the_file() {
        let temp = TempPath::new("plaintext");
        let mut wallet = Wallet::create(temp.path(), "pass").unwrap();
        wallet
            .add_key(&key(), Some("alice"), Some(Role::Owner))
            .unwrap();
        let text = std::fs::read_to_string(temp.path()).unwrap();
        assert!(!text.contains(TEST_WIF));
        // ...but the public key is there, since it is the index.
        assert!(text.contains(&key().public_key().to_prefixed("STM")));
    }

    #[test]
    fn adding_the_same_key_twice_replaces_rather_than_duplicates() {
        let temp = TempPath::new("dedupe");
        let mut wallet = Wallet::create(temp.path(), "pass").unwrap();
        wallet
            .add_key(&key(), Some("alice"), Some(Role::Posting))
            .unwrap();
        wallet
            .add_key(&key(), Some("alice"), Some(Role::Active))
            .unwrap();
        assert_eq!(wallet.len(), 1);
        assert!(wallet.key_for_role("alice", Role::Active).is_ok());
        assert!(wallet.key_for_role("alice", Role::Posting).is_err());
    }

    #[test]
    fn removing_a_key() {
        let temp = TempPath::new("remove");
        let mut wallet = Wallet::create(temp.path(), "pass").unwrap();
        let public = wallet.add_key(&key(), None, None).unwrap();
        assert!(wallet.remove_key(&public).unwrap());
        assert!(wallet.is_empty());
        assert!(
            !wallet.remove_key(&public).unwrap(),
            "removing twice is not an error"
        );
    }

    #[test]
    fn changing_the_passphrase_rekeys_every_entry() {
        let temp = TempPath::new("rekey");
        let mut wallet = Wallet::create(temp.path(), "old").unwrap();
        let other = PrivateKey::generate();
        wallet
            .add_key(&key(), Some("alice"), Some(Role::Posting))
            .unwrap();
        wallet
            .add_key(&other, Some("bob"), Some(Role::Active))
            .unwrap();

        wallet.change_passphrase("new").unwrap();

        let mut reopened = Wallet::open(temp.path()).unwrap();
        assert!(
            reopened.unlock("old").is_err(),
            "the old passphrase must stop working"
        );
        reopened.unlock("new").unwrap();
        assert_eq!(
            reopened.key_for_role("alice", Role::Posting).unwrap(),
            key()
        );
        assert_eq!(reopened.key_for_role("bob", Role::Active).unwrap(), other);
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let temp = TempPath::new("overwrite");
        Wallet::create(temp.path(), "pass").unwrap();
        let err = Wallet::create(temp.path(), "other").unwrap_err();
        assert!(format!("{err}").contains("refusing to overwrite"));
    }

    #[test]
    fn an_empty_passphrase_is_refused() {
        let temp = TempPath::new("empty-pass");
        assert!(Wallet::create(temp.path(), "").is_err());
    }

    #[test]
    fn the_index_is_readable_while_locked() {
        let temp = TempPath::new("index");
        {
            let mut wallet = Wallet::create(temp.path(), "pass").unwrap();
            wallet
                .add_key(&key(), Some("alice"), Some(Role::Posting))
                .unwrap();
            wallet
                .add_key(&PrivateKey::generate(), Some("alice"), Some(Role::Active))
                .unwrap();
        }
        let wallet = Wallet::open(temp.path()).unwrap();
        assert!(wallet.is_locked());
        let index = wallet.index();
        let mut roles = index["alice"].clone();
        roles.sort();
        assert_eq!(roles, vec!["active", "posting"]);
    }

    #[test]
    fn a_wallet_does_not_render_its_contents() {
        let temp = TempPath::new("debug");
        let mut wallet = Wallet::create(temp.path(), "pass").unwrap();
        wallet.add_key(&key(), None, None).unwrap();
        let shown = format!("{wallet:?}");
        assert!(!shown.contains(TEST_WIF));
        assert!(shown.contains("keys: 1"));
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempPath::new("perms");
        Wallet::create(temp.path(), "pass").unwrap();
        let mode = std::fs::metadata(temp.path()).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "wallet must not be group or world readable"
        );
    }
}
