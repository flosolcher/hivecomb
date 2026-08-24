//! BIP-32 hierarchical deterministic keys, and the derivation paths Hive wallets use.
//!
//! One seed — usually from a [`crate::bip39::Mnemonic`] — derives every role key for
//! every account, reproducibly. This is what Hive Keychain and Vessel do, and it is
//! strictly better than the brain keys and password keys Graphene shipped with: the
//! seed is high-entropy by construction and the derivation is hardened.
//!
//! # Paths
//!
//! Hive wallets use **BIP-48** with network index 13:
//!
//! ```text
//! m/48'/13'/<role>'/<account>'/<key>'
//! ```
//!
//! where role is `0` owner, `1` active, `3` memo, `4` posting. [`Role::bip48_index`]
//! encodes that mapping, which is otherwise a set of magic numbers scattered across
//! call sites — beem inlines it as an if/elif chain in `set_path_BIP48`.
//!
//! `m/44'/0'/<account>'/<chain>/<key>` (BIP-44) is also supported for wallets that
//! chose it.
//!
//! # Only hardened derivation from private keys
//!
//! Public (non-hardened) child derivation is deliberately **not** implemented. Its one
//! real use is watch-only wallets, and it carries a sharp edge: an extended public key
//! plus any one non-hardened child *private* key recovers the parent private key, and
//! therefore every sibling. For a library that exists to hold posting and active keys,
//! that trade is not worth making silently. Non-hardened *child* indices still work
//! when derived from a private key, which is what BIP-44 paths need.

use crate::error::{Error, Result};
use crate::keys::{PrivateKey, PublicKey, Role};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// The first hardened index. Anything at or above this is hardened.
pub const HARDENED: u32 = 0x8000_0000;

/// Hive's BIP-48 network index.
pub const HIVE_NETWORK_INDEX: u32 = 13;

/// Hive's registered SLIP-44 coin type, for BIP-44 style paths.
pub const HIVE_COIN_TYPE: u32 = 3054;

impl Role {
    /// The role's index in a BIP-48 path.
    ///
    /// Note that these are **not** contiguous: memo is 3 and posting is 4, with 2
    /// unused. Hive wallets agree on this mapping and it cannot be tidied.
    pub fn bip48_index(&self) -> u32 {
        match self {
            Role::Owner => 0,
            Role::Active => 1,
            Role::Memo => 3,
            Role::Posting => 4,
        }
    }
}

/// An extended private key: a key plus the chain code that lets it derive children.
#[derive(Clone)]
pub struct ExtendedPrivateKey {
    key: PrivateKey,
    chain_code: Zeroizing<[u8; 32]>,
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
}

impl std::fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedPrivateKey")
            .field("key", &"<redacted>")
            .field("chain_code", &"<redacted>")
            .field("depth", &self.depth)
            .field("child_number", &self.child_number)
            .finish()
    }
}

/// The BIP-32 identifier of a node: the first four bytes of `ripemd160(sha256(pubkey))`.
///
/// Takes the public key rather than the node so a caller that has already derived it does
/// not pay for a second scalar multiplication.
fn fingerprint_of(public: &PublicKey) -> [u8; 4] {
    let sha = Sha256::digest(public.to_bytes());
    let ripe = <ripemd::Ripemd160 as Digest>::digest(sha);
    [ripe[0], ripe[1], ripe[2], ripe[3]]
}

impl ExtendedPrivateKey {
    /// Derive the master key from a seed.
    ///
    /// `I = HMAC-SHA512("Bitcoin seed", seed)`; the left half is the key and the right
    /// half the chain code. The seed must be 16–64 bytes, as BIP-32 requires.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if !(16..=64).contains(&seed.len()) {
            return Err(Error::key(format!(
                "BIP-32 seed must be 16 to 64 bytes, got {}",
                seed.len()
            )));
        }
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
            .map_err(|e| Error::key(format!("HMAC init failed: {e}")))?;
        mac.update(seed);
        let i = Zeroizing::new(<[u8; 64]>::from(mac.finalize().into_bytes()));

        let mut chain_code = Zeroizing::new([0u8; 32]);
        chain_code.copy_from_slice(&i[32..]);
        Ok(ExtendedPrivateKey {
            key: PrivateKey::from_bytes(&i[..32])?,
            chain_code,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
        })
    }

    /// The private key at this node.
    pub fn private_key(&self) -> &PrivateKey {
        &self.key
    }

    /// The public key at this node.
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// Depth below the master key.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// This node's child index, as given to [`Self::derive_child`].
    pub fn child_number(&self) -> u32 {
        self.child_number
    }

    /// The first four bytes of `ripemd160(sha256(pubkey))`, identifying this node.
    pub fn fingerprint(&self) -> [u8; 4] {
        fingerprint_of(&self.public_key())
    }

    /// Derive one child.
    ///
    /// `index >= HARDENED` is a hardened derivation.
    pub fn derive_child(&self, index: u32) -> Result<Self> {
        let mut mac = HmacSha512::new_from_slice(&*self.chain_code)
            .map_err(|e| Error::key(format!("HMAC init failed: {e}")))?;

        // Deriving the public key is a scalar multiplication -- at ~23 microseconds it is
        // by a wide margin the most expensive thing in this function. A normal derivation
        // needs it for the HMAC and *every* derivation needs it again for the child's
        // parent fingerprint, so it is computed once here and reused. It used to be
        // computed twice on the normal path.
        let public = self.public_key();
        if index >= HARDENED {
            // Hardened: 0x00 || parent private key || index
            mac.update(&[0u8]);
            mac.update(&*self.key.expose_secret());
        } else {
            // Normal: parent public key || index
            mac.update(&public.to_bytes());
        }
        mac.update(&index.to_be_bytes());
        let i = Zeroizing::new(<[u8; 64]>::from(mac.finalize().into_bytes()));

        // child = (IL + parent) mod n. A zero or out-of-range result is a 1-in-2^127
        // event that BIP-32 says to skip rather than accept.
        let tweak = secp256k1::Scalar::from_be_bytes(i[..32].try_into().unwrap())
            .map_err(|_| Error::key("BIP-32: derived tweak is out of range; use the next index"))?;
        let child = self
            .key
            .inner()
            .add_tweak(&tweak)
            .map_err(|_| Error::key("BIP-32: derived key is invalid; use the next index"))?;

        let mut chain_code = Zeroizing::new([0u8; 32]);
        chain_code.copy_from_slice(&i[32..]);

        Ok(ExtendedPrivateKey {
            key: PrivateKey::from_bytes(&child.secret_bytes())?,
            chain_code,
            depth: self
                .depth
                .checked_add(1)
                .ok_or_else(|| Error::key("BIP-32 derivation is deeper than 255 levels"))?,
            parent_fingerprint: fingerprint_of(&public),
            child_number: index,
        })
    }

    /// Derive along a path such as `m/48'/13'/4'/0'/0'`.
    ///
    /// Both `'` and `h` mark a hardened index. A malformed path is an error; nothing
    /// is guessed.
    pub fn derive_path(&self, path: &str) -> Result<Self> {
        let path = path.trim();
        let mut parts = path.split('/');
        match parts.next() {
            Some("m") | Some("M") => {}
            _ => return Err(Error::key("derivation path must start with 'm'")),
        }
        let mut node = self.clone();
        for part in parts {
            if part.is_empty() {
                return Err(Error::key("derivation path has an empty component"));
            }
            let (digits, hardened) = match part.strip_suffix(['\'', 'h', 'H']) {
                Some(d) => (d, true),
                None => (part, false),
            };
            let mut index: u32 = digits
                .parse()
                .map_err(|_| Error::key(format!("path component {part:?} is not a number")))?;
            if index >= HARDENED {
                return Err(Error::key(format!(
                    "path index {index} is at or above the hardened boundary"
                )));
            }
            if hardened {
                index += HARDENED;
            }
            node = node.derive_child(index)?;
        }
        Ok(node)
    }

    /// Derive a Hive role key with the BIP-48 path wallets use.
    ///
    /// `m/48'/13'/<role>'/<account>'/<key>'`
    pub fn derive_hive_role(&self, role: Role, account: u32, key: u32) -> Result<PrivateKey> {
        let path = format!(
            "m/48'/{HIVE_NETWORK_INDEX}'/{}'/{account}'/{key}'",
            role.bip48_index()
        );
        Ok(self.derive_path(&path)?.key)
    }

    /// Serialize as an `xprv` string.
    pub fn to_xprv(&self) -> Zeroizing<String> {
        // Mainnet private: 0x0488ADE4
        self.encode(&[0x04, 0x88, 0xAD, 0xE4], true)
    }

    /// Serialize the matching `xpub` string.
    pub fn to_xpub(&self) -> String {
        // Mainnet public: 0x0488B21E
        self.encode(&[0x04, 0x88, 0xB2, 0x1E], false).to_string()
    }

    fn encode(&self, version: &[u8; 4], private: bool) -> Zeroizing<String> {
        let mut payload = Zeroizing::new(Vec::with_capacity(78));
        payload.extend_from_slice(version);
        payload.push(self.depth);
        payload.extend_from_slice(&self.parent_fingerprint);
        payload.extend_from_slice(&self.child_number.to_be_bytes());
        payload.extend_from_slice(&*self.chain_code);
        if private {
            payload.push(0);
            payload.extend_from_slice(&*self.key.expose_secret());
        } else {
            payload.extend_from_slice(&self.public_key().to_bytes());
        }
        Zeroizing::new(crate::base58::encode_check(&payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn bip32_test_vector_1() {
        // The canonical BIP-32 vector: seed 000102030405060708090a0b0c0d0e0f.
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        assert_eq!(
            &*master.to_xprv(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );
        assert_eq!(
            master.to_xpub(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );

        // m/0'
        let child = master.derive_path("m/0'").unwrap();
        assert_eq!(
            &*child.to_xprv(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );

        // m/0'/1
        let grandchild = master.derive_path("m/0'/1").unwrap();
        assert_eq!(
            &*grandchild.to_xprv(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        );
        assert_eq!(grandchild.depth(), 2);
    }

    #[test]
    fn paths_accept_both_hardened_markers() {
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        let m = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let a = m.derive_path("m/48'/13'/4'/0'/0'").unwrap();
        let b = m.derive_path("m/48h/13h/4h/0h/0h").unwrap();
        assert_eq!(a.private_key(), b.private_key());
    }

    #[test]
    fn malformed_paths_are_refused() {
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        let m = ExtendedPrivateKey::from_seed(&seed).unwrap();
        for bad in ["48'/13'", "m/", "m//1", "m/x", "m/-1", "m/2147483648", ""] {
            assert!(m.derive_path(bad).is_err(), "should reject path {bad:?}");
        }
        assert!(m.derive_path("m").is_ok(), "a bare 'm' is the master key");
    }

    #[test]
    fn hive_roles_use_bip48_and_differ_from_each_other() {
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        let m = ExtendedPrivateKey::from_seed(&seed).unwrap();

        let posting = m.derive_hive_role(Role::Posting, 0, 0).unwrap();
        let active = m.derive_hive_role(Role::Active, 0, 0).unwrap();
        let owner = m.derive_hive_role(Role::Owner, 0, 0).unwrap();
        let memo = m.derive_hive_role(Role::Memo, 0, 0).unwrap();

        let all = [&posting, &active, &owner, &memo];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "role keys must be distinct");
            }
        }
        // ...and the path is the one wallets use.
        assert_eq!(
            m.derive_path("m/48'/13'/4'/0'/0'").unwrap().private_key(),
            &posting
        );
        assert_eq!(
            m.derive_path("m/48'/13'/1'/0'/0'").unwrap().private_key(),
            &active
        );
    }

    #[test]
    fn the_bip48_role_indices_are_not_contiguous() {
        // memo is 3 and posting is 4; index 2 is unused. Wallets agree on this.
        assert_eq!(Role::Owner.bip48_index(), 0);
        assert_eq!(Role::Active.bip48_index(), 1);
        assert_eq!(Role::Memo.bip48_index(), 3);
        assert_eq!(Role::Posting.bip48_index(), 4);
    }

    #[test]
    fn different_accounts_and_key_indices_give_different_keys() {
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        let m = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let a = m.derive_hive_role(Role::Posting, 0, 0).unwrap();
        let b = m.derive_hive_role(Role::Posting, 1, 0).unwrap();
        let c = m.derive_hive_role(Role::Posting, 0, 1).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn derivation_is_deterministic_from_a_mnemonic() {
        use crate::bip39::Mnemonic;
        let mnemonic = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let seed = mnemonic.to_seed("");
        let a = ExtendedPrivateKey::from_seed(&*seed).unwrap();
        let b = ExtendedPrivateKey::from_seed(&*seed).unwrap();
        assert_eq!(
            a.derive_hive_role(Role::Posting, 0, 0).unwrap(),
            b.derive_hive_role(Role::Posting, 0, 0).unwrap()
        );
    }

    #[test]
    fn seed_length_is_validated() {
        assert!(ExtendedPrivateKey::from_seed(&[0u8; 15]).is_err());
        assert!(ExtendedPrivateKey::from_seed(&[0u8; 65]).is_err());
        assert!(ExtendedPrivateKey::from_seed(&[1u8; 16]).is_ok());
        assert!(ExtendedPrivateKey::from_seed(&[1u8; 64]).is_ok());
    }

    #[test]
    fn extended_keys_do_not_render_their_secret() {
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        let m = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let shown = format!("{m:?}");
        assert!(shown.contains("redacted"));
        assert!(!shown.contains(&hex(&*m.private_key().expose_secret())));
    }

    #[test]
    fn fingerprints_chain_correctly() {
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        let m = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let child = m.derive_child(HARDENED).unwrap();
        assert_eq!(child.parent_fingerprint, m.fingerprint());
        assert_eq!(child.depth(), 1);
        assert_eq!(child.child_number(), HARDENED);
    }
}
