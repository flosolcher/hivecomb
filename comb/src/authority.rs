//! Authorities: the weighted key/account sets behind Hive's owner, active and posting
//! permissions.
//!
//! An `authority` is a threshold plus two weighted maps — one of account names, one of
//! public keys. A signature set satisfies it when the weights of the entries it
//! satisfies sum to at least the threshold.
//!
//! # Ordering matters, and beem got it wrong
//!
//! Both maps are `flat_map` in hived: **sorted, with unique keys**. The sort order is
//! over the serialized key, and it is part of the signed bytes — two authorities with
//! the same entries in a different order serialize differently and produce different
//! signatures.
//!
//! beem's `PublicKey.__lt__` sorted by the **ripemd160 address** instead:
//!
//! ```python
//! def __lt__(self, other):
//!     return repr(self.address) < repr(other.address)
//! ```
//!
//! The address is `ripemd160(sha256(pubkey))`, which orders keys essentially at random
//! relative to their serialized form. Any authority holding more than one key could
//! therefore serialize in an order hived does not accept.
//!
//! [`Authority`] sorts by the serialized key and rejects duplicates.

use crate::error::{Error, Result};
use crate::keys::PublicKey;
use crate::reader::GrapheneDeserialize;
use crate::types::{write_array, write_u16, write_u32, GrapheneSerialize};

/// A weighted account entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountAuth {
    pub account: String,
    pub weight: u16,
}

/// hived renders authority entries as `["name", weight]` pairs, not objects.
impl serde::Serialize for AccountAuth {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(2)?;
        t.serialize_element(&self.account)?;
        t.serialize_element(&self.weight)?;
        t.end()
    }
}

impl GrapheneSerialize for AccountAuth {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        crate::types::write_string(out, &self.account)?;
        write_u16(out, self.weight);
        Ok(())
    }
}

/// A weighted key entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAuth {
    pub key: PublicKey,
    pub weight: u16,
}

/// Rendered as `["STM7...", weight]`.
impl serde::Serialize for KeyAuth {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(2)?;
        t.serialize_element(&self.key)?;
        t.serialize_element(&self.weight)?;
        t.end()
    }
}

impl GrapheneSerialize for KeyAuth {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        self.key.append_to(out)?;
        write_u16(out, self.weight);
        Ok(())
    }
}

/// A Hive authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Authority {
    /// Total weight required to satisfy this authority.
    pub weight_threshold: u32,
    /// Weighted account entries, kept sorted and unique.
    account_auths: Vec<AccountAuth>,
    /// Weighted key entries, kept sorted and unique.
    key_auths: Vec<KeyAuth>,
}

impl Authority {
    /// Build an authority, sorting both maps and rejecting duplicate entries.
    pub fn new(
        weight_threshold: u32,
        mut account_auths: Vec<AccountAuth>,
        mut key_auths: Vec<KeyAuth>,
    ) -> Result<Self> {
        account_auths.sort_by(|a, b| a.account.cmp(&b.account));
        if account_auths
            .windows(2)
            .any(|w| w[0].account == w[1].account)
        {
            return Err(Error::field("authority lists the same account twice"));
        }

        // Sort by the serialized key, which is what hived's flat_map orders by.
        key_auths.sort_by_key(|k| k.key.to_bytes());
        if key_auths.windows(2).any(|w| w[0].key == w[1].key) {
            return Err(Error::field("authority lists the same key twice"));
        }

        if weight_threshold == 0 {
            return Err(Error::field("authority weight_threshold must be non-zero"));
        }

        Ok(Authority {
            weight_threshold,
            account_auths,
            key_auths,
        })
    }

    /// A single-key authority with threshold 1 — the common case.
    pub fn from_key(key: PublicKey) -> Result<Self> {
        Self::new(1, Vec::new(), vec![KeyAuth { key, weight: 1 }])
    }

    /// The account entries, in serialization order.
    pub fn account_auths(&self) -> &[AccountAuth] {
        &self.account_auths
    }

    /// The key entries, in serialization order.
    pub fn key_auths(&self) -> &[KeyAuth] {
        &self.key_auths
    }

    /// Whether the declared weights can ever reach the threshold.
    ///
    /// An authority whose weights sum below its threshold can never be satisfied by
    /// anyone — for an `owner` authority that means a permanently locked account.
    /// hived rejects it; this lets a caller find out before broadcasting.
    pub fn is_satisfiable(&self) -> bool {
        let total: u64 = self
            .account_auths
            .iter()
            .map(|a| u64::from(a.weight))
            .chain(self.key_auths.iter().map(|k| u64::from(k.weight)))
            .sum();
        total >= u64::from(self.weight_threshold)
    }
}

impl GrapheneSerialize for Authority {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_u32(out, self.weight_threshold);
        write_array(out, &self.account_auths)?;
        write_array(out, &self.key_auths)?;
        Ok(())
    }
}

impl crate::reader::GrapheneDeserialize for AccountAuth {
    fn read_from(r: &mut crate::reader::Reader<'_>) -> Result<Self> {
        Ok(AccountAuth {
            account: r.string()?,
            weight: r.u16()?,
        })
    }
}

impl crate::reader::GrapheneDeserialize for KeyAuth {
    fn read_from(r: &mut crate::reader::Reader<'_>) -> Result<Self> {
        Ok(KeyAuth {
            key: PublicKey::read_from(r)?,
            weight: r.u16()?,
        })
    }
}

impl crate::reader::GrapheneDeserialize for Authority {
    /// Reads and re-validates: the sort and uniqueness invariants are enforced on the
    /// way in, so a peer that sent an unsorted or duplicated map is rejected rather
    /// than quietly accepted into a value that would then re-serialize differently.
    fn read_from(r: &mut crate::reader::Reader<'_>) -> Result<Self> {
        let weight_threshold = r.u32()?;
        let account_auths: Vec<AccountAuth> = r.array()?;
        let key_auths: Vec<KeyAuth> = r.array()?;
        Authority::new(weight_threshold, account_auths, key_auths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PrivateKey;

    fn key(n: u8) -> PublicKey {
        let mut bytes = [1u8; 32];
        bytes[31] = n;
        PrivateKey::from_bytes(&bytes).unwrap().public_key()
    }

    #[test]
    fn keys_are_sorted_by_serialized_form() {
        let a = key(1);
        let b = key(2);
        let c = key(3);
        let auth = Authority::new(
            1,
            Vec::new(),
            vec![
                KeyAuth { key: c, weight: 1 },
                KeyAuth { key: a, weight: 1 },
                KeyAuth { key: b, weight: 1 },
            ],
        )
        .unwrap();
        let order: Vec<_> = auth.key_auths().iter().map(|k| k.key.to_bytes()).collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted, "keys must serialize in ascending key order");
    }

    #[test]
    fn accounts_are_sorted() {
        let auth = Authority::new(
            1,
            vec![
                AccountAuth {
                    account: "zulu".into(),
                    weight: 1,
                },
                AccountAuth {
                    account: "alpha".into(),
                    weight: 1,
                },
            ],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(auth.account_auths()[0].account, "alpha");
    }

    #[test]
    fn input_order_does_not_change_the_bytes() {
        let a = key(1);
        let b = key(2);
        let forward = Authority::new(
            2,
            Vec::new(),
            vec![KeyAuth { key: a, weight: 1 }, KeyAuth { key: b, weight: 1 }],
        )
        .unwrap();
        let backward = Authority::new(
            2,
            Vec::new(),
            vec![KeyAuth { key: b, weight: 1 }, KeyAuth { key: a, weight: 1 }],
        )
        .unwrap();
        assert_eq!(forward.to_wire().unwrap(), backward.to_wire().unwrap());
    }

    #[test]
    fn duplicates_are_rejected() {
        let a = key(1);
        assert!(Authority::new(
            1,
            Vec::new(),
            vec![KeyAuth { key: a, weight: 1 }, KeyAuth { key: a, weight: 2 }]
        )
        .is_err());
        assert!(Authority::new(
            1,
            vec![
                AccountAuth {
                    account: "bob".into(),
                    weight: 1
                },
                AccountAuth {
                    account: "bob".into(),
                    weight: 1
                }
            ],
            Vec::new()
        )
        .is_err());
    }

    #[test]
    fn zero_threshold_is_rejected() {
        assert!(Authority::new(
            0,
            Vec::new(),
            vec![KeyAuth {
                key: key(1),
                weight: 1
            }]
        )
        .is_err());
    }

    #[test]
    fn unsatisfiable_authorities_are_detectable() {
        let auth = Authority::new(
            5,
            Vec::new(),
            vec![KeyAuth {
                key: key(1),
                weight: 1,
            }],
        )
        .unwrap();
        assert!(
            !auth.is_satisfiable(),
            "an owner authority like this locks the account"
        );
        assert!(Authority::from_key(key(1)).unwrap().is_satisfiable());
    }

    #[test]
    fn wire_layout() {
        let auth = Authority::from_key(key(1)).unwrap();
        let wire = auth.to_wire().unwrap();
        // u32 threshold + varint 0 accounts + varint 1 key + 33 key bytes + u16 weight
        assert_eq!(wire.len(), 4 + 1 + 1 + 33 + 2);
        assert_eq!(&wire[0..4], &1u32.to_le_bytes());
        assert_eq!(wire[4], 0, "no account auths");
        assert_eq!(wire[5], 1, "one key auth");
    }
}
