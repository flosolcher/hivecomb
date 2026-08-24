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
use crate::types::{write_array, write_u16, write_u32, GrapheneSerialize};

/// A weighted account entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountAuth {
    /// The account whose authority of the same role is deferred to.
    pub account: String,
    /// How much this contributes towards the threshold.
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
    /// A key that can sign for this authority.
    pub key: PublicKey,
    /// How much a signature from this key contributes towards the threshold.
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

    /// Check a set of public keys against this authority.
    ///
    /// Returns how much weight they carry and whether that meets the threshold.
    ///
    /// # `satisfied` is a lower bound, and the report says so
    ///
    /// An authority can delegate to **another account** through `account_auths`,
    /// and resolving those means fetching that account's authority from a node —
    /// possibly recursively, since hived allows up to 4 levels. This function is
    /// offline, so it cannot follow them.
    ///
    /// Rather than ignore them, it lists them in
    /// [`AuthorityCheck::unresolved_accounts`]. So:
    ///
    /// * `satisfied == true` means **definitely satisfied**, from keys alone;
    /// * `satisfied == false` with an empty `unresolved_accounts` means
    ///   **definitely not satisfied**;
    /// * `satisfied == false` with entries there means **not from keys alone** —
    ///   the answer depends on accounts this call could not look up.
    ///
    /// Collapsing that third case into a plain `false` is what makes an offline
    /// authority check quietly wrong for any account that shares posting rights,
    /// which on Hive is most of them.
    pub fn check(&self, keys: &[PublicKey]) -> AuthorityCheck {
        let mut weight: u64 = 0;
        let mut matched = Vec::new();
        for entry in &self.key_auths {
            if keys.contains(&entry.key) {
                weight += u64::from(entry.weight);
                matched.push(entry.key);
            }
        }
        AuthorityCheck {
            satisfied: weight >= u64::from(self.weight_threshold),
            weight,
            threshold: self.weight_threshold,
            matched_keys: matched,
            unresolved_accounts: self.account_auths.clone(),
        }
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
        // hived's `validate_auth_size` sums the two lists against one budget:
        //
        //     size = a.account_auths.size() + a.key_auths.size();
        //     assert( size <= HIVE_MAX_AUTHORITY_MEMBERSHIP );
        //
        // One budget of forty between them, not forty each — which is the reading a
        // caller is most likely to get wrong, since the two lists are separate fields.
        let entries = self.account_auths.len() + self.key_auths.len();
        if entries > crate::operations::MAX_AUTHORITY_MEMBERSHIP {
            return Err(Error::field(format!(
                "authority names {entries} entries across account_auths and key_auths; \
                 hived allows at most {} between them",
                crate::operations::MAX_AUTHORITY_MEMBERSHIP
            )));
        }
        write_u32(out, self.weight_threshold);
        write_array(out, &self.account_auths)?;
        write_array(out, &self.key_auths)?;
        Ok(())
    }
}

/// hived sends authority entries as `["name", weight]` pairs.
impl<'de> serde::Deserialize<'de> for AccountAuth {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let (account, weight) = <(String, u16)>::deserialize(d)?;
        Ok(AccountAuth { account, weight })
    }
}

/// Sent as `["STM7...", weight]`.
impl<'de> serde::Deserialize<'de> for KeyAuth {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let (key, weight) = <(PublicKey, u16)>::deserialize(d)?;
        Ok(KeyAuth { key, weight })
    }
}

/// Re-validates on the way in: an authority from the network that is unsorted or
/// duplicated is refused rather than accepted into a value that would then
/// re-serialize differently.
impl<'de> serde::Deserialize<'de> for Authority {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(serde::Deserialize)]
        struct Raw {
            weight_threshold: u32,
            #[serde(default)]
            account_auths: Vec<AccountAuth>,
            #[serde(default)]
            key_auths: Vec<KeyAuth>,
        }
        let raw = Raw::deserialize(d)?;
        Authority::new(raw.weight_threshold, raw.account_auths, raw.key_auths)
            .map_err(D::Error::custom)
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

/// The result of checking keys against an [`Authority`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityCheck {
    /// Whether the matched keys alone meet the threshold.
    ///
    /// `false` with a non-empty [`Self::unresolved_accounts`] means "not from
    /// keys alone", not "no".
    pub satisfied: bool,
    /// Total weight of the keys that matched.
    pub weight: u64,
    /// The threshold that weight is measured against.
    pub threshold: u32,
    /// The keys that carried weight.
    pub matched_keys: Vec<PublicKey>,
    /// Delegations to other accounts, which an offline check cannot follow.
    pub unresolved_accounts: Vec<AccountAuth>,
}

impl AuthorityCheck {
    /// Whether the answer is final, or depends on accounts not looked up.
    pub fn is_conclusive(&self) -> bool {
        self.satisfied || self.unresolved_accounts.is_empty()
    }

    /// How much more weight is needed, if any.
    pub fn shortfall(&self) -> u64 {
        u64::from(self.threshold).saturating_sub(self.weight)
    }
}

#[cfg(test)]
mod tests {

    /// hived sums `account_auths` and `key_auths` against one budget of forty, not
    /// forty each — the reading a caller is most likely to get wrong, since they are
    /// separate fields.
    #[test]
    fn the_two_authority_lists_share_one_membership_budget() {
        use crate::operations::MAX_AUTHORITY_MEMBERSHIP;
        use crate::types::GrapheneSerialize;

        let accounts = |n: usize| {
            (0..n)
                .map(|i| AccountAuth {
                    account: format!("acct{i:04}"),
                    weight: 1,
                })
                .collect::<Vec<_>>()
        };
        let one_key = vec![KeyAuth {
            key: key(1),
            weight: 1,
        }];

        // One short of the budget in accounts, plus one key, is exactly the budget.
        let at =
            Authority::new(1, accounts(MAX_AUTHORITY_MEMBERSHIP - 1), one_key.clone()).unwrap();
        let mut out = Vec::new();
        assert!(
            at.append_to(&mut out).is_ok(),
            "exactly the budget is allowed"
        );

        // The full budget in accounts *plus* a key is one too many — which it would not
        // be if each list had its own forty.
        let over = Authority::new(1, accounts(MAX_AUTHORITY_MEMBERSHIP), one_key).unwrap();
        let mut out = Vec::new();
        assert!(
            over.append_to(&mut out).is_err(),
            "the two lists share one budget, so this is one past it"
        );
    }
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
    fn checking_keys_against_an_authority() {
        let a = key(1);
        let b = key(2);
        let stranger = key(3);
        let auth = Authority::new(
            2,
            Vec::new(),
            vec![KeyAuth { key: a, weight: 1 }, KeyAuth { key: b, weight: 1 }],
        )
        .unwrap();

        let neither = auth.check(&[stranger]);
        assert!(!neither.satisfied);
        assert_eq!(neither.weight, 0);
        assert_eq!(neither.shortfall(), 2);
        assert!(
            neither.is_conclusive(),
            "no delegations, so this is a real no"
        );

        let one = auth.check(&[a]);
        assert!(!one.satisfied);
        assert_eq!(one.weight, 1);
        assert_eq!(one.matched_keys, vec![a]);

        let both = auth.check(&[a, b, stranger]);
        assert!(both.satisfied);
        assert_eq!(both.weight, 2);
        assert_eq!(both.shortfall(), 0);
    }

    #[test]
    fn a_delegated_authority_is_reported_as_unresolved_not_as_a_no() {
        // The case that makes an offline check quietly wrong if account_auths
        // are ignored: @alice can post through @bot, and the keys alone say no.
        let auth = Authority::new(
            1,
            vec![AccountAuth {
                account: "bot".into(),
                weight: 1,
            }],
            vec![KeyAuth {
                key: key(1),
                weight: 1,
            }],
        )
        .unwrap();

        let stranger = auth.check(&[key(9)]);
        assert!(!stranger.satisfied);
        assert!(
            !stranger.is_conclusive(),
            "the answer depends on @bot's authority, which was not fetched"
        );
        assert_eq!(stranger.unresolved_accounts.len(), 1);
        assert_eq!(stranger.unresolved_accounts[0].account, "bot");

        // With the key, it is a definite yes and the delegation is moot.
        let holder = auth.check(&[key(1)]);
        assert!(holder.satisfied);
        assert!(holder.is_conclusive());
    }

    #[test]
    fn weights_do_not_overflow_on_a_pathological_authority() {
        let auths: Vec<KeyAuth> = (1..=40)
            .map(|n| KeyAuth {
                key: key(n),
                weight: u16::MAX,
            })
            .collect();
        let keys: Vec<PublicKey> = auths.iter().map(|k| k.key).collect();
        let auth = Authority::new(u32::MAX, Vec::new(), auths).unwrap();
        let check = auth.check(&keys);
        assert_eq!(check.weight, u64::from(u16::MAX) * 40);
        assert!(!check.satisfied);
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
