//! Accounts and resource credits.

use super::Manabar;
use crate::asset::Amount;
use crate::authority::Authority;
use crate::keys::PublicKey;
use crate::types::PointInTime;
use std::collections::BTreeMap;

/// A delayed vote entry: VESTS not yet eligible to vote for witnesses.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DelayedVote {
    pub time: PointInTime,
    /// Held as a string by the API, since it can exceed JSON's 53-bit number range.
    pub val: String,
}

/// A Hive account, as `condenser_api.get_accounts` and `database_api.find_accounts`
/// return it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub id: u64,
    pub name: String,

    // --- Authorities ---
    pub owner: Authority,
    pub active: Authority,
    pub posting: Authority,
    pub memo_key: PublicKey,

    // --- Metadata ---
    #[serde(default)]
    pub json_metadata: String,
    #[serde(default)]
    pub posting_json_metadata: String,

    // --- Governance ---
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub witnesses_voted_for: u32,
    /// When this account's governance votes expire. Added in HF25; beem predates it.
    #[serde(default)]
    pub governance_vote_expiration_ts: Option<PointInTime>,
    #[serde(default)]
    pub proxied_vsf_votes: Vec<serde_json::Value>,
    #[serde(default)]
    pub delayed_votes: Vec<DelayedVote>,

    // --- Recovery ---
    #[serde(default)]
    pub recovery_account: String,
    #[serde(default)]
    pub reset_account: Option<String>,
    #[serde(default)]
    pub last_account_recovery: Option<PointInTime>,
    #[serde(default)]
    pub last_owner_update: Option<PointInTime>,
    /// Added in HF26.
    #[serde(default)]
    pub previous_owner_update: Option<PointInTime>,
    #[serde(default)]
    pub last_account_update: Option<PointInTime>,

    // --- Balances ---
    pub balance: Amount,
    pub savings_balance: Amount,
    pub hbd_balance: Amount,
    pub savings_hbd_balance: Amount,
    #[serde(default)]
    pub reward_hive_balance: Option<Amount>,
    #[serde(default)]
    pub reward_hbd_balance: Option<Amount>,
    #[serde(default)]
    pub reward_vesting_balance: Option<Amount>,
    #[serde(default)]
    pub reward_vesting_hive: Option<Amount>,

    // --- Vesting ---
    pub vesting_shares: Amount,
    pub delegated_vesting_shares: Amount,
    pub received_vesting_shares: Amount,
    pub vesting_withdraw_rate: Amount,
    #[serde(default)]
    pub post_voting_power: Option<Amount>,
    #[serde(default)]
    pub next_vesting_withdrawal: Option<PointInTime>,
    #[serde(default)]
    pub withdraw_routes: u32,

    // --- Mana ---
    pub voting_manabar: Manabar,
    #[serde(default)]
    pub downvote_manabar: Option<Manabar>,

    // --- Activity ---
    #[serde(default)]
    pub created: Option<PointInTime>,
    #[serde(default)]
    pub post_count: u64,
    #[serde(default)]
    pub comment_count: u64,
    #[serde(default)]
    pub last_post: Option<PointInTime>,
    #[serde(default)]
    pub last_vote_time: Option<PointInTime>,
    #[serde(default)]
    pub can_vote: bool,
    #[serde(default)]
    pub pending_claimed_accounts: u32,
    /// Number of live recurrent transfers. Added in HF25; beem cannot even build the
    /// operation that creates one.
    #[serde(default)]
    pub open_recurrent_transfers: u32,

    /// Anything the node sent that this build does not model.
    ///
    /// A hardfork that adds a field does not silently lose it here.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Account {
    /// Effective VESTS for voting: owned, minus delegated out, plus received.
    ///
    /// This is what determines vote weight, and it is *not* `vesting_shares` — an
    /// account that has delegated most of its stake away still shows the full amount
    /// there.
    pub fn effective_vesting_shares(&self) -> crate::Result<Amount> {
        self.vesting_shares
            .checked_sub(&self.delegated_vesting_shares)?
            .checked_add(&self.received_vesting_shares)
    }

    /// Voting power as a percentage, at `now` (Unix seconds).
    ///
    /// The chain stores the value at the last update and lets clients extrapolate, so
    /// this needs no network call.
    pub fn voting_power(&self, now: u64) -> f64 {
        self.voting_manabar.percentage(self.max_vote_mana(), now)
    }

    /// Downvote power as a percentage. Downvote mana is a quarter of vote mana.
    pub fn downvote_power(&self, now: u64) -> f64 {
        match &self.downvote_manabar {
            None => 0.0,
            Some(bar) => bar.percentage(self.max_vote_mana() / 4, now),
        }
    }

    /// Maximum vote mana: the effective VESTS, in their smallest unit.
    fn max_vote_mana(&self) -> i64 {
        self.effective_vesting_shares()
            .map(|a| a.units())
            .unwrap_or(0)
    }

    /// Whether the account's governance votes have expired at `now`.
    ///
    /// Hive expires witness and proposal votes after a year of inactivity (HF25). An
    /// account in that state still *shows* its votes but they no longer count.
    pub fn governance_votes_expired(&self, now: u64) -> bool {
        match self.governance_vote_expiration_ts {
            None => false,
            Some(ts) => u64::from(ts.unix()) <= now,
        }
    }

    /// Parse `posting_json_metadata`, falling back to `json_metadata`.
    ///
    /// Both are free-form strings that may be empty or invalid JSON — most accounts
    /// have at least one that does not parse — so this returns `None` rather than an
    /// error.
    pub fn profile(&self) -> Option<serde_json::Value> {
        for field in [&self.posting_json_metadata, &self.json_metadata] {
            if field.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(field) {
                if let Some(profile) = value.get("profile") {
                    return Some(profile.clone());
                }
                return Some(value);
            }
        }
        None
    }
}

/// The resource-credit mana bar, as `rc_api.find_rc_accounts` returns it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RcManabar {
    pub current_mana: serde_json::Value,
    pub last_update_time: u64,
}

impl RcManabar {
    /// The stored mana as an integer.
    ///
    /// hived sends this as a string on some endpoints and a number on others, because
    /// RC values exceed JSON's 53-bit safe integer range.
    pub fn current_mana(&self) -> i64 {
        match &self.current_mana {
            serde_json::Value::String(s) => s.parse().unwrap_or(0),
            serde_json::Value::Number(n) => n.as_i64().unwrap_or(0),
            _ => 0,
        }
    }

    /// As a plain [`Manabar`].
    pub fn as_manabar(&self) -> Manabar {
        Manabar {
            current_mana: self.current_mana(),
            last_update_time: self.last_update_time,
        }
    }
}

/// An account's resource credits.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RcAccount {
    pub account: String,
    pub rc_manabar: RcManabar,
    /// Maximum RC, sent as a string for the same range reason.
    pub max_rc: serde_json::Value,
    #[serde(default)]
    pub max_rc_creation_adjustment: Option<Amount>,
    #[serde(default)]
    pub delegated_rc: Option<serde_json::Value>,
    #[serde(default)]
    pub received_delegated_rc: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl RcAccount {
    /// Maximum RC as an integer.
    pub fn max_rc(&self) -> i64 {
        match &self.max_rc {
            serde_json::Value::String(s) => s.parse().unwrap_or(0),
            serde_json::Value::Number(n) => n.as_i64().unwrap_or(0),
            _ => 0,
        }
    }

    /// RC available at `now`.
    pub fn current_rc(&self, now: u64) -> i64 {
        self.rc_manabar.as_manabar().current(self.max_rc(), now)
    }

    /// RC as a percentage of the maximum at `now`.
    pub fn percentage(&self, now: u64) -> f64 {
        self.rc_manabar.as_manabar().percentage(self.max_rc(), now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::Chain;

    /// A real `condenser_api.get_accounts` response, trimmed to the modelled fields
    /// plus one this build does not know about.
    const SAMPLE: &str = r#"{
        "id": 1370484,
        "name": "hiveio",
        "owner": {"weight_threshold": 1, "account_auths": [], "key_auths": [["STM65PUAPA4yC4RgPtGgsPupxT6yJtMhmT5JHFdsT3uoCbR8WJ25s", 1]]},
        "active": {"weight_threshold": 1, "account_auths": [["pettycash", 1]], "key_auths": []},
        "posting": {"weight_threshold": 1, "account_auths": [["threespeak", 1]], "key_auths": []},
        "memo_key": "STM7wrsg1BZogeK7X3eG4ivxmLaH69FomR8rLkBbepb3z3hm5SbXu",
        "json_metadata": "",
        "posting_json_metadata": "{\"profile\":{\"name\":\"Hive\",\"website\":\"hive.io\"}}",
        "proxy": "",
        "previous_owner_update": "1970-01-01T00:00:00",
        "last_owner_update": "1970-01-01T00:00:00",
        "last_account_update": "2021-11-09T21:56:27",
        "created": "2020-03-06T12:22:51",
        "recovery_account": "steempeak",
        "reset_account": "null",
        "comment_count": 0,
        "post_count": 81,
        "can_vote": true,
        "voting_manabar": {"current_mana": 314566314850, "last_update_time": 1754586540},
        "downvote_manabar": {"current_mana": 78641578712, "last_update_time": 1754586540},
        "balance": "283.442 HIVE",
        "savings_balance": "0.000 HIVE",
        "hbd_balance": "50.418 HBD",
        "savings_hbd_balance": "0.000 HBD",
        "reward_hbd_balance": "0.076 HBD",
        "reward_hive_balance": "0.000 HIVE",
        "reward_vesting_balance": "1210.467281 VESTS",
        "reward_vesting_hive": "0.737 HIVE",
        "vesting_shares": "314566.314850 VESTS",
        "delegated_vesting_shares": "0.000000 VESTS",
        "received_vesting_shares": "0.000000 VESTS",
        "vesting_withdraw_rate": "0.000000 VESTS",
        "post_voting_power": "314566.314850 VESTS",
        "next_vesting_withdrawal": "1969-12-31T23:59:59",
        "withdraw_routes": 0,
        "witnesses_voted_for": 0,
        "last_post": "2025-12-31T19:41:36",
        "last_vote_time": "2025-01-01T06:03:33",
        "pending_claimed_accounts": 0,
        "governance_vote_expiration_ts": "1969-12-31T23:59:59",
        "delayed_votes": [],
        "open_recurrent_transfers": 0,
        "a_field_from_a_future_hardfork": 42
    }"#;

    fn sample() -> Account {
        serde_json::from_str(SAMPLE).unwrap()
    }

    #[test]
    fn parses_a_real_account_response() {
        let a = sample();
        assert_eq!(a.name, "hiveio");
        assert_eq!(a.id, 1_370_484);
        assert_eq!(a.balance.to_string(), "283.442 HIVE");
        assert_eq!(a.hbd_balance.to_string(), "50.418 HBD");
        assert_eq!(a.vesting_shares.units(), 314_566_314_850);
        assert_eq!(a.recovery_account, "steempeak");
        assert_eq!(a.owner.key_auths().len(), 1);
        assert_eq!(a.active.account_auths()[0].account, "pettycash");
    }

    #[test]
    fn keeps_fields_it_does_not_model() {
        // A hardfork that adds a field must not silently lose it.
        let a = sample();
        assert_eq!(
            a.extra.get("a_field_from_a_future_hardfork"),
            Some(&serde_json::json!(42))
        );
    }

    #[test]
    fn post_hf25_fields_are_present() {
        // beem predates all three of these.
        let a = sample();
        assert!(a.governance_vote_expiration_ts.is_some());
        assert_eq!(a.open_recurrent_transfers, 0);
        assert!(a.previous_owner_update.is_some());
    }

    #[test]
    fn effective_vesting_accounts_for_delegation() {
        let mut a = sample();
        a.vesting_shares = Amount::parse("1000.000000 VESTS", Chain::Hive).unwrap();
        a.delegated_vesting_shares = Amount::parse("300.000000 VESTS", Chain::Hive).unwrap();
        a.received_vesting_shares = Amount::parse("50.000000 VESTS", Chain::Hive).unwrap();
        assert_eq!(
            a.effective_vesting_shares().unwrap().to_string(),
            "750.000000 VESTS"
        );
    }

    #[test]
    fn voting_power_extrapolates_without_a_network_call() {
        let mut a = sample();
        a.vesting_shares = Amount::parse("1000.000000 VESTS", Chain::Hive).unwrap();
        a.delegated_vesting_shares = Amount::parse("0.000000 VESTS", Chain::Hive).unwrap();
        a.received_vesting_shares = Amount::parse("0.000000 VESTS", Chain::Hive).unwrap();
        let max = a.effective_vesting_shares().unwrap().units();

        a.voting_manabar = Manabar {
            current_mana: max / 2,
            last_update_time: 1000,
        };
        assert!((a.voting_power(1000) - 50.0).abs() < 0.01);
        // Fully regenerated five days later.
        assert!((a.voting_power(1000 + super::super::REGENERATION_SECONDS) - 100.0).abs() < 0.01);
    }

    #[test]
    fn downvote_mana_is_a_quarter_of_vote_mana() {
        let mut a = sample();
        a.vesting_shares = Amount::parse("1000.000000 VESTS", Chain::Hive).unwrap();
        a.delegated_vesting_shares = Amount::parse("0.000000 VESTS", Chain::Hive).unwrap();
        a.received_vesting_shares = Amount::parse("0.000000 VESTS", Chain::Hive).unwrap();
        let quarter = a.effective_vesting_shares().unwrap().units() / 4;
        a.downvote_manabar = Some(Manabar {
            current_mana: quarter,
            last_update_time: 0,
        });
        assert!((a.downvote_power(0) - 100.0).abs() < 0.01);
    }

    #[test]
    fn governance_expiry_is_computed_not_guessed() {
        let mut a = sample();
        a.governance_vote_expiration_ts = Some(PointInTime::from_unix(2_000_000_000).unwrap());
        assert!(!a.governance_votes_expired(1_000_000_000));
        assert!(a.governance_votes_expired(2_000_000_001));
        a.governance_vote_expiration_ts = None;
        assert!(!a.governance_votes_expired(u64::MAX));
    }

    #[test]
    fn profile_survives_empty_and_invalid_metadata() {
        let a = sample();
        assert_eq!(a.profile().unwrap()["website"], "hive.io");

        let mut broken = sample();
        broken.posting_json_metadata = "not json".into();
        broken.json_metadata = String::new();
        assert!(
            broken.profile().is_none(),
            "must not error on unparsable metadata"
        );

        let mut fallback = sample();
        fallback.posting_json_metadata = String::new();
        fallback.json_metadata = r#"{"profile":{"name":"from json_metadata"}}"#.into();
        assert_eq!(fallback.profile().unwrap()["name"], "from json_metadata");
    }

    #[test]
    fn rc_accounts_handle_string_and_numeric_mana() {
        let as_string: RcAccount = serde_json::from_str(
            r#"{"account":"a","rc_manabar":{"current_mana":"5000000000000","last_update_time":1000},"max_rc":"10000000000000"}"#,
        )
        .unwrap();
        assert_eq!(as_string.max_rc(), 10_000_000_000_000);
        assert_eq!(as_string.rc_manabar.current_mana(), 5_000_000_000_000);
        assert!((as_string.percentage(1000) - 50.0).abs() < 0.01);

        let as_number: RcAccount = serde_json::from_str(
            r#"{"account":"a","rc_manabar":{"current_mana":500,"last_update_time":0},"max_rc":1000}"#,
        )
        .unwrap();
        assert_eq!(as_number.max_rc(), 1000);
        assert!((as_number.percentage(0) - 50.0).abs() < 0.01);
    }

    #[test]
    fn round_trips_through_json() {
        let a = sample();
        let json = serde_json::to_string(&a).unwrap();
        let back: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }
}
