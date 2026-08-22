//! Witnesses and the price feed.

use crate::asset::Amount;
use crate::keys::MaybePublicKey;
use crate::operations::ChainProperties;
use crate::types::PointInTime;
use std::collections::BTreeMap;

/// A published exchange rate: `base` per `quote`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PriceFeed {
    pub base: Amount,
    pub quote: Amount,
}

impl PriceFeed {
    /// The rate as `base / quote`, or `None` if the quote is zero.
    ///
    /// Returned as `f64` because it is for display and comparison. Never compute a
    /// transfer amount from it — use integer arithmetic on [`Amount`] for that.
    pub fn rate(&self) -> Option<f64> {
        if self.quote.units() == 0 {
            return None;
        }
        let base = self.base.units() as f64 / 10f64.powi(i32::from(self.base.precision()));
        let quote = self.quote.units() as f64 / 10f64.powi(i32::from(self.quote.precision()));
        Some(base / quote)
    }
}

/// A witness, as `condenser_api.get_witness_by_account` returns it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Witness {
    pub id: u64,
    pub owner: String,
    pub created: PointInTime,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub total_missed: u64,
    #[serde(default)]
    pub last_confirmed_block_num: u32,
    /// A retired witness publishes the null key here, which is not a valid curve
    /// point — see [`MaybePublicKey`].
    pub signing_key: MaybePublicKey,
    #[serde(default)]
    pub props: Option<ChainProperties>,
    #[serde(default)]
    pub hbd_exchange_rate: Option<PriceFeed>,
    #[serde(default)]
    pub last_hbd_exchange_update: Option<PointInTime>,
    /// Sent as a string: witness vote weights exceed JSON's safe integer range.
    #[serde(default)]
    pub votes: Option<String>,
    #[serde(default)]
    pub virtual_last_update: Option<String>,
    #[serde(default)]
    pub running_version: Option<String>,
    #[serde(default)]
    pub hardfork_version_vote: Option<String>,
    #[serde(default)]
    pub available_witness_account_subsidies: Option<i64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Witness {
    /// Total votes as an integer.
    pub fn votes(&self) -> i128 {
        self.votes
            .as_deref()
            .and_then(|v| v.parse::<i128>().ok())
            .unwrap_or(0)
    }

    /// Whether the witness has retired.
    ///
    /// A witness disables itself by publishing the null public key: 33 zero bytes,
    /// which is not a point on the curve. That is why `signing_key` is a
    /// [`MaybePublicKey`] rather than a [`crate::keys::PublicKey`] — a type that
    /// insisted on a valid point could not parse a retired witness at all.
    pub fn is_disabled(&self) -> bool {
        self.signing_key.is_null()
    }
}

/// `database_api.get_witness_schedule`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WitnessSchedule {
    #[serde(default)]
    pub current_shuffled_witnesses: Vec<String>,
    #[serde(default)]
    pub num_scheduled_witnesses: Option<u32>,
    #[serde(default)]
    pub median_props: Option<ChainProperties>,
    #[serde(default)]
    pub majority_version: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_witness_response() {
        let w: Witness = serde_json::from_str(
            r#"{"id":1,"owner":"gtg","created":"2016-04-25T17:30:00",
                "url":"https://example.org","total_missed":100,
                "last_confirmed_block_num":109235465,
                "signing_key":"STM7wrsg1BZogeK7X3eG4ivxmLaH69FomR8rLkBbepb3z3hm5SbXu",
                "props":{"account_creation_fee":"3.000 HIVE","maximum_block_size":65536,
                         "hbd_interest_rate":2000},
                "hbd_exchange_rate":{"base":"0.250 HBD","quote":"1.000 HIVE"},
                "votes":"140000000000000000",
                "running_version":"1.27.5"}"#,
        )
        .unwrap();
        assert_eq!(w.owner, "gtg");
        assert_eq!(w.votes(), 140_000_000_000_000_000);
        assert_eq!(w.props.as_ref().unwrap().hbd_interest_rate, 2000);
        assert!(!w.is_disabled());
    }

    #[test]
    fn a_retired_witness_is_recognised() {
        // The null key: a witness publishes this to stop producing.
        let w: Witness = serde_json::from_str(
            r#"{"id":1,"owner":"retired","created":"2016-04-25T17:30:00",
                "signing_key":"STM1111111111111111111111111111111114T1Anm"}"#,
        )
        .unwrap();
        assert!(w.is_disabled());
    }

    #[test]
    fn vote_weights_beyond_the_json_safe_range_survive() {
        // 1.4e17 exceeds JSON's 2^53 safe integer range, which is why hived sends it
        // as a string. Parsing it as f64 would lose the low digits.
        let w: Witness = serde_json::from_str(
            r#"{"id":1,"owner":"a","created":"2016-04-25T17:30:00",
                "signing_key":"STM7wrsg1BZogeK7X3eG4ivxmLaH69FomR8rLkBbepb3z3hm5SbXu",
                "votes":"140000000000000123"}"#,
        )
        .unwrap();
        assert_eq!(w.votes(), 140_000_000_000_000_123);
    }

    #[test]
    fn price_feed_rate() {
        let feed = PriceFeed {
            base: Amount::parse("0.250 HBD", crate::chains::Chain::Hive).unwrap(),
            quote: Amount::parse("1.000 HIVE", crate::chains::Chain::Hive).unwrap(),
        };
        assert!((feed.rate().unwrap() - 0.25).abs() < 1e-9);

        let zero = PriceFeed {
            base: Amount::parse("0.250 HBD", crate::chains::Chain::Hive).unwrap(),
            quote: Amount::parse("0.000 HIVE", crate::chains::Chain::Hive).unwrap(),
        };
        assert!(zero.rate().is_none(), "must not divide by zero");
    }
}
