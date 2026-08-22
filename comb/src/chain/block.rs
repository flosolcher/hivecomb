//! Blocks, global properties and the reward/feed state.

use crate::asset::Amount;
use crate::keys::PublicKey;
use crate::sign::Signature;
use crate::types::PointInTime;
use std::collections::BTreeMap;

/// A block header.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub previous: String,
    pub timestamp: PointInTime,
    pub witness: String,
    pub transaction_merkle_root: String,
    #[serde(default)]
    pub extensions: Vec<serde_json::Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl BlockHeader {
    /// The block number, read from the first four bytes of `previous` plus one.
    ///
    /// A block id embeds its own number big-endian in its leading four bytes, so a
    /// block's number is its predecessor's plus one. This is why a block does not carry
    /// its number as a field.
    pub fn block_num(&self) -> crate::Result<u32> {
        let previous = crate::transaction::BlockRef::from_block_id(&self.previous)?;
        Ok(previous.block_num + 1)
    }
}

/// A full block, as `block_api.get_block` returns it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub previous: String,
    pub timestamp: PointInTime,
    pub witness: String,
    pub transaction_merkle_root: String,
    #[serde(default)]
    pub extensions: Vec<serde_json::Value>,
    #[serde(default)]
    pub witness_signature: Option<String>,
    #[serde(default)]
    pub transactions: Vec<serde_json::Value>,
    #[serde(default)]
    pub block_id: Option<String>,
    #[serde(default)]
    pub signing_key: Option<PublicKey>,
    #[serde(default)]
    pub transaction_ids: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Block {
    /// The block number.
    pub fn block_num(&self) -> crate::Result<u32> {
        match &self.block_id {
            Some(id) => Ok(crate::transaction::BlockRef::from_block_id(id)?.block_num),
            None => {
                let previous = crate::transaction::BlockRef::from_block_id(&self.previous)?;
                Ok(previous.block_num + 1)
            }
        }
    }

    /// The witness signature, parsed.
    pub fn signature(&self) -> Option<crate::Result<Signature>> {
        self.witness_signature
            .as_ref()
            .map(|s| Signature::from_hex(s))
    }

    /// Every operation in the block, signed and virtual alike, flattened across
    /// transactions.
    pub fn operations(&self) -> crate::Result<Vec<crate::operations::AnyOperation>> {
        let mut out = Vec::new();
        for tx in &self.transactions {
            if let Some(ops) = tx.get("operations").and_then(|o| o.as_array()) {
                for op in ops {
                    out.push(crate::operations::AnyOperation::from_json(op)?);
                }
            }
        }
        Ok(out)
    }
}

/// `database_api.get_dynamic_global_properties`.
///
/// The extended form; [`crate::rpc::DynamicGlobalProperties`] carries only the fields
/// the TaPoS path needs, so that the signing path does not depend on this shape.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DynamicGlobalProperties {
    pub head_block_number: u32,
    pub head_block_id: String,
    pub time: PointInTime,
    pub current_witness: String,
    #[serde(default)]
    pub last_irreversible_block_num: u32,
    #[serde(default)]
    pub current_supply: Option<Amount>,
    #[serde(default)]
    pub current_hbd_supply: Option<Amount>,
    #[serde(default)]
    pub total_vesting_fund_hive: Option<Amount>,
    #[serde(default)]
    pub total_vesting_shares: Option<Amount>,
    #[serde(default)]
    pub hbd_interest_rate: Option<u16>,
    #[serde(default)]
    pub maximum_block_size: Option<u32>,
    #[serde(default)]
    pub participation_count: Option<u32>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl DynamicGlobalProperties {
    /// Convert VESTS to HIVE using the current global ratio.
    ///
    /// This is the conversion behind "Hive Power": VESTS are a share of
    /// `total_vesting_fund_hive`, and the ratio moves every block. Returns `None` when
    /// the node did not send the totals — `condenser_api` includes them,
    /// `database_api` does not always.
    pub fn vests_to_hive(&self, vests: &Amount) -> Option<crate::Result<Amount>> {
        let fund = self.total_vesting_fund_hive.as_ref()?;
        let total = self.total_vesting_shares.as_ref()?;
        if total.units() == 0 {
            return None;
        }
        // i128 throughout: VESTS totals are ~10^17 units and multiplying by the fund
        // would overflow i64 several times over.
        let hive_units =
            i128::from(vests.units()) * i128::from(fund.units()) / i128::from(total.units());
        Some(Amount::from_units(
            hive_units as i64,
            fund.symbol(),
            crate::chains::Chain::Hive,
        ))
    }

    /// Convert HIVE to VESTS using the current global ratio.
    pub fn hive_to_vests(&self, hive: &Amount) -> Option<crate::Result<Amount>> {
        let fund = self.total_vesting_fund_hive.as_ref()?;
        let total = self.total_vesting_shares.as_ref()?;
        if fund.units() == 0 {
            return None;
        }
        let vest_units =
            i128::from(hive.units()) * i128::from(total.units()) / i128::from(fund.units());
        Some(Amount::from_units(
            vest_units as i64,
            total.symbol(),
            crate::chains::Chain::Hive,
        ))
    }
}

/// `database_api.get_feed_history` — the witness price feed and its median.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FeedHistory {
    pub current_median_history: super::PriceFeed,
    #[serde(default)]
    pub price_history: Vec<super::PriceFeed>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// A reward fund, as `database_api.get_reward_funds` returns it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RewardFund {
    pub name: String,
    pub reward_balance: Amount,
    #[serde(default)]
    pub recent_claims: Option<String>,
    #[serde(default)]
    pub last_update: Option<PointInTime>,
    #[serde(default)]
    pub author_reward_curve: Option<String>,
    #[serde(default)]
    pub curation_reward_curve: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::Chain;

    #[test]
    fn block_number_comes_from_the_previous_id() {
        let header: BlockHeader = serde_json::from_str(
            r#"{"previous":"0682cd082661d0deec68a9a0cad32f49376d03c2",
                "timestamp":"2026-08-22T03:23:33","witness":"abit",
                "transaction_merkle_root":"0000000000000000000000000000000000000000"}"#,
        )
        .unwrap();
        // 0x0682cd08 = 109235464, so this block is 109235465.
        assert_eq!(header.block_num().unwrap(), 109_235_465);
        assert_eq!(header.witness, "abit");
    }

    #[test]
    fn a_block_prefers_its_own_id_when_it_has_one() {
        let block: Block = serde_json::from_str(
            r#"{"previous":"0682cd082661d0deec68a9a0cad32f49376d03c2",
                "timestamp":"2026-08-22T03:23:33","witness":"abit",
                "transaction_merkle_root":"0000000000000000000000000000000000000000",
                "block_id":"0682cd092661d0deec68a9a0cad32f49376d03c2"}"#,
        )
        .unwrap();
        assert_eq!(block.block_num().unwrap(), 109_235_465);
    }

    #[test]
    fn block_operations_flatten_across_transactions() {
        let block: Block = serde_json::from_str(
            r#"{"previous":"0682cd082661d0deec68a9a0cad32f49376d03c2",
                "timestamp":"2026-08-22T03:23:33","witness":"abit",
                "transaction_merkle_root":"0000000000000000000000000000000000000000",
                "transactions":[
                  {"operations":[["vote",{"voter":"a","author":"b","permlink":"p","weight":10000}]]},
                  {"operations":[
                    ["transfer",{"from":"a","to":"b","amount":"1.000 HIVE","memo":""}],
                    ["custom_json",{"required_auths":[],"required_posting_auths":["a"],"id":"x","json":"{}"}]
                  ]}
                ]}"#,
        )
        .unwrap();
        let ops = block.operations().unwrap();
        assert_eq!(ops.len(), 3);
        assert_eq!(
            ops.iter().map(|o| o.name()).collect::<Vec<_>>(),
            vec!["vote", "transfer", "custom_json"]
        );
    }

    #[test]
    fn vests_convert_both_ways_without_overflowing() {
        // Realistic totals: ~180M HIVE in the fund against ~3.4e11 VESTS.
        let props: DynamicGlobalProperties = serde_json::from_str(
            r#"{"head_block_number":1,"head_block_id":"00000001aabbccdd00000000000000000000abcd",
                "time":"2026-08-22T03:23:33","current_witness":"w",
                "total_vesting_fund_hive":"180000000.000 HIVE",
                "total_vesting_shares":"340000000000.000000 VESTS"}"#,
        )
        .unwrap();

        let vests = crate::asset::Amount::parse("340000.000000 VESTS", Chain::Hive).unwrap();
        let hive = props.vests_to_hive(&vests).unwrap().unwrap();
        assert_eq!(hive.symbol(), "HIVE");
        assert_eq!(hive.to_string(), "180.000 HIVE");

        // ...and back again.
        let back = props.hive_to_vests(&hive).unwrap().unwrap();
        assert_eq!(back.to_string(), "340000.000000 VESTS");
    }

    #[test]
    fn conversion_is_none_when_the_node_did_not_send_the_totals() {
        let props: DynamicGlobalProperties = serde_json::from_str(
            r#"{"head_block_number":1,"head_block_id":"00000001aabbccdd00000000000000000000abcd",
                "time":"2026-08-22T03:23:33","current_witness":"w"}"#,
        )
        .unwrap();
        let vests = crate::asset::Amount::parse("1.000000 VESTS", Chain::Hive).unwrap();
        assert!(props.vests_to_hive(&vests).is_none());
    }

    #[test]
    fn unknown_global_properties_are_kept() {
        let props: DynamicGlobalProperties = serde_json::from_str(
            r#"{"head_block_number":1,"head_block_id":"00000001aabbccdd00000000000000000000abcd",
                "time":"2026-08-22T03:23:33","current_witness":"w","total_pow":514415}"#,
        )
        .unwrap();
        assert_eq!(
            props.extra.get("total_pow"),
            Some(&serde_json::json!(514_415))
        );
    }
}
