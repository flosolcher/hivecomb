//! Hive operations: the things a transaction contains.
//!
//! [`OperationId`] is the complete table of hived's operation static variant, virtual
//! operations included. [`Operation`] is the subset a client can construct and sign;
//! virtual operations are deliberately absent from it, because they cannot be
//! broadcast and modelling them as constructible would invite exactly that mistake.
//!
//! # Field order is consensus
//!
//! Each operation serializes its fields in declaration order with no names and no
//! padding, so an omitted, reordered or mistyped field does not fail — it produces a
//! valid signature over different bytes. Every struct here is ordered to match
//! `libraries/protocol/include/hive/protocol/hive_operations.hpp`, and the field
//! order is pinned by tests.

mod ids;
pub mod virtual_ops;

pub use ids::{all_names, OperationId, FIRST_VIRTUAL_OP, LAST_OP};
pub use virtual_ops::VirtualOperation;

use crate::asset::Amount;
use crate::authority::Authority;
use crate::error::{Error, Result};
use crate::keys::PublicKey;
use crate::reader::{GrapheneDeserialize, Reader};
use crate::types::{
    write_array, write_bool, write_i16, write_optional, write_string, write_u16, write_u32,
    write_u64, write_varint32, GrapheneSerialize, PointInTime,
};

/// Maximum length of a `custom_json` id, from hived's `custom_id_type`.
pub const MAX_CUSTOM_ID_LEN: usize = 32;

/// Entries an [`crate::authority::Authority`] may hold in total.
///
/// hived's `HIVE_MAX_AUTHORITY_MEMBERSHIP`. `validate_auth_size` asserts
/// `account_auths.size() + key_auths.size() <= HIVE_MAX_AUTHORITY_MEMBERSHIP`, so the
/// two kinds share one budget of 40 rather than having 40 each.
///
/// The same constant separately bounds the auth lists on the three custom operations,
/// where it is `required_auths.size() + required_posting_auths.size()`.
pub const MAX_AUTHORITY_MEMBERSHIP: usize = 40;

/// Beneficiaries a comment may name.
///
/// hived asserts `beneficiaries.size() < HIVE_BENEFICIARY_LIMIT` against a constant of
/// 128, so the usable maximum is **127** — and the comment beside it explains why the
/// bound exists at all: "Require size serialization fits in one byte."
///
/// Note this is **not** `HIVE_MAX_COMMENT_BENEFICIARIES`, which is 8 and which
/// `comment_payout_beneficiaries::validate` does not use. A constant that looks like the
/// limit and is not; the transaction size limit has the same trap.
pub const MAX_BENEFICIARIES: usize = 127;

/// Longest proposal subject, in bytes.
///
/// `validate_string_max_size( subject, HIVE_PROPOSAL_SUBJECT_MAX_LENGTH, ... )` with
/// **no `- 1`**, and that helper is `<=`, so the bound is the constant itself. Unlike
/// the memo and title, which subtract one. Derived rather than assumed for that reason.
pub const MAX_PROPOSAL_SUBJECT_LEN: usize = 80;

/// Proposal ids one `update_proposal_votes` or `remove_proposal` may carry.
///
/// `proposal_ids.size() <= HIVE_PROPOSAL_MAX_IDS_NUMBER`, and separately the list must
/// not be empty.
pub const MAX_PROPOSAL_IDS: usize = 5;

/// Longest witness URL, in bytes.
///
/// `validate_string_max_size( url, HIVE_MAX_WITNESS_URL_LENGTH, ... )` — again with no
/// `- 1`, so the bound is the constant. Applies to `witness_update` and
/// `witness_set_properties`.
pub const MAX_WITNESS_URL_LEN: usize = 2048;

/// Longest memo any operation may carry, in bytes.
///
/// hived writes this as `validate_string_max_size( memo, HIVE_MAX_MEMO_SIZE - 1, ... )`,
/// and `validate_string_max_size` asserts `size() <= max`. So the constant is 2048 and
/// the usable maximum is **2047** — the kind of off-by-one that is invisible unless the
/// helper is read as well as the call site.
///
/// Enforced in `validate()`, so it applies to every transaction unconditionally, on
/// `transfer`, `transfer_to_savings`, `transfer_from_savings` and `recurrent_transfer`.
pub const MAX_MEMO_LEN: usize = 2047;

/// Longest comment title, in bytes.
///
/// `validate_string_max_size( title, HIVE_COMMENT_TITLE_LIMIT - 1, ... )` against a
/// constant of 256, so **255**.
pub const MAX_TITLE_LEN: usize = 255;

/// Longest permlink, in bytes.
///
/// `validate_permlink` asserts `permlink.size() < HIVE_MAX_PERMLINK_LENGTH` against a
/// constant of 256, so **255**. Note the different form: a bare `<` here where the memo
/// and title use `<= constant - 1`. Both arrive at "one less than the constant", by
/// different routes, which is why each is derived rather than assumed.
pub const MAX_PERMLINK_LEN: usize = 255;

/// Custom operations one account may have in a single block.
///
/// hived's `HIVE_CUSTOM_OP_BLOCK_LIMIT`, confirmed against a live node's
/// `database_api.get_config`. Enforced in `database::limit_custom_op_count`, which
/// counts `custom`, `custom_json` and `custom_binary` alike, per **impacted account**,
/// accumulating transactions already pending in the same block.
///
/// It is a rate limit rather than a shape rule, so no node selection routes around it
/// and no library can fully check it — the rest of the block is not visible from here.
pub const MAX_CUSTOM_OPS_PER_BLOCK: usize = 5;

/// Maximum payload of a `custom_json` or `custom` operation, in bytes.
///
/// hived's `HIVE_CUSTOM_OP_DATA_MAX_LENGTH`, confirmed against a live node's
/// `database_api.get_config`.
///
/// # Where this is enforced, which is not where you would look
///
/// Not in `validate()`. `custom_json_operation::validate` checks the *id* length and the
/// JSON's syntax and says nothing about its size; the size is checked in
/// `custom_json_evaluator::do_apply`, behind `has_hardfork(
/// HIVE_HARDFORK_1_26_SOLIDIFY_OLD_SOFTFORKS )`, as is `custom_operation`'s `data`. So it
/// is a consensus rule rather than a shape rule, and it has applied since HF26.
///
/// That distinction matters because it means **nothing upstream will warn a caller**.
/// `condenser_api.get_transaction_hex` is a pure serializer: asked for a `custom_json`
/// carrying 20,000 bytes it returns valid-looking hex without complaint. A library that
/// does not check produces a signable, broadcastable transaction that the chain then
/// refuses **in its entirety** — every operation in it, not merely the oversized one.
pub const MAX_CUSTOM_DATA_LEN: usize = 8192;

/// A price, as used by `feed_publish` and `limit_order_create2`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Price {
    pub base: Amount,
    pub quote: Amount,
}

impl GrapheneSerialize for Price {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        self.base.append_to(out)?;
        self.quote.append_to(out)
    }
}

/// A comment beneficiary route.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Beneficiary {
    pub account: String,
    /// Share in basis points; the total across all beneficiaries may not exceed 10000.
    pub weight: u16,
}

impl GrapheneSerialize for Beneficiary {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_string(out, &self.account)?;
        write_u16(out, self.weight);
        Ok(())
    }
}

/// The `comment_options` extension variant. Tag 0 is the beneficiary list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommentOptionsExtension {
    /// `comment_payout_beneficiaries`
    Beneficiaries(Vec<Beneficiary>),
}

impl GrapheneSerialize for CommentOptionsExtension {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            CommentOptionsExtension::Beneficiaries(list) => {
                if list.is_empty() {
                    return Err(Error::field("beneficiaries must name at least one account"));
                }
                if list.len() > MAX_BENEFICIARIES {
                    return Err(Error::field(format!(
                        "{} beneficiaries; hived allows at most {MAX_BENEFICIARIES}",
                        list.len()
                    )));
                }
                let total: u32 = list.iter().map(|b| u32::from(b.weight)).sum();
                if total > 10_000 {
                    return Err(Error::field(format!(
                        "beneficiary weights total {total} basis points, which exceeds 10000"
                    )));
                }
                // hived requires the beneficiary list sorted by account and unique.
                let mut sorted = list.clone();
                sorted.sort_by(|a, b| a.account.cmp(&b.account));
                if sorted.windows(2).any(|w| w[0].account == w[1].account) {
                    return Err(Error::field("the same beneficiary is listed twice"));
                }
                write_varint32(out, 0);
                write_array(out, &sorted)
            }
        }
    }
}

/// Renders as `[0, {"beneficiaries": [...]}]`, the static-variant JSON form.
impl serde::Serialize for CommentOptionsExtension {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        match self {
            CommentOptionsExtension::Beneficiaries(list) => {
                let mut sorted = list.clone();
                sorted.sort_by(|a, b| a.account.cmp(&b.account));
                let mut t = s.serialize_tuple(2)?;
                t.serialize_element(&0u8)?;
                t.serialize_element(&serde_json::json!({ "beneficiaries": sorted }))?;
                t.end()
            }
        }
    }
}

/// Parsed from `[0, {"beneficiaries": [...]}]`.
impl<'de> serde::Deserialize<'de> for CommentOptionsExtension {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(serde::Deserialize)]
        struct Beneficiaries {
            beneficiaries: Vec<Beneficiary>,
        }
        let (tag, value) = <(u32, serde_json::Value)>::deserialize(d)?;
        match tag {
            0 => {
                let b: Beneficiaries = serde_json::from_value(value).map_err(D::Error::custom)?;
                Ok(CommentOptionsExtension::Beneficiaries(b.beneficiaries))
            }
            other => Err(D::Error::custom(format!(
                "unknown comment_options extension variant {other}"
            ))),
        }
    }
}

/// A `recurrent_transfer` extension. Tag 1 carries the HF28 `pair_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecurrentTransferExtension {
    /// `recurrent_transfer_pair_id`, added in HF28 so an account can run several
    /// concurrent recurrent transfers to the same recipient. beem predates this
    /// entirely.
    ///
    /// One byte, not two. hived declares this `uint8_t`, and it *truncates* rather
    /// than rejecting: asked to serialize `pair_id: 258` it writes `0x02`, and
    /// `65535` writes `0xff`. Holding it as a `u8` here makes that unrepresentable
    /// instead of silently wrong.
    PairId(u8),
}

impl GrapheneSerialize for RecurrentTransferExtension {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            RecurrentTransferExtension::PairId(id) => {
                write_varint32(out, 1);
                out.push(*id);
                Ok(())
            }
        }
    }
}

/// Renders as `{"type": "recurrent_transfer_pair_id", "value": {"pair_id": n}}`.
///
/// Not as `[1, {"pair_id": n}]`. Most Graphene static variants accept the `[tag, value]`
/// pair in JSON, and this one does not: hived answers a `recurrent_transfer` carrying an
/// array-form extension with `Bad Cast: Input data have to treated as object, but got
/// array_type`, so the transaction cannot be broadcast at all. The binary encoding is
/// unaffected -- it is the varint tag followed by the `u16`, either way -- which is what
/// makes the array form easy to ship untested: everything round-trips locally and only
/// the node objects.
///
/// Verified against `condenser_api.get_transaction_hex` on a live node.
impl serde::Serialize for RecurrentTransferExtension {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        match self {
            RecurrentTransferExtension::PairId(id) => {
                let mut t = s.serialize_struct("extension", 2)?;
                t.serialize_field("type", "recurrent_transfer_pair_id")?;
                t.serialize_field("value", &serde_json::json!({ "pair_id": id }))?;
                t.end()
            }
        }
    }
}

/// Accepts the `{"type", "value"}` form hived emits, and the `[tag, value]` form that
/// older tooling writes, so a transaction built elsewhere still parses.
impl<'de> serde::Deserialize<'de> for RecurrentTransferExtension {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(serde::Deserialize)]
        struct PairId {
            pair_id: u8,
        }

        let raw = serde_json::Value::deserialize(d)?;
        let value = match &raw {
            serde_json::Value::Object(map) => {
                let tag = map
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| D::Error::custom("extension object has no `type`"))?;
                if tag != "recurrent_transfer_pair_id" {
                    return Err(D::Error::custom(format!(
                        "unknown recurrent_transfer extension `{tag}`"
                    )));
                }
                map.get("value")
                    .ok_or_else(|| D::Error::custom("extension object has no `value`"))?
                    .clone()
            }
            serde_json::Value::Array(items) if items.len() == 2 => {
                let tag = items[0]
                    .as_u64()
                    .ok_or_else(|| D::Error::custom("extension tag is not an integer"))?;
                if tag != 1 {
                    return Err(D::Error::custom(format!(
                        "unknown recurrent_transfer extension variant {tag}"
                    )));
                }
                items[1].clone()
            }
            _ => {
                return Err(D::Error::custom(
                    "recurrent_transfer extension must be an object or a [tag, value] pair",
                ))
            }
        };

        let p: PairId = serde_json::from_value(value).map_err(D::Error::custom)?;
        Ok(RecurrentTransferExtension::PairId(p.pair_id))
    }
}

/// A `vector<char>` field, which hived renders in JSON as a hex string.
///
/// `custom` and `custom_binary` both carry one. Modelling it as a distinct type keeps
/// the hex encoding in one place instead of at each call site.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HexBytes(pub Vec<u8>);

impl HexBytes {
    /// Parse a hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim();
        if !s.len().is_multiple_of(2) {
            return Err(Error::field("hex buffer has an odd number of characters"));
        }
        (0..s.len() / 2)
            .map(|i| {
                u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                    .map_err(|_| Error::field("buffer is not valid hex"))
            })
            .collect::<Result<Vec<u8>>>()
            .map(HexBytes)
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The raw bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(v: Vec<u8>) -> Self {
        HexBytes(v)
    }
}

impl serde::Serialize for HexBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for HexBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        HexBytes::from_hex(&s).map_err(D::Error::custom)
    }
}

impl GrapheneSerialize for HexBytes {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        crate::types::write_bytes(out, &self.0)
    }
}

impl GrapheneDeserialize for HexBytes {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(HexBytes(r.bytes()?))
    }
}

/// An empty `extensions_type`, which most operations carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoExtensions;

impl GrapheneSerialize for NoExtensions {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_varint32(out, 0);
        Ok(())
    }
}

/// Accepts `[]`; a non-empty array is refused rather than silently dropped.
impl<'de> serde::Deserialize<'de> for NoExtensions {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let v = Vec::<serde_json::Value>::deserialize(d)?;
        if !v.is_empty() {
            return Err(D::Error::custom(format!(
                "operation carries {} extension(s), which this build does not model",
                v.len()
            )));
        }
        Ok(NoExtensions)
    }
}

/// Renders as `[]`.
impl serde::Serialize for NoExtensions {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_seq(std::iter::empty::<u8>())
    }
}

macro_rules! op_struct {
    (
        $(#[$meta:meta])*
        $name:ident {
            $( $(#[$fmeta:meta])* $field:ident : $ty:ty ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        pub struct $name {
            $( $(#[$fmeta])* pub $field : $ty ),*
        }
    };
}

// ---------------------------------------------------------------------------
// Operation payloads, in hived declaration order.
// ---------------------------------------------------------------------------

op_struct! {
    /// `vote_operation` (id 0).
    Vote {
        voter: String,
        author: String,
        permlink: String,
        /// Vote weight in basis points, `-10000..=10000`. Signed: negative is a downvote.
        weight: i16,
    }
}

op_struct! {
    /// `comment_operation` (id 1) — posts and replies.
    Comment {
        parent_author: String,
        parent_permlink: String,
        author: String,
        permlink: String,
        title: String,
        body: String,
        json_metadata: String,
    }
}

op_struct! {
    /// `transfer_operation` (id 2).
    Transfer {
        from: String,
        to: String,
        amount: Amount,
        /// Plaintext, or a `#`-prefixed encrypted memo from [`crate::memo`].
        memo: String,
    }
}

op_struct! {
    /// `transfer_to_vesting_operation` (id 3) — "power up".
    TransferToVesting {
        from: String,
        to: String,
        amount: Amount,
    }
}

op_struct! {
    /// `withdraw_vesting_operation` (id 4) — "power down".
    WithdrawVesting {
        account: String,
        vesting_shares: Amount,
    }
}

op_struct! {
    /// `limit_order_create_operation` (id 5).
    LimitOrderCreate {
        owner: String,
        orderid: u32,
        amount_to_sell: Amount,
        min_to_receive: Amount,
        fill_or_kill: bool,
        expiration: PointInTime,
    }
}

op_struct! {
    /// `limit_order_cancel_operation` (id 6).
    LimitOrderCancel {
        owner: String,
        orderid: u32,
    }
}

op_struct! {
    /// `feed_publish_operation` (id 7) — witness price feed.
    FeedPublish {
        publisher: String,
        exchange_rate: Price,
    }
}

op_struct! {
    /// `convert_operation` (id 8) — HBD to HIVE over 3.5 days.
    Convert {
        owner: String,
        requestid: u32,
        amount: Amount,
    }
}

op_struct! {
    /// `account_witness_vote_operation` (id 12).
    AccountWitnessVote {
        account: String,
        witness: String,
        approve: bool,
    }
}

op_struct! {
    /// `account_witness_proxy_operation` (id 13).
    AccountWitnessProxy {
        account: String,
        proxy: String,
    }
}

op_struct! {
    /// `custom_operation` (id 15) — opaque binary payload.
    Custom {
        required_auths: Vec<String>,
        id: u16,
        data: HexBytes,
    }
}

op_struct! {
    /// `delete_comment_operation` (id 17).
    DeleteComment {
        author: String,
        permlink: String,
    }
}

op_struct! {
    /// `custom_json_operation` (id 18) — the workhorse for layer-2 applications.
    CustomJson {
        /// Accounts whose **active** authority must sign.
        required_auths: Vec<String>,
        /// Accounts whose **posting** authority must sign.
        required_posting_auths: Vec<String>,
        /// Application id, at most [`MAX_CUSTOM_ID_LEN`] bytes.
        id: String,
        /// The JSON payload, already serialized to a string.
        json: String,
    }
}

op_struct! {
    /// `comment_options_operation` (id 19).
    CommentOptions {
        author: String,
        permlink: String,
        max_accepted_payout: Amount,
        /// Share of the payout taken as HBD, in basis points.
        percent_hbd: u16,
        allow_votes: bool,
        allow_curation_rewards: bool,
        extensions: Vec<CommentOptionsExtension>,
    }
}

op_struct! {
    /// `set_withdraw_vesting_route_operation` (id 20).
    SetWithdrawVestingRoute {
        from_account: String,
        to_account: String,
        percent: u16,
        auto_vest: bool,
    }
}

op_struct! {
    /// `limit_order_create2_operation` (id 21).
    /// `exchange_rate` precedes `fill_or_kill`, which is the opposite of
    /// `limit_order_create`'s shape and was verified against hived's own
    /// serialization rather than inferred from the sibling operation.
    LimitOrderCreate2 {
        owner: String,
        orderid: u32,
        amount_to_sell: Amount,
        exchange_rate: Price,
        fill_or_kill: bool,
        expiration: PointInTime,
    }
}

op_struct! {
    /// `claim_account_operation` (id 22) — claim an account creation token.
    ClaimAccount {
        creator: String,
        fee: Amount,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `create_claimed_account_operation` (id 23).
    CreateClaimedAccount {
        creator: String,
        new_account_name: String,
        owner: Authority,
        active: Authority,
        posting: Authority,
        memo_key: PublicKey,
        json_metadata: String,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `change_recovery_account_operation` (id 26).
    ChangeRecoveryAccount {
        account_to_recover: String,
        new_recovery_account: String,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `transfer_to_savings_operation` (id 32).
    TransferToSavings {
        from: String,
        to: String,
        amount: Amount,
        memo: String,
    }
}

op_struct! {
    /// `transfer_from_savings_operation` (id 33) — completes after three days.
    TransferFromSavings {
        from: String,
        request_id: u32,
        to: String,
        amount: Amount,
        memo: String,
    }
}

op_struct! {
    /// `cancel_transfer_from_savings_operation` (id 34).
    CancelTransferFromSavings {
        from: String,
        request_id: u32,
    }
}

op_struct! {
    /// `decline_voting_rights_operation` (id 36) — irreversible after 30 days.
    DeclineVotingRights {
        account: String,
        decline: bool,
    }
}

op_struct! {
    /// `claim_reward_balance_operation` (id 39).
    ClaimRewardBalance {
        account: String,
        reward_hive: Amount,
        reward_hbd: Amount,
        reward_vests: Amount,
    }
}

op_struct! {
    /// `delegate_vesting_shares_operation` (id 40).
    DelegateVestingShares {
        delegator: String,
        delegatee: String,
        vesting_shares: Amount,
    }
}

op_struct! {
    /// `account_update2_operation` (id 43).
    AccountUpdate2 {
        account: String,
        owner: Option<Authority>,
        active: Option<Authority>,
        posting: Option<Authority>,
        memo_key: Option<PublicKey>,
        json_metadata: String,
        posting_json_metadata: String,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `create_proposal_operation` (id 44) — a DHF funding request.
    CreateProposal {
        creator: String,
        receiver: String,
        start_date: PointInTime,
        end_date: PointInTime,
        daily_pay: Amount,
        subject: String,
        permlink: String,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `update_proposal_votes_operation` (id 45).
    UpdateProposalVotes {
        voter: String,
        proposal_ids: Vec<u64>,
        approve: bool,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `remove_proposal_operation` (id 46).
    RemoveProposal {
        proposal_owner: String,
        proposal_ids: Vec<u64>,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `update_proposal_operation` (id 47).
    UpdateProposal {
        proposal_id: u64,
        creator: String,
        daily_pay: Amount,
        subject: String,
        permlink: String,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `collateralized_convert_operation` (id 48), added in HF25.
    ///
    /// Converts HIVE to HBD immediately against collateral. **beem cannot construct
    /// this operation** — it is absent from its id table.
    CollateralizedConvert {
        owner: String,
        requestid: u32,
        amount: Amount,
    }
}

op_struct! {
    /// `recurrent_transfer_operation` (id 49), added in HF25 and extended in HF28.
    ///
    /// **beem cannot construct this operation.** Its unreachable `Recurring_transfer`
    /// class also misspells the name, omits `memo`'s sibling `extensions`, and types
    /// `recurrence`/`executions` as signed `Int16` where hived uses `uint16_t`.
    RecurrentTransfer {
        from: String,
        to: String,
        amount: Amount,
        memo: String,
        /// Hours between executions. hived requires at least 24.
        recurrence: u16,
        /// Total number of executions, including the first. hived requires at least 2.
        executions: u16,
        extensions: Vec<RecurrentTransferExtension>,
    }
}

/// A 20-byte block id, as used by `witness_block_approve` and `pow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockId(pub [u8; 20]);

impl BlockId {
    /// Parse a 40-character hex block id.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != 40 {
            return Err(Error::field(format!(
                "block id must be 40 hex characters, got {}",
                s.len()
            )));
        }
        let mut out = [0u8; 20];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::field("block id is not valid hex"))?;
        }
        Ok(BlockId(out))
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl GrapheneSerialize for BlockId {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        crate::types::write_raw(out, &self.0);
        Ok(())
    }
}

impl<'de> serde::Deserialize<'de> for BlockId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        BlockId::from_hex(&s).map_err(D::Error::custom)
    }
}

impl serde::Serialize for BlockId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

/// `legacy_chain_properties` — the witness-voted chain parameters carried by
/// `witness_update` and `pow`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainProperties {
    /// Fee to create an account. Serialized as a legacy asset.
    pub account_creation_fee: Amount,
    /// Maximum block size the witness will accept, in bytes.
    pub maximum_block_size: u32,
    /// HBD interest rate in basis points.
    pub hbd_interest_rate: u16,
}

impl GrapheneSerialize for ChainProperties {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        self.account_creation_fee.append_to(out)?;
        write_u32(out, self.maximum_block_size);
        write_u16(out, self.hbd_interest_rate);
        Ok(())
    }
}

/// One entry of `witness_set_properties`'s `flat_map<string, vector<char>>`.
///
/// The value is the **hex-encoded binary serialization** of the property, not its JSON
/// form — hived unpacks each value according to the key. Callers usually build these
/// with the helpers on [`WitnessProperty`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessProperty {
    pub key: String,
    pub value: Vec<u8>,
}

impl WitnessProperty {
    /// A property whose value is a `public_key_type`.
    pub fn public_key(key: &str, value: &PublicKey) -> Result<Self> {
        Ok(WitnessProperty {
            key: key.to_string(),
            value: value.to_wire()?,
        })
    }

    /// A property whose value is an `asset`.
    pub fn asset(key: &str, value: &Amount) -> Result<Self> {
        Ok(WitnessProperty {
            key: key.to_string(),
            value: value.to_wire()?,
        })
    }

    /// A property whose value is a `uint32`.
    pub fn uint32(key: &str, value: u32) -> Self {
        WitnessProperty {
            key: key.to_string(),
            value: value.to_le_bytes().to_vec(),
        }
    }

    /// A property whose value is a `uint16`.
    pub fn uint16(key: &str, value: u16) -> Self {
        WitnessProperty {
            key: key.to_string(),
            value: value.to_le_bytes().to_vec(),
        }
    }

    /// A property whose value is a length-prefixed string, such as `url`.
    pub fn string(key: &str, value: &str) -> Result<Self> {
        let mut buf = Vec::new();
        write_string(&mut buf, value)?;
        Ok(WitnessProperty {
            key: key.to_string(),
            value: buf,
        })
    }
}

impl GrapheneSerialize for WitnessProperty {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_string(out, &self.key)?;
        crate::types::write_bytes(out, &self.value)?;
        Ok(())
    }
}

/// Parsed from `["key", "<hex>"]`.
impl<'de> serde::Deserialize<'de> for WitnessProperty {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let (key, hex) = <(String, String)>::deserialize(d)?;
        Ok(WitnessProperty {
            key,
            value: HexBytes::from_hex(&hex).map_err(D::Error::custom)?.0,
        })
    }
}

impl serde::Serialize for WitnessProperty {
    /// hived renders these as `["key", "<hex>"]` pairs.
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let hex: String = self.value.iter().map(|b| format!("{b:02x}")).collect();
        let mut t = s.serialize_tuple(2)?;
        t.serialize_element(&self.key)?;
        t.serialize_element(&hex)?;
        t.end()
    }
}

op_struct! {
    /// `account_create_operation` (id 9).
    AccountCreate {
        fee: Amount,
        creator: String,
        new_account_name: String,
        owner: Authority,
        active: Authority,
        posting: Authority,
        memo_key: PublicKey,
        json_metadata: String,
    }
}

op_struct! {
    /// `account_update_operation` (id 10).
    ///
    /// Note that `memo_key` is **not** optional here, unlike in `account_update2`.
    AccountUpdate {
        account: String,
        owner: Option<Authority>,
        active: Option<Authority>,
        posting: Option<Authority>,
        memo_key: PublicKey,
        json_metadata: String,
    }
}

op_struct! {
    /// `witness_update_operation` (id 11).
    ///
    /// Setting `block_signing_key` to the null key retires the witness.
    WitnessUpdate {
        owner: String,
        url: String,
        block_signing_key: PublicKey,
        props: ChainProperties,
        fee: Amount,
    }
}

op_struct! {
    /// `witness_block_approve_operation` (id 16).
    ///
    /// beem has no class for this operation at all.
    WitnessBlockApprove {
        witness: String,
        block_id: BlockId,
    }
}

op_struct! {
    /// `request_account_recovery_operation` (id 24).
    RequestAccountRecovery {
        recovery_account: String,
        account_to_recover: String,
        new_owner_authority: Authority,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `recover_account_operation` (id 25).
    RecoverAccount {
        account_to_recover: String,
        new_owner_authority: Authority,
        recent_owner_authority: Authority,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `escrow_transfer_operation` (id 27).
    ///
    /// The field order here is hived's, which is not the order the JSON form
    /// suggests: the two amounts precede `escrow_id` and `agent`, and `json_meta`
    /// sits *between* `fee` and the two deadlines rather than at the end. Verified
    /// byte for byte against `condenser_api.get_transaction_hex`; an earlier
    /// arrangement that read more naturally produced a digest hived did not agree
    /// with, and therefore a signature it would have rejected.
    EscrowTransfer {
        from: String,
        to: String,
        hbd_amount: Amount,
        hive_amount: Amount,
        escrow_id: u32,
        agent: String,
        fee: Amount,
        json_meta: String,
        ratification_deadline: PointInTime,
        escrow_expiration: PointInTime,
    }
}

op_struct! {
    /// `escrow_dispute_operation` (id 28).
    ///
    /// **beem omits `agent`**, serializing four of the five fields. Every field after
    /// the gap lands in the wrong place, so the operation hived reconstructs is not
    /// the one that was signed.
    EscrowDispute {
        from: String,
        to: String,
        agent: String,
        who: String,
        escrow_id: u32,
    }
}

op_struct! {
    /// `escrow_release_operation` (id 29).
    ///
    /// **beem omits both `agent` and `receiver`**, serializing six of the eight
    /// fields — including the field that says who the funds go to.
    EscrowRelease {
        from: String,
        to: String,
        agent: String,
        who: String,
        receiver: String,
        escrow_id: u32,
        hbd_amount: Amount,
        hive_amount: Amount,
    }
}

op_struct! {
    /// `escrow_approve_operation` (id 31).
    EscrowApprove {
        from: String,
        to: String,
        agent: String,
        who: String,
        escrow_id: u32,
        approve: bool,
    }
}

op_struct! {
    /// `custom_binary_operation` (id 35).
    ///
    /// **The chain refuses this operation outright.** `custom_binary_evaluator::do_apply`
    /// is a single unconditional assert — `"custom_binary_operation is disallowed"` —
    /// so a transaction containing one can be built and signed and will never apply. It
    /// is modelled here because it exists in the operation table and has to round-trip
    /// when reading history, not because it can be broadcast. Verified against hived at
    /// the revision mainnet runs.
    ///
    /// **beem serializes two of these six fields** (`id` and `data`) and types `id` as
    /// a `Uint16`, where hived uses a `custom_id_type` string. Its output cannot be
    /// deserialized as this operation at all.
    CustomBinary {
        required_owner_auths: Vec<String>,
        required_active_auths: Vec<String>,
        required_posting_auths: Vec<String>,
        required_auths: Vec<Authority>,
        id: String,
        data: HexBytes,
    }
}

op_struct! {
    /// `reset_account_operation` (id 37).
    ///
    /// Disabled on chain — hived rejects it. Present so that historical blocks can be
    /// read and so the operation table stays complete.
    ResetAccount {
        reset_account: String,
        account_to_reset: String,
        new_owner_authority: Authority,
    }
}

op_struct! {
    /// `set_reset_account_operation` (id 38).
    ///
    /// Disabled on chain, like [`ResetAccount`].
    SetResetAccount {
        account: String,
        current_reset_account: String,
        reset_account: String,
    }
}

op_struct! {
    /// `account_create_with_delegation_operation` (id 41).
    ///
    /// Superseded by `claim_account` + `create_claimed_account`, and rejected since
    /// HF20. Kept for reading history.
    AccountCreateWithDelegation {
        fee: Amount,
        delegation: Amount,
        creator: String,
        new_account_name: String,
        owner: Authority,
        active: Authority,
        posting: Authority,
        memo_key: PublicKey,
        json_metadata: String,
        extensions: NoExtensions,
    }
}

op_struct! {
    /// `witness_set_properties_operation` (id 42).
    ///
    /// The modern way for a witness to publish parameters. Properties are a
    /// `flat_map`, so they serialize **sorted by key**; build values with the helpers
    /// on [`WitnessProperty`].
    WitnessSetProperties {
        owner: String,
        props: Vec<WitnessProperty>,
        extensions: NoExtensions,
    }
}

// ---------------------------------------------------------------------------
// The operation variant
// ---------------------------------------------------------------------------

/// An operation that can be placed in a transaction and signed.
///
/// Virtual operations are absent by design: the chain emits them and they can never be
/// broadcast, so there is no constructor for one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    Vote(Vote),
    Comment(Comment),
    AccountCreate(AccountCreate),
    AccountUpdate(AccountUpdate),
    WitnessUpdate(WitnessUpdate),
    WitnessBlockApprove(WitnessBlockApprove),
    RequestAccountRecovery(RequestAccountRecovery),
    RecoverAccount(RecoverAccount),
    EscrowTransfer(EscrowTransfer),
    EscrowDispute(EscrowDispute),
    EscrowRelease(EscrowRelease),
    EscrowApprove(EscrowApprove),
    CustomBinary(CustomBinary),
    ResetAccount(ResetAccount),
    SetResetAccount(SetResetAccount),
    AccountCreateWithDelegation(AccountCreateWithDelegation),
    WitnessSetProperties(WitnessSetProperties),
    Transfer(Transfer),
    TransferToVesting(TransferToVesting),
    WithdrawVesting(WithdrawVesting),
    LimitOrderCreate(LimitOrderCreate),
    LimitOrderCancel(LimitOrderCancel),
    FeedPublish(FeedPublish),
    Convert(Convert),
    AccountWitnessVote(AccountWitnessVote),
    AccountWitnessProxy(AccountWitnessProxy),
    Custom(Custom),
    DeleteComment(DeleteComment),
    CustomJson(CustomJson),
    CommentOptions(CommentOptions),
    SetWithdrawVestingRoute(SetWithdrawVestingRoute),
    LimitOrderCreate2(LimitOrderCreate2),
    ClaimAccount(ClaimAccount),
    CreateClaimedAccount(CreateClaimedAccount),
    ChangeRecoveryAccount(ChangeRecoveryAccount),
    TransferToSavings(TransferToSavings),
    TransferFromSavings(TransferFromSavings),
    CancelTransferFromSavings(CancelTransferFromSavings),
    DeclineVotingRights(DeclineVotingRights),
    ClaimRewardBalance(ClaimRewardBalance),
    DelegateVestingShares(DelegateVestingShares),
    AccountUpdate2(AccountUpdate2),
    CreateProposal(CreateProposal),
    UpdateProposalVotes(UpdateProposalVotes),
    RemoveProposal(RemoveProposal),
    UpdateProposal(UpdateProposal),
    CollateralizedConvert(CollateralizedConvert),
    RecurrentTransfer(RecurrentTransfer),
}

/// Refuse a string longer than hived's `validate()` allows for that field.
///
/// One helper for every length bound rather than the check written out at each site,
/// so the four memo-carrying operations cannot drift apart from one another.
fn check_len(value: &str, max: usize, what: &str) -> Result<()> {
    if value.len() > max {
        return Err(Error::field(format!(
            "{what} is {} bytes; hived allows at most {max}",
            value.len()
        )));
    }
    Ok(())
}

impl Operation {
    /// Accounts this operation counts against, for hived's per-block custom-op limit.
    ///
    /// Empty for everything that is not a custom operation. For the three that are, it
    /// is the accounts whose authority the operation requires — which is what
    /// `operation_get_impacted_accounts` yields for them, and what
    /// `database::limit_custom_op_count` tallies.
    pub fn custom_op_accounts(&self) -> Vec<&str> {
        self.custom_op_accounts_iter().collect()
    }

    /// The same accounts, without allocating.
    ///
    /// [`Self::custom_op_accounts`] returns a `Vec` because that is what a caller
    /// reaching for a public helper wants. The per-block budget check does not: it runs
    /// inside `body_bytes`, so it is on the signing path, and a ten-operation
    /// transaction was paying for ten vectors that never outlived the loop that read
    /// them.
    pub(crate) fn custom_op_accounts_iter(&self) -> impl Iterator<Item = &str> {
        const NONE: &[String] = &[];
        let (a, b, c) = match self {
            Operation::Custom(o) => (o.required_auths.as_slice(), NONE, NONE),
            Operation::CustomJson(o) => (
                o.required_auths.as_slice(),
                o.required_posting_auths.as_slice(),
                NONE,
            ),
            Operation::CustomBinary(o) => (
                o.required_owner_auths.as_slice(),
                o.required_active_auths.as_slice(),
                o.required_posting_auths.as_slice(),
            ),
            _ => (NONE, NONE, NONE),
        };
        a.iter().chain(b).chain(c).map(String::as_str)
    }

    /// The operation's id in hived's static variant.
    pub fn id(&self) -> OperationId {
        match self {
            Operation::Vote(_) => OperationId::Vote,
            Operation::Comment(_) => OperationId::Comment,
            Operation::AccountCreate(_) => OperationId::AccountCreate,
            Operation::AccountUpdate(_) => OperationId::AccountUpdate,
            Operation::WitnessUpdate(_) => OperationId::WitnessUpdate,
            Operation::WitnessBlockApprove(_) => OperationId::WitnessBlockApprove,
            Operation::RequestAccountRecovery(_) => OperationId::RequestAccountRecovery,
            Operation::RecoverAccount(_) => OperationId::RecoverAccount,
            Operation::EscrowTransfer(_) => OperationId::EscrowTransfer,
            Operation::EscrowDispute(_) => OperationId::EscrowDispute,
            Operation::EscrowRelease(_) => OperationId::EscrowRelease,
            Operation::EscrowApprove(_) => OperationId::EscrowApprove,
            Operation::CustomBinary(_) => OperationId::CustomBinary,
            Operation::ResetAccount(_) => OperationId::ResetAccount,
            Operation::SetResetAccount(_) => OperationId::SetResetAccount,
            Operation::AccountCreateWithDelegation(_) => OperationId::AccountCreateWithDelegation,
            Operation::WitnessSetProperties(_) => OperationId::WitnessSetProperties,
            Operation::Transfer(_) => OperationId::Transfer,
            Operation::TransferToVesting(_) => OperationId::TransferToVesting,
            Operation::WithdrawVesting(_) => OperationId::WithdrawVesting,
            Operation::LimitOrderCreate(_) => OperationId::LimitOrderCreate,
            Operation::LimitOrderCancel(_) => OperationId::LimitOrderCancel,
            Operation::FeedPublish(_) => OperationId::FeedPublish,
            Operation::Convert(_) => OperationId::Convert,
            Operation::AccountWitnessVote(_) => OperationId::AccountWitnessVote,
            Operation::AccountWitnessProxy(_) => OperationId::AccountWitnessProxy,
            Operation::Custom(_) => OperationId::Custom,
            Operation::DeleteComment(_) => OperationId::DeleteComment,
            Operation::CustomJson(_) => OperationId::CustomJson,
            Operation::CommentOptions(_) => OperationId::CommentOptions,
            Operation::SetWithdrawVestingRoute(_) => OperationId::SetWithdrawVestingRoute,
            Operation::LimitOrderCreate2(_) => OperationId::LimitOrderCreate2,
            Operation::ClaimAccount(_) => OperationId::ClaimAccount,
            Operation::CreateClaimedAccount(_) => OperationId::CreateClaimedAccount,
            Operation::ChangeRecoveryAccount(_) => OperationId::ChangeRecoveryAccount,
            Operation::TransferToSavings(_) => OperationId::TransferToSavings,
            Operation::TransferFromSavings(_) => OperationId::TransferFromSavings,
            Operation::CancelTransferFromSavings(_) => OperationId::CancelTransferFromSavings,
            Operation::DeclineVotingRights(_) => OperationId::DeclineVotingRights,
            Operation::ClaimRewardBalance(_) => OperationId::ClaimRewardBalance,
            Operation::DelegateVestingShares(_) => OperationId::DelegateVestingShares,
            Operation::AccountUpdate2(_) => OperationId::AccountUpdate2,
            Operation::CreateProposal(_) => OperationId::CreateProposal,
            Operation::UpdateProposalVotes(_) => OperationId::UpdateProposalVotes,
            Operation::RemoveProposal(_) => OperationId::RemoveProposal,
            Operation::UpdateProposal(_) => OperationId::UpdateProposal,
            Operation::CollateralizedConvert(_) => OperationId::CollateralizedConvert,
            Operation::RecurrentTransfer(_) => OperationId::RecurrentTransfer,
        }
    }

    /// Serialize just the operation body, without the variant tag.
    fn append_body(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Operation::Vote(o) => {
                write_string(out, &o.voter)?;
                write_string(out, &o.author)?;
                write_string(out, &o.permlink)?;
                write_i16(out, o.weight);
            }
            Operation::Comment(o) => {
                check_len(&o.title, MAX_TITLE_LEN, "comment title")?;
                check_len(&o.permlink, MAX_PERMLINK_LEN, "comment permlink")?;
                check_len(
                    &o.parent_permlink,
                    MAX_PERMLINK_LEN,
                    "comment parent_permlink",
                )?;
                write_string(out, &o.parent_author)?;
                write_string(out, &o.parent_permlink)?;
                write_string(out, &o.author)?;
                write_string(out, &o.permlink)?;
                write_string(out, &o.title)?;
                write_string(out, &o.body)?;
                write_string(out, &o.json_metadata)?;
            }
            Operation::AccountCreate(o) => {
                o.fee.append_to(out)?;
                write_string(out, &o.creator)?;
                write_string(out, &o.new_account_name)?;
                o.owner.append_to(out)?;
                o.active.append_to(out)?;
                o.posting.append_to(out)?;
                o.memo_key.append_to(out)?;
                write_string(out, &o.json_metadata)?;
            }
            Operation::AccountUpdate(o) => {
                write_string(out, &o.account)?;
                write_optional(out, o.owner.as_ref())?;
                write_optional(out, o.active.as_ref())?;
                write_optional(out, o.posting.as_ref())?;
                o.memo_key.append_to(out)?;
                write_string(out, &o.json_metadata)?;
            }
            Operation::WitnessUpdate(o) => {
                check_len(&o.url, MAX_WITNESS_URL_LEN, "witness_update url")?;
                write_string(out, &o.owner)?;
                write_string(out, &o.url)?;
                o.block_signing_key.append_to(out)?;
                o.props.append_to(out)?;
                o.fee.append_to(out)?;
            }
            Operation::WitnessBlockApprove(o) => {
                write_string(out, &o.witness)?;
                o.block_id.append_to(out)?;
            }
            Operation::RequestAccountRecovery(o) => {
                write_string(out, &o.recovery_account)?;
                write_string(out, &o.account_to_recover)?;
                o.new_owner_authority.append_to(out)?;
                o.extensions.append_to(out)?;
            }
            Operation::RecoverAccount(o) => {
                write_string(out, &o.account_to_recover)?;
                o.new_owner_authority.append_to(out)?;
                o.recent_owner_authority.append_to(out)?;
                o.extensions.append_to(out)?;
            }
            Operation::EscrowTransfer(o) => {
                // hived's order, verified byte for byte against a node: the amounts
                // come before escrow_id and agent, and json_meta before the deadlines.
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                o.hbd_amount.append_to(out)?;
                o.hive_amount.append_to(out)?;
                write_u32(out, o.escrow_id);
                write_string(out, &o.agent)?;
                o.fee.append_to(out)?;
                write_string(out, &o.json_meta)?;
                o.ratification_deadline.append_to(out)?;
                o.escrow_expiration.append_to(out)?;
            }
            Operation::EscrowDispute(o) => {
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                write_string(out, &o.agent)?;
                write_string(out, &o.who)?;
                write_u32(out, o.escrow_id);
            }
            Operation::EscrowRelease(o) => {
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                write_string(out, &o.agent)?;
                write_string(out, &o.who)?;
                write_string(out, &o.receiver)?;
                write_u32(out, o.escrow_id);
                o.hbd_amount.append_to(out)?;
                o.hive_amount.append_to(out)?;
            }
            Operation::EscrowApprove(o) => {
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                write_string(out, &o.agent)?;
                write_string(out, &o.who)?;
                write_u32(out, o.escrow_id);
                write_bool(out, o.approve);
            }
            Operation::CustomBinary(o) => {
                if o.id.len() > MAX_CUSTOM_ID_LEN {
                    return Err(Error::field(format!(
                        "custom_binary id is {} bytes; hived allows at most {MAX_CUSTOM_ID_LEN}",
                        o.id.len()
                    )));
                }
                write_sorted_account_set(out, &o.required_owner_auths, "required_owner_auths")?;
                write_sorted_account_set(out, &o.required_active_auths, "required_active_auths")?;
                write_sorted_account_set(out, &o.required_posting_auths, "required_posting_auths")?;
                // `required_auths` is a plain vector<authority>, not a flat_set, so it
                // keeps the caller's order.
                write_array(out, &o.required_auths)?;
                write_string(out, &o.id)?;
                o.data.append_to(out)?;
            }
            Operation::ResetAccount(o) => {
                write_string(out, &o.reset_account)?;
                write_string(out, &o.account_to_reset)?;
                o.new_owner_authority.append_to(out)?;
            }
            Operation::SetResetAccount(o) => {
                write_string(out, &o.account)?;
                write_string(out, &o.current_reset_account)?;
                write_string(out, &o.reset_account)?;
            }
            Operation::AccountCreateWithDelegation(o) => {
                o.fee.append_to(out)?;
                o.delegation.append_to(out)?;
                write_string(out, &o.creator)?;
                write_string(out, &o.new_account_name)?;
                o.owner.append_to(out)?;
                o.active.append_to(out)?;
                o.posting.append_to(out)?;
                o.memo_key.append_to(out)?;
                write_string(out, &o.json_metadata)?;
                o.extensions.append_to(out)?;
            }
            Operation::WitnessSetProperties(o) => {
                write_string(out, &o.owner)?;
                // `props` is a flat_map: sorted by key, unique.
                let mut props = o.props.clone();
                props.sort_by(|a, b| a.key.cmp(&b.key));
                if props.windows(2).any(|w| w[0].key == w[1].key) {
                    return Err(Error::field(
                        "witness_set_properties lists the same key twice",
                    ));
                }
                write_array(out, &props)?;
                o.extensions.append_to(out)?;
            }
            Operation::Transfer(o) => {
                check_len(&o.memo, MAX_MEMO_LEN, "transfer memo")?;
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                o.amount.append_to(out)?;
                write_string(out, &o.memo)?;
            }
            Operation::TransferToVesting(o) => {
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                o.amount.append_to(out)?;
            }
            Operation::WithdrawVesting(o) => {
                write_string(out, &o.account)?;
                o.vesting_shares.append_to(out)?;
            }
            Operation::LimitOrderCreate(o) => {
                write_string(out, &o.owner)?;
                write_u32(out, o.orderid);
                o.amount_to_sell.append_to(out)?;
                o.min_to_receive.append_to(out)?;
                write_bool(out, o.fill_or_kill);
                o.expiration.append_to(out)?;
            }
            Operation::LimitOrderCancel(o) => {
                write_string(out, &o.owner)?;
                write_u32(out, o.orderid);
            }
            Operation::FeedPublish(o) => {
                write_string(out, &o.publisher)?;
                o.exchange_rate.append_to(out)?;
            }
            Operation::Convert(o) => {
                write_string(out, &o.owner)?;
                write_u32(out, o.requestid);
                o.amount.append_to(out)?;
            }
            Operation::AccountWitnessVote(o) => {
                write_string(out, &o.account)?;
                write_string(out, &o.witness)?;
                write_bool(out, o.approve);
            }
            Operation::AccountWitnessProxy(o) => {
                write_string(out, &o.account)?;
                write_string(out, &o.proxy)?;
            }
            Operation::Custom(o) => {
                if o.data.0.len() > MAX_CUSTOM_DATA_LEN {
                    return Err(Error::field(format!(
                        "custom data is {} bytes; hived allows at most {MAX_CUSTOM_DATA_LEN}",
                        o.data.0.len()
                    )));
                }
                write_sorted_account_set(out, &o.required_auths, "required_auths")?;
                write_u16(out, o.id);
                o.data.append_to(out)?;
            }
            Operation::DeleteComment(o) => {
                write_string(out, &o.author)?;
                write_string(out, &o.permlink)?;
            }
            Operation::CustomJson(o) => {
                if o.id.len() > MAX_CUSTOM_ID_LEN {
                    return Err(Error::field(format!(
                        "custom_json id is {} bytes; hived allows at most {MAX_CUSTOM_ID_LEN}",
                        o.id.len()
                    )));
                }
                if o.json.len() > MAX_CUSTOM_DATA_LEN {
                    return Err(Error::field(format!(
                        "custom_json json is {} bytes; hived allows at most \
                         {MAX_CUSTOM_DATA_LEN}. The whole transaction would be rejected, \
                         not just this operation, so batch the payload into several \
                         operations instead",
                        o.json.len()
                    )));
                }
                if o.required_auths.len() + o.required_posting_auths.len()
                    > MAX_AUTHORITY_MEMBERSHIP
                {
                    return Err(Error::field(format!(
                        "custom_json names {} accounts across required_auths and \
                         required_posting_auths; hived allows at most \
                         {MAX_AUTHORITY_MEMBERSHIP} between them",
                        o.required_auths.len() + o.required_posting_auths.len()
                    )));
                }
                if o.required_auths.is_empty() && o.required_posting_auths.is_empty() {
                    return Err(Error::field(
                        "custom_json needs at least one required_auths or required_posting_auths entry",
                    ));
                }
                write_sorted_account_set(out, &o.required_auths, "required_auths")?;
                write_sorted_account_set(out, &o.required_posting_auths, "required_posting_auths")?;
                write_string(out, &o.id)?;
                write_string(out, &o.json)?;
            }
            Operation::CommentOptions(o) => {
                write_string(out, &o.author)?;
                write_string(out, &o.permlink)?;
                o.max_accepted_payout.append_to(out)?;
                write_u16(out, o.percent_hbd);
                write_bool(out, o.allow_votes);
                write_bool(out, o.allow_curation_rewards);
                write_array(out, &o.extensions)?;
            }
            Operation::SetWithdrawVestingRoute(o) => {
                write_string(out, &o.from_account)?;
                write_string(out, &o.to_account)?;
                write_u16(out, o.percent);
                write_bool(out, o.auto_vest);
            }
            Operation::LimitOrderCreate2(o) => {
                // exchange_rate precedes fill_or_kill here, unlike limit_order_create.
                write_string(out, &o.owner)?;
                write_u32(out, o.orderid);
                o.amount_to_sell.append_to(out)?;
                o.exchange_rate.append_to(out)?;
                write_bool(out, o.fill_or_kill);
                o.expiration.append_to(out)?;
            }
            Operation::ClaimAccount(o) => {
                write_string(out, &o.creator)?;
                o.fee.append_to(out)?;
                o.extensions.append_to(out)?;
            }
            Operation::CreateClaimedAccount(o) => {
                write_string(out, &o.creator)?;
                write_string(out, &o.new_account_name)?;
                o.owner.append_to(out)?;
                o.active.append_to(out)?;
                o.posting.append_to(out)?;
                o.memo_key.append_to(out)?;
                write_string(out, &o.json_metadata)?;
                o.extensions.append_to(out)?;
            }
            Operation::ChangeRecoveryAccount(o) => {
                write_string(out, &o.account_to_recover)?;
                write_string(out, &o.new_recovery_account)?;
                o.extensions.append_to(out)?;
            }
            Operation::TransferToSavings(o) => {
                check_len(&o.memo, MAX_MEMO_LEN, "transfer_to_savings memo")?;
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                o.amount.append_to(out)?;
                write_string(out, &o.memo)?;
            }
            Operation::TransferFromSavings(o) => {
                check_len(&o.memo, MAX_MEMO_LEN, "transfer_from_savings memo")?;
                write_string(out, &o.from)?;
                write_u32(out, o.request_id);
                write_string(out, &o.to)?;
                o.amount.append_to(out)?;
                write_string(out, &o.memo)?;
            }
            Operation::CancelTransferFromSavings(o) => {
                write_string(out, &o.from)?;
                write_u32(out, o.request_id);
            }
            Operation::DeclineVotingRights(o) => {
                write_string(out, &o.account)?;
                write_bool(out, o.decline);
            }
            Operation::ClaimRewardBalance(o) => {
                write_string(out, &o.account)?;
                o.reward_hive.append_to(out)?;
                o.reward_hbd.append_to(out)?;
                o.reward_vests.append_to(out)?;
            }
            Operation::DelegateVestingShares(o) => {
                write_string(out, &o.delegator)?;
                write_string(out, &o.delegatee)?;
                o.vesting_shares.append_to(out)?;
            }
            Operation::AccountUpdate2(o) => {
                write_string(out, &o.account)?;
                write_optional(out, o.owner.as_ref())?;
                write_optional(out, o.active.as_ref())?;
                write_optional(out, o.posting.as_ref())?;
                write_optional(out, o.memo_key.as_ref())?;
                write_string(out, &o.json_metadata)?;
                write_string(out, &o.posting_json_metadata)?;
                o.extensions.append_to(out)?;
            }
            Operation::CreateProposal(o) => {
                check_len(
                    &o.subject,
                    MAX_PROPOSAL_SUBJECT_LEN,
                    "create_proposal subject",
                )?;
                check_len(&o.permlink, MAX_PERMLINK_LEN, "create_proposal permlink")?;
                write_string(out, &o.creator)?;
                write_string(out, &o.receiver)?;
                o.start_date.append_to(out)?;
                o.end_date.append_to(out)?;
                o.daily_pay.append_to(out)?;
                write_string(out, &o.subject)?;
                write_string(out, &o.permlink)?;
                o.extensions.append_to(out)?;
            }
            Operation::UpdateProposalVotes(o) => {
                write_string(out, &o.voter)?;
                write_sorted_proposal_ids(out, &o.proposal_ids)?;
                write_bool(out, o.approve);
                o.extensions.append_to(out)?;
            }
            Operation::RemoveProposal(o) => {
                write_string(out, &o.proposal_owner)?;
                write_sorted_proposal_ids(out, &o.proposal_ids)?;
                o.extensions.append_to(out)?;
            }
            Operation::UpdateProposal(o) => {
                check_len(
                    &o.subject,
                    MAX_PROPOSAL_SUBJECT_LEN,
                    "update_proposal subject",
                )?;
                check_len(&o.permlink, MAX_PERMLINK_LEN, "update_proposal permlink")?;
                write_u64(out, o.proposal_id);
                write_string(out, &o.creator)?;
                o.daily_pay.append_to(out)?;
                write_string(out, &o.subject)?;
                write_string(out, &o.permlink)?;
                o.extensions.append_to(out)?;
            }
            Operation::CollateralizedConvert(o) => {
                write_string(out, &o.owner)?;
                write_u32(out, o.requestid);
                o.amount.append_to(out)?;
            }
            Operation::RecurrentTransfer(o) => {
                check_len(&o.memo, MAX_MEMO_LEN, "recurrent_transfer memo")?;
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                o.amount.append_to(out)?;
                write_string(out, &o.memo)?;
                write_u16(out, o.recurrence);
                write_u16(out, o.executions);
                write_array(out, &o.extensions)?;
            }
        }
        Ok(())
    }
}

/// Write a `flat_set<account_name_type>`: sorted, unique.
///
/// hived declares `required_auths` and `required_posting_auths` as `flat_set`, which
/// is an **ordered, unique** container. beem serialized whatever order the caller
/// passed, with no dedup, so a transaction with several auths could go on the wire in
/// an order hived's deserializer does not produce — the signature then covers bytes
/// the node will not reconstruct.
fn write_sorted_account_set(out: &mut Vec<u8>, accounts: &[String], what: &str) -> Result<()> {
    let mut sorted: Vec<&String> = accounts.iter().collect();
    sorted.sort();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::field(format!("{what} lists the same account twice")));
    }
    write_array(out, &sorted)?;
    Ok(())
}

/// Write a `flat_set<int64_t>` of proposal ids: sorted, unique.
fn write_sorted_proposal_ids(out: &mut Vec<u8>, ids: &[u64]) -> Result<()> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::field("proposal_ids lists the same id twice"));
    }
    if sorted.is_empty() {
        return Err(Error::field("proposal_ids is empty"));
    }
    if sorted.len() > MAX_PROPOSAL_IDS {
        return Err(Error::field(format!(
            "proposal_ids has {} entries; hived allows at most {MAX_PROPOSAL_IDS}",
            sorted.len()
        )));
    }
    write_array(out, &sorted)?;
    Ok(())
}

impl GrapheneSerialize for Operation {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        write_varint32(out, self.id().as_u32());
        self.append_body(out)
    }
}

/// An operation renders as just its payload object; the enclosing
/// `[name, {...}]` pair is added by [`crate::transaction`].
impl serde::Serialize for Operation {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        macro_rules! delegate {
            ($($variant:ident),* $(,)?) => {
                match self {
                    $( Operation::$variant(o) => o.serialize(s), )*
                }
            };
        }
        delegate!(
            Vote,
            Comment,
            AccountCreate,
            AccountUpdate,
            WitnessUpdate,
            WitnessBlockApprove,
            RequestAccountRecovery,
            RecoverAccount,
            EscrowTransfer,
            EscrowDispute,
            EscrowRelease,
            EscrowApprove,
            CustomBinary,
            ResetAccount,
            SetResetAccount,
            AccountCreateWithDelegation,
            WitnessSetProperties,
            Transfer,
            TransferToVesting,
            WithdrawVesting,
            LimitOrderCreate,
            LimitOrderCancel,
            FeedPublish,
            Convert,
            AccountWitnessVote,
            AccountWitnessProxy,
            Custom,
            DeleteComment,
            CustomJson,
            CommentOptions,
            SetWithdrawVestingRoute,
            LimitOrderCreate2,
            ClaimAccount,
            CreateClaimedAccount,
            ChangeRecoveryAccount,
            TransferToSavings,
            TransferFromSavings,
            CancelTransferFromSavings,
            DeclineVotingRights,
            ClaimRewardBalance,
            DelegateVestingShares,
            AccountUpdate2,
            CreateProposal,
            UpdateProposalVotes,
            RemoveProposal,
            UpdateProposal,
            CollateralizedConvert,
            RecurrentTransfer,
        )
    }
}

/// Read an `extensions_type` that this crate always writes empty.
///
/// A non-empty extensions array means the sender is using a protocol feature this
/// build does not model. Silently dropping it would produce a value that
/// re-serializes to different bytes, so it is refused.
fn read_no_extensions(r: &mut Reader<'_>) -> Result<NoExtensions> {
    let count = r.varint32()?;
    if count != 0 {
        return Err(Error::ser(format!(
            "operation carries {count} extension(s), which this build does not model"
        )));
    }
    Ok(NoExtensions)
}

impl GrapheneDeserialize for ChainProperties {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ChainProperties {
            account_creation_fee: Amount::read_from(r)?,
            maximum_block_size: r.u32()?,
            hbd_interest_rate: r.u16()?,
        })
    }
}

impl GrapheneDeserialize for BlockId {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        let bytes = r.raw(20)?;
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(BlockId(out))
    }
}

impl GrapheneDeserialize for Price {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Price {
            base: Amount::read_from(r)?,
            quote: Amount::read_from(r)?,
        })
    }
}

impl GrapheneDeserialize for Beneficiary {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Beneficiary {
            account: r.string()?,
            weight: r.u16()?,
        })
    }
}

impl GrapheneDeserialize for WitnessProperty {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(WitnessProperty {
            key: r.string()?,
            value: r.bytes()?,
        })
    }
}

impl GrapheneDeserialize for CommentOptionsExtension {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        match r.varint32()? {
            0 => Ok(CommentOptionsExtension::Beneficiaries(r.array()?)),
            tag => Err(Error::ser(format!(
                "unknown comment_options extension variant {tag}"
            ))),
        }
    }
}

impl GrapheneDeserialize for RecurrentTransferExtension {
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        match r.varint32()? {
            1 => Ok(RecurrentTransferExtension::PairId(r.u8()?)),
            tag => Err(Error::ser(format!(
                "unknown recurrent_transfer extension variant {tag}"
            ))),
        }
    }
}

impl GrapheneDeserialize for Operation {
    /// Read the variant tag, then the payload.
    ///
    /// A virtual operation id is refused: virtual operations never appear inside a
    /// transaction, so encountering one means the bytes are not a transaction.
    fn read_from(r: &mut Reader<'_>) -> Result<Self> {
        let tag = r.varint32()?;
        let id = OperationId::from_u32(tag)?;
        if id.is_virtual() {
            return Err(Error::ser(format!(
                "{} is a virtual operation and cannot appear in a transaction",
                id.name()
            )));
        }
        Ok(match id {
            OperationId::Vote => Operation::Vote(Vote {
                voter: r.string()?,
                author: r.string()?,
                permlink: r.string()?,
                weight: r.i16()?,
            }),
            OperationId::Comment => Operation::Comment(Comment {
                parent_author: r.string()?,
                parent_permlink: r.string()?,
                author: r.string()?,
                permlink: r.string()?,
                title: r.string()?,
                body: r.string()?,
                json_metadata: r.string()?,
            }),
            OperationId::AccountCreate => Operation::AccountCreate(AccountCreate {
                fee: Amount::read_from(r)?,
                creator: r.string()?,
                new_account_name: r.string()?,
                owner: Authority::read_from(r)?,
                active: Authority::read_from(r)?,
                posting: Authority::read_from(r)?,
                memo_key: PublicKey::read_from(r)?,
                json_metadata: r.string()?,
            }),
            OperationId::AccountUpdate => Operation::AccountUpdate(AccountUpdate {
                account: r.string()?,
                owner: r.optional::<Authority>()?,
                active: r.optional::<Authority>()?,
                posting: r.optional::<Authority>()?,
                memo_key: PublicKey::read_from(r)?,
                json_metadata: r.string()?,
            }),
            OperationId::WitnessUpdate => Operation::WitnessUpdate(WitnessUpdate {
                owner: r.string()?,
                url: r.string()?,
                block_signing_key: PublicKey::read_from(r)?,
                props: ChainProperties::read_from(r)?,
                fee: Amount::read_from(r)?,
            }),
            OperationId::WitnessBlockApprove => {
                Operation::WitnessBlockApprove(WitnessBlockApprove {
                    witness: r.string()?,
                    block_id: BlockId::read_from(r)?,
                })
            }
            OperationId::RequestAccountRecovery => {
                Operation::RequestAccountRecovery(RequestAccountRecovery {
                    recovery_account: r.string()?,
                    account_to_recover: r.string()?,
                    new_owner_authority: Authority::read_from(r)?,
                    extensions: read_no_extensions(r)?,
                })
            }
            OperationId::RecoverAccount => Operation::RecoverAccount(RecoverAccount {
                account_to_recover: r.string()?,
                new_owner_authority: Authority::read_from(r)?,
                recent_owner_authority: Authority::read_from(r)?,
                extensions: read_no_extensions(r)?,
            }),
            OperationId::EscrowTransfer => Operation::EscrowTransfer(EscrowTransfer {
                from: r.string()?,
                to: r.string()?,
                hbd_amount: Amount::read_from(r)?,
                hive_amount: Amount::read_from(r)?,
                escrow_id: r.u32()?,
                agent: r.string()?,
                fee: Amount::read_from(r)?,
                json_meta: r.string()?,
                ratification_deadline: r.point_in_time()?,
                escrow_expiration: r.point_in_time()?,
            }),
            OperationId::EscrowDispute => Operation::EscrowDispute(EscrowDispute {
                from: r.string()?,
                to: r.string()?,
                agent: r.string()?,
                who: r.string()?,
                escrow_id: r.u32()?,
            }),
            OperationId::EscrowRelease => Operation::EscrowRelease(EscrowRelease {
                from: r.string()?,
                to: r.string()?,
                agent: r.string()?,
                who: r.string()?,
                receiver: r.string()?,
                escrow_id: r.u32()?,
                hbd_amount: Amount::read_from(r)?,
                hive_amount: Amount::read_from(r)?,
            }),
            OperationId::EscrowApprove => Operation::EscrowApprove(EscrowApprove {
                from: r.string()?,
                to: r.string()?,
                agent: r.string()?,
                who: r.string()?,
                escrow_id: r.u32()?,
                approve: r.bool()?,
            }),
            OperationId::CustomBinary => Operation::CustomBinary(CustomBinary {
                required_owner_auths: r.array::<String>()?,
                required_active_auths: r.array::<String>()?,
                required_posting_auths: r.array::<String>()?,
                required_auths: r.array::<Authority>()?,
                id: r.string()?,
                data: HexBytes::read_from(r)?,
            }),
            OperationId::ResetAccount => Operation::ResetAccount(ResetAccount {
                reset_account: r.string()?,
                account_to_reset: r.string()?,
                new_owner_authority: Authority::read_from(r)?,
            }),
            OperationId::SetResetAccount => Operation::SetResetAccount(SetResetAccount {
                account: r.string()?,
                current_reset_account: r.string()?,
                reset_account: r.string()?,
            }),
            OperationId::AccountCreateWithDelegation => {
                Operation::AccountCreateWithDelegation(AccountCreateWithDelegation {
                    fee: Amount::read_from(r)?,
                    delegation: Amount::read_from(r)?,
                    creator: r.string()?,
                    new_account_name: r.string()?,
                    owner: Authority::read_from(r)?,
                    active: Authority::read_from(r)?,
                    posting: Authority::read_from(r)?,
                    memo_key: PublicKey::read_from(r)?,
                    json_metadata: r.string()?,
                    extensions: read_no_extensions(r)?,
                })
            }
            OperationId::WitnessSetProperties => {
                Operation::WitnessSetProperties(WitnessSetProperties {
                    owner: r.string()?,
                    props: r.array::<WitnessProperty>()?,
                    extensions: read_no_extensions(r)?,
                })
            }
            OperationId::Transfer => Operation::Transfer(Transfer {
                from: r.string()?,
                to: r.string()?,
                amount: Amount::read_from(r)?,
                memo: r.string()?,
            }),
            OperationId::TransferToVesting => Operation::TransferToVesting(TransferToVesting {
                from: r.string()?,
                to: r.string()?,
                amount: Amount::read_from(r)?,
            }),
            OperationId::WithdrawVesting => Operation::WithdrawVesting(WithdrawVesting {
                account: r.string()?,
                vesting_shares: Amount::read_from(r)?,
            }),
            OperationId::LimitOrderCreate => Operation::LimitOrderCreate(LimitOrderCreate {
                owner: r.string()?,
                orderid: r.u32()?,
                amount_to_sell: Amount::read_from(r)?,
                min_to_receive: Amount::read_from(r)?,
                fill_or_kill: r.bool()?,
                expiration: r.point_in_time()?,
            }),
            OperationId::LimitOrderCancel => Operation::LimitOrderCancel(LimitOrderCancel {
                owner: r.string()?,
                orderid: r.u32()?,
            }),
            OperationId::FeedPublish => Operation::FeedPublish(FeedPublish {
                publisher: r.string()?,
                exchange_rate: Price::read_from(r)?,
            }),
            OperationId::Convert => Operation::Convert(Convert {
                owner: r.string()?,
                requestid: r.u32()?,
                amount: Amount::read_from(r)?,
            }),
            OperationId::AccountWitnessVote => Operation::AccountWitnessVote(AccountWitnessVote {
                account: r.string()?,
                witness: r.string()?,
                approve: r.bool()?,
            }),
            OperationId::AccountWitnessProxy => {
                Operation::AccountWitnessProxy(AccountWitnessProxy {
                    account: r.string()?,
                    proxy: r.string()?,
                })
            }
            OperationId::Custom => Operation::Custom(Custom {
                required_auths: r.array::<String>()?,
                id: r.u16()?,
                data: HexBytes::read_from(r)?,
            }),
            OperationId::DeleteComment => Operation::DeleteComment(DeleteComment {
                author: r.string()?,
                permlink: r.string()?,
            }),
            OperationId::CustomJson => Operation::CustomJson(CustomJson {
                required_auths: r.array::<String>()?,
                required_posting_auths: r.array::<String>()?,
                id: r.string()?,
                json: r.string()?,
            }),
            OperationId::CommentOptions => Operation::CommentOptions(CommentOptions {
                author: r.string()?,
                permlink: r.string()?,
                max_accepted_payout: Amount::read_from(r)?,
                percent_hbd: r.u16()?,
                allow_votes: r.bool()?,
                allow_curation_rewards: r.bool()?,
                extensions: r.array::<CommentOptionsExtension>()?,
            }),
            OperationId::SetWithdrawVestingRoute => {
                Operation::SetWithdrawVestingRoute(SetWithdrawVestingRoute {
                    from_account: r.string()?,
                    to_account: r.string()?,
                    percent: r.u16()?,
                    auto_vest: r.bool()?,
                })
            }
            OperationId::LimitOrderCreate2 => Operation::LimitOrderCreate2(LimitOrderCreate2 {
                owner: r.string()?,
                orderid: r.u32()?,
                amount_to_sell: Amount::read_from(r)?,
                exchange_rate: Price::read_from(r)?,
                fill_or_kill: r.bool()?,
                expiration: r.point_in_time()?,
            }),
            OperationId::ClaimAccount => Operation::ClaimAccount(ClaimAccount {
                creator: r.string()?,
                fee: Amount::read_from(r)?,
                extensions: read_no_extensions(r)?,
            }),
            OperationId::CreateClaimedAccount => {
                Operation::CreateClaimedAccount(CreateClaimedAccount {
                    creator: r.string()?,
                    new_account_name: r.string()?,
                    owner: Authority::read_from(r)?,
                    active: Authority::read_from(r)?,
                    posting: Authority::read_from(r)?,
                    memo_key: PublicKey::read_from(r)?,
                    json_metadata: r.string()?,
                    extensions: read_no_extensions(r)?,
                })
            }
            OperationId::ChangeRecoveryAccount => {
                Operation::ChangeRecoveryAccount(ChangeRecoveryAccount {
                    account_to_recover: r.string()?,
                    new_recovery_account: r.string()?,
                    extensions: read_no_extensions(r)?,
                })
            }
            OperationId::TransferToSavings => Operation::TransferToSavings(TransferToSavings {
                from: r.string()?,
                to: r.string()?,
                amount: Amount::read_from(r)?,
                memo: r.string()?,
            }),
            OperationId::TransferFromSavings => {
                Operation::TransferFromSavings(TransferFromSavings {
                    from: r.string()?,
                    request_id: r.u32()?,
                    to: r.string()?,
                    amount: Amount::read_from(r)?,
                    memo: r.string()?,
                })
            }
            OperationId::CancelTransferFromSavings => {
                Operation::CancelTransferFromSavings(CancelTransferFromSavings {
                    from: r.string()?,
                    request_id: r.u32()?,
                })
            }
            OperationId::DeclineVotingRights => {
                Operation::DeclineVotingRights(DeclineVotingRights {
                    account: r.string()?,
                    decline: r.bool()?,
                })
            }
            OperationId::ClaimRewardBalance => Operation::ClaimRewardBalance(ClaimRewardBalance {
                account: r.string()?,
                reward_hive: Amount::read_from(r)?,
                reward_hbd: Amount::read_from(r)?,
                reward_vests: Amount::read_from(r)?,
            }),
            OperationId::DelegateVestingShares => {
                Operation::DelegateVestingShares(DelegateVestingShares {
                    delegator: r.string()?,
                    delegatee: r.string()?,
                    vesting_shares: Amount::read_from(r)?,
                })
            }
            OperationId::AccountUpdate2 => Operation::AccountUpdate2(AccountUpdate2 {
                account: r.string()?,
                owner: r.optional::<Authority>()?,
                active: r.optional::<Authority>()?,
                posting: r.optional::<Authority>()?,
                memo_key: r.optional::<PublicKey>()?,
                json_metadata: r.string()?,
                posting_json_metadata: r.string()?,
                extensions: read_no_extensions(r)?,
            }),
            OperationId::CreateProposal => Operation::CreateProposal(CreateProposal {
                creator: r.string()?,
                receiver: r.string()?,
                start_date: r.point_in_time()?,
                end_date: r.point_in_time()?,
                daily_pay: Amount::read_from(r)?,
                subject: r.string()?,
                permlink: r.string()?,
                extensions: read_no_extensions(r)?,
            }),
            OperationId::UpdateProposalVotes => {
                Operation::UpdateProposalVotes(UpdateProposalVotes {
                    voter: r.string()?,
                    proposal_ids: r.array::<u64>()?,
                    approve: r.bool()?,
                    extensions: read_no_extensions(r)?,
                })
            }
            OperationId::RemoveProposal => Operation::RemoveProposal(RemoveProposal {
                proposal_owner: r.string()?,
                proposal_ids: r.array::<u64>()?,
                extensions: read_no_extensions(r)?,
            }),
            OperationId::UpdateProposal => Operation::UpdateProposal(UpdateProposal {
                proposal_id: r.u64()?,
                creator: r.string()?,
                daily_pay: Amount::read_from(r)?,
                subject: r.string()?,
                permlink: r.string()?,
                extensions: read_no_extensions(r)?,
            }),
            OperationId::CollateralizedConvert => {
                Operation::CollateralizedConvert(CollateralizedConvert {
                    owner: r.string()?,
                    requestid: r.u32()?,
                    amount: Amount::read_from(r)?,
                })
            }
            OperationId::RecurrentTransfer => Operation::RecurrentTransfer(RecurrentTransfer {
                from: r.string()?,
                to: r.string()?,
                amount: Amount::read_from(r)?,
                memo: r.string()?,
                recurrence: r.u16()?,
                executions: r.u16()?,
                extensions: r.array::<RecurrentTransferExtension>()?,
            }),
            OperationId::Pow | OperationId::Pow2 => {
                return Err(Error::ser(format!(
                    "{} is an obsolete mining operation that this build does not decode",
                    id.name()
                )))
            }
            other => {
                return Err(Error::ser(format!(
                    "operation {} has no decoder",
                    other.name()
                )))
            }
        })
    }
}

impl Operation {
    /// Parse from either JSON shape the API uses.
    ///
    /// `condenser_api` sends `["transfer", {...}]`; appbase APIs send
    /// `{"type": "transfer_operation", "value": {...}}`. beem handled both too, in
    /// `Operation.__init__`, by branching on `isinstance` and slicing the `_operation`
    /// suffix with a hard-coded `[:-10]`.
    ///
    /// A virtual operation name is refused: virtual operations cannot be broadcast, so
    /// decoding one into a signable [`Operation`] would invite exactly that mistake.
    /// Use [`AnyOperation::from_json`] when reading history, where both kinds appear.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        let (name, payload) = virtual_ops::split_operation_json(value)?;
        Self::from_named(name, payload)
    }

    /// Build from JSON that the caller owns, without copying the payload.
    ///
    /// Identical to [`Operation::from_json`] except that it consumes the value. The
    /// borrowing version has to clone the payload out of it, which for a caller that
    /// just parsed the JSON itself is a deep copy of every field for nothing — the
    /// dominant cost in decoding a transaction with many operations.
    pub fn from_json_owned(value: serde_json::Value) -> Result<Self> {
        let (name, payload) = virtual_ops::split_operation_json_owned(value)?;
        Self::from_named(name, payload)
    }

    fn from_named(name: String, payload: serde_json::Value) -> Result<Self> {
        let id = OperationId::from_name(&name)?;
        if id.is_virtual() {
            return Err(Error::ser(format!(
                "{} is a virtual operation and cannot be built as a signable operation",
                id.name()
            )));
        }
        Self::from_parts(id, payload)
    }

    fn from_parts(id: OperationId, value: serde_json::Value) -> Result<Self> {
        let de_err =
            |e: serde_json::Error| Error::ser(format!("could not decode {}: {e}", id.name()));
        Ok(match id {
            OperationId::Vote => Operation::Vote(serde_json::from_value(value).map_err(de_err)?),
            OperationId::Comment => {
                Operation::Comment(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::AccountCreate => {
                Operation::AccountCreate(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::AccountUpdate => {
                Operation::AccountUpdate(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::WitnessUpdate => {
                Operation::WitnessUpdate(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::WitnessBlockApprove => {
                Operation::WitnessBlockApprove(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::RequestAccountRecovery => {
                Operation::RequestAccountRecovery(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::RecoverAccount => {
                Operation::RecoverAccount(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::EscrowTransfer => {
                Operation::EscrowTransfer(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::EscrowDispute => {
                Operation::EscrowDispute(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::EscrowRelease => {
                Operation::EscrowRelease(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::EscrowApprove => {
                Operation::EscrowApprove(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::CustomBinary => {
                Operation::CustomBinary(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::ResetAccount => {
                Operation::ResetAccount(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::SetResetAccount => {
                Operation::SetResetAccount(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::AccountCreateWithDelegation => Operation::AccountCreateWithDelegation(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            OperationId::WitnessSetProperties => {
                Operation::WitnessSetProperties(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::Transfer => {
                Operation::Transfer(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::TransferToVesting => {
                Operation::TransferToVesting(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::WithdrawVesting => {
                Operation::WithdrawVesting(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::LimitOrderCreate => {
                Operation::LimitOrderCreate(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::LimitOrderCancel => {
                Operation::LimitOrderCancel(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::FeedPublish => {
                Operation::FeedPublish(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::Convert => {
                Operation::Convert(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::AccountWitnessVote => {
                Operation::AccountWitnessVote(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::AccountWitnessProxy => {
                Operation::AccountWitnessProxy(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::Custom => {
                Operation::Custom(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::DeleteComment => {
                Operation::DeleteComment(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::CustomJson => {
                Operation::CustomJson(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::CommentOptions => {
                Operation::CommentOptions(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::SetWithdrawVestingRoute => {
                Operation::SetWithdrawVestingRoute(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::LimitOrderCreate2 => {
                Operation::LimitOrderCreate2(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::ClaimAccount => {
                Operation::ClaimAccount(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::CreateClaimedAccount => {
                Operation::CreateClaimedAccount(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::ChangeRecoveryAccount => {
                Operation::ChangeRecoveryAccount(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::TransferToSavings => {
                Operation::TransferToSavings(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::TransferFromSavings => {
                Operation::TransferFromSavings(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::CancelTransferFromSavings => {
                Operation::CancelTransferFromSavings(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::DeclineVotingRights => {
                Operation::DeclineVotingRights(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::ClaimRewardBalance => {
                Operation::ClaimRewardBalance(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::DelegateVestingShares => {
                Operation::DelegateVestingShares(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::AccountUpdate2 => {
                Operation::AccountUpdate2(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::CreateProposal => {
                Operation::CreateProposal(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::UpdateProposalVotes => {
                Operation::UpdateProposalVotes(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::RemoveProposal => {
                Operation::RemoveProposal(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::UpdateProposal => {
                Operation::UpdateProposal(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::CollateralizedConvert => {
                Operation::CollateralizedConvert(serde_json::from_value(value).map_err(de_err)?)
            }
            OperationId::RecurrentTransfer => {
                Operation::RecurrentTransfer(serde_json::from_value(value).map_err(de_err)?)
            }
            other => {
                return Err(Error::ser(format!(
                    "operation {} cannot be built from JSON",
                    other.name()
                )))
            }
        })
    }

    /// Render as `[name, {fields}]`, the form `network_broadcast_api` expects.
    pub fn to_json(&self) -> Result<serde_json::Value> {
        let value = serde_json::to_value(self)
            .map_err(|e| Error::ser(format!("could not render operation as JSON: {e}")))?;
        Ok(serde_json::json!([self.id().name(), value]))
    }
}

/// An operation of either kind, as it appears in account history and block output.
///
/// History interleaves both: a `transfer` a user signed sits next to the
/// `fill_recurrent_transfer` the chain emitted. Keeping them one type to read and two
/// types to construct is the point — you can iterate history without special-casing,
/// but you cannot accidentally try to broadcast something the chain emits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum AnyOperation {
    /// An operation someone signed and broadcast.
    Signed(Operation),
    /// An operation the chain emitted.
    Virtual(VirtualOperation),
}

impl AnyOperation {
    /// Parse from either JSON shape, accepting both kinds.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        let (name, payload) = virtual_ops::split_operation_json(value)?;
        let id = OperationId::from_name(&name)?;
        if id.is_virtual() {
            VirtualOperation::from_json(value).map(AnyOperation::Virtual)
        } else {
            Operation::from_parts(id, payload).map(AnyOperation::Signed)
        }
    }

    /// The operation's id.
    pub fn id(&self) -> OperationId {
        match self {
            AnyOperation::Signed(o) => o.id(),
            AnyOperation::Virtual(o) => o.id(),
        }
    }

    /// The hived name, without the `_operation` suffix.
    pub fn name(&self) -> &'static str {
        self.id().name()
    }

    /// Whether this is an operation the chain emitted.
    pub fn is_virtual(&self) -> bool {
        matches!(self, AnyOperation::Virtual(_))
    }

    /// The signable operation, if this is one.
    pub fn as_signed(&self) -> Option<&Operation> {
        match self {
            AnyOperation::Signed(o) => Some(o),
            AnyOperation::Virtual(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::Chain;

    fn hive(s: &str) -> Amount {
        Amount::parse(s, Chain::Hive).unwrap()
    }

    #[test]
    fn vote_wire_layout() {
        let op = Operation::Vote(Vote {
            voter: "alice".into(),
            author: "bob".into(),
            permlink: "a-post".into(),
            weight: 10_000,
        });
        let wire = op.to_wire().unwrap();
        let mut expected = vec![0x00]; // op id 0
        expected.extend_from_slice(&[5, b'a', b'l', b'i', b'c', b'e']);
        expected.extend_from_slice(&[3, b'b', b'o', b'b']);
        expected.extend_from_slice(&[6, b'a', b'-', b'p', b'o', b's', b't']);
        expected.extend_from_slice(&10_000i16.to_le_bytes());
        assert_eq!(wire, expected);
    }

    #[test]
    fn downvotes_serialize_as_a_negative_int16() {
        let op = Operation::Vote(Vote {
            voter: "a".into(),
            author: "b".into(),
            permlink: "c".into(),
            weight: -10_000,
        });
        let wire = op.to_wire().unwrap();
        assert_eq!(&wire[wire.len() - 2..], &(-10_000i16).to_le_bytes());
    }

    #[test]
    fn custom_json_wire_layout() {
        let op = Operation::CustomJson(CustomJson {
            required_auths: vec![],
            required_posting_auths: vec!["alice".into()],
            id: "my_app_action".into(),
            json: r#"{"trx_id":"abc"}"#.into(),
        });
        let wire = op.to_wire().unwrap();
        assert_eq!(wire[0], 18, "custom_json is operation 18");
        assert_eq!(wire[1], 0, "no active auths");
        assert_eq!(wire[2], 1, "one posting auth");
    }

    #[test]
    fn custom_json_sorts_and_dedups_auth_sets() {
        let unsorted = Operation::CustomJson(CustomJson {
            required_auths: vec![],
            required_posting_auths: vec!["zulu".into(), "alpha".into(), "mike".into()],
            id: "x".into(),
            json: "{}".into(),
        });
        let sorted = Operation::CustomJson(CustomJson {
            required_auths: vec![],
            required_posting_auths: vec!["alpha".into(), "mike".into(), "zulu".into()],
            id: "x".into(),
            json: "{}".into(),
        });
        assert_eq!(unsorted.to_wire().unwrap(), sorted.to_wire().unwrap());

        let dup = Operation::CustomJson(CustomJson {
            required_auths: vec![],
            required_posting_auths: vec!["bob".into(), "bob".into()],
            id: "x".into(),
            json: "{}".into(),
        });
        assert!(dup.to_wire().is_err());
    }

    #[test]
    fn custom_json_enforces_the_id_length_and_a_signer() {
        let too_long = Operation::CustomJson(CustomJson {
            required_auths: vec![],
            required_posting_auths: vec!["a".into()],
            id: "x".repeat(33),
            json: "{}".into(),
        });
        assert!(too_long.to_wire().is_err());

        let no_auths = Operation::CustomJson(CustomJson {
            required_auths: vec![],
            required_posting_auths: vec![],
            id: "x".into(),
            json: "{}".into(),
        });
        assert!(no_auths.to_wire().is_err());
    }

    #[test]
    fn transfer_includes_the_memo() {
        let op = Operation::Transfer(Transfer {
            from: "alice".into(),
            to: "bob".into(),
            amount: hive("1.000 HIVE"),
            memo: "thanks".into(),
        });
        let wire = op.to_wire().unwrap();
        assert_eq!(wire[0], 2);
        assert!(wire.ends_with(&[6, b't', b'h', b'a', b'n', b'k', b's']));
    }

    #[test]
    fn recurrent_transfer_is_constructible_and_correctly_typed() {
        // The whole point: beem cannot build this at all.
        let op = Operation::RecurrentTransfer(RecurrentTransfer {
            from: "alice".into(),
            to: "bob".into(),
            amount: hive("1.000 HIVE"),
            memo: String::new(),
            recurrence: 24,
            executions: 12,
            extensions: vec![],
        });
        let wire = op.to_wire().unwrap();
        assert_eq!(wire[0], 49, "recurrent_transfer is operation 49");
        // ...recurrence, executions as u16 LE, then an empty extensions array.
        assert_eq!(&wire[wire.len() - 5..], &[24, 0, 12, 0, 0]);
    }

    #[test]
    fn recurrent_transfer_carries_the_hf28_pair_id() {
        let op = Operation::RecurrentTransfer(RecurrentTransfer {
            from: "alice".into(),
            to: "bob".into(),
            amount: hive("1.000 HIVE"),
            memo: String::new(),
            recurrence: 24,
            executions: 12,
            extensions: vec![RecurrentTransferExtension::PairId(7)],
        });
        let wire = op.to_wire().unwrap();
        // one extension, variant tag 1, then the single-byte pair id
        assert_eq!(&wire[wire.len() - 3..], &[1, 1, 7]);
    }

    /// Field orders that were wrong until a node was asked.
    ///
    /// Both of these round-tripped perfectly through `hivecomb`'s own serializer and
    /// deserializer, and both would have been rejected by the chain. A round-trip test
    /// cannot catch a field order that is wrong in both directions; only an external
    /// authority can. The bytes below are what `condenser_api.get_transaction_hex`
    /// returned for these exact operations, so this test is that authority, frozen.
    ///
    /// See `tests/hived_serialization_oracle.py` to re-measure them.
    #[test]
    fn escrow_transfer_matches_hiveds_own_bytes() {
        let op = Operation::EscrowTransfer(EscrowTransfer {
            from: "aaa".into(),
            to: "bbb".into(),
            hbd_amount: hive("1.000 HBD"),
            hive_amount: hive("2.000 HIVE"),
            escrow_id: 0x1122_3344,
            agent: "ccc".into(),
            fee: hive("0.100 HIVE"),
            json_meta: "JM".into(),
            ratification_deadline: PointInTime::from_unix(1_893_456_000).unwrap(), // 2030-01-01T00:00:00Z
            escrow_expiration: PointInTime::from_unix(1_927_756_800).unwrap(), // 2031-02-02T00:00:00Z
        });
        // op id 27, then: from, to, hbd, hive, escrow_id, agent, fee, json_meta,
        // ratification_deadline, escrow_expiration. Note that json_meta sits between
        // the fee and the deadlines, which is not where the JSON form suggests.
        let expected = hex_to_bytes(
            "1b0361616103626262e8030000000000000353424400000000d00700000000000003535445             454d00004433221103636363640000000000000003535445454d0000024a4d80d8db70003c             e772",
        );
        assert_eq!(op.to_wire().unwrap(), expected);
    }

    #[test]
    fn limit_order_create2_matches_hiveds_own_bytes() {
        let op = Operation::LimitOrderCreate2(LimitOrderCreate2 {
            owner: "aaa".into(),
            orderid: 0x1122_3344,
            amount_to_sell: hive("7.000 HIVE"),
            exchange_rate: Price {
                base: hive("3.000 HIVE"),
                quote: hive("5.000 HBD"),
            },
            fill_or_kill: true,
            expiration: PointInTime::from_unix(1_893_456_000).unwrap(), // 2030-01-01T00:00:00Z
        });
        // op id 21, then: owner, orderid, amount_to_sell, exchange_rate, fill_or_kill,
        // expiration. `exchange_rate` precedes `fill_or_kill` -- the reverse of the
        // order `limit_order_create` would lead you to expect.
        let expected = hex_to_bytes(
            "150361616144332211581b00000000000003535445454d0000b80b0000000000000353544             5454d0000881300000000000003534244000000000180d8db70",
        );
        assert_eq!(op.to_wire().unwrap(), expected);
    }

    #[test]
    fn recurrent_transfer_pair_id_uses_the_json_shape_hived_accepts() {
        // hived rejects the `[tag, value]` array form for this extension with
        // "Bad Cast: Input data have to treated as object, but got array_type", so a
        // transaction carrying it cannot be broadcast at all. The binary is identical
        // either way, which is what makes the wrong form easy to ship.
        let ext = RecurrentTransferExtension::PairId(7);
        let json = serde_json::to_string(&ext).unwrap();
        assert_eq!(
            json,
            r#"{"type":"recurrent_transfer_pair_id","value":{"pair_id":7}}"#
        );

        // Both forms still parse, so transactions built by other tooling load.
        let from_object: RecurrentTransferExtension = serde_json::from_str(&json).unwrap();
        let from_array: RecurrentTransferExtension =
            serde_json::from_str(r#"[1, {"pair_id": 7}]"#).unwrap();
        assert_eq!(from_object, ext);
        assert_eq!(from_array, ext);
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn deserialize_then_serialize_is_not_the_identity_for_control_bytes() {
        // Found by cargo-fuzz on its first run, within four minutes.
        //
        // A string field holding a raw byte below 0x20 parses back as that byte, and
        // re-serializing puts it through `hived_transport_form`, which writes the five
        // characters `u0000` instead. So parse and serialize are NOT inverses.
        //
        // That is not a defect in the transform -- hived's JSON parser does the same
        // thing, so those are the bytes any signature has to cover -- but it is a
        // property callers need to know: a transaction parsed from foreign bytes and
        // re-signed does not sign the bytes it arrived as. Wire bytes from hived can
        // never contain such a character, because anything hived stored went through
        // that same parser first; foreign binary can.
        //
        // What does hold, and what the fuzz targets assert, is that it settles after
        // one pass.
        use crate::operations::Operation;
        use crate::{Chain, GrapheneDeserialize, GrapheneSerialize, Reader};

        let wire = {
            let mut out = vec![0u8]; // op id 0: vote
            out.extend_from_slice(&[4, 0, 0, 0, 0]); // voter: four NUL bytes
            out.extend_from_slice(&[0]); // author: ""
            out.extend_from_slice(&[0]); // permlink: ""
            out.extend_from_slice(&[1, 0]); // weight: 1
            out
        };

        let mut reader = Reader::new(&wire, Chain::Hive);
        let op = Operation::read_from(&mut reader).expect("parses");
        let again = op.to_wire().expect("re-serializes");

        assert_ne!(again, wire, "if these are equal the asymmetry is gone");

        // But it is stable from the second pass on: the transform is idempotent,
        // because `u0000` contains nothing that gets transformed again.
        let mut reader2 = Reader::new(&again, Chain::Hive);
        let op2 = Operation::read_from(&mut reader2).expect("parses");
        assert_eq!(op2.to_wire().expect("re-serializes"), again);
    }

    #[test]
    fn collateralized_convert_is_constructible() {
        let op = Operation::CollateralizedConvert(CollateralizedConvert {
            owner: "alice".into(),
            requestid: 1,
            amount: hive("1.000 HIVE"),
        });
        assert_eq!(op.to_wire().unwrap()[0], 48);
    }

    #[test]
    fn account_update2_encodes_absent_optionals_as_a_single_zero() {
        let op = Operation::AccountUpdate2(AccountUpdate2 {
            account: "alice".into(),
            owner: None,
            active: None,
            posting: None,
            memo_key: None,
            json_metadata: String::new(),
            posting_json_metadata: "{}".into(),
            extensions: NoExtensions,
        });
        let wire = op.to_wire().unwrap();
        assert_eq!(wire[0], 43);
        // op id, varint(5) + "alice", then four absent optionals
        assert_eq!(&wire[7..11], &[0, 0, 0, 0]);
    }

    #[test]
    fn comment_options_rejects_over_full_beneficiaries() {
        let op = Operation::CommentOptions(CommentOptions {
            author: "alice".into(),
            permlink: "p".into(),
            max_accepted_payout: Amount::parse("1000000.000 HBD", Chain::Hive).unwrap(),
            percent_hbd: 10_000,
            allow_votes: true,
            allow_curation_rewards: true,
            extensions: vec![CommentOptionsExtension::Beneficiaries(vec![
                Beneficiary {
                    account: "a".into(),
                    weight: 6000,
                },
                Beneficiary {
                    account: "b".into(),
                    weight: 5000,
                },
            ])],
        });
        assert!(op.to_wire().is_err(), "11000 basis points must be refused");
    }

    #[test]
    fn proposal_ids_are_sorted_and_deduped() {
        let a = Operation::RemoveProposal(RemoveProposal {
            proposal_owner: "alice".into(),
            proposal_ids: vec![9, 3, 5],
            extensions: NoExtensions,
        });
        let b = Operation::RemoveProposal(RemoveProposal {
            proposal_owner: "alice".into(),
            proposal_ids: vec![3, 5, 9],
            extensions: NoExtensions,
        });
        assert_eq!(a.to_wire().unwrap(), b.to_wire().unwrap());

        let dup = Operation::RemoveProposal(RemoveProposal {
            proposal_owner: "alice".into(),
            proposal_ids: vec![3, 3],
            extensions: NoExtensions,
        });
        assert!(dup.to_wire().is_err());
    }

    #[test]
    fn every_variant_reports_a_non_virtual_id() {
        // A virtual operation must never be constructible.
        let ops = sample_of_every_variant();
        for op in &ops {
            assert!(
                !op.id().is_virtual(),
                "{:?} is virtual and must not be in the Operation enum",
                op.id()
            );
        }
    }

    #[test]
    fn every_variant_serializes_with_its_own_tag() {
        for op in sample_of_every_variant() {
            let wire = op.to_wire().unwrap();
            let (tag, _) = crate::types::read_varint32(&wire).unwrap();
            assert_eq!(tag, op.id().as_u32(), "{:?} wrote the wrong tag", op.id());
        }
    }

    #[test]
    fn escrow_release_carries_agent_and_receiver() {
        // beem omits both, serializing six of eight fields — including the one that
        // says who the funds go to. See SECURITY_FINDINGS.md finding 22.
        let op = Operation::EscrowRelease(EscrowRelease {
            from: "alice".into(),
            to: "bob".into(),
            agent: "carol".into(),
            who: "alice".into(),
            receiver: "bob".into(),
            escrow_id: 1,
            hbd_amount: hive("1.000 HBD"),
            hive_amount: hive("2.000 HIVE"),
        });
        let wire = op.to_wire().unwrap();
        assert_eq!(wire[0], 29);
        // Five length-prefixed names, then a u32 id, then two 16-byte assets.
        let names_len: usize = ["alice", "bob", "carol", "alice", "bob"]
            .iter()
            .map(|n| 1 + n.len())
            .sum();
        assert_eq!(wire.len(), 1 + names_len + 4 + 16 + 16);
        // "carol" must actually be present.
        assert!(wire.windows(5).any(|w| w == b"carol"));
    }

    #[test]
    fn escrow_dispute_carries_agent() {
        let op = Operation::EscrowDispute(EscrowDispute {
            from: "alice".into(),
            to: "bob".into(),
            agent: "carol".into(),
            who: "alice".into(),
            escrow_id: 7,
        });
        let wire = op.to_wire().unwrap();
        assert_eq!(wire[0], 28);
        assert!(wire.windows(5).any(|w| w == b"carol"));
        assert_eq!(&wire[wire.len() - 4..], &7u32.to_le_bytes());
    }

    /// hived caps a `custom_json` payload at 8192 bytes, and the boundary is exact.
    ///
    /// Sat on deliberately, because nothing in this suite previously did: a test that
    /// only ever uses small payloads cannot notice the check being removed, and one
    /// that only ever uses enormous ones cannot notice an off-by-one.
    #[test]
    fn a_custom_json_payload_is_capped_at_the_boundary() {
        let at_limit = |n: usize| {
            Operation::CustomJson(CustomJson {
                required_auths: vec![],
                required_posting_auths: vec!["alice".into()],
                id: "my_app".into(),
                json: "x".repeat(n),
            })
        };
        assert!(
            at_limit(MAX_CUSTOM_DATA_LEN).to_wire().is_ok(),
            "exactly {MAX_CUSTOM_DATA_LEN} bytes is within the limit, not past it"
        );
        let err = at_limit(MAX_CUSTOM_DATA_LEN + 1)
            .to_wire()
            .expect_err("one byte over must be refused");
        let text = err.to_string();
        assert!(
            text.contains("8193"),
            "the error should say how big it was: {text}"
        );
        // The message has to explain the blast radius, because the failure mode is
        // counter-intuitive: the chain rejects the entire transaction, so every other
        // operation batched alongside it is lost too.
        assert!(
            text.contains("whole transaction"),
            "the error should say the whole transaction is rejected: {text}"
        );
    }

    /// The same cap applies to `custom`, whose payload is binary rather than JSON.
    #[test]
    fn a_custom_binary_payload_is_capped_at_the_boundary() {
        let op = |n: usize| {
            Operation::Custom(Custom {
                required_auths: vec!["alice".into()],
                id: 7,
                data: HexBytes(vec![0x5a; n]),
            })
        };
        assert!(op(MAX_CUSTOM_DATA_LEN).to_wire().is_ok());
        assert!(op(MAX_CUSTOM_DATA_LEN + 1).to_wire().is_err());
    }

    /// The cap is hived's, not this crate's invention.
    ///
    /// `HIVE_CUSTOM_OP_DATA_MAX_LENGTH`, read from a live node's
    /// `database_api.get_config` on 2026-08-24. Pinned so that changing the constant
    /// here requires deciding to, rather than happening.
    #[test]
    fn the_payload_cap_matches_hived() {
        assert_eq!(MAX_CUSTOM_DATA_LEN, 8192);
        assert_eq!(MAX_CUSTOM_ID_LEN, 32);
    }

    /// Every length bound derived from hived, at its exact boundary.
    ///
    /// Each is the constant minus one, and each arrives there by a different route in
    /// hived — the memo and title via `validate_string_max_size(x, CONST - 1)` where the
    /// helper is `<=`, the permlink via a bare `size() < CONST`. Assuming either form
    /// from the other would be wrong by one, so both ends are pinned.
    #[test]
    fn the_length_bounds_sit_exactly_where_hived_puts_them() {
        use crate::Chain;

        let transfer = |memo: &str| {
            Operation::Transfer(Transfer {
                from: "alice".into(),
                to: "bob".into(),
                amount: Amount::parse("1.000 HIVE", Chain::Hive).unwrap(),
                memo: memo.into(),
            })
        };
        assert!(transfer(&"m".repeat(MAX_MEMO_LEN)).to_wire().is_ok());
        assert!(transfer(&"m".repeat(MAX_MEMO_LEN + 1)).to_wire().is_err());

        let comment = |title: &str, permlink: &str| {
            Operation::Comment(Comment {
                parent_author: String::new(),
                parent_permlink: "hive-100".into(),
                author: "alice".into(),
                permlink: permlink.into(),
                title: title.into(),
                body: "b".into(),
                json_metadata: "{}".into(),
            })
        };
        let t = "t".repeat(MAX_TITLE_LEN);
        let p = "p".repeat(MAX_PERMLINK_LEN);
        assert!(
            comment(&t, &p).to_wire().is_ok(),
            "both exactly at the bound"
        );
        assert!(comment(&"t".repeat(MAX_TITLE_LEN + 1), &p)
            .to_wire()
            .is_err());
        assert!(comment(&t, &"p".repeat(MAX_PERMLINK_LEN + 1))
            .to_wire()
            .is_err());
    }

    /// The constants are hived's, restated. Pinned so a change has to be deliberate.
    ///
    /// Read from `libraries/protocol` at the revision mainnet ran on 2026-08-24
    /// (`1584099c3054`, blockchain_version 1.28.7), cross-checked against three nodes'
    /// `database_api.get_config`.
    #[test]
    fn the_length_bounds_match_hived() {
        assert_eq!(MAX_MEMO_LEN, 2048 - 1);
        assert_eq!(MAX_TITLE_LEN, 256 - 1);
        assert_eq!(MAX_PERMLINK_LEN, 256 - 1);
    }

    /// All four memo-carrying operations enforce it, not just `transfer`.
    #[test]
    fn every_memo_carrying_operation_is_bounded() {
        use crate::types::PointInTime;
        use crate::Chain;

        let big = "m".repeat(MAX_MEMO_LEN + 1);
        let amount = Amount::parse("1.000 HIVE", Chain::Hive).unwrap();
        let ops = vec![
            Operation::Transfer(Transfer {
                from: "alice".into(),
                to: "bob".into(),
                amount,
                memo: big.clone(),
            }),
            Operation::TransferToSavings(TransferToSavings {
                from: "alice".into(),
                to: "bob".into(),
                amount,
                memo: big.clone(),
            }),
            Operation::TransferFromSavings(TransferFromSavings {
                from: "alice".into(),
                request_id: 1,
                to: "bob".into(),
                amount,
                memo: big.clone(),
            }),
            Operation::RecurrentTransfer(RecurrentTransfer {
                from: "alice".into(),
                to: "bob".into(),
                amount,
                memo: big,
                recurrence: 24,
                executions: 2,
                extensions: vec![],
            }),
        ];
        let _ = PointInTime::from_unix(0);
        for op in ops {
            let name = op.id().name();
            assert!(op.to_wire().is_err(), "{name} did not bound its memo");
        }
    }

    /// The remaining bounds hived's `validate()` applies, each at its exact boundary.
    ///
    /// Each was read from hived rather than inferred, because the forms differ: the
    /// proposal subject and witness URL use `validate_string_max_size(x, CONST)` with no
    /// subtraction, where the memo and title use `CONST - 1`. Assuming one from the
    /// other is wrong by one in whichever direction you guess.
    #[test]
    fn the_remaining_bounds_sit_exactly_where_hived_puts_them() {
        use crate::types::PointInTime;
        use crate::Chain;

        let proposal = |subject: &str, permlink: &str| {
            Operation::CreateProposal(CreateProposal {
                creator: "alice".into(),
                receiver: "bob".into(),
                start_date: PointInTime::from_unix(1_893_456_000).unwrap(),
                end_date: PointInTime::from_unix(1_927_756_800).unwrap(),
                daily_pay: Amount::parse("1.000 HBD", Chain::Hive).unwrap(),
                subject: subject.into(),
                permlink: permlink.into(),
                extensions: NoExtensions,
            })
        };
        let subj = "s".repeat(MAX_PROPOSAL_SUBJECT_LEN);
        assert!(
            proposal(&subj, "p").to_wire().is_ok(),
            "exactly 80 is allowed"
        );
        assert!(proposal(&"s".repeat(MAX_PROPOSAL_SUBJECT_LEN + 1), "p")
            .to_wire()
            .is_err());
        assert!(proposal(&subj, &"p".repeat(MAX_PERMLINK_LEN + 1))
            .to_wire()
            .is_err());

        let witness = |url: &str| {
            Operation::WitnessUpdate(WitnessUpdate {
                owner: "alice".into(),
                url: url.into(),
                block_signing_key: PublicKey::from_prefixed_any(
                    "STM6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
                )
                .unwrap(),
                props: ChainProperties {
                    account_creation_fee: Amount::parse("3.000 HIVE", Chain::Hive).unwrap(),
                    maximum_block_size: 65_536,
                    hbd_interest_rate: 0,
                },
                fee: Amount::parse("0.000 HIVE", Chain::Hive).unwrap(),
            })
        };
        assert!(
            witness(&"u".repeat(MAX_WITNESS_URL_LEN)).to_wire().is_ok(),
            "2048 allowed"
        );
        assert!(witness(&"u".repeat(MAX_WITNESS_URL_LEN + 1))
            .to_wire()
            .is_err());
    }

    /// Proposal id lists are bounded at both ends.
    #[test]
    fn proposal_id_lists_are_bounded() {
        let votes = |n: u64| {
            Operation::UpdateProposalVotes(UpdateProposalVotes {
                voter: "alice".into(),
                proposal_ids: (0..n).collect(),
                approve: true,
                extensions: NoExtensions,
            })
        };
        assert!(votes(0).to_wire().is_err(), "empty is refused");
        assert!(votes(MAX_PROPOSAL_IDS as u64).to_wire().is_ok());
        assert!(votes(MAX_PROPOSAL_IDS as u64 + 1).to_wire().is_err());
    }

    /// The constants are hived's, restated. Pinned so a change has to be deliberate.
    #[test]
    fn the_remaining_bounds_match_hived() {
        assert_eq!(MAX_AUTHORITY_MEMBERSHIP, 40);
        assert_eq!(MAX_BENEFICIARIES, 128 - 1);
        assert_eq!(MAX_PROPOSAL_SUBJECT_LEN, 80);
        assert_eq!(MAX_PROPOSAL_IDS, 5);
        assert_eq!(MAX_WITNESS_URL_LEN, 2048);
    }

    #[test]
    fn custom_binary_has_all_six_fields() {
        // beem serializes only `id` and `data`, and types `id` as a Uint16.
        let op = Operation::CustomBinary(CustomBinary {
            required_owner_auths: vec![],
            required_active_auths: vec!["alice".into()],
            required_posting_auths: vec![],
            required_auths: vec![],
            id: "app".into(),
            data: HexBytes(vec![0xde, 0xad]),
        });
        let wire = op.to_wire().unwrap();
        assert_eq!(wire[0], 35);
        // op id, then four empty-or-one-element containers before the id string.
        assert_eq!(wire[1], 0, "no owner auths");
        assert_eq!(wire[2], 1, "one active auth");
        assert_eq!(&wire[3..9], b"\x05alice");
        assert_eq!(wire[9], 0, "no posting auths");
        assert_eq!(wire[10], 0, "no authority objects");
        assert_eq!(
            &wire[11..15],
            b"\x03app",
            "id is a length-prefixed string, not a u16"
        );
    }

    #[test]
    fn witness_set_properties_sorts_its_flat_map() {
        let a = Operation::WitnessSetProperties(WitnessSetProperties {
            owner: "w".into(),
            props: vec![
                WitnessProperty::uint32("maximum_block_size", 65536),
                WitnessProperty::uint16("hbd_interest_rate", 1000),
            ],
            extensions: NoExtensions,
        });
        let b = Operation::WitnessSetProperties(WitnessSetProperties {
            owner: "w".into(),
            props: vec![
                WitnessProperty::uint16("hbd_interest_rate", 1000),
                WitnessProperty::uint32("maximum_block_size", 65536),
            ],
            extensions: NoExtensions,
        });
        assert_eq!(a.to_wire().unwrap(), b.to_wire().unwrap());

        let dup = Operation::WitnessSetProperties(WitnessSetProperties {
            owner: "w".into(),
            props: vec![
                WitnessProperty::uint32("maximum_block_size", 1),
                WitnessProperty::uint32("maximum_block_size", 2),
            ],
            extensions: NoExtensions,
        });
        assert!(dup.to_wire().is_err());
    }

    #[test]
    fn account_update_memo_key_is_not_optional() {
        // account_update carries a bare public_key_type; only account_update2 makes it
        // an optional. Getting these two the wrong way round shifts every later field.
        let key = crate::keys::PrivateKey::generate().public_key();
        let update = Operation::AccountUpdate(AccountUpdate {
            account: "a".into(),
            owner: None,
            active: None,
            posting: None,
            memo_key: key,
            json_metadata: String::new(),
        });
        let wire = update.to_wire().unwrap();
        // op id + varint(1) + "a" + three absent optionals, then 33 raw key bytes.
        assert_eq!(&wire[3..6], &[0, 0, 0]);
        assert_eq!(&wire[6..39], &key.to_bytes());
    }

    #[test]
    fn every_non_virtual_operation_except_mining_is_constructible() {
        use std::collections::HashSet;
        let built: HashSet<u32> = sample_of_every_variant()
            .iter()
            .map(|op| op.id().as_u32())
            .collect();
        // pow (14) and pow2 (30) are the obsolete mining operations; hived has
        // rejected them since HF17 and beem never implemented them either.
        let obsolete_mining: HashSet<u32> = [14, 30].into_iter().collect();
        let missing: Vec<u32> = (0..FIRST_VIRTUAL_OP)
            .filter(|id| !built.contains(id) && !obsolete_mining.contains(id))
            .collect();
        assert!(
            missing.is_empty(),
            "operations not constructible: {missing:?}"
        );
        assert_eq!(
            built.len(),
            (FIRST_VIRTUAL_OP as usize) - obsolete_mining.len()
        );
    }

    #[test]
    fn every_operation_round_trips_through_the_wire_format() {
        // The property that hand-written assertions cannot give: serialize every
        // variant, read it back, serialize again, and require the bytes to match.
        // Any field written but not read (or read in the wrong order) shows up here
        // without anyone having to remember to assert on it.
        for op in sample_of_every_variant() {
            let wire = op.to_wire().unwrap();
            let mut r = Reader::new(&wire, Chain::Hive);
            let back = Operation::read_from(&mut r)
                .unwrap_or_else(|e| panic!("{:?} failed to decode: {e}", op.id()));
            r.expect_end()
                .unwrap_or_else(|e| panic!("{:?} left bytes unread: {e}", op.id()));
            assert_eq!(back.id(), op.id());
            assert_eq!(
                back.to_wire().unwrap(),
                wire,
                "{:?} did not round trip",
                op.id()
            );
        }
    }

    #[test]
    fn decoding_refuses_virtual_operations() {
        // A virtual operation can never be in a transaction; seeing one means the
        // bytes are not a transaction.
        let mut wire = Vec::new();
        crate::types::write_varint32(&mut wire, OperationId::ProducerReward.as_u32());
        let mut r = Reader::new(&wire, Chain::Hive);
        let err = Operation::read_from(&mut r).unwrap_err();
        assert!(format!("{err}").contains("virtual"));
    }

    #[test]
    fn decoding_refuses_unknown_operation_ids() {
        let mut wire = Vec::new();
        crate::types::write_varint32(&mut wire, 200);
        let mut r = Reader::new(&wire, Chain::Hive);
        assert!(Operation::read_from(&mut r).is_err());
    }

    #[test]
    fn decoding_refuses_unmodelled_extensions() {
        // claim_account with a non-empty extensions array. Dropping it silently would
        // give a value that re-serializes to different bytes.
        let mut wire = Vec::new();
        crate::types::write_varint32(&mut wire, OperationId::ClaimAccount.as_u32());
        crate::types::write_string(&mut wire, "alice").unwrap();
        hive("0.000 HIVE").append_to(&mut wire).unwrap();
        crate::types::write_varint32(&mut wire, 1); // one extension
        let mut r = Reader::new(&wire, Chain::Hive);
        let err = Operation::read_from(&mut r).unwrap_err();
        assert!(format!("{err}").contains("extension"));
    }

    #[test]
    fn truncated_operations_error_rather_than_panic() {
        let op = Operation::Transfer(Transfer {
            from: "alice".into(),
            to: "bob".into(),
            amount: hive("1.000 HIVE"),
            memo: "hello".into(),
        });
        let wire = op.to_wire().unwrap();
        for cut in 1..wire.len() {
            let mut r = Reader::new(&wire[..cut], Chain::Hive);
            let decoded = Operation::read_from(&mut r).and_then(|o| {
                r.expect_end()?;
                Ok(o)
            });
            assert!(decoded.is_err(), "truncating to {cut} bytes should fail");
        }
    }

    #[test]
    fn json_round_trips_every_operation() {
        // Same property as the wire round trip, over the JSON representation the API
        // uses. Catches a field that serializes but does not parse back.
        for op in sample_of_every_variant() {
            let json = op.to_json().unwrap();
            let back = Operation::from_json(&json)
                .unwrap_or_else(|e| panic!("{:?} failed to parse back: {e}", op.id()));
            assert_eq!(back, op, "{:?} did not round trip through JSON", op.id());
        }
    }

    #[test]
    fn json_accepts_both_the_condenser_and_appbase_shapes() {
        let condenser = serde_json::json!([
            "transfer",
            {"from": "alice", "to": "bob", "amount": "1.000 HIVE", "memo": "hi"}
        ]);
        let appbase = serde_json::json!({
            "type": "transfer_operation",
            "value": {"from": "alice", "to": "bob", "amount": "1.000 HIVE", "memo": "hi"}
        });
        let a = Operation::from_json(&condenser).unwrap();
        let b = Operation::from_json(&appbase).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.id(), OperationId::Transfer);
    }

    #[test]
    fn json_refuses_a_virtual_operation_as_signable() {
        let vop = serde_json::json!([
            "producer_reward",
            {"producer": "alice", "vesting_shares": "1.000000 VESTS"}
        ]);
        assert!(Operation::from_json(&vop).is_err());
        // ...but AnyOperation reads it happily.
        let any = AnyOperation::from_json(&vop).unwrap();
        assert!(any.is_virtual());
        assert_eq!(any.name(), "producer_reward");
        assert!(any.as_signed().is_none());
    }

    #[test]
    fn json_refuses_malformed_and_unknown_shapes() {
        assert!(Operation::from_json(&serde_json::json!("transfer")).is_err());
        assert!(Operation::from_json(&serde_json::json!(["transfer"])).is_err());
        assert!(Operation::from_json(&serde_json::json!(["nope", {}])).is_err());
        assert!(Operation::from_json(&serde_json::json!({"type": 1, "value": {}})).is_err());
    }

    #[test]
    fn json_refuses_unmodelled_extensions() {
        let op = serde_json::json!([
            "claim_account",
            {"creator": "alice", "fee": "0.000 HIVE", "extensions": [[99, {}]]}
        ]);
        assert!(Operation::from_json(&op).is_err());
    }

    #[test]
    fn any_operation_reads_a_mixed_history_stream() {
        // What account_history_api actually hands back: signed and virtual, interleaved.
        let stream = serde_json::json!([
            ["transfer", {"from": "a", "to": "b", "amount": "1.000 HIVE", "memo": ""}],
            ["producer_reward", {"producer": "w", "vesting_shares": "1.000000 VESTS"}],
            ["fill_recurrent_transfer", {"from": "a", "to": "b", "amount": "1.000 HIVE",
                                         "memo": "", "remaining_executions": 5}],
            ["curation_reward", {"curator": "c", "reward": "1.000000 VESTS",
                                 "author": "a", "permlink": "p",
                                 "payout_must_be_claimed": true}],
        ]);
        let ops: Vec<AnyOperation> = stream
            .as_array()
            .unwrap()
            .iter()
            .map(|v| AnyOperation::from_json(v).unwrap())
            .collect();
        assert_eq!(ops.len(), 4);
        assert!(!ops[0].is_virtual());
        assert!(ops[1].is_virtual() && ops[2].is_virtual() && ops[3].is_virtual());
        assert_eq!(
            ops.iter().map(|o| o.id().as_u32()).collect::<Vec<_>>(),
            vec![2, 64, 83, 52]
        );
    }

    #[test]
    fn hf25_and_later_virtual_operations_parse() {
        // Everything here postdates beem's last release.
        let cases = [
            (
                "limit_order_cancelled",
                serde_json::json!({"seller": "a", "orderid": 1, "amount_back": "1.000 HIVE"}),
            ),
            (
                "proposal_fee",
                serde_json::json!({"creator": "a", "treasury": "t", "proposal_id": 1, "fee": "10.000 HBD"}),
            ),
            ("producer_missed", serde_json::json!({"producer": "w"})),
            (
                "proxy_cleared",
                serde_json::json!({"account": "a", "proxy": "p"}),
            ),
            (
                "escrow_approved",
                serde_json::json!({"from": "a", "to": "b", "agent": "c", "escrow_id": 1, "fee": "0.100 HIVE"}),
            ),
            (
                "declined_voting_rights",
                serde_json::json!({"account": "a"}),
            ),
            (
                "expired_account_notification",
                serde_json::json!({"account": "a"}),
            ),
            (
                "collateralized_convert_immediate_conversion",
                serde_json::json!({"owner": "a", "requestid": 1, "hbd_out": "1.000 HBD"}),
            ),
        ];
        for (name, value) in cases {
            let json = serde_json::json!([name, value]);
            let op = AnyOperation::from_json(&json)
                .unwrap_or_else(|e| panic!("{name} failed to parse: {e}"));
            assert!(op.is_virtual(), "{name} should be virtual");
            assert_eq!(op.name(), name);
        }
    }

    #[test]
    fn a_recurrent_transfer_fill_carries_its_pair_id() {
        let json = serde_json::json!([
            "fill_recurrent_transfer",
            {"from": "a", "to": "b", "amount": "1.000 HIVE", "memo": "",
             "remaining_executions": 3, "extensions": [[1, {"pair_id": 7}]]}
        ]);
        let op = AnyOperation::from_json(&json).unwrap();
        match op {
            AnyOperation::Virtual(VirtualOperation::FillRecurrentTransfer(v)) => {
                assert_eq!(v.remaining_executions, 3);
                assert_eq!(v.extensions, vec![RecurrentTransferExtension::PairId(7)]);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn virtual_operation_ids_are_the_chains_not_beems() {
        // beem reports each of these two lower, because two non-virtual operations are
        // missing from its table.
        for (name, id) in [
            ("fill_convert_request", 50u32),
            ("producer_reward", 64),
            ("fill_recurrent_transfer", 83),
            ("declined_voting_rights", 92),
        ] {
            assert_eq!(OperationId::from_name(name).unwrap().as_u32(), id);
        }
    }

    /// One value of every `Operation` variant, so the tests above cover all of them.
    /// The owned decoder must agree with the borrowing one on every variant.
    ///
    /// `from_json_owned` exists only to avoid a deep copy, so any difference in what it
    /// accepts or produces is a bug and not a trade-off. Two decoders for the signed
    /// wire format that disagree is precisely the kind of divergence this crate cannot
    /// afford, so they are compared over every variant and in both JSON shapes.
    #[test]
    fn the_owned_decoder_agrees_with_the_borrowing_one() {
        for op in sample_of_every_variant() {
            let payload = serde_json::to_value(&op).expect("operation renders as JSON");
            let name = op.id().name();

            let condenser = serde_json::json!([name, payload]);
            let appbase = serde_json::json!({ "type": name, "value": payload });

            for (shape, value) in [("condenser", condenser), ("appbase", appbase)] {
                let borrowed = Operation::from_json(&value)
                    .unwrap_or_else(|e| panic!("{name} as {shape} failed to decode: {e}"));
                let owned = Operation::from_json_owned(value)
                    .unwrap_or_else(|e| panic!("{name} as {shape} failed to decode owned: {e}"));
                assert_eq!(borrowed, owned, "{name} decoded differently as {shape}");
                assert_eq!(borrowed, op, "{name} did not round-trip as {shape}");
            }
        }
    }

    /// And they must agree on what to *reject*, or the owned path is a hole.
    #[test]
    fn the_owned_decoder_rejects_what_the_borrowing_one_rejects() {
        let bad = [
            serde_json::json!([]),
            serde_json::json!(["vote"]),
            serde_json::json!(["vote", {}, "extra"]),
            // The input that distinguishes a length check from a "take the last two"
            // implementation: the trailing pair here IS a valid operation, so an owned
            // decoder that pops from the back without checking the length would accept
            // a three-element array that the borrowing one rejects. Found by mutating
            // `arr.len() == 2` to `>= 2` and noticing the corpus did not catch it.
            serde_json::json!([
                "ignored",
                "vote",
                { "voter": "alice", "author": "bob", "permlink": "p", "weight": 10000 }
            ]),
            serde_json::json!([
                { "voter": "alice", "author": "bob", "permlink": "p", "weight": 10000 },
                "vote"
            ]),
            serde_json::json!([1, {}]),
            serde_json::json!({ "type": 7, "value": {} }),
            serde_json::json!({ "type": "vote" }),
            serde_json::json!({ "value": {} }),
            serde_json::json!({}),
            serde_json::json!("vote"),
            serde_json::json!(42),
            serde_json::json!(null),
            // A real virtual operation: refused by both, not decoded as signable.
            serde_json::json!(["producer_reward", { "producer": "alice", "vesting_shares": "1.000000 VESTS" }]),
        ];
        for value in bad {
            let borrowed = Operation::from_json(&value);
            let owned = Operation::from_json_owned(value.clone());
            assert_eq!(
                borrowed.is_err(),
                owned.is_err(),
                "the two decoders disagree on whether to accept {value}"
            );
        }
    }

    fn sample_of_every_variant() -> Vec<Operation> {
        let key = crate::keys::PrivateKey::generate().public_key();
        let auth = Authority::from_key(key).unwrap();
        let t = PointInTime::from_unix(1_700_000_000).unwrap();
        let price = Price {
            base: hive("1.000 HIVE"),
            quote: hive("1.000 HBD"),
        };
        vec![
            Operation::AccountCreate(AccountCreate {
                fee: hive("3.000 HIVE"),
                creator: "a".into(),
                new_account_name: "b".into(),
                owner: auth.clone(),
                active: auth.clone(),
                posting: auth.clone(),
                memo_key: key,
                json_metadata: "{}".into(),
            }),
            Operation::AccountUpdate(AccountUpdate {
                account: "a".into(),
                owner: None,
                active: Some(auth.clone()),
                posting: None,
                memo_key: key,
                json_metadata: "{}".into(),
            }),
            Operation::WitnessUpdate(WitnessUpdate {
                owner: "a".into(),
                url: "https://example.org".into(),
                block_signing_key: key,
                props: ChainProperties {
                    account_creation_fee: hive("3.000 HIVE"),
                    maximum_block_size: 65536,
                    hbd_interest_rate: 1000,
                },
                fee: hive("0.000 HIVE"),
            }),
            Operation::WitnessBlockApprove(WitnessBlockApprove {
                witness: "a".into(),
                block_id: BlockId([7u8; 20]),
            }),
            Operation::RequestAccountRecovery(RequestAccountRecovery {
                recovery_account: "a".into(),
                account_to_recover: "b".into(),
                new_owner_authority: auth.clone(),
                extensions: NoExtensions,
            }),
            Operation::RecoverAccount(RecoverAccount {
                account_to_recover: "a".into(),
                new_owner_authority: auth.clone(),
                recent_owner_authority: auth.clone(),
                extensions: NoExtensions,
            }),
            Operation::EscrowTransfer(EscrowTransfer {
                from: "a".into(),
                to: "b".into(),
                agent: "c".into(),
                escrow_id: 1,
                hbd_amount: hive("1.000 HBD"),
                hive_amount: hive("1.000 HIVE"),
                fee: hive("0.100 HIVE"),
                ratification_deadline: t,
                escrow_expiration: t,
                json_meta: "{}".into(),
            }),
            Operation::EscrowDispute(EscrowDispute {
                from: "a".into(),
                to: "b".into(),
                agent: "c".into(),
                who: "a".into(),
                escrow_id: 1,
            }),
            Operation::EscrowRelease(EscrowRelease {
                from: "a".into(),
                to: "b".into(),
                agent: "c".into(),
                who: "a".into(),
                receiver: "b".into(),
                escrow_id: 1,
                hbd_amount: hive("1.000 HBD"),
                hive_amount: hive("1.000 HIVE"),
            }),
            Operation::EscrowApprove(EscrowApprove {
                from: "a".into(),
                to: "b".into(),
                agent: "c".into(),
                who: "c".into(),
                escrow_id: 1,
                approve: true,
            }),
            Operation::CustomBinary(CustomBinary {
                required_owner_auths: vec![],
                required_active_auths: vec!["a".into()],
                required_posting_auths: vec![],
                required_auths: vec![],
                id: "x".into(),
                data: HexBytes(vec![1, 2, 3]),
            }),
            Operation::ResetAccount(ResetAccount {
                reset_account: "a".into(),
                account_to_reset: "b".into(),
                new_owner_authority: auth.clone(),
            }),
            Operation::SetResetAccount(SetResetAccount {
                account: "a".into(),
                current_reset_account: "b".into(),
                reset_account: "c".into(),
            }),
            Operation::AccountCreateWithDelegation(AccountCreateWithDelegation {
                fee: hive("3.000 HIVE"),
                delegation: hive("0.000000 VESTS"),
                creator: "a".into(),
                new_account_name: "b".into(),
                owner: auth.clone(),
                active: auth.clone(),
                posting: auth.clone(),
                memo_key: key,
                json_metadata: "{}".into(),
                extensions: NoExtensions,
            }),
            Operation::WitnessSetProperties(WitnessSetProperties {
                owner: "a".into(),
                props: vec![
                    WitnessProperty::uint32("maximum_block_size", 65536),
                    WitnessProperty::asset("account_creation_fee", &hive("3.000 HIVE")).unwrap(),
                ],
                extensions: NoExtensions,
            }),
            Operation::Vote(Vote {
                voter: "a".into(),
                author: "b".into(),
                permlink: "c".into(),
                weight: 1,
            }),
            Operation::Comment(Comment {
                parent_author: String::new(),
                parent_permlink: "t".into(),
                author: "a".into(),
                permlink: "p".into(),
                title: "T".into(),
                body: "B".into(),
                json_metadata: "{}".into(),
            }),
            Operation::Transfer(Transfer {
                from: "a".into(),
                to: "b".into(),
                amount: hive("1.000 HIVE"),
                memo: String::new(),
            }),
            Operation::TransferToVesting(TransferToVesting {
                from: "a".into(),
                to: "b".into(),
                amount: hive("1.000 HIVE"),
            }),
            Operation::WithdrawVesting(WithdrawVesting {
                account: "a".into(),
                vesting_shares: hive("1.000000 VESTS"),
            }),
            Operation::LimitOrderCreate(LimitOrderCreate {
                owner: "a".into(),
                orderid: 1,
                amount_to_sell: hive("1.000 HIVE"),
                min_to_receive: hive("1.000 HBD"),
                fill_or_kill: false,
                expiration: t,
            }),
            Operation::LimitOrderCancel(LimitOrderCancel {
                owner: "a".into(),
                orderid: 1,
            }),
            Operation::FeedPublish(FeedPublish {
                publisher: "a".into(),
                exchange_rate: price.clone(),
            }),
            Operation::Convert(Convert {
                owner: "a".into(),
                requestid: 1,
                amount: hive("1.000 HBD"),
            }),
            Operation::AccountWitnessVote(AccountWitnessVote {
                account: "a".into(),
                witness: "w".into(),
                approve: true,
            }),
            Operation::AccountWitnessProxy(AccountWitnessProxy {
                account: "a".into(),
                proxy: "p".into(),
            }),
            Operation::Custom(Custom {
                required_auths: vec!["a".into()],
                id: 1,
                data: HexBytes(vec![1, 2, 3]),
            }),
            Operation::DeleteComment(DeleteComment {
                author: "a".into(),
                permlink: "p".into(),
            }),
            Operation::CustomJson(CustomJson {
                required_auths: vec![],
                required_posting_auths: vec!["a".into()],
                id: "x".into(),
                json: "{}".into(),
            }),
            Operation::CommentOptions(CommentOptions {
                author: "a".into(),
                permlink: "p".into(),
                max_accepted_payout: hive("1.000 HBD"),
                percent_hbd: 10_000,
                allow_votes: true,
                allow_curation_rewards: true,
                extensions: vec![],
            }),
            Operation::SetWithdrawVestingRoute(SetWithdrawVestingRoute {
                from_account: "a".into(),
                to_account: "b".into(),
                percent: 100,
                auto_vest: false,
            }),
            Operation::LimitOrderCreate2(LimitOrderCreate2 {
                owner: "a".into(),
                orderid: 1,
                amount_to_sell: hive("1.000 HIVE"),
                fill_or_kill: false,
                exchange_rate: price,
                expiration: t,
            }),
            Operation::ClaimAccount(ClaimAccount {
                creator: "a".into(),
                fee: hive("0.000 HIVE"),
                extensions: NoExtensions,
            }),
            Operation::CreateClaimedAccount(CreateClaimedAccount {
                creator: "a".into(),
                new_account_name: "b".into(),
                owner: auth.clone(),
                active: auth.clone(),
                posting: auth.clone(),
                memo_key: key,
                json_metadata: "{}".into(),
                extensions: NoExtensions,
            }),
            Operation::ChangeRecoveryAccount(ChangeRecoveryAccount {
                account_to_recover: "a".into(),
                new_recovery_account: "b".into(),
                extensions: NoExtensions,
            }),
            Operation::TransferToSavings(TransferToSavings {
                from: "a".into(),
                to: "b".into(),
                amount: hive("1.000 HIVE"),
                memo: String::new(),
            }),
            Operation::TransferFromSavings(TransferFromSavings {
                from: "a".into(),
                request_id: 1,
                to: "b".into(),
                amount: hive("1.000 HIVE"),
                memo: String::new(),
            }),
            Operation::CancelTransferFromSavings(CancelTransferFromSavings {
                from: "a".into(),
                request_id: 1,
            }),
            Operation::DeclineVotingRights(DeclineVotingRights {
                account: "a".into(),
                decline: true,
            }),
            Operation::ClaimRewardBalance(ClaimRewardBalance {
                account: "a".into(),
                reward_hive: hive("0.000 HIVE"),
                reward_hbd: hive("0.000 HBD"),
                reward_vests: hive("0.000000 VESTS"),
            }),
            Operation::DelegateVestingShares(DelegateVestingShares {
                delegator: "a".into(),
                delegatee: "b".into(),
                vesting_shares: hive("1.000000 VESTS"),
            }),
            Operation::AccountUpdate2(AccountUpdate2 {
                account: "a".into(),
                owner: None,
                active: None,
                posting: None,
                memo_key: None,
                json_metadata: "{}".into(),
                posting_json_metadata: "{}".into(),
                extensions: NoExtensions,
            }),
            Operation::CreateProposal(CreateProposal {
                creator: "a".into(),
                receiver: "b".into(),
                start_date: t,
                end_date: t,
                daily_pay: hive("1.000 HBD"),
                subject: "s".into(),
                permlink: "p".into(),
                extensions: NoExtensions,
            }),
            Operation::UpdateProposalVotes(UpdateProposalVotes {
                voter: "a".into(),
                proposal_ids: vec![1],
                approve: true,
                extensions: NoExtensions,
            }),
            Operation::RemoveProposal(RemoveProposal {
                proposal_owner: "a".into(),
                proposal_ids: vec![1],
                extensions: NoExtensions,
            }),
            Operation::UpdateProposal(UpdateProposal {
                proposal_id: 1,
                creator: "a".into(),
                daily_pay: hive("1.000 HBD"),
                subject: "s".into(),
                permlink: "p".into(),
                extensions: NoExtensions,
            }),
            Operation::CollateralizedConvert(CollateralizedConvert {
                owner: "a".into(),
                requestid: 1,
                amount: hive("1.000 HIVE"),
            }),
            Operation::RecurrentTransfer(RecurrentTransfer {
                from: "a".into(),
                to: "b".into(),
                amount: hive("1.000 HIVE"),
                memo: String::new(),
                recurrence: 24,
                executions: 2,
                extensions: vec![],
            }),
        ]
    }
}
