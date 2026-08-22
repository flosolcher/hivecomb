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

pub use ids::{OperationId, FIRST_VIRTUAL_OP, LAST_OP};

use crate::asset::Amount;
use crate::authority::Authority;
use crate::error::{Error, Result};
use crate::keys::PublicKey;
use crate::types::{
    write_array, write_bool, write_i16, write_optional, write_string, write_u16, write_u32,
    write_u64, write_varint32, GrapheneSerialize, PointInTime,
};

/// Maximum length of a `custom_json` id, from hived's `custom_id_type`.
pub const MAX_CUSTOM_ID_LEN: usize = 32;

/// A price, as used by `feed_publish` and `limit_order_create2`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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

/// A `recurrent_transfer` extension. Tag 1 carries the HF28 `pair_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecurrentTransferExtension {
    /// `recurrent_transfer_pair_id`, added in HF28 so an account can run several
    /// concurrent recurrent transfers to the same recipient. beem predates this
    /// entirely.
    PairId(u16),
}

impl GrapheneSerialize for RecurrentTransferExtension {
    fn append_to(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            RecurrentTransferExtension::PairId(id) => {
                write_varint32(out, 1);
                write_u16(out, *id);
                Ok(())
            }
        }
    }
}

/// Renders as `[1, {"pair_id": n}]`.
impl serde::Serialize for RecurrentTransferExtension {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        match self {
            RecurrentTransferExtension::PairId(id) => {
                let mut t = s.serialize_tuple(2)?;
                t.serialize_element(&1u8)?;
                t.serialize_element(&serde_json::json!({ "pair_id": id }))?;
                t.end()
            }
        }
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
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
        data: Vec<u8>,
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
    LimitOrderCreate2 {
        owner: String,
        orderid: u32,
        amount_to_sell: Amount,
        fill_or_kill: bool,
        exchange_rate: Price,
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

impl serde::Serialize for BlockId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

/// `legacy_chain_properties` — the witness-voted chain parameters carried by
/// `witness_update` and `pow`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
    EscrowTransfer {
        from: String,
        to: String,
        agent: String,
        escrow_id: u32,
        hbd_amount: Amount,
        hive_amount: Amount,
        fee: Amount,
        ratification_deadline: PointInTime,
        escrow_expiration: PointInTime,
        json_meta: String,
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
    /// **beem serializes two of these six fields** (`id` and `data`) and types `id` as
    /// a `Uint16`, where hived uses a `custom_id_type` string. Its output cannot be
    /// deserialized as this operation at all.
    CustomBinary {
        required_owner_auths: Vec<String>,
        required_active_auths: Vec<String>,
        required_posting_auths: Vec<String>,
        required_auths: Vec<Authority>,
        id: String,
        data: Vec<u8>,
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

impl Operation {
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
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                write_string(out, &o.agent)?;
                write_u32(out, o.escrow_id);
                o.hbd_amount.append_to(out)?;
                o.hive_amount.append_to(out)?;
                o.fee.append_to(out)?;
                o.ratification_deadline.append_to(out)?;
                o.escrow_expiration.append_to(out)?;
                write_string(out, &o.json_meta)?;
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
                crate::types::write_bytes(out, &o.data)?;
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
                write_sorted_account_set(out, &o.required_auths, "required_auths")?;
                write_u16(out, o.id);
                crate::types::write_bytes(out, &o.data)?;
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
                write_string(out, &o.owner)?;
                write_u32(out, o.orderid);
                o.amount_to_sell.append_to(out)?;
                write_bool(out, o.fill_or_kill);
                o.exchange_rate.append_to(out)?;
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
                write_string(out, &o.from)?;
                write_string(out, &o.to)?;
                o.amount.append_to(out)?;
                write_string(out, &o.memo)?;
            }
            Operation::TransferFromSavings(o) => {
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
            id: "sm_team_reveal".into(),
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
        // one extension, variant tag 1, then the u16 pair id
        assert_eq!(&wire[wire.len() - 4..], &[1, 1, 7, 0]);
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

    #[test]
    fn custom_binary_has_all_six_fields() {
        // beem serializes only `id` and `data`, and types `id` as a Uint16.
        let op = Operation::CustomBinary(CustomBinary {
            required_owner_auths: vec![],
            required_active_auths: vec!["alice".into()],
            required_posting_auths: vec![],
            required_auths: vec![],
            id: "app".into(),
            data: vec![0xde, 0xad],
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

    /// One value of every `Operation` variant, so the tests above cover all of them.
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
                data: vec![1, 2, 3],
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
                data: vec![1, 2, 3],
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
