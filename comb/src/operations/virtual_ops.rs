//! Virtual operations.
//!
//! Virtual operations are emitted **by the chain**, never submitted. They record things
//! that happen as a consequence of consensus rather than of a signed request: a payout
//! landing, a conversion settling, a power-down instalment, a witness missing a block.
//! They appear in `account_history_api` and in block output, and they can never be
//! signed or broadcast — which is why they are a separate type here rather than
//! variants of [`Operation`](crate::operations::Operation).
//!
//! # beem models none of these
//!
//! beem has no class for any virtual operation. It hands back the raw dictionary from
//! the API and leaves every caller to reach into it by key, so a renamed or newly-added
//! field surfaces as a `KeyError` at the point of use rather than at the point of
//! decode. Roughly a third of the operations here — everything marked *Added in HF25*
//! or later — postdates beem's last release entirely.
//!
//! Its operation-id table is also wrong for all of them: because two non-virtual
//! operations are missing from it, **every virtual id beem reports is two lower than
//! the chain's** (see `SECURITY_FINDINGS.md` finding 2).

use crate::asset::Amount;
use crate::error::{Error, Result};
use crate::operations::OperationId;

/// `fill_convert_request_operation` (id 50).
///
/// An HBD to HIVE conversion completing after 3.5 days.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FillConvertRequest {
    pub owner: String,
    pub requestid: u32,
    pub amount_in: Amount,
    pub amount_out: Amount,
}
/// `author_reward_operation` (id 51).
///
/// An author's share of a post payout.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorReward {
    pub author: String,
    pub permlink: String,
    pub hbd_payout: Amount,
    pub hive_payout: Amount,
    pub vesting_payout: Amount,
    pub curators_vesting_payout: Amount,
    pub payout_must_be_claimed: bool,
}
/// `curation_reward_operation` (id 52).
///
/// A curator's share of a post payout.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CurationReward {
    pub curator: String,
    pub reward: Amount,
    pub author: String,
    pub permlink: String,
    pub payout_must_be_claimed: bool,
}
/// `comment_reward_operation` (id 53).
///
/// The totals for a post's payout.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommentReward {
    pub author: String,
    pub permlink: String,
    pub payout: Amount,
    pub author_rewards: i64,
    pub total_payout_value: Amount,
    pub curator_payout_value: Amount,
    pub beneficiary_payout_value: Amount,
}
/// `liquidity_reward_operation` (id 54).
///
/// The market-making reward. Discontinued.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LiquidityReward {
    pub owner: String,
    pub payout: Amount,
}
/// `interest_operation` (id 55).
///
/// HBD savings interest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Interest {
    pub owner: String,
    pub interest: Amount,
    pub is_saved_into_hbd_balance: bool,
}
/// `fill_vesting_withdraw_operation` (id 56).
///
/// One weekly instalment of a power-down.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FillVestingWithdraw {
    pub from_account: String,
    pub to_account: String,
    pub withdrawn: Amount,
    pub deposited: Amount,
}
/// `fill_order_operation` (id 57).
///
/// A market order matching.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FillOrder {
    pub current_owner: String,
    pub current_orderid: u32,
    pub current_pays: Amount,
    pub open_owner: String,
    pub open_orderid: u32,
    pub open_pays: Amount,
}
/// `shutdown_witness_operation` (id 58).
///
/// A witness disabled for missing too many blocks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShutdownWitness {
    pub owner: String,
}
/// `fill_transfer_from_savings_operation` (id 59).
///
/// A savings withdrawal completing after three days.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FillTransferFromSavings {
    pub from: String,
    pub to: String,
    pub amount: Amount,
    pub request_id: u32,
    pub memo: String,
}
/// `hardfork_operation` (id 60).
///
/// A hardfork activating.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Hardfork {
    pub hardfork_id: u32,
}
/// `comment_payout_update_operation` (id 61).
///
/// A post's payout being recalculated.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommentPayoutUpdate {
    pub author: String,
    pub permlink: String,
}
/// `return_vesting_delegation_operation` (id 62).
///
/// Delegated VESTS returning after the cooldown.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReturnVestingDelegation {
    pub account: String,
    pub vesting_shares: Amount,
}
/// `comment_benefactor_reward_operation` (id 63).
///
/// A beneficiary's share of a post payout.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommentBenefactorReward {
    pub benefactor: String,
    pub author: String,
    pub permlink: String,
    pub hbd_payout: Amount,
    pub hive_payout: Amount,
    pub vesting_payout: Amount,
    pub payout_must_be_claimed: bool,
}
/// `producer_reward_operation` (id 64).
///
/// A witness's reward for producing a block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProducerReward {
    pub producer: String,
    pub vesting_shares: Amount,
}
/// `clear_null_account_balance_operation` (id 65).
///
/// Funds sent to @null being burned.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClearNullAccountBalance {
    pub total_cleared: Vec<Amount>,
}
/// `proposal_pay_operation` (id 66).
///
/// An hourly DHF proposal payment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProposalPay {
    pub proposal_id: u32,
    pub receiver: String,
    pub payer: String,
    pub payment: Amount,
}
/// `dhf_funding_operation` (id 67).
///
/// The DHF receiving its share of inflation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DhfFunding {
    pub treasury: String,
    pub additional_funds: Amount,
}
/// `hardfork_hive_operation` (id 68).
///
/// An account's balance moved to the treasury at the Hive fork.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HardforkHive {
    pub account: String,
    pub treasury: String,
    pub other_affected_accounts: Vec<String>,
    pub hbd_transferred: Amount,
    pub hive_transferred: Amount,
    pub vests_converted: Amount,
    pub total_hive_from_vests: Amount,
}
/// `hardfork_hive_restore_operation` (id 69).
///
/// A balance restored after the Hive fork.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HardforkHiveRestore {
    pub account: String,
    pub treasury: String,
    pub hbd_transferred: Amount,
    pub hive_transferred: Amount,
}
/// `delayed_voting_operation` (id 70).
///
/// Newly powered-up VESTS becoming eligible to vote for witnesses.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DelayedVoting {
    pub voter: String,
    pub votes: u64,
}
/// `consolidate_treasury_balance_operation` (id 71).
///
/// Balances moved into the treasury account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsolidateTreasuryBalance {
    pub total_moved: Vec<Amount>,
}
/// `effective_comment_vote_operation` (id 72).
///
/// A vote's effect on a post, after all the curve maths.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EffectiveCommentVote {
    pub voter: String,
    pub author: String,
    pub permlink: String,
    pub weight: u64,
    pub rshares: i64,
    pub total_vote_weight: u64,
    pub pending_payout: Amount,
}
/// `ineffective_delete_comment_operation` (id 73).
///
/// A delete that could not take effect.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IneffectiveDeleteComment {
    pub author: String,
    pub permlink: String,
}
/// `dhf_conversion_operation` (id 74).
///
/// The DHF converting HIVE to HBD.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DhfConversion {
    pub treasury: String,
    pub hive_amount_in: Amount,
    pub hbd_amount_out: Amount,
}
/// `expired_account_notification_operation` (id 75).
///
/// A governance vote expiring after a year of inactivity. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExpiredAccountNotification {
    pub account: String,
}
/// `changed_recovery_account_operation` (id 76).
///
/// A recovery-account change taking effect after 30 days.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChangedRecoveryAccount {
    pub account: String,
    pub old_recovery_account: String,
    pub new_recovery_account: String,
}
/// `transfer_to_vesting_completed_operation` (id 77).
///
/// A power-up completing, naming the VESTS actually received.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransferToVestingCompleted {
    pub from_account: String,
    pub to_account: String,
    pub hive_vested: Amount,
    pub vesting_shares_received: Amount,
}
/// `pow_reward_operation` (id 78).
///
/// A mining reward. Obsolete since HF17.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PowReward {
    pub worker: String,
    pub reward: Amount,
}
/// `vesting_shares_split_operation` (id 79).
///
/// The one-off VESTS redenomination.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VestingSharesSplit {
    pub owner: String,
    pub vesting_shares_before_split: Amount,
    pub vesting_shares_after_split: Amount,
}
/// `account_created_operation` (id 80).
///
/// An account being created.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountCreated {
    pub new_account_name: String,
    pub creator: String,
    pub initial_vesting_shares: Amount,
    pub initial_delegation: Amount,
}
/// `fill_collateralized_convert_request_operation` (id 81).
///
/// A collateralized conversion settling. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FillCollateralizedConvertRequest {
    pub owner: String,
    pub requestid: u32,
    pub amount_in: Amount,
    pub amount_out: Amount,
    pub excess_collateral: Amount,
}
/// `system_warning_operation` (id 82).
///
/// A diagnostic emitted by the node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SystemWarning {
    pub message: String,
}
/// `fill_recurrent_transfer_operation` (id 83).
///
/// One instalment of a recurrent transfer. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FillRecurrentTransfer {
    pub from: String,
    pub to: String,
    pub amount: Amount,
    pub memo: String,
    pub remaining_executions: u16,
    /// HF28 `pair_id` extension, absent on older records.
    #[serde(default)]
    pub extensions: Vec<crate::operations::RecurrentTransferExtension>,
}
/// `failed_recurrent_transfer_operation` (id 84).
///
/// A recurrent transfer instalment that could not be paid. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FailedRecurrentTransfer {
    pub from: String,
    pub to: String,
    pub amount: Amount,
    pub memo: String,
    pub consecutive_failures: u8,
    pub remaining_executions: u16,
    pub deleted: bool,
    /// HF28 `pair_id` extension, absent on older records.
    #[serde(default)]
    pub extensions: Vec<crate::operations::RecurrentTransferExtension>,
}
/// `limit_order_cancelled_operation` (id 85).
///
/// An order cancelled or expired, naming what came back. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LimitOrderCancelled {
    pub seller: String,
    pub orderid: u32,
    pub amount_back: Amount,
}
/// `producer_missed_operation` (id 86).
///
/// A witness missing its block. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProducerMissed {
    pub producer: String,
}
/// `proposal_fee_operation` (id 87).
///
/// The fee charged for creating a DHF proposal. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProposalFee {
    pub creator: String,
    pub treasury: String,
    pub proposal_id: u32,
    pub fee: Amount,
}
/// `collateralized_convert_immediate_conversion_operation` (id 88).
///
/// The HBD paid out immediately by a collateralized conversion. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollateralizedConvertImmediateConversion {
    pub owner: String,
    pub requestid: u32,
    pub hbd_out: Amount,
}
/// `escrow_approved_operation` (id 89).
///
/// An escrow both parties approved. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EscrowApproved {
    pub from: String,
    pub to: String,
    pub agent: String,
    pub escrow_id: u32,
    pub fee: Amount,
}
/// `escrow_rejected_operation` (id 90).
///
/// An escrow that was not ratified in time. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EscrowRejected {
    pub from: String,
    pub to: String,
    pub agent: String,
    pub escrow_id: u32,
    pub hbd_amount: Amount,
    pub hive_amount: Amount,
    pub fee: Amount,
}
/// `proxy_cleared_operation` (id 91).
///
/// A witness proxy being cleared. Added in HF25.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProxyCleared {
    pub account: String,
    pub proxy: String,
}
/// `declined_voting_rights_operation` (id 92).
///
/// A decline_voting_rights request taking effect after 30 days. Added in HF26.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeclinedVotingRights {
    pub account: String,
}

/// An operation emitted by the chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum VirtualOperation {
    FillConvertRequest(FillConvertRequest),
    AuthorReward(AuthorReward),
    CurationReward(CurationReward),
    CommentReward(CommentReward),
    LiquidityReward(LiquidityReward),
    Interest(Interest),
    FillVestingWithdraw(FillVestingWithdraw),
    FillOrder(FillOrder),
    ShutdownWitness(ShutdownWitness),
    FillTransferFromSavings(FillTransferFromSavings),
    Hardfork(Hardfork),
    CommentPayoutUpdate(CommentPayoutUpdate),
    ReturnVestingDelegation(ReturnVestingDelegation),
    CommentBenefactorReward(CommentBenefactorReward),
    ProducerReward(ProducerReward),
    ClearNullAccountBalance(ClearNullAccountBalance),
    ProposalPay(ProposalPay),
    DhfFunding(DhfFunding),
    HardforkHive(HardforkHive),
    HardforkHiveRestore(HardforkHiveRestore),
    DelayedVoting(DelayedVoting),
    ConsolidateTreasuryBalance(ConsolidateTreasuryBalance),
    EffectiveCommentVote(EffectiveCommentVote),
    IneffectiveDeleteComment(IneffectiveDeleteComment),
    DhfConversion(DhfConversion),
    ExpiredAccountNotification(ExpiredAccountNotification),
    ChangedRecoveryAccount(ChangedRecoveryAccount),
    TransferToVestingCompleted(TransferToVestingCompleted),
    PowReward(PowReward),
    VestingSharesSplit(VestingSharesSplit),
    AccountCreated(AccountCreated),
    FillCollateralizedConvertRequest(FillCollateralizedConvertRequest),
    SystemWarning(SystemWarning),
    FillRecurrentTransfer(FillRecurrentTransfer),
    FailedRecurrentTransfer(FailedRecurrentTransfer),
    LimitOrderCancelled(LimitOrderCancelled),
    ProducerMissed(ProducerMissed),
    ProposalFee(ProposalFee),
    CollateralizedConvertImmediateConversion(CollateralizedConvertImmediateConversion),
    EscrowApproved(EscrowApproved),
    EscrowRejected(EscrowRejected),
    ProxyCleared(ProxyCleared),
    DeclinedVotingRights(DeclinedVotingRights),
}

impl VirtualOperation {
    /// The operation's id in hived's static variant.
    pub fn id(&self) -> OperationId {
        match self {
            VirtualOperation::FillConvertRequest(_) => OperationId::FillConvertRequest,
            VirtualOperation::AuthorReward(_) => OperationId::AuthorReward,
            VirtualOperation::CurationReward(_) => OperationId::CurationReward,
            VirtualOperation::CommentReward(_) => OperationId::CommentReward,
            VirtualOperation::LiquidityReward(_) => OperationId::LiquidityReward,
            VirtualOperation::Interest(_) => OperationId::Interest,
            VirtualOperation::FillVestingWithdraw(_) => OperationId::FillVestingWithdraw,
            VirtualOperation::FillOrder(_) => OperationId::FillOrder,
            VirtualOperation::ShutdownWitness(_) => OperationId::ShutdownWitness,
            VirtualOperation::FillTransferFromSavings(_) => OperationId::FillTransferFromSavings,
            VirtualOperation::Hardfork(_) => OperationId::Hardfork,
            VirtualOperation::CommentPayoutUpdate(_) => OperationId::CommentPayoutUpdate,
            VirtualOperation::ReturnVestingDelegation(_) => OperationId::ReturnVestingDelegation,
            VirtualOperation::CommentBenefactorReward(_) => OperationId::CommentBenefactorReward,
            VirtualOperation::ProducerReward(_) => OperationId::ProducerReward,
            VirtualOperation::ClearNullAccountBalance(_) => OperationId::ClearNullAccountBalance,
            VirtualOperation::ProposalPay(_) => OperationId::ProposalPay,
            VirtualOperation::DhfFunding(_) => OperationId::DhfFunding,
            VirtualOperation::HardforkHive(_) => OperationId::HardforkHive,
            VirtualOperation::HardforkHiveRestore(_) => OperationId::HardforkHiveRestore,
            VirtualOperation::DelayedVoting(_) => OperationId::DelayedVoting,
            VirtualOperation::ConsolidateTreasuryBalance(_) => {
                OperationId::ConsolidateTreasuryBalance
            }
            VirtualOperation::EffectiveCommentVote(_) => OperationId::EffectiveCommentVote,
            VirtualOperation::IneffectiveDeleteComment(_) => OperationId::IneffectiveDeleteComment,
            VirtualOperation::DhfConversion(_) => OperationId::DhfConversion,
            VirtualOperation::ExpiredAccountNotification(_) => {
                OperationId::ExpiredAccountNotification
            }
            VirtualOperation::ChangedRecoveryAccount(_) => OperationId::ChangedRecoveryAccount,
            VirtualOperation::TransferToVestingCompleted(_) => {
                OperationId::TransferToVestingCompleted
            }
            VirtualOperation::PowReward(_) => OperationId::PowReward,
            VirtualOperation::VestingSharesSplit(_) => OperationId::VestingSharesSplit,
            VirtualOperation::AccountCreated(_) => OperationId::AccountCreated,
            VirtualOperation::FillCollateralizedConvertRequest(_) => {
                OperationId::FillCollateralizedConvertRequest
            }
            VirtualOperation::SystemWarning(_) => OperationId::SystemWarning,
            VirtualOperation::FillRecurrentTransfer(_) => OperationId::FillRecurrentTransfer,
            VirtualOperation::FailedRecurrentTransfer(_) => OperationId::FailedRecurrentTransfer,
            VirtualOperation::LimitOrderCancelled(_) => OperationId::LimitOrderCancelled,
            VirtualOperation::ProducerMissed(_) => OperationId::ProducerMissed,
            VirtualOperation::ProposalFee(_) => OperationId::ProposalFee,
            VirtualOperation::CollateralizedConvertImmediateConversion(_) => {
                OperationId::CollateralizedConvertImmediateConversion
            }
            VirtualOperation::EscrowApproved(_) => OperationId::EscrowApproved,
            VirtualOperation::EscrowRejected(_) => OperationId::EscrowRejected,
            VirtualOperation::ProxyCleared(_) => OperationId::ProxyCleared,
            VirtualOperation::DeclinedVotingRights(_) => OperationId::DeclinedVotingRights,
        }
    }

    /// The hived name, without the `_operation` suffix.
    pub fn name(&self) -> &'static str {
        self.id().name()
    }

    /// Parse from either JSON shape the API uses.
    ///
    /// `condenser_api` sends `["producer_reward", {...}]`; appbase APIs send
    /// `{"type": "producer_reward_operation", "value": {...}}`. Both are accepted,
    /// and an unrecognised name is an error rather than a silently-dropped record.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        let (name, payload) = split_operation_json(value)?;
        Self::from_parts(&name, payload)
    }

    fn from_parts(name: &str, value: serde_json::Value) -> Result<Self> {
        let name = name.strip_suffix("_operation").unwrap_or(name);
        let de_err = |e: serde_json::Error| Error::ser(format!("could not decode {name}: {e}"));
        Ok(match name {
            "fill_convert_request" => {
                VirtualOperation::FillConvertRequest(serde_json::from_value(value).map_err(de_err)?)
            }
            "author_reward" => {
                VirtualOperation::AuthorReward(serde_json::from_value(value).map_err(de_err)?)
            }
            "curation_reward" => {
                VirtualOperation::CurationReward(serde_json::from_value(value).map_err(de_err)?)
            }
            "comment_reward" => {
                VirtualOperation::CommentReward(serde_json::from_value(value).map_err(de_err)?)
            }
            "liquidity_reward" => {
                VirtualOperation::LiquidityReward(serde_json::from_value(value).map_err(de_err)?)
            }
            "interest" => {
                VirtualOperation::Interest(serde_json::from_value(value).map_err(de_err)?)
            }
            "fill_vesting_withdraw" => VirtualOperation::FillVestingWithdraw(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "fill_order" => {
                VirtualOperation::FillOrder(serde_json::from_value(value).map_err(de_err)?)
            }
            "shutdown_witness" => {
                VirtualOperation::ShutdownWitness(serde_json::from_value(value).map_err(de_err)?)
            }
            "fill_transfer_from_savings" => VirtualOperation::FillTransferFromSavings(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "hardfork" => {
                VirtualOperation::Hardfork(serde_json::from_value(value).map_err(de_err)?)
            }
            "comment_payout_update" => VirtualOperation::CommentPayoutUpdate(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "return_vesting_delegation" => VirtualOperation::ReturnVestingDelegation(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "comment_benefactor_reward" => VirtualOperation::CommentBenefactorReward(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "producer_reward" => {
                VirtualOperation::ProducerReward(serde_json::from_value(value).map_err(de_err)?)
            }
            "clear_null_account_balance" => VirtualOperation::ClearNullAccountBalance(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "proposal_pay" => {
                VirtualOperation::ProposalPay(serde_json::from_value(value).map_err(de_err)?)
            }
            "dhf_funding" => {
                VirtualOperation::DhfFunding(serde_json::from_value(value).map_err(de_err)?)
            }
            "hardfork_hive" => {
                VirtualOperation::HardforkHive(serde_json::from_value(value).map_err(de_err)?)
            }
            "hardfork_hive_restore" => VirtualOperation::HardforkHiveRestore(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "delayed_voting" => {
                VirtualOperation::DelayedVoting(serde_json::from_value(value).map_err(de_err)?)
            }
            "consolidate_treasury_balance" => VirtualOperation::ConsolidateTreasuryBalance(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "effective_comment_vote" => VirtualOperation::EffectiveCommentVote(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "ineffective_delete_comment" => VirtualOperation::IneffectiveDeleteComment(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "dhf_conversion" => {
                VirtualOperation::DhfConversion(serde_json::from_value(value).map_err(de_err)?)
            }
            "expired_account_notification" => VirtualOperation::ExpiredAccountNotification(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "changed_recovery_account" => VirtualOperation::ChangedRecoveryAccount(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "transfer_to_vesting_completed" => VirtualOperation::TransferToVestingCompleted(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "pow_reward" => {
                VirtualOperation::PowReward(serde_json::from_value(value).map_err(de_err)?)
            }
            "vesting_shares_split" => {
                VirtualOperation::VestingSharesSplit(serde_json::from_value(value).map_err(de_err)?)
            }
            "account_created" => {
                VirtualOperation::AccountCreated(serde_json::from_value(value).map_err(de_err)?)
            }
            "fill_collateralized_convert_request" => {
                VirtualOperation::FillCollateralizedConvertRequest(
                    serde_json::from_value(value).map_err(de_err)?,
                )
            }
            "system_warning" => {
                VirtualOperation::SystemWarning(serde_json::from_value(value).map_err(de_err)?)
            }
            "fill_recurrent_transfer" => VirtualOperation::FillRecurrentTransfer(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "failed_recurrent_transfer" => VirtualOperation::FailedRecurrentTransfer(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "limit_order_cancelled" => VirtualOperation::LimitOrderCancelled(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            "producer_missed" => {
                VirtualOperation::ProducerMissed(serde_json::from_value(value).map_err(de_err)?)
            }
            "proposal_fee" => {
                VirtualOperation::ProposalFee(serde_json::from_value(value).map_err(de_err)?)
            }
            "collateralized_convert_immediate_conversion" => {
                VirtualOperation::CollateralizedConvertImmediateConversion(
                    serde_json::from_value(value).map_err(de_err)?,
                )
            }
            "escrow_approved" => {
                VirtualOperation::EscrowApproved(serde_json::from_value(value).map_err(de_err)?)
            }
            "escrow_rejected" => {
                VirtualOperation::EscrowRejected(serde_json::from_value(value).map_err(de_err)?)
            }
            "proxy_cleared" => {
                VirtualOperation::ProxyCleared(serde_json::from_value(value).map_err(de_err)?)
            }
            "declined_voting_rights" => VirtualOperation::DeclinedVotingRights(
                serde_json::from_value(value).map_err(de_err)?,
            ),
            other => {
                return Err(Error::Unknown {
                    kind: "virtual operation",
                    name: other.to_string(),
                })
            }
        })
    }
}

/// Split either JSON operation shape into a name and a payload.
///
/// Shared with [`crate::operations`], which parses the non-virtual half the same way.
pub(crate) fn split_operation_json(
    value: &serde_json::Value,
) -> Result<(String, serde_json::Value)> {
    // Appbase: {"type": "...", "value": {...}}
    if let Some(obj) = value.as_object() {
        if let (Some(t), Some(v)) = (obj.get("type"), obj.get("value")) {
            let name = t
                .as_str()
                .ok_or_else(|| Error::ser("operation \"type\" is not a string"))?;
            return Ok((name.to_string(), v.clone()));
        }
    }
    // Condenser: ["name", {...}]
    if let Some(arr) = value.as_array() {
        if arr.len() == 2 {
            let name = arr[0]
                .as_str()
                .ok_or_else(|| Error::ser("operation name is not a string"))?;
            return Ok((name.to_string(), arr[1].clone()));
        }
    }
    Err(Error::ser(
        "operation must be [name, value] or {type, value}".to_string(),
    ))
}
