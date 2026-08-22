//! The Hive operation table.
//!
//! These ids are the tags of hived's `operation` static variant, defined in
//! `libraries/protocol/include/hive/protocol/operations.hpp`. The variant is
//! **append-only**: inserting an operation in the middle renumbers every operation
//! after it, so the order below is a consensus rule, not a convention.
//!
//! # What beem got wrong here
//!
//! beem's `beembase/operationids.py` shipped two lists and used the wrong one.
//!
//! **The active list is pre-HF25.** It contains neither `collateralized_convert` (48)
//! nor `recurrent_transfer` (49), so beem cannot construct either operation at all —
//! `Operation.__init__` raises `ValueError("Unknown operation")`. Worse, because those
//! two non-virtual operations are missing, **every virtual operation id in beem is two
//! lower than on chain**: `fill_convert_request` is 50 here and 48 there,
//! `producer_reward` is 64 here and 62 there. Any code that maps an id back to a name,
//! or builds an operation-id bitmask for `account_history_api`, reads the wrong
//! operations.
//!
//! **The HF25 list is worse.** It is guarded by a comment inviting you to enable it —
//! `# uncoment when using with HF25` — and it contains a missing comma:
//!
//! ```python
//! 'convert',
//! 'collateralized_convert'      # <- no comma
//! 'account_create',
//! ```
//!
//! Python concatenates adjacent string literals, so that is the single element
//! `'collateralized_convertaccount_create'`. The list loses two names, gains one
//! nonsense name, and **shifts every id from index 10 onward by one**. It also inserts
//! the two new operations in the middle rather than appending them, which renumbers
//! everything after — the opposite of what hived did.
//!
//! Following beem's own instruction therefore makes every transaction serialize under
//! the wrong operation id. The signature is well formed; it just authorises something
//! other than what was asked, and the chain rejects it.

use crate::error::{Error, Result};

/// A Hive operation id — the tag of hived's `operation` static variant.
///
/// Ids 0–49 are operations a client can construct and broadcast. Ids 50–92 are
/// **virtual** operations: the chain emits them, they appear in account history, and
/// they can never be signed or broadcast. [`OperationId::is_virtual`] separates them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum OperationId {
    // --- Non-virtual operations -------------------------------------------------
    Vote = 0,
    Comment = 1,
    Transfer = 2,
    TransferToVesting = 3,
    WithdrawVesting = 4,
    LimitOrderCreate = 5,
    LimitOrderCancel = 6,
    FeedPublish = 7,
    Convert = 8,
    AccountCreate = 9,
    AccountUpdate = 10,
    WitnessUpdate = 11,
    AccountWitnessVote = 12,
    AccountWitnessProxy = 13,
    Pow = 14,
    Custom = 15,
    WitnessBlockApprove = 16,
    DeleteComment = 17,
    CustomJson = 18,
    CommentOptions = 19,
    SetWithdrawVestingRoute = 20,
    LimitOrderCreate2 = 21,
    ClaimAccount = 22,
    CreateClaimedAccount = 23,
    RequestAccountRecovery = 24,
    RecoverAccount = 25,
    ChangeRecoveryAccount = 26,
    EscrowTransfer = 27,
    EscrowDispute = 28,
    EscrowRelease = 29,
    Pow2 = 30,
    EscrowApprove = 31,
    TransferToSavings = 32,
    TransferFromSavings = 33,
    CancelTransferFromSavings = 34,
    CustomBinary = 35,
    DeclineVotingRights = 36,
    ResetAccount = 37,
    SetResetAccount = 38,
    ClaimRewardBalance = 39,
    DelegateVestingShares = 40,
    AccountCreateWithDelegation = 41,
    WitnessSetProperties = 42,
    AccountUpdate2 = 43,
    CreateProposal = 44,
    UpdateProposalVotes = 45,
    RemoveProposal = 46,
    UpdateProposal = 47,
    /// Added in HF25. beem cannot construct this operation.
    CollateralizedConvert = 48,
    /// Added in HF25, extended with `extensions` in HF28. beem cannot construct this
    /// operation, and its unreachable `Recurring_transfer` class also misspells the
    /// name, omits `extensions`, and types `recurrence`/`executions` as signed.
    RecurrentTransfer = 49,

    // --- Virtual operations -----------------------------------------------------
    FillConvertRequest = 50,
    AuthorReward = 51,
    CurationReward = 52,
    CommentReward = 53,
    LiquidityReward = 54,
    Interest = 55,
    FillVestingWithdraw = 56,
    FillOrder = 57,
    ShutdownWitness = 58,
    FillTransferFromSavings = 59,
    Hardfork = 60,
    CommentPayoutUpdate = 61,
    ReturnVestingDelegation = 62,
    CommentBenefactorReward = 63,
    ProducerReward = 64,
    ClearNullAccountBalance = 65,
    ProposalPay = 66,
    DhfFunding = 67,
    HardforkHive = 68,
    HardforkHiveRestore = 69,
    DelayedVoting = 70,
    ConsolidateTreasuryBalance = 71,
    EffectiveCommentVote = 72,
    IneffectiveDeleteComment = 73,
    DhfConversion = 74,
    ExpiredAccountNotification = 75,
    ChangedRecoveryAccount = 76,
    TransferToVestingCompleted = 77,
    PowReward = 78,
    VestingSharesSplit = 79,
    AccountCreated = 80,
    FillCollateralizedConvertRequest = 81,
    SystemWarning = 82,
    FillRecurrentTransfer = 83,
    FailedRecurrentTransfer = 84,
    LimitOrderCancelled = 85,
    ProducerMissed = 86,
    ProposalFee = 87,
    CollateralizedConvertImmediateConversion = 88,
    EscrowApproved = 89,
    EscrowRejected = 90,
    ProxyCleared = 91,
    DeclinedVotingRights = 92,
}

/// The lowest virtual operation id. Everything below this can be broadcast.
pub const FIRST_VIRTUAL_OP: u32 = 50;

/// The highest operation id this build knows.
pub const LAST_OP: u32 = 92;

impl OperationId {
    /// The numeric tag written on the wire.
    pub fn as_u32(&self) -> u32 {
        *self as u32
    }

    /// Whether the chain emits this operation rather than accepting it.
    ///
    /// A virtual operation can never be signed or broadcast.
    pub fn is_virtual(&self) -> bool {
        self.as_u32() >= FIRST_VIRTUAL_OP
    }

    /// The hived name, without the `_operation` suffix.
    pub fn name(&self) -> &'static str {
        NAMES[self.as_u32() as usize].0
    }

    /// Resolve a numeric id.
    pub fn from_u32(id: u32) -> Result<Self> {
        if id > LAST_OP {
            return Err(Error::Unknown {
                kind: "operation id",
                name: id.to_string(),
            });
        }
        Ok(NAMES[id as usize].1)
    }

    /// Resolve a name, with or without the `_operation` suffix.
    ///
    /// beem's spelling `recurring_transfer` is accepted as an alias for
    /// `recurrent_transfer` so that callers migrating from beem are not silently
    /// broken — but the hived spelling is what goes on the wire.
    pub fn from_name(name: &str) -> Result<Self> {
        let name = name.strip_suffix("_operation").unwrap_or(name);
        if name == "recurring_transfer" {
            return Ok(OperationId::RecurrentTransfer);
        }
        NAMES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, id)| *id)
            .ok_or_else(|| Error::Unknown {
                kind: "operation",
                name: name.to_string(),
            })
    }
}

/// Name/id pairs, indexed by id. The index *is* the id — see the test below.
static NAMES: [(&str, OperationId); 93] = [
    ("vote", OperationId::Vote),
    ("comment", OperationId::Comment),
    ("transfer", OperationId::Transfer),
    ("transfer_to_vesting", OperationId::TransferToVesting),
    ("withdraw_vesting", OperationId::WithdrawVesting),
    ("limit_order_create", OperationId::LimitOrderCreate),
    ("limit_order_cancel", OperationId::LimitOrderCancel),
    ("feed_publish", OperationId::FeedPublish),
    ("convert", OperationId::Convert),
    ("account_create", OperationId::AccountCreate),
    ("account_update", OperationId::AccountUpdate),
    ("witness_update", OperationId::WitnessUpdate),
    ("account_witness_vote", OperationId::AccountWitnessVote),
    ("account_witness_proxy", OperationId::AccountWitnessProxy),
    ("pow", OperationId::Pow),
    ("custom", OperationId::Custom),
    ("witness_block_approve", OperationId::WitnessBlockApprove),
    ("delete_comment", OperationId::DeleteComment),
    ("custom_json", OperationId::CustomJson),
    ("comment_options", OperationId::CommentOptions),
    (
        "set_withdraw_vesting_route",
        OperationId::SetWithdrawVestingRoute,
    ),
    ("limit_order_create2", OperationId::LimitOrderCreate2),
    ("claim_account", OperationId::ClaimAccount),
    ("create_claimed_account", OperationId::CreateClaimedAccount),
    (
        "request_account_recovery",
        OperationId::RequestAccountRecovery,
    ),
    ("recover_account", OperationId::RecoverAccount),
    (
        "change_recovery_account",
        OperationId::ChangeRecoveryAccount,
    ),
    ("escrow_transfer", OperationId::EscrowTransfer),
    ("escrow_dispute", OperationId::EscrowDispute),
    ("escrow_release", OperationId::EscrowRelease),
    ("pow2", OperationId::Pow2),
    ("escrow_approve", OperationId::EscrowApprove),
    ("transfer_to_savings", OperationId::TransferToSavings),
    ("transfer_from_savings", OperationId::TransferFromSavings),
    (
        "cancel_transfer_from_savings",
        OperationId::CancelTransferFromSavings,
    ),
    ("custom_binary", OperationId::CustomBinary),
    ("decline_voting_rights", OperationId::DeclineVotingRights),
    ("reset_account", OperationId::ResetAccount),
    ("set_reset_account", OperationId::SetResetAccount),
    ("claim_reward_balance", OperationId::ClaimRewardBalance),
    (
        "delegate_vesting_shares",
        OperationId::DelegateVestingShares,
    ),
    (
        "account_create_with_delegation",
        OperationId::AccountCreateWithDelegation,
    ),
    ("witness_set_properties", OperationId::WitnessSetProperties),
    ("account_update2", OperationId::AccountUpdate2),
    ("create_proposal", OperationId::CreateProposal),
    ("update_proposal_votes", OperationId::UpdateProposalVotes),
    ("remove_proposal", OperationId::RemoveProposal),
    ("update_proposal", OperationId::UpdateProposal),
    ("collateralized_convert", OperationId::CollateralizedConvert),
    ("recurrent_transfer", OperationId::RecurrentTransfer),
    ("fill_convert_request", OperationId::FillConvertRequest),
    ("author_reward", OperationId::AuthorReward),
    ("curation_reward", OperationId::CurationReward),
    ("comment_reward", OperationId::CommentReward),
    ("liquidity_reward", OperationId::LiquidityReward),
    ("interest", OperationId::Interest),
    ("fill_vesting_withdraw", OperationId::FillVestingWithdraw),
    ("fill_order", OperationId::FillOrder),
    ("shutdown_witness", OperationId::ShutdownWitness),
    (
        "fill_transfer_from_savings",
        OperationId::FillTransferFromSavings,
    ),
    ("hardfork", OperationId::Hardfork),
    ("comment_payout_update", OperationId::CommentPayoutUpdate),
    (
        "return_vesting_delegation",
        OperationId::ReturnVestingDelegation,
    ),
    (
        "comment_benefactor_reward",
        OperationId::CommentBenefactorReward,
    ),
    ("producer_reward", OperationId::ProducerReward),
    (
        "clear_null_account_balance",
        OperationId::ClearNullAccountBalance,
    ),
    ("proposal_pay", OperationId::ProposalPay),
    ("dhf_funding", OperationId::DhfFunding),
    ("hardfork_hive", OperationId::HardforkHive),
    ("hardfork_hive_restore", OperationId::HardforkHiveRestore),
    ("delayed_voting", OperationId::DelayedVoting),
    (
        "consolidate_treasury_balance",
        OperationId::ConsolidateTreasuryBalance,
    ),
    ("effective_comment_vote", OperationId::EffectiveCommentVote),
    (
        "ineffective_delete_comment",
        OperationId::IneffectiveDeleteComment,
    ),
    ("dhf_conversion", OperationId::DhfConversion),
    (
        "expired_account_notification",
        OperationId::ExpiredAccountNotification,
    ),
    (
        "changed_recovery_account",
        OperationId::ChangedRecoveryAccount,
    ),
    (
        "transfer_to_vesting_completed",
        OperationId::TransferToVestingCompleted,
    ),
    ("pow_reward", OperationId::PowReward),
    ("vesting_shares_split", OperationId::VestingSharesSplit),
    ("account_created", OperationId::AccountCreated),
    (
        "fill_collateralized_convert_request",
        OperationId::FillCollateralizedConvertRequest,
    ),
    ("system_warning", OperationId::SystemWarning),
    (
        "fill_recurrent_transfer",
        OperationId::FillRecurrentTransfer,
    ),
    (
        "failed_recurrent_transfer",
        OperationId::FailedRecurrentTransfer,
    ),
    ("limit_order_cancelled", OperationId::LimitOrderCancelled),
    ("producer_missed", OperationId::ProducerMissed),
    ("proposal_fee", OperationId::ProposalFee),
    (
        "collateralized_convert_immediate_conversion",
        OperationId::CollateralizedConvertImmediateConversion,
    ),
    ("escrow_approved", OperationId::EscrowApproved),
    ("escrow_rejected", OperationId::EscrowRejected),
    ("proxy_cleared", OperationId::ProxyCleared),
    ("declined_voting_rights", OperationId::DeclinedVotingRights),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_index_is_the_operation_id() {
        // This is the invariant beem's list violated. If anyone inserts an operation
        // in the middle of NAMES rather than appending, this fails immediately.
        for (index, (name, id)) in NAMES.iter().enumerate() {
            assert_eq!(
                id.as_u32(),
                index as u32,
                "{name} is at index {index} but has id {}",
                id.as_u32()
            );
        }
        assert_eq!(NAMES.len() as u32, LAST_OP + 1);
    }

    #[test]
    fn names_are_unique() {
        let mut seen: Vec<&str> = NAMES.iter().map(|(n, _)| *n).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before, "duplicate operation name in the table");
    }

    #[test]
    fn the_post_hf25_operations_exist() {
        // beem's active table has neither, so it cannot build them at all.
        assert_eq!(
            OperationId::from_name("collateralized_convert")
                .unwrap()
                .as_u32(),
            48
        );
        assert_eq!(
            OperationId::from_name("recurrent_transfer")
                .unwrap()
                .as_u32(),
            49
        );
    }

    #[test]
    fn beems_misspelling_is_accepted_as_an_alias() {
        assert_eq!(
            OperationId::from_name("recurring_transfer").unwrap(),
            OperationId::RecurrentTransfer
        );
        // ...but the wire name is hived's.
        assert_eq!(OperationId::RecurrentTransfer.name(), "recurrent_transfer");
    }

    #[test]
    fn virtual_operations_start_at_fifty() {
        // In beem every one of these is two lower, because two non-virtual operations
        // are missing from its table.
        assert_eq!(OperationId::FillConvertRequest.as_u32(), 50);
        assert_eq!(OperationId::ProducerReward.as_u32(), 64);
        assert!(OperationId::FillConvertRequest.is_virtual());
        assert!(!OperationId::RecurrentTransfer.is_virtual());
        assert!(!OperationId::CollateralizedConvert.is_virtual());
    }

    #[test]
    fn round_trips_by_id_and_name() {
        for id in 0..=LAST_OP {
            let op = OperationId::from_u32(id).unwrap();
            assert_eq!(op.as_u32(), id);
            assert_eq!(OperationId::from_name(op.name()).unwrap(), op);
            let suffixed = format!("{}_operation", op.name());
            assert_eq!(OperationId::from_name(&suffixed).unwrap(), op);
        }
    }

    #[test]
    fn unknown_ids_and_names_are_errors() {
        assert!(OperationId::from_u32(93).is_err());
        assert!(OperationId::from_u32(u32::MAX).is_err());
        assert!(OperationId::from_name("not_an_operation").is_err());
        // The exact string beem's missing comma produces.
        assert!(OperationId::from_name("collateralized_convertaccount_create").is_err());
    }
}
