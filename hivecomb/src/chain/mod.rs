//! Chain state: the objects a node returns.
//!
//! These are read-only views of chain state, parsed from the API rather than
//! constructed. They exist so that reading an account balance or a witness's
//! parameters is a typed operation rather than a series of dictionary lookups.
//!
//! # Why this is a type and not a dict
//!
//! beem returns `Account` objects that subclass `dict` and reach into the raw JSON by
//! key, converting on access. A field the node renamed, or one that a particular API
//! namespace does not return, surfaces as a `KeyError` at the point of use — often far
//! from the call that fetched it, and often only for some accounts.
//!
//! Here the shape is declared once. Fields Hive added after beem stopped
//! (`governance_vote_expiration_ts`, `open_recurrent_transfers`, `previous_owner_update`)
//! are present; fields that only some namespaces return are `Option`.
//!
//! # Unknown fields are kept, not dropped
//!
//! Every type here carries an `extra` map holding anything the node sent that this
//! build does not model. A hardfork that adds a field therefore does not silently lose
//! it, and [`Account::extra`] is where to look for something new before this crate has
//! caught up.

mod account;
mod block;
mod manabar;
mod witness;

pub use account::{Account, DelayedVote, RcAccount, RcManabar};
pub use block::{Block, BlockHeader, DynamicGlobalProperties, FeedHistory, RewardFund};
pub use manabar::{Manabar, REGENERATION_SECONDS};
pub use witness::{PriceFeed, Witness, WitnessSchedule};
