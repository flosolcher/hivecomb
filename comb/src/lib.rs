//! # comb
//!
//! A Rust library for the [Hive](https://hive.io) blockchain: key handling, Graphene
//! binary serialization, transaction construction, signing and RPC.
//!
//! `comb` is a from-scratch reimplementation, in Rust, of the Python library
//! [`beem`](https://github.com/holgern/beem) by Holger Nahrstaedt, which in turn
//! descends from `python-bitshares` and `python-graphenelib` by Fabian Schuh. See
//! `CREDITS.md` for the full lineage — the design, the wire format and the great
//! majority of the domain knowledge encoded here are theirs.
//!
//! The port exists because `beem` stopped being maintained at version 0.24.26 (its
//! classifiers stop at Python 3.9), because several defects in it are security- rather
//! than convenience-relevant, and because Hive has added operations since that beem
//! cannot serialize at all. Every such defect is documented at the point in the code
//! that fixes it, and collected in `SECURITY_FINDINGS.md`.
//!
//! ## Design rules
//!
//! * **No silent fallbacks.** Where beem swallowed an error and continued with a
//!   default — a chain id, an ECDSA backend, a base58 character — `comb` returns an
//!   error. A silent fallback in a signing path produces a valid-looking signature
//!   over the wrong bytes, which is the worst possible failure mode.
//! * **Signing never needs the network.** The chain id is a compile-time constant and
//!   the block reference is cached with an explicit staleness bound, so producing a
//!   signature is a pure CPU operation.
//! * **Secrets do not render, and do not linger.** See [`keys`].
//! * **Unknown input is refused, never defaulted.**

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod asset;
pub mod authority;
pub mod base58;
#[cfg(feature = "bip32")]
pub mod bip32;
#[cfg(feature = "bip38")]
pub mod bip38;
#[cfg(feature = "bip32")]
pub mod bip39;
pub mod chain;
pub mod chains;
pub mod error;
pub mod keys;
#[cfg(feature = "memo")]
pub mod memo;
pub mod operations;
pub mod reader;
#[cfg(feature = "rpc")]
pub mod rpc;
pub mod sign;
pub mod tapos;
pub mod transaction;
pub mod types;

pub use asset::Amount;
pub use authority::Authority;
pub use chains::{Chain, ChainId};
pub use error::{Error, Result};
pub use keys::{PrivateKey, PublicKey};
pub use operations::{AnyOperation, Operation, OperationId, VirtualOperation};
pub use reader::{GrapheneDeserialize, Reader};
pub use sign::Signature;
pub use tapos::TaposCache;
pub use transaction::{BlockRef, SignedTransaction, Transaction};
pub use types::GrapheneSerialize;
