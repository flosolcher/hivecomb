//! Error type for `hivecomb`.
//!
//! # Security invariant
//!
//! **No variant of [`Error`] ever carries secret material.** WIF strings, raw private
//! scalars, seeds, shared secrets and cleartext memos must never reach an error value,
//! because errors are routinely logged, wrapped into Python tracebacks, and reported to
//! crash handlers. Where an error needs to describe *what* was wrong with a key, it
//! describes the shape (length, prefix, checksum) and never the content.
//!
//! This is deliberately stricter than beem, whose exceptions propagate the offending
//! value in several places.

use std::fmt;

/// The result type used throughout `hivecomb`.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A base58 string contained a character outside the Bitcoin alphabet, or decoded
    /// to an impossible length.
    ///
    /// beem's `base58decode` used `BASE58_ALPHABET.find(c)`, which returns `-1` for an
    /// unknown character and was fed straight into the accumulator — silently decoding
    /// invalid input to wrong bytes. We reject instead.
    #[error("invalid base58: {0}")]
    Base58(String),

    /// A base58check or Graphene-ripemd160 checksum did not match.
    #[error("checksum mismatch: {0}")]
    Checksum(&'static str),

    /// A key could not be parsed. Never contains the key itself.
    #[error("invalid key: {0}")]
    Key(String),

    /// A signature was malformed, non-canonical, or failed verification.
    #[error("invalid signature: {0}")]
    Signature(String),

    /// The value did not fit the Graphene wire encoding.
    #[error("serialization: {0}")]
    Serialization(String),

    /// An operation, asset or field was not recognised.
    #[error("unknown {kind}: {name}")]
    Unknown { kind: &'static str, name: String },

    /// A field required by the protocol was absent, or a field was present that this
    /// version does not know how to honour.
    ///
    /// Refusing unknown fields is deliberate: silently dropping a field the caller set
    /// would produce a transaction that does something other than what was asked.
    #[error("field error: {0}")]
    Field(String),

    /// A timestamp could not be parsed or was outside the representable range.
    #[error("invalid time: {0}")]
    Time(String),

    /// The cached block reference is older than the configured staleness bound.
    ///
    /// This is a hard refusal by design: signing against a stale TaPoS reference
    /// produces a transaction the relay accepts and the chain later rejects.
    #[error("TaPoS reference is stale: {0}")]
    StaleTapos(String),

    /// Memo encryption or decryption failed.
    #[error("memo: {0}")]
    Memo(String),

    /// A network or RPC level failure.
    #[error("rpc: {0}")]
    Rpc(String),

    /// The node answered with a JSON-RPC error object.
    #[error("rpc error {code}: {message}")]
    RpcResponse { code: i64, message: String },

    /// A chain id was requested that this build does not know, or a caller tried to
    /// sign against the pre-HF24 all-zero chain id.
    #[error("chain: {0}")]
    Chain(String),
}

impl Error {
    pub(crate) fn key(msg: impl fmt::Display) -> Self {
        Error::Key(msg.to_string())
    }
    pub(crate) fn sig(msg: impl fmt::Display) -> Self {
        Error::Signature(msg.to_string())
    }
    pub(crate) fn ser(msg: impl fmt::Display) -> Self {
        Error::Serialization(msg.to_string())
    }
    pub(crate) fn field(msg: impl fmt::Display) -> Self {
        Error::Field(msg.to_string())
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(e: bs58::decode::Error) -> Self {
        Error::Base58(e.to_string())
    }
}

impl From<secp256k1::Error> for Error {
    // secp256k1's Display never includes key bytes, so this is safe to forward.
    fn from(e: secp256k1::Error) -> Self {
        Error::Signature(e.to_string())
    }
}
