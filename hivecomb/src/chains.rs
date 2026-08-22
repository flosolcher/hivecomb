//! Chain parameters: chain ids, address prefixes and native assets.
//!
//! # The bug this module exists to close
//!
//! beem shipped a `known_chains` table in which the entry literally named `"HIVE"`
//! carried the **pre-HF24 all-zero chain id**, while the live one lived under
//! `"HIVE2"`. Two places in `beem/blockchaininstance.py` fell back to
//! `known_chains["HIVE"]` when the node lookup failed, and the first of them did so
//! inside a bare `except:`:
//!
//! ```python
//! try:
//!     return self.rpc.get_network(props=config)
//! except:
//!     return known_chains["HIVE"]
//! ```
//!
//! A signature computed over the wrong chain id is simply invalid, so a node error at
//! that exact point produced **a silently unusable signature** rather than a failure.
//! It looked like a relay rejection, not a signing bug.
//!
//! `hivecomb` removes the failure mode rather than handling it:
//!
//! * The live Hive chain id is a compile-time constant. Signing never needs the
//!   network to learn it — this is the single largest reason the whole signing path
//!   can be made offline.
//! * The all-zero id is retained only as [`Chain::SteemLegacy`], is documented as
//!   pre-HF24, and [`ChainId::is_all_zero`] lets callers refuse it explicitly.
//! * There is no fallback. An unknown chain is an error.
//!
//! # Hardfork note
//!
//! The chain id is exactly the kind of constant that moves at a hardfork. It lives
//! here, in one named place. If Hive ever forks the chain id, [`HIVE_CHAIN_ID`] is the
//! only line that changes.

use crate::error::{Error, Result};

/// Length of a chain id in bytes.
pub const CHAIN_ID_LEN: usize = 32;

/// The live Hive chain id, in effect since hardfork 24 (2020).
pub const HIVE_CHAIN_ID: ChainId = ChainId([
    0xbe, 0xea, 0xb0, 0xde, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
]);

/// The all-zero chain id used by Steem and by Hive before hardfork 24.
///
/// Present for completeness and for reading historical blocks. Signing a Hive
/// transaction with this id yields a signature the chain rejects.
pub const ZERO_CHAIN_ID: ChainId = ChainId([0u8; CHAIN_ID_LEN]);

/// A 32-byte chain id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainId(pub [u8; CHAIN_ID_LEN]);

impl ChainId {
    /// Parse a 64-character hex chain id.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != CHAIN_ID_LEN * 2 {
            return Err(Error::Chain(format!(
                "chain id must be {} hex characters, got {}",
                CHAIN_ID_LEN * 2,
                s.len()
            )));
        }
        let mut out = [0u8; CHAIN_ID_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::Chain("chain id is not valid hex".into()))?;
        }
        Ok(ChainId(out))
    }

    /// Render as lowercase hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Raw bytes, as prefixed to the transaction before hashing.
    pub fn as_bytes(&self) -> &[u8; CHAIN_ID_LEN] {
        &self.0
    }

    /// Whether this is the all-zero (pre-HF24 / Steem) chain id.
    ///
    /// Callers that must never sign against it — which on Hive is all of them —
    /// should check this before signing. beem's silent fallback is exactly what this
    /// predicate is here to make impossible to reproduce by accident.
    pub fn is_all_zero(&self) -> bool {
        self.0 == [0u8; CHAIN_ID_LEN]
    }
}

/// A native asset of a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAsset {
    /// NAI identifier, e.g. `@@000000021`.
    pub nai: &'static str,
    /// Ticker used on the wire, e.g. `HIVE`.
    pub symbol: &'static str,
    /// Legacy ticker this asset serializes as in the pre-HF24 binary format.
    ///
    /// Hive kept Steem's binary symbols after the rename: `HIVE` still goes on the
    /// wire as `STEEM` and `HBD` as `SBD` in the legacy asset encoding.
    pub wire_symbol: &'static str,
    /// Number of decimal places.
    pub precision: u8,
}

/// A supported chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[derive(Default)]
pub enum Chain {
    /// Hive, post-HF24. This is the default and the only one Hive callers want.
    #[default]
    Hive,
    /// The Hive testnet.
    HiveTestnet,
    /// Steem / pre-HF24 Hive, with the all-zero chain id.
    SteemLegacy,
}

/// Everything needed to build and sign a transaction for a chain.
#[derive(Debug, Clone)]
pub struct ChainProperties {
    /// Prefixed to the transaction bytes before hashing, so a signature is valid on
    /// exactly one chain.
    pub chain_id: ChainId,
    /// Address prefix for public keys, e.g. `STM`.
    pub prefix: &'static str,
    /// The assets this chain accepts, with the symbol written on the wire — which is
    /// not always the symbol users type. See [`ChainAsset`].
    pub assets: &'static [ChainAsset],
}

const HIVE_ASSETS: &[ChainAsset] = &[
    ChainAsset {
        nai: "@@000000013",
        symbol: "HBD",
        wire_symbol: "SBD",
        precision: 3,
    },
    ChainAsset {
        nai: "@@000000021",
        symbol: "HIVE",
        wire_symbol: "STEEM",
        precision: 3,
    },
    ChainAsset {
        nai: "@@000000037",
        symbol: "VESTS",
        wire_symbol: "VESTS",
        precision: 6,
    },
];

const TESTNET_ASSETS: &[ChainAsset] = &[
    ChainAsset {
        nai: "@@000000013",
        symbol: "TBD",
        wire_symbol: "TBD",
        precision: 3,
    },
    ChainAsset {
        nai: "@@000000021",
        symbol: "TESTS",
        wire_symbol: "TESTS",
        precision: 3,
    },
    ChainAsset {
        nai: "@@000000037",
        symbol: "VESTS",
        wire_symbol: "VESTS",
        precision: 6,
    },
];

const STEEM_ASSETS: &[ChainAsset] = &[
    ChainAsset {
        nai: "@@000000013",
        symbol: "SBD",
        wire_symbol: "SBD",
        precision: 3,
    },
    ChainAsset {
        nai: "@@000000021",
        symbol: "STEEM",
        wire_symbol: "STEEM",
        precision: 3,
    },
    ChainAsset {
        nai: "@@000000037",
        symbol: "VESTS",
        wire_symbol: "VESTS",
        precision: 6,
    },
];

impl Chain {
    /// The chain's parameters.
    pub fn properties(&self) -> ChainProperties {
        match self {
            Chain::Hive => ChainProperties {
                chain_id: HIVE_CHAIN_ID,
                prefix: "STM",
                assets: HIVE_ASSETS,
            },
            Chain::HiveTestnet => ChainProperties {
                // The Hive testnet ("TESTDEV") chain id.
                chain_id: ChainId([
                    0x18, 0xdc, 0xf0, 0xa2, 0x85, 0x36, 0x5f, 0xc5, 0x8b, 0x71, 0xf1, 0x8b, 0x3d,
                    0x3f, 0xec, 0x95, 0x4a, 0xa0, 0xc1, 0x41, 0xc4, 0x4e, 0x4e, 0x5c, 0xb4, 0xcf,
                    0x77, 0x7b, 0x9e, 0xab, 0x27, 0x4e,
                ]),
                prefix: "TST",
                assets: TESTNET_ASSETS,
            },
            Chain::SteemLegacy => ChainProperties {
                chain_id: ZERO_CHAIN_ID,
                prefix: "STM",
                assets: STEEM_ASSETS,
            },
        }
    }

    /// The chain id used when signing.
    pub fn chain_id(&self) -> ChainId {
        self.properties().chain_id
    }

    /// The public-key address prefix.
    pub fn prefix(&self) -> &'static str {
        self.properties().prefix
    }

    /// Look up a native asset by its ticker or its NAI.
    pub fn asset(&self, symbol: &str) -> Result<ChainAsset> {
        let props = self.properties();
        props
            .assets
            .iter()
            .find(|a| a.symbol == symbol || a.nai == symbol || a.wire_symbol == symbol)
            .copied()
            .ok_or_else(|| Error::Unknown {
                kind: "asset",
                name: symbol.to_string(),
            })
    }

    /// Resolve a chain by name. There is deliberately no fallback for an unknown name.
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_ascii_uppercase().as_str() {
            // Both spellings map to the live chain. beem's "HIVE" meant the all-zero
            // pre-HF24 id, which is a trap we do not reproduce.
            "HIVE" | "HIVE2" => Ok(Chain::Hive),
            "TESTNET" | "TESTDEV" | "HIVE_TESTNET" => Ok(Chain::HiveTestnet),
            "STEEM" | "STEEM_LEGACY" => Ok(Chain::SteemLegacy),
            other => Err(Error::Unknown {
                kind: "chain",
                name: other.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hive_chain_id_is_the_post_hf24_constant() {
        assert_eq!(
            HIVE_CHAIN_ID.to_hex(),
            "beeab0de00000000000000000000000000000000000000000000000000000000"
        );
        assert!(!HIVE_CHAIN_ID.is_all_zero());
    }

    #[test]
    fn hive_name_resolves_to_the_live_chain_not_the_zero_id() {
        // This is the regression test for beem's table: there, `known_chains["HIVE"]`
        // was the all-zero id and only "HIVE2" was live.
        let c = Chain::from_name("HIVE").unwrap();
        assert_eq!(c.chain_id(), HIVE_CHAIN_ID);
        assert!(!c.chain_id().is_all_zero());
    }

    #[test]
    fn unknown_chain_is_an_error_not_a_fallback() {
        assert!(Chain::from_name("NOPE").is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let id = ChainId::from_hex(&HIVE_CHAIN_ID.to_hex()).unwrap();
        assert_eq!(id, HIVE_CHAIN_ID);
        assert!(ChainId::from_hex("abc").is_err());
        assert!(ChainId::from_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn assets_resolve_by_symbol_nai_and_wire_symbol() {
        let hive = Chain::Hive;
        assert_eq!(hive.asset("HIVE").unwrap().precision, 3);
        assert_eq!(hive.asset("@@000000037").unwrap().symbol, "VESTS");
        assert_eq!(hive.asset("SBD").unwrap().symbol, "HBD");
        assert!(hive.asset("DOGE").is_err());
    }
}
