//! Transactions: building, digesting and signing.
//!
//! # Signing needs no network
//!
//! A Hive transaction needs exactly two things from outside itself: the **chain id**
//! and a **block reference** (TaPoS). The chain id is a compile-time constant — see
//! [`crate::chains`]. The block reference is derived from any recent block and stays
//! valid far longer than a single submit, so it can be fetched in the background and
//! reused.
//!
//! Neither belongs in the critical path, and here neither is. Producing a signature is
//! a pure CPU operation.
//!
//! beem could not do this. `blockchaininstance.py:496-549` calls `get_config` over
//! JSON-RPC on the way to every signature, to fetch chain parameters that are mostly
//! constant. When nodes are slow, signing is slow — and signing sits inside whatever
//! deadline the caller is working against.
//!
//! # What gets signed
//!
//! ```text
//! digest = sha256( chain_id || ref_block_num  (u16 LE)
//!                           || ref_block_prefix (u32 LE)
//!                           || expiration       (u32 LE)
//!                           || operations       (varint count, then each)
//!                           || extensions       (varint count) )
//! ```
//!
//! Signatures are **not** part of the signed bytes, and are not part of the
//! transaction id either.

use crate::chains::{Chain, ChainId};
use crate::error::{Error, Result};
use crate::keys::{PrivateKey, PublicKey};
use crate::operations::Operation;
use crate::reader::Reader;
use crate::sign::{self, Signature};
use crate::types::{
    write_array, write_u16, write_u32, write_varint32, GrapheneSerialize, PointInTime,
};
use sha2::{Digest, Sha256};

/// Default seconds until a transaction expires.
///
/// hived caps expiration at one hour past head-block time; a minute is the usual
/// working value and leaves room for a retry.
pub const DEFAULT_EXPIRATION_SECS: u32 = 60;

/// hived's hard limit on how far in the future an expiration may be set.
pub const MAX_EXPIRATION_SECS: u32 = 3600;

/// A reference to a recent block, for transaction-as-proof-of-stake.
///
/// TaPoS binds a transaction to a fork: if the referenced block is not in the chain
/// the node is building on, the transaction is invalid there. That is what stops a
/// transaction from being replayed onto a competing fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    /// Low 16 bits of the referenced block number.
    pub ref_block_num: u16,
    /// Bytes 4..8 of the block id, read as a little-endian `u32`.
    pub ref_block_prefix: u32,
    /// The full block number the reference came from, kept for staleness checks.
    pub block_num: u32,
}

impl BlockRef {
    /// Derive a reference from a block number and its 20-byte block id.
    ///
    /// The block id is hived's `block_id_type`: a 160-bit hash whose **first four
    /// bytes are the big-endian block number**, with the remaining 16 bytes the hash.
    /// The prefix is taken from bytes 4..8 — that is, the first four bytes *after* the
    /// embedded block number — read little-endian.
    pub fn from_block_id(block_id_hex: &str) -> Result<Self> {
        let hex = block_id_hex.trim();
        if hex.len() != 40 {
            return Err(Error::field(format!(
                "block id must be 40 hex characters, got {}",
                hex.len()
            )));
        }
        let mut bytes = [0u8; 20];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::field("block id is not valid hex"))?;
        }
        let block_num = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let ref_block_prefix = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Ok(BlockRef {
            ref_block_num: (block_num & 0xffff) as u16,
            ref_block_prefix,
            block_num,
        })
    }
}

/// An unsigned transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub ref_block_num: u16,
    pub ref_block_prefix: u32,
    pub expiration: PointInTime,
    pub operations: Vec<Operation>,
}

impl Transaction {
    /// Build a transaction against a block reference, expiring `expiration_secs` from
    /// now.
    pub fn new(
        block_ref: BlockRef,
        operations: Vec<Operation>,
        expiration_secs: u32,
    ) -> Result<Self> {
        if operations.is_empty() {
            return Err(Error::field(
                "a transaction must contain at least one operation",
            ));
        }
        if expiration_secs == 0 || expiration_secs > MAX_EXPIRATION_SECS {
            return Err(Error::field(format!(
                "expiration of {expiration_secs}s is outside hived's 1..={MAX_EXPIRATION_SECS}s window"
            )));
        }
        Ok(Transaction {
            ref_block_num: block_ref.ref_block_num,
            ref_block_prefix: block_ref.ref_block_prefix,
            expiration: PointInTime::now_plus(expiration_secs)?,
            operations,
        })
    }

    /// Serialize the transaction body — everything the digest covers.
    ///
    /// Signatures are excluded. beem achieved this by mutating `self.data`, computing
    /// the bytes, and putting the signatures back; a failure in between left the
    /// object without its signatures. Here the body simply never contains them.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(64 + self.operations.len() * 64);
        write_u16(&mut out, self.ref_block_num);
        write_u32(&mut out, self.ref_block_prefix);
        self.expiration.append_to(&mut out)?;
        write_array(&mut out, &self.operations)?;
        write_varint32(&mut out, 0); // extensions: always empty for a client transaction
        Ok(out)
    }

    /// The digest that gets signed: `sha256(chain_id || body)`.
    ///
    /// Refuses the all-zero chain id. That is the value beem fell back to inside a
    /// bare `except:`, and signing against it yields a signature the chain rejects
    /// with no indication that signing was the problem.
    pub fn digest(&self, chain: Chain) -> Result<[u8; 32]> {
        self.digest_with_chain_id(chain.chain_id())
    }

    /// The digest against an explicit chain id, for testnets and forks.
    pub fn digest_with_chain_id(&self, chain_id: ChainId) -> Result<[u8; 32]> {
        if chain_id.is_all_zero() {
            return Err(Error::Chain(
                "refusing to sign against the all-zero chain id: it is the pre-HF24 \
                 value and produces a signature Hive rejects"
                    .into(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(chain_id.as_bytes());
        hasher.update(self.body_bytes()?);
        Ok(hasher.finalize().into())
    }

    /// The transaction id: the first 20 bytes of `sha256(body)`, as hex.
    ///
    /// Note that this does **not** include the chain id, and does not include
    /// signatures.
    pub fn id(&self) -> Result<String> {
        let digest = Sha256::digest(self.body_bytes()?);
        Ok(digest[..20].iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Sign with one or more keys.
    ///
    /// Duplicate keys are collapsed, since a second signature from the same key adds
    /// nothing and hived rejects a transaction carrying a redundant signature.
    pub fn sign(self, keys: &[PrivateKey], chain: Chain) -> Result<SignedTransaction> {
        if keys.is_empty() {
            return Err(Error::field("no signing keys were provided"));
        }
        let digest = self.digest(chain)?;

        let mut unique: Vec<&PrivateKey> = Vec::with_capacity(keys.len());
        for key in keys {
            if !unique.contains(&key) {
                unique.push(key);
            }
        }

        let signatures = unique
            .iter()
            .map(|key| sign::sign_digest(&digest, key))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedTransaction {
            transaction: self,
            signatures,
        })
    }
}

/// A transaction with its signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub signatures: Vec<Signature>,
}

impl SignedTransaction {
    /// The signing keys, recovered and verified.
    ///
    /// Every signature must verify; one that does not is an error rather than a
    /// skipped entry. beem's equivalent looped over all four recovery parameters and
    /// appended every candidate that did not raise, so its result could hold four
    /// unrelated keys for a single signature.
    pub fn signers(&self, chain: Chain) -> Result<Vec<PublicKey>> {
        let digest = self.transaction.digest(chain)?;
        self.signatures
            .iter()
            .map(|sig| sign::recover(&digest, sig))
            .collect()
    }

    /// Check that the transaction is signed by every one of `required`.
    pub fn verify(&self, required: &[PublicKey], chain: Chain) -> Result<()> {
        let found = self.signers(chain)?;
        for key in required {
            if !found.contains(key) {
                return Err(Error::sig(format!(
                    "transaction is not signed by {}",
                    key.to_prefixed(chain.prefix())
                )));
            }
        }
        Ok(())
    }

    /// The JSON form a node's `network_broadcast_api` expects.
    pub fn to_json(&self) -> Result<serde_json::Value> {
        let ops: Result<Vec<serde_json::Value>> = self
            .transaction
            .operations
            .iter()
            .map(operation_to_json)
            .collect();
        Ok(serde_json::json!({
            "ref_block_num": self.transaction.ref_block_num,
            "ref_block_prefix": self.transaction.ref_block_prefix,
            "expiration": self.transaction.expiration.to_iso()?,
            "operations": ops?,
            "extensions": Vec::<serde_json::Value>::new(),
            "signatures": self.signatures.iter().map(|s| s.to_hex()).collect::<Vec<_>>(),
        }))
    }
}

/// Render an operation in Hive's `[name, {fields}]` JSON form.
fn operation_to_json(op: &Operation) -> Result<serde_json::Value> {
    let value = serde_json::to_value(op)
        .map_err(|e| Error::ser(format!("could not render operation as JSON: {e}")))?;
    Ok(serde_json::json!([op.id().name(), value]))
}

impl Transaction {
    /// Decode a transaction body from the Graphene wire format.
    ///
    /// This is the inverse of [`Transaction::body_bytes`] and reads the same field set
    /// — signatures are not part of it.
    pub fn from_body_bytes(bytes: &[u8], chain: Chain) -> Result<Self> {
        let mut r = Reader::new(bytes, chain);
        let tx = Self::read_body(&mut r)?;
        r.expect_end()?;
        Ok(tx)
    }

    fn read_body(r: &mut Reader<'_>) -> Result<Self> {
        let ref_block_num = r.u16()?;
        let ref_block_prefix = r.u32()?;
        let expiration = r.point_in_time()?;
        let operations: Vec<Operation> = r.array()?;
        let extension_count = r.varint32()?;
        if extension_count != 0 {
            return Err(Error::ser(format!(
                "transaction carries {extension_count} extension(s), which this build does not model"
            )));
        }
        if operations.is_empty() {
            return Err(Error::ser("transaction contains no operations"));
        }
        Ok(Transaction {
            ref_block_num,
            ref_block_prefix,
            expiration,
            operations,
        })
    }
}

impl SignedTransaction {
    /// Serialize the full transaction including its signatures.
    ///
    /// This is the form used for peer-to-peer transmission and for storing a
    /// transaction in a block. It is **not** what gets hashed for the digest — see
    /// [`Transaction::body_bytes`].
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let mut out = self.transaction.body_bytes()?;
        write_varint32(
            &mut out,
            u32::try_from(self.signatures.len()).map_err(|_| {
                Error::ser("transaction carries an implausible number of signatures")
            })?,
        );
        for sig in &self.signatures {
            out.extend_from_slice(sig.as_bytes());
        }
        Ok(out)
    }

    /// Decode a full signed transaction.
    pub fn from_wire(bytes: &[u8], chain: Chain) -> Result<Self> {
        let mut r = Reader::new(bytes, chain);
        let transaction = Transaction::read_body(&mut r)?;
        let count = r.varint32()? as usize;
        // Each signature is 65 bytes; refuse a count the buffer cannot hold before
        // allocating for it.
        if count.saturating_mul(crate::sign::SIGNATURE_LEN) > r.remaining() {
            return Err(Error::ser(format!(
                "transaction claims {count} signatures but only {} bytes remain",
                r.remaining()
            )));
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            let raw = r.raw(crate::sign::SIGNATURE_LEN)?;
            signatures.push(Signature::from_bytes(&raw)?);
        }
        r.expect_end()?;
        Ok(SignedTransaction {
            transaction,
            signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::Amount;
    use crate::operations::{CustomJson, Vote};

    /// A fixed key used throughout these tests.
    ///
    /// It is published here on purpose and must never hold value. Checked against
    /// `account_by_key_api.get_key_references` on 2026-08-22: **no Hive account uses
    /// it.** Do not fund it, and do not copy it into anything that will.
    const TEST_WIF: &str = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

    fn block_ref() -> BlockRef {
        BlockRef {
            ref_block_num: 0x1234,
            ref_block_prefix: 0xdeadbeef,
            block_num: 0x51234,
        }
    }

    fn a_vote() -> Operation {
        Operation::Vote(Vote {
            voter: "alice".into(),
            author: "bob".into(),
            permlink: "a-post".into(),
            weight: 10_000,
        })
    }

    fn fixed_tx() -> Transaction {
        Transaction {
            ref_block_num: 0x1234,
            ref_block_prefix: 0xdeadbeef,
            expiration: PointInTime::from_unix(1_700_000_000).unwrap(),
            operations: vec![a_vote()],
        }
    }

    #[test]
    fn transaction_body_round_trips() {
        let tx = fixed_tx();
        let bytes = tx.body_bytes().unwrap();
        let back = Transaction::from_body_bytes(&bytes, Chain::Hive).unwrap();
        assert_eq!(back, tx);
        assert_eq!(
            back.digest(Chain::Hive).unwrap(),
            tx.digest(Chain::Hive).unwrap()
        );
        assert_eq!(back.id().unwrap(), tx.id().unwrap());
    }

    #[test]
    fn signed_transaction_round_trips_with_its_signatures() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let other = PrivateKey::generate();
        let signed = fixed_tx()
            .sign(&[key.clone(), other.clone()], Chain::Hive)
            .unwrap();
        let bytes = signed.to_wire().unwrap();
        let back = SignedTransaction::from_wire(&bytes, Chain::Hive).unwrap();
        assert_eq!(back, signed);
        // ...and the recovered signatures still verify.
        back.verify(&[key.public_key(), other.public_key()], Chain::Hive)
            .unwrap();
    }

    #[test]
    fn signatures_are_not_part_of_the_digest() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let tx = fixed_tx();
        let unsigned_digest = tx.digest(Chain::Hive).unwrap();
        let signed = tx.clone().sign(&[key], Chain::Hive).unwrap();
        assert_eq!(
            signed.transaction.digest(Chain::Hive).unwrap(),
            unsigned_digest
        );
        // The full wire form is longer than the body by exactly the signature block.
        assert_eq!(
            signed.to_wire().unwrap().len(),
            tx.body_bytes().unwrap().len() + 1 + 65
        );
    }

    #[test]
    fn a_truncated_transaction_errors_at_every_cut() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let signed = fixed_tx().sign(&[key], Chain::Hive).unwrap();
        let bytes = signed.to_wire().unwrap();
        for cut in 0..bytes.len() {
            assert!(
                SignedTransaction::from_wire(&bytes[..cut], Chain::Hive).is_err(),
                "truncating to {cut} bytes should fail"
            );
        }
        assert!(SignedTransaction::from_wire(&bytes, Chain::Hive).is_ok());
    }

    #[test]
    fn an_implausible_signature_count_is_refused_before_allocating() {
        let mut bytes = fixed_tx().body_bytes().unwrap();
        write_varint32(&mut bytes, 4_000_000_000);
        let err = SignedTransaction::from_wire(&bytes, Chain::Hive).unwrap_err();
        assert!(format!("{err}").contains("only"));
    }

    #[test]
    fn a_transaction_with_no_operations_is_refused_on_read() {
        let mut bytes = Vec::new();
        write_u16(&mut bytes, 1);
        write_u32(&mut bytes, 2);
        PointInTime::from_unix(1_700_000_000)
            .unwrap()
            .append_to(&mut bytes)
            .unwrap();
        write_varint32(&mut bytes, 0); // zero operations
        write_varint32(&mut bytes, 0); // no extensions
        assert!(Transaction::from_body_bytes(&bytes, Chain::Hive).is_err());
    }

    #[test]
    fn block_ref_derivation() {
        // Block 5, with a synthetic id whose first four bytes are the block number.
        let id = "00000005aabbccdd00000000000000000000abcd";
        let r = BlockRef::from_block_id(id).unwrap();
        assert_eq!(r.block_num, 5);
        assert_eq!(r.ref_block_num, 5);
        // bytes 4..8 = aa bb cc dd, little-endian
        assert_eq!(r.ref_block_prefix, 0xddccbbaa);
    }

    #[test]
    fn ref_block_num_takes_the_low_sixteen_bits() {
        // Block 0x00012345 -> ref_block_num 0x2345.
        let id = "00012345aabbccdd00000000000000000000abcd";
        let r = BlockRef::from_block_id(id).unwrap();
        assert_eq!(r.block_num, 0x12345);
        assert_eq!(r.ref_block_num, 0x2345);
    }

    #[test]
    fn block_ref_rejects_malformed_ids() {
        assert!(BlockRef::from_block_id("abc").is_err());
        assert!(BlockRef::from_block_id(&"z".repeat(40)).is_err());
    }

    #[test]
    fn body_layout_is_exactly_the_signed_bytes() {
        let tx = fixed_tx();
        let body = tx.body_bytes().unwrap();
        assert_eq!(&body[0..2], &0x1234u16.to_le_bytes());
        assert_eq!(&body[2..6], &0xdeadbeefu32.to_le_bytes());
        assert_eq!(&body[6..10], &1_700_000_000u32.to_le_bytes());
        assert_eq!(body[10], 1, "one operation");
        assert_eq!(*body.last().unwrap(), 0, "empty extensions array");
    }

    #[test]
    fn digest_is_chain_id_prefixed() {
        let tx = fixed_tx();
        let digest = tx.digest(Chain::Hive).unwrap();
        let mut expected = Sha256::new();
        expected.update(crate::chains::HIVE_CHAIN_ID.as_bytes());
        expected.update(tx.body_bytes().unwrap());
        assert_eq!(digest, <[u8; 32]>::from(expected.finalize()));
    }

    #[test]
    fn a_different_chain_gives_a_different_digest() {
        let tx = fixed_tx();
        assert_ne!(
            tx.digest(Chain::Hive).unwrap(),
            tx.digest(Chain::HiveTestnet).unwrap()
        );
    }

    #[test]
    fn the_all_zero_chain_id_is_refused() {
        // beem fell back to exactly this value inside a bare `except:`.
        let tx = fixed_tx();
        let err = tx.digest(Chain::SteemLegacy).unwrap_err();
        assert!(format!("{err}").contains("all-zero"));
        assert!(tx
            .digest_with_chain_id(crate::chains::ZERO_CHAIN_ID)
            .is_err());
    }

    #[test]
    fn transaction_id_is_twenty_bytes_of_sha256_over_the_body() {
        let tx = fixed_tx();
        let id = tx.id().unwrap();
        assert_eq!(id.len(), 40);
        let expected = Sha256::digest(tx.body_bytes().unwrap());
        let expected_hex: String = expected[..20].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(id, expected_hex);
    }

    #[test]
    fn signing_round_trips() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let signed = fixed_tx()
            .sign(std::slice::from_ref(&key), Chain::Hive)
            .unwrap();
        assert_eq!(signed.signatures.len(), 1);
        assert_eq!(signed.signers(Chain::Hive).unwrap(), vec![key.public_key()]);
        signed.verify(&[key.public_key()], Chain::Hive).unwrap();
    }

    #[test]
    fn verification_rejects_a_key_that_did_not_sign() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let other = PrivateKey::generate();
        let signed = fixed_tx().sign(&[key], Chain::Hive).unwrap();
        assert!(signed.verify(&[other.public_key()], Chain::Hive).is_err());
    }

    #[test]
    fn duplicate_keys_produce_one_signature() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let signed = fixed_tx()
            .sign(&[key.clone(), key.clone(), key], Chain::Hive)
            .unwrap();
        assert_eq!(signed.signatures.len(), 1);
    }

    #[test]
    fn multiple_distinct_keys_each_sign() {
        let a = PrivateKey::from_wif(TEST_WIF).unwrap();
        let b = PrivateKey::generate();
        let signed = fixed_tx()
            .sign(&[a.clone(), b.clone()], Chain::Hive)
            .unwrap();
        assert_eq!(signed.signatures.len(), 2);
        let signers = signed.signers(Chain::Hive).unwrap();
        assert!(signers.contains(&a.public_key()));
        assert!(signers.contains(&b.public_key()));
    }

    #[test]
    fn signing_is_reproducible() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let a = fixed_tx()
            .sign(std::slice::from_ref(&key), Chain::Hive)
            .unwrap();
        let b = fixed_tx().sign(&[key], Chain::Hive).unwrap();
        assert_eq!(a.signatures, b.signatures);
    }

    #[test]
    fn tampering_with_the_body_invalidates_the_signature() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let mut signed = fixed_tx()
            .sign(std::slice::from_ref(&key), Chain::Hive)
            .unwrap();
        signed.transaction.ref_block_num ^= 1;
        assert!(signed.verify(&[key.public_key()], Chain::Hive).is_err());
    }

    #[test]
    fn empty_transactions_and_bad_expirations_are_refused() {
        assert!(Transaction::new(block_ref(), vec![], 60).is_err());
        assert!(Transaction::new(block_ref(), vec![a_vote()], 0).is_err());
        assert!(Transaction::new(block_ref(), vec![a_vote()], 7200).is_err());
        assert!(Transaction::new(block_ref(), vec![a_vote()], 60).is_ok());
    }

    #[test]
    fn signing_without_keys_is_refused() {
        assert!(fixed_tx().sign(&[], Chain::Hive).is_err());
    }

    #[test]
    fn json_form_matches_what_a_node_expects() {
        let key = PrivateKey::from_wif(TEST_WIF).unwrap();
        let tx = Transaction {
            ref_block_num: 1,
            ref_block_prefix: 2,
            expiration: PointInTime::from_unix(1_700_000_000).unwrap(),
            operations: vec![Operation::CustomJson(CustomJson {
                required_auths: vec![],
                required_posting_auths: vec!["alice".into()],
                id: "test".into(),
                json: "{}".into(),
            })],
        };
        let json = tx.sign(&[key], Chain::Hive).unwrap().to_json().unwrap();
        assert_eq!(json["ref_block_num"], 1);
        assert_eq!(json["expiration"], "2023-11-14T22:13:20");
        assert_eq!(json["operations"][0][0], "custom_json");
        assert_eq!(json["operations"][0][1]["id"], "test");
        assert_eq!(json["signatures"].as_array().unwrap().len(), 1);
        assert!(json["extensions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn amounts_survive_the_round_trip_into_a_transaction() {
        let tx = Transaction {
            ref_block_num: 1,
            ref_block_prefix: 2,
            expiration: PointInTime::from_unix(1_700_000_000).unwrap(),
            operations: vec![Operation::Transfer(crate::operations::Transfer {
                from: "alice".into(),
                to: "bob".into(),
                amount: Amount::parse("0.001 HIVE", Chain::Hive).unwrap(),
                memo: String::new(),
            })],
        };
        let body = tx.body_bytes().unwrap();
        // The amount's 8-byte unit count must be exactly 1, not 0 or 2.
        assert!(body.windows(8).any(|w| w == 1i64.to_le_bytes()));
    }
}
