//! Node.js bindings for `hivecomb`.
//!
//! The surface mirrors the Python module: hold a key, sign a login handshake, build
//! and sign an operation, cache a block reference. It is not a port of dhive's or
//! hive-js's API — those are async RPC clients, and this is the signing and
//! serialization core they would sit on top of.
//!
//! # Rules the boundary enforces
//!
//! * **Nothing panics into Node.** Every fallible path returns a JS `Error`. A panic
//!   crossing N-API takes the process down.
//! * **No key material in an error.** Messages come from `hivecomb`, which never puts
//!   secrets in them, so a stack trace stays safe to log.
//! * **A key does not render.** `toString()` and `toJSON()` on a `PrivateKey` return
//!   `<PrivateKey redacted>`, so `console.log`, template literals and
//!   `JSON.stringify` cannot leak it. Exporting requires the explicitly-named
//!   `toWif()`.
//! * **Unknown input is refused, never defaulted.**

#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi::Either;
use napi_derive::napi;

use hivecomb_core::chains::Chain as RsChain;
use hivecomb_core::keys::{PrivateKey as RsPrivateKey, PublicKey as RsPublicKey};
use hivecomb_core::operations::Operation as RsOperation;
use hivecomb_core::sign as rs_sign;
use hivecomb_core::tapos::TaposCache as RsTaposCache;
use hivecomb_core::transaction::{BlockRef as RsBlockRef, Transaction as RsTransaction};
use hivecomb_core::types::PointInTime;
use hivecomb_core::Error as RsError;

use std::sync::Arc;
use std::time::Duration;

/// Map a `hivecomb` error onto a JS `Error`.
///
/// The reason string is the library's own, which never contains key material.
fn err(e: RsError) -> Error {
    Error::from_reason(e.to_string())
}

fn chain_from(name: Option<String>) -> Result<RsChain> {
    match name.as_deref() {
        None => Ok(RsChain::Hive),
        Some(n) => RsChain::from_name(n).map_err(err),
    }
}

/// Accept a `string` or a `Buffer` for a message, without guessing.
fn message_bytes(message: Either<String, Buffer>) -> Vec<u8> {
    match message {
        Either::A(text) => text.into_bytes(),
        Either::B(buffer) => buffer.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A Hive private key.
#[napi]
pub struct PrivateKey {
    inner: RsPrivateKey,
}

#[napi]
impl PrivateKey {
    /// Parse a WIF (`5...`) or a 64-character hex scalar.
    #[napi(constructor)]
    pub fn new(key: String) -> Result<Self> {
        Ok(PrivateKey {
            inner: RsPrivateKey::parse(&key).map_err(err)?,
        })
    }

    /// Parse a WIF specifically. Rejects Bitcoin compressed-form (`K`/`L`) keys.
    #[napi(factory)]
    pub fn from_wif(wif: String) -> Result<Self> {
        Ok(PrivateKey {
            inner: RsPrivateKey::from_wif(&wif).map_err(err)?,
        })
    }

    /// Generate a new key from the OS CSPRNG.
    #[napi(factory)]
    pub fn generate() -> Self {
        PrivateKey {
            inner: RsPrivateKey::generate(),
        }
    }

    /// Derive a key from an account name, role and master password.
    ///
    /// Hive's master-password scheme: one unsalted SHA-256, no work factor. Weak by
    /// construction and provided because account creation defines it, not because it
    /// is a good idea. Prefer `fromMnemonic`.
    #[napi(factory)]
    pub fn from_password(account: String, role: String, password: String) -> Result<Self> {
        let role: hivecomb_core::keys::Role = role.parse().map_err(err)?;
        let derived = hivecomb_core::keys::PasswordKey::new(&account, role, &password, true)
            .map_err(err)?
            .private_key()
            .map_err(err)?;
        Ok(PrivateKey { inner: derived })
    }

    /// Derive a key from a Graphene brain key and sequence number.
    #[napi(factory)]
    pub fn from_brain_key(phrase: String, sequence: Option<u32>) -> Result<Self> {
        let derived = hivecomb_core::keys::BrainKey::new(&phrase, sequence.unwrap_or(0))
            .map_err(err)?
            .private_key()
            .map_err(err)?;
        Ok(PrivateKey { inner: derived })
    }

    /// Derive a Hive role key from a BIP-39 mnemonic, on the BIP-48 path wallets use.
    #[napi(factory)]
    pub fn from_mnemonic(
        mnemonic: String,
        role: String,
        account_index: Option<u32>,
        key_index: Option<u32>,
        passphrase: Option<String>,
    ) -> Result<Self> {
        let role: hivecomb_core::keys::Role = role.parse().map_err(err)?;
        let phrase = hivecomb_core::bip39::Mnemonic::parse(&mnemonic).map_err(err)?;
        let seed = phrase.to_seed(passphrase.as_deref().unwrap_or(""));
        let master = hivecomb_core::bip32::ExtendedPrivateKey::from_seed(&*seed).map_err(err)?;
        let derived = master
            .derive_hive_role(role, account_index.unwrap_or(0), key_index.unwrap_or(0))
            .map_err(err)?;
        Ok(PrivateKey { inner: derived })
    }

    /// Decrypt a BIP-38 `6P...` key.
    #[napi(factory)]
    pub fn from_bip38(encrypted: String, passphrase: String) -> Result<Self> {
        Ok(PrivateKey {
            inner: hivecomb_core::bip38::decrypt(&encrypted, &passphrase).map_err(err)?,
        })
    }

    /// The matching public key.
    #[napi]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Export as a WIF string.
    ///
    /// Named so every disclosure of the secret is visible at the call site. There is
    /// deliberately no getter, no `toString` and no `toJSON` that does this for you.
    #[napi]
    pub fn to_wif(&self) -> String {
        self.inner.to_wif().to_string()
    }

    /// Encrypt this key under a passphrase, BIP-38 style. Returns a `6P...` string.
    #[napi]
    pub fn to_bip38(&self, passphrase: String) -> Result<String> {
        hivecomb_core::bip38::encrypt(&self.inner, &passphrase)
            .map(|s| s.to_string())
            .map_err(err)
    }

    /// Sign an arbitrary message — the login-handshake primitive.
    ///
    /// Returns the 65-byte compact signature as hex.
    #[napi]
    pub fn sign_message(&self, message: Either<String, Buffer>) -> Result<String> {
        Ok(rs_sign::sign_message(&message_bytes(message), &self.inner)
            .map_err(err)?
            .to_hex())
    }

    /// Redacted. See the module docs.
    // clippy suggests implementing Display instead. That is right for ordinary
    // Rust and wrong here: napi exports an *inherent* `to_string` as JavaScript's
    // `toString()`, and a Display impl would not cross the boundary at all.
    #[allow(clippy::inherent_to_string)]
    #[napi]
    pub fn to_string(&self) -> String {
        "<PrivateKey redacted>".to_string()
    }

    /// Redacted, so `JSON.stringify` cannot leak the key either.
    ///
    /// The `js_name` matters: JavaScript looks for `toJSON` exactly, and napi's
    /// default conversion of `to_json` would give `toJson`, which
    /// `JSON.stringify` ignores.
    #[napi(js_name = "toJSON")]
    pub fn to_json(&self) -> String {
        "<PrivateKey redacted>".to_string()
    }
}

/// A Hive public key.
#[napi]
pub struct PublicKey {
    inner: RsPublicKey,
}

#[napi]
impl PublicKey {
    /// Parse a prefixed key such as `STM7...`.
    #[napi(constructor)]
    pub fn new(key: String) -> Result<Self> {
        Ok(PublicKey {
            inner: RsPublicKey::from_prefixed_any(&key).map_err(err)?,
        })
    }

    /// Render with a chain prefix.
    #[napi]
    pub fn to_string_with_prefix(&self, prefix: Option<String>) -> String {
        self.inner.to_prefixed(prefix.as_deref().unwrap_or("STM"))
    }

    /// The 33-byte compressed encoding, as hex.
    #[napi]
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    // clippy suggests implementing Display instead. That is right for ordinary
    // Rust and wrong here: napi exports an *inherent* `to_string` as JavaScript's
    // `toString()`, and a Display impl would not cross the boundary at all.
    #[allow(clippy::inherent_to_string)]
    #[napi]
    pub fn to_string(&self) -> String {
        self.inner.to_prefixed("STM")
    }

    #[napi(js_name = "toJSON")]
    pub fn to_json(&self) -> String {
        self.inner.to_prefixed("STM")
    }

    /// Whether two keys are the same point.
    #[napi]
    pub fn equals(&self, other: &PublicKey) -> bool {
        self.inner == other.inner
    }
}

// ---------------------------------------------------------------------------
// Module-level signing
// ---------------------------------------------------------------------------

/// Sign a message with a WIF key, returning hex.
#[napi]
pub fn sign_message(message: Either<String, Buffer>, wif: String) -> Result<String> {
    let key = RsPrivateKey::parse(&wif).map_err(err)?;
    Ok(rs_sign::sign_message(&message_bytes(message), &key)
        .map_err(err)?
        .to_hex())
}

/// Recover the public key that signed a message.
///
/// Raises unless the signature is well formed. Recovery answers "which key would have
/// produced this?", so a tampered signature recovers a *different* key rather than
/// failing — compare the result, or use `verifyMessage`.
#[napi]
pub fn recover_message(message: Either<String, Buffer>, signature: String) -> Result<PublicKey> {
    let sig = rs_sign::Signature::from_hex(&signature).map_err(err)?;
    Ok(PublicKey {
        inner: rs_sign::recover_message(&message_bytes(message), &sig).map_err(err)?,
    })
}

/// Verify that `signature` over `message` was made by `publicKey`.
#[napi]
pub fn verify_message(
    message: Either<String, Buffer>,
    signature: String,
    public_key: &PublicKey,
) -> Result<bool> {
    let sig = rs_sign::Signature::from_hex(&signature).map_err(err)?;
    match rs_sign::verify_message(&message_bytes(message), &sig, &public_key.inner) {
        Ok(()) => Ok(true),
        Err(RsError::Signature(_)) => Ok(false),
        Err(other) => Err(err(other)),
    }
}

// ---------------------------------------------------------------------------
// Block references and TaPoS
// ---------------------------------------------------------------------------

/// A reference to a recent block, binding a transaction to a fork.
#[napi]
#[derive(Clone, Copy)]
pub struct BlockRef {
    inner: RsBlockRef,
}

#[napi]
impl BlockRef {
    /// Derive from a 40-character block id, as `head_block_id` gives you.
    #[napi(factory)]
    pub fn from_block_id(block_id: String) -> Result<Self> {
        Ok(BlockRef {
            inner: RsBlockRef::from_block_id(&block_id).map_err(err)?,
        })
    }

    /// Build directly from the two reference fields.
    #[napi(factory)]
    pub fn from_parts(ref_block_num: u32, ref_block_prefix: u32) -> Result<Self> {
        let num = u16::try_from(ref_block_num)
            .map_err(|_| Error::from_reason("refBlockNum must fit in 16 bits"))?;
        Ok(BlockRef {
            inner: RsBlockRef {
                ref_block_num: num,
                ref_block_prefix,
                block_num: u32::from(num),
            },
        })
    }

    #[napi(getter)]
    pub fn ref_block_num(&self) -> u32 {
        u32::from(self.inner.ref_block_num)
    }

    #[napi(getter)]
    pub fn ref_block_prefix(&self) -> u32 {
        self.inner.ref_block_prefix
    }

    #[napi(getter)]
    pub fn block_num(&self) -> u32 {
        self.inner.block_num
    }
}

/// A block reference with an explicit staleness bound.
///
/// Refresh it from a timer; read it on the signing path. Reading a stale reference
/// throws rather than returning something unusable — signing against an expired one
/// produces a transaction the relay accepts and the chain rejects.
#[napi]
pub struct TaposCache {
    inner: Arc<RsTaposCache>,
}

#[napi]
impl TaposCache {
    #[napi(constructor)]
    pub fn new(max_age_seconds: Option<u32>) -> Self {
        TaposCache {
            inner: Arc::new(RsTaposCache::with_max_age(Duration::from_secs(u64::from(
                max_age_seconds.unwrap_or(180),
            )))),
        }
    }

    /// Store a freshly fetched reference.
    #[napi]
    pub fn store(&self, block_ref: &BlockRef) {
        self.inner.store(block_ref.inner);
    }

    /// Store from a `head_block_id` string.
    #[napi]
    pub fn store_block_id(&self, block_id: String) -> Result<()> {
        self.inner
            .store(RsBlockRef::from_block_id(&block_id).map_err(err)?);
        Ok(())
    }

    /// The cached reference, or a thrown error if it is stale or absent.
    #[napi]
    pub fn block_ref(&self) -> Result<BlockRef> {
        Ok(BlockRef {
            inner: self.inner.block_ref().map_err(err)?,
        })
    }

    /// Whether a usable reference is available right now.
    #[napi]
    pub fn is_fresh(&self) -> bool {
        self.inner.is_fresh()
    }

    /// Age of the cached reference in seconds, or `null`.
    #[napi]
    pub fn age_seconds(&self) -> Option<f64> {
        self.inner.age().map(|d| d.as_secs_f64())
    }

    #[napi]
    pub fn invalidate(&self) {
        self.inner.invalidate();
    }
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// Normalise one operation and route it through the shared JSON decoder.
///
/// Accepts `["custom_json", {...}]` and `{type, value}`. All 48 signable operations
/// work, because this is the same decoder the Rust API uses.
fn operation_from_json(mut value: serde_json::Value) -> Result<RsOperation> {

    // hived's `json` and `json_metadata` fields are *strings* holding JSON, not JSON
    // objects. Every Hive client lets a caller pass the object and serializes it, and
    // the separators matter because the string is what gets signed.
    let fields = match &mut value {
        serde_json::Value::Array(items) if items.len() == 2 => items.get_mut(1),
        serde_json::Value::Object(map) => map.get_mut("value"),
        _ => None,
    };
    if let Some(serde_json::Value::Object(map)) = fields {
        for key in [
            "json",
            "json_metadata",
            "posting_json_metadata",
            "json_meta",
        ] {
            if let Some(entry) = map.get_mut(key) {
                if !entry.is_string() {
                    let text = serde_json::to_string(entry)
                        .map_err(|e| Error::from_reason(format!("could not encode {key}: {e}")))?;
                    *entry = serde_json::Value::String(text);
                }
            }
        }
    }

    RsOperation::from_json(&value).map_err(err)
}

fn operations_from_json(operations: Vec<serde_json::Value>) -> Result<Vec<RsOperation>> {
    if operations.is_empty() {
        return Err(Error::from_reason(
            "a transaction needs at least one operation",
        ));
    }
    operations.into_iter().map(operation_from_json).collect()
}

/// Operations given either as a JS array or as one already-stringified JSON array.
///
/// The array form is convenient and slow. napi converts it field by field, and that
/// cost is per *field* rather than per byte: measured against dhive it is roughly
/// 7-9 microseconds for every operation regardless of how much data the operation
/// carries, which is why it hurts most for the smallest operations. The Rust
/// serialization underneath takes 1.23 microseconds.
///
/// A JSON string crosses once. `JSON.stringify` is native and `serde_json` is fast, so
/// the whole cost becomes proportional to bytes instead of to fields.
fn operations_from_either(
    operations: Either<String, Vec<serde_json::Value>>,
) -> Result<Vec<RsOperation>> {
    match operations {
        Either::A(json) => {
            let values: Vec<serde_json::Value> = serde_json::from_str(&json)
                .map_err(|e| Error::from_reason(format!("operations JSON: {e}")))?;
            operations_from_json(values)
        }
        Either::B(values) => operations_from_json(values),
    }
}

/// Build and sign a transaction entirely offline.
///
/// `operations` is an array of `[name, fields]` pairs. `blockRef` supplies the TaPoS
/// reference — from a `TaposCache`, or `BlockRef.fromBlockId(...)`.
///
/// Returns an object ready to POST to `network_broadcast_api.broadcast_transaction`,
/// plus the transaction id under `trxId`.
///
/// No network access happens anywhere in this call.
#[napi(ts_return_type = "any")]
pub fn sign_transaction<'a>(
    env: &'a Env,
    operations: Either<String, Vec<serde_json::Value>>,
    block_ref: &BlockRef,
    // Either WIF strings or `PrivateKey` instances, or a mix. An evaluator pointed out
    // that this crate exports a `PrivateKey` whose whole design is that the secret does
    // not leak through `toString`, `JSON.stringify` or `util.inspect` — and then made
    // the one function that matters take the WIF as a plain string, so a caller had to
    // keep the raw secret around anyway. The re-parse costs ~2.5 us against a ~96 us
    // signing call, so this is about where the secret lives, not about speed.
    keys: Vec<Either<String, &PrivateKey>>,
    expiration_seconds: Option<u32>,
    chain: Option<String>,
) -> Result<Unknown<'a>> {
    let chain = chain_from(chain)?;
    let ops = operations_from_either(operations)?;
    let keys: Vec<RsPrivateKey> = keys
        .iter()
        .map(|k| match k {
            Either::A(wif) => RsPrivateKey::parse(wif).map_err(err),
            Either::B(key) => Ok(key.inner.clone()),
        })
        .collect::<Result<_>>()?;

    let tx =
        RsTransaction::new(block_ref.inner, ops, expiration_seconds.unwrap_or(60)).map_err(err)?;
    let trx_id = tx.id().map_err(err)?;
    let expiration = tx.expiration.to_iso().map_err(err)?;
    let signed = tx.sign(&keys, chain).map_err(err)?;
    let rendered = SignedJson {
        tx: &signed.transaction,
        signatures: signed.signatures.iter().map(|s| s.to_hex()).collect(),
        trx_id: &trx_id,
        expiration,
    };
    let text = serde_json::to_string(&rendered)
        .map_err(|e| Error::from_reason(format!("could not render the signed transaction: {e}")))?;
    json_parse(env, &text)
}

/// The digest a transaction would be signed over, without signing it.
#[napi]
pub fn transaction_digest(
    operations: Either<String, Vec<serde_json::Value>>,
    block_ref: &BlockRef,
    expiration: String,
    chain: Option<String>,
) -> Result<Buffer> {
    let chain = chain_from(chain)?;
    let tx = RsTransaction {
        ref_block_num: block_ref.inner.ref_block_num,
        ref_block_prefix: block_ref.inner.ref_block_prefix,
        expiration: PointInTime::parse(&expiration).map_err(err)?,
        operations: operations_from_either(operations)?,
    };
    Ok(Buffer::from(tx.digest(chain).map_err(err)?.to_vec()))
}

/// The transaction id of an unsigned operation set, without signing it.
#[napi]
pub fn transaction_id(
    operations: Either<String, Vec<serde_json::Value>>,
    block_ref: &BlockRef,
    expiration: String,
) -> Result<String> {
    let tx = RsTransaction {
        ref_block_num: block_ref.inner.ref_block_num,
        ref_block_prefix: block_ref.inner.ref_block_prefix,
        expiration: PointInTime::parse(&expiration).map_err(err)?,
        operations: operations_from_either(operations)?,
    };
    tx.id().map_err(err)
}

// ---------------------------------------------------------------------------
// Memos
// ---------------------------------------------------------------------------

/// Encrypt a memo, returning the `#`-prefixed string.
///
/// The plaintext is written as a Graphene string (varint length, then UTF-8), which is
/// what hive-js, dhive, Keychain and HiveSigner all do.
#[napi]
pub fn encode_memo(
    from_wif: String,
    to_public_key: String,
    message: String,
    nonce: Option<BigInt>,
) -> Result<String> {
    let from = RsPrivateKey::parse(&from_wif).map_err(err)?;
    let to = RsPublicKey::from_prefixed_any(&to_public_key).map_err(err)?;
    match nonce {
        Some(n) => {
            let (_, value, lossless) = n.get_u64();
            if !lossless {
                return Err(Error::from_reason(
                    "nonce must fit in an unsigned 64-bit integer",
                ));
            }
            hivecomb_core::memo::encode_with_nonce(&from, &to, &message, value)
        }
        None => hivecomb_core::memo::encode(&from, &to, &message),
    }
    .map_err(err)
}

/// Decrypt a `#`-prefixed memo with either side's memo key.
#[napi]
pub fn decode_memo(wif: String, memo: String) -> Result<String> {
    let key = RsPrivateKey::parse(&wif).map_err(err)?;
    hivecomb_core::memo::decode(&key, &memo).map_err(err)
}

/// Whether a memo field holds an encrypted memo.
#[napi]
pub fn is_encrypted_memo(memo: String) -> bool {
    hivecomb_core::memo::is_encrypted(&memo)
}

// ---------------------------------------------------------------------------
// Mnemonics, authorities, chain
// ---------------------------------------------------------------------------

/// Generate a new BIP-39 mnemonic.
#[napi]
pub fn generate_mnemonic(strength: Option<u32>) -> Result<String> {
    hivecomb_core::bip39::Mnemonic::generate(strength.unwrap_or(256) as usize)
        .map(|m| m.phrase().to_string())
        .map_err(err)
}

/// Validate a BIP-39 mnemonic's checksum and word list.
#[napi]
pub fn validate_mnemonic(mnemonic: String) -> bool {
    hivecomb_core::bip39::Mnemonic::parse(&mnemonic).is_ok()
}

/// The result of checking keys against an authority.
#[napi(object)]
pub struct AuthorityCheck {
    /// Whether the matched keys alone meet the threshold.
    pub satisfied: bool,
    /// Whether the answer is final, or depends on accounts not looked up.
    pub conclusive: bool,
    pub weight: i64,
    pub threshold: u32,
    pub shortfall: i64,
    pub matched_keys: Vec<String>,
    /// Delegations to other accounts, which an offline check cannot follow.
    pub unresolved_accounts: Vec<String>,
}

/// Check whether a set of public keys satisfies an authority.
///
/// `authority` is the shape the API returns:
/// `{weight_threshold, account_auths, key_auths}`.
///
/// **`satisfied` is a lower bound.** An authority can delegate to another account, and
/// following that means fetching *its* authority. This check is offline, so such
/// entries are listed in `unresolvedAccounts` rather than ignored: `satisfied: false`
/// with a non-empty list means "not from these keys alone", not "no". `conclusive`
/// says which.
#[napi]
pub fn check_authority(
    authority: serde_json::Value,
    public_keys: Vec<String>,
) -> Result<AuthorityCheck> {
    let auth: hivecomb_core::authority::Authority =
        serde_json::from_value(authority).map_err(|e| Error::from_reason(e.to_string()))?;
    let keys: Vec<RsPublicKey> = public_keys
        .iter()
        .map(|k| RsPublicKey::from_prefixed_any(k).map_err(err))
        .collect::<Result<_>>()?;

    let check = auth.check(&keys);
    Ok(AuthorityCheck {
        satisfied: check.satisfied,
        conclusive: check.is_conclusive(),
        weight: check.weight as i64,
        threshold: check.threshold,
        shortfall: check.shortfall() as i64,
        matched_keys: check
            .matched_keys
            .iter()
            .map(|k| k.to_prefixed("STM"))
            .collect(),
        unresolved_accounts: check
            .unresolved_accounts
            .iter()
            .map(|a| a.account.clone())
            .collect(),
    })
}

/// The chain id this build signs against, as hex.
#[napi]
pub fn chain_id(chain: Option<String>) -> Result<String> {
    Ok(chain_from(chain)?.chain_id().to_hex())
}

/// The library version.
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}


// ---------------------------------------------------------------------------
// Rendering a signed transaction back to JavaScript
// ---------------------------------------------------------------------------
//
// The obvious implementation -- build a `serde_json::Value` and hand it to napi --
// costs more than the signing does once a transaction carries more than a couple of
// operations, because napi then walks that tree and materialises every node
// individually. Measured against dhive 1.3.6 at 50 operations it was 508 us against
// dhive's 236; the signing itself accounted for 239 of that, so the *return* was
// costing more than the elliptic curve work.
//
// Rendering straight to a JSON string and letting V8 parse it skips both the
// intermediate tree and the per-node crossing, and `JSON.parse` is among the most
// heavily optimised paths in the engine. Same 50 operations: 335 us.
//
// What this does NOT do is echo back the operations the caller passed in. That would
// be faster still and it would be wrong: hivecomb normalises operations on the way in
// -- an object-valued `json_metadata` becomes the JSON *string* that the signature
// actually covers -- so handing back the caller's own array could return a
// transaction that does not match what was signed. The operations rendered here are
// the ones that were serialized and hashed.

struct OpPair<'a>(&'a RsOperation);

impl serde::Serialize for OpPair<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(2)?;
        t.serialize_element(self.0.id().name())?;
        t.serialize_element(self.0)?;
        t.end()
    }
}

struct SignedJson<'a> {
    tx: &'a RsTransaction,
    signatures: Vec<String>,
    trx_id: &'a str,
    expiration: String,
}

impl serde::Serialize for SignedJson<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut m = s.serialize_struct("tx", 7)?;
        m.serialize_field("ref_block_num", &self.tx.ref_block_num)?;
        m.serialize_field("ref_block_prefix", &self.tx.ref_block_prefix)?;
        m.serialize_field("expiration", &self.expiration)?;
        let ops: Vec<OpPair<'_>> = self.tx.operations.iter().map(OpPair).collect();
        m.serialize_field("operations", &ops)?;
        m.serialize_field("extensions", &[(); 0])?;
        m.serialize_field("signatures", &self.signatures)?;
        m.serialize_field("trx_id", self.trx_id)?;
        m.end()
    }
}

/// Hand a JSON string to V8's own parser.
fn json_parse<'a>(env: &'a Env, text: &str) -> Result<Unknown<'a>> {
    let global = env.get_global()?;
    let json_ns: Object = global.get_named_property("JSON")?;
    let parse: Function<String, Unknown> = json_ns.get_named_property("parse")?;
    parse.call(text.to_owned())
}
