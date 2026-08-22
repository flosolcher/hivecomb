//! Python bindings for `comb`.
//!
//! The surface is deliberately narrow and mirrors what a Hive application actually
//! does: hold a key, sign a login handshake, build and sign an operation, cache a
//! block reference. It is not a transliteration of beem's API — that API grew around
//! a design in which every object could reach the network, and reproducing it would
//! reproduce the problem this port exists to remove.
//!
//! # Rules the boundary enforces
//!
//! * **Nothing panics across the FFI.** Every fallible path returns a Python
//!   exception. A panic unwinding into CPython in a submit path is worse than an
//!   exception, so there are no `unwrap`s on anything derived from input.
//! * **No key material in an exception.** Error messages are the Rust ones, which
//!   never carry secrets — so a traceback stays safe to log.
//! * **`repr()` never discloses a key.** `PrivateKey.__repr__` and `__str__` both
//!   return `<PrivateKey redacted>`. beem's returned the raw scalar and the WIF
//!   respectively, which is how keys end up in logs.
//! * **Unknown input is refused, never defaulted.**

// `#[pymethods]` expands to code clippy reads as a redundant `PyResult` conversion.
// The lint fires on macro-generated lines, not on anything written here.
#![allow(clippy::useless_conversion)]

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use comb_core::chains::Chain as RsChain;
use comb_core::keys::{PrivateKey as RsPrivateKey, PublicKey as RsPublicKey};
use comb_core::operations::{
    CustomJson as RsCustomJson, Operation as RsOperation, Transfer as RsTransfer, Vote as RsVote,
};
use comb_core::sign as rs_sign;
use comb_core::tapos::TaposCache as RsTaposCache;
use comb_core::transaction::{BlockRef as RsBlockRef, Transaction as RsTransaction};
use comb_core::types::PointInTime;
use comb_core::Error as RsError;

use std::sync::Arc;
use std::time::Duration;

/// Map a `comb` error onto a Python exception.
///
/// `ValueError` for anything the caller could have supplied differently,
/// `RuntimeError` for environmental failures. Neither ever carries key material.
fn to_py_err(e: RsError) -> PyErr {
    match e {
        RsError::Rpc(_) | RsError::RpcResponse { .. } | RsError::StaleTapos(_) => {
            PyRuntimeError::new_err(e.to_string())
        }
        other => PyValueError::new_err(other.to_string()),
    }
}

fn chain_from_name(name: Option<&str>) -> PyResult<RsChain> {
    match name {
        None => Ok(RsChain::Hive),
        Some(n) => RsChain::from_name(n).map_err(to_py_err),
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A Hive private key.
#[pyclass(name = "PrivateKey", module = "comb")]
#[derive(Clone)]
pub struct PyPrivateKey {
    inner: RsPrivateKey,
}

#[pymethods]
impl PyPrivateKey {
    /// Parse a WIF (`5...`) or a 64-character hex scalar.
    #[new]
    fn new(key: &str) -> PyResult<Self> {
        Ok(PyPrivateKey {
            inner: RsPrivateKey::parse(key).map_err(to_py_err)?,
        })
    }

    /// Parse a WIF specifically. Rejects Bitcoin compressed-form (`K`/`L`) keys.
    #[staticmethod]
    fn from_wif(wif: &str) -> PyResult<Self> {
        Ok(PyPrivateKey {
            inner: RsPrivateKey::from_wif(wif).map_err(to_py_err)?,
        })
    }

    /// Generate a new key from the OS CSPRNG.
    #[staticmethod]
    fn generate() -> Self {
        PyPrivateKey {
            inner: RsPrivateKey::generate(),
        }
    }

    /// The matching public key.
    fn public_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Export as a WIF string.
    ///
    /// Named so that every disclosure of the secret is visible at the call site.
    /// There is deliberately no property, no `__str__` and no `__repr__` that does
    /// this for you.
    fn to_wif(&self) -> String {
        self.inner.to_wif().to_string()
    }

    /// Derive a key from an account name, role and master password.
    ///
    /// This is Hive's master-password scheme: a single unsalted SHA-256. It is weak by
    /// construction — see the Rust `keys` module docs — and is provided because the
    /// account-creation flow defines it, not because it is a good idea.
    #[staticmethod]
    #[pyo3(signature = (account, role, password))]
    fn from_password(account: &str, role: &str, password: &str) -> PyResult<Self> {
        let role: comb_core::keys::Role = role.parse().map_err(to_py_err)?;
        let derived = comb_core::keys::PasswordKey::new(account, role, password, true)
            .map_err(to_py_err)?
            .private_key()
            .map_err(to_py_err)?;
        Ok(PyPrivateKey { inner: derived })
    }

    /// Derive a key from a Graphene brain key and sequence number.
    #[staticmethod]
    #[pyo3(signature = (phrase, sequence = 0))]
    fn from_brain_key(phrase: &str, sequence: u32) -> PyResult<Self> {
        let derived = comb_core::keys::BrainKey::new(phrase, sequence)
            .map_err(to_py_err)?
            .private_key()
            .map_err(to_py_err)?;
        Ok(PyPrivateKey { inner: derived })
    }

    /// Derive a Hive role key from a BIP-39 mnemonic, using the BIP-48 path wallets use.
    #[staticmethod]
    #[pyo3(signature = (mnemonic, role, account_index = 0, key_index = 0, passphrase = ""))]
    fn from_mnemonic(
        mnemonic: &str,
        role: &str,
        account_index: u32,
        key_index: u32,
        passphrase: &str,
    ) -> PyResult<Self> {
        let role: comb_core::keys::Role = role.parse().map_err(to_py_err)?;
        let phrase = comb_core::bip39::Mnemonic::parse(mnemonic).map_err(to_py_err)?;
        let seed = phrase.to_seed(passphrase);
        let master = comb_core::bip32::ExtendedPrivateKey::from_seed(&*seed).map_err(to_py_err)?;
        let derived = master
            .derive_hive_role(role, account_index, key_index)
            .map_err(to_py_err)?;
        Ok(PyPrivateKey { inner: derived })
    }

    /// Encrypt this key under a passphrase, BIP-38 style. Returns a `6P...` string.
    fn to_bip38(&self, passphrase: &str) -> PyResult<String> {
        comb_core::bip38::encrypt(&self.inner, passphrase)
            .map(|s| s.to_string())
            .map_err(to_py_err)
    }

    /// Decrypt a BIP-38 `6P...` key.
    #[staticmethod]
    fn from_bip38(encrypted: &str, passphrase: &str) -> PyResult<Self> {
        Ok(PyPrivateKey {
            inner: comb_core::bip38::decrypt(encrypted, passphrase).map_err(to_py_err)?,
        })
    }

    /// Sign an arbitrary message — the login-handshake primitive.
    ///
    /// Returns the 65-byte compact signature as hex, the same form
    /// `beemgraphenebase.ecdsasig.sign_message` produced.
    #[pyo3(signature = (message))]
    fn sign_message(&self, message: MessageArg) -> PyResult<String> {
        let bytes = message.as_bytes();
        Ok(rs_sign::sign_message(&bytes, &self.inner)
            .map_err(to_py_err)?
            .to_hex())
    }

    fn __repr__(&self) -> &'static str {
        "<PrivateKey redacted>"
    }

    fn __str__(&self) -> &'static str {
        "<PrivateKey redacted>"
    }

    fn __eq__(&self, other: &PyPrivateKey) -> bool {
        self.inner == other.inner
    }
}

/// A Hive public key.
#[pyclass(name = "PublicKey", module = "comb")]
#[derive(Clone)]
pub struct PyPublicKey {
    inner: RsPublicKey,
}

#[pymethods]
impl PyPublicKey {
    /// Parse a prefixed key such as `STM7...`.
    #[new]
    fn new(key: &str) -> PyResult<Self> {
        Ok(PyPublicKey {
            inner: RsPublicKey::from_prefixed_any(key).map_err(to_py_err)?,
        })
    }

    /// Render with a chain prefix.
    #[pyo3(signature = (prefix = "STM"))]
    fn to_string_with_prefix(&self, prefix: &str) -> String {
        self.inner.to_prefixed(prefix)
    }

    /// The 33-byte compressed encoding, as hex.
    fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    fn __str__(&self) -> String {
        self.inner.to_prefixed("STM")
    }

    fn __repr__(&self) -> String {
        format!("<PublicKey {}>", self.inner.to_prefixed("STM"))
    }

    fn __eq__(&self, other: &PyPublicKey) -> bool {
        self.inner == other.inner
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.inner.to_bytes().hash(&mut h);
        h.finish()
    }
}

/// Accepts either `str` or `bytes` for a message, without guessing.
#[derive(FromPyObject)]
enum MessageArg {
    Text(String),
    Bytes(Vec<u8>),
}

impl MessageArg {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            MessageArg::Text(s) => s.as_bytes().to_vec(),
            MessageArg::Bytes(b) => b.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Module-level signing helpers
// ---------------------------------------------------------------------------

/// Sign a message with a WIF key, returning hex.
///
/// A drop-in replacement for `beemgraphenebase.ecdsasig.sign_message(msg, wif)`,
/// except that it returns hex rather than raw bytes and never touches the network.
#[pyfunction]
#[pyo3(signature = (message, wif))]
fn sign_message(message: MessageArg, wif: &str) -> PyResult<String> {
    let key = RsPrivateKey::parse(wif).map_err(to_py_err)?;
    Ok(rs_sign::sign_message(&message.as_bytes(), &key)
        .map_err(to_py_err)?
        .to_hex())
}

/// Verify a hex signature over a message and return the public key that made it.
///
/// Raises if the signature does not verify. beem's equivalent returned a
/// plausible-looking key regardless, because it discarded `ecdsa_verify`'s result.
#[pyfunction]
#[pyo3(signature = (message, signature))]
fn recover_message(message: MessageArg, signature: &str) -> PyResult<PyPublicKey> {
    let sig = rs_sign::Signature::from_hex(signature).map_err(to_py_err)?;
    let key = rs_sign::recover_message(&message.as_bytes(), &sig).map_err(to_py_err)?;
    Ok(PyPublicKey { inner: key })
}

/// Verify that `signature` over `message` was made by `public_key`.
#[pyfunction]
#[pyo3(signature = (message, signature, public_key))]
fn verify_message(
    message: MessageArg,
    signature: &str,
    public_key: &PyPublicKey,
) -> PyResult<bool> {
    let sig = rs_sign::Signature::from_hex(signature).map_err(to_py_err)?;
    match rs_sign::verify_message(&message.as_bytes(), &sig, &public_key.inner) {
        Ok(()) => Ok(true),
        Err(RsError::Signature(_)) => Ok(false),
        Err(other) => Err(to_py_err(other)),
    }
}

// ---------------------------------------------------------------------------
// Block references and the TaPoS cache
// ---------------------------------------------------------------------------

/// A reference to a recent block, binding a transaction to a fork.
#[pyclass(name = "BlockRef", module = "comb")]
#[derive(Clone, Copy)]
pub struct PyBlockRef {
    inner: RsBlockRef,
}

#[pymethods]
impl PyBlockRef {
    /// Derive from a 40-character block id, as `get_dynamic_global_properties`
    /// returns in `head_block_id`.
    #[staticmethod]
    fn from_block_id(block_id: &str) -> PyResult<Self> {
        Ok(PyBlockRef {
            inner: RsBlockRef::from_block_id(block_id).map_err(to_py_err)?,
        })
    }

    /// Build directly from the two reference fields.
    ///
    /// Use this when reconstructing a transaction whose block id is no longer at
    /// hand; `block_num` is then unknown and reported as the low 16 bits.
    #[staticmethod]
    fn from_parts(ref_block_num: u16, ref_block_prefix: u32) -> Self {
        PyBlockRef {
            inner: RsBlockRef {
                ref_block_num,
                ref_block_prefix,
                block_num: u32::from(ref_block_num),
            },
        }
    }

    #[getter]
    fn ref_block_num(&self) -> u16 {
        self.inner.ref_block_num
    }

    #[getter]
    fn ref_block_prefix(&self) -> u32 {
        self.inner.ref_block_prefix
    }

    #[getter]
    fn block_num(&self) -> u32 {
        self.inner.block_num
    }

    fn __repr__(&self) -> String {
        format!(
            "<BlockRef block_num={} ref_block_num={} ref_block_prefix={}>",
            self.inner.block_num, self.inner.ref_block_num, self.inner.ref_block_prefix
        )
    }
}

/// A block reference with an explicit staleness bound.
///
/// Refresh it from a background thread; read it on the signing path. Reading a stale
/// reference raises `RuntimeError` rather than returning something unusable — signing
/// against an expired reference produces a transaction the relay accepts and the chain
/// rejects, which is a silent failure.
#[pyclass(name = "TaposCache", module = "comb")]
pub struct PyTaposCache {
    inner: Arc<RsTaposCache>,
}

#[pymethods]
impl PyTaposCache {
    #[new]
    #[pyo3(signature = (max_age_seconds = 180))]
    fn new(max_age_seconds: u64) -> Self {
        PyTaposCache {
            inner: Arc::new(RsTaposCache::with_max_age(Duration::from_secs(
                max_age_seconds,
            ))),
        }
    }

    /// Store a freshly fetched reference.
    fn store(&self, block_ref: &PyBlockRef) {
        self.inner.store(block_ref.inner);
    }

    /// Store from a `head_block_id` string.
    fn store_block_id(&self, block_id: &str) -> PyResult<()> {
        self.inner
            .store(RsBlockRef::from_block_id(block_id).map_err(to_py_err)?);
        Ok(())
    }

    /// The cached reference, or `RuntimeError` if it is stale or absent.
    fn block_ref(&self) -> PyResult<PyBlockRef> {
        Ok(PyBlockRef {
            inner: self.inner.block_ref().map_err(to_py_err)?,
        })
    }

    /// Whether a usable reference is available right now.
    fn is_fresh(&self) -> bool {
        self.inner.is_fresh()
    }

    /// Age of the cached reference in seconds, or `None`.
    fn age_seconds(&self) -> Option<f64> {
        self.inner.age().map(|d| d.as_secs_f64())
    }

    fn invalidate(&self) {
        self.inner.invalidate();
    }
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// Convert a Python value into `serde_json::Value`.
///
/// Rejects anything that has no JSON representation rather than coercing it —
/// a silently stringified object would end up signed.
fn py_to_json(value: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if value.is_none() {
        return Ok(serde_json::Value::Null);
    }
    if let Ok(v) = value.extract::<bool>() {
        return Ok(serde_json::Value::Bool(v));
    }
    if let Ok(v) = value.extract::<i64>() {
        return Ok(serde_json::Value::from(v));
    }
    if let Ok(v) = value.extract::<u64>() {
        return Ok(serde_json::Value::from(v));
    }
    if let Ok(v) = value.extract::<f64>() {
        return serde_json::Number::from_f64(v)
            .map(serde_json::Value::Number)
            .ok_or_else(|| PyValueError::new_err("non-finite float has no JSON form"));
    }
    if let Ok(v) = value.extract::<String>() {
        return Ok(serde_json::Value::String(v));
    }
    if let Ok(dict) = value.downcast::<PyDict>() {
        let mut map = serde_json::Map::with_capacity(dict.len());
        for (k, v) in dict.iter() {
            let key: String = k
                .extract()
                .map_err(|_| PyValueError::new_err("operation field names must be strings"))?;
            map.insert(key, py_to_json(&v)?);
        }
        return Ok(serde_json::Value::Object(map));
    }
    if let Ok(list) = value.downcast::<PyList>() {
        return list.iter().map(|item| py_to_json(&item)).collect();
    }
    if let Ok(tuple) = value.downcast::<pyo3::types::PyTuple>() {
        return tuple.iter().map(|item| py_to_json(&item)).collect();
    }
    Err(PyValueError::new_err(format!(
        "{} has no JSON representation and cannot go into an operation",
        value.get_type().name()?
    )))
}

/// Convert a Python operation description into a `comb` operation.
///
/// Accepts `("custom_json", {...})` and `{"type": "custom_json", "value": {...}}`.
/// All 48 signable operations work, because this routes through the same JSON
/// decoder the Rust API uses — including `recurrent_transfer` and
/// `collateralized_convert`, which beem cannot build at all.
///
/// **Unknown fields are refused**, so a typo in a field name fails loudly instead
/// of silently producing a transaction that does something else.
fn operation_from_py(
    op_type: &str,
    value: &Bound<'_, PyDict>,
    _chain: RsChain,
) -> PyResult<RsOperation> {
    let mut fields = py_to_json(value.as_any())?;

    // hived's `json` and `json_metadata` fields are *strings* holding JSON, not
    // JSON objects. Every Hive client lets a caller pass the object and serializes
    // it, so accepting a dict here is convenience rather than laxity — and the
    // separators matter, because the string is what gets signed.
    if let Some(map) = fields.as_object_mut() {
        for key in [
            "json",
            "json_metadata",
            "posting_json_metadata",
            "json_meta",
        ] {
            if let Some(entry) = map.get_mut(key) {
                if !entry.is_string() {
                    let text = serde_json::to_string(entry).map_err(|e| {
                        PyValueError::new_err(format!("could not encode {key}: {e}"))
                    })?;
                    *entry = serde_json::Value::String(text);
                }
            }
        }
    }

    let described = serde_json::json!([op_type, fields]);
    RsOperation::from_json(&described).map_err(to_py_err)
}

/// Build and sign a transaction entirely offline.
///
/// `operations` is a list of `(name, fields)` tuples. `block_ref` supplies the TaPoS
/// reference — from a `TaposCache`, or from `BlockRef.from_block_id(...)`.
///
/// Returns a dict ready to POST to `network_broadcast_api.broadcast_transaction`, plus
/// the transaction id under `"trx_id"`.
///
/// No network access happens anywhere in this call.
#[pyfunction]
#[pyo3(signature = (operations, block_ref, wifs, expiration_seconds = 60, chain = None))]
fn sign_transaction(
    py: Python<'_>,
    operations: &Bound<'_, PyList>,
    block_ref: &PyBlockRef,
    wifs: Vec<String>,
    expiration_seconds: u32,
    chain: Option<&str>,
) -> PyResult<PyObject> {
    let chain = chain_from_name(chain)?;

    let mut ops = Vec::with_capacity(operations.len());
    for item in operations.iter() {
        let (name, fields): (String, Bound<'_, PyDict>) = item.extract().map_err(|_| {
            PyValueError::new_err(
                "each operation must be a (name, dict) tuple, e.g. (\"custom_json\", {...})",
            )
        })?;
        ops.push(operation_from_py(&name, &fields, chain)?);
    }

    let keys: Vec<RsPrivateKey> = wifs
        .iter()
        .map(|w| RsPrivateKey::parse(w).map_err(to_py_err))
        .collect::<PyResult<_>>()?;

    let tx = RsTransaction::new(block_ref.inner, ops, expiration_seconds).map_err(to_py_err)?;
    let trx_id = tx.id().map_err(to_py_err)?;
    let signed = tx.sign(&keys, chain).map_err(to_py_err)?;
    let json = signed.to_json().map_err(to_py_err)?;

    let out = json_to_py(py, &json)?;
    let dict = out.downcast_bound::<PyDict>(py)?;
    dict.set_item("trx_id", trx_id)?;
    Ok(out)
}

/// Compute the digest a transaction would be signed over, without signing it.
///
/// This is the exact value a differential test compares against beem's
/// `sha256(chain_id || serialized_tx)`.
#[pyfunction]
#[pyo3(signature = (operations, block_ref, expiration, chain = None))]
fn transaction_digest(
    py: Python<'_>,
    operations: &Bound<'_, PyList>,
    block_ref: &PyBlockRef,
    expiration: &str,
    chain: Option<&str>,
) -> PyResult<PyObject> {
    let chain = chain_from_name(chain)?;
    let mut ops = Vec::with_capacity(operations.len());
    for item in operations.iter() {
        let (name, fields): (String, Bound<'_, PyDict>) = item.extract()?;
        ops.push(operation_from_py(&name, &fields, chain)?);
    }
    let tx = RsTransaction {
        ref_block_num: block_ref.inner.ref_block_num,
        ref_block_prefix: block_ref.inner.ref_block_prefix,
        expiration: PointInTime::parse(expiration).map_err(to_py_err)?,
        operations: ops,
    };
    let digest = tx.digest(chain).map_err(to_py_err)?;
    Ok(PyBytes::new_bound(py, &digest).into())
}

/// Convert a `serde_json::Value` into Python objects.
fn json_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject> {
    Ok(match value {
        serde_json::Value::Null => py.None(),
        serde_json::Value::Bool(b) => b.into_py(py),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_py(py)
            } else if let Some(u) = n.as_u64() {
                u.into_py(py)
            } else {
                n.as_f64()
                    .ok_or_else(|| PyValueError::new_err("unrepresentable number"))?
                    .into_py(py)
            }
        }
        serde_json::Value::String(s) => s.into_py(py),
        serde_json::Value::Array(a) => {
            let list = PyList::empty_bound(py);
            for item in a {
                list.append(json_to_py(py, item)?)?;
            }
            list.into()
        }
        serde_json::Value::Object(o) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in o {
                dict.set_item(k, json_to_py(py, v)?)?;
            }
            dict.into()
        }
    })
}

/// Encrypt a memo to `to_key`, returning the `#`-prefixed string.
///
/// The plaintext is written as a Graphene string (varint length, then UTF-8), which is
/// what hive-js, dhive, Hive Keychain and HiveSigner all do. beem omits that prefix on
/// encode while trying to strip one on decode.
#[pyfunction]
#[pyo3(signature = (from_wif, to_public_key, message, nonce = None))]
fn encode_memo(
    from_wif: &str,
    to_public_key: &str,
    message: &str,
    nonce: Option<u64>,
) -> PyResult<String> {
    let from = RsPrivateKey::parse(from_wif).map_err(to_py_err)?;
    let to = RsPublicKey::from_prefixed_any(to_public_key).map_err(to_py_err)?;
    match nonce {
        Some(n) => comb_core::memo::encode_with_nonce(&from, &to, message, n),
        None => comb_core::memo::encode(&from, &to, message),
    }
    .map_err(to_py_err)
}

/// Decrypt a `#`-prefixed memo with either side's memo key.
///
/// Accepts memos written without the varint prefix, so anything beem produced can
/// still be read.
#[pyfunction]
#[pyo3(signature = (wif, memo))]
fn decode_memo(wif: &str, memo: &str) -> PyResult<String> {
    let key = RsPrivateKey::parse(wif).map_err(to_py_err)?;
    comb_core::memo::decode(&key, memo).map_err(to_py_err)
}

/// Whether a memo field holds an encrypted memo.
#[pyfunction]
fn is_encrypted_memo(memo: &str) -> bool {
    comb_core::memo::is_encrypted(memo)
}

/// Recover the public key that signed a 32-byte digest, verifying as it goes.
///
/// Raises unless the signature genuinely verifies. Recovery alone proves nothing:
/// it succeeds for essentially any well-formed 65-byte input, which is why beem's
/// `verify_message` could return a plausible-looking key for a bogus signature.
#[pyfunction]
#[pyo3(signature = (digest, signature))]
fn recover_digest(digest: &[u8], signature: &str) -> PyResult<PyPublicKey> {
    let digest: [u8; 32] = digest.try_into().map_err(|_| {
        PyValueError::new_err(format!("digest must be 32 bytes, got {}", digest.len()))
    })?;
    let sig = rs_sign::Signature::from_hex(signature).map_err(to_py_err)?;
    Ok(PyPublicKey {
        inner: rs_sign::recover(&digest, &sig).map_err(to_py_err)?,
    })
}

/// Generate a new BIP-39 mnemonic.
#[pyfunction]
#[pyo3(signature = (strength = 256))]
fn generate_mnemonic(strength: usize) -> PyResult<String> {
    comb_core::bip39::Mnemonic::generate(strength)
        .map(|m| m.phrase().to_string())
        .map_err(to_py_err)
}

/// Validate a BIP-39 mnemonic's checksum and word list.
#[pyfunction]
fn validate_mnemonic(mnemonic: &str) -> bool {
    comb_core::bip39::Mnemonic::parse(mnemonic).is_ok()
}

/// The transaction id of an unsigned operation set, without signing it.
///
/// Useful for pre-registering an id before broadcast.
#[pyfunction]
#[pyo3(signature = (operations, block_ref, expiration, chain = None))]
fn transaction_id(
    operations: &Bound<'_, PyList>,
    block_ref: &PyBlockRef,
    expiration: &str,
    chain: Option<&str>,
) -> PyResult<String> {
    let chain = chain_from_name(chain)?;
    let mut ops = Vec::with_capacity(operations.len());
    for item in operations.iter() {
        let (name, fields): (String, Bound<'_, PyDict>) = item.extract()?;
        ops.push(operation_from_py(&name, &fields, chain)?);
    }
    let tx = RsTransaction {
        ref_block_num: block_ref.inner.ref_block_num,
        ref_block_prefix: block_ref.inner.ref_block_prefix,
        expiration: PointInTime::parse(expiration).map_err(to_py_err)?,
        operations: ops,
    };
    tx.id().map_err(to_py_err)
}

/// The chain id this build signs against, as hex.
#[pyfunction]
#[pyo3(signature = (chain = None))]
fn chain_id(chain: Option<&str>) -> PyResult<String> {
    Ok(chain_from_name(chain)?.chain_id().to_hex())
}

#[pymodule]
fn comb(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<PyPrivateKey>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyBlockRef>()?;
    m.add_class::<PyTaposCache>()?;
    m.add_function(wrap_pyfunction!(sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(verify_message, m)?)?;
    m.add_function(wrap_pyfunction!(recover_message, m)?)?;
    m.add_function(wrap_pyfunction!(sign_transaction, m)?)?;
    m.add_function(wrap_pyfunction!(transaction_digest, m)?)?;
    m.add_function(wrap_pyfunction!(chain_id, m)?)?;
    m.add_function(wrap_pyfunction!(encode_memo, m)?)?;
    m.add_function(wrap_pyfunction!(decode_memo, m)?)?;
    m.add_function(wrap_pyfunction!(is_encrypted_memo, m)?)?;
    m.add_function(wrap_pyfunction!(generate_mnemonic, m)?)?;
    m.add_function(wrap_pyfunction!(validate_mnemonic, m)?)?;
    m.add_function(wrap_pyfunction!(transaction_id, m)?)?;
    m.add_function(wrap_pyfunction!(recover_digest, m)?)?;
    Ok(())
}
