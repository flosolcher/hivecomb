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

use comb_core::asset::Amount as RsAmount;
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

/// Convert a Python operation description into a `comb` operation.
///
/// Accepts `("custom_json", {...})` or `{"type": "custom_json", "value": {...}}`.
/// **Unknown keys are refused**, so a typo in a field name fails loudly instead of
/// silently producing a transaction that does something else.
fn operation_from_py(
    op_type: &str,
    value: &Bound<'_, PyDict>,
    chain: RsChain,
) -> PyResult<RsOperation> {
    fn get_str(d: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
        d.get_item(key)?
            .ok_or_else(|| PyValueError::new_err(format!("missing field {key:?}")))?
            .extract()
    }
    fn get_str_list(d: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
        match d.get_item(key)? {
            None => Ok(Vec::new()),
            Some(v) => v.extract(),
        }
    }
    fn reject_unknown(d: &Bound<'_, PyDict>, allowed: &[&str]) -> PyResult<()> {
        for key in d.keys() {
            let name: String = key.extract()?;
            if !allowed.contains(&name.as_str()) {
                return Err(PyValueError::new_err(format!(
                    "unknown field {name:?}; allowed fields are {allowed:?}"
                )));
            }
        }
        Ok(())
    }

    match op_type {
        "custom_json" => {
            reject_unknown(
                value,
                &["required_auths", "required_posting_auths", "id", "json"],
            )?;
            // `json` may be given as a string or as any JSON-serializable object.
            let json_field = value
                .get_item("json")?
                .ok_or_else(|| PyValueError::new_err("missing field \"json\""))?;
            let json = match json_field.extract::<String>() {
                Ok(s) => s,
                Err(_) => {
                    let dumps = json_field.py().import_bound("json")?.getattr("dumps")?;
                    let kwargs = PyDict::new_bound(json_field.py());
                    kwargs.set_item("separators", (",", ":"))?;
                    dumps.call((json_field,), Some(&kwargs))?.extract()?
                }
            };
            Ok(RsOperation::CustomJson(RsCustomJson {
                required_auths: get_str_list(value, "required_auths")?,
                required_posting_auths: get_str_list(value, "required_posting_auths")?,
                id: get_str(value, "id")?,
                json,
            }))
        }
        "transfer" => {
            reject_unknown(value, &["from", "to", "amount", "memo"])?;
            let amount_text: String = get_str(value, "amount")?;
            Ok(RsOperation::Transfer(RsTransfer {
                from: get_str(value, "from")?,
                to: get_str(value, "to")?,
                amount: RsAmount::parse(&amount_text, chain).map_err(to_py_err)?,
                memo: value
                    .get_item("memo")?
                    .map(|v| v.extract::<String>())
                    .transpose()?
                    .unwrap_or_default(),
            }))
        }
        "vote" => {
            reject_unknown(value, &["voter", "author", "permlink", "weight"])?;
            let weight: i64 = value
                .get_item("weight")?
                .ok_or_else(|| PyValueError::new_err("missing field \"weight\""))?
                .extract()?;
            let weight = i16::try_from(weight).map_err(|_| {
                PyValueError::new_err("vote weight must fit in an int16 (-10000..=10000)")
            })?;
            Ok(RsOperation::Vote(RsVote {
                voter: get_str(value, "voter")?,
                author: get_str(value, "author")?,
                permlink: get_str(value, "permlink")?,
                weight,
            }))
        }
        other => Err(PyValueError::new_err(format!(
            "operation {other:?} is not yet exposed through the Python bindings; \
             build it through the Rust API or open an issue"
        ))),
    }
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
    Ok(())
}
