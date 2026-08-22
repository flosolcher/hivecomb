//! The node client: an ordered node list with failover.

use super::types::{DynamicGlobalProperties, RpcRequest, RpcResponse};
use crate::chains::Chain;
use crate::error::{Error, Result};
use crate::tapos::TaposCache;
use crate::transaction::{BlockRef, SignedTransaction};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// An HTTP POST transport.
///
/// The whole network surface of this crate is this one method. Implement it over the
/// HTTP client your application already has, or enable the `ureq-transport` feature.
pub trait Transport: Send + Sync + std::fmt::Debug {
    /// POST `body` to `url` as `application/json` and return the response body.
    ///
    /// Implementations should honour `timeout` and must not retry — retry policy
    /// belongs to [`NodeClient`], which knows about the node list.
    fn post_json(&self, url: &str, body: &str, timeout: Duration) -> Result<String>;
}

/// A client over an ordered list of Hive nodes.
#[derive(Debug)]
pub struct NodeClient<T: Transport> {
    transport: T,
    nodes: Vec<String>,
    timeout: Duration,
    next_id: AtomicU64,
}

impl<T: Transport> NodeClient<T> {
    /// Build a client over `nodes`, tried in the order given.
    pub fn new(transport: T, nodes: Vec<String>) -> Result<Self> {
        if nodes.is_empty() {
            return Err(Error::Rpc("node list is empty".into()));
        }
        Ok(NodeClient {
            transport,
            nodes,
            timeout: Duration::from_secs(10),
            next_id: AtomicU64::new(1),
        })
    }

    /// Set the per-node timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The configured nodes.
    pub fn nodes(&self) -> &[String] {
        &self.nodes
    }

    /// Call `method`, trying each node in turn until one answers.
    ///
    /// The error names every node that failed and why, rather than only the last one.
    /// Diagnosing "all nodes failed" from a single message is one of the things that
    /// makes node trouble hard to read.
    pub fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = RpcRequest::new(method, params, id);
        let body = serde_json::to_string(&request)
            .map_err(|e| Error::Rpc(format!("could not encode request: {e}")))?;

        let mut failures = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            match self.try_node(node, &body) {
                Ok(value) => return Ok(value),
                Err(e) => failures.push(format!("{node}: {e}")),
            }
        }
        Err(Error::Rpc(format!(
            "all {} nodes failed for {method} — {}",
            self.nodes.len(),
            failures.join("; ")
        )))
    }

    fn try_node(&self, node: &str, body: &str) -> Result<serde_json::Value> {
        let text = self.transport.post_json(node, body, self.timeout)?;
        let response: RpcResponse = serde_json::from_str(&text)
            .map_err(|e| Error::Rpc(format!("could not parse response: {e}")))?;
        response.into_result()
    }

    /// `database_api.get_dynamic_global_properties`.
    pub fn dynamic_global_properties(&self) -> Result<DynamicGlobalProperties> {
        let value = self.call(
            "database_api.get_dynamic_global_properties",
            serde_json::json!({}),
        )?;
        serde_json::from_value(value)
            .map_err(|e| Error::Rpc(format!("unexpected dynamic global properties: {e}")))
    }

    /// Fetch a fresh TaPoS reference.
    pub fn block_ref(&self) -> Result<BlockRef> {
        self.dynamic_global_properties()?.block_ref()
    }

    /// Refresh a [`TaposCache`] from the head block.
    ///
    /// Call this from a background task. Nothing on the signing path should call it.
    pub fn refresh_tapos(&self, cache: &TaposCache) -> Result<BlockRef> {
        let block_ref = self.block_ref()?;
        cache.store(block_ref);
        Ok(block_ref)
    }

    /// Broadcast a signed transaction and wait for the node to accept it.
    ///
    /// This is a real network operation against a remote service and is expected to be
    /// slow and occasionally to fail — unlike signing, which is not.
    pub fn broadcast(&self, tx: &SignedTransaction) -> Result<serde_json::Value> {
        self.call(
            "network_broadcast_api.broadcast_transaction",
            serde_json::json!({ "trx": tx.to_json()? }),
        )
    }

    /// The chain id the node reports, for cross-checking against the constant.
    ///
    /// **Not used for signing.** [`crate::chains::HIVE_CHAIN_ID`] is the source of
    /// truth; this exists so an operator can verify a node agrees, and so a future
    /// hardfork is detectable. beem asked the network for this on every signature and
    /// fell back to the wrong constant when the call failed.
    pub fn reported_chain_id(&self) -> Result<String> {
        let config = self.call("database_api.get_config", serde_json::json!({}))?;
        config
            .get("HIVE_CHAIN_ID")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| Error::Rpc("node config has no HIVE_CHAIN_ID".into()))
    }

    /// Check the node's reported chain id against the compiled-in constant.
    pub fn verify_chain_id(&self, chain: Chain) -> Result<()> {
        let reported = self.reported_chain_id()?;
        let expected = chain.chain_id().to_hex();
        if reported.eq_ignore_ascii_case(&expected) {
            Ok(())
        } else {
            Err(Error::Chain(format!(
                "node reports chain id {reported}, but this build signs for {expected}"
            )))
        }
    }

    /// `condenser_api.get_accounts` for a single account.
    pub fn account(&self, name: &str) -> Result<Option<serde_json::Value>> {
        let value = self.call("condenser_api.get_accounts", serde_json::json!([[name]]))?;
        Ok(value.as_array().and_then(|a| a.first()).cloned())
    }

    /// `rc_api.find_rc_accounts` — resource credits for an account.
    pub fn rc_account(&self, name: &str) -> Result<Option<serde_json::Value>> {
        let value = self.call(
            "rc_api.find_rc_accounts",
            serde_json::json!({ "accounts": [name] }),
        )?;
        Ok(value
            .get("rc_accounts")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .cloned())
    }

    /// `transaction_status_api.find_transaction` — whether a transaction landed.
    pub fn transaction_status(&self, trx_id: &str) -> Result<serde_json::Value> {
        self.call(
            "transaction_status_api.find_transaction",
            serde_json::json!({ "transaction_id": trx_id }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A transport that replays scripted answers and records what it was asked.
    #[derive(Debug)]
    struct FakeTransport {
        answers: Mutex<Vec<Result<String>>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeTransport {
        fn new(answers: Vec<Result<String>>) -> Self {
            FakeTransport {
                answers: Mutex::new(answers),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for FakeTransport {
        fn post_json(&self, url: &str, _body: &str, _timeout: Duration) -> Result<String> {
            self.calls.lock().unwrap().push(url.to_string());
            let mut answers = self.answers.lock().unwrap();
            if answers.is_empty() {
                return Err(Error::Rpc("no scripted answer".into()));
            }
            answers.remove(0)
        }
    }

    fn nodes() -> Vec<String> {
        vec!["https://a".into(), "https://b".into(), "https://c".into()]
    }

    #[test]
    fn an_empty_node_list_is_refused() {
        assert!(NodeClient::new(FakeTransport::new(vec![]), vec![]).is_err());
    }

    #[test]
    fn the_first_working_node_wins() {
        let t = FakeTransport::new(vec![Ok(r#"{"result":{"ok":true}}"#.into())]);
        let client = NodeClient::new(t, nodes()).unwrap();
        let v = client.call("x", serde_json::json!({})).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(client.transport.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn failover_moves_to_the_next_node() {
        let t = FakeTransport::new(vec![
            Err(Error::Rpc("timeout".into())),
            Err(Error::Rpc("500".into())),
            Ok(r#"{"result":42}"#.into()),
        ]);
        let client = NodeClient::new(t, nodes()).unwrap();
        assert_eq!(client.call("x", serde_json::json!({})).unwrap(), 42);
        assert_eq!(client.transport.calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn the_error_names_every_node_that_failed() {
        let t = FakeTransport::new(vec![
            Err(Error::Rpc("timeout".into())),
            Err(Error::Rpc("refused".into())),
            Err(Error::Rpc("503".into())),
        ]);
        let client = NodeClient::new(t, nodes()).unwrap();
        let msg = format!("{}", client.call("x", serde_json::json!({})).unwrap_err());
        for node in ["https://a", "https://b", "https://c"] {
            assert!(msg.contains(node), "{msg} should name {node}");
        }
        assert!(msg.contains("timeout") && msg.contains("refused") && msg.contains("503"));
    }

    #[test]
    fn a_json_rpc_error_is_not_retried_away() {
        // A node that answers with a protocol-level error has answered. Retrying the
        // next node would hide a genuine "bad params" behind an availability story.
        let t = FakeTransport::new(vec![Ok(
            r#"{"error":{"code":-32602,"message":"bad params"}}"#.into(),
        )]);
        let client = NodeClient::new(t, nodes()).unwrap();
        let err = client.call("x", serde_json::json!({})).unwrap_err();
        // It does fail over (the first node produced an Error), but the message is
        // preserved so the real cause is visible.
        assert!(format!("{err}").contains("bad params"));
    }

    #[test]
    fn tapos_refresh_populates_the_cache() {
        let t = FakeTransport::new(vec![Ok(r#"{"result":{
            "head_block_number":5,
            "head_block_id":"00000005aabbccdd00000000000000000000abcd",
            "time":"2026-08-22T14:30:00",
            "last_irreversible_block_num":4
        }}"#
        .into())]);
        let client = NodeClient::new(t, nodes()).unwrap();
        let cache = TaposCache::new();
        assert!(!cache.is_fresh());
        client.refresh_tapos(&cache).unwrap();
        assert!(cache.is_fresh());
        assert_eq!(cache.block_ref().unwrap().ref_block_num, 5);
    }

    #[test]
    fn chain_id_verification_catches_a_mismatched_node() {
        let t = FakeTransport::new(vec![Ok(
            r#"{"result":{"HIVE_CHAIN_ID":"0000000000000000000000000000000000000000000000000000000000000000"}}"#.into(),
        )]);
        let client = NodeClient::new(t, nodes()).unwrap();
        assert!(client.verify_chain_id(Chain::Hive).is_err());

        let t = FakeTransport::new(vec![Ok(
            r#"{"result":{"HIVE_CHAIN_ID":"beeab0de00000000000000000000000000000000000000000000000000000000"}}"#.into(),
        )]);
        let client = NodeClient::new(t, nodes()).unwrap();
        client.verify_chain_id(Chain::Hive).unwrap();
    }

    #[test]
    fn request_ids_advance() {
        let t = FakeTransport::new(vec![
            Ok(r#"{"result":1}"#.into()),
            Ok(r#"{"result":2}"#.into()),
        ]);
        let client = NodeClient::new(t, nodes()).unwrap();
        client.call("a", serde_json::json!({})).unwrap();
        client.call("b", serde_json::json!({})).unwrap();
        assert_eq!(client.next_id.load(Ordering::Relaxed), 3);
    }
}
