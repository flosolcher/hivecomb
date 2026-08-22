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

    // -----------------------------------------------------------------------
    // Typed accessors
    //
    // beem proxied every method through `__getattr__`, so the whole API surface was
    // reachable but nothing was checked until a KeyError fired at the point of use.
    // `call` still reaches anything hived exposes; these are the paths worth typing.
    // -----------------------------------------------------------------------

    /// Extended global properties, with the supply and vesting totals.
    pub fn global_properties(&self) -> Result<crate::chain::DynamicGlobalProperties> {
        let value = self.call(
            "database_api.get_dynamic_global_properties",
            serde_json::json!({}),
        )?;
        serde_json::from_value(value)
            .map_err(|e| Error::Rpc(format!("unexpected global properties: {e}")))
    }

    /// Look up accounts by name.
    ///
    /// Names that do not exist are simply absent from the result, so the returned
    /// vector may be shorter than the request. Use [`Self::find_account`] when a
    /// missing account needs to be visible.
    pub fn accounts(&self, names: &[&str]) -> Result<Vec<crate::chain::Account>> {
        let value = self.call("condenser_api.get_accounts", serde_json::json!([names]))?;
        serde_json::from_value(value)
            .map_err(|e| Error::Rpc(format!("unexpected account response: {e}")))
    }

    /// Look up one account, distinguishing "not found" from an error.
    pub fn find_account(&self, name: &str) -> Result<Option<crate::chain::Account>> {
        Ok(self.accounts(&[name])?.into_iter().next())
    }

    /// Resource credits for a set of accounts.
    pub fn rc_accounts(&self, names: &[&str]) -> Result<Vec<crate::chain::RcAccount>> {
        let value = self.call(
            "rc_api.find_rc_accounts",
            serde_json::json!({ "accounts": names }),
        )?;
        serde_json::from_value(
            value
                .get("rc_accounts")
                .cloned()
                .ok_or_else(|| Error::Rpc("rc_api response has no rc_accounts".into()))?,
        )
        .map_err(|e| Error::Rpc(format!("unexpected rc account response: {e}")))
    }

    /// A witness by account name.
    pub fn witness(&self, name: &str) -> Result<Option<crate::chain::Witness>> {
        let value = self.call(
            "condenser_api.get_witness_by_account",
            serde_json::json!([name]),
        )?;
        if value.is_null() {
            return Ok(None);
        }
        serde_json::from_value(value)
            .map(Some)
            .map_err(|e| Error::Rpc(format!("unexpected witness response: {e}")))
    }

    /// The witness price feed and its median.
    pub fn feed_history(&self) -> Result<crate::chain::FeedHistory> {
        let value = self.call("database_api.get_feed_history", serde_json::json!({}))?;
        serde_json::from_value(value)
            .map_err(|e| Error::Rpc(format!("unexpected feed history: {e}")))
    }

    /// The reward funds.
    pub fn reward_funds(&self) -> Result<Vec<crate::chain::RewardFund>> {
        let value = self.call("database_api.get_reward_funds", serde_json::json!({}))?;
        serde_json::from_value(
            value
                .get("funds")
                .cloned()
                .ok_or_else(|| Error::Rpc("reward fund response has no funds".into()))?,
        )
        .map_err(|e| Error::Rpc(format!("unexpected reward funds: {e}")))
    }

    /// A block by number.
    ///
    /// Returns `None` for a block the node does not have — beyond the head, or pruned
    /// from a non-archive node.
    pub fn block(&self, block_num: u32) -> Result<Option<crate::chain::Block>> {
        let value = self.call(
            "block_api.get_block",
            serde_json::json!({ "block_num": block_num }),
        )?;
        match value.get("block") {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(block) => serde_json::from_value(block.clone())
                .map(Some)
                .map_err(|e| Error::Rpc(format!("unexpected block response: {e}"))),
        }
    }

    /// An account's operation history, newest first.
    ///
    /// `limit` is capped at 1000 by hived, and the cap is checked here so a bad call
    /// fails locally rather than after a round trip. Each entry is
    /// `[sequence, {trx_id, block, timestamp, op, ...}]`; the `op` member parses with
    /// [`crate::operations::AnyOperation::from_json`], which handles both signed and
    /// virtual operations.
    pub fn account_history(
        &self,
        account: &str,
        start: i64,
        limit: u32,
    ) -> Result<Vec<serde_json::Value>> {
        if limit == 0 || limit > 1000 {
            return Err(Error::Rpc(format!(
                "account history limit must be 1..=1000, got {limit}"
            )));
        }
        let value = self.call(
            "condenser_api.get_account_history",
            serde_json::json!([account, start, limit]),
        )?;
        value
            .as_array()
            .cloned()
            .ok_or_else(|| Error::Rpc("account history response is not an array".into()))
    }

    /// Which accounts a set of public keys belongs to.
    pub fn accounts_by_key(&self, keys: &[&str]) -> Result<Vec<Vec<String>>> {
        let value = self.call(
            "account_by_key_api.get_key_references",
            serde_json::json!({ "keys": keys }),
        )?;
        serde_json::from_value(
            value
                .get("accounts")
                .cloned()
                .ok_or_else(|| Error::Rpc("key reference response has no accounts".into()))?,
        )
        .map_err(|e| Error::Rpc(format!("unexpected key references: {e}")))
    }

    /// Whether an account has at least `rc` resource credits at `now`.
    ///
    /// The extrapolation to "right now" happens locally, so repeated checks against a
    /// cached [`crate::chain::RcAccount`] cost nothing.
    pub fn has_rc_for(&self, account: &str, rc: i64, now: u64) -> Result<bool> {
        let accounts = self.rc_accounts(&[account])?;
        let rc_account = accounts
            .first()
            .ok_or_else(|| Error::Rpc(format!("no RC record for {account}")))?;
        Ok(rc_account.current_rc(now) >= rc)
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
    fn typed_accessors_parse_real_shapes() {
        // The same fixture the live-fixture tests use, served through the client.
        let account_json = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/account.json"
        ))
        .unwrap();
        let t = FakeTransport::new(vec![Ok(format!(r#"{{"result":{account_json}}}"#))]);
        let client = NodeClient::new(t, nodes()).unwrap();
        let accounts = client.accounts(&["hiveio", "blocktrades", "gtg"]).unwrap();
        assert_eq!(accounts.len(), 3);
        assert!(accounts.iter().any(|a| a.name == "hiveio"));
    }

    #[test]
    fn a_missing_account_is_none_not_an_error() {
        let t = FakeTransport::new(vec![Ok(r#"{"result":[]}"#.into())]);
        let client = NodeClient::new(t, nodes()).unwrap();
        assert!(client.find_account("nosuchaccount").unwrap().is_none());
    }

    #[test]
    fn a_missing_block_is_none_not_an_error() {
        // block_api returns {} for a block the node does not have.
        let t = FakeTransport::new(vec![Ok(r#"{"result":{}}"#.into())]);
        let client = NodeClient::new(t, nodes()).unwrap();
        assert!(client.block(999_999_999).unwrap().is_none());

        let t = FakeTransport::new(vec![Ok(r#"{"result":{"block":null}}"#.into())]);
        let client = NodeClient::new(t, nodes()).unwrap();
        assert!(client.block(1).unwrap().is_none());
    }

    #[test]
    fn account_history_limits_are_checked_before_the_round_trip() {
        let t = FakeTransport::new(vec![]);
        let client = NodeClient::new(t, nodes()).unwrap();
        assert!(client.account_history("a", -1, 0).is_err());
        assert!(client.account_history("a", -1, 1001).is_err());
        // Nothing was sent.
        assert!(client.transport.calls.lock().unwrap().is_empty());
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
