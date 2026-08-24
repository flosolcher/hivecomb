//! The node client: an ordered node list with failover.

use super::health::{head_block_of, HealthPolicy, HealthTracker, NodeHealth};
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
    passes: u32,
    initial_backoff: Duration,
    next_id: AtomicU64,
    health: Option<HealthTracker>,
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
            passes: 1,
            initial_backoff: Duration::from_millis(250),
            next_id: AtomicU64::new(1),
            health: None,
        })
    }

    /// Set the per-node timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Retry the whole node list this many times before giving up.
    ///
    /// Each pass waits longer than the last. One pass (the default) is right
    /// for a call on a deadline — a submit window, say — where failing fast and
    /// letting the caller decide beats sleeping. More passes suit a background
    /// task, where an outage that clears in a second should not surface as an
    /// error.
    pub fn with_retries(mut self, passes: u32, initial_backoff: Duration) -> Self {
        self.passes = passes.max(1);
        self.initial_backoff = initial_backoff;
        self
    }

    /// Remember which nodes are failing, and try them last.
    ///
    /// Off by default, and deliberately so: without it this client walks the node list
    /// from the front every time, which is predictable and is the right mechanism for
    /// an application that has failover policy of its own.
    ///
    /// Turn it on for a **long-running process**, where the default has one sharp edge:
    /// if the first node is down, every call pays its full timeout before reaching a
    /// node that answers. A ten-second timeout and a node that stays down makes every
    /// request a ten-second request.
    ///
    /// Health only ever reorders the list. No node is excluded, so a period in which
    /// every node is unwell still tries every node — see [`HealthTracker::order`].
    ///
    /// ```no_run
    /// # use hivecomb::rpc::{HealthPolicy, NodeClient, UreqTransport, DEFAULT_NODES};
    /// let nodes = DEFAULT_NODES.iter().map(|s| s.to_string()).collect();
    /// let client = NodeClient::new(UreqTransport::default(), nodes)?
    ///     .with_health_tracking(HealthPolicy::default());
    /// # Ok::<(), hivecomb::Error>(())
    /// ```
    pub fn with_health_tracking(mut self, policy: HealthPolicy) -> Self {
        self.health = Some(HealthTracker::new(self.nodes.len(), policy));
        self
    }

    /// What the health tracker believes about each node, in node-list order.
    ///
    /// `None` when health tracking is off. Pair it with [`NodeClient::nodes`], which is
    /// in the same order.
    pub fn health(&self) -> Option<Vec<NodeHealth>> {
        self.health.as_ref().map(HealthTracker::snapshot)
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
        for pass in 0..self.passes {
            if pass > 0 {
                // Exponential backoff between passes, capped so a long retry
                // budget cannot turn into an unbounded sleep.
                let wait = self
                    .initial_backoff
                    .saturating_mul(1u32 << (pass - 1).min(6))
                    .min(Duration::from_secs(30));
                std::thread::sleep(wait);
                failures.push(format!("(retry pass {} after {:?})", pass + 1, wait));
            }
            for index in self.call_order(method) {
                let node = &self.nodes[index];
                match self.try_node(node, &body) {
                    Ok(value) => {
                        if let Some(health) = &self.health {
                            health.record_success(index, method);
                            // Staleness is observed from responses that happen to carry
                            // a head block rather than probed for, so tracking it costs
                            // the caller no extra request.
                            if let Some(head) = head_block_of(&value) {
                                health.observe_head_block(index, head);
                            }
                        }
                        return Ok(value);
                    }
                    Err(e) => {
                        if let Some(health) = &self.health {
                            health.record_failure(index, method);
                        }
                        failures.push(format!("{node}: {e}"));
                    }
                }
            }
        }
        Err(Error::Rpc(format!(
            "all {} node(s) failed for {method} over {} pass(es) — {}",
            self.nodes.len(),
            self.passes,
            failures.join("; ")
        )))
    }

    /// The order to try nodes in. Without health tracking this is the configured
    /// order, which is what the module documentation promises.
    fn call_order(&self, method: &str) -> Vec<usize> {
        match &self.health {
            Some(health) => health.order(method),
            None => (0..self.nodes.len()).collect(),
        }
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

    /// Every operation the chain recorded for a block.
    ///
    /// This is the **only** way to reach virtual operations. They are emitted by
    /// consensus rather than carried in a transaction, so they do not appear in
    /// `block_api.get_block` at all — filtering a block's transactions for them
    /// yields nothing rather than an error.
    pub fn ops_in_block(&self, block_num: u32, only_virtual: bool) -> Result<Vec<BlockOperation>> {
        let value = self.call(
            "condenser_api.get_ops_in_block",
            serde_json::json!([block_num, only_virtual]),
        )?;
        serde_json::from_value(value)
            .map_err(|e| Error::Rpc(format!("unexpected get_ops_in_block response: {e}")))
    }

    /// Operations across a range of blocks, inclusive.
    ///
    /// One request per block: `condenser_api` has no batched form, and
    /// `account_history_api.enum_virtual_ops` covers only the virtual half.
    pub fn ops_in_block_range(
        &self,
        from: u32,
        to: u32,
        only_virtual: bool,
    ) -> Result<Vec<BlockOperation>> {
        if to < from {
            return Err(Error::Rpc(format!(
                "block range {from}..={to} runs backwards"
            )));
        }
        let mut out = Vec::new();
        for block_num in from..=to {
            out.extend(self.ops_in_block(block_num, only_virtual)?);
        }
        Ok(out)
    }

    /// Iterate blocks from `start`, following the head.
    ///
    /// The iterator is lazy and never ends on its own — take from it, or use
    /// [`BlockStream::until`]. It sleeps between polls rather than spinning,
    /// and yields an error item rather than stopping when a call fails, so a
    /// transient outage does not silently end a stream.
    pub fn stream_blocks(&self, start: Option<u32>, mode: StreamMode) -> BlockStream<'_, T> {
        BlockStream {
            client: self,
            next: start,
            stop: None,
            mode,
            head: 0,
            poll_interval: Duration::from_secs(3),
        }
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

/// One operation as `get_ops_in_block` reports it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockOperation {
    /// `[name, fields]`, the condenser shape.
    pub op: serde_json::Value,
    /// Block this operation was included in.
    #[serde(default)]
    pub block: u32,
    /// Transaction id. Empty for a virtual operation, which belongs to no transaction.
    #[serde(default)]
    pub trx_id: String,
    /// Position of the transaction within the block.
    #[serde(default)]
    pub trx_in_block: u32,
    /// Position of the operation within the transaction.
    #[serde(default)]
    pub op_in_trx: u32,
    /// True for an operation the chain produced itself rather than one anybody signed.
    /// These never appear in `block_api.get_block`; see `ops_in_block`.
    #[serde(default)]
    pub virtual_op: bool,
    /// The block's timestamp, not the operation's.
    #[serde(default)]
    pub timestamp: String,
}

impl BlockOperation {
    /// Decode into a typed operation, signed or virtual.
    pub fn parse(&self) -> Result<crate::operations::AnyOperation> {
        crate::operations::AnyOperation::from_json(&self.op)
    }

    /// The operation's name, without decoding the payload.
    pub fn name(&self) -> Option<&str> {
        self.op.as_array()?.first()?.as_str()
    }
}

/// Which head a stream follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamMode {
    /// Follow the irreversible head: blocks that can no longer be reverted.
    ///
    /// About a minute behind, and the right default for anything that acts on
    /// what it sees.
    Irreversible,
    /// Follow the head block, as produced.
    ///
    /// Faster, but a block here can still be orphaned by a fork — so treat what
    /// it reports as provisional.
    Head,
}

/// A lazy iterator over blocks. See [`NodeClient::stream_blocks`].
#[derive(Debug)]
pub struct BlockStream<'a, T: Transport> {
    client: &'a NodeClient<T>,
    next: Option<u32>,
    stop: Option<u32>,
    mode: StreamMode,
    head: u32,
    poll_interval: Duration,
}

impl<'a, T: Transport> BlockStream<'a, T> {
    /// Stop after this block number.
    pub fn until(mut self, stop: u32) -> Self {
        self.stop = Some(stop);
        self
    }

    /// How long to wait when the stream has caught up with the head.
    pub fn poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    fn current_head(&self) -> Result<u32> {
        let props = self.client.dynamic_global_properties()?;
        Ok(match self.mode {
            StreamMode::Irreversible => props.last_irreversible_block_num,
            StreamMode::Head => props.head_block_number,
        })
    }
}

impl<T: Transport> Iterator for BlockStream<'_, T> {
    type Item = Result<crate::chain::Block>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let wanted = match self.next {
                Some(n) => n,
                None => match self.current_head() {
                    Ok(head) => {
                        self.head = head;
                        head
                    }
                    Err(e) => return Some(Err(e)),
                },
            };

            if let Some(stop) = self.stop {
                if wanted > stop {
                    return None;
                }
            }

            if wanted > self.head {
                match self.current_head() {
                    Ok(head) => self.head = head,
                    Err(e) => return Some(Err(e)),
                }
                if wanted > self.head {
                    std::thread::sleep(self.poll_interval);
                    continue;
                }
            }

            self.next = Some(wanted + 1);
            return match self.client.block(wanted) {
                // A block the node does not have yet: wait rather than ending.
                Ok(None) => {
                    self.next = Some(wanted);
                    std::thread::sleep(self.poll_interval);
                    continue;
                }
                Ok(Some(block)) => Some(Ok(block)),
                Err(e) => Some(Err(e)),
            };
        }
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

    /// A transport that fails for a named set of hosts and answers for the rest,
    /// recording every URL it was asked for. Unlike `FakeTransport` this is keyed on
    /// the node rather than on call order, which is what a health test needs.
    #[derive(Debug)]
    struct PerNodeTransport {
        dead: Vec<String>,
        calls: Mutex<Vec<String>>,
        body: String,
    }

    impl PerNodeTransport {
        fn new(dead: &[&str]) -> Self {
            PerNodeTransport {
                dead: dead.iter().map(|s| s.to_string()).collect(),
                calls: Mutex::new(Vec::new()),
                body: r#"{"result":{"ok":true}}"#.to_string(),
            }
        }
        fn seen(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Transport for PerNodeTransport {
        fn post_json(&self, url: &str, _body: &str, _timeout: Duration) -> Result<String> {
            self.calls.lock().unwrap().push(url.to_string());
            if self.dead.iter().any(|d| d == url) {
                return Err(Error::Rpc("refused".into()));
            }
            Ok(self.body.clone())
        }
    }

    /// Two failures is the default threshold's worth for our purposes; the default
    /// policy needs three, so tests that want a cooldown say so explicitly.
    fn quick_policy() -> HealthPolicy {
        HealthPolicy {
            failures_before_cooldown: 2,
            api_failures_before_cooldown: 2,
            ..Default::default()
        }
    }

    #[test]
    fn without_health_tracking_a_dead_first_node_is_retried_every_call() {
        // The documented default, and the behaviour the health tracker exists to
        // offer an alternative to. If this ever stops holding, the opt-in is no
        // longer opt-in.
        let client = NodeClient::new(PerNodeTransport::new(&["https://a"]), nodes()).unwrap();
        for _ in 0..3 {
            client.call("x", serde_json::json!({})).unwrap();
        }
        let seen = client.transport.seen();
        assert_eq!(
            seen.iter().filter(|u| *u == "https://a").count(),
            3,
            "the dead node must be tried on every call: {seen:?}"
        );
    }

    #[test]
    fn with_health_tracking_a_dead_first_node_stops_being_tried_first() {
        let client = NodeClient::new(PerNodeTransport::new(&["https://a"]), nodes())
            .unwrap()
            .with_health_tracking(quick_policy());

        // Two calls to cross the failure threshold, then three more that should not
        // touch the dead node at all.
        for _ in 0..5 {
            client.call("x", serde_json::json!({})).unwrap();
        }

        // Call 1 and 2 each try a (failing) then b. That is two failures on this
        // method, which cools the pair, so calls 3 to 5 go straight to b.
        assert_eq!(
            client.transport.seen(),
            [
                "https://a",
                "https://b", // call 1
                "https://a",
                "https://b", // call 2
                "https://b", // call 3
                "https://b", // call 4
                "https://b", // call 5
            ]
        );
    }

    #[test]
    fn health_tracking_still_tries_every_node_when_all_of_them_are_dead() {
        // The safety property at the client level: reordering must never shrink the
        // set of nodes tried, or a total outage becomes unrecoverable.
        let client = NodeClient::new(
            PerNodeTransport::new(&["https://a", "https://b", "https://c"]),
            nodes(),
        )
        .unwrap()
        .with_health_tracking(quick_policy());

        for _ in 0..3 {
            assert!(client.call("x", serde_json::json!({})).is_err());
        }
        let seen = client.transport.seen();
        assert_eq!(seen.len(), 9, "every call must try all three: {seen:?}");
        for node in ["https://a", "https://b", "https://c"] {
            assert_eq!(
                seen.iter().filter(|u| *u == node).count(),
                3,
                "{node} must still be tried on every call: {seen:?}"
            );
        }
    }

    #[test]
    fn a_node_failing_one_method_is_still_first_choice_for_another() {
        #[derive(Debug)]
        struct MethodTransport {
            calls: Mutex<Vec<String>>,
        }
        impl Transport for MethodTransport {
            fn post_json(&self, url: &str, body: &str, _t: Duration) -> Result<String> {
                self.calls.lock().unwrap().push(url.to_string());
                // Node a serves everything except account_history_api, which is what a
                // partial node looks like from outside.
                if url == "https://a" && body.contains("account_history_api") {
                    return Err(Error::Rpc("no such api".into()));
                }
                Ok(r#"{"result":1}"#.to_string())
            }
        }

        let client = NodeClient::new(
            MethodTransport {
                calls: Mutex::new(Vec::new()),
            },
            nodes(),
        )
        .unwrap()
        .with_health_tracking(quick_policy());

        for _ in 0..3 {
            client
                .call(
                    "account_history_api.get_ops_in_block",
                    serde_json::json!({}),
                )
                .unwrap();
        }
        client
            .call("database_api.get_accounts", serde_json::json!({}))
            .unwrap();

        let seen = client.transport.calls.lock().unwrap().clone();
        assert_eq!(
            seen.last().unwrap(),
            "https://a",
            "the working method must still go to node a first: {seen:?}"
        );
    }

    #[test]
    fn a_head_block_in_a_response_is_observed() {
        #[derive(Debug)]
        struct HeadTransport;
        impl Transport for HeadTransport {
            fn post_json(&self, url: &str, _b: &str, _t: Duration) -> Result<String> {
                // Node a is a thousand blocks behind and answers perfectly, which is
                // the case failure counting alone can never notice.
                let head = if url == "https://a" { 1_000 } else { 2_000 };
                Ok(format!(r#"{{"result":{{"head_block_number":{head}}}}}"#))
            }
        }
        let client = NodeClient::new(HeadTransport, nodes())
            .unwrap()
            .with_health_tracking(quick_policy());

        // One call reaches only node a, so only a's head is known and nothing can be
        // judged stale yet.
        client.call("x", serde_json::json!({})).unwrap();
        assert_eq!(client.health().unwrap()[0].head_block, Some(1_000));
        assert!(
            !client.health().unwrap()[0].stale,
            "nothing to compare against"
        );

        // Teach it what b reports, and a becomes measurably behind.
        client.health.as_ref().unwrap().observe_head_block(1, 2_000);
        let report = client.health().unwrap();
        assert!(report[0].stale, "node a is 1000 blocks behind: {report:?}");
        assert!(!report[1].stale);
    }

    #[test]
    fn hammering_one_node_does_not_demote_the_others() {
        // The access pattern of a long-running service, and the shape of the bug the
        // staleness compensation was written for. `call` returns on the first success,
        // so a healthy list means node 0 answers every time and nodes 1 and 2 are never
        // asked again after whatever first touched them. Their readings then age purely
        // because nobody asked.
        //
        // Comparing raw readings would demote them for that -- and keep node 0 first
        // for the same reason, since it alone has a fresh reading. The feature would
        // lock onto whichever node it already preferred and call the healthy majority
        // stale. An operator running exactly this pattern named it from their side; it
        // is a positive feedback loop, not a one-off false positive, which is why it
        // gets a test at the client level and not only in the tracker.
        // Blocks scaled to 1ms so the test runs in milliseconds while the chain
        // advances at a rate the compensation can actually credit. Advancing 800
        // blocks in zero wall-clock time, as a first version of this test did, is not
        // a chain -- it is a scenario the compensation is right to refuse to explain.
        const BASE: u64 = 109_242_600;
        #[derive(Debug)]
        struct HeadTransport {
            start: std::time::Instant,
        }
        impl Transport for HeadTransport {
            fn post_json(&self, _url: &str, _b: &str, _t: Duration) -> Result<String> {
                let elapsed = self.start.elapsed().as_millis() as u64;
                Ok(format!(
                    r#"{{"result":{{"head_block_number":{}}}}}"#,
                    BASE + elapsed
                ))
            }
        }

        let policy = HealthPolicy {
            block_interval: Duration::from_millis(1),
            head_block_ttl: Duration::from_secs(30),
            ..quick_policy()
        };
        let client = NodeClient::new(
            HeadTransport {
                start: std::time::Instant::now(),
            },
            nodes(),
        )
        .unwrap()
        .with_health_tracking(policy);

        // Nodes 1 and 2 were seen once, at the start, and are never asked again.
        let health = client.health.as_ref().expect("tracking is on");
        health.observe_head_block(1, BASE);
        health.observe_head_block(2, BASE);

        // Long enough that the chain has moved many blocks past their readings.
        std::thread::sleep(Duration::from_millis(60));
        for _ in 0..40 {
            client.call("x", serde_json::json!({})).unwrap();
        }

        let report = client.health().expect("tracking is on");
        assert!(
            report[0].head_block.expect("node 0 was asked") >= BASE + 60,
            "the chain must have moved well past their readings: {report:?}"
        );
        assert!(
            !report[1].stale && !report[2].stale,
            "nodes are not stale for not having been asked: {report:?}"
        );
        assert_eq!(
            client.call_order("x"),
            vec![0, 1, 2],
            "and the order must not lock onto whichever node happens to be first"
        );
    }

    #[test]
    fn a_recovered_node_comes_back_into_service_on_its_own() {
        // The property, end to end: a node that fails is demoted, and when it starts
        // answering again it returns to the front without anything having scheduled a
        // re-check.
        //
        // It comes from cooldowns *expiring*, not from recovery logic. There is
        // deliberately no demotion list, no probation and no half-open state to get
        // wrong -- the cooldown is one instant per node, and once it is past the node
        // simply sorts where it always did. A peer building the same feature by ranking
        // periodically got the property a different way, by recomputing the whole order
        // from scratch each round so nothing is ever removed from the input; their point
        // was that "demote, then schedule a re-check" buys a state machine and every bug
        // that comes with one. Both routes avoid that. This test is here so a future
        // edit cannot introduce one without noticing.
        #[derive(Debug)]
        struct Recovering {
            fail_until: usize,
            seen: Mutex<Vec<String>>,
        }
        impl Transport for Recovering {
            fn post_json(&self, url: &str, _b: &str, _t: Duration) -> Result<String> {
                let mut seen = self.seen.lock().unwrap();
                seen.push(url.to_string());
                let calls_to_bad = seen.iter().filter(|u| *u == "https://a").count();
                if url == "https://a" && calls_to_bad <= self.fail_until {
                    return Err(Error::Rpc("still down".into()));
                }
                Ok(r#"{"result":1}"#.to_string())
            }
        }

        let client = NodeClient::new(
            Recovering {
                fail_until: 2,
                seen: Mutex::new(Vec::new()),
            },
            nodes(),
        )
        .unwrap()
        .with_health_tracking(HealthPolicy {
            failures_before_cooldown: 2,
            api_failures_before_cooldown: 2,
            api_cooldown: Duration::from_millis(30),
            node_cooldown: Duration::from_millis(30),
            ..Default::default()
        });

        // Two calls demote it.
        client.call("x", serde_json::json!({})).unwrap();
        client.call("x", serde_json::json!({})).unwrap();
        assert_eq!(client.call_order("x"), vec![1, 2, 0], "demoted");

        // While cooling, it is not tried first.
        client.call("x", serde_json::json!({})).unwrap();
        let during = client.transport.seen.lock().unwrap().len();

        // The cooldown lapses and it is simply tried again -- and by now it answers.
        std::thread::sleep(Duration::from_millis(60));
        client.call("x", serde_json::json!({})).unwrap();

        let seen = client.transport.seen.lock().unwrap().clone();
        assert_eq!(
            seen.len(),
            during + 1,
            "the recovered node should answer on the first attempt: {seen:?}"
        );
        assert_eq!(seen.last().unwrap(), "https://a");
        assert_eq!(
            client.call_order("x"),
            vec![0, 1, 2],
            "and one success restores it fully, with no lingering probation"
        );
        let report = client.health().unwrap();
        assert_eq!(report[0].consecutive_failures, 0, "{report:?}");
        assert!(report[0].cooling_methods.is_empty(), "{report:?}");
    }

    #[test]
    fn health_is_none_unless_it_was_asked_for() {
        let client = NodeClient::new(FakeTransport::new(vec![]), nodes()).unwrap();
        assert!(client.health().is_none());
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
    fn ops_in_block_parses_and_separates_virtual_from_signed() {
        let t = FakeTransport::new(vec![Ok(r#"{"result":[
            {"op":["vote",{"voter":"a","author":"b","permlink":"p","weight":100}],
             "block":1,"trx_id":"aa","virtual_op":false,"timestamp":"2026-08-22T04:00:00"},
            {"op":["producer_reward",{"producer":"w","vesting_shares":"1.000000 VESTS"}],
             "block":1,"trx_id":"","virtual_op":true,"timestamp":"2026-08-22T04:00:00"}
        ]}"#
        .into())]);
        let client = NodeClient::new(t, nodes()).unwrap();
        let ops = client.ops_in_block(1, false).unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].name(), Some("vote"));
        assert!(!ops[0].virtual_op);
        assert!(ops[1].virtual_op);

        // Both decode, and the virtual one is recognised as such.
        assert!(!ops[0].parse().unwrap().is_virtual());
        assert!(ops[1].parse().unwrap().is_virtual());
    }

    #[test]
    fn a_backwards_block_range_is_refused_before_any_request() {
        let t = FakeTransport::new(vec![]);
        let client = NodeClient::new(t, nodes()).unwrap();
        assert!(client.ops_in_block_range(10, 5, false).is_err());
        assert!(client.transport.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn retry_passes_are_reported_in_the_error() {
        let t = FakeTransport::new(vec![
            Err(Error::Rpc("down".into())),
            Err(Error::Rpc("down".into())),
            Err(Error::Rpc("down".into())),
            Err(Error::Rpc("down".into())),
            Err(Error::Rpc("down".into())),
            Err(Error::Rpc("down".into())),
        ]);
        let client = NodeClient::new(t, nodes())
            .unwrap()
            .with_retries(2, Duration::from_millis(1));
        let err = format!("{}", client.call("x", serde_json::json!({})).unwrap_err());
        assert!(err.contains("2 pass(es)"), "{err}");
        assert!(err.contains("retry pass 2"), "{err}");
        // Every node was tried on both passes.
        assert_eq!(client.transport.calls.lock().unwrap().len(), 6);
    }

    #[test]
    fn one_pass_is_the_default_so_a_deadline_is_not_slept_through() {
        let t = FakeTransport::new(vec![
            Err(Error::Rpc("down".into())),
            Err(Error::Rpc("down".into())),
            Err(Error::Rpc("down".into())),
        ]);
        let client = NodeClient::new(t, nodes()).unwrap();
        assert!(client.call("x", serde_json::json!({})).is_err());
        assert_eq!(client.transport.calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn a_bounded_stream_stops_where_it_was_told_to() {
        // Head at 5; stream 3..=4 and stop.
        let props = r#"{"result":{"head_block_number":5,
            "head_block_id":"00000005aabbccdd00000000000000000000abcd",
            "time":"2026-08-22T04:00:00","last_irreversible_block_num":5}}"#;
        let block = |n: u32| {
            format!(
                r#"{{"result":{{"block":{{"previous":"{:08x}aabbccdd00000000000000000000abcd",
                "timestamp":"2026-08-22T04:00:00","witness":"w",
                "transaction_merkle_root":"0000000000000000000000000000000000000000"}}}}}}"#,
                n - 1
            )
        };
        let t = FakeTransport::new(vec![Ok(props.into()), Ok(block(3)), Ok(block(4))]);
        let client = NodeClient::new(t, nodes()).unwrap();
        let blocks: Vec<_> = client
            .stream_blocks(Some(3), StreamMode::Irreversible)
            .until(4)
            .collect();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].as_ref().unwrap().block_num().unwrap(), 3);
        assert_eq!(blocks[1].as_ref().unwrap().block_num().unwrap(), 4);
    }

    #[test]
    fn a_stream_yields_an_error_rather_than_ending_on_one() {
        let props = r#"{"result":{"head_block_number":5,
            "head_block_id":"00000005aabbccdd00000000000000000000abcd",
            "time":"2026-08-22T04:00:00","last_irreversible_block_num":5}}"#;
        // Every node fails on the block fetch, so the stream reports it.
        let t = FakeTransport::new(vec![
            Ok(props.into()),
            Err(Error::Rpc("boom".into())),
            Err(Error::Rpc("boom".into())),
            Err(Error::Rpc("boom".into())),
        ]);
        let client = NodeClient::new(t, nodes()).unwrap();
        let first = client
            .stream_blocks(Some(3), StreamMode::Head)
            .until(3)
            .next()
            .unwrap();
        assert!(
            first.is_err(),
            "a failed fetch must surface, not end the stream"
        );
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
