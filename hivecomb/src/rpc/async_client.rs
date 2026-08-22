//! The async JSON-RPC layer.
//!
//! # Why this exists, and why it is not just "the sync client with `.await`"
//!
//! Signing in `hivecomb` needs no network at all, so the async layer buys nothing
//! there. What it buys is on the **broadcast** side, which is a real network call and
//! is often inside somebody's deadline.
//!
//! Sequential failover — try node 1, then node 2, then node 3 — has a worst case of
//! *the sum of the timeouts*. Three sick nodes at 15 seconds each is 45 seconds before
//! the fourth is even attempted. That is precisely the failure that motivated this
//! project: the specification it came from records a submit burning ~46 s and forfeiting
//! a match, and records the fix as racing three nodes concurrently per wave.
//!
//! [`AsyncNodeClient::race`] is that fix. It fires the same request at several nodes at
//! once and takes the first success, so the worst case is **one** timeout rather than
//! the sum. You cannot express that cleanly in a blocking API without threads, which is
//! the specific reason this layer is async rather than a generic preference for it.
//!
//! # Runtime-agnostic on purpose
//!
//! Nothing here pulls in an executor. The trait uses `-> impl Future` rather than an
//! `#[async_trait]` box, and the retry backoff takes a **caller-supplied sleep**, so
//! tokio, async-std and smol all work:
//!
//! ```ignore
//! let client = AsyncNodeClient::new(transport, nodes)?
//!     .with_retries(3, Duration::from_millis(250), |d| Box::pin(tokio::time::sleep(d)));
//! ```
//!
//! Enable `reqwest-transport` for a working transport and a tokio sleeper if you would
//! rather not wire that up.
//!
//! # What racing is and is not safe for
//!
//! **Reads are always safe to race.** They have no side effects, and the first answer
//! is as good as the last.
//!
//! **Broadcasting is safe to race, but for a reason worth knowing:** the chain
//! deduplicates by transaction id, so the same signed transaction arriving at three
//! nodes is accepted once. What it is *not* safe to do is race two **differently
//! signed** transactions for the same intent — different expirations mean different
//! ids, and both can land. [`AsyncNodeClient::broadcast_raced`] takes one already-signed
//! transaction for exactly that reason.

use super::types::{DynamicGlobalProperties, RpcRequest, RpcResponse};
use crate::error::{Error, Result};
use crate::transaction::{BlockRef, SignedTransaction};
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A future returned by a caller-supplied sleep.
pub type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// How to wait between retry passes.
///
/// Boxed because it is stored in the client and called rarely; the cost is one
/// allocation per retry pass, against a wait measured in hundreds of milliseconds.
pub type Sleeper = Arc<dyn Fn(Duration) -> SleepFuture + Send + Sync>;

/// An async HTTP POST transport.
///
/// The whole network surface of the async layer is this one method. Uses
/// `-> impl Future` rather than a boxed `async_trait`, so there is no allocation per
/// call and no macro in the way.
pub trait AsyncTransport: Send + Sync + std::fmt::Debug {
    /// POST `body` to `url` as `application/json` and return the response body.
    ///
    /// Implementations should honour `timeout` and **must not retry** — retry and
    /// failover policy belongs to [`AsyncNodeClient`], which knows the node list.
    fn post_json(
        &self,
        url: &str,
        body: &str,
        timeout: Duration,
    ) -> impl Future<Output = Result<String>> + Send;
}

/// An async client over a list of Hive nodes.
#[derive(Clone)]
pub struct AsyncNodeClient<T: AsyncTransport> {
    transport: Arc<T>,
    nodes: Vec<String>,
    timeout: Duration,
    passes: u32,
    initial_backoff: Duration,
    sleeper: Option<Sleeper>,
    next_id: Arc<AtomicU64>,
}

impl<T: AsyncTransport> std::fmt::Debug for AsyncNodeClient<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncNodeClient")
            .field("nodes", &self.nodes.len())
            .field("timeout", &self.timeout)
            .field("passes", &self.passes)
            .field("has_sleeper", &self.sleeper.is_some())
            .finish()
    }
}

impl<T: AsyncTransport> AsyncNodeClient<T> {
    /// Build a client over `nodes`, tried in the order given.
    pub fn new(transport: T, nodes: Vec<String>) -> Result<Self> {
        if nodes.is_empty() {
            return Err(Error::Rpc("node list is empty".into()));
        }
        Ok(AsyncNodeClient {
            transport: Arc::new(transport),
            nodes,
            timeout: Duration::from_secs(10),
            passes: 1,
            initial_backoff: Duration::from_millis(250),
            sleeper: None,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Set the per-node timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Retry the whole node list this many times, waiting via `sleep` between passes.
    ///
    /// The sleep is supplied rather than assumed so that no executor is baked in.
    /// With `reqwest-transport` enabled, [`super::tokio_sleeper`] provides one.
    ///
    /// The default is a single pass, for the same reason as the blocking client: a
    /// call on a deadline should fail fast and let the caller decide.
    pub fn with_retries<S, F>(mut self, passes: u32, initial_backoff: Duration, sleep: S) -> Self
    where
        S: Fn(Duration) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.passes = passes.max(1);
        self.initial_backoff = initial_backoff;
        self.sleeper = Some(Arc::new(move |d| Box::pin(sleep(d)) as SleepFuture));
        self
    }

    /// The configured nodes.
    pub fn nodes(&self) -> &[String] {
        &self.nodes
    }

    fn request_body(&self, method: &str, params: serde_json::Value) -> Result<String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        serde_json::to_string(&RpcRequest::new(method, params, id))
            .map_err(|e| Error::Rpc(format!("could not encode request: {e}")))
    }

    async fn try_node(&self, node: &str, body: &str) -> Result<serde_json::Value> {
        let text = self.transport.post_json(node, body, self.timeout).await?;
        let response: RpcResponse = serde_json::from_str(&text)
            .map_err(|e| Error::Rpc(format!("could not parse response: {e}")))?;
        response.into_result()
    }

    /// Call `method`, trying each node in turn until one answers.
    ///
    /// Same semantics as the blocking client, so behaviour does not change with the
    /// execution model. Use [`Self::race`] when latency matters more than politeness
    /// to the nodes.
    pub async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = self.request_body(method, params)?;
        let mut failures = Vec::with_capacity(self.nodes.len());

        for pass in 0..self.passes {
            if pass > 0 {
                if let Some(sleep) = &self.sleeper {
                    let wait = self
                        .initial_backoff
                        .saturating_mul(1u32 << (pass - 1).min(6))
                        .min(Duration::from_secs(30));
                    sleep(wait).await;
                    failures.push(format!("(retry pass {} after {:?})", pass + 1, wait));
                }
            }
            for node in &self.nodes {
                match self.try_node(node, &body).await {
                    Ok(value) => return Ok(value),
                    Err(e) => failures.push(format!("{node}: {e}")),
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

    /// Call `method` on `width` nodes **at once** and take the first success.
    ///
    /// Worst-case latency is one timeout rather than the sum of `width` of them, which
    /// is the whole point — see the module docs. Losing requests are dropped as soon as
    /// a winner is found.
    ///
    /// `width` is clamped to the node count. A width of 1 is just [`Self::call`] over
    /// the first node.
    ///
    /// Safe for reads unconditionally. Safe for broadcast because the chain
    /// deduplicates by transaction id — see [`Self::broadcast_raced`].
    pub async fn race(
        &self,
        method: &str,
        params: serde_json::Value,
        width: usize,
    ) -> Result<serde_json::Value> {
        let width = width.clamp(1, self.nodes.len());
        let body = self.request_body(method, params)?;

        let mut inflight = FuturesUnordered::new();
        for node in self.nodes.iter().take(width) {
            let body = body.clone();
            inflight.push(async move {
                let result = self.try_node(node, &body).await;
                (node.clone(), result)
            });
        }

        let mut failures = Vec::with_capacity(width);
        while let Some((node, result)) = inflight.next().await {
            match result {
                // Dropping `inflight` here cancels the losers.
                Ok(value) => return Ok(value),
                Err(e) => failures.push(format!("{node}: {e}")),
            }
        }

        Err(Error::Rpc(format!(
            "all {width} raced node(s) failed for {method} — {}",
            failures.join("; ")
        )))
    }

    // -----------------------------------------------------------------------
    // Typed accessors, mirroring the blocking client so code can move between
    // them without relearning anything.
    // -----------------------------------------------------------------------

    /// The properties the TaPoS path needs.
    pub async fn dynamic_global_properties(&self) -> Result<DynamicGlobalProperties> {
        let value = self
            .call(
                "database_api.get_dynamic_global_properties",
                serde_json::json!({}),
            )
            .await?;
        serde_json::from_value(value)
            .map_err(|e| Error::Rpc(format!("unexpected global properties: {e}")))
    }

    /// Extended global properties, with supply and vesting totals.
    pub async fn global_properties(&self) -> Result<crate::chain::DynamicGlobalProperties> {
        let value = self
            .call(
                "database_api.get_dynamic_global_properties",
                serde_json::json!({}),
            )
            .await?;
        serde_json::from_value(value)
            .map_err(|e| Error::Rpc(format!("unexpected global properties: {e}")))
    }

    /// Fetch a fresh TaPoS reference.
    pub async fn block_ref(&self) -> Result<BlockRef> {
        self.dynamic_global_properties().await?.block_ref()
    }

    /// Refresh a [`crate::tapos::TaposCache`] from the head block.
    ///
    /// Call this from a background task. Nothing on the signing path should call it —
    /// that is the property the whole design exists to keep.
    pub async fn refresh_tapos(&self, cache: &crate::tapos::TaposCache) -> Result<BlockRef> {
        let block_ref = self.block_ref().await?;
        cache.store(block_ref);
        Ok(block_ref)
    }

    /// Look up accounts by name.
    pub async fn accounts(&self, names: &[&str]) -> Result<Vec<crate::chain::Account>> {
        let value = self
            .call("condenser_api.get_accounts", serde_json::json!([names]))
            .await?;
        serde_json::from_value(value)
            .map_err(|e| Error::Rpc(format!("unexpected account response: {e}")))
    }

    /// Look up one account, distinguishing "not found" from an error.
    pub async fn find_account(&self, name: &str) -> Result<Option<crate::chain::Account>> {
        Ok(self.accounts(&[name]).await?.into_iter().next())
    }

    /// Resource credits for a set of accounts.
    pub async fn rc_accounts(&self, names: &[&str]) -> Result<Vec<crate::chain::RcAccount>> {
        let value = self
            .call(
                "rc_api.find_rc_accounts",
                serde_json::json!({ "accounts": names }),
            )
            .await?;
        serde_json::from_value(
            value
                .get("rc_accounts")
                .cloned()
                .ok_or_else(|| Error::Rpc("rc_api response has no rc_accounts".into()))?,
        )
        .map_err(|e| Error::Rpc(format!("unexpected rc account response: {e}")))
    }

    /// A block by number, or `None` if the node does not have it.
    pub async fn block(&self, block_num: u32) -> Result<Option<crate::chain::Block>> {
        let value = self
            .call(
                "block_api.get_block",
                serde_json::json!({ "block_num": block_num }),
            )
            .await?;
        match value.get("block") {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(block) => serde_json::from_value(block.clone())
                .map(Some)
                .map_err(|e| Error::Rpc(format!("unexpected block response: {e}"))),
        }
    }

    /// Every operation recorded for a block, virtual included.
    pub async fn ops_in_block(
        &self,
        block_num: u32,
        only_virtual: bool,
    ) -> Result<Vec<super::BlockOperation>> {
        let value = self
            .call(
                "condenser_api.get_ops_in_block",
                serde_json::json!([block_num, only_virtual]),
            )
            .await?;
        serde_json::from_value(value)
            .map_err(|e| Error::Rpc(format!("unexpected get_ops_in_block response: {e}")))
    }

    /// Fetch several blocks **concurrently**.
    ///
    /// The reason to reach for the async layer when indexing: a thousand sequential
    /// block fetches is a thousand round trips end to end, while this overlaps
    /// `concurrency` of them. Results come back in block order regardless of which
    /// finished first.
    pub async fn blocks(
        &self,
        from: u32,
        to: u32,
        concurrency: usize,
    ) -> Result<Vec<Option<crate::chain::Block>>> {
        if to < from {
            return Err(Error::Rpc(format!(
                "block range {from}..={to} runs backwards"
            )));
        }
        let concurrency = concurrency.max(1);
        let mut fetched: Vec<(u32, Option<crate::chain::Block>)> =
            Vec::with_capacity((to - from + 1) as usize);
        let mut pending = FuturesUnordered::new();
        let mut next = from;

        loop {
            // Keep the window full: start new fetches as old ones land, rather
            // than in fixed batches, so one slow block does not stall the rest.
            while pending.len() < concurrency && next <= to {
                let number = next;
                next += 1;
                pending.push(async move { (number, self.block(number).await) });
            }
            let Some((number, result)) = pending.next().await else {
                break;
            };
            fetched.push((number, result?));
        }

        fetched.sort_by_key(|(number, _)| *number);
        Ok(fetched.into_iter().map(|(_, block)| block).collect())
    }

    /// Broadcast a signed transaction, racing `width` nodes.
    ///
    /// Racing a broadcast is safe **because the chain deduplicates by transaction id**:
    /// the same signed bytes arriving at three nodes are accepted once. That is why this
    /// takes an already-signed transaction rather than signing per node — two
    /// differently-signed transactions for the same intent have different ids, and both
    /// would land.
    pub async fn broadcast_raced(
        &self,
        tx: &SignedTransaction,
        width: usize,
    ) -> Result<serde_json::Value> {
        self.race(
            "network_broadcast_api.broadcast_transaction",
            serde_json::json!({ "trx": tx.to_json()? }),
            width,
        )
        .await
    }

    /// Broadcast a signed transaction with ordinary failover.
    pub async fn broadcast(&self, tx: &SignedTransaction) -> Result<serde_json::Value> {
        self.call(
            "network_broadcast_api.broadcast_transaction",
            serde_json::json!({ "trx": tx.to_json()? }),
        )
        .await
    }

    /// Check the node's reported chain id against the compiled-in constant.
    pub async fn verify_chain_id(&self, chain: crate::chains::Chain) -> Result<()> {
        let config = self
            .call("database_api.get_config", serde_json::json!({}))
            .await?;
        let reported = config
            .get("HIVE_CHAIN_ID")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Rpc("node config has no HIVE_CHAIN_ID".into()))?;
        let expected = chain.chain_id().to_hex();
        if reported.eq_ignore_ascii_case(&expected) {
            Ok(())
        } else {
            Err(Error::Chain(format!(
                "node reports chain id {reported}, but this build signs for {expected}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    // tokio's Instant, not std's: these tests run on a paused virtual clock, and
    // std::time::Instant would measure real elapsed time -- near zero for all of
    // them -- so the comparisons below would pass without proving anything.
    use tokio::time::Instant;

    /// A transport that answers per node, optionally after a delay.
    ///
    /// The delays are what make the racing tests mean something: a race is only
    /// worth having if a slow node cannot hold up a fast one.
    #[derive(Debug)]
    struct FakeTransport {
        answers: Mutex<std::collections::HashMap<String, (Duration, Result<String>)>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeTransport {
        fn new(answers: Vec<(&str, Duration, Result<String>)>) -> Self {
            FakeTransport {
                answers: Mutex::new(
                    answers
                        .into_iter()
                        .map(|(node, delay, result)| (node.to_string(), (delay, result)))
                        .collect(),
                ),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl AsyncTransport for FakeTransport {
        fn post_json(
            &self,
            url: &str,
            _body: &str,
            _timeout: Duration,
        ) -> impl Future<Output = Result<String>> + Send {
            self.calls.lock().unwrap().push(url.to_string());
            let entry = self
                .answers
                .lock()
                .unwrap()
                .get(url)
                .map(|(delay, result)| (*delay, result.clone()));
            async move {
                match entry {
                    None => Err(Error::Rpc("no scripted answer".into())),
                    Some((delay, result)) => {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        result
                    }
                }
            }
        }
    }

    fn nodes() -> Vec<String> {
        vec!["https://a".into(), "https://b".into(), "https://c".into()]
    }

    const OK: &str = r#"{"result":42}"#;

    #[tokio::test]
    async fn an_empty_node_list_is_refused() {
        assert!(AsyncNodeClient::new(FakeTransport::new(vec![]), vec![]).is_err());
    }

    #[tokio::test]
    async fn call_falls_over_to_the_next_node() {
        let t = FakeTransport::new(vec![
            ("https://a", Duration::ZERO, Err(Error::Rpc("down".into()))),
            ("https://b", Duration::ZERO, Ok(OK.into())),
        ]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();
        assert_eq!(client.call("x", serde_json::json!({})).await.unwrap(), 42);
        assert_eq!(client.transport.call_count(), 2);
    }

    #[tokio::test]
    async fn call_error_names_every_node_that_failed() {
        let t = FakeTransport::new(vec![
            (
                "https://a",
                Duration::ZERO,
                Err(Error::Rpc("timeout".into())),
            ),
            (
                "https://b",
                Duration::ZERO,
                Err(Error::Rpc("refused".into())),
            ),
            ("https://c", Duration::ZERO, Err(Error::Rpc("503".into()))),
        ]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();
        let msg = format!(
            "{}",
            client.call("x", serde_json::json!({})).await.unwrap_err()
        );
        for node in ["https://a", "https://b", "https://c"] {
            assert!(msg.contains(node), "{msg} should name {node}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn racing_takes_one_timeout_not_the_sum() {
        // This is the whole justification for the async layer. Two nodes hang for
        // 15 s each and the third answers instantly.
        //
        // Sequential failover would take 30 s to reach the working node. Racing
        // takes as long as the fastest answer.
        let slow = Duration::from_secs(15);
        let t = FakeTransport::new(vec![
            ("https://a", slow, Err(Error::Rpc("timeout".into()))),
            ("https://b", slow, Err(Error::Rpc("timeout".into()))),
            ("https://c", Duration::ZERO, Ok(OK.into())),
        ]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();

        let started = Instant::now();
        let value = client.race("x", serde_json::json!({}), 3).await.unwrap();
        let elapsed = started.elapsed();

        assert_eq!(value, 42);
        assert!(
            elapsed < slow,
            "racing took {elapsed:?}, which is no better than waiting for one slow node"
        );
        // All three were dispatched; the two slow ones were dropped on the winner.
        assert_eq!(client.transport.call_count(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn sequential_failover_really_is_the_sum_it_is_claimed_to_be() {
        // The comparison the test above is measured against, asserted rather than
        // assumed.
        let slow = Duration::from_secs(15);
        let t = FakeTransport::new(vec![
            ("https://a", slow, Err(Error::Rpc("timeout".into()))),
            ("https://b", slow, Err(Error::Rpc("timeout".into()))),
            ("https://c", Duration::ZERO, Ok(OK.into())),
        ]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();

        let started = Instant::now();
        client.call("x", serde_json::json!({})).await.unwrap();
        assert!(
            started.elapsed() >= slow * 2,
            "failover should have waited for both slow nodes"
        );
    }

    #[tokio::test]
    async fn racing_reports_every_failure_when_none_answer() {
        let t = FakeTransport::new(vec![
            (
                "https://a",
                Duration::ZERO,
                Err(Error::Rpc("down-a".into())),
            ),
            (
                "https://b",
                Duration::ZERO,
                Err(Error::Rpc("down-b".into())),
            ),
        ]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();
        let msg = format!(
            "{}",
            client
                .race("x", serde_json::json!({}), 2)
                .await
                .unwrap_err()
        );
        assert!(msg.contains("down-a") && msg.contains("down-b"), "{msg}");
        assert!(msg.contains("2 raced"), "{msg}");
    }

    #[tokio::test]
    async fn race_width_is_clamped_to_the_node_count() {
        let t = FakeTransport::new(vec![("https://a", Duration::ZERO, Ok(OK.into()))]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();
        assert_eq!(
            client.race("x", serde_json::json!({}), 99).await.unwrap(),
            42
        );
        // Width 0 becomes 1, so exactly one node is asked.
        let t = FakeTransport::new(vec![("https://a", Duration::ZERO, Ok(OK.into()))]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();
        assert_eq!(
            client.race("x", serde_json::json!({}), 0).await.unwrap(),
            42
        );
        assert_eq!(client.transport.call_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_use_the_supplied_sleep() {
        let t = FakeTransport::new(vec![(
            "https://a",
            Duration::ZERO,
            Err(Error::Rpc("down".into())),
        )]);
        let client = AsyncNodeClient::new(t, vec!["https://a".into()])
            .unwrap()
            .with_retries(3, Duration::from_millis(100), |d| tokio::time::sleep(d));
        let msg = format!(
            "{}",
            client.call("x", serde_json::json!({})).await.unwrap_err()
        );
        assert!(msg.contains("3 pass(es)"), "{msg}");
        assert!(msg.contains("retry pass 2"), "{msg}");
        assert_eq!(client.transport.call_count(), 3);
    }

    #[tokio::test]
    async fn one_pass_is_the_default_so_a_deadline_is_not_slept_through() {
        let t = FakeTransport::new(vec![(
            "https://a",
            Duration::ZERO,
            Err(Error::Rpc("down".into())),
        )]);
        let client = AsyncNodeClient::new(t, vec!["https://a".into()]).unwrap();
        assert!(client.call("x", serde_json::json!({})).await.is_err());
        assert_eq!(client.transport.call_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_block_fetch_returns_them_in_order() {
        // Blocks answer out of order -- the later one is fast, the earlier slow --
        // and the result must still be ordered by block number.
        let block = |n: u32| {
            format!(
                r#"{{"result":{{"block":{{"previous":"{:08x}aabbccdd00000000000000000000abcd",
                "timestamp":"2026-08-22T04:00:00","witness":"w",
                "transaction_merkle_root":"0000000000000000000000000000000000000000"}}}}}}"#,
                n - 1
            )
        };
        // One node, so every fetch goes to it; the fake answers the same for all.
        let t = FakeTransport::new(vec![("https://a", Duration::ZERO, Ok(block(3)))]);
        let client = AsyncNodeClient::new(t, vec!["https://a".into()]).unwrap();
        let blocks = client.blocks(10, 14, 3).await.unwrap();
        assert_eq!(blocks.len(), 5);
        assert!(blocks.iter().all(|b| b.is_some()));
    }

    #[tokio::test]
    async fn a_backwards_block_range_is_refused_before_any_request() {
        let t = FakeTransport::new(vec![]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();
        assert!(client.blocks(10, 5, 2).await.is_err());
        assert_eq!(client.transport.call_count(), 0);
    }

    #[tokio::test]
    async fn typed_accessors_parse_the_same_shapes_as_the_blocking_client() {
        let account_json = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/account.json"
        ))
        .unwrap();
        let t = FakeTransport::new(vec![(
            "https://a",
            Duration::ZERO,
            Ok(format!(r#"{{"result":{account_json}}}"#)),
        )]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();
        let accounts = client.accounts(&["hiveio"]).await.unwrap();
        assert!(accounts.iter().any(|a| a.name == "hiveio"));
    }

    #[tokio::test]
    async fn chain_id_mismatch_is_caught() {
        let t = FakeTransport::new(vec![(
            "https://a",
            Duration::ZERO,
            Ok(r#"{"result":{"HIVE_CHAIN_ID":"0000000000000000000000000000000000000000000000000000000000000000"}}"#.into()),
        )]);
        let client = AsyncNodeClient::new(t, nodes()).unwrap();
        assert!(client
            .verify_chain_id(crate::chains::Chain::Hive)
            .await
            .is_err());
    }
}
