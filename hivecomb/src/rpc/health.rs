//! Remembering which nodes are failing, so a dead one is not retried first forever.
//!
//! [`NodeClient`](super::NodeClient) walks its node list from the front on every call.
//! That is the right default — it is a mechanism rather than a policy, and it is
//! predictable — but it has one sharp edge in a long-running process: if the first node
//! is down, **every** call pays its full timeout before reaching a node that works. A
//! ten-second timeout and a node that stays down turns every request into a
//! ten-second request.
//!
//! This module is the opt-in fix. It remembers what failed and reorders the list
//! accordingly; the client without it behaves exactly as before.
//!
//! # The property that matters
//!
//! **No node is ever removed from the order.** Health only ever changes the sequence in
//! which nodes are tried, never the set. A tracker that could exclude a node would be a
//! tracker that can turn a recoverable outage into a total one — if every node is
//! cooling down, the correct behaviour is to try them all anyway, in the order least
//! likely to waste time. That is what [`HealthTracker::order`] does, and
//! `every_node_is_still_tried_when_all_of_them_are_cooling` is the test that holds it.
//!
//! # What is tracked
//!
//! Three things, mirroring what dhive's `NodeHealthTracker` found worth tracking:
//!
//! * **Consecutive failures per node.** Past a threshold the node goes into a cooldown
//!   and sorts last. One success clears it — a node that answers is healthy, whatever
//!   it did before. The streak must involve *more than one method* to count, so a node
//!   with a single missing API is never judged broadly broken.
//!
//!   That condition is the difference between per-method tracking working and being
//!   decorative: without it, a node failing one API repeatedly crosses the whole-node
//!   threshold too, and gets cooled entirely for a fault affecting one call.
//! * **Failures per node *and method*.** A node can serve `database_api` perfectly and
//!   404 on `account_history_api`, which is common when an operator runs a partial
//!   node. Cooling that pair, rather than the whole node, keeps the node useful for
//!   everything else.
//! * **Head block staleness.** A node that answers promptly with data an hour old is
//!   worse than one that is merely slow, and it fails no request, so failure counting
//!   alone will never notice it. Head block numbers are observed from any response that
//!   carries one, and a node far enough behind the best-known head sorts after healthy
//!   ones.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How aggressively to deprioritise a node that is failing or behind.
///
/// The defaults match dhive's, which are the only field-tested numbers available for
/// this: 3 consecutive failures for a 30-second node cooldown, 2 failures on one method
/// for a 60-second cooldown of that pair, and 30 blocks (about 90 seconds) behind the
/// best-known head to count as stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthPolicy {
    /// How long a node is deprioritised after crossing the failure threshold.
    pub node_cooldown: Duration,
    /// How long a node is deprioritised *for one method* after crossing the
    /// per-method threshold.
    pub api_cooldown: Duration,
    /// Consecutive failures before a node enters a whole-node cooldown.
    ///
    /// Counted only when the streak involves more than one method — see
    /// [`HealthTracker::record_failure`].
    pub failures_before_cooldown: u32,
    /// Failures on one method before that node-and-method pair enters cooldown.
    pub api_failures_before_cooldown: u32,
    /// How many blocks behind the best-known head a node may be before it counts as
    /// stale.
    pub stale_block_threshold: u64,
    /// How long an observed head block number is worth believing. Past this, the
    /// observation is ignored rather than treated as current — a stale *observation*
    /// is not evidence of a stale *node*.
    pub head_block_ttl: Duration,
    /// How long the chain takes to produce a block. Hive is three seconds.
    ///
    /// Used to age observations forward before comparing them. Two nodes are almost
    /// never observed at the same instant, and without this the older observation looks
    /// behind by however many blocks the chain produced in between — so a node that is
    /// perfectly current gets judged stale for not having been asked recently. With a
    /// two-minute TTL and three-second blocks that is forty blocks of drift against a
    /// thirty-block threshold, which is not a corner case.
    pub block_interval: Duration,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        HealthPolicy {
            node_cooldown: Duration::from_secs(30),
            api_cooldown: Duration::from_secs(60),
            failures_before_cooldown: 3,
            api_failures_before_cooldown: 2,
            stale_block_threshold: 30,
            head_block_ttl: Duration::from_secs(120),
            block_interval: Duration::from_secs(3),
        }
    }
}

/// What the tracker currently believes about one node.
///
/// Returned by [`NodeClient::health`](super::NodeClient::health) so an operator can see
/// why a node is being skipped, rather than inferring it from latency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHealth {
    /// Failures since the last success.
    pub consecutive_failures: u32,
    /// Whether the node is in a whole-node cooldown right now.
    pub in_cooldown: bool,
    /// Methods this node is currently cooling down for, sorted.
    pub cooling_methods: Vec<String>,
    /// The most recent head block observed from this node, if one is still within
    /// [`HealthPolicy::head_block_ttl`].
    pub head_block: Option<u64>,
    /// Whether that head block is far enough behind the best known to count as stale.
    pub stale: bool,
}

/// One node's mutable state.
#[derive(Debug, Default)]
struct NodeState {
    consecutive_failures: u32,
    /// The distinct methods involved in the current failure streak. A node is only
    /// judged broadly broken when more than one method is failing on it.
    streak_methods: HashSet<String>,
    cooldown_until: Option<Instant>,
    method_failures: HashMap<String, u32>,
    method_cooldown_until: HashMap<String, Instant>,
    head_block: Option<(u64, Instant)>,
}

impl NodeState {
    fn cooling(&self, now: Instant) -> bool {
        self.cooldown_until.is_some_and(|t| t > now)
    }

    fn cooling_for(&self, method: &str, now: Instant) -> bool {
        self.method_cooldown_until
            .get(method)
            .is_some_and(|t| *t > now)
    }

    /// The head block this node reported, if the observation is still fresh.
    fn fresh_head(&self, now: Instant, ttl: Duration) -> Option<u64> {
        self.head_block
            .filter(|(_, seen)| now.duration_since(*seen) <= ttl)
            .map(|(block, _)| block)
    }

    /// The same, aged forward to now at the chain's block rate.
    ///
    /// Comparing raw observations taken at different moments measures the gap between
    /// the *observations*, not between the nodes. Aging each one forward by the blocks
    /// the chain will have produced since removes that, and leaves only a real
    /// difference in how far behind the nodes are.
    ///
    /// The compensation errs toward *not* demoting: a node genuinely behind, last seen
    /// a while ago, gets credited with blocks it may not have caught up on. That is the
    /// right direction to be wrong in — this only ever reorders a list, and shuffling a
    /// usable node backwards on weak evidence costs more than leaving it in place.
    fn projected_head(&self, now: Instant, ttl: Duration, interval: Duration) -> Option<u64> {
        let (block, seen) = self.head_block?;
        let age = now.duration_since(seen);
        if age > ttl {
            return None;
        }
        let interval = interval.as_secs_f64();
        let advanced = if interval > 0.0 {
            (age.as_secs_f64() / interval) as u64
        } else {
            0
        };
        Some(block.saturating_add(advanced))
    }
}

/// Per-node health, remembered across calls.
///
/// Cheap to consult: one mutex acquisition per call, against a network round trip.
#[derive(Debug)]
pub struct HealthTracker {
    policy: HealthPolicy,
    state: Mutex<Vec<NodeState>>,
}

impl HealthTracker {
    /// A tracker for `node_count` nodes, indexed in the same order as the client's
    /// node list.
    pub fn new(node_count: usize, policy: HealthPolicy) -> Self {
        let mut state = Vec::with_capacity(node_count);
        state.resize_with(node_count, NodeState::default);
        HealthTracker {
            policy,
            state: Mutex::new(state),
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> HealthPolicy {
        self.policy
    }

    /// The order to try nodes in for `method`, best first.
    ///
    /// Always returns **every** index exactly once. Nodes are grouped into tiers and
    /// the configured order is preserved within each, so a healthy list comes back
    /// unchanged and the client's documented "tried in the order given" behaviour still
    /// holds whenever nothing is wrong:
    ///
    /// 0. healthy and current
    /// 1. healthy but behind the best-known head
    /// 2. cooling down for this method specifically
    /// 3. cooling down entirely
    pub fn order(&self, method: &str) -> Vec<usize> {
        let now = Instant::now();
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // The yardstick for staleness is the best head anyone has recently reported.
        // With no fresh observation at all, nothing can be judged stale -- which is
        // the correct answer, not a reason to guess.
        let best_head = state.iter().filter_map(|s| self.projected(s, now)).max();

        let mut tiers: Vec<(u8, usize)> = state
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let tier = if s.cooling(now) {
                    3
                } else if s.cooling_for(method, now) {
                    2
                } else if self.is_stale(s, best_head, now) {
                    1
                } else {
                    0
                };
                (tier, i)
            })
            .collect();

        // Stable, so the configured order survives inside a tier.
        tiers.sort_by_key(|(tier, _)| *tier);
        tiers.into_iter().map(|(_, i)| i).collect()
    }

    /// This node's head, aged forward to now, if the observation is still fresh.
    fn projected(&self, s: &NodeState, now: Instant) -> Option<u64> {
        s.projected_head(now, self.policy.head_block_ttl, self.policy.block_interval)
    }

    fn is_stale(&self, s: &NodeState, best_head: Option<u64>, now: Instant) -> bool {
        let (Some(best), Some(mine)) = (best_head, self.projected(s, now)) else {
            return false;
        };
        best.saturating_sub(mine) > self.policy.stale_block_threshold
    }

    /// Record that `index` answered `method`.
    ///
    /// Clears the node's failure count and any cooldown, whole-node and per-method
    /// alike. A node that answers is healthy; there is no penance period.
    pub fn record_success(&self, index: usize, method: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = state.get_mut(index) else {
            return;
        };
        s.consecutive_failures = 0;
        s.streak_methods.clear();
        s.cooldown_until = None;
        s.method_failures.remove(method);
        s.method_cooldown_until.remove(method);
    }

    /// Record that `index` failed `method`.
    pub fn record_failure(&self, index: usize, method: &str) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = state.get_mut(index) else {
            return;
        };

        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        s.streak_methods.insert(method.to_owned());

        // A whole-node cooldown needs failures on *more than one method*. Otherwise a
        // node that serves everything but one API -- a partial node, which is a normal
        // thing for an operator to run -- would be cooled entirely for a fault that
        // affects one call, and the per-method tracking below would be pointless for
        // the exact case it exists to handle. Failing broadly is what marks a node as
        // broken; failing narrowly marks a method as unavailable there.
        if s.consecutive_failures >= self.policy.failures_before_cooldown
            && s.streak_methods.len() > 1
        {
            s.cooldown_until = Some(now + self.policy.node_cooldown);
        }

        let counter = s.method_failures.entry(method.to_owned()).or_insert(0);
        *counter = counter.saturating_add(1);
        let hits = *counter;
        if hits >= self.policy.api_failures_before_cooldown {
            s.method_cooldown_until
                .insert(method.to_owned(), now + self.policy.api_cooldown);
        }
    }

    /// Record the head block `index` reported.
    ///
    /// Called with whatever a response happened to carry; nothing extra is requested to
    /// obtain it, because a library that issues its own health probes is spending the
    /// caller's rate limit on a decision the caller did not ask for.
    pub fn observe_head_block(&self, index: usize, head_block: u64) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = state.get_mut(index) {
            s.head_block = Some((head_block, now));
        }
    }

    /// What the tracker believes about every node, in node-list order.
    pub fn snapshot(&self) -> Vec<NodeHealth> {
        let now = Instant::now();
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let best_head = state.iter().filter_map(|s| self.projected(s, now)).max();

        state
            .iter()
            .map(|s| {
                let mut cooling_methods: Vec<String> = s
                    .method_cooldown_until
                    .iter()
                    .filter(|(_, t)| **t > now)
                    .map(|(m, _)| m.clone())
                    .collect();
                cooling_methods.sort();
                NodeHealth {
                    consecutive_failures: s.consecutive_failures,
                    in_cooldown: s.cooling(now),
                    cooling_methods,
                    head_block: s.fresh_head(now, self.policy.head_block_ttl),
                    stale: self.is_stale(s, best_head, now),
                }
            })
            .collect()
    }
}

/// The head block number a response carries, if it carries one.
///
/// `get_dynamic_global_properties` is the call that reports it, and it is also the call
/// a client makes most often — every TaPoS refresh is one — so staleness gets observed
/// as a side effect of work that was happening anyway.
pub(crate) fn head_block_of(value: &serde_json::Value) -> Option<u64> {
    value
        .get("head_block_number")
        .and_then(serde_json::Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HealthPolicy {
        HealthPolicy {
            failures_before_cooldown: 2,
            api_failures_before_cooldown: 2,
            ..Default::default()
        }
    }

    #[test]
    fn a_healthy_list_comes_back_in_the_configured_order() {
        let t = HealthTracker::new(3, policy());
        assert_eq!(t.order("x"), vec![0, 1, 2]);
    }

    #[test]
    fn a_failing_node_sorts_last() {
        let t = HealthTracker::new(3, policy());
        // One failure is not enough -- the threshold is two.
        t.record_failure(0, "x");
        assert_eq!(
            t.order("x"),
            vec![0, 1, 2],
            "one failure must not move a node"
        );
        t.record_failure(0, "x");
        assert_eq!(t.order("x"), vec![1, 2, 0]);
    }

    #[test]
    fn one_success_clears_the_cooldown() {
        let t = HealthTracker::new(3, policy());
        t.record_failure(0, "x");
        t.record_failure(0, "x");
        assert_eq!(t.order("x"), vec![1, 2, 0]);
        t.record_success(0, "x");
        assert_eq!(t.order("x"), vec![0, 1, 2]);
    }

    #[test]
    fn a_method_cooldown_does_not_move_the_node_for_other_methods() {
        // The point of tracking per method: a node serving database_api fine and
        // failing account_history_api should stay first choice for database_api.
        let t = HealthTracker::new(3, policy());
        t.record_failure(0, "account_history_api.get_ops_in_block");
        t.record_success(0, "database_api.get_accounts");
        t.record_failure(0, "account_history_api.get_ops_in_block");

        assert_eq!(
            t.order("account_history_api.get_ops_in_block"),
            vec![1, 2, 0],
            "the failing pair must sort last"
        );
        assert_eq!(
            t.order("database_api.get_accounts"),
            vec![0, 1, 2],
            "the working pair must be untouched"
        );
    }

    #[test]
    fn a_node_behind_the_head_sorts_after_current_ones() {
        let t = HealthTracker::new(3, policy());
        t.observe_head_block(0, 1_000);
        t.observe_head_block(1, 1_100);
        t.observe_head_block(2, 1_100);
        // Node 0 is 100 blocks behind the best known, past the 30-block threshold.
        assert_eq!(t.order("x"), vec![1, 2, 0]);
    }

    #[test]
    fn a_node_is_not_stale_merely_for_having_been_asked_earlier() {
        // The false positive this compensation exists for. Two nodes are essentially
        // never observed at the same instant, and the chain keeps producing blocks in
        // between, so comparing raw observations measures the gap between the
        // *observations* rather than between the nodes.
        //
        // Scaled down to keep the test fast: 10ms "blocks", so a 50ms gap is five of
        // them. Node 0 is observed at 100 and node 1 fifty milliseconds later at 105 --
        // node 0 is perfectly current, it simply has not been asked since. Comparing
        // raw heads makes it five blocks behind and, at this threshold, stale.
        let t = HealthTracker::new(
            2,
            HealthPolicy {
                stale_block_threshold: 2,
                block_interval: Duration::from_millis(10),
                head_block_ttl: Duration::from_secs(10),
                ..Default::default()
            },
        );
        t.observe_head_block(0, 100);
        std::thread::sleep(Duration::from_millis(50));
        t.observe_head_block(1, 105);

        let report = t.snapshot();
        assert!(
            !report[0].stale,
            "node 0 is current; it was just observed earlier: {report:?}"
        );
        assert_eq!(t.order("x"), vec![0, 1], "and so it keeps its place");
    }

    #[test]
    fn a_node_that_is_genuinely_behind_is_still_caught() {
        // The other side of the same compensation: it must not become a blanket excuse.
        // Both observed at the same moment, one far behind, and it is still demoted.
        let t = HealthTracker::new(
            2,
            HealthPolicy {
                stale_block_threshold: 2,
                block_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );
        t.observe_head_block(0, 100);
        t.observe_head_block(1, 500);
        assert!(t.snapshot()[0].stale, "400 blocks behind is behind");
        assert_eq!(t.order("x"), vec![1, 0]);
    }

    #[test]
    fn a_behind_node_with_an_old_observation_is_still_caught() {
        // Both halves at once, which is what distinguishes a correct compensation from
        // one that simply credits every node with enough blocks to look current. The
        // aged observation gets its five blocks and stays hundreds behind.
        //
        // Found by mutating the compensation to multiply by a thousand: the
        // same-instant test above could not see it, because at zero age there is
        // nothing to multiply.
        let t = HealthTracker::new(
            2,
            HealthPolicy {
                stale_block_threshold: 2,
                block_interval: Duration::from_millis(10),
                head_block_ttl: Duration::from_secs(10),
                ..Default::default()
            },
        );
        t.observe_head_block(0, 100);
        std::thread::sleep(Duration::from_millis(50));
        t.observe_head_block(1, 500);

        let report = t.snapshot();
        assert!(
            report[0].stale,
            "five blocks of credit does not close a 400-block gap: {report:?}"
        );
        assert!(
            !report[1].stale,
            "the current node must not be the stale one"
        );
        assert_eq!(t.order("x"), vec![1, 0]);
    }

    #[test]
    fn the_snapshot_reports_the_head_as_observed_not_as_projected() {
        // The projection is for comparing nodes to each other. An operator reading the
        // report wants the number the node actually said, not one adjusted on its
        // behalf, or the report cannot be checked against the node.
        let t = HealthTracker::new(1, policy());
        t.observe_head_block(0, 12_345);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(t.snapshot()[0].head_block, Some(12_345));
    }

    #[test]
    fn being_slightly_behind_is_not_stale() {
        let t = HealthTracker::new(2, policy());
        t.observe_head_block(0, 1_090);
        t.observe_head_block(1, 1_100);
        assert_eq!(
            t.order("x"),
            vec![0, 1],
            "10 blocks is within the threshold"
        );
    }

    #[test]
    fn nothing_is_stale_when_no_head_block_was_ever_observed() {
        let t = HealthTracker::new(3, policy());
        assert_eq!(t.order("x"), vec![0, 1, 2]);
        assert!(t
            .snapshot()
            .iter()
            .all(|h| !h.stale && h.head_block.is_none()));
    }

    #[test]
    fn a_cooling_node_sorts_after_a_merely_stale_one() {
        let t = HealthTracker::new(2, policy());
        // Node 0 is stale, node 1 is failing outright. Stale still beats broken.
        t.observe_head_block(0, 1_000);
        t.observe_head_block(1, 1_100);
        t.record_failure(1, "x");
        t.record_failure(1, "x");
        assert_eq!(t.order("x"), vec![0, 1]);
    }

    #[test]
    fn every_node_is_still_tried_when_all_of_them_are_cooling() {
        // The safety property: health reorders, it never excludes. If every node is
        // in cooldown the call must still try every one of them.
        let t = HealthTracker::new(3, policy());
        for i in 0..3 {
            t.record_failure(i, "x");
            t.record_failure(i, "x");
        }
        let mut order = t.order("x");
        assert_eq!(order.len(), 3, "no node may be dropped from the order");
        order.sort();
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn a_cooldown_expires() {
        let t = HealthTracker::new(
            2,
            HealthPolicy {
                failures_before_cooldown: 1,
                node_cooldown: Duration::from_millis(20),
                ..Default::default()
            },
        );
        // Two distinct methods, because a whole-node cooldown needs a broad fault.
        t.record_failure(0, "x");
        t.record_failure(0, "y");
        assert!(
            t.snapshot()[0].in_cooldown,
            "cooling immediately after failing"
        );
        assert_eq!(t.order("z"), vec![1, 0]);
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !t.snapshot()[0].in_cooldown,
            "and healthy again once it expires"
        );
        assert_eq!(t.order("z"), vec![0, 1]);
    }

    #[test]
    fn a_stale_head_observation_is_ignored_rather_than_believed() {
        // An observation older than the TTL says nothing about the node now. Treating
        // it as current would keep punishing a node that has since caught up and has
        // simply not been asked anything that reports a head block.
        let t = HealthTracker::new(
            2,
            HealthPolicy {
                head_block_ttl: Duration::from_millis(20),
                ..Default::default()
            },
        );
        t.observe_head_block(0, 1_000);
        t.observe_head_block(1, 1_100);
        assert_eq!(t.order("x"), vec![1, 0]);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(t.order("x"), vec![0, 1], "the observations have expired");
    }

    #[test]
    fn the_snapshot_reports_why_a_node_is_skipped() {
        let t = HealthTracker::new(2, policy());
        t.record_failure(0, "database_api.get_accounts");
        t.record_failure(0, "database_api.get_accounts");
        t.observe_head_block(0, 1_000);
        t.observe_head_block(1, 2_000);

        let s = t.snapshot();
        assert_eq!(s[0].consecutive_failures, 2);
        assert!(
            !s[0].in_cooldown,
            "one failing method is not a broadly broken node"
        );
        assert_eq!(s[0].cooling_methods, vec!["database_api.get_accounts"]);
        assert_eq!(s[0].head_block, Some(1_000));
        assert!(s[0].stale);
        assert_eq!(s[1].consecutive_failures, 0);
        assert!(!s[1].in_cooldown && !s[1].stale);
    }

    #[test]
    fn one_failing_method_never_cools_the_whole_node() {
        // The rule that makes per-method tracking worth having. However often this
        // node fails one API, it stays a first-class choice for every other.
        let t = HealthTracker::new(2, policy());
        for _ in 0..20 {
            t.record_failure(0, "account_history_api.get_ops_in_block");
        }
        let s = t.snapshot();
        assert_eq!(s[0].consecutive_failures, 20);
        assert!(!s[0].in_cooldown, "still not a whole-node fault");
        assert_eq!(
            t.order("database_api.get_accounts"),
            vec![0, 1],
            "an unaffected method must still prefer this node"
        );
        assert_eq!(
            t.order("account_history_api.get_ops_in_block"),
            vec![1, 0],
            "the affected method must not"
        );
    }

    #[test]
    fn failing_across_methods_does_cool_the_whole_node() {
        let t = HealthTracker::new(2, policy());
        t.record_failure(0, "database_api.get_accounts");
        t.record_failure(0, "account_history_api.get_ops_in_block");
        let s = t.snapshot();
        assert!(
            s[0].in_cooldown,
            "two different methods failing is a broken node: {s:?}"
        );
        assert_eq!(
            t.order("some_other_api.thing"),
            vec![1, 0],
            "a method it has never failed must still avoid it"
        );
    }

    #[test]
    fn a_success_ends_the_streak_so_old_methods_do_not_accumulate() {
        // Without clearing the streak, a node that fails one method, succeeds, then
        // fails a different one would look like it had failed across two methods.
        let t = HealthTracker::new(2, policy());
        t.record_failure(0, "a.one");
        t.record_success(0, "a.one");
        t.record_failure(0, "b.two");
        assert!(
            !t.snapshot()[0].in_cooldown,
            "the streak was broken by a success"
        );
    }

    #[test]
    fn out_of_range_indices_are_ignored_rather_than_panicking() {
        // The tracker is built from the client's node count, so this should not be
        // reachable -- but a panic here would take down a caller's process over a
        // bookkeeping mistake, which is a bad trade.
        let t = HealthTracker::new(1, policy());
        t.record_failure(99, "x");
        t.record_success(99, "x");
        t.observe_head_block(99, 1);
        assert_eq!(t.order("x"), vec![0]);
    }

    #[test]
    fn head_block_is_read_from_a_dynamic_global_properties_response() {
        let v = serde_json::json!({"head_block_number": 109_242_605u64, "time": "x"});
        assert_eq!(head_block_of(&v), Some(109_242_605));
        assert_eq!(head_block_of(&serde_json::json!({"other": 1})), None);
        assert_eq!(head_block_of(&serde_json::json!(42)), None);
    }
}
