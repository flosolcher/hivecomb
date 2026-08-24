//! What node health tracking is worth when a node is misbehaving.
//!
//!     cargo run --release --example bench_health --features rpc
//!
//! The happy path was measured when the feature was written: 0.20 µs per call in Rust,
//! 5.1 µs in the Python layer, against a 20 ms round trip. That is the cost. This is the
//! benefit, and it was the outstanding half — the case the feature exists for had never
//! been measured, only reasoned about.
//!
//! # Why these three cases
//!
//! An evaluator working on a Hive node selector made the point that the intuition is
//! backwards: a node that is fully **down** is the *safe* case, because it removes itself
//! from consideration quickly and, for a staleness comparison, contributes no reading at
//! all. The input that actually hurts is the node answering **slowly but successfully** —
//! it stays in rotation, stays in the reference set, and costs its latency on every call
//! that reaches it.
//!
//! So the three cases are a fast failure, a failure that costs a full timeout, and a slow
//! success. The third is the one worth having an answer about.
//!
//! # The result this is designed to be able to report
//!
//! Health tracking demotes on **failure**. A slow success is a success: it clears the
//! failure count and leaves the node exactly where it was. So the honest prediction is
//! that this helps enormously in the timeout case and **not at all** in the slow case,
//! and the benchmark is arranged so that a null result there is visible rather than
//! buried. A benchmark that can only show its feature winning is the same defect as a
//! test that cannot fail.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hivecomb::rpc::{HealthPolicy, NodeClient, Transport};
use hivecomb::{Error, Result};

/// A transport where one node misbehaves and the rest answer instantly.
#[derive(Debug)]
struct Flaky {
    /// The node that misbehaves, and how.
    bad: String,
    behaviour: Behaviour,
    /// Every URL asked, in order, so the benchmark can say where the time went.
    /// Shared out of the client rather than read back through it — the client
    /// deliberately does not expose its transport, and a benchmark is not a reason to
    /// widen a public API.
    calls: Arc<Mutex<Vec<String>>>,
    slept: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, Copy)]
enum Behaviour {
    /// Refuses immediately — a closed port.
    FailsFast,
    /// Hangs until the caller's timeout expires, then fails.
    TimesOut,
    /// Answers correctly, but slowly. The dangerous one.
    SlowSuccess(Duration),
}

impl Transport for Flaky {
    fn post_json(&self, url: &str, _body: &str, timeout: Duration) -> Result<String> {
        self.calls.lock().expect("poisoned").push(url.to_string());
        if url == self.bad {
            match self.behaviour {
                Behaviour::FailsFast => return Err(Error::Rpc("connection refused".into())),
                Behaviour::TimesOut => {
                    self.slept.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(timeout);
                    return Err(Error::Rpc("timed out".into()));
                }
                Behaviour::SlowSuccess(delay) => {
                    self.slept.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(delay);
                }
            }
        }
        Ok(r#"{"result":{"head_block_number":109242605}}"#.to_string())
    }
}

fn nodes() -> Vec<String> {
    vec![
        "https://bad".into(),
        "https://good-1".into(),
        "https://good-2".into(),
    ]
}

/// Run `calls` requests and report the wall time per call.
fn run(behaviour: Behaviour, health: bool, timeout: Duration, calls: u32) -> (f64, usize, usize) {
    let calls_seen = Arc::new(Mutex::new(Vec::new()));
    let slept = Arc::new(AtomicUsize::new(0));
    let transport = Flaky {
        bad: "https://bad".into(),
        behaviour,
        calls: Arc::clone(&calls_seen),
        slept: Arc::clone(&slept),
    };
    let client = NodeClient::new(transport, nodes())
        .expect("node list is not empty")
        .with_timeout(timeout);
    // Two failures is enough to cool a method here, so the effect shows within a
    // benchmark rather than after the default three.
    let client = if health {
        client.with_health_tracking(HealthPolicy {
            failures_before_cooldown: 2,
            api_failures_before_cooldown: 2,
            ..Default::default()
        })
    } else {
        client
    };

    let started = Instant::now();
    for _ in 0..calls {
        // Every case must still succeed: health tracking may reorder, never exclude.
        client
            .call(
                "database_api.get_dynamic_global_properties",
                serde_json::json!({}),
            )
            .expect("some node always answers");
    }
    let per_call = started.elapsed().as_secs_f64() / f64::from(calls) * 1e6;

    let hits = calls_seen
        .lock()
        .expect("poisoned")
        .iter()
        .filter(|u| *u == "https://bad")
        .count();
    (per_call, hits, slept.load(Ordering::Relaxed))
}

fn main() {
    let timeout = Duration::from_millis(200);
    let calls = 40u32;

    println!("node health tracking, cost against benefit");
    println!(
        "  {calls} calls over three nodes, the first misbehaving, {}ms timeout\n",
        timeout.as_millis()
    );
    // Microseconds throughout: a fast failure costs so little that milliseconds round
    // it to 0.00 and the ratio against it becomes noise dressed as a result.
    println!(
        "  {:<32} {:>12} {:>12} {:>13}  bad node reached",
        "case", "off (us)", "on (us)", "verdict"
    );
    println!("  {}", "-".repeat(92));

    for (label, behaviour) in [
        ("node refuses immediately", Behaviour::FailsFast),
        ("node hangs until the timeout", Behaviour::TimesOut),
        (
            "node answers, slowly (150ms)",
            Behaviour::SlowSuccess(Duration::from_millis(150)),
        ),
    ] {
        let (off, off_hits, _) = run(behaviour, false, timeout, calls);
        let (on, on_hits, _) = run(behaviour, true, timeout, calls);
        let saved = if on > 0.0 { off / on } else { f64::INFINITY };
        // Below a few microseconds a ratio says nothing: report the absolute saving and
        // let the reader decide, rather than printing "1.8x" over 0.00 against 0.00.
        let verdict = if off < 20.0 {
            format!("{:+.1}us", on - off)
        } else if saved >= 1.10 {
            format!("{saved:.1}x faster")
        } else if saved <= 0.90 {
            format!("{:.1}x SLOWER", 1.0 / saved)
        } else {
            "no change".to_string()
        };
        println!("  {label:<32} {off:>12.2} {on:>12.2} {verdict:>13}  {off_hits} -> {on_hits}",);
    }

    println!("\n  The third row is the one to read. Health tracking demotes on failure,");
    println!("  and a slow success is a success: it clears the failure count and leaves");
    println!("  the node first in line. There is no latency signal in this tracker, so");
    println!("  a node that is merely slow is never demoted and the feature does nothing");
    println!("  for it. That is a real gap, not a measurement artefact.");
}
