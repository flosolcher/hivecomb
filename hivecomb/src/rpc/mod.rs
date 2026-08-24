//! JSON-RPC access to Hive nodes.
//!
//! # Transport is pluggable, and the signing path does not depend on it
//!
//! The core of this crate — keys, serialization, signing — has no network dependency
//! at all, and this module is behind the `rpc` feature so that it stays that way for
//! callers who only sign. That is deliberate: `beem` pulled `requests`,
//! `websocket-client` and their transitive trees into every process that wanted to
//! produce a signature.
//!
//! [`Transport`] is the seam. Implement it over whatever HTTP client an application
//! already has, or enable the `ureq-transport` feature for a working default.
//!
//! # Failover
//!
//! [`NodeClient`] tries nodes in order and moves on when one fails. By default it does
//! **not** rank nodes by health, size waves, or manage retry budgets — an application
//! that cares about tail latency will already have policy of its own, and a library
//! that imposes its own would fight it. What this provides is the mechanism: an ordered
//! list, a per-node timeout, and an error that names every node that failed.
//!
//! That default has one sharp edge in a long-running process, though: walking the list
//! from the front every time means a dead first node costs its full timeout on *every*
//! call, forever. [`NodeClient::with_health_tracking`] is the opt-in answer — it
//! remembers which nodes and which node-and-method pairs are failing, notices nodes
//! that answer promptly with stale data, and sorts accordingly. It only ever reorders
//! the list; no node is excluded, so it cannot turn a partial outage into a total one.
//! Applications with their own policy are unaffected, because it stays off unless
//! asked for.

#[cfg(feature = "async")]
mod async_client;
mod client;
mod health;
mod types;

#[cfg(feature = "async")]
pub use async_client::{AsyncNodeClient, AsyncTransport, SleepFuture, Sleeper};
pub use client::{BlockOperation, BlockStream, NodeClient, StreamMode, Transport};
pub use health::{HealthPolicy, HealthTracker, NodeHealth};
pub use types::{DynamicGlobalProperties, RpcRequest, RpcResponse};

#[cfg(feature = "reqwest-transport")]
mod reqwest_transport;
#[cfg(feature = "reqwest-transport")]
pub use reqwest_transport::{tokio_sleeper, ReqwestTransport};

#[cfg(feature = "ureq-transport")]
mod ureq_transport;
#[cfg(feature = "ureq-transport")]
pub use ureq_transport::UreqTransport;

/// Public Hive API nodes, in no particular order of preference.
///
/// Provided as a starting point. Applications should prefer their own list: node
/// availability changes, and a hard-coded default that goes stale is exactly the kind
/// of thing that rots in an unmaintained library.
pub const DEFAULT_NODES: &[&str] = &[
    "https://api.hive.blog",
    "https://api.deathwing.me",
    "https://hive-api.arcange.eu",
    "https://api.openhive.network",
    "https://techcoderx.com",
    "https://api.syncad.com",
];
