//! A working [`AsyncTransport`](super::AsyncTransport) on `reqwest`, behind the
//! `reqwest-transport` feature.
//!
//! This is the batteries-included option. The async layer itself pulls in no executor;
//! this module is where tokio and reqwest enter, and only if you ask for them.

use super::async_client::AsyncTransport;
use crate::error::{Error, Result};
use std::future::Future;
use std::time::Duration;

/// An async HTTP transport.
///
/// Holds one `reqwest::Client`, so connections are pooled across calls and across
/// nodes — which matters when racing several at once.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build a transport with a pooled client.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("hivecomb/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Rpc(format!("could not build HTTP client: {e}")))?;
        Ok(ReqwestTransport { client })
    }

    /// Wrap an existing client, so an application's own configuration — proxies,
    /// certificates, connection limits — carries over.
    pub fn from_client(client: reqwest::Client) -> Self {
        ReqwestTransport { client }
    }
}

impl AsyncTransport for ReqwestTransport {
    fn post_json(
        &self,
        url: &str,
        body: &str,
        timeout: Duration,
    ) -> impl Future<Output = Result<String>> + Send {
        // Clone into the future so it borrows nothing: the client is cheap to clone
        // (it is an Arc internally) and this keeps the future `'static`, which is what
        // lets it be raced and spawned.
        let client = self.client.clone();
        let url = url.to_string();
        let body = body.to_string();
        async move {
            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .timeout(timeout)
                .body(body)
                .send()
                .await
                .map_err(|e| Error::Rpc(e.to_string()))?;
            response
                .text()
                .await
                .map_err(|e| Error::Rpc(format!("could not read response body: {e}")))
        }
    }
}

/// A sleeper for [`AsyncNodeClient::with_retries`](super::AsyncNodeClient::with_retries),
/// on tokio.
///
/// The client takes the sleep rather than assuming one so that no executor is baked
/// into the async layer. This is the convenience for the common case:
///
/// ```ignore
/// let client = AsyncNodeClient::new(ReqwestTransport::new()?, nodes)?
///     .with_retries(3, Duration::from_millis(250), tokio_sleeper());
/// ```
pub fn tokio_sleeper() -> impl Fn(Duration) -> tokio::time::Sleep + Send + Sync + 'static {
    tokio::time::sleep
}
