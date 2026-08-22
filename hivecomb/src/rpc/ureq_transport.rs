//! A working [`Transport`](super::Transport) over `ureq`, behind the
//! `ureq-transport` feature.

use super::client::Transport;
use crate::error::{Error, Result};
use std::time::Duration;

/// A blocking HTTP transport.
#[derive(Debug, Default, Clone, Copy)]
pub struct UreqTransport;

impl Transport for UreqTransport {
    fn post_json(&self, url: &str, body: &str, timeout: Duration) -> Result<String> {
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .user_agent(concat!("hivecomb/", env!("CARGO_PKG_VERSION")))
            .build();
        let response = agent
            .post(url)
            .set("Content-Type", "application/json")
            .send_string(body)
            .map_err(|e| Error::Rpc(e.to_string()))?;
        response
            .into_string()
            .map_err(|e| Error::Rpc(format!("could not read response body: {e}")))
    }
}
