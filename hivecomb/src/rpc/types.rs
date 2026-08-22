//! Request and response shapes for Hive's JSON-RPC.

use crate::error::{Error, Result};
use crate::transaction::BlockRef;
use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize)]
pub struct RpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

impl RpcRequest {
    /// Build a request for `method` with `params`.
    pub fn new(method: impl Into<String>, params: serde_json::Value, id: u64) -> Self {
        RpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.into(),
            params,
        }
    }
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcResponse {
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<RpcError>,
}

/// The `error` member of a JSON-RPC response.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

impl RpcResponse {
    /// Unwrap the result, turning a JSON-RPC `error` member into an [`Error`].
    ///
    /// A response carrying **both** `result` and `error` is treated as an error. beem's
    /// `noderpc` checked for `error` only after reading `result`, so a node that sent
    /// both would have its error ignored.
    pub fn into_result(self) -> Result<serde_json::Value> {
        if let Some(err) = self.error {
            return Err(Error::RpcResponse {
                code: err.code,
                message: err.message,
            });
        }
        self.result
            .ok_or_else(|| Error::Rpc("response carried neither a result nor an error".into()))
    }
}

/// The subset of `database_api.get_dynamic_global_properties` this crate needs.
#[derive(Debug, Clone, Deserialize)]
pub struct DynamicGlobalProperties {
    pub head_block_number: u32,
    pub head_block_id: String,
    pub time: String,
    #[serde(default)]
    pub last_irreversible_block_num: u32,
}

impl DynamicGlobalProperties {
    /// Derive a TaPoS reference from the head block.
    pub fn block_ref(&self) -> Result<BlockRef> {
        let block_ref = BlockRef::from_block_id(&self.head_block_id)?;
        // The block id embeds its own number in its first four bytes. If that does
        // not agree with the number the node reported alongside it, something is
        // wrong with the response and we should not sign against it.
        if block_ref.block_num != self.head_block_number {
            return Err(Error::Rpc(format!(
                "head_block_id encodes block {} but head_block_number is {}",
                block_ref.block_num, self.head_block_number
            )));
        }
        Ok(block_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_as_json_rpc_2() {
        let req = RpcRequest::new(
            "database_api.get_dynamic_global_properties",
            serde_json::json!({}),
            1,
        );
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains(r#""jsonrpc":"2.0""#));
        assert!(s.contains(r#""method":"database_api.get_dynamic_global_properties""#));
    }

    #[test]
    fn an_error_member_becomes_an_error() {
        let resp: RpcResponse = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}}"#,
        )
        .unwrap();
        match resp.into_result() {
            Err(Error::RpcResponse { code, message }) => {
                assert_eq!(code, -32602);
                assert_eq!(message, "bad params");
            }
            other => panic!("expected an RpcResponse error, got {other:?}"),
        }
    }

    #[test]
    fn an_error_wins_even_when_a_result_is_also_present() {
        let resp: RpcResponse =
            serde_json::from_str(r#"{"result":{"ok":true},"error":{"code":1,"message":"nope"}}"#)
                .unwrap();
        assert!(resp.into_result().is_err());
    }

    #[test]
    fn an_empty_response_is_an_error_not_a_null() {
        let resp: RpcResponse = serde_json::from_str(r#"{"jsonrpc":"2.0","id":1}"#).unwrap();
        assert!(resp.into_result().is_err());
    }

    #[test]
    fn block_ref_is_derived_from_the_head_block() {
        let props = DynamicGlobalProperties {
            head_block_number: 5,
            head_block_id: "00000005aabbccdd00000000000000000000abcd".into(),
            time: "2026-08-22T14:30:00".into(),
            last_irreversible_block_num: 4,
        };
        let r = props.block_ref().unwrap();
        assert_eq!(r.ref_block_num, 5);
        assert_eq!(r.ref_block_prefix, 0xddccbbaa);
    }

    #[test]
    fn an_inconsistent_head_block_is_refused() {
        // The id says block 5, the number says 9. Signing against either would be a
        // guess, so refuse.
        let props = DynamicGlobalProperties {
            head_block_number: 9,
            head_block_id: "00000005aabbccdd00000000000000000000abcd".into(),
            time: "2026-08-22T14:30:00".into(),
            last_irreversible_block_num: 4,
        };
        assert!(props.block_ref().is_err());
    }
}
