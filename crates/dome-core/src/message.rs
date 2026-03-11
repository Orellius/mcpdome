use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A parsed MCP message (JSON-RPC 2.0 envelope).
///
/// MCP uses JSON-RPC 2.0 over stdio or HTTP. Every message is one of:
/// - Request: has `method` + `params`, has `id`
/// - Response: has `result` or `error`, has `id`
/// - Notification: has `method` + `params`, no `id`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMessage {
    pub jsonrpc: String,

    /// Request/response correlation ID. None for notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,

    /// Method name (e.g. "tools/call", "tools/list", "initialize").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Method parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,

    /// Success response payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,

    /// Error response payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl McpMessage {
    /// Parse a JSON-RPC message from a raw JSON string.
    pub fn parse(raw: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(raw)
    }

    /// Serialize this message to a JSON string (no trailing newline).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// True if this is a request (has method + id).
    pub fn is_request(&self) -> bool {
        self.method.is_some() && self.id.is_some()
    }

    /// True if this is a notification (has method, no id).
    pub fn is_notification(&self) -> bool {
        self.method.is_some() && self.id.is_none()
    }

    /// True if this is a response (has result or error + id).
    pub fn is_response(&self) -> bool {
        self.id.is_some() && (self.result.is_some() || self.error.is_some())
    }

    /// If this is a tools/call request, extract the tool name.
    pub fn tool_name(&self) -> Option<&str> {
        if self.method.as_deref() != Some("tools/call") {
            return None;
        }
        self.params
            .as_ref()?
            .get("name")?
            .as_str()
    }

    /// Create a JSON-RPC error response for a given request ID.
    pub fn error_response(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: Some(id),
            method: None,
            params: None,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert!(msg.is_request());
        assert!(!msg.is_response());
        assert_eq!(msg.tool_name(), Some("read_file"));
    }

    #[test]
    fn parse_response() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert!(msg.is_response());
        assert!(!msg.is_request());
        assert_eq!(msg.tool_name(), None);
    }

    #[test]
    fn parse_notification() {
        let raw = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":"abc"}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert!(msg.is_notification());
        assert!(!msg.is_request());
    }

    #[test]
    fn error_response() {
        let resp = McpMessage::error_response(
            serde_json::json!(1),
            -32600,
            "denied by policy",
        );
        assert!(resp.is_response());
        assert_eq!(resp.error.unwrap().code, -32600);
    }

    #[test]
    fn roundtrip() {
        let raw = r#"{"jsonrpc":"2.0","id":42,"method":"initialize","params":{"capabilities":{}}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        let json = msg.to_json().unwrap();
        let msg2 = McpMessage::parse(&json).unwrap();
        assert_eq!(msg.method, msg2.method);
        assert_eq!(msg.id, msg2.id);
    }
}
