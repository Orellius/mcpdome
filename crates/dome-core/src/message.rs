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
        self.params.as_ref()?.get("name")?.as_str()
    }

    /// If this is a `resources/read` request, extract the resource URI from `params.uri`.
    pub fn resource_uri(&self) -> Option<&str> {
        if self.method.as_deref() != Some("resources/read") {
            return None;
        }
        self.params.as_ref()?.get("uri")?.as_str()
    }

    /// If this is a `prompts/get` request, extract the prompt name from `params.name`.
    pub fn prompt_name(&self) -> Option<&str> {
        if self.method.as_deref() != Some("prompts/get") {
            return None;
        }
        self.params.as_ref()?.get("name")?.as_str()
    }

    /// Return the primary "resource identifier" being accessed for any MCP method.
    ///
    /// - `tools/call`      -> tool name (`params.name`)
    /// - `resources/read`  -> resource URI (`params.uri`)
    /// - `prompts/get`     -> prompt name (`params.name`)
    /// - Listing methods (`resources/list`, `tools/list`, `prompts/list`) -> `None`
    /// - All other methods -> `None`
    pub fn method_resource_name(&self) -> Option<&str> {
        match self.method.as_deref()? {
            "tools/call" => self.params.as_ref()?.get("name")?.as_str(),
            "resources/read" => self.params.as_ref()?.get("uri")?.as_str(),
            "prompts/get" => self.params.as_ref()?.get("name")?.as_str(),
            _ => None,
        }
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
        let raw =
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}"#;
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
        let resp = McpMessage::error_response(serde_json::json!(1), -32600, "denied by policy");
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

    #[test]
    fn test_resource_uri_extraction() {
        let raw = r#"{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///etc/hosts"}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.resource_uri(), Some("file:///etc/hosts"));
    }

    #[test]
    fn test_prompt_name_extraction() {
        let raw = r#"{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"summarize","arguments":{"text":"hello"}}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.prompt_name(), Some("summarize"));
    }

    #[test]
    fn test_method_resource_name_covers_all_types() {
        // tools/call -> tool name
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.method_resource_name(), Some("read_file"));

        // resources/read -> URI
        let raw = r#"{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///tmp/data.json"}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.method_resource_name(), Some("file:///tmp/data.json"));

        // prompts/get -> prompt name
        let raw =
            r#"{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"code_review"}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.method_resource_name(), Some("code_review"));

        // listing methods -> None
        for method in &["resources/list", "tools/list", "prompts/list"] {
            let raw = format!(
                r#"{{"jsonrpc":"2.0","id":10,"method":"{}","params":{{}}}}"#,
                method
            );
            let msg = McpMessage::parse(&raw).unwrap();
            assert_eq!(
                msg.method_resource_name(),
                None,
                "{} should return None",
                method
            );
        }

        // other methods -> None
        let raw = r#"{"jsonrpc":"2.0","id":99,"method":"initialize","params":{"capabilities":{}}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.method_resource_name(), None);
    }

    #[test]
    fn test_resource_uri_returns_none_for_other_methods() {
        // tools/call should not return a resource URI
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.resource_uri(), None);

        // prompts/get should not return a resource URI
        let raw =
            r#"{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"summarize"}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.resource_uri(), None);

        // response should not return a resource URI
        let raw = r#"{"jsonrpc":"2.0","id":3,"result":{"contents":[]}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.resource_uri(), None);
    }

    #[test]
    fn test_prompt_name_returns_none_for_other_methods() {
        // tools/call should not return a prompt name
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.prompt_name(), None);

        // resources/read should not return a prompt name
        let raw = r#"{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///tmp/x"}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.prompt_name(), None);

        // response should not return a prompt name
        let raw = r#"{"jsonrpc":"2.0","id":3,"result":{"messages":[]}}"#;
        let msg = McpMessage::parse(raw).unwrap();
        assert_eq!(msg.prompt_name(), None);
    }
}
