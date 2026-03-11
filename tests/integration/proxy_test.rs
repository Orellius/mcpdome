//! Integration tests for MCPDome proxy.
//!
//! These tests spawn the echo_server.py fixture as a child process and
//! verify that MCP JSON-RPC messages pass through correctly. We test at
//! two levels:
//!   1. StdioTransport level (spawn + send/recv directly)
//!   2. Full binary level (spawn mcpdome proxy, pipe messages through it)

use dome_core::McpMessage;
use dome_transport::stdio::StdioTransport;
use serde_json::json;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

/// Resolve the path to the echo_server.py fixture.
fn echo_server_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/echo_server.py");
    path
}

/// Helper: send a raw JSON-RPC message string through a StdioWriter, receive via StdioReader.
/// Returns the parsed McpMessage response.
async fn send_and_recv(
    writer: &mut dome_transport::stdio::StdioWriter,
    reader: &mut dome_transport::stdio::StdioReader,
    msg: &McpMessage,
) -> McpMessage {
    writer.send(msg).await.expect("failed to send message");
    timeout(Duration::from_secs(5), reader.recv())
        .await
        .expect("timed out waiting for response")
        .expect("failed to receive response")
}

/// Build a JSON-RPC request McpMessage.
fn make_request(id: serde_json::Value, method: &str, params: serde_json::Value) -> McpMessage {
    McpMessage {
        jsonrpc: "2.0".to_string(),
        id: Some(id),
        method: Some(method.to_string()),
        params: Some(params),
        result: None,
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Transport-level tests: spawn echo_server.py via StdioTransport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_initialize_through_transport() {
    let server_path = echo_server_path();
    let transport = StdioTransport::spawn("python3", &[server_path.to_str().unwrap()])
        .await
        .expect("failed to spawn echo server");
    let (mut reader, mut writer, mut child) = transport.split();

    let request = make_request(json!(1), "initialize", json!({"capabilities": {}}));
    let response = send_and_recv(&mut writer, &mut reader, &request).await;

    assert!(
        response.is_response(),
        "expected a response, got: {:?}",
        response
    );
    assert_eq!(response.id, Some(json!(1)));

    let result = response
        .result
        .expect("expected result in initialize response");
    assert_eq!(result["protocolVersion"], "2024-11-05");
    assert_eq!(result["serverInfo"]["name"], "echo-test-server");
    assert!(result["capabilities"]["tools"].is_object());

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_tools_list_through_transport() {
    let server_path = echo_server_path();
    let transport = StdioTransport::spawn("python3", &[server_path.to_str().unwrap()])
        .await
        .expect("failed to spawn echo server");
    let (mut reader, mut writer, mut child) = transport.split();

    let request = make_request(json!(2), "tools/list", json!({}));
    let response = send_and_recv(&mut writer, &mut reader, &request).await;

    assert!(response.is_response());
    assert_eq!(response.id, Some(json!(2)));

    let result = response
        .result
        .expect("expected result in tools/list response");
    let tools = result["tools"]
        .as_array()
        .expect("tools should be an array");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "echo");
    assert_eq!(tools[0]["inputSchema"]["type"], "object");

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_tools_call_echo_through_transport() {
    let server_path = echo_server_path();
    let transport = StdioTransport::spawn("python3", &[server_path.to_str().unwrap()])
        .await
        .expect("failed to spawn echo server");
    let (mut reader, mut writer, mut child) = transport.split();

    let request = make_request(
        json!(3),
        "tools/call",
        json!({"name": "echo", "arguments": {"message": "hello from MCPDome"}}),
    );
    let response = send_and_recv(&mut writer, &mut reader, &request).await;

    assert!(response.is_response());
    assert_eq!(response.id, Some(json!(3)));

    let result = response
        .result
        .expect("expected result in tools/call response");
    let content = result["content"]
        .as_array()
        .expect("content should be an array");
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], "text");
    assert_eq!(content[0]["text"], "hello from MCPDome");

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_tools_call_unknown_tool_returns_error() {
    let server_path = echo_server_path();
    let transport = StdioTransport::spawn("python3", &[server_path.to_str().unwrap()])
        .await
        .expect("failed to spawn echo server");
    let (mut reader, mut writer, mut child) = transport.split();

    let request = make_request(
        json!(4),
        "tools/call",
        json!({"name": "nonexistent", "arguments": {}}),
    );
    let response = send_and_recv(&mut writer, &mut reader, &request).await;

    assert!(response.is_response());
    assert_eq!(response.id, Some(json!(4)));
    assert!(response.error.is_some(), "expected error for unknown tool");
    let err = response.error.unwrap();
    assert_eq!(err.code, -32601);
    assert!(err.message.contains("nonexistent"));

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_unknown_method_echoes_back() {
    let server_path = echo_server_path();
    let transport = StdioTransport::spawn("python3", &[server_path.to_str().unwrap()])
        .await
        .expect("failed to spawn echo server");
    let (mut reader, mut writer, mut child) = transport.split();

    let request = make_request(json!(5), "custom/ping", json!({"data": "test123"}));
    let response = send_and_recv(&mut writer, &mut reader, &request).await;

    assert!(response.is_response());
    assert_eq!(response.id, Some(json!(5)));

    let result = response.result.expect("expected echo result");
    // The echo server wraps the original message under "echo"
    let echoed = &result["echo"];
    assert_eq!(echoed["method"], "custom/ping");
    assert_eq!(echoed["params"]["data"], "test123");

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_multiple_sequential_requests() {
    let server_path = echo_server_path();
    let transport = StdioTransport::spawn("python3", &[server_path.to_str().unwrap()])
        .await
        .expect("failed to spawn echo server");
    let (mut reader, mut writer, mut child) = transport.split();

    // Send initialize, tools/list, tools/call in sequence -- verify ordering is preserved
    let init = make_request(json!(1), "initialize", json!({"capabilities": {}}));
    let r1 = send_and_recv(&mut writer, &mut reader, &init).await;
    assert_eq!(r1.id, Some(json!(1)));
    assert!(r1.result.is_some());

    let list = make_request(json!(2), "tools/list", json!({}));
    let r2 = send_and_recv(&mut writer, &mut reader, &list).await;
    assert_eq!(r2.id, Some(json!(2)));
    assert!(r2.result.is_some());

    let call = make_request(
        json!(3),
        "tools/call",
        json!({"name": "echo", "arguments": {"message": "seq-test"}}),
    );
    let r3 = send_and_recv(&mut writer, &mut reader, &call).await;
    assert_eq!(r3.id, Some(json!(3)));
    let r3_result = r3.result.unwrap();
    let content = r3_result["content"][0]["text"].as_str().unwrap();
    assert_eq!(content, "seq-test");

    let _ = child.kill().await;
}

// ---------------------------------------------------------------------------
// Full binary proxy test: spawn mcpdome as a proxy in front of echo_server.py
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_full_proxy_passthrough() {
    let server_path = echo_server_path();

    // Build the mcpdome binary path from CARGO_BIN_EXE (set by cargo test)
    let mcpdome_bin = env!("CARGO_BIN_EXE_mcpdome");

    let upstream_cmd = format!("python3 {}", server_path.display());

    let mut proxy = Command::new(mcpdome_bin)
        .arg("proxy")
        .arg("--upstream")
        .arg(&upstream_cmd)
        .arg("--log-level")
        .arg("off")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn mcpdome proxy");

    let mut stdin = proxy.stdin.take().expect("failed to get proxy stdin");
    let stdout = proxy.stdout.take().expect("failed to get proxy stdout");
    let mut reader = BufReader::new(stdout);

    // Helper closure: send a line and read the response line
    async fn send_line(
        stdin: &mut tokio::process::ChildStdin,
        reader: &mut BufReader<tokio::process::ChildStdout>,
        request: &str,
    ) -> String {
        stdin
            .write_all(format!("{}\n", request).as_bytes())
            .await
            .expect("failed to write to proxy stdin");
        stdin.flush().await.expect("failed to flush proxy stdin");

        let mut line = String::new();
        timeout(Duration::from_secs(10), reader.read_line(&mut line))
            .await
            .expect("timed out reading from proxy")
            .expect("failed to read from proxy stdout");
        line.trim().to_string()
    }

    // 1. initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"capabilities": {}}
    });
    let resp_str = send_line(&mut stdin, &mut reader, &init_req.to_string()).await;
    let resp: serde_json::Value = serde_json::from_str(&resp_str).expect("invalid JSON from proxy");
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["serverInfo"]["name"], "echo-test-server");

    // 2. tools/list
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    let resp_str = send_line(&mut stdin, &mut reader, &list_req.to_string()).await;
    let resp: serde_json::Value = serde_json::from_str(&resp_str).expect("invalid JSON from proxy");
    assert_eq!(resp["id"], 2);
    assert_eq!(resp["result"]["tools"][0]["name"], "echo");

    // 3. tools/call
    let call_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "proxy-e2e"}}
    });
    let resp_str = send_line(&mut stdin, &mut reader, &call_req.to_string()).await;
    let resp: serde_json::Value = serde_json::from_str(&resp_str).expect("invalid JSON from proxy");
    assert_eq!(resp["id"], 3);
    assert_eq!(resp["result"]["content"][0]["text"], "proxy-e2e");

    // Close stdin to signal shutdown
    drop(stdin);
    let status = timeout(Duration::from_secs(5), proxy.wait())
        .await
        .expect("timed out waiting for proxy to exit")
        .expect("failed to wait for proxy");
    // The proxy should exit cleanly (or be killed, either is fine)
    let _ = status;
}
