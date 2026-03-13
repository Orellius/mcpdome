# dome-core

Shared types, traits, and error taxonomy for the MCPDome security gateway.

## What it does

- Defines `McpMessage`, a typed JSON-RPC 2.0 envelope for parsing, serializing, and inspecting MCP protocol messages (requests, responses, notifications).
- Provides `DomeError`, a unified error enum covering authentication, policy, rate-limiting, injection, schema drift, and transport failures.
- Maps every error variant to a JSON-RPC error code so the proxy can return structured responses to MCP clients.
- Supplies helper methods for common message operations: tool name extraction, request/response classification, and error response construction.

## Usage

```toml
[dependencies]
dome-core = "0.3"
```

```rust
use dome_core::{McpMessage, DomeError};

let msg = McpMessage::parse(raw_json)?;
if msg.is_request() {
    println!("tool: {:?}", msg.tool_name());
}
```

## Part of MCPDome

This crate is part of [MCPDome](https://github.com/orellius/mcpdome), a security gateway for the Model Context Protocol. See the main repository for full documentation.

## License

Apache-2.0
