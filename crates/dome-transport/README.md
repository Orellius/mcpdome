# dome-transport

MCP wire protocol transport layer for MCPDome, supporting stdio and HTTP+SSE communication with MCP servers.

## What it does

- Defines an async `Transport` trait for reading and writing `McpMessage` values over any wire protocol.
- Implements `StdioTransport` which spawns an MCP server as a child process and communicates via stdin/stdout.
- Implements `HttpSseTransport` (feature-gated) with Server-Sent Events, session management, and CORS support.
- **Bounded reads** — enforces a 10MB maximum message size to prevent memory exhaustion from oversized payloads.
- **Timeouts** — 5-minute read timeout and 30-second write timeout prevent hung connections from blocking resources.
- **HTTP body limits** — 256KB body limit on HTTP transport with restricted CORS defaults (localhost only).
- Handles newline-delimited JSON serialization and deserialization on the wire.
- Provides graceful shutdown and child process lifecycle management.

## Usage

```toml
[dependencies]
dome-transport = "0.3"
```

```rust
use dome_transport::stdio::StdioTransport;

let transport = StdioTransport::spawn("mcp-server", &["--stdio"]).await?;
```

## Part of MCPDome

This crate is part of [MCPDome](https://github.com/orellius/mcpdome), a security gateway for the Model Context Protocol. See the main repository for full documentation.

## License

Apache-2.0
