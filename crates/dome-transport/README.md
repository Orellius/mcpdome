# dome-transport

MCP wire protocol transport layer for MCPDome, supporting stdio-based communication with MCP servers.

## What it does

- Defines an async `Transport` trait for reading and writing `McpMessage` values over any wire protocol.
- Implements `StdioTransport` which spawns an MCP server as a child process and communicates via stdin/stdout.
- Handles newline-delimited JSON serialization and deserialization on the wire.
- Provides graceful shutdown and child process lifecycle management.

## Usage

```toml
[dependencies]
dome-transport = "0.1"
```

```rust
use dome_transport::stdio::StdioTransport;

let transport = StdioTransport::spawn("mcp-server", &["--stdio"]).await?;
```

## Part of MCPDome

This crate is part of [MCPDome](https://github.com/orellius/mcpdome), a security gateway for the Model Context Protocol. See the main repository for full documentation.

## License

Apache-2.0
