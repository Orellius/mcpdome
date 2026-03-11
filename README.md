# MCPDome -- Iron Dome for AI Agents

Transparent security proxy for the Model Context Protocol (MCP).

MCPDome sits between your AI agent and any MCP server, intercepting every JSON-RPC message on the wire. It enforces authentication, authorization, rate limiting, and injection detection -- without modifying either side. Think of it as a firewall for AI tool calls.

```
┌──────────┐         ┌─────────┐         ┌────────────┐
│ AI Agent │ ──MCP──>│ MCPDome │──MCP──> │ MCP Server │
│ (Client) │<──MCP── │ Gateway │<──MCP── │  (Tools)   │
└──────────┘         └─────────┘         └────────────┘
                          │
                     ┌────┴────┐
                     │ Policy  │
                     │  TOML   │
                     └─────────┘
```

## Install

```bash
# From crates.io (planned)
cargo install mcpdome

# From source
git clone https://github.com/orellius/mcpdome.git
cd mcpdome
cargo build --release
```

## Usage

Wrap any stdio MCP server:

```bash
mcpdome proxy --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

Proxy an HTTP MCP server:

```bash
mcpdome proxy --transport http --upstream "https://mcp.example.com" --listen 0.0.0.0:3100
```

Validate policy before deploying:

```bash
mcpdome validate --config ./mcpdome.toml
```

## Status

**v0.1.0 -- Transparent Proxy (Phase 1)**

The proxy relays MCP traffic end-to-end over stdio with audit logging. Policy enforcement and detection are coming next.

## Roadmap

| Phase | Version | What Ships |
|-------|---------|------------|
| 1     | v0.1.0  | Transparent stdio proxy, audit logging |
| 2     | v0.2.0  | TOML policy engine, authentication, default-deny authorization |
| 3     | v0.3.0  | Injection detection, schema pinning, rate limiting |
| 4     | v1.0.0  | HTTP transport, OAuth/mTLS, budget tracking, signed audit logs |

## Architecture

Rust workspace of focused crates:

```
mcpdome (binary)
  ├── dome-core         Shared types & error taxonomy
  ├── dome-transport    MCP wire protocol (stdio, HTTP+SSE)
  ├── dome-gate         Interceptor chain orchestration
  ├── dome-sentinel     Authentication & identity
  ├── dome-policy       TOML policy engine
  ├── dome-ledger       Hash-chained audit logging
  ├── dome-throttle     Rate limiting & budget control
  └── dome-ward         Injection detection & schema pinning
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full deep dive.

## License

Apache-2.0

## Author

Orel Ohayon / [Orellius.ai](https://orellius.ai)
