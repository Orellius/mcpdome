# dome-gate

Interceptor chain orchestration for MCPDome -- the core proxy that wires all security layers together.

## What it does

- Runs the MCPDome proxy loop, sitting between the MCP client and server on stdio.
- **Enforces session initialization** — blocks all requests until the client completes `initialize` with valid credentials. Returns JSON-RPC errors on auth failure (never forwards unauthenticated requests).
- Orchestrates the full inbound interceptor chain: Sentinel (auth) → Throttle (rate limit) → **Ward (injection)** → Policy (authz) → Ledger (audit). Ward runs before Policy so injection detection cannot be bypassed by permissive rules.
- **Guards all MCP methods** — not just `tools/call`. Rate limiting, policy, and injection scanning apply to `resources/read`, `prompts/get`, and all other methods.
- **Sends proper JSON-RPC error responses** on deny (rate limit, policy, injection) instead of silently dropping messages.
- **Strips PSK credentials** from `initialize` messages before forwarding to the upstream server.
- **Outbound scanning** — scans server responses for injection patterns and logs warnings. Blocks critical schema drift by substituting known-good schemas.
- Records every inbound and outbound decision to the hash-chained audit ledger.
- Drops invalid JSON with parse error responses instead of forwarding malformed messages.

## Usage

```toml
[dependencies]
dome-gate = "0.1"
```

```rust
use dome_gate::{Gate, GateConfig};

let gate = Gate::new(config, authenticators, policy_engine, rate_config, budget_config, ledger);
gate.run_stdio("mcp-server", &["--stdio"]).await?;
```

## Part of MCPDome

This crate is part of [MCPDome](https://github.com/orellius/mcpdome), a security gateway for the Model Context Protocol. See the main repository for full documentation.

## License

Apache-2.0
