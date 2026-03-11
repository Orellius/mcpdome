# dome-gate

Interceptor chain orchestration for MCPDome -- the core proxy that wires all security layers together.

## What it does

- Runs the MCPDome proxy loop, sitting between the MCP client and server on stdio.
- Orchestrates the full inbound interceptor chain in order: authentication (Sentinel), rate limiting and budgets (Throttle), authorization (Policy), and injection scanning (Ward).
- Handles outbound interception for schema pinning, detecting tool definition drift between the first and subsequent `tools/list` responses.
- Records every decision (allow, deny, rate-limit, injection) to the hash-chained audit ledger.
- Supports transparent pass-through mode for zero-enforcement deployments.

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
