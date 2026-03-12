<p align="center">
  <img src="assets/mcpdome-logo.png" alt="MCPDome" width="320" />
</p>

<h1 align="center">MCPDome</h1>

<p align="center"><strong>Protective Dome for AI Agents — MCP Security Gateway</strong></p>

<p align="center">
  <a href="https://crates.io/crates/mcpdome"><img src="https://img.shields.io/crates/v/mcpdome.svg" alt="crates.io" /></a>
  <a href="https://crates.io/crates?q=dome-"><img src="https://img.shields.io/badge/crates-8%20published-e6822a" alt="crates" /></a>
  <a href="https://github.com/orellius/mcpdome/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="license" /></a>
  <a href="https://github.com/orellius/mcpdome"><img src="https://img.shields.io/badge/rust-2024%20edition-orange.svg" alt="rust" /></a>
  <a href="https://docs.rs/mcpdome"><img src="https://docs.rs/mcpdome/badge.svg" alt="docs.rs" /></a>
  <a href="https://github.com/orellius/mcpdome/actions"><img src="https://github.com/orellius/mcpdome/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
</p>

<p align="center">
  If you find MCPDome useful, consider giving it a star — it helps others discover the project!
</p>

<p align="center">
  <a href="https://github.com/orellius/mcpdome/blob/main/ARCHITECTURE.md"><strong>Architecture</strong></a> ·
  <a href="https://github.com/orellius/mcpdome/blob/main/mcpdome.example.toml"><strong>Example Policy</strong></a> ·
  <a href="https://github.com/orellius/mcpdome/blob/main/CHANGELOG.md"><strong>Changelog</strong></a>
</p>

<p align="center">
  <a href="https://orellius.ai"><strong>Made by Orellius.ai</strong></a>
</p>

---

MCPDome sits between your AI agent and any MCP server, intercepting every JSON-RPC message on the wire. It enforces authentication, authorization, rate limiting, and injection detection — without modifying either side. Think of it as a firewall for AI tool calls.

<div align="center">

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

</div>

## Why MCPDome?

AI agents are getting access to powerful tools — file systems, databases, APIs, code execution. MCP is the protocol connecting them. But **there's no security layer in the middle**. MCPDome fixes that:

- **Default-deny policy engine** — TOML rules evaluated by priority, first match wins
- **Injection detection** — Regex patterns with Unicode normalization (NFKC, homoglyph transliteration, zero-width stripping), recursive JSON scanning, and heuristic analysis (entropy, Base64, length)
- **Schema pinning** — Canonical SHA-256 hashes of tool definitions detect and **block** rug pulls and tool shadowing
- **Hash-chained audit logs** — Tamper-evident NDJSON logging with SHA-256 chain linking, full inbound + outbound coverage
- **Token-bucket rate limiting** — Global, per-identity, and per-tool limits with LRU eviction and TTL-based cleanup
- **Pre-shared key authentication** — Argon2id-hashed PSKs with constant-time comparison, automatic credential stripping
- **Full method coverage** — All MCP methods are guarded (not just `tools/call`), with proper JSON-RPC error responses on deny
- **Outbound scanning** — Server responses are scanned for injection patterns before reaching the AI agent
- **0.2ms overhead** — Rust performance, single binary, zero config to start

## Install

```bash
# From crates.io
cargo install mcpdome

# From source
git clone https://github.com/orellius/mcpdome.git
cd mcpdome
cargo build --release
```

## Quick Start

Wrap any stdio MCP server — zero config, transparent mode:

```bash
mcpdome proxy --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

Enable security features progressively:

```bash
# Injection detection
mcpdome proxy --upstream "..." --enable-ward

# Schema pinning (detect tool definition changes)
mcpdome proxy --upstream "..." --enable-schema-pin

# Rate limiting
mcpdome proxy --upstream "..." --enable-rate-limit

# Everything
mcpdome proxy --upstream "..." --enable-ward --enable-schema-pin --enable-rate-limit
```

## What It Catches

<div align="center">

| Threat | How MCPDome Stops It |
|--------|---------------------|
| Prompt injection in tool args | Ward scans with Unicode normalization, recursive JSON extraction, and heuristic analysis |
| Unicode/encoding evasion | NFKC normalization, homoglyph transliteration, zero-width character stripping |
| Secret leakage (AWS keys, PATs) | Policy deny_regex with recursive argument inspection (catches nested payloads) |
| Tool rug pulls | Schema pinning with canonical JSON hashing **blocks** critical drift (not just warns) |
| Data exfiltration | Ward detects exfil patterns; outbound scanning catches malicious server responses |
| Unauthorized tool access | Default-deny policy on **all** MCP methods, not just tool calls |
| Pre-initialize attacks | Session enforcement blocks all requests before authenticated `initialize` |
| Abuse / runaway agents | Global + per-identity + per-tool rate limiting with LRU eviction |
| Credential leakage | Argon2id PSK hashing, automatic credential stripping before forwarding |
| Tampering with audit trail | SHA-256 hash chain with full inbound + outbound audit coverage |

</div>

## Policy Example

```toml
# Block secret patterns everywhere (highest priority)
[[rules]]
id = "block-secrets"
priority = 1
effect = "deny"
identities = "*"
tools = "*"
arguments = [
    { param = "*", deny_regex = ["AKIA[A-Z0-9]{16}", "ghp_[a-zA-Z0-9]{36}"] },
]

# Developers can read, not delete
[[rules]]
id = "dev-read-tools"
priority = 100
effect = "allow"
identities = { labels = ["role:developer"] }
tools = ["read_file", "grep", "git_status"]

# Write only to safe paths
[[rules]]
id = "dev-write-safe"
priority = 110
effect = "allow"
identities = { labels = ["role:developer"] }
tools = ["write_file"]
arguments = [
    { param = "path", allow_glob = ["/tmp/**"], deny_regex = [".*\\.env$"] },
]
```

See [`mcpdome.example.toml`](mcpdome.example.toml) for a complete policy file.

## Architecture

Rust workspace of focused crates, each with a single responsibility:

```
mcpdome (binary)
  ├── dome-core         Shared types & error taxonomy
  ├── dome-transport    MCP wire protocol (stdio, HTTP+SSE)
  ├── dome-gate         Interceptor chain orchestration
  ├── dome-sentinel     Authentication & identity resolution
  ├── dome-policy       TOML policy engine (default-deny)
  ├── dome-ledger       Hash-chained audit logging
  ├── dome-throttle     Token-bucket rate limiting & budgets
  └── dome-ward         Injection detection & schema pinning
```

**Interceptor chain order** (inbound):
```
sentinel → throttle → ward → policy → ledger → upstream server
```

Ward runs **before** policy so injection detection cannot be bypassed by overly permissive authorization rules.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full deep dive.

## Test Suite

154 tests covering every security component:

```
dome-core       5 tests   (message parsing, error mapping)
dome-sentinel  17 tests   (PSK auth, Argon2id hashing, chain resolution)
dome-policy    23 tests   (rules, priority, recursive arg constraints, secrets)
dome-throttle  18 tests   (token bucket, rate limits, budgets, LRU eviction, global limits)
dome-ward      63 tests   (injection patterns, Unicode normalization, recursive scanning, schema pins, heuristics)
dome-ledger    21 tests   (hash chain, tamper detection, file rotation)
integration     7 tests   (full binary proxy end-to-end)
```

```bash
cargo test --workspace
```

## Roadmap

| Phase | What Ships | Status |
|-------|-----------|--------|
| 1 | Transparent stdio proxy, audit logging | Done |
| 2 | TOML policy engine, PSK authentication, default-deny | Done |
| 3 | Injection detection, schema pinning, rate limiting | Done |
| 4 | HTTP transport, OAuth/mTLS, budget tracking, config hot-reload | Next |

## License

Apache-2.0

## Author

Orel Ohayon / [Orellius.ai](https://orellius.ai)
