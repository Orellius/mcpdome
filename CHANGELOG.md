# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-03-13

### Added
- **HTTP+SSE transport** — `--transport http --bind-addr 127.0.0.1:3100` enables HTTP transport with Server-Sent Events, session management, restricted CORS, and 256KB body limits.
- **SIGTERM/SIGINT signal handling** — graceful shutdown via `tokio::select!` racing signal handlers against the proxy loop.
- **Upstream command validation** — PATH-based lookup before spawning child process; fails fast with actionable error message.
- **Graceful child termination** — sends EOF to child stdin, waits up to 5 seconds for clean exit, SIGKILL only as last resort.
- **Debug impl for Gate** — enables `{:?}` formatting without exposing internal interceptor state.
- **ProxyState abstraction** — extracted interceptor chain logic into shared struct, eliminating duplication between stdio and HTTP transports.
- **Full method coverage** — all MCP methods (resources/read, prompts/get, etc.) are guarded with method-specific resource extraction.
- **Outbound injection scanning** — server responses scanned for injection patterns before reaching the AI agent.
- **Configurable outbound blocking** — option to block (not just warn) when threats detected in outbound messages.
- **Bounded I/O** — 10MB max message size, 5-minute read timeouts on client connections.
- 235 tests across all crates (up from 127).

### Changed
- Interceptor chain reordered: ward now runs **before** policy so injection detection cannot be bypassed by permissive rules.
- Ward scans all MCP methods, not just `tools/call`.
- Rate limiting applies to all MCP methods with method-specific resource extraction.
- JSON-RPC error responses sent on deny instead of silently dropping messages.
- Credentials (PSK and API key) stripped from `initialize` messages before forwarding.

## [0.1.0] - 2026-03-11

### Added
- Transparent stdio proxy — wraps any MCP server, forwarding JSON-RPC messages bidirectionally.
- TOML policy engine with default-deny evaluation, priority-ordered rules, identity labels, tool matching, and argument constraints (allow_glob, deny_regex).
- Pre-shared key (PSK) authentication with identity resolution chain and anonymous fallback.
- Injection detection via compiled regex patterns: prompt injection, command injection, path traversal, encoding evasion, data exfiltration.
- Schema pinning: SHA-256 hashing of tool definitions on first `tools/list` response, drift detection on subsequent responses.
- Heuristic analysis: Shannon entropy scoring, Base64 detection, suspicious length checks.
- Token-bucket rate limiting with per-identity and per-tool limits using DashMap concurrency.
- Hash-chained audit logging: SHA-256 linked NDJSON entries with stderr and file sinks.
- Interceptor chain orchestration: sentinel → throttle → policy → ward → ledger (inbound), schema-pin → ledger (outbound).
- Progressive security enablement via CLI flags: `--enable-ward`, `--enable-schema-pin`, `--enable-rate-limit`, `--enforce-policy`.
- 8 focused crates: dome-core, dome-transport, dome-gate, dome-sentinel, dome-policy, dome-ledger, dome-throttle, dome-ward.
- 127 tests across all crates.
- Published all 9 crates to crates.io.

[Unreleased]: https://github.com/orellius/mcpdome/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/orellius/mcpdome/compare/v0.1.0...v0.4.0
[0.1.0]: https://github.com/orellius/mcpdome/releases/tag/v0.1.0
