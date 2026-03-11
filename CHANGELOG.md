# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/orellius/mcpdome/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/orellius/mcpdome/releases/tag/v0.1.0
