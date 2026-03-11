# dome-ward

Injection detection, schema integrity verification, and heuristic analysis for MCPDome.

## What it does

- Scans tool arguments and descriptions for known injection patterns (prompt injection, command injection, path traversal) using a compiled regex pattern set.
- Implements schema pinning: cryptographically hashes tool schemas on first `tools/list` response and detects drift (added, removed, or modified tools) on subsequent responses.
- Provides heuristic analysis utilities: Shannon entropy scoring, Base64 encoding detection, and suspicious length checks for identifying obfuscated payloads.
- Returns structured `InjectionMatch` and `SchemaDrift` results with severity levels for audit logging and policy decisions.

## Usage

```toml
[dependencies]
dome-ward = "0.1"
```

```rust
use dome_ward::{InjectionScanner, SchemaPinStore};

let scanner = InjectionScanner::new();
let matches = scanner.scan_text(&tool_arguments);

let mut store = SchemaPinStore::new();
store.pin_tools(&tools_list_result);
let drifts = store.verify_tools(&later_tools_list_result);
```

## Part of MCPDome

This crate is part of [MCPDome](https://github.com/orellius/mcpdome), a security gateway for the Model Context Protocol. See the main repository for full documentation.

## License

Apache-2.0
