# dome-ward

Injection detection, schema integrity verification, and heuristic analysis for MCPDome.

## What it does

- Scans tool arguments with **recursive JSON extraction** — walks nested objects and arrays to scan every string leaf, preventing evasion via nested payloads.
- **Unicode normalization** before scanning: NFKC normalization, zero-width character stripping, Cyrillic/Greek homoglyph transliteration, and Unicode whitespace collapsing.
- Implements schema pinning with **canonical JSON hashing** (recursively sorted keys) for deterministic SHA-256 fingerprints immune to key ordering differences.
- **Combined pattern + heuristic scanning**: regex patterns for injection/exfiltration plus entropy scoring (>4.5), Base64 detection, and suspicious length checks in a single `scan_with_heuristics()` pass.
- Returns structured `InjectionMatch`, `SchemaDrift`, and `ScanResult` values with severity levels for audit logging and policy decisions.

## Usage

```toml
[dependencies]
dome-ward = "0.3"
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
