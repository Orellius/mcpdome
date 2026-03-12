# dome-policy

TOML-based policy engine for MCPDome with default-deny authorization.

## What it does

- Parses human-readable TOML policy files into typed authorization rules with glob and regex matchers for tools, identities, and argument constraints.
- Evaluates requests against rules in priority order (lowest number = highest priority), with first-match-wins semantics.
- Enforces default-deny: if no rule matches a request, it is denied.
- Supports identity matching by principal name or label (e.g., `role:admin`), and tool matching by exact name or glob pattern.
- **Recursive argument inspection** — deny_regex and allow_glob constraints descend into nested JSON objects and arrays, preventing bypass via nested payloads.
- Returns structured `Decision` values with the matching rule ID, effect, and metadata for audit logging.

## Usage

```toml
[dependencies]
dome-policy = "0.1"
```

```rust
use dome_policy::{parse_policy, PolicyEngine, Identity};

let rules = parse_policy(toml_string)?;
let engine = PolicyEngine::new(rules)?;
let decision = engine.evaluate(&identity, "read_file", &args);
```

## Part of MCPDome

This crate is part of [MCPDome](https://github.com/orellius/mcpdome), a security gateway for the Model Context Protocol. See the main repository for full documentation.

## License

Apache-2.0
