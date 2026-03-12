# dome-sentinel

Authentication and identity resolution for MCPDome.

## What it does

- Resolves raw MCP connections into typed `Identity` values with principal names, auth methods, and label sets.
- Chains pluggable `Authenticator` strategies with first-match semantics: if credentials are present but invalid, the chain stops (no fallthrough to weaker methods).
- Ships with built-in authenticators: `PskAuthenticator` with **Argon2id password hashing** and **constant-time comparison** (via `subtle`), plus `AnonymousAuthenticator` for open access.
- Strips credential fields (e.g., `_mcpdome_psk`) from forwarded messages so secrets never reach the upstream MCP server.
- Supports label-based identity metadata (e.g., `role:admin`, `env:staging`) for downstream policy evaluation.

## Usage

```toml
[dependencies]
dome-sentinel = "0.1"
```

```rust
use dome_sentinel::{IdentityResolver, PskAuthenticator, ResolverConfig};

let resolver = IdentityResolver::new(
    vec![Box::new(PskAuthenticator::new(entries))],
    ResolverConfig { allow_anonymous: false },
);
let identity = resolver.resolve(&msg).await?;
```

## Part of MCPDome

This crate is part of [MCPDome](https://github.com/orellius/mcpdome), a security gateway for the Model Context Protocol. See the main repository for full documentation.

## License

Apache-2.0
