# dome-throttle

Token-bucket rate limiting and budget tracking for MCPDome.

## What it does

- Provides `RateLimiter` with **global**, per-identity, and per-tool token-bucket rate limiting, using DashMap for lock-free concurrent access.
- **TOCTOU-safe bucket access** — uses DashMap's `entry()` API for atomic get-or-insert, eliminating race conditions in concurrent bucket creation.
- **LRU eviction with TTL** — DashMap entries are automatically cleaned up when the map exceeds `max_entries`, preventing unbounded memory growth from unique identity/tool combinations.
- Provides `BudgetTracker` for cumulative spend tracking per identity with configurable rolling time windows, caps, and TTL-based eviction.
- Returns `DomeError::RateLimited` or `DomeError::BudgetExhausted` on violation, allowing the interceptor chain to block and audit the request.
- Supports configurable bucket sizes, refill rates, global limits, and budget limits via `RateLimiterConfig` and `BudgetTrackerConfig`.

## Usage

```toml
[dependencies]
dome-throttle = "0.4"
```

```rust
use dome_throttle::{RateLimiter, RateLimiterConfig};

let limiter = RateLimiter::new(RateLimiterConfig::default());
limiter.check_rate_limit("user:alice", Some("read_file"))?;
```

## Part of MCPDome

This crate is part of [MCPDome](https://github.com/orellius/mcpdome), a security gateway for the Model Context Protocol. See the main repository for full documentation.

## License

Apache-2.0
