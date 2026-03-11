# Contributing to MCPDome

Thanks for your interest in MCPDome. Here's how to contribute.

## Getting Started

```bash
git clone https://github.com/Orellius/mcpdome.git
cd mcpdome
cargo test --workspace
```

**Requirements:**
- Rust (2024 edition)

## Development Workflow

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run the full check suite:

```bash
cargo fmt --all          # Format
cargo clippy --workspace -- -D warnings  # Lint
cargo test --workspace   # Test
```

4. Open a pull request against `main`

## What to Contribute

**High-impact areas:**
- New injection detection patterns for `dome-ward`
- HTTP+SSE transport support for `dome-transport`
- OAuth and mTLS authenticators for `dome-sentinel`
- Policy hot-reload and file watcher
- Budget tracking and cost attribution for `dome-throttle`
- Additional audit sinks (S3, webhook, syslog)
- Documentation improvements and examples

**Before starting large changes**, open an issue to discuss the approach.

## Code Guidelines

- Follow standard Rust idioms
- Use `thiserror` for error types, `anyhow` for application errors
- Use `tracing` for logging (not `println!`)
- No `unwrap()` in library code — return `Result`
- Tests go in `#[cfg(test)] mod tests` blocks in the same file
- Keep dependencies minimal — every new dep is a liability

## Architecture Rules

- Each crate must work independently (except declared dependencies)
- Security enforcement must be deterministic — no LLM reasoning in the enforcement path
- The interceptor chain order is fixed: sentinel → throttle → policy → ward → ledger
- Default-deny: if no rule matches, the request is blocked

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
