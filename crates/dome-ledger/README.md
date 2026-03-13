# dome-ledger

Hash-chained audit logging with multiple sinks for MCPDome.

## What it does

- Records every proxy decision (allow, deny, rate-limit, injection-detected) as a structured `AuditEntry` with request ID, identity, method, tool, and timing metadata.
- Links each entry to its predecessor via a SHA-256 hash chain, making the audit log tamper-evident.
- Fans entries out to configurable `AuditSink` implementations: `StderrSink` for console output, `FileSink` for NDJSON log files, and `MemorySink` for testing.
- **Runtime chain validation** — `append()` returns `ChainAppendError` on hash mismatch instead of relying on debug assertions, catching corruption in production.
- **Mutex poisoning resilience** — file sinks recover from poisoned mutexes instead of panicking, ensuring audit logging continues after thread panics.
- Provides `verify_chain` for post-hoc integrity verification of a recorded audit sequence.

## Usage

```toml
[dependencies]
dome-ledger = "0.3"
```

```rust
use dome_ledger::{Ledger, StderrSink, FileSink};

let ledger = Ledger::new(vec![
    Box::new(StderrSink),
    Box::new(FileSink::new("audit.ndjson")?),
]);
ledger.record(entry)?;
```

## Part of MCPDome

This crate is part of [MCPDome](https://github.com/orellius/mcpdome), a security gateway for the Model Context Protocol. See the main repository for full documentation.

## License

Apache-2.0
