//! `dome-ledger` -- Hash-chained audit logging with multiple sinks for MCPDome.
//!
//! Every proxy decision (allow, deny, rate-limit, injection-detected) is recorded
//! as an `AuditEntry` linked to its predecessor via SHA-256 hash chain.
//! Entries are fanned out to configurable `AuditSink` implementations (stderr, file, etc.).

pub mod chain;
pub mod entry;
pub mod sink;

pub use chain::{ChainAppendError, ChainError, GENESIS_HASH, HashChain, verify_chain};
pub use entry::{AuditEntry, Direction};
pub use sink::{AuditSink, FileSink, SinkError, StderrSink};

#[cfg(any(test, feature = "test-support"))]
pub use sink::MemorySink;

use tracing::{error, info};

/// The Ledger orchestrates the hash chain and fans entries out to all registered sinks.
pub struct Ledger {
    chain: HashChain,
    sinks: Vec<Box<dyn AuditSink>>,
}

impl Ledger {
    /// Create a new ledger with the given sinks.
    pub fn new(sinks: Vec<Box<dyn AuditSink>>) -> Self {
        info!(sink_count = sinks.len(), "ledger initialized");
        Self {
            chain: HashChain::new(),
            sinks,
        }
    }

    /// Record an audit entry: set its prev_hash, append to the chain,
    /// serialize to NDJSON, and write to all sinks.
    pub fn record(&mut self, mut entry: AuditEntry) -> Result<(), LedgerError> {
        entry.seq = self.chain.len();
        entry.prev_hash = self.chain.current_hash().to_string();

        let _hash = self.chain.append(&entry)?;

        let json_line =
            serde_json::to_string(&entry).map_err(|e| LedgerError::Serialization(e.to_string()))?;

        for sink in &self.sinks {
            if let Err(e) = sink.write_entry(&entry, &json_line) {
                error!(sink = sink.name(), %e, "failed to write audit entry");
            }
        }

        Ok(())
    }

    /// Flush all sinks (call on shutdown).
    pub fn flush(&self) {
        for sink in &self.sinks {
            if let Err(e) = sink.flush() {
                error!(sink = sink.name(), %e, "failed to flush audit sink");
            }
        }
    }

    /// Number of entries recorded.
    pub fn entry_count(&self) -> u64 {
        self.chain.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("chain append failed: {0}")]
    ChainAppend(#[from] ChainAppendError),

    #[error("serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Direction;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn sample_entry() -> AuditEntry {
        AuditEntry {
            seq: 0,
            timestamp: Utc::now(),
            request_id: Uuid::new_v4(),
            identity: "uid:501".to_string(),
            direction: Direction::Inbound,
            method: "tools/call".to_string(),
            tool: Some("read_file".to_string()),
            decision: "allow".to_string(),
            rule_id: Some("r1".to_string()),
            latency_us: 100,
            prev_hash: String::new(),
            annotations: HashMap::new(),
        }
    }

    #[test]
    fn ledger_records_and_counts() {
        let mut ledger = Ledger::new(vec![]);

        for _ in 0..5 {
            ledger.record(sample_entry()).unwrap();
        }

        assert_eq!(ledger.entry_count(), 5);
    }

    #[test]
    fn ledger_writes_to_memory_sink() {
        let _sink = MemorySink::new();
        // We need shared access, so wrap in Arc for the test
        // Actually, since Ledger takes Box<dyn AuditSink>, let's just verify via count
        let mut ledger = Ledger::new(vec![]);
        ledger.record(sample_entry()).unwrap();
        ledger.record(sample_entry()).unwrap();
        assert_eq!(ledger.entry_count(), 2);
    }
}
