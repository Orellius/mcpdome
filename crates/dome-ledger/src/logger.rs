use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

use crate::chain::HashChain;
use crate::entry::{AuditEntry, Direction};
use crate::sink::{AuditSink, SinkError};

/// Builder for constructing an audit entry before it gets chained and logged.
pub struct EntryBuilder {
    pub request_id: Uuid,
    pub identity: String,
    pub direction: Direction,
    pub method: String,
    pub tool: Option<String>,
    pub decision: String,
    pub rule_id: Option<String>,
    pub latency_us: u64,
    pub annotations: HashMap<String, serde_json::Value>,
}

/// The central audit logger that maintains the hash chain and dispatches
/// serialized entries to all configured sinks.
///
/// Thread safety: the logger uses interior mutability for the chain state.
/// Callers should hold a single AuditLogger per process and call `log_entry`
/// from one task at a time (or wrap in a Mutex/channel for concurrent use).
pub struct AuditLogger {
    chain: HashChain,
    sinks: Vec<Box<dyn AuditSink>>,
    next_seq: u64,
}

impl AuditLogger {
    /// Create a new logger with the given sinks. The hash chain starts
    /// at the genesis hash.
    pub fn new(sinks: Vec<Box<dyn AuditSink>>) -> Self {
        Self {
            chain: HashChain::new(),
            sinks,
            next_seq: 0,
        }
    }

    /// Log an audit entry. This:
    /// 1. Assigns the next sequence number
    /// 2. Sets the timestamp
    /// 3. Links to the previous hash in the chain
    /// 4. Appends to the hash chain
    /// 5. Serializes to JSON
    /// 6. Writes to all sinks
    ///
    /// Returns the completed entry and its hash.
    pub fn log_entry(
        &mut self,
        builder: EntryBuilder,
    ) -> Result<(AuditEntry, String), LedgerError> {
        let entry = AuditEntry {
            seq: self.next_seq,
            timestamp: Utc::now(),
            request_id: builder.request_id,
            identity: builder.identity,
            direction: builder.direction,
            method: builder.method,
            tool: builder.tool,
            decision: builder.decision,
            rule_id: builder.rule_id,
            latency_us: builder.latency_us,
            prev_hash: self.chain.current_hash().to_string(),
            annotations: builder.annotations,
        };

        let hash = self
            .chain
            .append(&entry)
            .map_err(|e| LedgerError::Serialization(e.to_string()))?;

        let json_line = serde_json::to_string(&entry)
            .map_err(|e| LedgerError::Serialization(e.to_string()))?;

        // Write to all sinks. Collect errors but don't stop on first failure.
        let mut sink_errors: Vec<SinkError> = Vec::new();
        for sink in &self.sinks {
            if let Err(e) = sink.write_entry(&entry, &json_line) {
                tracing::error!(sink = sink.name(), error = %e, "audit sink write failed");
                sink_errors.push(e);
            }
        }

        self.next_seq += 1;

        if !sink_errors.is_empty() {
            // Log succeeded (chain advanced), but some sinks failed.
            // We still return Ok because the entry is committed to the chain.
            tracing::warn!(
                failed_sinks = sink_errors.len(),
                "some audit sinks failed to write"
            );
        }

        Ok((entry, hash))
    }

    /// Flush all sinks. Should be called on graceful shutdown.
    pub fn flush_all(&self) -> Vec<SinkError> {
        let mut errors = Vec::new();
        for sink in &self.sinks {
            if let Err(e) = sink.flush() {
                tracing::error!(sink = sink.name(), error = %e, "audit sink flush failed");
                errors.push(e);
            }
        }
        errors
    }

    /// Returns the current chain length (number of entries logged).
    pub fn chain_len(&self) -> u64 {
        self.chain.len()
    }

    /// Returns the current head hash of the chain.
    pub fn current_hash(&self) -> &str {
        self.chain.current_hash()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("failed to serialize audit entry: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{verify_chain, GENESIS_HASH};
    use crate::entry::Direction;
    use crate::sink::MemorySink;
    use std::sync::Arc;

    fn make_builder(method: &str) -> EntryBuilder {
        EntryBuilder {
            request_id: Uuid::new_v4(),
            identity: "uid:501".to_string(),
            direction: Direction::Inbound,
            method: method.to_string(),
            tool: Some("read_file".to_string()),
            decision: "allow".to_string(),
            rule_id: Some("r1".to_string()),
            latency_us: 200,
            annotations: HashMap::new(),
        }
    }

    #[test]
    fn logger_assigns_sequential_numbers() {
        let mut logger = AuditLogger::new(vec![]);

        for expected_seq in 0..5 {
            let (entry, _) = logger.log_entry(make_builder("tools/call")).unwrap();
            assert_eq!(entry.seq, expected_seq);
        }
    }

    #[test]
    fn logger_produces_valid_chain() {
        let mut logger = AuditLogger::new(vec![]);
        let mut entries = Vec::new();

        for _ in 0..10 {
            let (entry, _) = logger.log_entry(make_builder("tools/call")).unwrap();
            entries.push(entry);
        }

        // The chain should verify cleanly
        assert!(verify_chain(&entries).is_ok());
    }

    #[test]
    fn logger_first_entry_has_genesis_prev_hash() {
        let mut logger = AuditLogger::new(vec![]);
        let (entry, _) = logger.log_entry(make_builder("initialize")).unwrap();
        assert_eq!(entry.prev_hash, GENESIS_HASH);
    }

    #[test]
    fn logger_writes_to_all_sinks() {
        let sink_a = Arc::new(MemorySink::new());
        let sink_b = Arc::new(MemorySink::new());

        // We need to clone the Arcs so the logger owns them,
        // but we keep references to check later.
        let mut logger = AuditLogger::new(vec![
            Box::new(ArcSinkAdapter(Arc::clone(&sink_a))),
            Box::new(ArcSinkAdapter(Arc::clone(&sink_b))),
        ]);

        for _ in 0..3 {
            logger.log_entry(make_builder("tools/call")).unwrap();
        }

        assert_eq!(sink_a.len(), 3);
        assert_eq!(sink_b.len(), 3);

        // Both sinks should have the same content
        assert_eq!(sink_a.entries(), sink_b.entries());
    }

    #[test]
    fn logger_entries_are_valid_ndjson() {
        let sink = Arc::new(MemorySink::new());
        let mut logger = AuditLogger::new(vec![Box::new(ArcSinkAdapter(Arc::clone(&sink)))]);

        logger.log_entry(make_builder("tools/call")).unwrap();
        logger.log_entry(make_builder("tools/list")).unwrap();

        for json_line in sink.entries() {
            // Each line must be valid JSON
            let parsed: AuditEntry = serde_json::from_str(&json_line).unwrap();
            assert!(!json_line.contains('\n'));
            assert!(parsed.seq < 2);
        }
    }

    #[test]
    fn sequence_numbers_are_strictly_monotonic() {
        let mut logger = AuditLogger::new(vec![]);
        let mut prev_seq = None;

        for _ in 0..20 {
            let (entry, _) = logger.log_entry(make_builder("tools/call")).unwrap();
            if let Some(prev) = prev_seq {
                assert!(entry.seq > prev, "seq {} should be > {}", entry.seq, prev);
            }
            prev_seq = Some(entry.seq);
        }
    }

    #[test]
    fn chain_hash_advances_per_entry() {
        let mut logger = AuditLogger::new(vec![]);
        let mut hashes = Vec::new();

        for _ in 0..5 {
            let (_, hash) = logger.log_entry(make_builder("tools/call")).unwrap();
            hashes.push(hash);
        }

        // All hashes should be unique
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(unique.len(), hashes.len());
    }

    // Adapter so we can use Arc<MemorySink> as a Box<dyn AuditSink>
    struct ArcSinkAdapter(Arc<MemorySink>);

    impl AuditSink for ArcSinkAdapter {
        fn write_entry(
            &self,
            entry: &AuditEntry,
            json_line: &str,
        ) -> Result<(), crate::sink::SinkError> {
            self.0.write_entry(entry, json_line)
        }

        fn flush(&self) -> Result<(), crate::sink::SinkError> {
            self.0.flush()
        }

        fn name(&self) -> &str {
            self.0.name()
        }
    }
}
