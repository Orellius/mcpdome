use sha2::{Digest, Sha256};

use crate::entry::AuditEntry;

/// The genesis hash: 64 hex zeros (SHA-256 of "nothing").
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A hash chain that computes SHA-256 digests linking each audit entry
/// to its predecessor, making any retroactive tampering detectable.
///
/// The chain starts from a genesis hash of all zeros. Each subsequent
/// entry's hash is computed over its JSON serialization, and the next
/// entry stores that hash in its `prev_hash` field.
#[derive(Debug)]
pub struct HashChain {
    /// The hash of the most recently appended entry.
    current_hash: String,
    /// Number of entries appended so far.
    len: u64,
}

impl HashChain {
    /// Create a new chain starting from the genesis hash.
    pub fn new() -> Self {
        Self {
            current_hash: GENESIS_HASH.to_string(),
            len: 0,
        }
    }

    /// Returns the hash that should be used as `prev_hash` for the next entry.
    pub fn current_hash(&self) -> &str {
        &self.current_hash
    }

    /// Returns how many entries have been appended.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns true if no entries have been appended.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append an entry to the chain. The entry's `prev_hash` must already
    /// be set to `self.current_hash()` before calling this.
    ///
    /// Returns the SHA-256 hash of the serialized entry, which becomes
    /// the new chain head.
    pub fn append(&mut self, entry: &AuditEntry) -> Result<String, ChainAppendError> {
        if entry.prev_hash != self.current_hash {
            return Err(ChainAppendError::HashMismatch {
                expected: self.current_hash.clone(),
                got: entry.prev_hash.clone(),
            });
        }
        let hash = hash_entry(entry)?;
        self.current_hash = hash.clone();
        self.len += 1;
        Ok(hash)
    }
}

impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the SHA-256 hash of an audit entry by serializing it to
/// canonical JSON and hashing the bytes.
pub fn hash_entry(entry: &AuditEntry) -> Result<String, serde_json::Error> {
    let json = serde_json::to_string(entry)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let digest = hasher.finalize();
    Ok(hex::encode(&digest))
}

/// Hex encoding helper (no external dep needed for this).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Verify the integrity of an ordered sequence of audit entries.
///
/// Walks the chain from the first entry, recomputing hashes and checking
/// that each entry's `prev_hash` matches the hash of the entry before it.
/// The first entry's `prev_hash` must be the genesis hash.
///
/// Returns `Ok(())` if the chain is valid, or `Err` with a description
/// of the first integrity violation found.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), ChainError> {
    if entries.is_empty() {
        return Ok(());
    }

    // First entry must reference genesis
    if entries[0].prev_hash != GENESIS_HASH {
        return Err(ChainError::BadGenesis {
            seq: entries[0].seq,
            got: entries[0].prev_hash.clone(),
        });
    }

    // Check sequence monotonicity
    for window in entries.windows(2) {
        if window[1].seq <= window[0].seq {
            return Err(ChainError::NonMonotonicSeq {
                prev_seq: window[0].seq,
                curr_seq: window[1].seq,
            });
        }
    }

    // Walk the chain and verify hashes
    let mut expected_prev = GENESIS_HASH.to_string();
    for entry in entries {
        if entry.prev_hash != expected_prev {
            return Err(ChainError::HashMismatch {
                seq: entry.seq,
                expected: expected_prev,
                got: entry.prev_hash.clone(),
            });
        }
        expected_prev = hash_entry(entry).map_err(|e| ChainError::SerializationFailed {
            seq: entry.seq,
            reason: e.to_string(),
        })?;
    }

    Ok(())
}

/// Errors detected during chain verification.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("entry seq={seq}: prev_hash should be genesis, got {got}")]
    BadGenesis { seq: u64, got: String },

    #[error("entry seq={seq}: expected prev_hash={expected}, got {got}")]
    HashMismatch {
        seq: u64,
        expected: String,
        got: String,
    },

    #[error("non-monotonic sequence: prev={prev_seq}, curr={curr_seq}")]
    NonMonotonicSeq { prev_seq: u64, curr_seq: u64 },

    #[error("failed to serialize entry seq={seq}: {reason}")]
    SerializationFailed { seq: u64, reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ChainAppendError {
    #[error("prev_hash mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },
    #[error("failed to serialize entry: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{AuditEntry, Direction};
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn make_entry(seq: u64, prev_hash: &str) -> AuditEntry {
        AuditEntry {
            seq,
            timestamp: Utc::now(),
            request_id: Uuid::new_v4(),
            identity: "uid:501".to_string(),
            direction: Direction::Inbound,
            method: "tools/call".to_string(),
            tool: Some("read_file".to_string()),
            decision: "allow".to_string(),
            rule_id: Some("r1".to_string()),
            latency_us: 100,
            prev_hash: prev_hash.to_string(),
            annotations: HashMap::new(),
        }
    }

    #[test]
    fn chain_starts_at_genesis() {
        let chain = HashChain::new();
        assert_eq!(chain.current_hash(), GENESIS_HASH);
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn chain_append_updates_hash() {
        let mut chain = HashChain::new();
        let entry = make_entry(0, GENESIS_HASH);
        let hash = chain.append(&entry).unwrap();

        assert_ne!(hash, GENESIS_HASH);
        assert_eq!(chain.current_hash(), &hash);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn hash_is_deterministic() {
        // Same entry produces same hash
        let entry = make_entry(0, GENESIS_HASH);
        let h1 = hash_entry(&entry).unwrap();
        let h2 = hash_entry(&entry).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_entries_produce_different_hashes() {
        let e1 = make_entry(0, GENESIS_HASH);
        let mut e2 = make_entry(0, GENESIS_HASH);
        e2.identity = "uid:999".to_string();

        let h1 = hash_entry(&e1).unwrap();
        let h2 = hash_entry(&e2).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn chain_integrity_three_entries() {
        let mut chain = HashChain::new();
        let mut entries = Vec::new();

        for seq in 0..3 {
            let entry = make_entry(seq, chain.current_hash());
            chain.append(&entry).unwrap();
            entries.push(entry);
        }

        // Each entry's prev_hash should match the hash of the previous entry
        let h0 = hash_entry(&entries[0]).unwrap();
        assert_eq!(entries[1].prev_hash, h0);

        let h1 = hash_entry(&entries[1]).unwrap();
        assert_eq!(entries[2].prev_hash, h1);
    }

    #[test]
    fn verify_valid_chain() {
        let mut chain = HashChain::new();
        let mut entries = Vec::new();

        for seq in 0..5 {
            let entry = make_entry(seq, chain.current_hash());
            chain.append(&entry).unwrap();
            entries.push(entry);
        }

        assert!(verify_chain(&entries).is_ok());
    }

    #[test]
    fn verify_empty_chain() {
        assert!(verify_chain(&[]).is_ok());
    }

    #[test]
    fn verify_detects_tampered_entry() {
        let mut chain = HashChain::new();
        let mut entries = Vec::new();

        for seq in 0..3 {
            let entry = make_entry(seq, chain.current_hash());
            chain.append(&entry).unwrap();
            entries.push(entry);
        }

        // Tamper with the middle entry
        entries[1].decision = "deny:tampered".to_string();

        let result = verify_chain(&entries);
        assert!(result.is_err());
        match result.unwrap_err() {
            ChainError::HashMismatch { seq, .. } => assert_eq!(seq, 2),
            other => panic!("expected HashMismatch, got: {other}"),
        }
    }

    #[test]
    fn verify_detects_bad_genesis() {
        let entry = make_entry(0, "not_genesis");
        let result = verify_chain(&[entry]);
        assert!(matches!(result.unwrap_err(), ChainError::BadGenesis { .. }));
    }

    #[test]
    fn verify_detects_non_monotonic_seq() {
        let mut chain = HashChain::new();
        let e0 = make_entry(0, chain.current_hash());
        chain.append(&e0).unwrap();

        // Seq goes backwards
        let e1 = make_entry(0, chain.current_hash());

        let result = verify_chain(&[e0, e1]);
        assert!(matches!(
            result.unwrap_err(),
            ChainError::NonMonotonicSeq { .. }
        ));
    }

    #[test]
    fn sequence_monotonicity_across_chain() {
        let mut chain = HashChain::new();
        let mut entries = Vec::new();

        for seq in 0..10 {
            let entry = make_entry(seq, chain.current_hash());
            chain.append(&entry).unwrap();
            entries.push(entry);
        }

        // All sequence numbers are strictly increasing
        for window in entries.windows(2) {
            assert!(window[1].seq > window[0].seq);
        }

        assert!(verify_chain(&entries).is_ok());
    }
}
