use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// Direction of the message through the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// A single audit log entry recorded by the ledger.
///
/// Each entry captures a complete snapshot of a proxy decision:
/// who requested what, which rule applied, and how long it took.
/// The `prev_hash` field links this entry to the previous one,
/// forming a tamper-evident hash chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number, starting at 0.
    pub seq: u64,

    /// Wall-clock time when this entry was created.
    pub timestamp: DateTime<Utc>,

    /// Correlation ID for the originating JSON-RPC request.
    pub request_id: Uuid,

    /// Resolved principal string (e.g. "uid:501", "oauth:user@example.com").
    pub identity: String,

    /// Whether this was a client-to-server or server-to-client message.
    pub direction: Direction,

    /// JSON-RPC method name (e.g. "tools/call", "initialize").
    pub method: String,

    /// Tool name, if the method was "tools/call".
    pub tool: Option<String>,

    /// Human-readable decision string (e.g. "allow", "deny:policy", "deny:rate_limit").
    pub decision: String,

    /// ID of the policy rule that produced this decision, if any.
    pub rule_id: Option<String>,

    /// Processing latency in microseconds.
    pub latency_us: u64,

    /// Hex-encoded SHA-256 hash of the previous entry. Genesis entry uses all zeros.
    pub prev_hash: String,

    /// Arbitrary key-value annotations added by interceptors (e.g. ward flags).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, Value>,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::Inbound => write!(f, "inbound"),
            Direction::Outbound => write!(f, "outbound"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(seq: u64, prev_hash: &str) -> AuditEntry {
        AuditEntry {
            seq,
            timestamp: Utc::now(),
            request_id: Uuid::new_v4(),
            identity: "uid:501".to_string(),
            direction: Direction::Inbound,
            method: "tools/call".to_string(),
            tool: Some("filesystem_read".to_string()),
            decision: "allow".to_string(),
            rule_id: Some("dev-read-tools".to_string()),
            latency_us: 142,
            prev_hash: prev_hash.to_string(),
            annotations: HashMap::new(),
        }
    }

    #[test]
    fn entry_serializes_to_json() {
        let entry = sample_entry(0, "0000000000000000000000000000000000000000000000000000000000000000");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"seq\":0"));
        assert!(json.contains("\"direction\":\"inbound\""));
        assert!(json.contains("\"method\":\"tools/call\""));
        assert!(json.contains("\"tool\":\"filesystem_read\""));
    }

    #[test]
    fn entry_roundtrips_through_json() {
        let entry = sample_entry(42, "abcd1234");
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.seq, 42);
        assert_eq!(deserialized.prev_hash, "abcd1234");
        assert_eq!(deserialized.identity, "uid:501");
        assert_eq!(deserialized.direction, Direction::Inbound);
    }

    #[test]
    fn ndjson_single_line() {
        let entry = sample_entry(0, "0".repeat(64).as_str());
        let json = serde_json::to_string(&entry).unwrap();
        // NDJSON requires no embedded newlines in a single record
        assert!(!json.contains('\n'));
    }

    #[test]
    fn empty_annotations_omitted() {
        let entry = sample_entry(0, "00");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("annotations"));
    }

    #[test]
    fn annotations_present_when_populated() {
        let mut entry = sample_entry(0, "00");
        entry.annotations.insert("ward_flags".to_string(), serde_json::json!(["sensitive_path"]));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("annotations"));
        assert!(json.contains("sensitive_path"));
    }
}
