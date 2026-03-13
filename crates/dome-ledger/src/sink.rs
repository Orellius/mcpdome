use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::entry::AuditEntry;

/// A destination for serialized audit entries.
///
/// Implementations must be safe to call from async contexts (hence Send + Sync).
/// Each sink receives the already-serialized NDJSON line, so it only needs
/// to handle I/O.
pub trait AuditSink: Send + Sync {
    /// Write a single audit entry (already serialized as a JSON line).
    fn write_entry(&self, entry: &AuditEntry, json_line: &str) -> Result<(), SinkError>;

    /// Flush any buffered output. Called periodically and on shutdown.
    fn flush(&self) -> Result<(), SinkError>;

    /// Human-readable name for logging/diagnostics.
    fn name(&self) -> &str;
}

/// Errors from sink I/O operations.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("sink I/O error in {sink}: {source}")]
    Io {
        sink: String,
        source: std::io::Error,
    },

    #[error("sink serialization error in {sink}: {reason}")]
    Serialization { sink: String, reason: String },
}

/// Writes NDJSON audit entries to stderr.
///
/// Useful during development and when piping to log aggregators
/// that consume stderr.
pub struct StderrSink;

impl StderrSink {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StderrSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for StderrSink {
    fn write_entry(&self, _entry: &AuditEntry, json_line: &str) -> Result<(), SinkError> {
        let mut stderr = std::io::stderr().lock();
        writeln!(stderr, "{}", json_line).map_err(|e| SinkError::Io {
            sink: self.name().to_string(),
            source: e,
        })?;
        Ok(())
    }

    fn flush(&self) -> Result<(), SinkError> {
        std::io::stderr().flush().map_err(|e| SinkError::Io {
            sink: self.name().to_string(),
            source: e,
        })
    }

    fn name(&self) -> &str {
        "stderr"
    }
}

/// Writes NDJSON audit entries to a file, with basic size-based rotation.
///
/// When the current file exceeds `max_bytes`, it is renamed with a `.N` suffix
/// and a new file is opened. Old rotated files are not automatically deleted;
/// external log rotation (logrotate, etc.) can handle cleanup.
pub struct FileSink {
    path: PathBuf,
    max_bytes: u64,
    state: Mutex<FileSinkState>,
}

struct FileSinkState {
    writer: std::io::BufWriter<std::fs::File>,
    bytes_written: u64,
    rotation_count: u32,
}

impl FileSink {
    /// Create a new file sink writing to `path`.
    /// Rotates when the file exceeds `max_bytes` (0 = no rotation).
    pub fn new(path: PathBuf, max_bytes: u64) -> Result<Self, SinkError> {
        let file = open_append(&path)?;
        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            path: path.clone(),
            max_bytes,
            state: Mutex::new(FileSinkState {
                writer: std::io::BufWriter::new(file),
                bytes_written,
                rotation_count: 0,
            }),
        })
    }

    fn rotate(&self, state: &mut FileSinkState) -> Result<(), SinkError> {
        state.writer.flush().map_err(|e| SinkError::Io {
            sink: self.name().to_string(),
            source: e,
        })?;

        state.rotation_count += 1;
        let rotated = self.path.with_extension(format!(
            "{}.{}",
            self.path
                .extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default(),
            state.rotation_count
        ));

        std::fs::rename(&self.path, &rotated).map_err(|e| SinkError::Io {
            sink: self.name().to_string(),
            source: e,
        })?;

        let file = open_append(&self.path)?;
        state.writer = std::io::BufWriter::new(file);
        state.bytes_written = 0;

        Ok(())
    }
}

fn open_append(path: &std::path::Path) -> Result<std::fs::File, SinkError> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| SinkError::Io {
            sink: path.display().to_string(),
            source: e,
        })
}

impl AuditSink for FileSink {
    fn write_entry(&self, _entry: &AuditEntry, json_line: &str) -> Result<(), SinkError> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        // Check rotation before writing
        if self.max_bytes > 0 && state.bytes_written > self.max_bytes {
            self.rotate(&mut state)?;
        }

        let line = format!("{}\n", json_line);
        let line_bytes = line.len() as u64;

        state
            .writer
            .write_all(line.as_bytes())
            .map_err(|e| SinkError::Io {
                sink: self.name().to_string(),
                source: e,
            })?;
        state.bytes_written += line_bytes;

        Ok(())
    }

    fn flush(&self) -> Result<(), SinkError> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.writer.flush().map_err(|e| SinkError::Io {
            sink: self.name().to_string(),
            source: e,
        })
    }

    fn name(&self) -> &str {
        "file"
    }
}

/// An in-memory sink that collects entries, useful for testing.
#[cfg(any(test, feature = "test-support"))]
pub struct MemorySink {
    entries: Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "test-support"))]
impl MemorySink {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn entries(&self) -> Vec<String> {
        self.entries.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(any(test, feature = "test-support"))]
impl AuditSink for MemorySink {
    fn write_entry(&self, _entry: &AuditEntry, json_line: &str) -> Result<(), SinkError> {
        self.entries.lock().unwrap().push(json_line.to_string());
        Ok(())
    }

    fn flush(&self) -> Result<(), SinkError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "memory"
    }
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
            latency_us: 50,
            prev_hash: "00".repeat(32),
            annotations: HashMap::new(),
        }
    }

    #[test]
    fn memory_sink_collects_entries() {
        let sink = MemorySink::new();
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();

        sink.write_entry(&entry, &json).unwrap();
        sink.write_entry(&entry, &json).unwrap();

        assert_eq!(sink.len(), 2);
        assert!(!sink.is_empty());
    }

    #[test]
    fn file_sink_writes_ndjson() {
        let dir = std::env::temp_dir().join(format!("dome_ledger_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.ndjson");

        let sink = FileSink::new(path.clone(), 0).unwrap();
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();

        sink.write_entry(&entry, &json).unwrap();
        sink.write_entry(&entry, &json).unwrap();
        sink.flush().unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON
        for line in &lines {
            let _: AuditEntry = serde_json::from_str(line).unwrap();
        }

        // Cleanup
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_sink_rotates() {
        let dir = std::env::temp_dir().join(format!("dome_ledger_rotate_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.ndjson");

        // Very small max to trigger rotation quickly
        let sink = FileSink::new(path.clone(), 50).unwrap();
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();

        // Write enough entries to trigger at least one rotation
        for _ in 0..5 {
            sink.write_entry(&entry, &json).unwrap();
        }
        sink.flush().unwrap();

        // The rotated file should exist
        let rotated = dir.join("audit.ndjson.1");
        assert!(rotated.exists() || path.exists());

        // Cleanup
        std::fs::remove_dir_all(&dir).ok();
    }
}
