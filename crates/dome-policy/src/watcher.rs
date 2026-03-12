//! Policy hot-reload via file watching and SIGHUP signal handling.
//!
//! [`PolicyWatcher`] monitors a policy TOML file for changes using the `notify`
//! crate and atomically swaps the active [`PolicyEngine`] via `arc-swap`. On
//! Unix systems, it also listens for SIGHUP to force an immediate re-read.
//!
//! Invalid policy files are logged and ignored -- the last known-good engine
//! remains active. This ensures a typo in a config change never crashes a
//! running proxy.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::evaluator::PolicyEngine;
use crate::parser::parse_policy;

/// Shared handle to the active policy engine.
///
/// Readers call `policy.load()` for a lock-free snapshot.
/// The watcher swaps in new engines atomically via `policy.store(...)`.
pub type SharedPolicyEngine = Arc<ArcSwap<PolicyEngine>>;

/// Errors that can occur when setting up the policy watcher.
#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("failed to read policy file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse policy: {0}")]
    Parse(#[from] crate::parser::PolicyParseError),

    #[error("failed to build policy engine: {0}")]
    Build(#[from] crate::evaluator::PolicyBuildError),

    #[error("failed to initialize file watcher: {0}")]
    Notify(#[from] notify::Error),
}

/// Watches a policy TOML file for changes and hot-swaps the active engine.
///
/// # Usage
///
/// ```ignore
/// let (watcher, shared_engine) = PolicyWatcher::new("./mcpdome.toml").await?;
/// // Pass `shared_engine` to the gate / interceptor chain.
/// // Spawn the watcher to run in the background:
/// tokio::spawn(watcher.run());
/// ```
pub struct PolicyWatcher {
    policy_path: PathBuf,
    shared: SharedPolicyEngine,
    /// Channel that receives reload signals (from file watcher or SIGHUP).
    reload_rx: mpsc::Receiver<ReloadTrigger>,
    /// Keep the notify watcher alive for the lifetime of this struct.
    _fs_watcher: RecommendedWatcher,
}

/// What triggered the reload.
#[derive(Debug)]
enum ReloadTrigger {
    FileChanged,
    #[cfg(unix)]
    Sighup,
}

impl PolicyWatcher {
    /// Create a new watcher for the given policy file path.
    ///
    /// Loads and validates the policy immediately. Returns the watcher (which
    /// must be spawned) and a shared handle to the active engine.
    pub async fn new(path: impl AsRef<Path>) -> Result<(Self, SharedPolicyEngine), WatcherError> {
        let policy_path = path.as_ref().to_path_buf();

        // Initial load.
        let engine = load_engine_from_file(&policy_path)?;
        let rule_count = engine.rule_count();
        let shared: SharedPolicyEngine = Arc::new(ArcSwap::from_pointee(engine));

        info!(
            path = %policy_path.display(),
            rules = rule_count,
            "policy loaded (initial)"
        );

        // Set up an mpsc channel for reload triggers. Buffer a few to avoid
        // dropping events if we're mid-reload.
        let (reload_tx, reload_rx) = mpsc::channel::<ReloadTrigger>(16);

        // --- File system watcher ---
        let fs_tx = reload_tx.clone();
        let watch_path = policy_path.clone();
        let mut fs_watcher =
            notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        // Only react to writes / creates (covers editors that
                        // rename-and-replace).
                        if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                            let _ = fs_tx.try_send(ReloadTrigger::FileChanged);
                        }
                    }
                    Err(e) => {
                        warn!(%e, "file watcher error");
                    }
                }
            })?;

        // Watch the parent directory so we catch rename-and-replace patterns
        // used by editors (vim, emacs, etc.). If the file has no parent, watch
        // the file itself.
        let watch_target = watch_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| watch_path.clone());
        fs_watcher.watch(&watch_target, RecursiveMode::NonRecursive)?;

        // --- SIGHUP handler (Unix only) ---
        #[cfg(unix)]
        {
            let sig_tx = reload_tx.clone();
            tokio::spawn(async move {
                let mut stream =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                        .expect("failed to register SIGHUP handler");
                loop {
                    stream.recv().await;
                    info!("received SIGHUP -- triggering policy reload");
                    let _ = sig_tx.try_send(ReloadTrigger::Sighup);
                }
            });
        }

        let shared_clone = Arc::clone(&shared);
        Ok((
            Self {
                policy_path,
                shared,
                reload_rx,
                _fs_watcher: fs_watcher,
            },
            shared_clone,
        ))
    }

    /// Run the watcher loop. This future never resolves under normal operation.
    ///
    /// Debounces rapid file-change events (editors sometimes fire multiple
    /// events for a single save). After each trigger, waits 200ms for more
    /// events before performing the reload.
    pub async fn run(mut self) {
        const DEBOUNCE: Duration = Duration::from_millis(200);

        loop {
            // Wait for a reload signal.
            let trigger = match self.reload_rx.recv().await {
                Some(t) => t,
                None => {
                    info!("reload channel closed -- watcher exiting");
                    return;
                }
            };

            // Debounce: drain any additional events that arrive within the
            // debounce window so we only reload once per burst.
            #[cfg(unix)]
            let is_sighup = matches!(trigger, ReloadTrigger::Sighup);
            #[cfg(not(unix))]
            let is_sighup = false;

            if !is_sighup {
                tokio::time::sleep(DEBOUNCE).await;
                // Drain any queued events.
                while self.reload_rx.try_recv().is_ok() {}
            }

            self.perform_reload();
        }
    }

    /// Attempt to reload the policy file and swap the engine.
    fn perform_reload(&self) {
        match load_engine_from_file(&self.policy_path) {
            Ok(engine) => {
                let rule_count = engine.rule_count();
                self.shared.store(Arc::new(engine));
                info!(
                    path = %self.policy_path.display(),
                    rules = rule_count,
                    "policy reloaded successfully"
                );
            }
            Err(e) => {
                // Keep the last known-good engine. Never crash.
                warn!(
                    path = %self.policy_path.display(),
                    %e,
                    "policy reload failed -- keeping previous config"
                );
            }
        }
    }

    /// Get a clone of the shared engine handle.
    pub fn shared_engine(&self) -> SharedPolicyEngine {
        Arc::clone(&self.shared)
    }
}

/// Load, parse, and build a `PolicyEngine` from a TOML file on disk.
fn load_engine_from_file(path: &Path) -> Result<PolicyEngine, WatcherError> {
    let content = std::fs::read_to_string(path)?;
    let rules = parse_policy(&content)?;
    let engine = PolicyEngine::new(rules)?;
    Ok(engine)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::NamedTempFile;

    /// Helper: write a valid policy TOML and return the path.
    fn write_policy(file: &NamedTempFile, toml: &str) {
        std::fs::write(file.path(), toml).unwrap();
    }

    fn valid_policy_v1() -> &'static str {
        r#"
[[rules]]
id = "allow-all"
priority = 100
effect = "allow"
identities = "*"
tools = "*"
"#
    }

    fn valid_policy_v2() -> &'static str {
        r#"
[[rules]]
id = "allow-read"
priority = 100
effect = "allow"
identities = "*"
tools = ["read_file"]

[[rules]]
id = "deny-write"
priority = 50
effect = "deny"
identities = "*"
tools = ["write_file"]
"#
    }

    fn invalid_policy() -> &'static str {
        r#"
[[rules
this is not valid toml!!!
"#
    }

    // --- Test: file modification triggers reload ---

    #[tokio::test]
    async fn file_change_triggers_reload() {
        let tmp = NamedTempFile::new().unwrap();
        write_policy(&tmp, valid_policy_v1());

        let (watcher, shared) = PolicyWatcher::new(tmp.path()).await.unwrap();

        // Initial state: 1 rule.
        assert_eq!(shared.load().rule_count(), 1);

        // Spawn the watcher.
        let handle = tokio::spawn(watcher.run());

        // Give the watcher time to start.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Modify the policy file.
        write_policy(&tmp, valid_policy_v2());

        // Wait for debounce + reload.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Engine should now have 2 rules.
        assert_eq!(shared.load().rule_count(), 2);

        handle.abort();
    }

    // --- Test: invalid policy does not replace good config ---

    #[tokio::test]
    async fn invalid_policy_keeps_last_good() {
        let tmp = NamedTempFile::new().unwrap();
        write_policy(&tmp, valid_policy_v1());

        let (watcher, shared) = PolicyWatcher::new(tmp.path()).await.unwrap();
        assert_eq!(shared.load().rule_count(), 1);

        let handle = tokio::spawn(watcher.run());
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Write invalid policy.
        write_policy(&tmp, invalid_policy());
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Still has the old good engine.
        assert_eq!(shared.load().rule_count(), 1);

        // Now write a valid policy again.
        write_policy(&tmp, valid_policy_v2());
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert_eq!(shared.load().rule_count(), 2);

        handle.abort();
    }

    // --- Test: atomic swap under concurrent reads ---

    #[tokio::test]
    async fn atomic_swap_under_concurrent_reads() {
        let tmp = NamedTempFile::new().unwrap();
        write_policy(&tmp, valid_policy_v1());

        let (watcher, shared) = PolicyWatcher::new(tmp.path()).await.unwrap();

        let watcher_handle = tokio::spawn(watcher.run());

        // Spawn concurrent readers.
        let read_count = Arc::new(AtomicUsize::new(0));
        let mut reader_handles = Vec::new();

        for _ in 0..10 {
            let shared_clone = Arc::clone(&shared);
            let count = Arc::clone(&read_count);
            reader_handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    // Load should never panic or return a partially-constructed engine.
                    let engine = shared_clone.load();
                    let rc = engine.rule_count();
                    // Must be either 1 (v1) or 2 (v2). Never 0 or anything else.
                    assert!(rc == 1 || rc == 2, "unexpected rule count: {rc}");
                    count.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }));
        }

        // Mid-way through the reads, swap the policy.
        tokio::time::sleep(Duration::from_millis(50)).await;
        write_policy(&tmp, valid_policy_v2());

        // Wait for all readers to finish.
        for h in reader_handles {
            h.await.unwrap();
        }

        assert_eq!(read_count.load(Ordering::Relaxed), 1000);

        watcher_handle.abort();
    }

    // --- Test: load_engine_from_file works ---

    #[test]
    fn load_engine_from_file_success() {
        let tmp = NamedTempFile::new().unwrap();
        write_policy(&tmp, valid_policy_v1());
        let engine = load_engine_from_file(tmp.path()).unwrap();
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn load_engine_from_file_invalid_toml() {
        let tmp = NamedTempFile::new().unwrap();
        write_policy(&tmp, invalid_policy());
        let err = load_engine_from_file(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("parse"));
    }

    #[test]
    fn load_engine_from_file_missing_file() {
        let err = load_engine_from_file(Path::new("/nonexistent/policy.toml")).unwrap_err();
        assert!(matches!(err, WatcherError::Io(_)));
    }
}
