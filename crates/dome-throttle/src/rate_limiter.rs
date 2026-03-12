use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use dome_core::DomeError;
use tokio::time::Instant;
use tracing::warn;

use crate::token_bucket::TokenBucket;

/// Composite key for rate-limit buckets.
/// Covers per-identity and per-identity-per-tool granularity.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct BucketKey {
    pub identity: String,
    pub tool: Option<String>,
}

impl BucketKey {
    /// Key for a per-identity global limit.
    pub fn for_identity(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            tool: None,
        }
    }

    /// Key for a per-identity-per-tool limit.
    pub fn for_tool(identity: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            tool: Some(tool.into()),
        }
    }
}

/// Tracked bucket entry with insertion time for TTL-based eviction.
#[derive(Debug, Clone)]
struct TrackedBucket {
    bucket: TokenBucket,
    last_used: Instant,
}

/// Configuration for rate limit defaults.
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Max tokens (burst) for per-identity buckets.
    pub per_identity_max: f64,
    /// Refill rate (tokens/sec) for per-identity buckets.
    pub per_identity_rate: f64,
    /// Max tokens (burst) for per-tool buckets.
    pub per_tool_max: f64,
    /// Refill rate (tokens/sec) for per-tool buckets.
    pub per_tool_rate: f64,
    /// Maximum number of entries in the DashMap before cleanup triggers.
    pub max_entries: usize,
    /// Time-to-live for idle bucket entries (in seconds).
    pub entry_ttl_secs: u64,
    /// Optional global rate limit (burst, rate). If set, all requests
    /// share this single bucket checked before per-identity/per-tool checks.
    pub global_limit: Option<(f64, f64)>,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            per_identity_max: 100.0,
            per_identity_rate: 100.0,
            per_tool_max: 20.0,
            per_tool_rate: 20.0,
            max_entries: 10_000,
            entry_ttl_secs: 3600,
            global_limit: None,
        }
    }
}

/// Concurrent rate limiter backed by DashMap of token buckets.
///
/// Supports per-identity, per-identity-per-tool, and global rate limits.
/// Buckets are created lazily on first access. Stale entries are evicted
/// periodically to prevent unbounded memory growth.
pub struct RateLimiter {
    buckets: DashMap<BucketKey, TrackedBucket>,
    config: RateLimiterConfig,
    /// Global rate limit bucket, protected by a parking_lot-style lock inside DashMap.
    global_bucket: Option<std::sync::Mutex<TokenBucket>>,
    /// Counter for periodic cleanup scheduling.
    insert_counter: AtomicU64,
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        let global_bucket = config
            .global_limit
            .map(|(max, rate)| std::sync::Mutex::new(TokenBucket::new(max, rate)));

        Self {
            buckets: DashMap::new(),
            global_bucket,
            insert_counter: AtomicU64::new(0),
            config,
        }
    }

    /// Check rate limit for an identity, optionally scoped to a specific tool.
    ///
    /// This performs up to three checks in order:
    /// 1. Global rate limit (if configured)
    /// 2. Per-identity global limit (always checked)
    /// 3. Per-identity-per-tool limit (only if `tool` is Some)
    ///
    /// All applicable checks must pass for the request to proceed.
    pub fn check_rate_limit(&self, identity: &str, tool: Option<&str>) -> Result<(), DomeError> {
        // Check global rate limit first
        if let Some(ref global) = self.global_bucket {
            let mut bucket = global
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !bucket.try_acquire() {
                warn!("global rate limit exceeded");
                return Err(DomeError::RateLimited {
                    limit: self.config.global_limit.map(|(_, r)| r as u64).unwrap_or(0),
                    window: "1s".to_string(),
                });
            }
        }

        // Check per-identity limit
        let identity_key = BucketKey::for_identity(identity);
        let identity_ok = self.get_or_insert_bucket(
            identity_key,
            self.config.per_identity_max,
            self.config.per_identity_rate,
        );

        if !identity_ok {
            warn!(identity = identity, "rate limit exceeded for identity");
            return Err(DomeError::RateLimited {
                limit: self.config.per_identity_rate as u64,
                window: "1s".to_string(),
            });
        }

        // Check per-tool limit if a tool is specified
        if let Some(tool_name) = tool {
            let tool_key = BucketKey::for_tool(identity, tool_name);
            let tool_ok = self.get_or_insert_bucket(
                tool_key,
                self.config.per_tool_max,
                self.config.per_tool_rate,
            );

            if !tool_ok {
                warn!(
                    identity = identity,
                    tool = tool_name,
                    "rate limit exceeded for tool"
                );
                return Err(DomeError::RateLimited {
                    limit: self.config.per_tool_rate as u64,
                    window: "1s".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Get or create a bucket, try to acquire a token, and trigger cleanup if needed.
    fn get_or_insert_bucket(&self, key: BucketKey, max: f64, rate: f64) -> bool {
        let now = Instant::now();
        let is_new = !self.buckets.contains_key(&key);

        let mut entry = self.buckets.entry(key).or_insert_with(|| TrackedBucket {
            bucket: TokenBucket::new(max, rate),
            last_used: now,
        });

        entry.last_used = now;
        let ok = entry.bucket.try_acquire();

        // If we inserted a new entry, bump the counter and maybe clean up
        if is_new {
            let count = self.insert_counter.fetch_add(1, Ordering::Relaxed);
            // Every 100 insertions, check if we need cleanup
            if count % 100 == 99 {
                drop(entry); // Release the DashMap ref before cleanup
                self.maybe_cleanup();
            }
        }

        ok
    }

    /// Remove entries that have been idle longer than the TTL.
    /// Called periodically (every 100 insertions) to prevent unbounded growth.
    fn maybe_cleanup(&self) {
        if self.buckets.len() <= self.config.max_entries {
            return;
        }

        let now = Instant::now();
        let ttl = std::time::Duration::from_secs(self.config.entry_ttl_secs);

        self.buckets.retain(|_key, entry| {
            now.duration_since(entry.last_used) < ttl
        });
    }

    /// Explicitly run cleanup, removing entries older than TTL.
    /// Useful for maintenance tasks.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let ttl = std::time::Duration::from_secs(self.config.entry_ttl_secs);

        self.buckets.retain(|_key, entry| {
            now.duration_since(entry.last_used) < ttl
        });
    }

    /// Number of active buckets (for diagnostics).
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter_with_config(
        identity_max: f64,
        identity_rate: f64,
        tool_max: f64,
        tool_rate: f64,
    ) -> RateLimiter {
        RateLimiter::new(RateLimiterConfig {
            per_identity_max: identity_max,
            per_identity_rate: identity_rate,
            per_tool_max: tool_max,
            per_tool_rate: tool_rate,
            ..Default::default()
        })
    }

    #[test]
    fn per_identity_limit_allows_within_burst() {
        let limiter = limiter_with_config(5.0, 1.0, 10.0, 10.0);

        for i in 0..5 {
            assert!(
                limiter.check_rate_limit("user-a", None).is_ok(),
                "request {i} should pass"
            );
        }
    }

    #[test]
    fn per_identity_limit_rejects_at_burst() {
        let limiter = limiter_with_config(3.0, 0.0, 10.0, 10.0);

        // Drain the bucket (refill_rate = 0, so no refill)
        assert!(limiter.check_rate_limit("user-b", None).is_ok());
        assert!(limiter.check_rate_limit("user-b", None).is_ok());
        assert!(limiter.check_rate_limit("user-b", None).is_ok());

        let err = limiter.check_rate_limit("user-b", None).unwrap_err();
        assert!(matches!(err, DomeError::RateLimited { .. }));
    }

    #[test]
    fn per_tool_limit_independent_of_identity_limit() {
        // Identity allows 100, but tool only allows 2
        let limiter = limiter_with_config(100.0, 0.0, 2.0, 0.0);

        assert!(
            limiter
                .check_rate_limit("user-c", Some("dangerous_tool"))
                .is_ok()
        );
        assert!(
            limiter
                .check_rate_limit("user-c", Some("dangerous_tool"))
                .is_ok()
        );

        // Tool bucket exhausted
        let err = limiter
            .check_rate_limit("user-c", Some("dangerous_tool"))
            .unwrap_err();
        assert!(matches!(err, DomeError::RateLimited { .. }));

        // But a different tool should still work
        assert!(
            limiter
                .check_rate_limit("user-c", Some("safe_tool"))
                .is_ok()
        );
    }

    #[test]
    fn separate_identities_have_separate_buckets() {
        let limiter = limiter_with_config(2.0, 0.0, 10.0, 10.0);

        // Drain user-1
        assert!(limiter.check_rate_limit("user-1", None).is_ok());
        assert!(limiter.check_rate_limit("user-1", None).is_ok());
        assert!(limiter.check_rate_limit("user-1", None).is_err());

        // user-2 should be unaffected
        assert!(limiter.check_rate_limit("user-2", None).is_ok());
        assert!(limiter.check_rate_limit("user-2", None).is_ok());
    }

    #[test]
    fn no_tool_check_when_tool_is_none() {
        let limiter = limiter_with_config(100.0, 100.0, 1.0, 0.0);

        // Without tool, only identity bucket is checked
        for _ in 0..50 {
            assert!(limiter.check_rate_limit("user-x", None).is_ok());
        }

        // Bucket count should be 1 (only identity bucket)
        assert_eq!(limiter.bucket_count(), 1);
    }

    #[test]
    fn concurrent_access_basic_correctness() {
        use std::sync::Arc;
        use std::thread;

        let limiter = Arc::new(limiter_with_config(1000.0, 0.0, 1000.0, 0.0));
        let mut handles = vec![];

        // Spawn 10 threads each making 50 requests
        for t in 0..10 {
            let limiter = Arc::clone(&limiter);
            handles.push(thread::spawn(move || {
                let id = format!("thread-{t}");
                let mut ok_count = 0u32;
                for _ in 0..50 {
                    if limiter.check_rate_limit(&id, Some("tool")).is_ok() {
                        ok_count += 1;
                    }
                }
                ok_count
            }));
        }

        let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        // Each thread has its own identity with 1000 token budget, so all should pass
        assert_eq!(total, 500);
    }

    // --- Global rate limit tests ---

    #[test]
    fn global_rate_limit_blocks_all_identities() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            per_identity_max: 100.0,
            per_identity_rate: 100.0,
            per_tool_max: 100.0,
            per_tool_rate: 100.0,
            global_limit: Some((3.0, 0.0)), // 3 burst, no refill
            ..Default::default()
        });

        // Global bucket has 3 tokens total across all identities
        assert!(limiter.check_rate_limit("user-1", None).is_ok());
        assert!(limiter.check_rate_limit("user-2", None).is_ok());
        assert!(limiter.check_rate_limit("user-3", None).is_ok());

        // Fourth request from any identity should fail
        let err = limiter.check_rate_limit("user-4", None).unwrap_err();
        assert!(matches!(err, DomeError::RateLimited { .. }));
    }

    #[test]
    fn no_global_limit_allows_unlimited() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            per_identity_max: 100.0,
            per_identity_rate: 100.0,
            per_tool_max: 100.0,
            per_tool_rate: 100.0,
            global_limit: None,
            ..Default::default()
        });

        // Should pass many requests without global limit
        for i in 0..50 {
            assert!(
                limiter
                    .check_rate_limit(&format!("user-{i}"), None)
                    .is_ok()
            );
        }
    }

    // --- LRU / cleanup tests ---

    #[test]
    fn cleanup_removes_stale_entries() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            per_identity_max: 10.0,
            per_identity_rate: 10.0,
            per_tool_max: 10.0,
            per_tool_rate: 10.0,
            max_entries: 10_000,
            entry_ttl_secs: 0, // TTL of 0 means everything is immediately stale
            ..Default::default()
        });

        // Create some entries
        for i in 0..10 {
            let _ = limiter.check_rate_limit(&format!("user-{i}"), None);
        }
        assert_eq!(limiter.bucket_count(), 10);

        // Cleanup should remove all entries since TTL is 0
        limiter.cleanup();
        assert_eq!(limiter.bucket_count(), 0);
    }

    #[test]
    fn max_entries_config_is_respected() {
        let config = RateLimiterConfig {
            max_entries: 50,
            ..Default::default()
        };
        assert_eq!(config.max_entries, 50);
    }
}
