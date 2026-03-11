use dashmap::DashMap;
use dome_core::DomeError;
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
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            per_identity_max: 100.0,
            per_identity_rate: 100.0,
            per_tool_max: 20.0,
            per_tool_rate: 20.0,
        }
    }
}

/// Concurrent rate limiter backed by DashMap of token buckets.
///
/// Supports per-identity and per-identity-per-tool limits.
/// Buckets are created lazily on first access.
pub struct RateLimiter {
    buckets: DashMap<BucketKey, TokenBucket>,
    config: RateLimiterConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            buckets: DashMap::new(),
            config,
        }
    }

    /// Check rate limit for an identity, optionally scoped to a specific tool.
    ///
    /// This performs two checks:
    /// 1. Per-identity global limit (always checked)
    /// 2. Per-identity-per-tool limit (only if `tool` is Some)
    ///
    /// Both must pass for the request to proceed.
    pub fn check_rate_limit(&self, identity: &str, tool: Option<&str>) -> Result<(), DomeError> {
        // Check per-identity limit
        let identity_key = BucketKey::for_identity(identity);
        let identity_ok = self
            .buckets
            .entry(identity_key)
            .or_insert_with(|| {
                TokenBucket::new(self.config.per_identity_max, self.config.per_identity_rate)
            })
            .try_acquire();

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
            let tool_ok = self
                .buckets
                .entry(tool_key)
                .or_insert_with(|| {
                    TokenBucket::new(self.config.per_tool_max, self.config.per_tool_rate)
                })
                .try_acquire();

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
}
