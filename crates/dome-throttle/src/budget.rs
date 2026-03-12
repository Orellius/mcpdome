use std::time::Duration;

use dashmap::DashMap;
use dome_core::DomeError;
use tokio::time::Instant;
use tracing::warn;

/// Per-identity budget with a rolling window.
#[derive(Debug, Clone)]
pub struct Budget {
    pub spent: f64,
    pub cap: f64,
    pub unit: String,
    pub window: Duration,
    pub window_start: Instant,
}

impl Budget {
    pub fn new(cap: f64, unit: impl Into<String>, window: Duration) -> Self {
        Self {
            spent: 0.0,
            cap,
            unit: unit.into(),
            window,
            window_start: Instant::now(),
        }
    }

    /// Create with an explicit start time (for testing).
    pub fn new_at(cap: f64, unit: impl Into<String>, window: Duration, now: Instant) -> Self {
        Self {
            spent: 0.0,
            cap,
            unit: unit.into(),
            window,
            window_start: now,
        }
    }

    /// Remaining budget in the current window.
    pub fn remaining(&self) -> f64 {
        (self.cap - self.spent).max(0.0)
    }

    /// Check if the window has expired and reset if so. Returns true if reset happened.
    fn maybe_reset(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= self.window {
            self.spent = 0.0;
            self.window_start = now;
            true
        } else {
            false
        }
    }

    /// Try to spend `amount` from this budget. Resets window if expired.
    fn try_spend_inner(&mut self, amount: f64, now: Instant) -> Result<(), (f64, f64, String)> {
        self.maybe_reset(now);

        if self.spent + amount > self.cap {
            Err((self.spent, self.cap, self.unit.clone()))
        } else {
            self.spent += amount;
            Ok(())
        }
    }
}

/// Configuration for default budgets assigned to new identities.
#[derive(Debug, Clone)]
pub struct BudgetTrackerConfig {
    pub default_cap: f64,
    pub default_unit: String,
    pub default_window: Duration,
}

impl Default for BudgetTrackerConfig {
    fn default() -> Self {
        Self {
            default_cap: 100.0,
            default_unit: "calls".to_string(),
            default_window: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Concurrent budget tracker backed by DashMap.
///
/// Tracks cumulative spend per identity within rolling time windows.
/// Budgets are created lazily with default config on first access.
/// Stale entries (past their window) are periodically cleaned up to
/// prevent unbounded memory growth.
pub struct BudgetTracker {
    budgets: DashMap<String, Budget>,
    config: BudgetTrackerConfig,
    /// Maximum number of tracked identities before cleanup triggers.
    max_entries: usize,
    /// Counter for periodic cleanup scheduling.
    insert_counter: std::sync::atomic::AtomicU64,
}

impl BudgetTracker {
    pub fn new(config: BudgetTrackerConfig) -> Self {
        Self {
            budgets: DashMap::new(),
            max_entries: 10_000,
            insert_counter: std::sync::atomic::AtomicU64::new(0),
            config,
        }
    }

    /// Create a tracker with a custom max entries limit.
    pub fn with_max_entries(config: BudgetTrackerConfig, max_entries: usize) -> Self {
        Self {
            budgets: DashMap::new(),
            max_entries,
            insert_counter: std::sync::atomic::AtomicU64::new(0),
            config,
        }
    }

    /// Try to spend `amount` for the given identity.
    ///
    /// If the budget window has expired, it resets automatically before checking.
    /// Returns `Ok(())` if spend is within cap, or `DomeError::BudgetExhausted` otherwise.
    pub fn try_spend(&self, identity: &str, amount: f64) -> Result<(), DomeError> {
        self.try_spend_at(identity, amount, Instant::now())
    }

    /// Same as `try_spend` but with explicit timestamp (for testing).
    pub fn try_spend_at(&self, identity: &str, amount: f64, now: Instant) -> Result<(), DomeError> {
        let is_new = !self.budgets.contains_key(identity);

        let mut entry = self.budgets.entry(identity.to_string()).or_insert_with(|| {
            Budget::new_at(
                self.config.default_cap,
                &self.config.default_unit,
                self.config.default_window,
                now,
            )
        });

        let result = entry
            .try_spend_inner(amount, now)
            .map_err(|(spent, cap, unit)| {
                warn!(
                    identity = identity,
                    spent = spent,
                    cap = cap,
                    unit = %unit,
                    "budget exhausted"
                );
                DomeError::BudgetExhausted { spent, cap, unit }
            });

        // Periodic cleanup on new insertions
        if is_new {
            let count = self
                .insert_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if count % 100 == 99 {
                drop(entry);
                self.maybe_cleanup(now);
            }
        }

        result
    }

    /// Remove entries whose windows have expired (stale budgets).
    /// Called periodically to prevent unbounded memory growth.
    fn maybe_cleanup(&self, now: Instant) {
        if self.budgets.len() <= self.max_entries {
            return;
        }

        self.budgets.retain(|_key, budget| {
            // Keep entries whose window hasn't expired yet
            now.duration_since(budget.window_start) < budget.window
        });
    }

    /// Explicitly run cleanup, removing entries whose windows have expired.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.budgets.retain(|_key, budget| {
            now.duration_since(budget.window_start) < budget.window
        });
    }

    /// Register a custom budget for an identity (overrides defaults).
    pub fn set_budget(&self, identity: impl Into<String>, budget: Budget) {
        self.budgets.insert(identity.into(), budget);
    }

    /// Current spend for an identity, if tracked.
    pub fn current_spend(&self, identity: &str) -> Option<f64> {
        self.budgets.get(identity).map(|b| b.spent)
    }

    /// Number of tracked identities.
    pub fn tracked_count(&self) -> usize {
        self.budgets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker_with_cap(cap: f64, window_secs: u64) -> BudgetTracker {
        BudgetTracker::new(BudgetTrackerConfig {
            default_cap: cap,
            default_unit: "usd".to_string(),
            default_window: Duration::from_secs(window_secs),
        })
    }

    #[tokio::test(start_paused = true)]
    async fn spend_within_cap_succeeds() {
        let tracker = tracker_with_cap(10.0, 3600);
        let now = Instant::now();

        assert!(tracker.try_spend_at("user-a", 3.0, now).is_ok());
        assert!(tracker.try_spend_at("user-a", 3.0, now).is_ok());
        assert!(tracker.try_spend_at("user-a", 4.0, now).is_ok());
        // Exactly at cap
        assert_eq!(tracker.current_spend("user-a"), Some(10.0));
    }

    #[tokio::test(start_paused = true)]
    async fn rejects_when_exceeding_cap() {
        let tracker = tracker_with_cap(5.0, 3600);
        let now = Instant::now();

        assert!(tracker.try_spend_at("user-b", 4.0, now).is_ok());

        // This would push to 6.0, exceeding cap of 5.0
        let err = tracker.try_spend_at("user-b", 2.0, now).unwrap_err();
        match err {
            DomeError::BudgetExhausted { spent, cap, unit } => {
                assert!((spent - 4.0).abs() < f64::EPSILON);
                assert!((cap - 5.0).abs() < f64::EPSILON);
                assert_eq!(unit, "usd");
            }
            other => panic!("expected BudgetExhausted, got: {other:?}"),
        }

        // Spend should not have changed after rejection
        assert_eq!(tracker.current_spend("user-b"), Some(4.0));
    }

    #[tokio::test(start_paused = true)]
    async fn window_reset_clears_spend() {
        let tracker = tracker_with_cap(5.0, 60); // 60 second window
        let now = Instant::now();

        // Spend to the cap
        assert!(tracker.try_spend_at("user-c", 5.0, now).is_ok());
        assert!(tracker.try_spend_at("user-c", 1.0, now).is_err());

        // Advance past the window
        let later = now + Duration::from_secs(61);
        assert!(
            tracker.try_spend_at("user-c", 3.0, later).is_ok(),
            "should succeed after window reset"
        );
        assert_eq!(tracker.current_spend("user-c"), Some(3.0));
    }

    #[tokio::test(start_paused = true)]
    async fn separate_identities_have_separate_budgets() {
        let tracker = tracker_with_cap(5.0, 3600);
        let now = Instant::now();

        assert!(tracker.try_spend_at("alice", 5.0, now).is_ok());
        assert!(tracker.try_spend_at("alice", 1.0, now).is_err());

        // Bob is unaffected
        assert!(tracker.try_spend_at("bob", 5.0, now).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn custom_budget_overrides_defaults() {
        let tracker = tracker_with_cap(100.0, 3600);
        let now = Instant::now();

        // Set a tight budget for a specific identity
        tracker.set_budget(
            "restricted-user",
            Budget::new_at(2.0, "tokens", Duration::from_secs(60), now),
        );

        assert!(tracker.try_spend_at("restricted-user", 1.0, now).is_ok());
        assert!(tracker.try_spend_at("restricted-user", 1.0, now).is_ok());
        assert!(tracker.try_spend_at("restricted-user", 1.0, now).is_err());
    }

    #[test]
    fn concurrent_budget_tracking() {
        use std::sync::Arc;
        use std::thread;

        // 1000 cap, spend 1.0 per request, 100 threads x 5 requests = 500 total
        let tracker = Arc::new(tracker_with_cap(1000.0, 3600));
        let mut handles = vec![];

        for t in 0..10 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                let id = format!("concurrent-{t}");
                let mut ok = 0u32;
                for _ in 0..5 {
                    if tracker.try_spend(&id, 1.0).is_ok() {
                        ok += 1;
                    }
                }
                ok
            }));
        }

        let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        // Each identity has its own budget of 1000, so all 50 should pass
        assert_eq!(total, 50);
    }

    #[test]
    fn concurrent_same_identity_respects_cap() {
        use std::sync::Arc;
        use std::thread;

        // Single identity, cap = 10, 20 threads each trying to spend 1.0
        let tracker = Arc::new(tracker_with_cap(10.0, 3600));
        let mut handles = vec![];

        for _ in 0..20 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                if tracker.try_spend("shared-user", 1.0).is_ok() {
                    1u32
                } else {
                    0u32
                }
            }));
        }

        let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        // Exactly 10 should succeed (cap = 10, each spends 1.0)
        assert_eq!(total, 10);
    }
}
