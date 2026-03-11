//! `dome-throttle` -- Token-bucket rate limiting and budget tracking for MCPDome.
//!
//! Two complementary mechanisms:
//!
//! - **RateLimiter**: Token-bucket per-identity and per-tool rate limits using DashMap
//!   for lock-free concurrent access.
//! - **BudgetTracker**: Cumulative spend tracking per identity with rolling time windows.
//!
//! Both are designed for the MCPDome interceptor chain, returning `DomeError::RateLimited`
//! or `DomeError::BudgetExhausted` on violation.

pub mod budget;
pub mod rate_limiter;
pub mod token_bucket;

pub use budget::{Budget, BudgetTracker, BudgetTrackerConfig};
pub use rate_limiter::{BucketKey, RateLimiter, RateLimiterConfig};
pub use token_bucket::TokenBucket;
