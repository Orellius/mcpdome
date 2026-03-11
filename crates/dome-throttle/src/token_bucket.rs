use tokio::time::Instant;

/// A token-bucket rate limiter.
///
/// Tokens refill continuously at `refill_rate` tokens/sec up to `max_tokens`.
/// Each `try_acquire` consumes one token. Thread-safe when wrapped in DashMap
/// (exterior mutability via `get_mut`).
#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub tokens: f64,
    pub max_tokens: f64,
    pub refill_rate: f64,
    pub last_refill: Instant,
}

impl TokenBucket {
    /// Create a new bucket starting full.
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Create a bucket with a specific start time (useful for testing).
    pub fn new_at(max_tokens: f64, refill_rate: f64, now: Instant) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: now,
        }
    }

    /// Refill tokens based on elapsed time, then try to consume one token.
    /// Returns `true` if the token was acquired, `false` if bucket is empty.
    pub fn try_acquire(&mut self) -> bool {
        self.try_acquire_at(Instant::now())
    }

    /// Same as `try_acquire` but accepts a timestamp (for deterministic testing).
    pub fn try_acquire_at(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill);
        let added = elapsed.as_secs_f64() * self.refill_rate;
        if added > 0.0 {
            self.tokens = (self.tokens + added).min(self.max_tokens);
            self.last_refill = now;
        }
    }

    /// Current token count (after refill).
    pub fn available(&mut self) -> f64 {
        self.refill(Instant::now());
        self.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn allows_requests_within_limit() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new_at(5.0, 1.0, now);

        // Should allow 5 requests (bucket starts full)
        for i in 0..5 {
            assert!(bucket.try_acquire_at(now), "request {i} should be allowed");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn denies_when_exhausted() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new_at(3.0, 1.0, now);

        // Drain the bucket
        assert!(bucket.try_acquire_at(now));
        assert!(bucket.try_acquire_at(now));
        assert!(bucket.try_acquire_at(now));

        // Should deny
        assert!(!bucket.try_acquire_at(now), "should deny when exhausted");
    }

    #[tokio::test(start_paused = true)]
    async fn refills_over_time() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new_at(3.0, 1.0, now);

        // Drain completely
        assert!(bucket.try_acquire_at(now));
        assert!(bucket.try_acquire_at(now));
        assert!(bucket.try_acquire_at(now));
        assert!(!bucket.try_acquire_at(now));

        // Advance 2 seconds: should refill 2 tokens (rate = 1/sec)
        let later = now + Duration::from_secs(2);
        assert!(bucket.try_acquire_at(later), "should allow after refill");
        assert!(bucket.try_acquire_at(later), "second token should be available");
        assert!(!bucket.try_acquire_at(later), "third should fail, only 2 refilled");
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_exceed_max() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new_at(3.0, 10.0, now);

        // Advance 100 seconds with high refill rate
        let later = now + Duration::from_secs(100);
        bucket.refill(later);

        // Should cap at max_tokens
        assert!(bucket.tokens <= bucket.max_tokens);
        assert!((bucket.tokens - 3.0).abs() < f64::EPSILON);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_refill() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new_at(10.0, 2.0, now);

        // Drain 5 tokens
        for _ in 0..5 {
            assert!(bucket.try_acquire_at(now));
        }
        // 5 tokens left

        // Advance 1 second at rate 2/sec => +2 tokens = 7
        let later = now + Duration::from_millis(1000);
        assert!(bucket.try_acquire_at(later)); // 6
        assert!(bucket.try_acquire_at(later)); // 5
        assert!(bucket.try_acquire_at(later)); // 4
        assert!(bucket.try_acquire_at(later)); // 3
        assert!(bucket.try_acquire_at(later)); // 2
        assert!(bucket.try_acquire_at(later)); // 1
        assert!(bucket.try_acquire_at(later)); // 0
        assert!(!bucket.try_acquire_at(later)); // empty
    }
}
