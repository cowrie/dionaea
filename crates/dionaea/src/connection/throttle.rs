// ABOUTME: Token bucket bandwidth limiter and cumulative byte accounting.
// ABOUTME: Pure logic — no I/O, no async. Used by TCP/UDP handler tasks.

use std::time::{Duration, Instant};

/// Token bucket rate limiter for bandwidth control.
///
/// Replenishes tokens at `bytes_per_second` rate. Each `try_consume(n)` call
/// either succeeds (enough tokens) or returns the duration to wait.
pub struct Throttle {
    /// Max bytes per second. 0 means unlimited.
    bytes_per_second: f64,
    /// Available tokens (bytes).
    available: f64,
    /// Last time tokens were replenished.
    last_refill: Instant,
}

impl Throttle {
    /// Create a new throttle. `bytes_per_second` of 0.0 means unlimited.
    pub fn new(bytes_per_second: f64) -> Self {
        Throttle {
            bytes_per_second,
            available: bytes_per_second, // start with a full bucket
            last_refill: Instant::now(),
        }
    }

    /// Create an unlimited throttle (no rate limiting).
    pub fn unlimited() -> Self {
        Self::new(0.0)
    }

    /// Whether this throttle is unlimited (no rate limiting).
    pub fn is_unlimited(&self) -> bool {
        self.bytes_per_second <= 0.0
    }

    /// Update the rate limit. Resets available tokens to the new rate.
    pub fn set_rate(&mut self, bytes_per_second: f64) {
        self.bytes_per_second = bytes_per_second;
        self.available = bytes_per_second;
        self.last_refill = Instant::now();
    }

    /// Refill tokens based on elapsed time since last refill.
    fn refill(&mut self, now: Instant) {
        if self.is_unlimited() {
            return;
        }
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.available += elapsed * self.bytes_per_second;
            // Cap at one second's worth (burst limit)
            if self.available > self.bytes_per_second {
                self.available = self.bytes_per_second;
            }
            self.last_refill = now;
        }
    }

    /// Try to consume `n` bytes. Returns `Ok(())` if allowed, or
    /// `Err(duration)` with the time to wait before retrying.
    pub fn try_consume(&mut self, n: usize) -> Result<(), Duration> {
        if self.is_unlimited() {
            return Ok(());
        }
        self.refill(Instant::now());
        let needed = n as f64;
        if self.available >= needed {
            self.available -= needed;
            Ok(())
        } else {
            let deficit = needed - self.available;
            let wait = Duration::from_secs_f64(deficit / self.bytes_per_second);
            Err(wait)
        }
    }

    /// Same as `try_consume` but with an explicit `now` for testing.
    pub fn try_consume_at(&mut self, n: usize, now: Instant) -> Result<(), Duration> {
        if self.is_unlimited() {
            return Ok(());
        }
        self.refill(now);
        let needed = n as f64;
        if self.available >= needed {
            self.available -= needed;
            Ok(())
        } else {
            let deficit = needed - self.available;
            let wait = Duration::from_secs_f64(deficit / self.bytes_per_second);
            Err(wait)
        }
    }

    /// How many bytes are currently available without waiting.
    pub fn available(&self) -> usize {
        if self.is_unlimited() {
            return usize::MAX;
        }
        self.available.max(0.0) as usize
    }
}

/// Cumulative byte counter with an optional cap.
///
/// Tracks total bytes transferred. When the limit is reached, the connection
/// should be closed.
pub struct Accounting {
    /// Total bytes counted so far.
    pub current: u64,
    /// Maximum bytes allowed. 0 means unlimited.
    pub limit: u64,
}

impl Accounting {
    /// Create accounting with the given limit. 0 means unlimited.
    pub fn new(limit: u64) -> Self {
        Accounting { current: 0, limit }
    }

    /// Create unlimited accounting (no byte cap).
    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// Whether this has no byte cap.
    pub fn is_unlimited(&self) -> bool {
        self.limit == 0
    }

    /// Add `n` bytes. Returns `true` if the limit has been reached or exceeded.
    pub fn add(&mut self, n: u64) -> bool {
        self.current += n;
        !self.is_unlimited() && self.current >= self.limit
    }

    /// How many bytes remain before the limit. `None` if unlimited.
    pub fn remaining(&self) -> Option<u64> {
        if self.is_unlimited() {
            None
        } else {
            Some(self.limit.saturating_sub(self.current))
        }
    }

    /// Update the byte limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Throttle tests ---

    #[test]
    fn test_unlimited_throttle_always_allows() {
        let mut t = Throttle::unlimited();
        assert!(t.is_unlimited());
        assert!(t.try_consume(1_000_000).is_ok());
        assert!(t.try_consume(1_000_000).is_ok());
        assert_eq!(t.available(), usize::MAX);
    }

    #[test]
    fn test_basic_rate_consumption() {
        let mut t = Throttle::new(1000.0); // 1000 bytes/sec
        assert!(!t.is_unlimited());

        // First consume should succeed (bucket starts full)
        assert!(t.try_consume(500).is_ok());
        assert_eq!(t.available(), 500);

        // Second consume within budget
        assert!(t.try_consume(500).is_ok());
        assert_eq!(t.available(), 0);
    }

    #[test]
    fn test_exhaustion_returns_wait_duration() {
        let now = Instant::now();
        let mut t = Throttle::new(1000.0);
        t.last_refill = now;

        // Exhaust the bucket
        assert!(t.try_consume_at(1000, now).is_ok());

        // Next consume should fail with a wait duration
        let result = t.try_consume_at(100, now);
        assert!(result.is_err());
        let wait = result.unwrap_err();
        // Need 100 bytes at 1000 bytes/sec = 0.1 seconds
        assert!((wait.as_secs_f64() - 0.1).abs() < 0.01);
    }

    #[test]
    fn test_interval_refill() {
        let now = Instant::now();
        let mut t = Throttle::new(1000.0);
        t.last_refill = now;

        // Exhaust
        assert!(t.try_consume_at(1000, now).is_ok());
        assert_eq!(t.available(), 0);

        // Advance 0.5 seconds → 500 bytes should refill
        let later = now + Duration::from_millis(500);
        assert!(t.try_consume_at(500, later).is_ok());
        assert_eq!(t.available(), 0);
    }

    #[test]
    fn test_refill_caps_at_one_second() {
        let now = Instant::now();
        let mut t = Throttle::new(1000.0);
        t.last_refill = now;

        // Exhaust
        assert!(t.try_consume_at(1000, now).is_ok());

        // Advance 5 seconds — should refill to max (1000), not 5000
        let later = now + Duration::from_secs(5);
        assert!(t.try_consume_at(1000, later).is_ok());
        // After consuming 1000 from a 1000-capped bucket, should be 0
        assert_eq!(t.available(), 0);
    }

    #[test]
    fn test_partial_consume() {
        let now = Instant::now();
        let mut t = Throttle::new(1000.0);
        t.last_refill = now;

        // Consume 300
        assert!(t.try_consume_at(300, now).is_ok());
        assert_eq!(t.available(), 700);

        // Consume 400
        assert!(t.try_consume_at(400, now).is_ok());
        assert_eq!(t.available(), 300);

        // Try to consume 500 — should fail
        let result = t.try_consume_at(500, now);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_rate_resets_bucket() {
        let mut t = Throttle::new(1000.0);
        assert!(t.try_consume(1000).is_ok());
        assert_eq!(t.available(), 0);

        t.set_rate(2000.0);
        assert_eq!(t.available(), 2000);
    }

    // --- Accounting tests ---

    #[test]
    fn test_accounting_unlimited() {
        let mut a = Accounting::unlimited();
        assert!(a.is_unlimited());
        assert_eq!(a.remaining(), None);

        // Adding never hits limit
        assert!(!a.add(1_000_000));
        assert!(!a.add(1_000_000));
        assert_eq!(a.current, 2_000_000);
    }

    #[test]
    fn test_accounting_at_limit_boundary() {
        let mut a = Accounting::new(1000);
        assert!(!a.is_unlimited());
        assert_eq!(a.remaining(), Some(1000));

        // Add up to but not at limit
        assert!(!a.add(999));
        assert_eq!(a.remaining(), Some(1));

        // Hit the limit exactly
        assert!(a.add(1));
        assert_eq!(a.remaining(), Some(0));
    }

    #[test]
    fn test_accounting_over_limit() {
        let mut a = Accounting::new(100);
        assert!(a.add(200)); // Over the limit
        assert_eq!(a.current, 200);
        assert_eq!(a.remaining(), Some(0));
    }

    #[test]
    fn test_accounting_set_limit() {
        let mut a = Accounting::new(100);
        assert!(!a.add(50));
        assert_eq!(a.remaining(), Some(50));

        a.set_limit(200);
        assert_eq!(a.remaining(), Some(150));

        a.set_limit(0);
        assert!(a.is_unlimited());
        assert_eq!(a.remaining(), None);
    }
}
