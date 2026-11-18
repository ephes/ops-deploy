//! Injectable wall clock (PLAN.md 6): the served time of the meta block,
//! the access log timestamp and the fixture replay's frozen time.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A source of the current wall-clock time.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Shared clock handle of a running endpoint.
pub type SharedClock = Arc<dyn Clock>;

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A frozen clock for tests (the fixture generator freezes Python's
/// `datetime` the same way).
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub SystemTime);

impl FixedClock {
    /// A clock frozen at `epoch` seconds after the Unix epoch.
    pub fn at_epoch(epoch: i64) -> Self {
        let time = if epoch >= 0 {
            UNIX_EPOCH + Duration::from_secs(epoch.unsigned_abs())
        } else {
            UNIX_EPOCH - Duration::from_secs(epoch.unsigned_abs())
        };
        Self(time)
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// Python's `int(datetime.now(tz=timezone.utc).timestamp())`: whole seconds
/// since the epoch, truncated toward zero.
pub fn epoch_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_seconds_truncates_toward_zero() {
        assert_eq!(epoch_seconds(UNIX_EPOCH + Duration::from_millis(1_999)), 1);
        assert_eq!(epoch_seconds(UNIX_EPOCH - Duration::from_millis(1_999)), -1);
        assert_eq!(
            epoch_seconds(FixedClock::at_epoch(1_792_576_800).now()),
            1_792_576_800
        );
        assert_eq!(epoch_seconds(FixedClock::at_epoch(-5).now()), -5);
    }
}
