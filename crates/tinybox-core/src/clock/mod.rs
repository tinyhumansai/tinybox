//! Where the current time comes from.
//!
//! Expiry needs to know when a box was created, which means the model needs a
//! clock. It arrives through a trait rather than `SystemTime::now` scattered
//! through the code, for one reason: tests have to be deterministic, and a test
//! that waits an hour for a box to expire is not a test anyone will run.
//!
//! ```
//! use std::time::Duration;
//! use tinybox_core::clock::{Clock, FixedClock};
//!
//! let clock = FixedClock::at_epoch();
//! let created = clock.now();
//!
//! clock.advance(Duration::from_secs(90));
//! assert_eq!(clock.now().duration_since(created).ok(), Some(Duration::from_secs(90)));
//! ```

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

/// A source of the current time.
pub trait Clock: std::fmt::Debug + Send + Sync + 'static {
    /// What time it is now.
    fn now(&self) -> SystemTime;
}

/// The real clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    /// A clock reading the operating system.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock that only moves when told to.
///
/// Everything about expiry is then testable in microseconds instead of hours,
/// and without the flakiness that comes from a test racing a real clock.
#[derive(Debug)]
pub struct FixedClock {
    now: Mutex<SystemTime>,
}

impl FixedClock {
    /// A clock stopped at `now`.
    #[must_use]
    pub fn at(now: SystemTime) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    /// A clock stopped at the Unix epoch.
    ///
    /// A fixed starting point keeps expected timestamps in tests literal rather
    /// than relative to whenever the suite happened to run.
    #[must_use]
    pub fn at_epoch() -> Self {
        Self::at(SystemTime::UNIX_EPOCH)
    }

    /// Move the clock forward.
    pub fn advance(&self, by: Duration) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        *now += by;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod test;
