//! Tests for the clock abstraction.

use std::time::{Duration, SystemTime};

use super::{Clock, FixedClock, SystemClock};

#[test]
fn the_system_clock_moves_forward() {
    let clock = SystemClock::new();
    let first = clock.now();
    let second = clock.now();

    // Monotonic enough to compare: the second reading is not before the first.
    assert!(second >= first);
    assert!(clock.now() >= SystemTime::UNIX_EPOCH);
}

#[test]
fn a_fixed_clock_does_not_move_on_its_own() {
    let clock = FixedClock::at_epoch();

    // Reading it twice must give the same answer, or nothing built on it is
    // reproducible.
    assert_eq!(clock.now(), clock.now());
    assert_eq!(clock.now(), SystemTime::UNIX_EPOCH);
}

#[test]
fn a_fixed_clock_moves_only_when_told() {
    let clock = FixedClock::at_epoch();

    clock.advance(Duration::from_secs(60));
    assert_eq!(
        clock.now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(60)
    );

    clock.advance(Duration::from_secs(30));
    assert_eq!(
        clock.now(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(90)
    );
}

#[test]
fn a_fixed_clock_can_start_anywhere() {
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let clock = FixedClock::at(start);

    assert_eq!(clock.now(), start);
}

#[test]
fn a_clock_is_usable_behind_a_trait_object() {
    let clock: Box<dyn Clock> = Box::new(FixedClock::at_epoch());

    assert_eq!(clock.now(), SystemTime::UNIX_EPOCH);
}
