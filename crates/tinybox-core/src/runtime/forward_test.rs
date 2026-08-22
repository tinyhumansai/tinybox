//! Tests for the [`Forward`](super::Forward) guard.
//!
//! What matters here is the guarantee the type exists to make: the tunnel
//! behind a forward is closed when the forward is dropped, exactly once, even
//! though core owns none of the machinery doing the closing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{Forward, ForwardGuard};

/// A guard that counts how many times it was closed.
#[derive(Debug)]
struct Counted(Arc<AtomicUsize>);

impl ForwardGuard for Counted {
    fn close(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn a_direct_forward_holds_nothing_open() {
    // A local host answers this way: the address is already reachable, so
    // there is no tunnel and nothing to tear down.
    let forward = Forward::direct(([127, 0, 0, 1], 7788).into());

    assert!(forward.is_direct());
    assert_eq!(forward.local_addr().port(), 7788);
}

#[test]
fn dropping_a_guarded_forward_closes_it_exactly_once() {
    let closes = Arc::new(AtomicUsize::new(0));
    {
        let forward = Forward::guarded(
            ([127, 0, 0, 1], 1234).into(),
            Box::new(Counted(closes.clone())),
        );
        assert!(!forward.is_direct());
        assert_eq!(closes.load(Ordering::Relaxed), 0, "not closed while held");
    }

    assert_eq!(closes.load(Ordering::Relaxed), 1);
}

#[test]
fn dropping_a_direct_forward_is_harmless() {
    // Nothing to close, and `Drop` must not assume there is.
    drop(Forward::direct(([127, 0, 0, 1], 1).into()));
}
