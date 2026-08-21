//! A live path from this machine to a port somewhere else.

use std::fmt;
use std::net::SocketAddr;

/// The far side of a [`Forward`], held open for as long as the forward is.
///
/// An `ssh -L` tunnel is a child process; a local forward is nothing at all.
/// The trait exists so that core can own the *guarantee* — that dropping a
/// [`Forward`] closes it — without owning any of the machinery, which belongs
/// to whichever host crate created it.
pub trait ForwardGuard: fmt::Debug + Send + Sync {
    /// Tear the forward down. Called at most once, from [`Forward`]'s `Drop`.
    ///
    /// Implementations must not block for long and must not panic: this runs
    /// during unwinding as often as not.
    fn close(&mut self);
}

/// A port on another machine, reachable at a local address.
///
/// [`Host::forward`](crate::runtime::Host::forward) returns one of these, and
/// it is a guard: the path exists for exactly as long as the value does. That
/// is why it is not `Clone` and why [`Forward::local_addr`] borrows rather than
/// handing out an address that could outlive the tunnel carrying it.
///
/// # Why reach includes this
///
/// A [`Sandbox`](crate::runtime::Sandbox) publishes a guest port to *its
/// host's* address space — that is what
/// [`PortMapping`](crate::spec::PortMapping) means. When the host is remote,
/// the caller still cannot reach it, and no amount of sandbox-side
/// configuration changes that. Closing the gap is a reach question, so it is
/// the [`Host`](crate::runtime::Host)'s to answer.
#[derive(Debug)]
pub struct Forward {
    local: SocketAddr,
    guard: Option<Box<dyn ForwardGuard>>,
}

impl Forward {
    /// A forward that needs nothing held open.
    ///
    /// A local host returns this: the address is already reachable, so there is
    /// no tunnel and nothing to tear down.
    #[must_use]
    pub const fn direct(local: SocketAddr) -> Self {
        Self { local, guard: None }
    }

    /// A forward that lives for as long as `guard` is held.
    #[must_use]
    pub fn guarded(local: SocketAddr, guard: Box<dyn ForwardGuard>) -> Self {
        Self {
            local,
            guard: Some(guard),
        }
    }

    /// Where to connect on this machine.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Whether anything is being held open on this forward's behalf.
    ///
    /// A caller has no reason to branch on this; it is here so that a host's
    /// tests can tell a real tunnel from a direct answer.
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        self.guard.is_none()
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.as_mut() {
            guard.close();
        }
    }
}
