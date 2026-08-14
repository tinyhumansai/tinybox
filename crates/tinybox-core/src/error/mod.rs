//! Crate-wide error and result types.
//!
//! Every fallible public function in this crate returns [`Result`], and every
//! failure mode is a distinct [`Error`] variant. Add a variant rather than
//! encoding new context into an existing message: callers match on variants,
//! and message text is not a stable API.
//!
//! Variants carry the data a caller needs to react, keep their `#[error]`
//! message lowercase and free of trailing punctuation, and are documented so
//! the rendered rustdoc explains when each one occurs.

use crate::capability::Capability;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An identifier was empty, over-long, or contained characters outside the
    /// permitted `[A-Za-z0-9._-]` set.
    #[error("identifier {value:?} is not a valid {kind}")]
    InvalidIdentifier {
        /// What the identifier was meant to name, such as `box id`.
        kind: &'static str,
        /// The rejected text, so a caller can report it back to a user.
        value: String,
    },

    /// A sandbox was asked for something it does not implement.
    ///
    /// Backends declare what they support through
    /// [`SandboxCapabilities`](crate::capability::SandboxCapabilities) and this
    /// variant is what a caller sees instead of a silently degraded result. A
    /// passthrough sandbox never pretends to have isolated anything.
    #[error("sandbox {sandbox} does not support {capability}")]
    Unsupported {
        /// The sandbox that refused the request.
        sandbox: String,
        /// The capability the caller needed.
        capability: Capability,
    },

    /// A resource limit was zero, and every limit tinybox applies must be
    /// positive to be meaningful.
    #[error("resource limit {limit} must be greater than zero")]
    ZeroResourceLimit {
        /// Which limit was zero, such as `memory_bytes`.
        limit: &'static str,
    },

    /// A box was referenced that the sandbox does not know about.
    #[error("no box with id {id}")]
    UnknownBox {
        /// The identifier that did not resolve.
        id: String,
    },

    /// A snapshot was referenced that the sandbox does not know about.
    #[error("no snapshot with id {id}")]
    UnknownSnapshot {
        /// The identifier that did not resolve.
        id: String,
    },

    /// A box was asked to do something its current state does not allow, such
    /// as executing a command in a box that was never started.
    #[error("box {id} is {actual} but must be {expected} for this operation")]
    InvalidState {
        /// The box whose state blocked the request.
        id: String,
        /// The state the box is actually in.
        actual: crate::runtime::BoxState,
        /// The state the operation required.
        expected: crate::runtime::BoxState,
    },
}

/// The crate's standard result type.
///
/// Use this alias in public signatures instead of spelling out
/// `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test;
