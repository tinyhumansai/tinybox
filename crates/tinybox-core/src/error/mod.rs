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

    /// A sandbox was handed a workspace source it cannot materialize.
    ///
    /// Distinct from [`Error::Unsupported`], which is about a capability the
    /// caller asked for. This is about the *input*: a passthrough sandbox runs
    /// a bare host process and has nowhere to unpack an OCI image to.
    #[error("sandbox {sandbox} cannot materialize a {kind} workspace")]
    UnsupportedWorkspaceSource {
        /// The sandbox that refused the source.
        sandbox: String,
        /// What kind of source it was, such as `OCI image`. Named `kind`
        /// rather than `source` because thiserror reserves that field name for
        /// a nested error.
        kind: &'static str,
    },

    /// A command was submitted with no program to run.
    #[error("sandbox {sandbox} was given a command with no program")]
    EmptyCommand {
        /// The sandbox that refused the command.
        sandbox: String,
    },

    /// A box already exists under the requested identifier.
    #[error("a box with id {id} already exists")]
    DuplicateBox {
        /// The identifier that was already taken.
        id: String,
    },

    /// An operating-system call failed.
    ///
    /// Carries the message rather than the [`std::io::Error`] itself so the
    /// crate-wide error stays comparable, which every test in this crate
    /// depends on.
    #[error("{operation} failed: {message}")]
    Io {
        /// What was being attempted, such as `spawn`.
        operation: &'static str,
        /// The operating system's description of the failure.
        message: String,
    },

    /// A backend tool reported a failure.
    ///
    /// Distinct from [`Error::Io`], which is this process failing to *start*
    /// something: here the tool ran and refused. The message is the tool's own
    /// diagnostic, because it is more specific than anything tinybox could
    /// reconstruct.
    #[error("{sandbox} could not {operation}: {message}")]
    Backend {
        /// The sandbox whose backend refused.
        sandbox: String,
        /// What was being attempted, such as `create the container`.
        operation: &'static str,
        /// What the backend said.
        message: String,
    },

    /// Reading or writing the box store failed, or its contents were not
    /// valid.
    #[error("box store {operation} failed: {message}")]
    Store {
        /// What was being attempted, such as `read`.
        operation: &'static str,
        /// What went wrong.
        message: String,
    },
}

impl Error {
    /// Wrap an operating-system failure, naming the operation that failed.
    ///
    /// Backend crates construct this, which is why it is public: `LocalHost`
    /// spawning a process is the first caller.
    #[must_use]
    pub fn io(operation: &'static str, error: &std::io::Error) -> Self {
        Self::Io {
            operation,
            message: error.to_string(),
        }
    }
}

/// The crate's standard result type.
///
/// Use this alias in public signatures instead of spelling out
/// `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test;
