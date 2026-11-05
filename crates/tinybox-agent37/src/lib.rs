//! A tinybox sandbox backed by the **agent37** hosted sandbox service.
//!
//! agent37 runs each sandbox behind a hosted HTTP API: the host hands it a
//! command and it executes it in an isolated, keyed environment in agent37's
//! own infrastructure, then returns the output. This backend turns tinybox
//! boxes into agent37 sandboxes, so a host can run untrusted commands off-box.
//!
//! # It is an HTTP wrapper, not a `Host`-driven CLI backend
//!
//! Unlike `tinybox-openshell`, which shells out to the `openshell` CLI
//! through a [`Host`](tinybox_core::Host) (ADR 0004), agent37 ships no CLI — it is a
//! native HTTP service usable by any standalone app. So this backend owns an
//! HTTP client directly. That is a deliberate departure from ADR 0004 and is
//! recorded in its own ADR (see this crate's `README.md`). The departure is
//! contained two ways:
//!
//! - All transport lives behind the [`Transport`] trait, so the request
//!   builders ([`api`]) and the [`Sandbox`](tinybox_core::Sandbox) impl are
//!   unit-tested with a fake transport and never touch the network.
//! - The **API key is read from configuration** ([`Agent37Config`], env
//!   `AGENT37_API_KEY`) at the transport boundary, the single place a
//!   credential enters this crate. It is never logged. agent37's hosts are
//!   fixed (`api.agent37.com` for the control plane, `sandbox.agent37.app` for
//!   exec), so there is nothing else to configure; both are overridable
//!   (`AGENT37_API_BASE` / `AGENT37_SANDBOX_BASE`) for a custom domain or a
//!   test stub.
//!
//! # What it enforces
//!
//! - **Isolation:** [`IsolationLevel::Kernel`](tinybox_core::IsolationLevel::Kernel)
//!   — agent37 runs each sandbox in its own kernel-isolated environment. Declare
//!   only what agent37 actually guarantees; do not widen this past its contract.
//! - **Network:** agent37's sandboxes are egress-controlled by the service; this
//!   backend declares [`NetworkPolicy::Denied`](tinybox_core::NetworkPolicy)
//!   support and refuses specs that ask for more, because widening egress is a
//!   service-side policy decision this backend cannot assert.
//! - **CPU, memory and disk:** mapped onto agent37's instance shape on create
//!   and declared [`BestEffort`](tinybox_core::Enforcement::BestEffort), since
//!   agent37 offers fixed shapes and caps CPU rather than honouring an
//!   arbitrary limit exactly.
//! - **Snapshots / forking:** not offered by agent37; declared unsupported
//!   rather than emulated (tinybox rule 1).

mod config;
mod sandbox;

pub mod api;
pub mod transport;

pub use config::{Agent37Config, ApiKey, DEFAULT_API_BASE, DEFAULT_SANDBOX_BASE};
pub use sandbox::{Agent37Sandbox, DEFAULT_NAMESPACE, NAME};
pub use transport::{HttpTransport, Transport};
