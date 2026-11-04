//! Where the agent37 credential and host addresses come from.
//!
//! This is the one place a credential enters the crate. The key never appears
//! in `Debug` output (see [`ApiKey`]), and must never be logged.
//!
//! agent37 runs on two fixed hosts, so there is normally **nothing to
//! configure but the key**:
//!
//! - the control plane (`create`, `inspect`, `delete`) at [`DEFAULT_API_BASE`],
//!   authenticated with `Authorization: Bearer`;
//! - exec at [`DEFAULT_SANDBOX_BASE`], authenticated with the `X-Agent37-Key`
//!   header.
//!
//! Both are overridable (a workspace [custom domain] serves the same endpoints
//! under `api.{domain}` / `sandbox.{domain}`, and tests point them at a local
//! stub), but neither is required.
//!
//! [custom domain]: https://www.agent37.com/docs/agents-api/domains

use std::env;
use std::fmt;

use tinybox_core::{Error, Result};

/// Environment variable holding the agent37 API key (an `sk_live_…` value).
pub(crate) const API_KEY_VAR: &str = "AGENT37_API_KEY";

/// Optional override for the control-plane base URL ([`DEFAULT_API_BASE`]).
pub(crate) const API_BASE_VAR: &str = "AGENT37_API_BASE";

/// Optional override for the exec base URL ([`DEFAULT_SANDBOX_BASE`]).
pub(crate) const SANDBOX_BASE_VAR: &str = "AGENT37_SANDBOX_BASE";

/// agent37's control plane: create, inspect and delete instances.
pub const DEFAULT_API_BASE: &str = "https://api.agent37.com";

/// agent37's exec host: run commands inside an instance.
pub const DEFAULT_SANDBOX_BASE: &str = "https://sandbox.agent37.app";

/// An API key that never prints itself.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    /// Wrap a raw key.
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The raw key, for building an auth header only.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKey(redacted)")
    }
}

/// The host addresses and credential a [`HttpTransport`](crate::HttpTransport)
/// needs.
#[derive(Clone, Debug)]
pub struct Agent37Config {
    /// Control-plane base URL (create, inspect, delete), without a trailing `/`.
    pub api_base: String,
    /// Exec base URL, without a trailing `/`.
    pub sandbox_base: String,
    /// The workspace API key.
    pub api_key: ApiKey,
}

impl Agent37Config {
    /// A config for the public agent37 hosts, carrying `api_key`.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_base: DEFAULT_API_BASE.to_owned(),
            sandbox_base: DEFAULT_SANDBOX_BASE.to_owned(),
            api_key: ApiKey::new(api_key),
        }
    }

    /// A config with explicit host bases, for a custom domain or a test stub.
    ///
    /// A trailing `/` is trimmed from each base so request paths join cleanly.
    #[must_use]
    pub fn with_bases(
        api_base: impl Into<String>,
        sandbox_base: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            api_base: api_base.into().trim_end_matches('/').to_owned(),
            sandbox_base: sandbox_base.into().trim_end_matches('/').to_owned(),
            api_key: ApiKey::new(api_key),
        }
    }

    /// Read the config from the process environment: `AGENT37_API_KEY`
    /// (required) and the optional `AGENT37_API_BASE` / `AGENT37_SANDBOX_BASE`
    /// overrides.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`] when `AGENT37_API_KEY` is unset or empty, so
    /// the failure names agent37 rather than surfacing as a bare env error.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| env::var(key).ok())
    }

    /// Read the config from a `lookup` of variable names to values — the
    /// process environment in production ([`Self::from_env`]), or a closure in
    /// tests. The key is required; the two bases default to agent37's public
    /// hosts when the lookup returns nothing (or only whitespace) for them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`] when `AGENT37_API_KEY` is unset or empty.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let Some(api_key) = present(&lookup, API_KEY_VAR) else {
            return Err(Error::Backend {
                sandbox: crate::NAME.to_owned(),
                operation: "read configuration",
                message: format!("environment variable {API_KEY_VAR} is unset or empty"),
            });
        };
        let api_base =
            present(&lookup, API_BASE_VAR).unwrap_or_else(|| DEFAULT_API_BASE.to_owned());
        let sandbox_base =
            present(&lookup, SANDBOX_BASE_VAR).unwrap_or_else(|| DEFAULT_SANDBOX_BASE.to_owned());
        Ok(Self::with_bases(api_base, sandbox_base, api_key))
    }
}

/// Look a variable up, treating an absent or whitespace-only value as unset.
fn present(lookup: &impl Fn(&str) -> Option<String>, var: &str) -> Option<String> {
    lookup(var).filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
