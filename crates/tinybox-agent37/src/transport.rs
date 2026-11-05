//! The HTTP seam. [`Transport`] is the five calls the [`Sandbox`](tinybox_core::Sandbox)
//! impl makes; [`HttpTransport`] is the real one, and it is the **only** code in
//! the crate that touches the network or the API key. Tests use a fake
//! `Transport` (see `sandbox/mod_tests.rs`), so the backend logic is exercised
//! without a live agent37.
//!
//! agent37 splits its API across two hosts, and this transport honours both:
//!
//! - the **control plane** (`create`, `list`, `inspect`, `delete`) on
//!   [`api_base`](crate::Agent37Config::api_base), authenticated with
//!   `Authorization: Bearer`;
//! - **exec** on [`sandbox_base`](crate::Agent37Config::sandbox_base),
//!   authenticated with the `X-Agent37-Key` header, which leaves
//!   `Authorization` free for whatever runs inside the instance.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use tinybox_core::{Error, Result};

use crate::NAME;
use crate::api::{CreateBody, ExecBody, ExecResult, InstanceView, ListResponse};
use crate::config::Agent37Config;

/// The header agent37's exec host authenticates with (not `Authorization`).
const KEY_HEADER: &str = "X-Agent37-Key";

/// How long [`HttpTransport::exec`] waits before each retry of a request agent37
/// refused before the command started. Six retries, 23.5 s in all: enough for a
/// checkpoint write or a wake to finish, short enough that a caller is not
/// left hanging on an instance that will not come back.
pub const EXEC_RETRY_BACKOFF: [Duration; 6] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(8),
];

/// Whether an exec refusal means the command never started, so sending it
/// again cannot run it twice.
///
/// agent37 answers `409 try_again` while a checkpoint is being written and
/// `503` (`try_again`, `wake_failed`, `wake_timeout`) when it could not wake the
/// instance; in both the command has not run. `504 try_again` is deliberately
/// absent: the gateway timed out while the command keeps running, and a retry
/// would run it a second time.
const fn exec_not_started(status: StatusCode) -> bool {
    matches!(status.as_u16(), 409 | 503)
}

/// The operations agent37 exposes, abstracted from HTTP.
#[async_trait]
pub trait Transport: std::fmt::Debug + Send + Sync + 'static {
    /// Create an instance; the returned view carries its id and status.
    async fn create(&self, body: &CreateBody) -> Result<InstanceView>;

    /// Every instance in the workspace, newest first.
    ///
    /// The workspace is shared with whatever else uses the account, so the
    /// listing holds instances that are not tinybox's.
    async fn list(&self) -> Result<Vec<InstanceView>>;

    /// Run a command in the instance to completion.
    async fn exec(&self, id: &str, body: &ExecBody) -> Result<ExecResult>;

    /// The instance's current view, or `None` when it does not exist.
    async fn inspect(&self, id: &str) -> Result<Option<InstanceView>>;

    /// Delete the instance; a missing instance is already deleted.
    async fn delete(&self, id: &str) -> Result<()>;
}

/// A [`Transport`] over agent37's HTTP API.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: Client,
    config: Agent37Config,
}

impl HttpTransport {
    /// Build a transport from a config, using a default HTTP client.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] when the HTTP client cannot be constructed.
    pub fn new(config: Agent37Config) -> Result<Self> {
        let client = Client::builder().build().map_err(|error| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "build the HTTP client",
            message: error.to_string(),
        })?;
        Ok(Self { client, config })
    }

    /// Build a transport reading its config from the environment.
    ///
    /// # Errors
    ///
    /// Everything [`Agent37Config::from_env`] and [`HttpTransport::new`] refuse.
    pub fn from_env() -> Result<Self> {
        Self::new(Agent37Config::from_env()?)
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{path}", self.config.api_base)
    }

    fn sandbox_url(&self, path: &str) -> String {
        format!("{}{path}", self.config.sandbox_base)
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.config.api_key.expose())
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn create(&self, body: &CreateBody) -> Result<InstanceView> {
        let response = self
            .client
            .post(self.api_url("/v1/instances"))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .json(body)
            .send()
            .await
            .map_err(|error| transport_error("create the instance", &error))?;
        read_json(response, "create the instance").await
    }

    async fn list(&self) -> Result<Vec<InstanceView>> {
        let response = self
            .client
            .get(self.api_url("/v1/instances"))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .send()
            .await
            .map_err(|error| transport_error("list the instances", &error))?;
        read_json::<ListResponse>(response, "list the instances")
            .await
            .map(|list| list.data)
    }

    async fn exec(&self, id: &str, body: &ExecBody) -> Result<ExecResult> {
        let mut backoff = EXEC_RETRY_BACKOFF.iter();
        loop {
            let response = self
                .client
                .post(self.sandbox_url(&format!("/v1/instances/{id}/exec")))
                .header(KEY_HEADER, self.config.api_key.expose())
                .json(body)
                .send()
                .await
                .map_err(|error| transport_error("run the command", &error))?;
            // Only a refusal that proves the command never started is retried;
            // once the retries are spent the last status is reported as is.
            if exec_not_started(response.status())
                && let Some(delay) = backoff.next()
            {
                tokio::time::sleep(*delay).await;
                continue;
            }
            return read_json(response, "run the command").await;
        }
    }

    async fn inspect(&self, id: &str) -> Result<Option<InstanceView>> {
        let response = self
            .client
            .get(self.api_url(&format!("/v1/instances/{id}")))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .send()
            .await
            .map_err(|error| transport_error("inspect the instance", &error))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        read_json(response, "inspect the instance").await.map(Some)
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let response = self
            .client
            .delete(self.api_url(&format!("/v1/instances/{id}")))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .send()
            .await
            .map_err(|error| transport_error("delete the instance", &error))?;
        let status = response.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            return Ok(());
        }
        Err(status_error("delete the instance", status))
    }
}

/// Parse a 2xx JSON body, or turn a non-2xx status into a backend error.
async fn read_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    operation: &'static str,
) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        return Err(status_error(operation, status));
    }
    response.json::<T>().await.map_err(|error| Error::Backend {
        sandbox: NAME.to_owned(),
        operation,
        message: format!("could not read the response body: {error}"),
    })
}

/// A transport failure (connection refused, timeout, DNS), with no secret in it.
fn transport_error(operation: &'static str, error: &reqwest::Error) -> Error {
    Error::Backend {
        sandbox: NAME.to_owned(),
        operation,
        message: format!("agent37 request failed: {error}"),
    }
}

/// A non-success HTTP status mapped to a backend error.
fn status_error(operation: &'static str, status: StatusCode) -> Error {
    Error::Backend {
        sandbox: NAME.to_owned(),
        operation,
        message: format!("agent37 returned HTTP {}", status.as_u16()),
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
