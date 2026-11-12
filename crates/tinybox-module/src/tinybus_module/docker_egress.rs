//! Decide, per Create, whether a Docker box's network allowlist is enforced.
//!
//! The native Linux egress controller is installed only when the host passes
//! its detection. Every other host keeps refusing an allowlist, now with the
//! reason the detection gave.

use std::sync::Arc;

use tinybox_core::{Host, Result};
use tinybox_docker::{
    DockerEgressController, NativeLinuxDockerEgressController, SystemEgressResolver,
};

/// The controller for a Docker `Create` that asks for an allowlist.
///
/// Returns `Ok(None)` for any other backend or network policy, so ordinary
/// boxes keep addressing whatever Docker daemon the host is configured for.
///
/// # Errors
///
/// Returns the detection failure for a Docker allowlist on a host that cannot
/// enforce one, for example a Desktop or rootless daemon, or firewall chains
/// that need passwordless `sudo`.
pub(super) async fn docker_egress_controller(
    backend: &str,
    network: &tinybox_bus::NetworkPolicy,
    host: &dyn Host,
) -> Result<Option<Arc<dyn DockerEgressController>>> {
    if backend != "docker" || !matches!(network, tinybox_bus::NetworkPolicy::Allowlist(_)) {
        return Ok(None);
    }
    let controller =
        NativeLinuxDockerEgressController::detect(host, Arc::new(SystemEgressResolver)).await?;
    Ok(Some(Arc::new(controller)))
}

#[cfg(test)]
#[path = "docker_egress_tests.rs"]
mod tests;
