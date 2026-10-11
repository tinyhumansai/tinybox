//! Module-owned one-shot Docker execution.

use std::path::PathBuf;
use std::time::Duration;

use tinybox_bus::{
    CleanupDockerOutput, CleanupDockerRequest, DockerRunOutput, DockerRunRequest, DockerStatus,
    DockerStatusRequest,
};
use tinybox_docker::{DockerCli, OneShot};
use tinybus::{Error, Result};

/// Run a bounded Docker command using the local Docker CLI.
pub(super) async fn run(request: DockerRunRequest) -> Result<DockerRunOutput> {
    run_with_cli(&DockerCli::new(), request, true).await
}

/// Run a bounded Docker command without mounting a host workspace.
pub(super) async fn run_without_workspace(
    cli: &DockerCli,
    request: DockerRunRequest,
) -> Result<DockerRunOutput> {
    run_with_cli(cli, request, false).await
}

/// Probe the module host's Docker daemon within the caller's deadline.
pub(super) async fn status(request: DockerStatusRequest) -> Result<DockerStatus> {
    status_with_cli(&DockerCli::new(), request).await
}

async fn status_with_cli(cli: &DockerCli, request: DockerStatusRequest) -> Result<DockerStatus> {
    validate_control_timeout(request.timeout_ms)?;
    let available = tokio::time::timeout(
        Duration::from_millis(request.timeout_ms),
        cli.is_available(),
    )
    .await
    .map_err(|_| control_failure("Docker status probe exceeded its deadline"))?;
    Ok(DockerStatus { available })
}

/// Stop containers matching a validated Docker label within the caller's deadline.
pub(super) async fn cleanup(request: CleanupDockerRequest) -> Result<CleanupDockerOutput> {
    cleanup_with_cli(&DockerCli::new(), request).await
}

async fn cleanup_with_cli(
    cli: &DockerCli,
    request: CleanupDockerRequest,
) -> Result<CleanupDockerOutput> {
    validate_control_timeout(request.timeout_ms)?;
    validate_label(&request.label)?;
    let containers_stopped = tokio::time::timeout(
        Duration::from_millis(request.timeout_ms),
        cli.kill_labelled_checked(&request.label),
    )
    .await
    .map_err(|_| control_failure("Docker cleanup exceeded its deadline"))?
    .map_err(|_| control_failure("Docker cleanup could not be completed"))?;
    Ok(CleanupDockerOutput { containers_stopped })
}

fn validate_control_timeout(timeout_ms: u64) -> Result<()> {
    if timeout_ms == 0 || timeout_ms > tinybox_bus::MAX_DOCKER_CONTROL_TIMEOUT_MS {
        return Err(invalid_control_request());
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<()> {
    let Some((key, value)) = label.split_once('=') else {
        return Err(invalid_control_request());
    };
    if key.is_empty()
        || value.is_empty()
        || label.len() > 256
        || label
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
    {
        return Err(invalid_control_request());
    }
    Ok(())
}

fn invalid_control_request() -> Error {
    Error::MethodFailed {
        name: tinybox_bus::INVALID_DOCKER_CONTROL.into(),
        message: "Docker control request is invalid".into(),
    }
}

fn control_failure(message: &str) -> Error {
    Error::MethodFailed {
        name: tinybox_bus::DOCKER_CONTROL_FAILED.into(),
        message: message.into(),
    }
}

async fn run_with_cli(
    cli: &DockerCli,
    request: DockerRunRequest,
    mount_workspace: bool,
) -> Result<DockerRunOutput> {
    validate(&request, mount_workspace)?;

    let mut spec = OneShot::new(&request.workspace, &request.command);
    if !mount_workspace {
        spec = spec.without_workspace();
    }
    if request.login_shell {
        spec = spec.with_login_shell();
    }
    if let Some(image) = &request.image {
        spec = spec.with_image(image);
    }
    if let Some(network) = &request.network {
        spec = spec.with_network(network);
    }
    if let Some(memory) = request.memory_limit_mb {
        spec = spec.with_memory_mb(memory);
    }
    if let Some(cpus) = request.cpus {
        spec = spec.with_cpus(cpus);
    }
    if let Some(read_only) = request.read_only_rootfs {
        spec = spec.with_read_only_rootfs(read_only);
    }
    spec = spec
        .with_read_only_mounts(request.read_only_mounts.iter().map(PathBuf::from))
        .with_extra_cap_drops(request.extra_cap_drops.clone())
        .with_env(
            request
                .env
                .into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
    if let Some(label) = request.label {
        spec = spec.with_label(label);
    }

    let outcome = cli
        .run_one_shot(&spec, Duration::from_millis(request.timeout_ms))
        .await
        .map_err(|_| failure("Docker client could not be started"))?;
    Ok(DockerRunOutput {
        exit_code: outcome.exit_code,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        timed_out: outcome.timed_out,
    })
}

fn validate(request: &DockerRunRequest, mount_workspace: bool) -> Result<()> {
    if request.timeout_ms > tinybox_bus::MAX_DOCKER_RUN_TIMEOUT_MS
        || (!mount_workspace && !request.workspace.is_empty())
    {
        return Err(failure("Docker run request is invalid"));
    }
    Ok(())
}

fn failure(message: &str) -> Error {
    Error::MethodFailed {
        name: tinybox_bus::INVALID_DOCKER_RUN.into(),
        message: message.into(),
    }
}

#[cfg(all(test, unix))]
#[path = "docker_tests.rs"]
mod tests;
