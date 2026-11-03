use std::{future::Future, time::Duration};

use tinybox_bus::{
    CreateRequest, ProcessRef, ReserveRequest, ResourceId, RunNativeShellRequest,
    RunNativeShellResult, ShellExecRequest,
};
use tinybox_host::{NativeShellClient, NativeShellRunOutcome};
use tinybus::Result;

use super::super::resources::Resources;

struct Client(std::sync::Arc<Resources>);

impl NativeShellClient for Client {
    type Error = String;

    async fn reserve(
        &self,
        request: ReserveRequest,
    ) -> std::result::Result<ResourceId, Self::Error> {
        self.0
            .reserve(request)
            .await
            .map_err(|error| error.to_string())
    }

    async fn create(&self, request: CreateRequest) -> std::result::Result<(), Self::Error> {
        self.0
            .create(request)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn start_native_shell_exec(
        &self,
        request: ShellExecRequest,
    ) -> std::result::Result<ProcessRef, Self::Error> {
        self.0
            .start_shell_exec(request)
            .await
            .map_err(|error| error.to_string())
    }

    async fn read_output(
        &self,
        process: ProcessRef,
        cursor: u64,
    ) -> std::result::Result<tinybox_bus::OutputBatch, Self::Error> {
        // The host helper expects transport polling to yield between empty
        // reads. This in-process adapter otherwise returns a ready future and
        // can starve the shell's output collector on a single-worker module.
        tokio::task::yield_now().await;
        self.0
            .read_output(&process, cursor)
            .await
            .map_err(|error| error.to_string())
    }

    async fn cancel(&self, process: ProcessRef) -> std::result::Result<(), Self::Error> {
        self.0
            .cancel(&process)
            .await
            .map_err(|error| error.to_string())
    }

    async fn release_output(&self, process: ProcessRef) -> std::result::Result<(), Self::Error> {
        self.0
            .release_output(&process)
            .await
            .map_err(|error| error.to_string())
    }

    async fn close(&self, resource: ResourceId) -> std::result::Result<(), Self::Error> {
        self.0
            .close(&resource)
            .await
            .map_err(|error| error.to_string())
    }
}

/// Supervises a native shell until it finishes, times out, is cancelled, or
/// reaches the requested yield point. The dropped request receiver is used as
/// the cancellation signal so this future always awaits native cleanup.
pub(in crate::tinybus_module) async fn run(
    resources: std::sync::Arc<Resources>,
    request: RunNativeShellRequest,
    abandoned: impl Future<Output = ()> + Send,
) -> Result<RunNativeShellResult> {
    let outcome = tinybox_host::run_native_shell(
        &Client(resources),
        tinybox_host::NativeShellRunRequest {
            create: request.create,
            shell: request.shell,
            yield_after: request.yield_after_ms.map(Duration::from_millis),
        },
        abandoned,
        |_| {},
    )
    .await
    .map_err(|error| {
        let name = match error {
            tinybox_host::NativeShellError::Execution(
                tinybox_bus::ExecutionFailure::OutputLimit,
            ) => tinybox_bus::OUTPUT_LIMIT,
            _ => tinybox_bus::BACKEND_ERROR,
        };
        super::super::resources::failure(name, &format!("native shell operation failed: {error:?}"))
    })?;

    Ok(match outcome {
        NativeShellRunOutcome::Finished(output) => RunNativeShellResult::Finished {
            exit_code: output.exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
            timed_out: output.timed_out,
        },
        NativeShellRunOutcome::Running(running) => RunNativeShellResult::Running {
            resource: running.resource,
            process: running.process,
            cursor: running.cursor,
            stdout: running.stdout,
            stderr: running.stderr,
        },
    })
}
