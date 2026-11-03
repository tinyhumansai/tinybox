//! Tests for runtime-neutral native shell orchestration.
use super::*;
use std::{collections::BTreeMap, sync::Mutex};
use tinybox_bus::{
    ExecutionFailure, HostConfig, NetworkPolicy, OutputStream, ResourceLimits, SelectShellRequest,
    Workspace,
};

struct MockClient {
    calls: Mutex<Vec<&'static str>>,
    reads: Mutex<u8>,
    behavior: MockBehavior,
}

#[derive(Clone, Copy)]
enum MockBehavior {
    Normal,
    FailCreate,
    Cancelled,
    ModuleTimeout,
    Running,
    FailResourceReserve,
    FailProcessReserve,
    FailStart,
    FailRead,
    FailCancel,
    FailRelease,
    FailClose,
    FailedExecution,
    InvalidCursor,
    FailedExecutionCloseFail,
    TimedOut,
    InvalidCursorCancelFail,
    InvalidCursorReleaseFail,
    RunningStderr,
    SkippedChunk,
}

impl NativeShellClient for MockClient {
    type Error = &'static str;

    async fn reserve(&self, request: ReserveRequest) -> Result<ResourceId, Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("reserve");
        if matches!(self.behavior, MockBehavior::FailResourceReserve)
            && matches!(request, ReserveRequest::Resource)
            || matches!(self.behavior, MockBehavior::FailProcessReserve)
                && matches!(request, ReserveRequest::Process(_))
        {
            return Err("reserve failed");
        }
        Ok(match request {
            ReserveRequest::Resource => ResourceId("resource-1".into()),
            ReserveRequest::Process(_) => ResourceId("process-1".into()),
            _ => return Err("unexpected reservation"),
        })
    }

    async fn create(&self, request: CreateRequest) -> Result<(), Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("create");
        assert_eq!(request.resource, ResourceId("resource-1".into()));
        if matches!(self.behavior, MockBehavior::FailCreate) {
            return Err("create failed");
        }
        Ok(())
    }

    async fn start_native_shell_exec(
        &self,
        request: ShellExecRequest,
    ) -> Result<ProcessRef, Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("start");
        assert_eq!(request.process, ResourceId("process-1".into()));
        assert!(request.timeout_ms > 0, "the module refuses a zero timeout");
        if matches!(self.behavior, MockBehavior::FailStart) {
            return Err("start failed");
        }
        Ok(ProcessRef {
            resource: request.resource,
            process: request.process,
        })
    }

    async fn read_output(&self, _: ProcessRef, cursor: u64) -> Result<OutputBatch, Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("read");
        let cancelled = self
            .calls
            .lock()
            .map_err(|_| "poisoned")?
            .contains(&"cancel");
        // A cancellation test must reach `cancel`, so its read never wins the race.
        if matches!(
            self.behavior,
            MockBehavior::TimedOut | MockBehavior::FailCancel
        ) && !cancelled
        {
            std::future::pending::<()>().await;
        }
        if matches!(self.behavior, MockBehavior::FailRead) {
            return Err("read failed");
        }
        let mut reads = self.reads.lock().map_err(|_| "poisoned")?;
        *reads = reads.wrapping_add(1);
        let state = if matches!(
            self.behavior,
            MockBehavior::Cancelled | MockBehavior::TimedOut
        ) {
            if cancelled {
                ExecutionState::Cancelled
            } else {
                ExecutionState::Running
            }
        } else if matches!(self.behavior, MockBehavior::ModuleTimeout) {
            ExecutionState::Failed {
                code: ExecutionFailure::TimedOut,
            }
        } else if matches!(self.behavior, MockBehavior::RunningStderr) && cancelled {
            ExecutionState::Cancelled
        } else if matches!(
            self.behavior,
            MockBehavior::Running | MockBehavior::RunningStderr
        ) {
            ExecutionState::Running
        } else if matches!(
            self.behavior,
            MockBehavior::FailedExecution | MockBehavior::FailedExecutionCloseFail
        ) {
            ExecutionState::Failed {
                code: ExecutionFailure::OutputLimit,
            }
        } else {
            ExecutionState::Exited { exit_code: 7 }
        };
        Ok(OutputBatch {
            chunks: if cursor == 0 {
                vec![OutputChunk {
                    sequence: u64::from(matches!(self.behavior, MockBehavior::SkippedChunk)),
                    stream: if matches!(
                        self.behavior,
                        MockBehavior::RunningStderr
                            | MockBehavior::InvalidCursor
                            | MockBehavior::InvalidCursorCancelFail
                            | MockBehavior::InvalidCursorReleaseFail
                    ) {
                        OutputStream::Stderr
                    } else {
                        OutputStream::Stdout
                    },
                    bytes: b"done".to_vec(),
                }]
            } else {
                Vec::new()
            },
            next_sequence: if matches!(
                self.behavior,
                MockBehavior::InvalidCursor
                    | MockBehavior::InvalidCursorCancelFail
                    | MockBehavior::InvalidCursorReleaseFail
            ) {
                0
            } else if cursor == 0 {
                1
            } else {
                cursor
            },
            state,
        })
    }

    async fn cancel(&self, _: ProcessRef) -> Result<(), Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("cancel");
        if matches!(
            self.behavior,
            MockBehavior::FailCancel | MockBehavior::InvalidCursorCancelFail
        ) {
            return Err("cancel failed");
        }
        Ok(())
    }

    async fn release_output(&self, _: ProcessRef) -> Result<(), Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("release");
        if matches!(
            self.behavior,
            MockBehavior::FailRelease | MockBehavior::InvalidCursorReleaseFail
        ) {
            return Err("release failed");
        }
        Ok(())
    }

    async fn close(&self, _: ResourceId) -> Result<(), Self::Error> {
        std::future::ready(()).await;
        self.calls.lock().map_err(|_| "poisoned")?.push("close");
        if matches!(
            self.behavior,
            MockBehavior::FailClose | MockBehavior::FailedExecutionCloseFail
        ) {
            return Err("close failed");
        }
        Ok(())
    }
}

#[test]
fn runs_and_cleans_up_a_shell_while_streaming_chunks() -> Result<(), &'static str> {
    futures_executor::block_on(runs_and_cleans_up_a_shell())
}

async fn runs_and_cleans_up_a_shell() -> Result<(), &'static str> {
    let client = MockClient {
        calls: Mutex::new(Vec::new()),
        reads: Mutex::new(0),
        behavior: MockBehavior::Normal,
    };
    let mut chunks = Vec::new();
    let output = run_native_shell(&client, request(), std::future::pending(), |chunk| {
        chunks.push(chunk.clone());
    })
    .await
    .map_err(|_| "run failed")?;
    let NativeShellRunOutcome::Finished(output) = output else {
        return Err("expected a finished outcome");
    };
    assert_eq!(output.exit_code, 7);
    assert_eq!(output.stdout, b"done");
    assert!(!output.timed_out);
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        *client.calls.lock().map_err(|_| "poisoned")?,
        [
            "reserve", "create", "reserve", "start", "read", "read", "release", "close"
        ]
    );
    Ok(())
}

#[test]
fn cancellation_reaps_the_process_before_releasing_and_closing() -> Result<(), &'static str> {
    futures_executor::block_on(async {
        let client = MockClient {
            calls: Mutex::new(Vec::new()),
            reads: Mutex::new(0),
            behavior: MockBehavior::Cancelled,
        };
        let output = run_native_shell(&client, request(), cancel_now(), ignore_chunk)
            .await
            .map_err(|_| "run failed")?;
        let NativeShellRunOutcome::Finished(output) = output else {
            return Err("expected a finished outcome");
        };
        assert_eq!(output.exit_code, -1);
        assert!(!output.timed_out);
        let calls = client.calls.lock().map_err(|_| "poisoned")?;
        assert_eq!(&calls[..4], &["reserve", "create", "reserve", "start"]);
        let cancel = calls
            .iter()
            .position(|call| *call == "cancel")
            .ok_or("cancel missing")?;
        let release = calls
            .iter()
            .position(|call| *call == "release")
            .ok_or("release missing")?;
        let close = calls
            .iter()
            .position(|call| *call == "close")
            .ok_or("close missing")?;
        assert!(cancel < release && release < close);
        Ok(())
    })
}

#[test]
fn create_failure_still_releases_the_resource_reservation() -> Result<(), &'static str> {
    futures_executor::block_on(async {
        let client = MockClient {
            calls: Mutex::new(Vec::new()),
            reads: Mutex::new(0),
            behavior: MockBehavior::FailCreate,
        };
        let error = run_native_shell(&client, request(), never_cancel(), ignore_chunk)
            .await
            .err()
            .ok_or("expected failure")?;
        assert!(matches!(
            error,
            NativeShellError::Transport {
                operation: "create resource",
                ..
            }
        ));
        assert_eq!(
            *client.calls.lock().map_err(|_| "poisoned")?,
            ["reserve", "create", "close"]
        );
        Ok(())
    })
}

#[test]
fn module_timeout_returns_collected_output_as_a_result() -> Result<(), &'static str> {
    futures_executor::block_on(async {
        let client = MockClient {
            calls: Mutex::new(Vec::new()),
            reads: Mutex::new(0),
            behavior: MockBehavior::ModuleTimeout,
        };
        let outcome = run_native_shell(&client, request(), never_cancel(), ignore_chunk)
            .await
            .map_err(|_| "run failed")?;
        let NativeShellRunOutcome::Finished(output) = outcome else {
            return Err("expected a finished outcome");
        };
        assert!(output.timed_out);
        assert_eq!(output.stdout, b"done");
        assert_eq!(output.exit_code, -1);
        Ok(())
    })
}

#[test]
fn yield_preserves_process_resource_cursor_and_partial_output() -> Result<(), &'static str> {
    futures_executor::block_on(async {
        let client = MockClient {
            calls: Mutex::new(Vec::new()),
            reads: Mutex::new(0),
            behavior: MockBehavior::Running,
        };
        let mut request = request();
        request.yield_after = Some(std::time::Duration::ZERO);
        let outcome = run_native_shell(&client, request, never_cancel(), ignore_chunk)
            .await
            .map_err(|_| "run failed")?;
        let NativeShellRunOutcome::Running(running) = outcome else {
            return Err("expected a running outcome");
        };
        assert_eq!(running.resource, ResourceId("resource-1".into()));
        assert_eq!(running.process.process, ResourceId("process-1".into()));
        assert_eq!(running.cursor, 1);
        assert_eq!(running.stdout, b"done");
        assert_eq!(
            *client.calls.lock().map_err(|_| "poisoned")?,
            ["reserve", "create", "reserve", "start", "read"]
        );
        Ok(())
    })
}

#[test]
fn reserve_start_and_read_failures_are_reported_and_cleaned_up() -> Result<(), &'static str> {
    for (behavior, operation) in [
        (MockBehavior::FailResourceReserve, "reserve resource"),
        (MockBehavior::FailProcessReserve, "reserve process"),
        (MockBehavior::FailStart, "start native shell"),
        (MockBehavior::FailRead, "read output"),
    ] {
        futures_executor::block_on(async {
            let client = mock(behavior);
            let error = run_native_shell(&client, request(), never_cancel(), ignore_chunk)
                .await
                .err()
                .ok_or("operation should fail")?;
            if operation == "read output" {
                assert!(matches!(
                    error,
                    NativeShellError::Transport {
                        operation: "read output",
                        ..
                    }
                ));
                assert!(
                    client
                        .calls
                        .lock()
                        .map_err(|_| "poisoned")?
                        .contains(&"cancel")
                );
                assert!(
                    client
                        .calls
                        .lock()
                        .map_err(|_| "poisoned")?
                        .contains(&"release")
                );
            } else {
                assert!(
                    matches!(error, NativeShellError::Transport { operation: actual, .. } if actual == operation)
                );
            }
            Ok::<(), &'static str>(())
        })?;
    }
    Ok(())
}

#[test]
fn terminal_execution_and_cleanup_failures_keep_the_primary_error() -> Result<(), &'static str> {
    futures_executor::block_on(async {
        let client = mock(MockBehavior::FailedExecution);
        assert!(matches!(
            run_native_shell(&client, request(), never_cancel(), ignore_chunk).await,
            Err(NativeShellError::Execution(ExecutionFailure::OutputLimit))
        ));
        Ok::<(), &'static str>(())
    })?;
    futures_executor::block_on(async {
        let client = mock(MockBehavior::FailClose);
        assert!(matches!(
            run_native_shell(&client, request(), never_cancel(), ignore_chunk).await,
            Err(NativeShellError::ResourceClose("close failed"))
        ));
        Ok::<(), &'static str>(())
    })?;
    futures_executor::block_on(async {
        let client = mock(MockBehavior::FailedExecutionCloseFail);
        let err = run_native_shell(&client, request(), never_cancel(), ignore_chunk)
            .await
            .err()
            .ok_or("expected cleanup failure")?;
        assert!(matches!(
            err,
            NativeShellError::Cleanup {
                operation: "close resource",
                ..
            }
        ));
        Ok::<(), &'static str>(())
    })?;
    Ok(())
}

#[test]
fn invalid_cursor_and_cancel_cleanup_errors_are_reported() {
    futures_executor::block_on(async {
        let client = mock(MockBehavior::InvalidCursor);
        assert!(matches!(
            run_native_shell(&client, request(), never_cancel(), ignore_chunk).await,
            Err(NativeShellError::InvalidOutputCursor)
        ));
    });
    futures_executor::block_on(async {
        let client = mock(MockBehavior::SkippedChunk);
        assert!(matches!(
            run_native_shell(&client, request(), never_cancel(), ignore_chunk).await,
            Err(NativeShellError::InvalidOutputCursor)
        ));
    });
    futures_executor::block_on(async {
        let client = mock(MockBehavior::FailCancel);
        assert!(matches!(
            run_native_shell(&client, request(), cancel_now(), ignore_chunk).await,
            Err(NativeShellError::Cancellation("cancel failed"))
        ));
    });
    futures_executor::block_on(async {
        let client = mock(MockBehavior::FailRelease);
        assert!(matches!(
            run_native_shell(&client, request(), never_cancel(), ignore_chunk).await,
            Err(NativeShellError::OutputRelease("release failed"))
        ));
    });
    futures_executor::block_on(async {
        let client = mock(MockBehavior::InvalidCursorCancelFail);
        assert!(matches!(
            run_native_shell(&client, request(), never_cancel(), ignore_chunk).await,
            Err(NativeShellError::Cleanup {
                operation: "cancel after invalid output cursor",
                ..
            })
        ));
    });
    futures_executor::block_on(async {
        let client = mock(MockBehavior::InvalidCursorReleaseFail);
        assert!(matches!(
            run_native_shell(&client, request(), never_cancel(), ignore_chunk).await,
            Err(NativeShellError::Cleanup {
                operation: "release output after invalid cursor",
                ..
            })
        ));
    });
}

#[test]
fn timeout_cancels_and_returns_collected_output() -> Result<(), &'static str> {
    // A zero timeout starts with the same one-millisecond floor it collects with.
    for timeout_ms in [0, 1] {
        futures_executor::block_on(async {
            let client = mock(MockBehavior::TimedOut);
            let mut req = request();
            req.shell.timeout_ms = timeout_ms;
            let outcome = run_native_shell(&client, req, never_cancel(), ignore_chunk)
                .await
                .map_err(|_| "run failed")?;
            let NativeShellRunOutcome::Finished(output) = outcome else {
                return Err("expected completion");
            };
            assert!(output.timed_out);
            assert_eq!(output.exit_code, -1);
            assert!(
                client
                    .calls
                    .lock()
                    .map_err(|_| "poisoned")?
                    .contains(&"cancel")
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn running_poll_without_yield_accumulates_stderr_until_timeout() -> Result<(), &'static str> {
    futures_executor::block_on(async {
        let client = mock(MockBehavior::RunningStderr);
        let mut req = request();
        req.shell.timeout_ms = 1;
        req.yield_after = Some(std::time::Duration::from_secs(5));
        let outcome = run_native_shell(&client, req, never_cancel(), ignore_chunk)
            .await
            .map_err(|_| "run failed")?;
        let NativeShellRunOutcome::Finished(output) = outcome else {
            return Err("expected completion");
        };
        assert!(output.timed_out);
        assert_eq!(output.stderr, b"done");
        assert_eq!(output.stdout.len(), 0);
        Ok(())
    })
}

fn mock(behavior: MockBehavior) -> MockClient {
    MockClient {
        calls: Mutex::new(Vec::new()),
        reads: Mutex::new(0),
        behavior,
    }
}

fn never_cancel() -> impl std::future::Future<Output = ()> {
    std::future::pending::<()>()
}

fn cancel_now() -> impl std::future::Future<Output = ()> {
    std::future::ready(())
}

fn ignore_chunk(_: &OutputChunk) {}

fn request() -> NativeShellRunRequest {
    NativeShellRunRequest {
        create: CreateRequest {
            resource: ResourceId("placeholder-resource".into()),
            backend: "passthrough".into(),
            host: HostConfig::Local,
            workspace: Workspace::Directory("/workspace".into()),
            network: NetworkPolicy::Open,
            resources: ResourceLimits::default(),
            ports: Vec::new(),
            env: BTreeMap::new(),
        },
        shell: ShellExecRequest {
            process: ResourceId("placeholder-process".into()),
            resource: ResourceId("placeholder-resource".into()),
            shell: SelectShellRequest {
                command: "echo done".into(),
                preserve_pipeline_status: false,
                runtime_path: None,
                python_utf8: false,
            },
            cwd: None,
            extra_env: BTreeMap::new(),
            state_dir: "/state".into(),
            timeout_ms: 1_000,
            stdin: None,
            jail: None,
            hide_window: false,
        },
        yield_after: None,
    }
}
