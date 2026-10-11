//! Streaming vocabulary preserves bytes and terminal status without native resources.
use super::*;

#[test]
fn streaming_output_preserves_binary_chunks_and_nonzero_exit() -> Result<(), serde_json::Error> {
    let batch: OutputBatch = serde_json::from_str(
        r#"{"chunks":[{"sequence":1,"stream":"stderr","bytes":[0,255,10]}],"next_sequence":2,"state":{"Exited":{"exit_code":7}}}"#,
    )?;
    assert_eq!(batch.chunks[0].bytes, [0, 255, 10]);
    assert_eq!(batch.chunks[0].stream, OutputStream::Stderr);
    assert_eq!(batch.state, ExecutionState::Exited { exit_code: 7 });
    assert_eq!(
        serde_json::from_value::<OutputBatch>(serde_json::to_value(&batch)?)?,
        batch
    );
    Ok(())
}

#[test]
fn cancellation_is_distinct_from_unacknowledged_running_output() -> Result<(), serde_json::Error> {
    assert_eq!(serde_json::to_value(ExecutionState::Running)?, "Running");
    assert_eq!(
        serde_json::to_value(ExecutionState::Cancelled)?,
        "Cancelled"
    );
    let failed = ExecutionState::Failed {
        code: ExecutionFailure::CleanupFailed,
    };
    assert_eq!(
        serde_json::to_value(failed)?,
        serde_json::json!({"Failed":{"code":"cleanup_failed"}})
    );
    Ok(())
}
