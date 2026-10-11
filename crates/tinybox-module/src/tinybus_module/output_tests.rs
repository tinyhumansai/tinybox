//! Replay, limits and acknowledged lifecycle tests for module-owned output.
use super::*;
use std::sync::Arc;
use tinybox_core::ExecutionObserver;

#[test]
fn binary_output_is_replayable_bounded_and_ordered_across_pipes()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let journal = OutputJournal::default();
    journal.output(OutputStream::Stdout, &[0, 255, 1])?;
    journal.output(OutputStream::Stderr, b"fault")?;
    let first = journal.read(0)?;
    assert_eq!(first, journal.read(0)?);
    assert_eq!(first.chunks[0].sequence, 0);
    assert_eq!(first.chunks[1].sequence, 1);
    assert_eq!(first.chunks[0].bytes, [0, 255, 1]);
    assert_eq!(first.next_sequence, 2);
    assert_eq!(first.state, ExecutionState::Running);
    assert!(journal.read(3).is_err());
    assert_eq!(journal.read(2)?.chunks, Vec::<OutputChunk>::new());
    Ok(())
}

#[test]
fn large_provider_frames_are_split_and_reads_never_exceed_batch_limit()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let journal = OutputJournal::default();
    let bytes = vec![7; MAX_OUTPUT_BYTES];
    journal.output(OutputStream::Stdout, &bytes)?;
    let mut cursor = 0;
    let mut collected = Vec::new();
    loop {
        let batch = journal.read(cursor)?;
        if batch.chunks.is_empty() {
            break;
        }
        assert!(
            batch
                .chunks
                .iter()
                .all(|chunk| chunk.bytes.len() <= FRAME_BYTES)
        );
        assert!(
            batch
                .chunks
                .iter()
                .map(|chunk| chunk.bytes.len())
                .sum::<usize>()
                <= BATCH_BYTES
        );
        collected.extend(batch.chunks.into_iter().flat_map(|chunk| chunk.bytes));
        cursor = batch.next_sequence;
    }
    assert_eq!(collected, bytes);
    assert!(
        journal
            .output(OutputStream::Stderr, b"over budget")
            .is_err()
    );
    assert_eq!(journal.read(0)?.state, ExecutionState::Running);
    journal.finish_failed(ExecutionFailure::OutputLimit);
    assert_eq!(
        journal.read(cursor)?.state,
        ExecutionState::Failed {
            code: ExecutionFailure::OutputLimit
        }
    );
    Ok(())
}

#[tokio::test]
async fn requesting_cancellation_does_not_claim_cleanup_completed()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let journal = OutputJournal::default();
    journal.cancel();
    journal.cancelled().await;
    assert_eq!(journal.read(0)?.state, ExecutionState::Running);
    journal.finish_exit(7);
    assert_eq!(journal.read(0)?.state, ExecutionState::Cancelled);
    Ok(())
}

#[tokio::test]
async fn cancellation_waiter_is_woken_without_a_lost_notification()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let journal = Arc::new(OutputJournal::default());
    let waiting = journal.clone();
    let task = tokio::spawn(async move {
        waiting.cancelled().await;
    });
    journal.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(1), task).await??;
    Ok(())
}

#[test]
fn terminal_states_preserve_nonzero_exit_and_refuse_late_output()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let journal = OutputJournal::default();
    journal.finish_exit(7);
    assert_eq!(
        journal.read(0)?.state,
        ExecutionState::Exited { exit_code: 7 }
    );
    assert!(journal.output(OutputStream::Stdout, b"late").is_err());
    journal.cancel();
    assert_eq!(
        journal.read(0)?.state,
        ExecutionState::Exited { exit_code: 7 }
    );
    Ok(())
}

#[test]
fn cleanup_failure_is_observable_and_kept_distinct_from_acknowledged_cancel()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let journal = OutputJournal::default();
    journal.cancel();
    journal.finish_failed(ExecutionFailure::CleanupFailed);
    assert_eq!(
        journal.read(0)?.state,
        ExecutionState::Failed {
            code: ExecutionFailure::CleanupFailed
        }
    );
    assert!(!journal.cleanup_acknowledged());
    journal.finish_failed(ExecutionFailure::BackendFailed);
    assert!(journal.cleanup_acknowledged());
    Ok(())
}

#[test]
fn empty_output_does_not_consume_sequence_or_memory()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let journal = OutputJournal::default();
    journal.output(OutputStream::Stdout, b"")?;
    assert_eq!(journal.read(0)?.next_sequence, 0);
    Ok(())
}
