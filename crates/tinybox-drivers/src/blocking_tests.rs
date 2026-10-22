use super::*;
use std::time::Duration;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn current_thread_call_fails_without_blocking_tasks_that_host_storage_needs()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let bridge = Blocking::new()?;
        let (progress_tx, progress_rx) = tokio::sync::oneshot::channel();
        let progress = tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = progress_tx.send(());
        });
        let (watchdog_tx, watchdog_rx) = tokio::sync::oneshot::channel();
        let watchdog = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            let _ = watchdog_tx.send(());
        });

        let result = bridge.run(async move {
            tokio::select! {
                _ = progress_rx => (),
                _ = watchdog_rx => (),
            }
        });

        assert!(result.is_err(), "the bridge must reject before waiting");
        progress.await?;
        watchdog
            .join()
            .map_err(|_| std::io::Error::other("watchdog thread panicked"))?;
        Ok(())
    })
}

#[test]
fn calls_from_outside_tokio_are_completed_by_the_bridge_runtime()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bridge = Blocking::new()?;
    let value = bridge.run(async {
        tokio::task::yield_now().await;
        42_u8
    })?;
    assert_eq!(value, 42);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn calls_from_multithread_tokio_use_the_blocking_handoff()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let bridge = Blocking::new()?;
    assert_eq!(bridge.run(async { "ready" })?, "ready");
    Ok(())
}

#[test]
fn a_stopped_bridge_and_a_bridge_callback_fail_without_waiting() -> TestResult {
    let (jobs, receiver) = tokio::sync::mpsc::unbounded_channel::<Job>();
    drop(receiver);
    let stopped = Blocking { jobs };
    assert!(stopped.run(async {}).is_err());

    let bridge = Blocking::new()?;
    let callback = bridge.clone();
    let outer = bridge.run(async move { callback.run(async {}) })?;
    let recursive = match outer {
        Ok(()) => return Err("a bridge callback must be rejected".into()),
        Err(error) => error,
    };
    assert_eq!(
        recursive.kind(),
        tinystoragedrivers_types::ErrorKind::Backend
    );
    Ok(())
}

#[test]
fn a_panicking_storage_future_is_reported_as_a_dropped_bridge_reply() -> TestResult {
    let bridge = Blocking::new()?;
    let error =
        bridge.run(async { std::panic::resume_unwind(Box::new("simulated storage task panic")) });
    let error = match error {
        Ok(()) => return Err("a panicking task must drop its reply".into()),
        Err(error) => error,
    };
    assert!(error.to_string().contains("dropped a call"));
    Ok(())
}

#[test]
fn startup_errors_keep_their_context_and_debug_is_redacted() -> TestResult {
    let bridge = Blocking::new()?;
    assert!(format!("{bridge:?}").contains("Blocking"));

    let runtime_error = startup_error(
        "runtime unavailable",
        std::io::Error::other("runtime fixture"),
    );
    assert_eq!(
        runtime_error.kind(),
        tinystoragedrivers_types::ErrorKind::Backend
    );
    assert_eq!(
        std::error::Error::source(&runtime_error)
            .ok_or("runtime startup source missing")?
            .to_string(),
        "runtime fixture"
    );
    assert!(runtime_error.to_string().contains("runtime unavailable"));

    let thread_error = startup_error(
        "bridge thread unavailable",
        std::io::Error::other("thread fixture"),
    );
    assert_eq!(
        thread_error.kind(),
        tinystoragedrivers_types::ErrorKind::Backend
    );
    assert_eq!(
        std::error::Error::source(&thread_error)
            .ok_or("thread startup source missing")?
            .to_string(),
        "thread fixture"
    );
    assert!(
        thread_error
            .to_string()
            .contains("bridge thread unavailable")
    );
    Ok(())
}
