//! A stdio session owns one child, its pipes and its bounded buffers.
use super::*;
use tinybox_bus::{JailEnforcement, NativeJailConfig, ResourceId};

/// Spawns children directly; the module's preflight is not under test here.
struct Plain;
impl JailBackend for Plain {
    fn name(&self) -> &'static str {
        "plain"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn spawn(
        &self,
        _: &Jail,
        mut cmd: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        cmd.spawn()
    }
}

fn request() -> StdioStartRequest {
    StdioStartRequest {
        process: ResourceId("p".into()),
        resource: ResourceId("r".into()),
        argv: vec!["sh".into()],
        cwd: None,
        env: std::collections::BTreeMap::new(),
        jail: NativeJailConfig {
            read_only: Vec::new(),
            read_write: Vec::new(),
            unix_paths: tinybox_bus::UnixPathGrants::default(),
            allow_net: true,
            allow_subprocess: true,
            enforcement: JailEnforcement::Declared,
            require_process_isolation: false,
            deny_read: Vec::new(),
            resources: None,
        },
    }
}

type Outcome = std::result::Result<(), Box<dyn std::error::Error>>;

async fn spawn_sh(script: &str) -> Result<Arc<StdioSession>> {
    let mut command = std::process::Command::new("sh");
    command.args(["-c", script]);
    StdioSession::spawn(
        request(),
        Arc::new(Plain),
        Jail::new(std::env::temp_dir(), "test"),
        command,
    )
    .await
}

/// A session that owns no child and never records an exit, as one whose
/// kill cannot be acknowledged. Shared with the resource-level tests.
pub(in crate::tinybus_module) fn inert_session() -> Arc<StdioSession> {
    Arc::new(StdioSession {
        request: request(),
        shared: Arc::new(Shared::default()),
        stdin: tokio::sync::Mutex::new(None),
        child: Arc::new(StdMutex::new(None)),
        group: 0,
        pumps: Vec::new(),
    })
}

#[tokio::test]
async fn a_reaped_child_is_forgotten_so_its_recycled_id_is_never_signalled() -> Outcome {
    let session = spawn_sh("exit 0").await?;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while session.status().running {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert!(
        session
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none(),
        "the reaped child handle must be dropped"
    );
    // Killing after the exit is a harmless acknowledgement.
    session.kill().await?;
    Ok(())
}

#[tokio::test]
async fn buffers_never_hold_more_than_their_bound_even_after_a_partial_drain() -> Outcome {
    let total = MAX_STDIO_BUFFER_BYTES * 3;
    let session = spawn_sh(&format!("head -c {total} /dev/zero")).await?;
    let held = |session: &StdioSession| session.shared.lock().stdout.len();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while held(&session) < MAX_STDIO_BUFFER_BYTES {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    // One byte of room: the pump must read one byte, not a whole chunk.
    let chunk = session.read(1, 0).await;
    assert_eq!(chunk.stdout.len(), 1);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(held(&session) <= MAX_STDIO_BUFFER_BYTES);
    session.kill().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_kill_that_is_never_acknowledged_reports_pending_cleanup() -> Outcome {
    let error = inert_session()
        .kill()
        .await
        .err()
        .ok_or("no exit is recorded, so the kill cannot be acknowledged")?;
    assert!(error.to_string().contains("remains pending"), "{error}");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_write_queued_behind_a_stuck_write_gives_up_at_its_own_deadline() -> Outcome {
    let session = inert_session();
    // Hold the stdin lock like a write blocked on a child that never reads.
    let _held = session.stdin.lock().await;
    let started = tokio::time::Instant::now();
    let error = session
        .write(b"x")
        .await
        .err()
        .ok_or("the stdin lock is held, so the write cannot succeed")?;
    assert!(error.to_string().contains("busy"), "{error}");
    assert!(started.elapsed() <= std::time::Duration::from_millis(MAX_STDIO_WAIT_MS));
    Ok(())
}
