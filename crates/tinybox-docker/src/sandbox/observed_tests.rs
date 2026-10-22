//! Container-side supervisor fixtures preserve workload streams and cleanup receipts.

#![cfg(unix)]
use super::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;

async fn reserve_fixture(token: &str) -> Result<(tempfile::TempDir, String)> {
    // The production control root is the container's `/tmp`. Keep these shell
    // protocol tests inside an owned fixture directory instead of relying on
    // the host process's `/tmp` quota.
    let fixture_root =
        tempfile::tempdir().map_err(|error| Error::io("create control fixture", &error))?;
    let dir = fixture_root
        .path()
        .join(format!("tinybox-observed-{token}"))
        .display()
        .to_string();
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(RESERVE)
        .arg("tinybox-observed-reserve")
        .arg(&dir)
        .arg(token)
        .output()
        .await
        .map_err(|error| Error::io("reserve observed fixture", &error))?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ready\n");
    Ok((fixture_root, dir))
}

#[test]
fn observed_exec_keeps_docker_flags_and_untrusted_argv_separate() -> Result<()> {
    let id = BoxId::new("box-4")?;
    let request = ExecRequest::new(["printf", "%s", "value; touch /tmp/nope"])
        .with_cwd("/workspace/project")
        .with_env("MODE", "two words")
        .with_stdin([0, 255, 1]);

    let observed = exec("team", &id, &request, "a1b2")?;
    let argv = observed.argv;
    assert_eq!(argv[0..3], ["docker", "exec", "-i"]);
    assert_eq!(argv[3..5], ["--workdir", "/workspace/project"]);
    assert_eq!(argv[5..7], ["--env", "MODE=two words"]);
    assert_eq!(argv[7], "tinybox-team-box-4");
    assert_eq!(argv[8..10], ["sh", "-c"]);
    assert!(argv[10].contains("setsid"));
    assert_eq!(argv[11], "tinybox-observed");
    assert_eq!(argv[12], "/tmp/tinybox-observed-a1b2");
    assert_eq!(argv[13], "a1b2");
    assert_eq!(argv[14..], request.argv);
    assert_eq!(observed.stdin, Some(vec![0, 255, 1]));
    Ok(())
}

#[tokio::test]
async fn supervisor_preserves_binary_pipes_stdin_and_exit_status() -> Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let token = format!("binary-fixture-{}", uuid::Uuid::new_v4().simple());
    let (_control_root, dir) = reserve_fixture(&token).await?;
    let real_workspace = temporary.path().join("real");
    std::fs::create_dir(&real_workspace)
        .map_err(|error| Error::io("create fixture workspace", &error))?;
    let workspace = temporary.path().join("workspace");
    std::os::unix::fs::symlink(&real_workspace, &workspace)
        .map_err(|error| Error::io("link fixture workspace", &error))?;
    let cwd = workspace.as_path();
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg("tinybox-observed")
        .arg(&dir)
        .arg(&token)
        .arg("sh")
        .arg("-c")
        .arg("cat; printf '\\377\\000'; printf '|%s|%s' \"$MODE\" \"$PWD\"; printf 'problem' >&2; exit 7")
        .current_dir(cwd)
        .env("MODE", "observed")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| Error::io("spawn local shell fixture", &error))?;
    let mut stdin = child.stdin.take().ok_or_else(|| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "test observed stdin",
        message: "fixture stdin was not piped".to_owned(),
    })?;
    stdin
        .write_all(&[0, 255, 1])
        .await
        .map_err(|error| Error::io("write fixture stdin", &error))?;
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .map_err(|_| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "wait for observed fixture",
            message: "fixture exceeded its deadline".to_owned(),
        })?
        .map_err(|error| Error::io("wait for local shell fixture", &error))?;

    assert_eq!(output.status.code(), Some(7));
    let mut expected_stdout = vec![0, 255, 1, 255, 0];
    let resolved_cwd = cwd
        .canonicalize()
        .map_err(|error| Error::io("resolve fixture workspace", &error))?;
    expected_stdout.extend_from_slice(format!("|observed|{}", resolved_cwd.display()).as_bytes());
    assert_eq!(output.stdout, expected_stdout);
    assert_eq!(output.stderr, b"problem");
    assert!(std::path::Path::new(&dir).join("done").exists());
    assert_eq!(
        std::fs::read(std::path::Path::new(&dir).join("status"))
            .map_err(|error| Error::io("read supervisor status", &error))?,
        b"7\n"
    );
    let _ = std::fs::remove_dir_all(dir);
    drop(temporary);
    Ok(())
}

#[tokio::test]
async fn supervisor_reaps_leader_and_retires_background_process_group() -> Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let token = format!("background-fixture-{}", uuid::Uuid::new_v4().simple());
    let (_control_root, dir) = reserve_fixture(&token).await?;
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("sh")
            .arg("-c")
            .arg(SUPERVISOR)
            .arg("tinybox-observed")
            .arg(&dir)
            .arg(&token)
            .arg("sh")
            .arg("-c")
            .arg("sleep 60 & printf 'leader-finished'")
            .output(),
    )
    .await
    .map_err(|_| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "reap background fixture",
        message: "supervisor did not finish process-group cleanup".to_owned(),
    })?
    .map_err(|error| Error::io("run background fixture", &error))?;

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"leader-finished");
    assert!(std::path::Path::new(&dir).join("done").exists());
    let _ = std::fs::remove_dir_all(dir);
    drop(temporary);
    Ok(())
}

#[tokio::test]
async fn image_without_setsid_refuses_observed_command_before_execution() -> Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let path = temporary.path().join("bin");
    std::fs::create_dir(&path).map_err(|error| Error::io("create fixture path", &error))?;
    std::os::unix::fs::symlink("/bin/mkdir", path.join("mkdir"))
        .map_err(|error| Error::io("link fixture mkdir", &error))?;
    std::os::unix::fs::symlink("/bin/cat", path.join("cat"))
        .map_err(|error| Error::io("link fixture cat", &error))?;
    let token = format!("unsupported-fixture-{}", uuid::Uuid::new_v4().simple());
    let (_control_root, dir) = reserve_fixture(&token).await?;

    let output = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg("tinybox-observed")
        .arg(&dir)
        .arg(&token)
        .arg("sh")
        .arg("-c")
        .arg("printf 'must-not-run'")
        .env("PATH", path)
        .output()
        .await
        .map_err(|error| Error::io("run unsupported fixture", &error))?;

    assert_eq!(output.status.code(), Some(125));
    assert_eq!(output.stdout, b"");
    assert!(std::path::Path::new(&dir).join("unsupported").exists());
    assert!(std::path::Path::new(&dir).join("done").exists());
    assert_eq!(
        std::fs::read(std::path::Path::new(&dir).join("status"))
            .map_err(|error| Error::io("read unsupported status", &error))?,
        b"125\n"
    );
    let acknowledgement = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(CANCEL_AND_ACK)
        .arg("tinybox-observed-cancel")
        .arg(&dir)
        .arg(&token)
        .output()
        .await
        .map_err(|error| Error::io("acknowledge unsupported fixture", &error))?;
    assert_eq!(acknowledgement.stdout, b"unsupported\n");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test]
async fn supervisor_requires_a_reserved_owner_token_before_starting() -> Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let token = format!("unreserved-fixture-{}", uuid::Uuid::new_v4().simple());
    let dir = temporary
        .path()
        .join(format!("tinybox-observed-{token}"))
        .display()
        .to_string();
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg("tinybox-observed")
        .arg(&dir)
        .arg(&token)
        .arg("sh")
        .arg("-c")
        .arg("printf 'must-not-run'")
        .output()
        .await
        .map_err(|error| Error::io("run unreserved fixture", &error))?;

    assert_eq!(output.status.code(), Some(125));
    assert_eq!(output.stdout, b"");
    assert!(!std::path::Path::new(&dir).exists());
    drop(temporary);
    Ok(())
}

#[tokio::test]
async fn reservation_retries_only_accept_the_original_owner_token() -> Result<()> {
    let token = format!("owner-fixture-{}", uuid::Uuid::new_v4().simple());
    let (_control_root, dir) = reserve_fixture(&token).await?;
    let retry = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(RESERVE)
        .arg("tinybox-observed-reserve")
        .arg(&dir)
        .arg(&token)
        .output()
        .await
        .map_err(|error| Error::io("retry observed reservation", &error))?;
    assert!(retry.status.success());
    assert_eq!(retry.stdout, b"ready\n");

    let foreign = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(RESERVE)
        .arg("tinybox-observed-reserve")
        .arg(&dir)
        .arg("different-owner")
        .output()
        .await
        .map_err(|error| Error::io("reject foreign observed reservation", &error))?;
    assert_eq!(foreign.status.code(), Some(125));
    assert_eq!(
        std::fs::read(std::path::Path::new(&dir).join("owner"))
            .map_err(|error| Error::io("read reservation owner", &error))?,
        format!("{token}\n").as_bytes()
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test]
async fn cancellation_fence_acknowledges_a_supervisor_that_starts_late() -> Result<()> {
    let token = format!("late-start-fixture-{}", uuid::Uuid::new_v4().simple());
    let (_control_root, dir) = reserve_fixture(&token).await?;
    let cancellation = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(CANCEL_AND_ACK)
        .arg("tinybox-observed-cancel")
        .arg(&dir)
        .arg(&token)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| Error::io("start early cancellation fixture", &error))?;
    let cancel_path = std::path::Path::new(&dir).join("cancel");
    tokio::time::timeout(Duration::from_secs(3), async {
        while !cancel_path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "observe startup fence",
        message: "cleanup did not publish its cancellation fence".to_owned(),
    })?;

    let late_supervisor = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg("tinybox-observed")
        .arg(&dir)
        .arg(&token)
        .arg("sh")
        .arg("-c")
        .arg("printf 'must-not-run'")
        .output()
        .await
        .map_err(|error| Error::io("run late supervisor fixture", &error))?;
    assert_eq!(late_supervisor.status.code(), Some(125));
    assert_eq!(late_supervisor.stdout, b"");
    let acknowledgement =
        tokio::time::timeout(Duration::from_secs(3), cancellation.wait_with_output())
            .await
            .map_err(|_| Error::Backend {
                sandbox: NAME.to_owned(),
                operation: "await late-start cleanup",
                message: "cancel waiter did not receive its receipt".to_owned(),
            })?
            .map_err(|error| Error::io("wait for late-start cleanup", &error))?;
    assert!(acknowledgement.status.success());
    assert_eq!(acknowledgement.stdout, b"");
    assert!(std::path::Path::new(&dir).join("done").exists());
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test]
async fn cancellation_waits_for_container_side_waiter_acknowledgement() -> Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let token = format!("cancel-fixture-{}", uuid::Uuid::new_v4().simple());
    let (_control_root, dir) = reserve_fixture(&token).await?;
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg("tinybox-observed")
        .arg(&dir)
        .arg(&token)
        .arg("sh")
        .arg("-c")
        .arg("sleep 60")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| Error::io("spawn cancellation fixture", &error))?;

    let pid_path = std::path::Path::new(&dir).join("pid");
    tokio::time::timeout(Duration::from_secs(3), async {
        while !pid_path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "start cancellation fixture",
        message: "supervisor did not publish its process-group identity".to_owned(),
    })?;

    let lost_reply = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("sh -c \"$1\" ignored \"$2\" \"$3\" >/dev/null; exit 42")
        .arg("simulate-lost-reply")
        .arg(CANCEL_AND_ACK)
        .arg(&dir)
        .arg(&token)
        .output()
        .await
        .map_err(|error| Error::io("simulate lost cancellation reply", &error))?;
    assert!(!lost_reply.status.success());
    assert!(std::path::Path::new(&dir).join("done").exists());
    let retry = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(CANCEL_AND_ACK)
        .arg("tinybox-observed-cancel")
        .arg(&dir)
        .arg(&token)
        .output()
        .await
        .map_err(|error| Error::io("retry lost cancellation reply", &error))?;
    assert!(retry.status.success());
    assert_eq!(retry.stdout, b"");

    let lost_release_reply = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("sh -c \"$1\" ignored \"$2\" \"$3\" >/dev/null; exit 42")
        .arg("simulate-lost-release-reply")
        .arg(RELEASE_RECEIPT)
        .arg(&dir)
        .arg(&token)
        .output()
        .await
        .map_err(|error| Error::io("simulate lost receipt-release reply", &error))?;
    assert!(!lost_release_reply.status.success());
    assert!(!std::path::Path::new(&dir).exists());
    let release_retry = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(RELEASE_RECEIPT)
        .arg("tinybox-observed-release")
        .arg(&dir)
        .arg(&token)
        .output()
        .await
        .map_err(|error| Error::io("retry receipt release", &error))?;
    assert!(release_retry.status.success());

    let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .map_err(|_| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "reap cancellation fixture",
            message: "supervisor did not exit after acknowledging cleanup".to_owned(),
        })?
        .map_err(|error| Error::io("reap cancellation fixture", &error))?;
    assert_ne!(status.code(), Some(0));
    assert!(!std::path::Path::new(&dir).exists());
    drop(temporary);
    Ok(())
}

#[tokio::test]
async fn cancelling_a_workload_does_not_leak_the_supervisors_wait_diagnostic() -> Result<()> {
    let token = format!(
        "cancel-diagnostic-fixture-{}",
        uuid::Uuid::new_v4().simple()
    );
    let (_control_root, dir) = reserve_fixture(&token).await?;
    let child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(SUPERVISOR)
        .arg("tinybox-observed")
        .arg(&dir)
        .arg(&token)
        .arg("sh")
        .arg("-c")
        .arg("printf 'ready'; sleep 60")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| Error::io("spawn diagnostic cancellation fixture", &error))?;

    let pid_path = std::path::Path::new(&dir).join("pid");
    tokio::time::timeout(Duration::from_secs(3), async {
        while !pid_path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "start diagnostic cancellation fixture",
        message: "supervisor did not publish its process-group identity".to_owned(),
    })?;

    let acknowledgement = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(CANCEL_AND_ACK)
        .arg("tinybox-observed-cancel")
        .arg(&dir)
        .arg(&token)
        .output()
        .await
        .map_err(|error| Error::io("cancel diagnostic fixture", &error))?;
    assert!(acknowledgement.status.success());

    let output = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .map_err(|_| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "reap diagnostic cancellation fixture",
            message: "supervisor did not exit after acknowledging cleanup".to_owned(),
        })?
        .map_err(|error| Error::io("wait for diagnostic cancellation fixture", &error))?;
    assert_ne!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"ready");
    assert_eq!(output.stderr, b"");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test]
async fn bash_supervisor_reaps_its_watcher_without_changing_workload_stderr() -> Result<()> {
    let token = format!(
        "watcher-diagnostic-fixture-{}",
        uuid::Uuid::new_v4().simple()
    );
    let (_control_root, dir) = reserve_fixture(&token).await?;
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("bash")
            .arg("-c")
            .arg(SUPERVISOR)
            .arg("tinybox-observed")
            .arg(&dir)
            .arg(&token)
            .arg("sh")
            .arg("-c")
            .arg("printf 'problem' >&2; exit 7")
            .output(),
    )
    .await
    .map_err(|_| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "reap watcher diagnostic fixture",
        message: "supervisor did not finish watcher cleanup".to_owned(),
    })?
    .map_err(|error| Error::io("run watcher diagnostic fixture", &error))?;
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stderr, b"problem");
    assert!(std::path::Path::new(&dir).join("done").exists());
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}
