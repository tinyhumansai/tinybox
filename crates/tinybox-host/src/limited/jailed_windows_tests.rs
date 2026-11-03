//! Windows integration coverage for the backend-owned `AppContainer` process path.

use super::*;
use tinybox_core::ExecRequest;

#[tokio::test]
async fn detected_owned_backend_runs_with_only_the_approved_environment()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::new(
        tinybox_jail::Jail::new(root.path(), "host-owned-appcontainer"),
        1024,
    )?;
    assert!(format!("{host:?}").contains("appcontainer"));

    let parent_path = std::env::var("PATH").ok();
    let system_root = std::env::var_os("SystemRoot").ok_or("missing SystemRoot")?;
    let cmd = std::path::PathBuf::from(system_root)
        .join("System32")
        .join("cmd.exe");
    let mut request = ExecRequest::new([
        cmd.to_string_lossy().as_ref(),
        "/C",
        "echo %TINYBOX_APPROVED_ENV% & echo %PATH%",
    ]);
    request.cwd = Some(root.path().to_owned());
    request.env.insert(
        "TINYBOX_APPROVED_ENV".to_owned(),
        "approved-marker".to_owned(),
    );
    let output = host.run(&request).await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("approved-marker"),
        "stdout={stdout:?}, stderr={stderr:?}, exit_code={}",
        output.exit_code
    );
    if let Some(parent_path) = parent_path {
        assert!(
            !stdout.contains(&parent_path),
            "parent PATH leaked into jailed process"
        );
    }
    host.drain_checked().await?;
    Ok(())
}
