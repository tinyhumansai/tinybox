use super::*;

#[test]
fn defaults_are_permissive() {
    let j = Jail::new("/tmp", "x");
    assert!(j.allow_net);
    assert!(j.allow_subprocess);
    assert_eq!(j.label, "x");
    assert_eq!(j.read_only.len(), 0);
    assert_eq!(j.resources, None);
}

#[test]
fn soft_resource_values_do_not_become_hard_constraints() {
    let mut jail = Jail::new("/tmp", "x");
    jail.resources = Some(tinybox_core::Resources::DEFAULT);
    assert_eq!(
        jail.constraints(),
        vec![tinybox_core::Constraint::Filesystem]
    );
    jail = jail.with_hard_requirements([
        tinybox_core::Constraint::Cpu,
        tinybox_core::Constraint::Memory,
        tinybox_core::Constraint::Pids,
        tinybox_core::Constraint::Disk,
    ]);
    assert_eq!(
        jail.constraints(),
        vec![
            tinybox_core::Constraint::Filesystem,
            tinybox_core::Constraint::Cpu,
            tinybox_core::Constraint::Memory,
            tinybox_core::Constraint::Pids,
            tinybox_core::Constraint::Disk,
        ]
    );
}

#[test]
fn hard_network_and_subprocess_requirements_deny_that_access() {
    use tinybox_core::{Constraint, HostRef, Placement, SandboxRef, WorkspaceSource};

    let jail =
        Jail::new("/tmp", "x").with_hard_requirements([Constraint::Network, Constraint::Cpu]);
    assert!(!jail.allow_net);
    assert!(jail.allow_subprocess);
    let placement = Placement::new(
        HostRef::new("local").expect("valid host ref"),
        SandboxRef::new("noop").expect("valid sandbox ref"),
    );
    let spec = tinybox_core::BoxSpec::new(placement, WorkspaceSource::LocalDir("/tmp".into()))
        .with_hard_requirements([Constraint::Subprocess]);
    let jail = Jail::new("/tmp", "x").with_box_spec(&spec);
    assert!(jail.allow_net);
    assert!(!jail.allow_subprocess);
}

#[test]
fn deny_net_is_idempotent() {
    let j = Jail::new("/tmp", "x").deny_net().deny_net();
    assert!(!j.allow_net);
}

#[test]
fn deny_subprocess_is_idempotent() {
    let j = Jail::new("/tmp", "x").deny_subprocess().deny_subprocess();
    assert!(!j.allow_subprocess);
}

#[test]
fn add_read_only_appends_in_order() {
    let j = Jail::new("/tmp", "x")
        .add_read_only("/a")
        .add_read_only("/b")
        .add_read_only("/c");
    assert_eq!(j.read_only.len(), 3);
    assert_eq!(j.read_only[0], PathBuf::from("/a"));
    assert_eq!(j.read_only[2], PathBuf::from("/c"));
}

#[test]
fn canonicalize_resolves_real_path() {
    let dir = std::env::temp_dir();
    let mut j = Jail::new(&dir, "x");
    j.canonicalize().unwrap();
    // After canonicalize, root has no `..` and resolves to a real path.
    assert!(j.root.is_absolute());
    assert!(j.root.exists());
}

#[test]
fn canonicalize_swallows_missing_read_only() {
    // read_only entries that don't exist are silently dropped from
    // canonicalization (they stay as-is). Verify no panic.
    let dir = std::env::temp_dir();
    let mut j = Jail::new(&dir, "x").add_read_only("/this/never/existed");
    j.canonicalize().unwrap();
    assert_eq!(j.read_only.len(), 1);
}

#[test]
fn canonicalize_errors_on_missing_root() {
    let mut j = Jail::new("/no/such/root/here", "x");
    let err = j.canonicalize().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn defaults_have_no_extra_read_write_paths() {
    let j = Jail::new("/tmp", "x");
    assert_eq!(j.read_write, Vec::<PathBuf>::new());
}

#[test]
fn add_read_write_appends_in_order_and_leaves_read_only_alone() {
    let j = Jail::new("/tmp", "x")
        .add_read_write("/a")
        .add_read_write("/b");
    assert_eq!(j.read_write, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    assert_eq!(j.read_only, Vec::<PathBuf>::new());
    assert_eq!(j.root, PathBuf::from("/tmp"));
}

#[test]
fn canonicalize_resolves_read_write_paths() {
    let root = tempfile::tempdir().unwrap();
    let extra = tempfile::tempdir().unwrap();
    let dotted = extra.path().join("sub").join("..");
    std::fs::create_dir_all(extra.path().join("sub")).unwrap();
    let mut j = Jail::new(root.path(), "x").add_read_write(&dotted);
    j.canonicalize().unwrap();
    assert_eq!(j.read_write, vec![extra.path().canonicalize().unwrap()]);
}

#[test]
fn canonicalize_keeps_missing_read_write_as_is() {
    let root = tempfile::tempdir().unwrap();
    let mut j = Jail::new(root.path(), "x").add_read_write("/this/never/existed");
    j.canonicalize().unwrap();
    assert_eq!(j.read_write, vec![PathBuf::from("/this/never/existed")]);
}

#[cfg(unix)]
#[test]
fn owned_captured_spawn_preserves_both_pipes_and_exit_status() -> std::io::Result<()> {
    use std::io::Read;
    use std::time::{Duration, Instant};

    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "owned-captured-spawn");
    let backend = crate::NoopBackend;
    let mut command = std::process::Command::new("/bin/sh");
    command.args([
        "-c",
        "printf stdout-marker; printf stderr-marker >&2; exit 23",
    ]);

    let mut child = crate::spawn_owned_captured_with(&backend, &jail, command)?;
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout_mut()
        .expect("captured stdout")
        .read_to_string(&mut stdout)?;
    child
        .stderr_mut()
        .expect("captured stderr")
        .read_to_string(&mut stderr)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "child did not exit",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    assert_eq!(stdout, "stdout-marker");
    assert_eq!(stderr, "stderr-marker");
    assert_eq!(status.code(), Some(23));
    assert!(!status.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn owned_spawn_with_an_approved_environment_drops_everything_else() -> std::io::Result<()> {
    use std::io::Read;

    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "owned-approved-env");
    let mut command = std::process::Command::new("/bin/sh");
    command
        .args([
            "-c",
            r#"printf '%s|%s' "${APPROVED-}" "${UNAPPROVED-unset}""#,
        ])
        .env("UNAPPROVED", "leaked");
    let approved = std::collections::BTreeMap::from([("APPROVED".to_owned(), "yes".to_owned())]);
    let mut child = crate::spawn_owned_captured_with_backend_and_env(
        &crate::NoopBackend,
        &jail,
        command,
        &approved,
    )?;
    let mut stdout = String::new();
    child
        .stdout_mut()
        .expect("captured stdout")
        .read_to_string(&mut stdout)?;
    assert_eq!(stdout, "yes|unset");
    Ok(())
}

#[cfg(windows)]
#[test]
fn owned_captured_spawn_does_not_claim_the_child_pid_as_a_process_group() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "owned-captured-spawn");
    let backend = crate::NoopBackend;
    let mut command = std::process::Command::new("cmd");
    command.args(["/C", "exit 0"]);

    let child = crate::spawn_owned_captured_with(&backend, &jail, command)?;

    assert_eq!(child.local_process_group_id(), None);
    Ok(())
}

#[cfg(unix)]
#[test]
fn canonicalize_deduplicates_denials_that_resolve_through_symlink_aliases() -> std::io::Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let store = tempfile::tempdir()?;
    let credential = store.path().join("credential");
    std::fs::write(&credential, b"secret")?;
    let alias = root.path().join("credential-alias");
    symlink(&credential, &alias)?;
    let mut jail = Jail::new(root.path(), "alias-denial");
    jail.deny_read = vec![alias, credential.clone()];

    jail.canonicalize()?;

    assert_eq!(jail.deny_read, vec![credential.canonicalize()?]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_nested_grant_through_a_symlink_planted_in_a_writable_root_is_refused() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    std::os::unix::fs::symlink(secret.path(), root.path().join("vendor"))?;
    let mut jail = Jail::new(root.path(), "t").add_read_only(root.path().join("vendor"));
    let err = jail.canonicalize().err().map(|e| e.kind());
    assert_eq!(err, Some(std::io::ErrorKind::InvalidInput));

    // Same through a read-write grant, and through a deeper component.
    let rw = tempfile::tempdir()?;
    std::fs::create_dir(rw.path().join("a"))?;
    std::os::unix::fs::symlink(secret.path(), rw.path().join("a").join("link"))?;
    let mut jail = Jail::new(root.path(), "t")
        .add_read_write(rw.path())
        .add_read_only(rw.path().join("a").join("link").join("x"));
    assert!(jail.canonicalize().is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_symlinked_grant_outside_any_writable_ancestor_is_still_allowed() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let target = tempfile::tempdir()?;
    let holder = tempfile::tempdir()?;
    let link = holder.path().join("tools");
    std::os::unix::fs::symlink(target.path(), &link)?;
    let mut jail = Jail::new(root.path(), "t").add_read_only(&link);
    jail.canonicalize()?;
    assert_eq!(jail.read_only, vec![target.path().canonicalize()?]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn the_check_sees_a_planted_link_however_the_root_is_spelled() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    std::os::unix::fs::symlink(secret.path(), root.path().join("vendor"))?;
    let holder = tempfile::tempdir()?;
    let alias = holder.path().join("alias");
    std::os::unix::fs::symlink(root.path(), &alias)?;
    // Root given by its real path, grant spelled through the alias (and the
    // reverse): both must be refused.
    for (writable, grant) in [
        (root.path().to_path_buf(), alias.join("vendor")),
        (alias.clone(), root.path().join("vendor")),
    ] {
        let err = crate::reject_symlinked_grants(&[writable.as_path()], &[grant.as_path()])
            .err()
            .map(|e| e.kind());
        assert_eq!(err, Some(std::io::ErrorKind::InvalidInput), "{grant:?}");
    }
    Ok(())
}

#[test]
fn nested_denial_refuses_only_paths_deeper_than_a_direct_child() {
    let writable = Path::new("/work");
    assert!(nested_denial(Path::new("/work/secret"), writable).is_none());
    assert!(nested_denial(Path::new("/elsewhere/a/secret"), writable).is_none());
    assert!(nested_denial(Path::new("/workshop/a/secret"), writable).is_none());
    for nested in ["/work/a/secret", "/work/a/b/secret", "/work"] {
        let error = nested_denial(Path::new(nested), writable).expect(nested);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{nested}");
    }
}
