//! Tests for the launcher; no `bwrap` needed, a stand-in script plays it.

use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt as _;

fn stand_in(dir: &Path, body: &str) -> io::Result<PathBuf> {
    let path = dir.join("fake-bwrap");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

/// The shell production would pick. Other tests in this process hold
/// descriptors above 9 open, which `dash` refuses to close by design.
fn shell() -> &'static str {
    pick_shell(|path| Path::new(path).is_file())
}

fn tmp() -> PathBuf {
    std::env::temp_dir()
}

fn run(shell: &str, body: &str, items: &[&str]) -> io::Result<String> {
    let dir = tempfile::tempdir()?;
    let bwrap = stand_in(dir.path(), body)?;
    let argv: Vec<OsString> = items.iter().map(OsString::from).collect();
    let file = ArgsFile::create(&argv, &tmp())?;
    let out = command(shell, &bwrap, &file, "prog".as_ref(), &["a".into()]).output()?;
    file.discard();
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn shell_prefers_bash_and_falls_back_to_sh() {
    assert_eq!(pick_shell(|p| p == "/bin/bash"), "/bin/bash");
    assert_eq!(pick_shell(|p| p == "/usr/bin/bash"), "/usr/bin/bash");
    assert_eq!(pick_shell(|_| false), "/bin/sh");
}

#[test]
fn the_args_file_is_private_nul_separated_and_never_reused() -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let file = ArgsFile::create(
        &["--setenv".into(), "TOKEN".into(), "s3cret".into()],
        &tmp(),
    )?;
    assert_eq!(std::fs::read(file.path())?, b"--setenv\0TOKEN\0s3cret\0");
    assert_eq!(std::fs::metadata(file.path())?.mode() & 0o777, 0o600);
    let dir = file
        .path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    assert_eq!(std::fs::metadata(&dir)?.mode() & 0o777, 0o700);
    let other = ArgsFile::create(&[], &tmp())?;
    assert_ne!(other.path(), file.path());
    file.discard();
    other.discard();
    assert!(!dir.exists());
    Ok(())
}

#[test]
fn the_launcher_hands_bwrap_the_args_on_fd_9_and_deletes_the_file() -> io::Result<()> {
    let out = run(
        shell(),
        r#"[ "$1" = "--args" ] && [ "$2" = "9" ] && [ "$3" = "--" ] || exit 3
cat <&9 | tr '\0' ','
printf '|%s|%s' "$4" "$5""#,
        &["--a", "value with space", "--b"],
    )?;
    assert_eq!(out, "--a,value with space,--b,|prog|a");
    Ok(())
}

#[test]
fn the_args_file_is_gone_once_the_launcher_has_started_bwrap() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let bwrap = stand_in(dir.path(), "exit 0")?;
    let file = ArgsFile::create(&["x".into()], &tmp())?;
    let path = file.path().to_path_buf();
    assert!(
        command(shell(), &bwrap, &file, "prog".as_ref(), &[])
            .status()?
            .success()
    );
    assert!(!path.exists() && !path.parent().is_some_and(Path::exists));
    Ok(())
}

#[test]
fn the_launcher_runs_with_an_empty_environment() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let bwrap = stand_in(dir.path(), "env")?;
    let file = ArgsFile::create(&[], &tmp())?;
    let out = command(shell(), &bwrap, &file, "prog".as_ref(), &[]).output()?;
    file.discard();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("HOME=") && !text.contains("LD_PRELOAD"),
        "{text}"
    );
    Ok(())
}

#[test]
fn inheritable_descriptors_including_high_numbers_are_closed_by_bash() -> io::Result<()> {
    let secret = tempfile::NamedTempFile::new()?;
    // Enough open files that some descriptors are above 9.
    let mut files = Vec::new();
    for _ in 0..12 {
        let file = std::fs::File::open(secret.path())?;
        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty())?;
        files.push(file);
    }
    let fds: Vec<i32> = files.iter().map(AsRawFd::as_raw_fd).collect();
    assert!(fds.iter().any(|fd| *fd > 9), "{fds:?}");
    let name = secret.path().display().to_string();
    let shell = shell();
    if !shell.ends_with("bash") {
        eprintln!("skipped: no bash");
        return Ok(());
    }
    let out = run(shell, "ls -l /proc/self/fd", &[])?;
    assert!(!out.contains(&name), "descriptors {fds:?} survived: {out}");
    Ok(())
}

#[test]
fn a_launcher_that_cannot_open_the_args_file_fails_closed_without_running_bwrap() -> io::Result<()>
{
    let dir = tempfile::tempdir()?;
    let marker = dir.path().join("ran");
    let bwrap = stand_in(dir.path(), &format!("touch '{}'", marker.display()))?;
    let missing = ArgsFile {
        dir: dir.path().join("gone"),
        file: dir.path().join("gone").join("args"),
    };
    let status = command(shell(), &bwrap, &missing, "prog".as_ref(), &[]).status()?;
    assert_eq!(status.code(), Some(126));
    assert!(!marker.exists(), "bwrap must not run without its arguments");
    Ok(())
}

#[test]
fn a_nul_byte_in_an_argument_is_refused_before_anything_is_written() {
    use std::os::unix::ffi::OsStringExt as _;
    let evil = OsString::from_vec(b"v\0--bind".to_vec());
    let kind = ArgsFile::create(&["--setenv".into(), "K".into(), evil], &tmp())
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::InvalidInput));
}

#[test]
fn the_args_directory_prefers_xdg_runtime_dir_but_never_one_inside_a_grant() -> io::Result<()> {
    let xdg = tempfile::tempdir()?;
    let temp = tempfile::tempdir()?;
    let chosen = base_dir(&[], Some(xdg.path().into()), temp.path().into())?;
    assert_eq!(chosen, xdg.path());
    // XDG dir inside a grant: fall back to the temp dir.
    let chosen = base_dir(&[xdg.path()], Some(xdg.path().into()), temp.path().into())?;
    assert_eq!(chosen, temp.path());
    // Unset or missing XDG dir: temp dir.
    let missing = xdg.path().join("missing");
    let chosen = base_dir(&[], Some(missing), temp.path().into())?;
    assert_eq!(chosen, temp.path());
    // Everything inside a grant: refuse.
    let kind = base_dir(&[temp.path()], None, temp.path().join("sub"))
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::PermissionDenied));
    Ok(())
}
