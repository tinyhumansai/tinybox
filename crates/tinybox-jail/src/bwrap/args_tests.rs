//! Tests for the `bwrap` argument builder.

use super::*;

const OPTS: Options = Options {
    disable_userns: true,
};

fn build(jail: &Jail) -> io::Result<Vec<String>> {
    jail_args(jail, None, OPTS).map(|argv| {
        argv.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    })
}

fn triple(argv: &[String], kind: &str, path: &Path) -> Option<usize> {
    let p = path.display().to_string();
    argv.windows(3)
        .position(|w| w[0] == kind && w[1] == p && w[2] == p)
}

fn pair(argv: &[String], flag: &str, path: &Path) -> Option<usize> {
    let p = path.display().to_string();
    argv.windows(2).position(|w| w[0] == flag && w[1] == p)
}

fn jail(root: &Path) -> Jail {
    Jail::new(root, "bwrap-test")
}

#[test]
fn namespaces_and_lifetime_flags_are_always_present() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let argv = build(&jail(root.path()))?;
    for flag in [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
    ] {
        assert!(argv.iter().any(|a| a == flag), "missing {flag}");
    }
    Ok(())
}

#[test]
fn disable_userns_is_omitted_when_the_probe_found_no_support() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let argv = jail_args(
        &jail(root.path()),
        None,
        Options {
            disable_userns: false,
        },
    )?;
    assert!(!argv.iter().any(|a| a == "--disable-userns"));
    Ok(())
}

#[test]
fn network_is_unshared_only_when_denied() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    assert!(
        !build(&jail(root.path()))?
            .iter()
            .any(|a| a == "--unshare-net")
    );
    assert!(
        build(&jail(root.path()).deny_net())?
            .iter()
            .any(|a| a == "--unshare-net")
    );
    Ok(())
}

#[test]
fn grants_become_bind_mounts_at_their_own_paths() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let ro = tempfile::tempdir()?;
    let rw = tempfile::tempdir()?;
    let j = jail(root.path())
        .add_read_only(ro.path())
        .add_read_write(rw.path());
    let argv = build(&j)?;
    assert!(triple(&argv, "--bind", root.path()).is_some());
    assert!(triple(&argv, "--bind", rw.path()).is_some());
    assert!(triple(&argv, "--ro-bind-try", ro.path()).is_some());
    assert!(triple(&argv, "--bind", ro.path()).is_none());
    Ok(())
}

#[test]
fn ungranted_paths_and_the_whole_of_etc_are_never_mounted() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let other = tempfile::tempdir()?;
    let argv = build(&jail(root.path()))?;
    let other = other.path().display().to_string();
    assert!(!argv.contains(&other));
    for etc in ["/etc", "/"] {
        assert!(triple(&argv, "--ro-bind-try", Path::new(etc)).is_none());
    }
    assert!(triple(&argv, "--ro-bind-try", Path::new("/etc/alternatives")).is_some());
    Ok(())
}

#[test]
fn a_read_only_grant_nested_in_the_root_is_mounted_after_it() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let nested = root.path().join("vendor");
    std::fs::create_dir(&nested)?;
    // Declared read-only grant first: order in the jail must not matter.
    let j = jail(root.path()).add_read_only(&nested);
    let argv = build(&j)?;
    let outer = triple(&argv, "--bind", root.path());
    let inner = triple(&argv, "--ro-bind-try", &nested);
    assert!(outer.is_some() && inner.is_some());
    assert!(outer < inner, "the nested read-only mount must come last");
    Ok(())
}

#[test]
fn a_read_only_grant_nested_in_a_read_write_grant_is_mounted_after_it() -> io::Result<()> {
    let rw = tempfile::tempdir()?;
    let nested = rw.path().join("sub").join("ro");
    std::fs::create_dir_all(&nested)?;
    let root = tempfile::tempdir()?;
    let j = jail(root.path())
        .add_read_only(&nested)
        .add_read_write(rw.path());
    let argv = build(&j)?;
    let outer = triple(&argv, "--bind", rw.path());
    let inner = triple(&argv, "--ro-bind-try", &nested);
    assert!(outer.is_some() && inner.is_some() && outer < inner);
    Ok(())
}

#[test]
fn grants_that_replace_a_private_mount_are_rejected() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    for bad in ["/", "/tmp", "/proc", "/proc/1", "/dev", "/dev/shm"] {
        for j in [
            jail(root.path()).add_read_only(bad),
            jail(root.path()).add_read_write(bad),
            jail(Path::new(bad)),
        ] {
            let kind = jail_args(&j, None, OPTS).err().map(|e| e.kind());
            assert_eq!(kind, Some(io::ErrorKind::InvalidInput), "{bad}");
        }
    }
    Ok(())
}

#[test]
fn a_grant_under_tmp_is_still_allowed() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    assert!(build(&jail(root.path())).is_ok());
    Ok(())
}

#[test]
fn deny_read_directly_inside_a_grant_is_masked_after_the_binds() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let secret_dir = root.path().join("secrets");
    std::fs::create_dir(&secret_dir)?;
    let secret_file = root.path().join("token");
    std::fs::write(&secret_file, "x")?;
    let mut j = jail(root.path());
    j.deny_read = vec![secret_dir.clone(), secret_file.clone()];
    let argv = build(&j)?;
    let bind = triple(&argv, "--bind", root.path());
    let dir_mask = pair(&argv, "--tmpfs", &secret_dir);
    let file = secret_file.display().to_string();
    let file_mask = argv
        .windows(3)
        .position(|w| w[0] == "--ro-bind" && w[1] == "/dev/null" && w[2] == file);
    assert!(bind.is_some() && dir_mask.is_some() && file_mask.is_some());
    assert!(bind < dir_mask && bind < file_mask);
    Ok(())
}

#[test]
fn deny_read_over_a_grant_drops_the_grant() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let ro = tempfile::tempdir()?;
    let mut j = jail(root.path()).add_read_only(ro.path());
    j.deny_read = vec![ro.path().to_path_buf()];
    let argv = build(&j)?;
    let ro = ro.path().display().to_string();
    assert!(!argv.contains(&ro));
    Ok(())
}

#[test]
fn deny_read_under_a_baseline_mount_is_enforced() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let mut j = jail(root.path());
    // A baseline file mount is dropped; a path inside /usr is masked.
    j.deny_read = vec![PathBuf::from("/etc/hosts"), PathBuf::from("/usr")];
    let argv = build(&j)?;
    assert!(triple(&argv, "--ro-bind-try", Path::new("/etc/hosts")).is_none());
    assert!(triple(&argv, "--ro-bind-try", Path::new("/usr")).is_none());
    assert!(triple(&argv, "--ro-bind-try", Path::new("/etc/passwd")).is_some());

    let mut j = jail(root.path());
    j.deny_read = vec![PathBuf::from("/usr/bin")];
    if Path::new("/usr/bin").is_dir() {
        let argv = build(&j)?;
        assert!(triple(&argv, "--ro-bind-try", Path::new("/usr")).is_some());
        assert!(pair(&argv, "--tmpfs", Path::new("/usr/bin")).is_some());
    }
    Ok(())
}

#[test]
fn deny_read_deeper_than_a_child_of_a_writable_grant_is_refused() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let nested = root.path().join("a").join("b");
    std::fs::create_dir_all(&nested)?;
    let mut j = jail(root.path());
    j.deny_read = vec![nested];
    let err = jail_args(&j, None, OPTS).err();
    assert_eq!(err.map(|e| e.kind()), Some(io::ErrorKind::InvalidInput));

    // The same path is fine when the holding mount is read-only.
    let ro = tempfile::tempdir()?;
    let nested = ro.path().join("a").join("b");
    std::fs::create_dir_all(&nested)?;
    let mut j = jail(root.path()).add_read_only(ro.path());
    j.deny_read = vec![nested.clone()];
    assert!(pair(&build(&j)?, "--tmpfs", &nested).is_some());
    Ok(())
}

#[test]
fn deny_read_of_a_missing_path_is_refused() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let mut j = jail(root.path());
    j.deny_read = vec![root.path().join("later")];
    assert_eq!(
        jail_args(&j, None, OPTS).err().map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    Ok(())
}

#[test]
fn missing_denial_inside_a_read_only_grant_is_refused() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let grant = tempfile::tempdir()?;
    let denied = grant.path().join("later");
    let mut j = jail(root.path()).add_read_only(grant.path());
    j.deny_read = vec![denied.clone()];
    assert_eq!(
        jail_args(&j, None, OPTS).err().map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    Ok(())
}

#[test]
fn missing_root_is_not_found() {
    let missing = jail(Path::new("/nonexistent/tinybox-jail-root"));
    let err = jail_args(&missing, None, OPTS).err().map(|e| e.kind());
    assert_eq!(err, Some(io::ErrorKind::NotFound));
}

#[test]
fn chdir_defaults_to_root_and_honours_the_command_cwd() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let sub = root.path().join("sub");
    let default = build(&jail(root.path()))?;
    assert!(pair(&default, "--chdir", root.path()).is_some());
    let custom: Vec<String> = jail_args(&jail(root.path()), Some(&sub), OPTS)?
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert!(pair(&custom, "--chdir", &sub).is_some());
    Ok(())
}

#[test]
fn relative_and_dotdot_paths_cannot_talk_around_the_private_mount_guard() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    for bad in [
        "/usr/../tmp",
        "/tmp/..",
        "/usr/../proc",
        "relative/dir",
        "/a/./../b",
    ] {
        for j in [
            jail(root.path()).add_read_only(bad),
            jail(root.path()).add_read_write(bad),
            jail(Path::new(bad)),
        ] {
            let kind = jail_args(&j, None, OPTS).err().map(|e| e.kind());
            assert_eq!(kind, Some(io::ErrorKind::InvalidInput), "{bad}");
        }
        let mut j = jail(root.path());
        j.deny_read = vec![bad.into()];
        assert!(jail_args(&j, None, OPTS).is_err(), "deny {bad}");
    }
    let kind = jail_args(&jail(root.path()), Some(Path::new("../x")), OPTS)
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::InvalidInput));
    Ok(())
}

#[test]
fn a_nested_grant_through_a_planted_symlink_is_refused() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    std::os::unix::fs::symlink(secret.path(), root.path().join("vendor"))?;
    let j = jail(root.path()).add_read_only(root.path().join("vendor"));
    let kind = jail_args(&j, None, OPTS).err().map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::InvalidInput));
    Ok(())
}

#[test]
fn nul_bytes_in_paths_are_rejected() -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let root = tempfile::tempdir()?;
    let evil = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/x\0--bind"));
    for j in [jail(root.path()).add_read_only(evil), jail(evil)] {
        let kind = jail_args(&j, None, OPTS).err().map(|e| e.kind());
        assert_eq!(kind, Some(io::ErrorKind::InvalidInput));
    }
    Ok(())
}

#[test]
fn a_denial_through_a_baseline_symlink_also_covers_the_link_target() -> io::Result<()> {
    // `/bin` is a symlink to `usr/bin` on merged-/usr hosts.
    let Ok(target) = std::fs::read_link("/bin") else {
        return Ok(());
    };
    if target != Path::new("usr/bin") || !Path::new("/usr/bin/sh").exists() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let mut j = jail(root.path());
    j.deny_read = vec![PathBuf::from("/bin/sh")];
    let argv = build(&j)?;
    assert!(
        argv.windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == "/dev/null" && w[2] == "/usr/bin/sh"),
        "{argv:?}"
    );
    Ok(())
}
