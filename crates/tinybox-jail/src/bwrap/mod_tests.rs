//! Tests for the bubblewrap backend that need no working `bwrap`.

use super::*;
use std::os::unix::fs::PermissionsExt as _;

fn fake_bwrap() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-bwrap.sh")
}

fn available() -> BubblewrapBackend {
    BubblewrapBackend::unverified("/nonexistent/bwrap", true)
}

fn verified(program: &str) -> Verified {
    Verified {
        program: program.into(),
        disable_userns: true,
    }
}

fn argv_of(cmd: &Command) -> Vec<String> {
    cmd.get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn unavailable_backend_claims_nothing_and_refuses_to_spawn() {
    let backend = BubblewrapBackend { verified: None };
    assert_eq!(backend.name(), "bubblewrap");
    assert!(!backend.is_available());
    assert_eq!(backend.isolation(), IsolationLevel::None);
    assert!(!backend.is_suitable_for_untrusted_code());
    let kind = backend
        .spawn(&Jail::new(".", "t"), Command::new("true"))
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::Unsupported));
}

#[test]
fn isolation_is_the_minimum_over_configurations_and_kernel_needs_a_private_network() {
    let hardened = BubblewrapBackend::unverified("/x", true);
    let closed = Jail::new(".", "t").deny_net();
    let open = Jail::new(".", "t");
    assert_eq!(hardened.isolation(), IsolationLevel::Process);
    assert_eq!(hardened.isolation_for(&closed), IsolationLevel::Kernel);
    assert_eq!(hardened.isolation_for(&open), IsolationLevel::Process);
    // Status without a jail (what a host reports) is the worst case, so the
    // per-backend question answers false.
    assert!(!hardened.is_suitable_for_untrusted_code());
    assert!(hardened.is_suitable_for_untrusted_jail(&closed));
    assert!(!hardened.is_suitable_for_untrusted_jail(&open));
    assert!(hardened.carves_denials());
    let old = BubblewrapBackend::unverified("/x", false);
    assert_eq!(old.isolation(), IsolationLevel::None);
    assert_eq!(old.isolation_for(&closed), IsolationLevel::None);
    assert!(!old.is_suitable_for_untrusted_jail(&closed));
    assert!(old.is_available(), "it still confines the filesystem");
}

#[test]
fn subprocess_denial_is_refused_because_it_is_not_enforced() {
    let backend = available();
    let jail = Jail::new(".", "t").deny_subprocess();
    assert!(backend.require(&jail).is_err());
    let kind = backend
        .spawn(&jail, Command::new("true"))
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::Unsupported));
}

#[test]
fn secrets_stay_out_of_argv_and_the_launcher_environment() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("node");
    cmd.arg("server.js")
        .env("GITHUB_TOKEN", "ghp_s3cret")
        .env("LD_PRELOAD", "/evil.so")
        .env("A", "1")
        .env_remove("B");
    let jail = Jail::new(root.path(), "t");
    let prepared = prepare_command(&verified("/usr/bin/bwrap"), &jail, &cmd)?;
    // The host-side process: empty environment, argv of paths only.
    assert_eq!(prepared.launcher.get_envs().count(), 0);
    let argv = argv_of(&prepared.launcher);
    for secret in ["ghp_s3cret", "/evil.so", "GITHUB_TOKEN", "LD_PRELOAD"] {
        assert!(
            !argv.iter().any(|a| a.contains(secret)),
            "{secret} leaked into the launcher argv: {argv:?}"
        );
    }
    // The values travel in the private args file instead.
    let content = std::fs::read(prepared.args.path())?;
    let fields: Vec<&[u8]> = content.split(|b| *b == 0).collect();
    for (k, v) in [
        ("GITHUB_TOKEN", "ghp_s3cret"),
        ("LD_PRELOAD", "/evil.so"),
        ("A", "1"),
    ] {
        assert!(
            fields
                .windows(3)
                .any(|w| w[0] == b"--setenv" && w[1] == k.as_bytes() && w[2] == v.as_bytes()),
            "{k} missing from the args file"
        );
    }
    assert!(fields.iter().any(|f| *f == b"--clearenv"));
    // The command itself rides on the launcher's argv, after the file path.
    assert_eq!(&argv[argv.len() - 2..], ["node", "server.js"]);
    prepared.args.discard();
    Ok(())
}

#[test]
fn trust_requires_root_ownership_and_no_group_or_other_write() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let bin = dir.path().join("bwrap");
    std::fs::write(&bin, "#!/bin/sh\n")?;
    let is_root = std::fs::metadata(&bin)?.uid() == 0;
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
    assert_eq!(is_trusted_binary(&bin), is_root, "owner must be root");
    for mode in [0o775, 0o757, 0o777] {
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(mode))?;
        assert!(!is_trusted_binary(&bin), "{mode:o} is writable by others");
    }
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644))?;
    assert!(!is_trusted_binary(&bin), "must be executable");
    assert!(!is_trusted_binary(&dir.path().join("missing")));
    Ok(())
}

#[test]
fn a_passthrough_shim_does_not_pass_the_isolation_probe() {
    // The fake runs its arguments unconfined: the host-only file stays visible
    // and the pid namespace is the parent's, so the probe must reject it.
    assert!(!BubblewrapBackend::with_program(fake_bwrap()).is_available());
    for program in ["/nonexistent/bwrap", "/bin/false", "/bin/true"] {
        assert!(!BubblewrapBackend::with_program(program).is_available());
    }
}

#[test]
fn spawn_runs_the_wrapped_command_through_the_launcher() -> io::Result<()> {
    let backend = BubblewrapBackend::unverified(fake_bwrap(), true);
    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "t");
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("exit 7");
    assert_eq!(backend.spawn(&jail, cmd)?.wait()?.code(), Some(7));
    Ok(())
}

#[test]
fn spawn_captured_pipes_the_wrapper_and_delivers_env_through_the_args_file() -> io::Result<()> {
    let backend = BubblewrapBackend::unverified(fake_bwrap(), true);
    let root = tempfile::tempdir()?;
    let jail = Jail::new(root.path(), "t");
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("printf %s \"$A\"").env("A", "hi");
    let out = backend.spawn_captured(&jail, cmd)?.wait_with_output()?;
    // Delivered through `--setenv` in the args file, applied by the stand-in.
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hi");
    Ok(())
}

#[test]
fn spawn_with_a_missing_root_is_not_found() {
    let backend = BubblewrapBackend::unverified(fake_bwrap(), true);
    let kind = backend
        .spawn(&Jail::new("/nonexistent/root", "t"), Command::new("true"))
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::NotFound));
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn a_launcher_that_passes_the_probe_is_available_with_process_isolation_minimum() {
    let backend = BubblewrapBackend::with_program(fixture("fake-bwrap-probe.sh"));
    assert!(backend.is_available());
    assert_eq!(backend.isolation(), IsolationLevel::Process);
    assert_eq!(
        backend.program(),
        Some(fixture("fake-bwrap-probe.sh").as_path())
    );
}

#[test]
fn a_bwrap_without_disable_userns_is_available_but_claims_no_isolation() {
    let backend = BubblewrapBackend::with_program(fixture("fake-bwrap-old.sh"));
    assert!(backend.is_available());
    assert_eq!(backend.isolation(), IsolationLevel::None);
    assert!(!backend.is_suitable_for_untrusted_code());
}

#[test]
fn the_default_constructor_probes_only_trusted_paths() {
    let backend = BubblewrapBackend::new();
    if let Some(program) = backend.program() {
        assert!(TRUSTED_PATHS.iter().any(|p| Path::new(p) == program));
        assert!(is_trusted_binary(program));
    }
    assert_eq!(
        BubblewrapBackend::default().is_available(),
        backend.is_available()
    );
}
