//! Public resolver regressions for custom Rustup and Cargo homes.
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tinybox_bus::{LocalGrantConfig, ProtectedPaths};
use tinybox_jail::grants::resolve_local_jail_grants;

fn has(grants: &[PathBuf], path: &Path) -> bool {
    grants.iter().any(|grant| grant == path)
}

fn run_child(
    test_name: &str,
    rustup_home: &OsStr,
    cargo_home: &OsStr,
    fixture_home: &Path,
    expect_omitted: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env("TINYBOX_CUSTOM_HOME_CHILD", "1")
        .env("TINYBOX_FIXTURE_HOME", fixture_home)
        .env("RUSTUP_HOME", rustup_home)
        .env("CARGO_HOME", cargo_home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("TINYBOX_EXPECT_HOMES_OMITTED");
    if expect_omitted {
        command.env("TINYBOX_EXPECT_HOMES_OMITTED", "1");
    }
    let output = command.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "child test {test_name} failed: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("running 1 test"),
        "child did not execute exactly one test: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("test {test_name} ... ok")),
        "child test did not report success: {stdout}\n{stderr}"
    );
    Ok(())
}

fn assert_custom_homes_are_granted() -> Result<(), Box<dyn std::error::Error>> {
    let home =
        PathBuf::from(std::env::var_os("TINYBOX_FIXTURE_HOME").ok_or("missing fixture home")?);
    let rustup = PathBuf::from(std::env::var_os("RUSTUP_HOME").ok_or("missing RUSTUP_HOME")?);
    let cargo = PathBuf::from(std::env::var_os("CARGO_HOME").ok_or("missing CARGO_HOME")?);
    let grants = resolve_local_jail_grants(
        Some(&home),
        &LocalGrantConfig::default(),
        &ProtectedPaths::default(),
    )?;
    let rustup = rustup.canonicalize()?;
    assert!(
        has(&grants.read_only, &rustup),
        "custom Rustup home was not read-only: {grants:?}"
    );
    assert!(
        !has(&grants.read_write, &rustup),
        "custom Rustup home was writable: {grants:?}"
    );
    let cargo = cargo.canonicalize()?;
    for entry in ["bin", "config.toml", "env", "registry", "git"] {
        let selected = cargo.join(entry);
        if selected.exists() {
            assert!(
                has(&grants.read_only, &selected),
                "custom Cargo entry {entry} was not read-only: {grants:?}"
            );
        }
    }
    assert!(
        !has(&grants.read_only, &cargo),
        "whole custom Cargo root was granted: {grants:?}"
    );
    assert!(
        !has(&grants.read_write, &cargo),
        "custom Cargo root was writable: {grants:?}"
    );
    Ok(())
}

fn assert_custom_homes_are_omitted() -> Result<(), Box<dyn std::error::Error>> {
    let home =
        PathBuf::from(std::env::var_os("TINYBOX_FIXTURE_HOME").ok_or("missing fixture home")?);
    let rustup = PathBuf::from(std::env::var_os("RUSTUP_HOME").ok_or("missing RUSTUP_HOME")?);
    let cargo = PathBuf::from(std::env::var_os("CARGO_HOME").ok_or("missing CARGO_HOME")?);
    let grants = resolve_local_jail_grants(
        Some(&home),
        &LocalGrantConfig::default(),
        &ProtectedPaths::default(),
    )?;
    let grant_reaches = |grant: &Path, root: &Path| grant == root || grant.starts_with(root);
    assert!(
        !grants
            .read_only
            .iter()
            .chain(&grants.read_write)
            .any(|grant| grant_reaches(grant, &rustup)),
        "invalid or missing Rustup home was granted: {grants:?}"
    );
    assert!(
        !grants
            .read_only
            .iter()
            .chain(&grants.read_write)
            .any(|grant| grant_reaches(grant, &cargo)),
        "invalid or missing Cargo home root was granted: {grants:?}"
    );
    Ok(())
}

#[test]
fn custom_utf8_rust_homes_are_discovered_by_public_resolver()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("TINYBOX_CUSTOM_HOME_CHILD").is_some() {
        return assert_custom_homes_are_granted();
    }
    let fixture = tempfile::tempdir()?;
    let rustup = fixture.path().join("rustup-custom");
    let cargo = fixture.path().join("cargo-custom");
    fs::create_dir_all(&rustup)?;
    fs::create_dir_all(cargo.join("bin"))?;
    fs::create_dir_all(cargo.join("registry"))?;
    fs::create_dir_all(cargo.join("git"))?;
    fs::write(cargo.join("config.toml"), "[net]\noffline = true\n")?;
    fs::write(cargo.join("env"), "")?;
    run_child(
        "custom_utf8_rust_homes_are_discovered_by_public_resolver",
        rustup.as_os_str(),
        cargo.as_os_str(),
        fixture.path(),
        false,
    )
}

#[test]
#[cfg(unix)]
fn custom_non_utf8_rust_homes_are_discovered_by_public_resolver()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::OsStringExt;
    if std::env::var_os("TINYBOX_CUSTOM_HOME_CHILD").is_some() {
        if std::env::var_os("TINYBOX_EXPECT_HOMES_OMITTED").is_some() {
            return assert_custom_homes_are_omitted();
        }
        return assert_custom_homes_are_granted();
    }
    let fixture = tempfile::tempdir()?;
    let rustup = fixture
        .path()
        .join(std::ffi::OsString::from_vec(b"rustup-\xff".to_vec()));
    let cargo = fixture
        .path()
        .join(std::ffi::OsString::from_vec(b"cargo-\xfe".to_vec()));
    #[cfg(target_os = "macos")]
    {
        let Err(error) = fs::create_dir_all(&rustup) else {
            return Err("APFS accepted an invalid UTF-8 Rustup path".into());
        };
        assert_eq!(
            error.raw_os_error(),
            Some(92),
            "unexpected APFS error: {error}"
        );
        let Err(error) = fs::create_dir_all(cargo.join("bin")) else {
            return Err("APFS accepted an invalid UTF-8 Cargo path".into());
        };
        assert_eq!(
            error.raw_os_error(),
            Some(92),
            "unexpected APFS error: {error}"
        );
        run_child(
            "custom_non_utf8_rust_homes_are_discovered_by_public_resolver",
            rustup.as_os_str(),
            cargo.as_os_str(),
            fixture.path(),
            true,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        fs::create_dir_all(&rustup)?;
        fs::create_dir_all(cargo.join("bin"))?;
        fs::create_dir_all(cargo.join("registry"))?;
        fs::create_dir_all(cargo.join("git"))?;
        fs::write(cargo.join("config.toml"), "[net]\noffline = true\n")?;
        fs::write(cargo.join("env"), "")?;
        run_child(
            "custom_non_utf8_rust_homes_are_discovered_by_public_resolver",
            rustup.as_os_str(),
            cargo.as_os_str(),
            fixture.path(),
            false,
        )
    }
}

#[test]
fn missing_custom_rust_homes_are_omitted_by_public_resolver()
-> Result<(), Box<dyn std::error::Error>> {
    const TEST_NAME: &str = "missing_custom_rust_homes_are_omitted_by_public_resolver";
    if std::env::var_os("TINYBOX_CUSTOM_HOME_CHILD").is_some() {
        return assert_custom_homes_are_omitted();
    }
    let fixture = tempfile::tempdir()?;
    let rustup = fixture.path().join("missing-rustup");
    let cargo = fixture.path().join("missing-cargo");
    assert!(!rustup.exists());
    assert!(!cargo.exists());
    run_child(
        TEST_NAME,
        rustup.as_os_str(),
        cargo.as_os_str(),
        fixture.path(),
        true,
    )
}
