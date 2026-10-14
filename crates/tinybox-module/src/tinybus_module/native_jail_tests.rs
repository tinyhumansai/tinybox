//! Native grant and enforcement preflight uses local files and mock facts.
use super::*;

struct Backend {
    available: bool,
    suitable: bool,
    name: &'static str,
    full: bool,
}
impl JailBackend for Backend {
    fn name(&self) -> &'static str {
        self.name
    }
    fn is_available(&self) -> bool {
        self.available
    }
    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::None
    }
    fn is_suitable_for_untrusted_code(&self) -> bool {
        self.suitable
    }
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
        if self.full {
            ConstraintSupport::NONE
                .with(Constraint::Filesystem, Enforcement::Enforced)
                .with(Constraint::Network, Enforcement::Enforced)
                .with(Constraint::Subprocess, Enforcement::Enforced)
        } else {
            ConstraintSupport::NONE.with(Constraint::Filesystem, Enforcement::BestEffort)
        }
    }
    fn spawn(&self, _: &Jail, _: std::process::Command) -> std::io::Result<std::process::Child> {
        Err(std::io::Error::other("preflight fixture never spawns"))
    }
}
fn config() -> NativeJailConfig {
    NativeJailConfig {
        read_only: vec![],
        read_write: vec![],
        unix_paths: tinybox_bus::UnixPathGrants::default(),
        allow_net: false,
        allow_subprocess: false,
        enforcement: JailEnforcement::Enforced,
        require_process_isolation: false,
    }
}
#[test]
fn native_grants_reject_relative_parent_null_and_missing_paths() {
    assert!(grants(&["/".repeat(tinybox_bus::MAX_FILE_PATH_BYTES + 1)]).is_err());
    for path in [
        "relative",
        "/usr/../etc",
        "/bad\0path",
        "/tinybox-missing-test-grant",
    ] {
        assert!(grants(&[path.into()]).is_err());
    }
}

#[cfg(unix)]
#[test]
fn unix_grants_reject_malformed_and_missing_byte_paths() {
    for path in [
        vec![b'r', b'e', b'l'],
        vec![b'/', b'a', b'/', b'.', b'.', b'/', b'b'],
        vec![b'/', b'a', 0, b'b'],
        vec![b'/'; tinybox_bus::MAX_FILE_PATH_BYTES + 1],
        b"/tinybox-missing-byte-grant".to_vec(),
    ] {
        assert!(unix_grants(&[path]).is_err());
    }
}

#[cfg(unix)]
#[test]
fn opted_in_unix_grants_preserve_path_bytes_and_validate_canonical_targets()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let root = tempfile::tempdir()?;
    let directory = root.path().join("文件");
    std::fs::create_dir(&directory)?;
    let bytes = directory.as_os_str().as_bytes().to_vec();
    let decoded = unix_grants(std::slice::from_ref(&bytes))?;
    assert_eq!(decoded, vec![directory.canonicalize()?]);

    let invalid_path = root
        .path()
        .join(std::ffi::OsString::from_vec(vec![b'f', 0xff]));
    #[cfg(target_os = "macos")]
    {
        let Err(error) = std::fs::write(&invalid_path, b"data") else {
            return Err("APFS accepted an invalid UTF-8 filename".into());
        };
        assert_eq!(error.raw_os_error(), Some(92));
        let invalid_bytes = invalid_path.as_os_str().as_bytes().to_vec();
        assert!(unix_grants(std::slice::from_ref(&invalid_bytes)).is_err());
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::fs::write(&invalid_path, b"data")?;
        let invalid_bytes = invalid_path.as_os_str().as_bytes().to_vec();
        let decoded = unix_grants(std::slice::from_ref(&invalid_bytes))?;
        assert_eq!(decoded, vec![invalid_path.canonicalize()?]);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn native_jail_counts_utf8_and_byte_grants_together() {
    let mut config = config();
    config.read_only = vec!["/".into(); tinybox_bus::MAX_NATIVE_JAIL_GRANTS];
    config.unix_paths.read_write = vec![b"/".to_vec()];
    assert!(
        prepare(
            std::path::Path::new("/"),
            &config,
            &tinybox_core::ExecRequest::new(["irrelevant"]),
            &Backend {
                available: true,
                suitable: true,
                name: "fixture",
                full: true,
            },
        )
        .is_err()
    );
}

#[cfg(not(unix))]
#[test]
fn non_unix_platform_refuses_nonempty_byte_grants() {
    assert!(unix_grants(&[b"/tmp".to_vec()]).is_err());
}
#[test]
fn unavailable_and_noop_backends_never_accept_declared_enforcement()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let mut request = tinybox_core::ExecRequest::new(["irrelevant"]);
    request.cwd = Some(temp.path().into());
    for (available, name) in [(false, "fixture"), (true, tinybox_jail::NOOP_BACKEND_NAME)] {
        let backend = Backend {
            available,
            suitable: true,
            name,
            full: true,
        };
        let mut config = config();
        config.enforcement = JailEnforcement::Declared;
        assert!(prepare(temp.path(), &config, &request, &backend).is_err());
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn approved_grants_preserve_flags_and_preflight_refuses_weaker_facts()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::OsStrExt;
    let root = tempfile::tempdir()?;
    let extra = tempfile::tempdir()?;
    let file = root.path().join("file");
    std::fs::write(&file, b"data")?;
    let backend = Backend {
        available: true,
        suitable: false,
        name: "fixture",
        full: true,
    };
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let mut config = config();
    config.read_only.push(file.to_string_lossy().into_owned());
    config
        .read_write
        .push(extra.path().to_string_lossy().into_owned());
    let jail = prepare(root.path(), &config, &command, &backend)?;
    assert_eq!(jail.root, root.path().canonicalize()?);
    assert_eq!(jail.read_only, vec![file.canonicalize()?]);
    assert_eq!(jail.read_write, vec![extra.path().canonicalize()?]);
    let byte_file = root.path().join("字节");
    std::fs::write(&byte_file, b"bytes")?;
    config.unix_paths.read_only = vec![byte_file.as_os_str().as_bytes().to_vec()];
    let jail = prepare(root.path(), &config, &command, &backend)?;
    assert!(jail.read_only.contains(&byte_file.canonicalize()?));
    assert!(!jail.allow_net && !jail.allow_subprocess);
    config.require_process_isolation = true;
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    config.require_process_isolation = false;
    let weak = Backend {
        available: true,
        suitable: false,
        name: "fixture",
        full: false,
    };
    assert!(prepare(root.path(), &config, &command, &weak).is_err());
    config.enforcement = JailEnforcement::Declared;
    assert!(prepare(root.path(), &config, &command, &weak).is_err());
    config.allow_net = true;
    config.allow_subprocess = true;
    assert!(prepare(root.path(), &config, &command, &weak).is_ok());
    config.read_only = vec!["/".into(); tinybox_bus::MAX_NATIVE_JAIL_GRANTS + 1];
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    config.read_only.clear();
    command.cwd = Some(extra.path().into());
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    command.cwd = None;
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    assert!(prepare(&file, &config, &command, &backend).is_err());
    assert!(prepare(&root.path().join("missing"), &config, &command, &backend).is_err());
    command.cwd = Some(root.path().join("missing"));
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn declared_enforcement_rejects_each_unsupported_requested_constraint()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
    struct DeclaredBackend(ConstraintSupport);
    impl JailBackend for DeclaredBackend {
        fn name(&self) -> &'static str {
            "declared fixture"
        }
        fn is_available(&self) -> bool {
            true
        }
        fn isolation(&self) -> tinybox_core::IsolationLevel {
            tinybox_core::IsolationLevel::None
        }
        fn constraint_support(&self) -> ConstraintSupport {
            self.0
        }
        fn spawn(
            &self,
            _: &Jail,
            _: std::process::Command,
        ) -> std::io::Result<std::process::Child> {
            Err(std::io::Error::other("preflight fixture never spawns"))
        }
    }
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let mut config = config();
    config.enforcement = JailEnforcement::Declared;
    let constraints = [
        Constraint::Filesystem,
        Constraint::Network,
        Constraint::Subprocess,
    ];
    let supported = constraints
        .iter()
        .fold(ConstraintSupport::NONE, |support, &constraint| {
            support.with(constraint, Enforcement::BestEffort)
        });
    assert!(prepare(root.path(), &config, &command, &DeclaredBackend(supported)).is_ok());
    for constraint in constraints {
        let unsupported = supported.with(constraint, Enforcement::Unsupported);
        assert!(
            prepare(
                root.path(),
                &config,
                &command,
                &DeclaredBackend(unsupported)
            )
            .is_err(),
            "unsupported {constraint} must be rejected before execution"
        );
    }
    assert!(
        prepare(
            root.path(),
            &config,
            &command,
            &DeclaredBackend(ConstraintSupport::NONE)
        )
        .is_err()
    );
    Ok(())
}
