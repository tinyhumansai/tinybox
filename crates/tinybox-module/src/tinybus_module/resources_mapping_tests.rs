//! Tests for the pure mappings between bus requests and the core model.

use super::*;

#[test]
fn an_allowlist_policy_reaches_the_box_spec_host_for_host_and_port_for_port() -> Result<()> {
    let request = CreateRequest {
        resource: ResourceId("allowlist-test".into()),
        backend: "docker".into(),
        workspace: Workspace::Directory("/work".into()),
        network: tinybox_bus::NetworkPolicy::Allowlist(tinybox_bus::EgressAllowlist {
            hosts: vec!["example.com".into(), "192.0.2.7".into()],
            ports: vec![443, 8443],
        }),
        ..Default::default()
    };
    let spec = make_spec(&request, "local")?;
    assert_eq!(
        spec.network,
        tinybox_core::NetworkPolicy::Allowlist(tinybox_core::EgressAllowlist {
            hosts: vec!["example.com".into(), "192.0.2.7".into()],
            ports: vec![443, 8443],
        })
    );
    Ok(())
}

#[test]
fn file_errors_keep_their_stable_names() {
    let name = |error: &tinybox_core::Error| match file_error(error) {
        tinybus::Error::MethodFailed { name, .. } => Some(name),
        _ => None,
    };
    for (error, expected) in [
        (
            tinybox_core::Error::UnsupportedHostFileTransfer { host: "ssh".into() },
            tinybox_bus::FILE_UNSUPPORTED,
        ),
        (
            tinybox_core::Error::InvalidWorkspacePath,
            tinybox_bus::INVALID_FILE_PATH,
        ),
        (
            tinybox_core::Error::InvalidFileTransfer { reason: "offset" },
            tinybox_bus::INVALID_FILE_CHUNK,
        ),
        (
            tinybox_core::Error::io("read", &std::io::Error::other("disk")),
            tinybox_bus::FILE_ERROR,
        ),
    ] {
        assert_eq!(name(&error).as_deref(), Some(expected), "{error}");
    }
}

#[test]
fn agent37_executes_on_every_platform_and_other_backends_only_on_supported_ones() {
    for platform in [
        super::super::Platform::Linux,
        super::super::Platform::Unix,
        super::super::Platform::Windows,
        super::super::Platform::Other,
    ] {
        assert!(supports_execution(platform, "agent37"));
    }
    assert!(!supports_execution(super::super::Platform::Other, "docker"));
    assert!(supports_execution(super::super::Platform::Linux, "docker"));
    assert!(!supports_execution(
        super::super::Platform::Linux,
        "namespace"
    ));
}
