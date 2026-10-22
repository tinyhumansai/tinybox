//! The stdio vocabulary is serialized independently of implementation types.
use super::*;
use crate::NativeJailConfig;

fn jail() -> NativeJailConfig {
    NativeJailConfig {
        read_only: Vec::new(),
        read_write: Vec::new(),
        unix_paths: crate::UnixPathGrants::default(),
        allow_net: false,
        allow_subprocess: false,
        enforcement: crate::JailEnforcement::Enforced,
        require_process_isolation: true,
        deny_read: Vec::new(),
        resources: None,
    }
}

#[test]
fn stdio_members_are_appended_after_the_1_20_catalogue() -> Result<(), &'static str> {
    use crate::{CONTRACT_VERSION, METHODS, names};
    assert!(CONTRACT_VERSION >= (1, 21));
    let start = METHODS
        .iter()
        .position(|name| *name == names::START_STDIO)
        .ok_or("StartStdio is not advertised")?;
    assert_eq!(
        &METHODS[start..start + 6],
        [
            "StartStdio",
            "WriteStdio",
            "ReadStdio",
            "CloseStdin",
            "KillStdio",
            "StdioStatus"
        ]
    );
    Ok(())
}

#[test]
fn start_request_requires_a_jail_and_defaults_cwd_and_env() -> Result<(), serde_json::Error> {
    let without_jail = serde_json::json!({
        "process": "p", "resource": "r", "argv": ["server"],
    });
    assert!(serde_json::from_value::<StdioStartRequest>(without_jail).is_err());
    let request: StdioStartRequest = serde_json::from_value(serde_json::json!({
        "process": "p", "resource": "r", "argv": ["server"],
        "jail": serde_json::to_value(jail())?,
    }))?;
    assert_eq!(request.cwd, None);
    assert!(request.env.is_empty());
    assert_eq!(
        serde_json::from_value::<StdioStartRequest>(serde_json::to_value(&request)?)?,
        request
    );
    Ok(())
}

#[test]
fn debug_output_redacts_environment_values_and_payload_bytes() {
    let mut env = std::collections::BTreeMap::new();
    env.insert("API_KEY".to_owned(), "hunter2-secret".to_owned());
    let request = StdioStartRequest {
        process: ResourceId("p".into()),
        resource: ResourceId("r".into()),
        argv: vec!["server".into(), "--token=also-secret".into()],
        cwd: None,
        env,
        jail: jail(),
    };
    let text = format!("{request:?}");
    assert!(text.contains("API_KEY"));
    assert!(!text.contains("hunter2-secret"));
    assert!(!text.contains("also-secret"));
    let write = StdioWriteRequest {
        process: ProcessRef {
            resource: ResourceId("r".into()),
            process: ResourceId("p".into()),
        },
        data: b"private payload".to_vec(),
    };
    assert!(!format!("{write:?}").contains("private"));
    let chunk = StdioChunk {
        stdout: b"private out".to_vec(),
        stderr: b"private err".to_vec(),
        stdout_closed: false,
        stderr_closed: false,
        status: StdioStatus {
            running: true,
            exit: None,
        },
    };
    assert!(!format!("{chunk:?}").contains("private"));
}

#[test]
fn exit_and_status_round_trip_with_stable_names() -> Result<(), serde_json::Error> {
    assert_eq!(
        serde_json::to_value(StdioExit::Code(3))?,
        serde_json::json!({"code": 3})
    );
    assert_eq!(
        serde_json::to_value(StdioExit::Signal(9))?,
        serde_json::json!({"signal": 9})
    );
    let status: StdioStatus = serde_json::from_value(serde_json::json!({"running": true}))?;
    assert_eq!(status.exit, None);
    Ok(())
}
