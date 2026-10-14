//! Unconditional compiled-artifact admission and local grant discovery proof.

use std::time::Duration;
use tinybus::{Connection, broker::Broker, module::ModuleHost, transport::memory::MemoryBus};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_manifest_admits_and_executes_grant_and_shell_discovery()
-> Result<(), Box<dyn std::error::Error>> {
    let built_artifact = compiled_artifact()?;
    // Cargo output inherits the checkout ACL on Windows, which need not meet
    // production module admission. Stage the real artifact with private ACLs.
    let staged = tempfile::Builder::new()
        .prefix("admitted-module-")
        .tempdir_in(built_artifact.parent().ok_or("artifact has no directory")?)?;
    #[cfg(windows)]
    secure_staging_directory(staged.path())?;
    let artifact = staged.path().join(
        built_artifact
            .file_name()
            .ok_or("artifact has no filename")?,
    );
    std::fs::copy(&built_artifact, &artifact)?;
    assert!(
        artifact.is_file(),
        "compiled TinyBox artifact missing: {}",
        artifact.display()
    );
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    let loaded = modules.load_file(&artifact)?;
    let declared: Vec<_> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(declared, tinybox_bus::METHODS);
    let client = Connection::connect(bus.connect().await?).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client
                .list_names()
                .await?
                .iter()
                .any(|name| name.as_str() == tinybox_bus::INTERFACE)
            {
                return Ok::<(), tinybus::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let proxy = client.proxy(
        tinybox_bus::INTERFACE,
        tinybox_bus::OBJECT_PATH,
        tinybox_bus::INTERFACE,
    )?;
    verify_discovery(&proxy).await?;
    verify_native_shell(&proxy).await?;
    proxy.call::<()>("Shutdown", ()).await?;
    broker_task.abort();
    Ok(())
}

async fn verify_discovery(proxy: &tinybus::Proxy) -> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    std::fs::create_dir(home.path().join("data"))?;
    let result: tinybox_bus::LocalGrants = proxy
        .call(
            "ResolveLocalGrants",
            (tinybox_bus::ResolveLocalGrantsRequest {
                home: Some(home.path().to_str().ok_or("home is not UTF-8")?.into()),
                config: tinybox_bus::LocalGrantConfig {
                    toolchain_homes: false,
                    extra_read_only: vec!["~/data".into()],
                    ..tinybox_bus::LocalGrantConfig::default()
                },
                protected: tinybox_bus::ProtectedPaths::default(),
                allow_unix_paths: false,
            },),
        )
        .await?;
    assert_eq!(
        result.read_only,
        vec![
            home.path()
                .join("data")
                .canonicalize()?
                .to_str()
                .ok_or("grant is not UTF-8")?
        ]
    );
    assert_eq!(result.read_write, Vec::<String>::new());
    let selection: tinybox_bus::ShellInvocation = proxy
        .call(
            "SelectShell",
            (tinybox_bus::SelectShellRequest {
                command: "false | true".into(),
                preserve_pipeline_status: false,
                runtime_path: None,
                python_utf8: false,
            },),
        )
        .await?;
    if cfg!(windows) {
        assert_eq!(selection.flavor, tinybox_bus::ShellFlavor::Cmd);
        let system_root = std::env::var_os("SystemRoot").map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        );
        assert_eq!(
            std::path::Path::new(&selection.program),
            system_root.join("System32").join("cmd.exe")
        );
        assert_eq!(selection.arguments, ["/D", "/E:ON", "/V:OFF", "/S", "/C"]);
        assert_eq!(selection.raw_arguments.as_deref(), Some("\"false | true\""));
    } else {
        assert_eq!(selection.flavor, tinybox_bus::ShellFlavor::Posix);
        assert!(selection.arguments.iter().any(|argument| argument == "-c"));
        if selection.program.ends_with("bash") {
            assert_eq!(selection.arguments[0], "-p");
        }
        assert_eq!(selection.raw_arguments, None);
        assert_eq!(
            selection.remove_environment,
            [
                "BASH_ENV",
                "ENV",
                "SHELLOPTS",
                "BASHOPTS",
                "POSIXLY_CORRECT"
            ]
        );
    }
    for include in ["~other/shared.conf", "%(prefix)/shared.conf"] {
        std::fs::write(
            home.path().join(".gitconfig"),
            format!("[include]\npath = {include}\n"),
        )?;
        let result = proxy
            .call::<tinybox_bus::LocalGrants>(
                "ResolveLocalGrants",
                (tinybox_bus::ResolveLocalGrantsRequest {
                    home: Some(home.path().to_str().ok_or("home is not UTF-8")?.into()),
                    config: tinybox_bus::LocalGrantConfig::default(),
                    protected: tinybox_bus::ProtectedPaths::default(),
                    allow_unix_paths: false,
                },),
            )
            .await;
        assert!(
            matches!(result, Err(tinybus::Error::MethodFailed { ref name, .. }) if name.as_str() == tinybox_bus::UNSUPPORTED_OPERATION),
            "{include}: {result:?}"
        );
    }
    Ok(())
}

async fn verify_native_shell(proxy: &tinybus::Proxy) -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let resource: tinybox_bus::ResourceId = proxy
        .call("Reserve", (tinybox_bus::ReserveRequest::Resource,))
        .await?;
    let _: tinybox_bus::ResourceInfo = proxy
        .call(
            "Create",
            (tinybox_bus::CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: tinybox_bus::Workspace::Directory(
                    workspace.path().to_str().ok_or("non-UTF8 fixture")?.into(),
                ),
                ..Default::default()
            },),
        )
        .await?;
    let process: tinybox_bus::ResourceId = proxy
        .call(
            "Reserve",
            (tinybox_bus::ReserveRequest::Process(resource.clone()),),
        )
        .await?;
    #[cfg(windows)]
    let payload = {
        let executable = workspace.path().join("quoted fixture tool.exe");
        std::fs::copy(std::env::current_exe()?, &executable)?;
        format!(
            "\"{}\" \"--list\" > \"{}\" & echo native-fixture",
            executable.display(),
            workspace.path().join("output (fixture).txt").display()
        )
    };
    #[cfg(not(windows))]
    let payload = "printf fixture > 'output (fixture).txt'; echo native-fixture";
    let running: tinybox_bus::ProcessRef = proxy
        .call(
            "StartNativeShellExec",
            (serde_json::json!({
                "process":process, "resource":resource,
                "shell":{"command":payload},
                "state_dir":state_dir.path().to_str().ok_or("non-UTF8 fixture")?,
                "timeout_ms":5000
            }),),
        )
        .await?;
    let batch = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let batch: tinybox_bus::OutputBatch =
                proxy.call("ReadOutput", (running.clone(), 0_u64)).await?;
            if batch.state != tinybox_bus::ExecutionState::Running {
                return Ok::<_, tinybus::Error>(batch);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(
        batch.state,
        tinybox_bus::ExecutionState::Exited { exit_code: 0 }
    );
    let stdout: Vec<u8> = batch
        .chunks
        .into_iter()
        .filter(|chunk| chunk.stream == tinybox_bus::OutputStream::Stdout)
        .flat_map(|chunk| chunk.bytes)
        .collect();
    let stdout = String::from_utf8(stdout)?;
    assert!(stdout.trim().ends_with("native-fixture"));
    let redirected = std::fs::read_to_string(workspace.path().join("output (fixture).txt"))?;
    #[cfg(windows)]
    assert!(redirected.contains("compiled_manifest_admits_and_executes_grant_and_shell_discovery"));
    #[cfg(not(windows))]
    assert_eq!(redirected, "fixture");
    proxy.call::<()>("ReleaseOutput", (running,)).await?;
    proxy.call::<()>("Close", (resource,)).await?;
    Ok(())
}

fn compiled_artifact() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let filename = format!(
        "{}tinybox{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    // All-feature/static-link builds omit the dynamic ABI. Build a dynamic
    // variant under this checkout: other PRs share ordinary Cargo artifacts
    // and must not replace the module between its build and admission.
    let target =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/module-dynamic-proof");
    let status = std::process::Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--offline",
            "-p",
            "tinybox-module",
            "--no-default-features",
            "--lib",
        ])
        .arg("--manifest-path")
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target)
        .status()?;
    assert!(
        status.success(),
        "default-feature dynamic artifact build failed: {status}"
    );
    Ok(target.join("debug").join(filename))
}

#[cfg(windows)]
fn secure_staging_directory(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let identity = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output()?;
    assert!(
        identity.status.success(),
        "current-user SID query failed: {identity:?}"
    );
    let sid = String::from_utf8(identity.stdout)?;
    let grant = format!("*{}:(OI)(CI)F", sid.trim());
    let acl = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(grant)
        .output()?;
    assert!(
        acl.status.success(),
        "private module staging ACL failed: {acl:?}"
    );
    Ok(())
}
