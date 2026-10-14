//! Compiled-module proof for custom Rust homes, grant transport, and local execution.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tinybus::{Connection, broker::Broker, module::ModuleHost, transport::memory::MemoryBus};

const TEST_NAME: &str = "compiled_module_discovers_and_runs_custom_rust_homes";
const CHILD_MODE: &str = "TINYBOX_RUST_HOMES_CHILD";
// Admission scans host toolchain trees; bound that I/O separately from shell calls.
const GRANT_SCAN_TIMEOUT: Duration = Duration::from_secs(180);

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_module_discovers_and_runs_custom_rust_homes() -> TestResult<()> {
    if let Some(mode) = std::env::var_os(CHILD_MODE) {
        return run_module_child(mode.to_str().ok_or("child mode is not UTF-8")?).await;
    }

    // This dynamic module build finishes before any child receives custom Cargo homes.
    let artifact = compiled_artifact()?;
    let utf8 = Fixture::new("utf8", None)?;
    run_child(&utf8, &artifact, "utf8", None)?;

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let bytes = Fixture::new("bytes", None)?;
        run_child(&bytes, &artifact, "bytes", None)?;
    }

    #[cfg(target_os = "macos")]
    {
        let mac_bytes = Fixture::new("mac-bytes", None)?;
        assert_macos_rejects_invalid_home_paths(&mac_bytes)?;
        run_child(&mac_bytes, &artifact, "mac-bytes", None)?;
    }

    #[cfg(target_os = "linux")]
    {
        let (rustup_home, rustup_proxy, toolchain) = installed_toolchain()?;
        let local_tools = Fixture::new("local-tools", Some(&rustup_home))?;
        local_tools.install_rustup_proxies(&rustup_proxy)?;
        run_child(&local_tools, &artifact, "local-tools", Some(&toolchain))?;

        let local_bytes = Fixture::new("local-bytes", None)?;
        run_child(&local_bytes, &artifact, "local-bytes", Some(&toolchain))?;
    }

    Ok(())
}

fn run_child(
    fixture: &Fixture,
    artifact: &Path,
    mode: &str,
    toolchain: Option<&str>,
) -> TestResult<()> {
    let mut child = Command::new(std::env::current_exe()?);
    child.args([TEST_NAME, "--nocapture"]).env_clear();

    for name in [
        "PATH",
        "LD_LIBRARY_PATH",
        "LLVM_PROFILE_FILE",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            child.env(name, value);
        }
    }

    child
        .env(CHILD_MODE, mode)
        .env("TINYBOX_E2E_ARTIFACT", artifact)
        .env("TINYBOX_E2E_HOME", &fixture.home)
        .env("TINYBOX_E2E_WORKSPACE", &fixture.workspace)
        .env("TINYBOX_E2E_STATE", &fixture.state)
        .env("TINYBOX_E2E_OUTSIDE", &fixture.outside_sentinel)
        .env("RUSTUP_HOME", &fixture.rustup_home)
        .env("CARGO_HOME", &fixture.cargo_home);
    if let Some(toolchain) = toolchain {
        child.env("TINYBOX_SELECTED_TOOLCHAIN", toolchain);
    }

    let output = child.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("running 1 test"),
        "child did not run exactly one matching test for {mode}: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("test {TEST_NAME} ... ok")),
        "child test result was absent for {mode}: {stdout}\n{stderr}"
    );
    assert!(
        output.status.success(),
        "compiled-module child failed for {mode}: {stdout}\n{stderr}"
    );
    Ok(())
}

struct Fixture {
    _root: tempfile::TempDir,
    rustup_home: PathBuf,
    cargo_home: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    state: PathBuf,
    outside_sentinel: PathBuf,
}

#[cfg(target_os = "macos")]
fn assert_macos_rejects_invalid_home_paths(fixture: &Fixture) -> TestResult<()> {
    for path in [&fixture.rustup_home, &fixture.cargo_home] {
        let Err(error) = fs::create_dir_all(path) else {
            return Err("macOS fixture unexpectedly created an invalid-byte home".into());
        };
        assert_eq!(
            error.raw_os_error(),
            Some(92),
            "unexpected macOS path error: {error}"
        );
    }
    Ok(())
}
impl Fixture {
    fn new(kind: &str, rustup_target: Option<&Path>) -> TestResult<Self> {
        let root = tempfile::tempdir()?;
        let (rustup_leaf, cargo_leaf) = match kind {
            "utf8" => (
                OsString::from("rustup-用户"),
                OsString::from("cargo-данные"),
            ),
            #[cfg(all(unix, not(target_os = "macos")))]
            "bytes" => (unix_name(b"rustup-\xff"), unix_name(b"cargo-\xfe")),
            #[cfg(target_os = "macos")]
            "mac-bytes" => (unix_name(b"rustup-\xff"), unix_name(b"cargo-\xfe")),
            #[cfg(unix)]
            "local-tools" => (OsString::from("rustup-работа"), unix_name(b"cargo-\xfc")),
            #[cfg(unix)]
            "local-bytes" => (unix_name(b"rustup-\xfd"), unix_name(b"cargo-\xfc")),
            _ => return Err("unknown Rust homes fixture".into()),
        };
        let rustup_home = root.path().join(rustup_leaf);
        let cargo_home = root.path().join(cargo_leaf);
        let create_homes = kind != "mac-bytes";
        if let Some(target) = rustup_target {
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &rustup_home)?;
            #[cfg(not(unix))]
            return Err("Rustup home symlink fixture requires Unix".into());
        } else if create_homes {
            fs::create_dir_all(&rustup_home)?;
            fs::write(rustup_home.join("settings.toml"), "version = 12\n")?;
            fs::create_dir_all(rustup_home.join("toolchains"))?;
        }
        if create_homes {
            fs::create_dir_all(cargo_home.join("bin"))?;
            fs::create_dir_all(cargo_home.join("registry"))?;
            fs::create_dir_all(cargo_home.join("git"))?;
            fs::write(cargo_home.join("config.toml"), "[net]\noffline = true\n")?;
            fs::write(cargo_home.join("env"), "TINYBOX_FIXTURE=1\n")?;
            fs::write(cargo_home.join("registry/cache-fixture"), "cache marker\n")?;
            fs::write(cargo_home.join("git/cache-fixture"), "git marker\n")?;
            fs::write(
                cargo_home.join("credentials.toml"),
                "credential fixture marker\n",
            )?;
        }

        let home = root.path().join("operator-home");
        let workspace = root.path().join("workspace");
        let state = root.path().join("state");
        let temp = root.path().join("temporary");
        fs::create_dir_all(&home)?;
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&state)?;
        fs::create_dir_all(temp)?;
        let outside_sentinel = root.path().join("outside-sentinel");
        fs::write(&outside_sentinel, "outside fixture marker\n")?;

        Ok(Self {
            _root: root,
            rustup_home,
            cargo_home,
            home,
            workspace,
            state,
            outside_sentinel,
        })
    }

    #[cfg(target_os = "linux")]
    fn install_rustup_proxies(&self, rustup: &Path) -> TestResult<()> {
        for name in ["rustup", "cargo", "rustc"] {
            fs::copy(rustup, self.cargo_home.join("bin").join(name))?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn unix_name(bytes: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(bytes.to_vec())
}

#[cfg(target_os = "linux")]
fn installed_toolchain() -> TestResult<(PathBuf, PathBuf, String)> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or("host home is unavailable before child environment seeding")?;
    let rustup_home =
        std::env::var_os("RUSTUP_HOME").map_or_else(|| home.join(".rustup"), PathBuf::from);
    if !rustup_home.join("settings.toml").is_file() || !rustup_home.join("toolchains").is_dir() {
        return Err("installed Rustup home or toolchains are unavailable".into());
    }

    let cargo_home =
        std::env::var_os("CARGO_HOME").map_or_else(|| home.join(".cargo"), PathBuf::from);
    let mut candidates = vec![cargo_home.join("bin/rustup")];
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|directory| directory.join("rustup")));
    }
    let rustup = candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or("installed Rustup multicall executable was not found")?
        .canonicalize()?;
    let status = Command::new(&rustup)
        .args(["show", "active-toolchain"])
        .output()?;
    if !status.status.success() {
        return Err(format!(
            "installed rustup could not identify the active toolchain: {}",
            String::from_utf8_lossy(&status.stderr)
        )
        .into());
    }
    let toolchain = String::from_utf8(status.stdout)?
        .split_whitespace()
        .next()
        .ok_or("installed rustup reported no active toolchain")?
        .to_owned();
    Ok((rustup_home.canonicalize()?, rustup, toolchain))
}

async fn wait_for_module_registration(client: &Connection) -> TestResult<()> {
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
    Ok(())
}
async fn run_module_child(mode: &str) -> TestResult<()> {
    let artifact = env_path("TINYBOX_E2E_ARTIFACT")?;
    let home = env_path("TINYBOX_E2E_HOME")?;
    let workspace = env_path("TINYBOX_E2E_WORKSPACE")?;
    let state = env_path("TINYBOX_E2E_STATE")?;
    #[cfg(target_os = "linux")]
    let outside = env_path("TINYBOX_E2E_OUTSIDE")?;
    let rustup_home = env_path("RUSTUP_HOME")?;
    let cargo_home = env_path("CARGO_HOME")?;

    // Stage the production artifact through the same admission path as the existing proof.
    let staged = tempfile::Builder::new()
        .prefix("rust-homes-module-")
        .tempdir_in(artifact.parent().ok_or("compiled artifact has no parent")?)?;
    #[cfg(windows)]
    secure_staging_directory(staged.path())?;
    let staged_artifact = staged.path().join(
        artifact
            .file_name()
            .ok_or("compiled artifact has no filename")?,
    );
    fs::copy(&artifact, &staged_artifact)?;

    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    let loaded = modules.load_file(&staged_artifact)?;
    let declared: Vec<_> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(declared, tinybox_bus::METHODS);

    let client = Connection::connect(bus.connect().await?).await?;
    wait_for_module_registration(&client).await?;
    let proxy = client.proxy(
        tinybox_bus::INTERFACE,
        tinybox_bus::OBJECT_PATH,
        tinybox_bus::INTERFACE,
    )?;

    let capabilities: tinybox_bus::ModuleCapabilities = proxy.call("Capabilities", ()).await?;
    assert_eq!(capabilities.contract_version, (1, 20));
    match mode {
        "utf8" => {
            let grants = resolve_grants(&proxy, &home, false).await?;
            assert_selected_entries(&grants, &rustup_home, &cargo_home)?;
            run_environment_shell(&proxy, &workspace, &state).await?;
        }
        #[cfg(target_os = "macos")]
        "mac-bytes" => {
            let grants = resolve_grants(&proxy, &home, true).await?;
            assert_macos_byte_homes_omitted(&grants, &rustup_home, &cargo_home)?;
            run_environment_shell(&proxy, &workspace, &state).await?;
        }
        "bytes" => {
            let grants = resolve_grants(&proxy, &home, true).await?;
            assert_selected_entries(&grants, &rustup_home, &cargo_home)?;
            let legacy = proxy
                .clone()
                .with_timeout(GRANT_SCAN_TIMEOUT)
                .call::<tinybox_bus::LocalGrants>(
                    "ResolveLocalGrants",
                    (grant_request(&home, false)?,),
                )
                .await;
            assert!(
                matches!(legacy, Err(tinybus::Error::MethodFailed { ref name, .. }) if name.as_str() == tinybox_bus::INVALID_FILE_PATH),
                "legacy grant request did not refuse non-UTF-8 paths: {legacy:?}"
            );
            run_environment_shell(&proxy, &workspace, &state).await?;
        }
        #[cfg(target_os = "linux")]
        "local-tools" | "local-bytes" => {
            let run_tools = mode == "local-tools";
            let grants = resolve_grants(&proxy, &home, true).await?;
            assert_selected_entries(&grants, &rustup_home, &cargo_home)?;
            run_environment_shell(&proxy, &workspace, &state).await?;
            let toolchain = std::env::var("TINYBOX_SELECTED_TOOLCHAIN")?;
            run_local_shell(
                &proxy, &workspace, &state, &outside, grants, &toolchain, run_tools,
            )
            .await?;
        }
        _ => return Err("unknown compiled-module fixture mode".into()),
    }

    proxy.call::<()>("Shutdown", ()).await?;
    broker_task.abort();
    Ok(())
}

fn env_path(name: &str) -> TestResult<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing fixture environment value {name}").into())
}

fn grant_request(
    home: &Path,
    allow_unix_paths: bool,
) -> TestResult<tinybox_bus::ResolveLocalGrantsRequest> {
    Ok(tinybox_bus::ResolveLocalGrantsRequest {
        home: Some(
            home.to_str()
                .ok_or("fixture home path is not UTF-8")?
                .into(),
        ),
        config: tinybox_bus::LocalGrantConfig {
            toolchain_homes: true,
            ..tinybox_bus::LocalGrantConfig::default()
        },
        protected: tinybox_bus::ProtectedPaths {
            components: vec!["credentials.toml".into()],
            ..tinybox_bus::ProtectedPaths::default()
        },
        allow_unix_paths,
    })
}

async fn resolve_grants(
    proxy: &tinybus::Proxy,
    home: &Path,
    allow_unix_paths: bool,
) -> TestResult<tinybox_bus::LocalGrants> {
    Ok(proxy
        .clone()
        .with_timeout(GRANT_SCAN_TIMEOUT)
        .call(
            "ResolveLocalGrants",
            (grant_request(home, allow_unix_paths)?,),
        )
        .await?)
}

#[cfg(target_os = "macos")]
fn assert_macos_byte_homes_omitted(
    grants: &tinybox_bus::LocalGrants,
    rustup_home: &Path,
    cargo_home: &Path,
) -> TestResult<()> {
    use std::os::unix::ffi::OsStrExt;

    for path in [rustup_home, cargo_home] {
        let Err(error) = fs::metadata(path) else {
            return Err("resolver created a macOS invalid-byte home".into());
        };
        assert_eq!(
            error.raw_os_error(),
            Some(2),
            "filesystem-rejected home should remain absent: {error}"
        );
        let root = path.as_os_str().as_bytes();
        let utf8_grant = grants
            .read_only
            .iter()
            .chain(&grants.read_write)
            .any(|entry| grant_path_is_root_or_descendant(entry.as_bytes(), root));
        let unix_grant = grants
            .unix_paths
            .read_only
            .iter()
            .chain(&grants.unix_paths.read_write)
            .any(|entry| grant_path_is_root_or_descendant(entry, root));
        assert!(
            !utf8_grant && !unix_grant,
            "filesystem-rejected missing home appeared in a grant group: {root:?}"
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn grant_path_is_root_or_descendant(candidate: &[u8], root: &[u8]) -> bool {
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}
fn assert_selected_entries(
    grants: &tinybox_bus::LocalGrants,
    rustup_home: &Path,
    cargo_home: &Path,
) -> TestResult<()> {
    assert_eq!(grants.read_write, Vec::<String>::new());
    assert_eq!(grants.unix_paths.read_write, Vec::<Vec<u8>>::new());

    assert!(
        grant_contains(grants, rustup_home)?,
        "custom Rustup home was not discovered: {}",
        rustup_home.display()
    );
    assert!(
        !grant_contains_rw(grants, rustup_home)?,
        "custom Rustup home was writable: {}",
        rustup_home.display()
    );

    for entry in ["bin", "config.toml", "env", "registry", "git"] {
        let path = cargo_home.join(entry);
        assert!(
            grant_contains(grants, &path)?,
            "selected Cargo entry {entry} was not read-only"
        );
        assert!(
            !grant_contains_rw(grants, &path)?,
            "selected Cargo entry {entry} was writable"
        );
    }

    let credentials = cargo_home.join("credentials.toml");
    assert!(
        !grant_contains(grants, cargo_home)?,
        "the whole Cargo home was granted"
    );
    assert!(
        !grant_contains(grants, &credentials)?,
        "Cargo credentials were granted"
    );
    Ok(())
}

fn grant_contains(grants: &tinybox_bus::LocalGrants, path: &Path) -> TestResult<bool> {
    let canonical = path.canonicalize()?;
    if canonical.to_str().is_some()
        && grants
            .read_only
            .iter()
            .any(|entry| Path::new(entry) == canonical)
    {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = canonical.as_os_str().as_bytes();
        Ok(grants
            .unix_paths
            .read_only
            .iter()
            .any(|entry| entry == bytes))
    }
    #[cfg(not(unix))]
    {
        Ok(false)
    }
}

fn grant_contains_rw(grants: &tinybox_bus::LocalGrants, path: &Path) -> TestResult<bool> {
    let canonical = path.canonicalize()?;
    if canonical.to_str().is_some()
        && grants
            .read_write
            .iter()
            .any(|entry| Path::new(entry) == canonical)
    {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = canonical.as_os_str().as_bytes();
        Ok(grants
            .unix_paths
            .read_write
            .iter()
            .any(|entry| entry == bytes))
    }
    #[cfg(not(unix))]
    {
        Ok(false)
    }
}

async fn run_environment_shell(
    proxy: &tinybus::Proxy,
    workspace: &Path,
    state: &Path,
) -> TestResult<()> {
    #[cfg(unix)]
    let command = r#"printf '%s\000%s' "$RUSTUP_HOME" "$CARGO_HOME""#;
    #[cfg(windows)]
    let command = "@chcp 65001 >NUL & @echo %RUSTUP_HOME%&@echo %CARGO_HOME%";
    let output = run_shell(
        proxy,
        workspace,
        state,
        command,
        None,
        std::collections::BTreeMap::new(),
    )
    .await?;

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let rustup = std::env::var_os("RUSTUP_HOME").ok_or("child RUSTUP_HOME is missing")?;
        let cargo = std::env::var_os("CARGO_HOME").ok_or("child CARGO_HOME is missing")?;
        let expected = [
            rustup.as_os_str().as_bytes(),
            b"\0",
            cargo.as_os_str().as_bytes(),
        ]
        .concat();
        assert_eq!(output, expected, "native shell changed Rust home bytes");
    }
    #[cfg(windows)]
    {
        let rustup = std::env::var_os("RUSTUP_HOME").ok_or("child RUSTUP_HOME is missing")?;
        let cargo = std::env::var_os("CARGO_HOME").ok_or("child CARGO_HOME is missing")?;
        let rustup = rustup
            .to_str()
            .ok_or("UTF-8 fixture RUSTUP_HOME changed encoding")?;
        let cargo = cargo
            .to_str()
            .ok_or("UTF-8 fixture CARGO_HOME changed encoding")?;
        let output = String::from_utf8(output)?;
        assert_eq!(output.lines().collect::<Vec<_>>(), [rustup, cargo]);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn assert_real_tool_versions(stdout: &str, run_tools: bool) {
    if run_tools {
        assert!(
            stdout.contains("cargo "),
            "cargo --version did not complete: {stdout}"
        );
        assert!(
            stdout.contains("rustc "),
            "rustc --version did not complete: {stdout}"
        );
    }
}
#[cfg(target_os = "linux")]
async fn run_local_shell(
    proxy: &tinybus::Proxy,
    workspace: &Path,
    state: &Path,
    outside: &Path,
    grants: tinybox_bus::LocalGrants,
    toolchain: &str,
    run_tools: bool,
) -> TestResult<()> {
    let status: tinybox_bus::JailStatus = proxy.call("JailStatus", ()).await?;
    assert!(
        status.available && status.filesystem == "enforced",
        "Linux Local proof requires the default backend's enforced filesystem: {status:?}"
    );
    let mut read_only = grants.read_only.clone();
    read_only.extend(
        ["/usr", "/bin", "/lib", "/lib64", "/dev"]
            .into_iter()
            .filter(|path| Path::new(path).exists())
            .map(str::to_owned),
    );
    let jail = tinybox_bus::NativeJailConfig {
        read_only,
        read_write: grants.read_write.clone(),
        unix_paths: grants.unix_paths.clone(),
        allow_net: true,
        allow_subprocess: true,
        enforcement: tinybox_bus::JailEnforcement::Enforced,
        require_process_isolation: false,
    };
    let extra_env = [
        (
            "OUTSIDE_SENTINEL".to_owned(),
            outside
                .to_str()
                .ok_or("outside fixture is not UTF-8")?
                .to_owned(),
        ),
        ("RUSTUP_TOOLCHAIN".to_owned(), toolchain.to_owned()),
        (
            "TINYBOX_RUN_REAL_TOOLS".to_owned(),
            if run_tools { "1" } else { "0" }.to_owned(),
        ),
    ]
    .into_iter()
    .collect();

    let command = r#"set -u
cat "$RUSTUP_HOME/settings.toml" >/dev/null || exit 30
cat "$CARGO_HOME/config.toml" >/dev/null || exit 31
cat "$CARGO_HOME/env" >/dev/null || exit 32
cat "$CARGO_HOME/registry/cache-fixture" >/dev/null || exit 33
cat "$CARGO_HOME/git/cache-fixture" >/dev/null || exit 34
if [ "$TINYBOX_RUN_REAL_TOOLS" = "1" ]; then
    export PATH="$CARGO_HOME/bin:${PATH:-}"
    cargo --version || exit 35
    rustc --version || exit 36
fi
if printf denied > "$RUSTUP_HOME/.tinybox-write-probe" 2>/dev/null; then exit 41; fi
if printf denied > "$CARGO_HOME/config.toml" 2>/dev/null; then exit 42; fi
if printf denied > "$CARGO_HOME/registry/write-probe" 2>/dev/null; then exit 43; fi
if printf denied > "$CARGO_HOME/git/write-probe" 2>/dev/null; then exit 44; fi
if cat "$CARGO_HOME/credentials.toml" >/dev/null 2>&1; then exit 45; fi
if cat "$OUTSIDE_SENTINEL" >/dev/null 2>&1; then exit 46; fi
printf workspace-write > rust-homes-workspace-check
printf rust-homes-local-ok"#;
    let output = run_shell(proxy, workspace, state, command, Some(jail), extra_env).await?;
    let stdout = String::from_utf8(output)?;
    assert_real_tool_versions(&stdout, run_tools);
    assert!(
        stdout.ends_with("rust-homes-local-ok"),
        "Local toolchain checks did not reach their final boundary marker: {stdout}"
    );
    assert_eq!(
        fs::read(workspace.join("rust-homes-workspace-check"))?,
        b"workspace-write"
    );
    assert!(
        !PathBuf::from(std::env::var_os("RUSTUP_HOME").ok_or("missing RUSTUP_HOME")?)
            .join(".tinybox-write-probe")
            .exists()
    );
    assert!(
        !PathBuf::from(std::env::var_os("CARGO_HOME").ok_or("missing CARGO_HOME")?)
            .join("registry/write-probe")
            .exists()
    );
    assert!(
        !PathBuf::from(std::env::var_os("CARGO_HOME").ok_or("missing CARGO_HOME")?)
            .join("git/write-probe")
            .exists()
    );
    Ok(())
}

async fn run_shell(
    proxy: &tinybus::Proxy,
    workspace: &Path,
    state: &Path,
    command: &str,
    jail: Option<tinybox_bus::NativeJailConfig>,
    extra_env: std::collections::BTreeMap<String, String>,
) -> TestResult<Vec<u8>> {
    let workspace_text = workspace.to_str().ok_or("workspace path is not UTF-8")?;
    let resource: tinybox_bus::ResourceId = proxy
        .call("Reserve", (tinybox_bus::ReserveRequest::Resource,))
        .await?;
    let _: tinybox_bus::ResourceInfo = proxy
        .call(
            "Create",
            (tinybox_bus::CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: tinybox_bus::Workspace::Directory(workspace_text.into()),
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
    let request = tinybox_bus::ShellExecRequest {
        process,
        resource: resource.clone(),
        shell: tinybox_bus::SelectShellRequest {
            command: command.into(),
            preserve_pipeline_status: false,
            runtime_path: None,
            python_utf8: false,
        },
        cwd: Some(workspace_text.into()),
        extra_env,
        state_dir: state.to_str().ok_or("state directory is not UTF-8")?.into(),
        timeout_ms: 90_000,
        stdin: None,
        jail,
        hide_window: false,
    };
    let running: tinybox_bus::ProcessRef = proxy.call("StartNativeShellExec", (request,)).await?;
    let batch = tokio::time::timeout(Duration::from_secs(100), async {
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
    let stderr: Vec<_> = batch
        .chunks
        .iter()
        .filter(|chunk| chunk.stream == tinybox_bus::OutputStream::Stderr)
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect();
    assert_eq!(
        batch.state,
        tinybox_bus::ExecutionState::Exited { exit_code: 0 },
        "native shell exited with stderr:\n{}",
        String::from_utf8_lossy(&stderr)
    );
    let output = batch
        .chunks
        .iter()
        .filter(|chunk| chunk.stream == tinybox_bus::OutputStream::Stdout)
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect();
    proxy.call::<()>("ReleaseOutput", (running,)).await?;
    proxy.call::<()>("Close", (resource,)).await?;
    Ok(output)
}

fn compiled_artifact() -> TestResult<PathBuf> {
    let filename = format!(
        "{}tinybox{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/module-dynamic-proof");
    let status = Command::new(env!("CARGO"))
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
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target)
        .status()?;
    assert!(
        status.success(),
        "dynamic TinyBox module build failed before child env seeding: {status}"
    );
    Ok(target.join("debug").join(filename))
}
#[cfg(windows)]
fn secure_staging_directory(path: &Path) -> TestResult<()> {
    let identity = Command::new("powershell")
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
    let acl = Command::new("icacls")
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
