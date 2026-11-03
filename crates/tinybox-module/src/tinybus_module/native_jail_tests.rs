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
    fn is_suitable_for_untrusted_jail(&self, _: &Jail) -> bool {
        self.suitable
    }
    fn carves_denials(&self) -> bool {
        self.name == "seatbelt"
    }
    fn validate_carved_denials(&self, jail: &Jail) -> std::io::Result<()> {
        if self.carves_denials() {
            tinybox_jail::SeatbeltBackend::new().validate_carved_denials(jail)
        } else {
            Ok(())
        }
    }
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
        if self.full {
            ConstraintSupport::NONE
                .with(Constraint::Filesystem, Enforcement::Enforced)
                .with(Constraint::Network, Enforcement::Enforced)
                .with(Constraint::Subprocess, Enforcement::Enforced)
                .with(Constraint::Cpu, Enforcement::BestEffort)
                .with(Constraint::Memory, Enforcement::BestEffort)
                .with(Constraint::Pids, Enforcement::BestEffort)
                .with(Constraint::Disk, Enforcement::BestEffort)
        } else {
            ConstraintSupport::NONE.with(Constraint::Filesystem, Enforcement::BestEffort)
        }
    }
    fn spawn(&self, _: &Jail, _: std::process::Command) -> std::io::Result<std::process::Child> {
        Err(std::io::Error::other("preflight fixture never spawns"))
    }
}

struct BaselineBackend(Backend, std::path::PathBuf);
impl JailBackend for BaselineBackend {
    fn name(&self) -> &'static str {
        self.0.name
    }
    fn is_available(&self) -> bool {
        self.0.available
    }
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        self.0.constraint_support()
    }
    fn implicit_grants(&self) -> Vec<std::path::PathBuf> {
        vec![self.1.clone()]
    }
    fn spawn(
        &self,
        jail: &Jail,
        cmd: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        self.0.spawn(jail, cmd)
    }
}

fn config() -> NativeJailConfig {
    NativeJailConfig {
        read_only: vec![],
        read_write: vec![],
        allow_net: false,
        allow_subprocess: false,
        enforcement: JailEnforcement::Enforced,
        require_process_isolation: false,
        deny_read: Vec::new(),
        resources: None,
    }
}

#[cfg(target_os = "linux")]
fn native_resource_runtime_available() -> bool {
    use std::os::unix::fs::FileTypeExt;
    use std::process::Command;

    let manager_socket = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .and_then(|address| address.strip_prefix("unix:path=").map(str::to_owned))
        .is_some_and(|path| {
            std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
        });
    let scope = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--property=CPUQuota=100%",
            "--property=MemoryMax=67108864",
            "--property=MemorySwapMax=0",
            "--property=TasksMax=16",
            "--",
            "/bin/true",
        ])
        .status()
        .is_ok_and(|status| status.success());
    let namespaces = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--",
            "/usr/bin/true",
        ])
        .status()
        .is_ok_and(|status| status.success());
    let available = manager_socket && scope && namespaces;
    if std::env::var_os("TINYBOX_REQUIRE_NATIVE_RESOURCE_TESTS").is_some() {
        assert!(
            available,
            "required native resource test environment is unavailable: manager={manager_socket}, systemd-scope={scope}, namespaces={namespaces}"
        );
    }
    available
}

#[cfg(target_os = "linux")]
fn pid_namespace_contains_process(pid: i32, namespace_inode: u64) -> std::io::Result<bool> {
    for entry in std::fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let Ok(namespaces) = std::fs::read_link(entry.path().join("ns/pid")) else {
            continue;
        };
        let same_pid = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))
            .and_then(|pids| pids.split_whitespace().last())
            .and_then(|pid| pid.parse::<i32>().ok())
            == Some(pid);
        let same_namespace = namespaces
            .to_string_lossy()
            .strip_prefix("pid:[")
            .and_then(|inode| inode.strip_suffix(']'))
            .and_then(|inode| inode.parse::<u64>().ok())
            == Some(namespace_inode);
        if same_pid && same_namespace {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(unix)]
#[test]
fn requested_native_resource_limits_are_refused_before_spawn()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let backend = Backend {
        available: true,
        suitable: false,
        name: "fixture",
        full: true,
    };
    let mut config = config();
    config.enforcement = JailEnforcement::Declared;
    config.resources = Some(tinybox_bus::ResourceLimits {
        cpu_millis: 500,
        memory_bytes: 1024 * 1024,
        pids_max: 32,
        disk_bytes: 1024 * 1024,
    });
    // Declared enforcement accepts best-effort filesystem constraints, but a
    // resource budget remains a hard requirement and must refuse before spawn.
    assert!(prepare(root.path(), &config, &command, &backend).is_err());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[test]
fn contract_21_resource_requests_refuse_before_spawn_on_non_linux()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["target-program"]);
    command.cwd = Some(root.path().into());
    let original = command.clone();
    let request = NativeJailRequest {
        jail: config(),
        resources: Some(tinybox_bus::NativeJailResourceRequest {
            cpu_millis: Some(1000),
            memory_bytes: None,
            pids_max: None,
            disk_bytes: None,
        }),
    };

    let error = collector_with_resources(root.path(), &request, &mut command)
        .err()
        .ok_or("non-Linux resource requests must refuse before target launch")?;
    assert_eq!(error.wire_name(), tinybox_bus::UNSUPPORTED_OPERATION);
    assert_eq!(command.argv, original.argv);
    assert_eq!(command.cwd, original.cwd);
    assert_eq!(command.env, original.env);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn resource_backend_consumes_one_validated_launcher_plan()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let backend = super::NativeResourceBackend::new();
    assert_eq!(backend.isolation(), tinybox_core::IsolationLevel::Kernel);
    let jail = tinybox_jail::Jail::new(std::env::temp_dir(), "resource-plan-test");
    assert!(backend.spawn(&jail, Command::new("true")).is_err());

    let backend = super::NativeResourceBackend::new();
    let request = tinybox_bus::NativeJailResourceRequest {
        cpu_millis: Some(1000),
        memory_bytes: None,
        pids_max: None,
        disk_bytes: None,
    };
    backend.bind_resources(request)?;
    assert!(backend.bind_resources(request).is_err());
    backend.bind(&["/bin/true".into()])?;
    assert!(backend.bind(&["/bin/false".into()]).is_err());
    let command = Command::new("/bin/false");
    assert!(backend.spawn(&jail, command).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_resource_limits_still_fail_closed_on_linux()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let backend = tinybox_jail::LandlockBackend::new();
    if !backend.is_available() {
        return Ok(());
    }

    // Contract 1.22's all-dimensions request remains hard and unsupported by
    // the Landlock-only path. The new 2.1 subset request uses a separate API.
    let mut config = config();
    config.resources = Some(tinybox_bus::ResourceLimits {
        cpu_millis: 100,
        memory_bytes: 64 * 1024 * 1024,
        pids_max: 16,
        disk_bytes: 1024,
    });

    assert!(
        prepare(root.path(), &config, &command, &backend).is_err(),
        "legacy Linux native jail must refuse the unsupported all-resource request"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn resource_aware_namespace_jail_preserves_grants_and_blocks_manager_escape()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    if !native_resource_runtime_available() {
        eprintln!("skipped: rootless systemd scope and bubblewrap namespaces are unavailable");
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let fixture = native_escape_fixture(root.path())?;

    let probe = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--property=CPUQuota=0.1%",
            "--property=MemoryMax=67108864",
            "--property=MemorySwapMax=0",
            "--property=TasksMax=16",
            "--",
            "/bin/true",
        ])
        .status()?;
    if !probe.success() {
        eprintln!("skipped: user systemd scope constraints are unavailable");
        return Ok(());
    }

    let (request, mut command) = resource_escape_command(
        &fixture.workspace,
        &fixture.denied_inside,
        &fixture.bash_env,
        &fixture.manager_alias,
        fixture.inherited_fd,
        fixture.inherited_inode,
        &fixture.outside,
    );
    let backend = resource_backend();
    let jail = prepare_with_resources(
        root.path().join("workspace").as_path(),
        &request,
        &mut command,
        backend.as_ref(),
    )?;
    let mut child_command = Command::new(command.argv.first().ok_or("missing launcher")?);
    child_command
        .args(command.argv.iter().skip(1))
        .env_clear()
        .envs(&command.env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = tinybox_jail::spawn_captured_with(backend.as_ref(), &jail, child_command)?;
    let mut ready = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.as_mut().ok_or("missing stdout pipe")?),
        &mut ready,
    )?;
    if ready != "READY\n" {
        let output = child.wait_with_output()?;
        return Err(format!(
            "launcher did not complete resource probes: status {:?}, stdout {}, stderr {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    assert_resource_cgroup(&command.argv, &mut child)?;
    child
        .stdin
        .as_mut()
        .ok_or("missing stdin pipe")?
        .write_all(b"continue\n")?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "launcher failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(fixture.workspace.join("control"))?,
        b"allowed"
    );
    assert_eq!(
        std::fs::read(fixture.workspace.join("from-bash-env"))?,
        b"startup"
    );
    assert!(
        !fixture.outside.exists(),
        "jail wrote outside its granted roots"
    );
    let _ = std::fs::remove_file(fixture.outside);
    Ok(())
}

#[cfg(target_os = "linux")]
struct NativeEscapeFixture {
    workspace: std::path::PathBuf,
    denied_inside: std::path::PathBuf,
    manager_alias: std::path::PathBuf,
    outside: std::path::PathBuf,
    bash_env: std::path::PathBuf,
    _inherited_manager: std::os::unix::net::UnixStream,
    inherited_fd: i32,
    inherited_inode: u64,
}

#[cfg(target_os = "linux")]
fn native_escape_fixture(
    root: &std::path::Path,
) -> std::result::Result<NativeEscapeFixture, Box<dyn std::error::Error>> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
        unix::net::UnixStream,
    };

    let workspace = root.join("workspace");
    std::fs::create_dir_all(workspace.join("hidden"))?;
    std::fs::write(workspace.join("hidden/secret"), "secret")?;
    let denied_inside = workspace.join("denied-inside");
    std::fs::create_dir_all(&denied_inside)?;
    std::fs::write(denied_inside.join("secret"), "secret")?;
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")?;
    let socket = address
        .strip_prefix("unix:path=")
        .ok_or("filesystem DBus manager socket is required for this escape test")?;
    let socket = std::path::PathBuf::from(socket);
    assert!(socket.metadata()?.file_type().is_socket());
    let inherited_manager = UnixStream::connect(&socket)?;
    let inherited_fd = inherited_manager.as_raw_fd();
    let flags = nix::fcntl::fcntl(&inherited_manager, nix::fcntl::FcntlArg::F_GETFD)?;
    assert_ne!(flags & nix::libc::FD_CLOEXEC, 0);
    nix::fcntl::fcntl(
        &inherited_manager,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )?;
    let inherited_inode = std::fs::metadata(format!("/proc/self/fd/{inherited_fd}"))?.ino();
    let manager_alias = workspace.join("manager-socket-alias");
    std::os::unix::fs::symlink(socket, &manager_alias)?;
    let outside = std::env::temp_dir().join(format!("tinybox-escape-proof-{}", std::process::id()));
    let _ = std::fs::remove_file(&outside);
    let bash_env = workspace.join("startup.sh");
    std::fs::write(
        &bash_env,
        format!(
            "printf startup > {}\n",
            shell_quote(&workspace.join("from-bash-env").display().to_string())
        ),
    )?;
    Ok(NativeEscapeFixture {
        workspace,
        denied_inside,
        manager_alias,
        outside,
        bash_env,
        _inherited_manager: inherited_manager,
        inherited_fd,
        inherited_inode,
    })
}

#[cfg(target_os = "linux")]
fn resource_escape_command(
    workspace: &std::path::Path,
    denied_inside: &std::path::Path,
    bash_env: &std::path::Path,
    manager_alias: &std::path::Path,
    inherited_fd: i32,
    inherited_inode: u64,
    outside: &std::path::Path,
) -> (tinybox_bus::NativeJailRequest, tinybox_core::ExecRequest) {
    let mut jail = config();
    jail.allow_net = false;
    jail.allow_subprocess = true;
    jail.require_process_isolation = true;
    jail.deny_read = vec![denied_inside.display().to_string()];
    let request = tinybox_bus::NativeJailRequest {
        jail,
        resources: Some(tinybox_bus::NativeJailResourceRequest {
            cpu_millis: Some(1000),
            memory_bytes: Some(64 * 1024 * 1024),
            pids_max: Some(16),
            disk_bytes: None,
        }),
    };
    let script = format!(
        "printf allowed > {}; test ! -e {} || exit 41; test ! -r {} || exit 42; python3 -c 'data=bytearray(8388608); data[0]=1' || exit 45; python3 -c {} || exit 44; python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX)\ntry: s.connect(sys.argv[1])\nexcept OSError: sys.exit(0)\nsys.exit(1)' {} || exit 46; python3 -c 'import os,sys; fd=int(os.environ[\"TINYBOX_MANAGER_FD\"]); expected=int(os.environ[\"TINYBOX_MANAGER_INODE\"])\ntry: actual=os.stat(f\"/proc/self/fd/{{fd}}\").st_ino\nexcept OSError: sys.exit(0)\nsys.exit(1 if actual==expected else 0)' || exit 47; if systemd-run --user --scope --quiet -- /usr/bin/touch {} 2>/dev/null; then exit 43; fi; printf 'READY\\n'; read -r _; exit 0",
        shell_quote(&workspace.join("control").display().to_string()),
        shell_quote(&denied_inside.join("secret").display().to_string()),
        shell_quote(&denied_inside.join("secret").display().to_string()),
        shell_quote(
            "import errno,os,signal\nchildren=[]\nblocked=False\ntry:\n for _ in range(64):\n  pid=os.fork()\n  if pid==0:\n   while True: os.pause()\n  children.append(pid)\nexcept OSError as e:\n blocked=e.errno==errno.EAGAIN\nfor pid in children: os.kill(pid,signal.SIGKILL)\nfor pid in children: os.waitpid(pid,0)\nassert blocked\n"
        ),
        shell_quote(&manager_alias.display().to_string()),
        shell_quote(&outside.display().to_string()),
    );
    let mut command = tinybox_core::ExecRequest::new(["/bin/bash", "-c", &script]);
    command.cwd = Some(workspace.into());
    command
        .env
        .insert("BASH_ENV".into(), bash_env.display().to_string());
    command
        .env
        .insert("TINYBOX_MANAGER_FD".into(), inherited_fd.to_string());
    command
        .env
        .insert("TINYBOX_MANAGER_INODE".into(), inherited_inode.to_string());
    (request, command)
}

#[cfg(target_os = "linux")]
fn assert_resource_cgroup(
    argv: &[String],
    child: &mut std::process::Child,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let unit = argv
        .iter()
        .find_map(|part| part.strip_prefix("--unit="))
        .ok_or("launcher has no unique transient-scope unit")?;
    let control_group = std::process::Command::new("systemctl")
        .args(["--user", "show", "--property=ControlGroup", "--value", unit])
        .output()?;
    assert!(
        control_group.status.success(),
        "cannot inspect transient scope"
    );
    let control_group = String::from_utf8(control_group.stdout)?;
    let cgroup =
        std::path::Path::new("/sys/fs/cgroup").join(control_group.trim_start_matches('/').trim());
    assert_eq!(
        std::fs::read_to_string(cgroup.join("memory.max"))?.trim(),
        "67108864"
    );
    assert_eq!(
        std::fs::read_to_string(cgroup.join("memory.swap.max"))?.trim(),
        "0"
    );
    assert_eq!(
        std::fs::read_to_string(cgroup.join("pids.max"))?.trim(),
        "16"
    );
    let pids_events = std::fs::read_to_string(cgroup.join("pids.events"))?;
    let max_events: u64 = pids_events
        .lines()
        .find_map(|line| line.strip_prefix("max "))
        .ok_or("missing pids max event counter")?
        .parse()?;
    assert!(max_events > 0, "fork fixture never hit the pids limit");
    let cpu_max = std::fs::read_to_string(cgroup.join("cpu.max"))?;
    let mut cpu_max = cpu_max.split_whitespace();
    let quota: u64 = cpu_max.next().ok_or("missing CPU quota")?.parse()?;
    let period: u64 = cpu_max.next().ok_or("missing CPU period")?.parse()?;
    assert!(
        quota > 0 && quota <= period,
        "CPU quota exceeded request: {quota}/{period}"
    );
    let _ = child.try_wait()?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn native_memory_limit_kills_a_workload_that_touches_past_its_budget()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    if !native_resource_runtime_available() {
        eprintln!("skipped: rootless systemd scope and bubblewrap namespaces are unavailable");
        return Ok(());
    }
    if !Command::new("python3").arg("--version").status()?.success() {
        eprintln!("skipped: python3 is unavailable for the memory pressure fixture");
        return Ok(());
    }
    let probe = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--property=MemoryMax=67108864",
            "--property=MemorySwapMax=0",
            "--property=CPUQuota=100%",
            "--property=TasksMax=16",
            "--",
            "/bin/true",
        ])
        .status()?;
    if !probe.success() {
        eprintln!("skipped: user systemd scope constraints are unavailable");
        return Ok(());
    }

    let root = tempfile::tempdir()?;
    let mut jail_config = config();
    jail_config.allow_subprocess = true;
    jail_config.require_process_isolation = true;
    let request = tinybox_bus::NativeJailRequest {
        jail: jail_config,
        resources: Some(tinybox_bus::NativeJailResourceRequest {
            cpu_millis: Some(1000),
            memory_bytes: Some(64 * 1024 * 1024),
            pids_max: Some(16),
            disk_bytes: None,
        }),
    };
    let script = format!(
        "python3 -c {}; status=$?; printf '%s' \"$status\" > {}; printf 'READY\\n'; read -r _; exit 0",
        shell_quote(
            "data=bytearray(256*1024*1024)\nfor i in range(0,len(data),4096): data[i]=1\nprint('allocation survived')"
        ),
        shell_quote(&root.path().join("python-status").display().to_string())
    );
    let mut command = tinybox_core::ExecRequest::new(["/bin/bash", "-c", &script]);
    command.cwd = Some(root.path().into());
    let backend = resource_backend();
    let jail = prepare_with_resources(root.path(), &request, &mut command, backend.as_ref())?;
    let mut launcher = Command::new(command.argv.first().ok_or("missing launcher")?);
    launcher
        .args(command.argv.iter().skip(1))
        .env_clear()
        .envs(&command.env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = tinybox_jail::spawn_captured_with(backend.as_ref(), &jail, launcher)?;
    let mut ready = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.as_mut().ok_or("missing stdout pipe")?),
        &mut ready,
    )?;
    assert_eq!(ready, "READY\n", "memory pressure workload did not finish");
    let cgroup = active_scope_cgroup(&command.argv, &mut child)?;
    let memory_events = std::fs::read_to_string(cgroup.join("memory.events")).map_err(|error| {
        std::io::Error::other(format!(
            "cannot read {}: {error}",
            cgroup.join("memory.events").display()
        ))
    })?;
    let oom_kills: u64 = memory_events
        .lines()
        .find_map(|line| line.strip_prefix("oom_kill "))
        .ok_or("missing memory OOM counter")?
        .parse()?;
    assert!(oom_kills > 0, "memory overrun did not increment oom_kill");
    assert_eq!(
        std::fs::read_to_string(root.path().join("python-status"))?,
        "137"
    );
    child
        .stdin
        .as_mut()
        .ok_or("missing stdin pipe")?
        .write_all(b"continue\n")?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success() || output.status.code() == Some(137),
        "OOM should terminate the workload with success or SIGKILL status, got {:?}",
        output.status
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn active_scope_cgroup(
    argv: &[String],
    child: &mut std::process::Child,
) -> std::io::Result<std::path::PathBuf> {
    let unit = argv
        .iter()
        .find_map(|part| part.strip_prefix("--unit="))
        .ok_or_else(|| std::io::Error::other("launcher has no transient scope unit"))?;
    let control_group = std::process::Command::new("systemctl")
        .args(["--user", "show", "--property=ControlGroup", "--value", unit])
        .output()?;
    assert!(control_group.status.success());
    let control_group = String::from_utf8(control_group.stdout)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    assert!(
        !control_group.trim().is_empty(),
        "scope {unit} has no cgroup path; systemd-run status is {:?}",
        child.try_wait()?
    );
    Ok(std::path::Path::new("/sys/fs/cgroup").join(control_group.trim_start_matches('/').trim()))
}

#[cfg(target_os = "linux")]
#[test]
fn fractional_cpu_limit_throttles_the_live_native_scope()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::{
        io::BufRead,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    if !native_resource_runtime_available() {
        eprintln!("skipped: rootless systemd scope and bubblewrap namespaces are unavailable");
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let release = root.path().join("release-cpu-loop");
    let script = format!(
        "printf 'READY\\n'; while [ ! -e {} ]; do :; done; printf 'DONE\\n'",
        shell_quote(&release.display().to_string())
    );
    let mut config = config();
    config.allow_subprocess = true;
    config.require_process_isolation = true;
    let request = tinybox_bus::NativeJailRequest {
        jail: config,
        resources: Some(tinybox_bus::NativeJailResourceRequest {
            cpu_millis: Some(1),
            memory_bytes: Some(64 * 1024 * 1024),
            pids_max: Some(16),
            disk_bytes: None,
        }),
    };
    let mut command = tinybox_core::ExecRequest::new(["/bin/bash", "-c", &script]);
    command.cwd = Some(root.path().into());
    let backend = resource_backend();
    let jail = prepare_with_resources(root.path(), &request, &mut command, backend.as_ref())?;
    let mut launcher = Command::new(command.argv.first().ok_or("missing launcher")?);
    launcher
        .args(command.argv.iter().skip(1))
        .env_clear()
        .envs(&command.env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = tinybox_jail::spawn_captured_with(backend.as_ref(), &jail, launcher)?;
    let mut ready = String::new();
    BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.as_mut().ok_or("missing stdout pipe")?),
        &mut ready,
    )?;
    assert_eq!(ready, "READY\n");
    let unit = command
        .argv
        .iter()
        .find_map(|part| part.strip_prefix("--unit="))
        .ok_or("launcher has no transient scope unit")?;
    let control_group = Command::new("systemctl")
        .args(["--user", "show", "--property=ControlGroup", "--value", unit])
        .output()?;
    assert!(control_group.status.success());
    let cgroup = std::path::Path::new("/sys/fs/cgroup").join(
        String::from_utf8(control_group.stdout)?
            .trim_start_matches('/')
            .trim(),
    );
    let cpu_max = std::fs::read_to_string(cgroup.join("cpu.max"))?;
    let mut cpu_max = cpu_max.split_whitespace();
    let quota: u64 = cpu_max.next().ok_or("missing CPU quota")?.parse()?;
    let period: u64 = cpu_max.next().ok_or("missing CPU period")?.parse()?;
    assert!(
        quota > 0 && quota * 1000 <= period,
        "CPU ratio exceeds 1 milli-CPU: {quota}/{period}"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let throttled = loop {
        let stats = std::fs::read_to_string(cgroup.join("cpu.stat"))?;
        let count: u64 = stats
            .lines()
            .find_map(|line| line.strip_prefix("nr_throttled "))
            .ok_or("missing CPU throttle counter")?
            .parse()?;
        if count > 0 {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        throttled,
        "CPU-bound workload was never throttled by cpu.max"
    );
    std::fs::write(&release, b"release")?;
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("DONE"));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn native_scope_exit_kills_double_forked_setsid_descendants()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    if !native_resource_runtime_available() {
        eprintln!("skipped: rootless systemd scope and bubblewrap namespaces are unavailable");
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let pid_file = root.path().join("detached.pid");
    let python = format!(
        "import os,time\nfirst=os.fork()\nif first == 0:\n os.setsid()\n second=os.fork()\n if second == 0:\n  with open({},'w') as pidfile: pidfile.write(f'{{os.getpid()}} {{os.stat(\"/proc/self/ns/pid\").st_ino}}')\n  while True: time.sleep(1)\n os._exit(0)\nos.waitpid(first,0)\nwhile not os.path.exists({}) or os.path.getsize({}) == 0: time.sleep(0.01)\npid=int(open({}).read().split()[0])\nos.kill(pid,0)",
        shell_quote(&pid_file.display().to_string()),
        shell_quote(&pid_file.display().to_string()),
        shell_quote(&pid_file.display().to_string()),
        shell_quote(&pid_file.display().to_string())
    );
    let script = format!(
        "python3 -c {}; status=$?; printf 'READY\\n'; read -r _; exit \"$status\"",
        shell_quote(&python)
    );
    let mut config = config();
    config.allow_subprocess = true;
    config.require_process_isolation = true;
    let request = tinybox_bus::NativeJailRequest {
        jail: config,
        resources: Some(tinybox_bus::NativeJailResourceRequest {
            cpu_millis: Some(1000),
            memory_bytes: Some(64 * 1024 * 1024),
            pids_max: Some(16),
            disk_bytes: None,
        }),
    };
    let mut command = tinybox_core::ExecRequest::new(["/bin/bash", "-c", &script]);
    command.cwd = Some(root.path().into());
    let backend = resource_backend();
    let jail = prepare_with_resources(root.path(), &request, &mut command, backend.as_ref())?;
    let mut launcher = Command::new(command.argv.first().ok_or("missing launcher")?);
    launcher
        .args(command.argv.iter().skip(1))
        .env_clear()
        .envs(&command.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = tinybox_jail::spawn_captured_with(backend.as_ref(), &jail, launcher)?;
    let mut ready = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.as_mut().ok_or("missing stdout pipe")?),
        &mut ready,
    )?;
    assert_eq!(ready, "READY\n");
    let identity = std::fs::read_to_string(&pid_file)?;
    let mut identity = identity.split_whitespace();
    let detached: i32 = identity.next().ok_or("missing detached PID")?.parse()?;
    let pid_namespace: u64 = identity
        .next()
        .ok_or("missing PID namespace inode")?
        .parse()?;
    assert!(
        pid_namespace_contains_process(detached, pid_namespace)?,
        "fixture did not expose its detached process in the host proc view"
    );
    child
        .stdin
        .as_mut()
        .ok_or("missing release pipe")?
        .write_all(b"continue\n")?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "jail supervisor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let still_alive = pid_namespace_contains_process(detached, pid_namespace)?;
        if !still_alive {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!("detached descendant {detached} survived scope exit").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn native_cancellation_kills_detached_descendants_and_preserves_stream_events()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::{process::Command, time::Duration};

    if !native_resource_runtime_available() {
        eprintln!("skipped: rootless systemd scope and bubblewrap namespaces are unavailable");
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let pid_file = root.path().join("cancelled-descendant");
    let python = format!(
        "import os,time,sys\nfirst=os.fork()\nif first == 0:\n os.setsid()\n second=os.fork()\n if second == 0:\n  with open({},'w') as f: f.write(f'{{os.getpid()}} {{os.stat(\"/proc/self/ns/pid\").st_ino}}')\n  while True: time.sleep(1)\n os._exit(0)\nos.waitpid(first,0)\nwhile not os.path.exists({}) or os.path.getsize({}) == 0: time.sleep(0.01)\nprint('stdout-ready',flush=True)\nprint('stderr-ready',file=sys.stderr,flush=True)\ntime.sleep(600)",
        shell_quote(&pid_file.display().to_string()),
        shell_quote(&pid_file.display().to_string()),
        shell_quote(&pid_file.display().to_string())
    );
    let mut jail_config = config();
    jail_config.allow_subprocess = true;
    jail_config.require_process_isolation = true;
    let request = tinybox_bus::NativeJailRequest {
        jail: jail_config,
        resources: Some(tinybox_bus::NativeJailResourceRequest {
            cpu_millis: Some(1000),
            memory_bytes: Some(64 * 1024 * 1024),
            pids_max: Some(16),
            disk_bytes: None,
        }),
    };
    let mut exec = tinybox_core::ExecRequest::new(["python3", "-c", &python]);
    exec.cwd = Some(root.path().into());
    let backend = resource_backend();
    let jail = prepare_with_resources(root.path(), &request, &mut exec, backend.as_ref())?;
    for key in ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"] {
        if let Ok(value) = std::env::var(key) {
            exec.env.insert(key.to_owned(), value);
        }
    }
    let approved_env = exec.env.clone();
    let host = Arc::new(tinybox_host::JailLocalHost::with_backend(
        jail,
        backend,
        tinybox_bus::MAX_OUTPUT_BYTES,
    )?);
    let mut command = Command::new(exec.argv.first().ok_or("missing target")?);
    command
        .args(exec.argv.iter().skip(1))
        .env_clear()
        .envs(&approved_env);
    let journal = Arc::new(super::super::output::OutputJournal::default());
    let runner = host.clone();
    let observer = journal.clone();
    let task = tokio::spawn(async move {
        runner
            .run_command_observed_with_env(command, None, observer, approved_env)
            .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        let output = journal.read(0)?;
        let stream_contains = |stream, marker: &[u8]| {
            let bytes: Vec<_> = output
                .chunks
                .iter()
                .filter(|chunk| chunk.stream == stream)
                .flat_map(|chunk| chunk.bytes.iter().copied())
                .collect();
            bytes.windows(marker.len()).any(|window| window == marker)
        };
        let stdout = stream_contains(tinybox_bus::OutputStream::Stdout, b"stdout-ready");
        let stderr = stream_contains(tinybox_bus::OutputStream::Stderr, b"stderr-ready");
        if stdout && stderr && pid_file.metadata().is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        ready,
        "native exec did not deliver both output streams and descendant identity: {:?}",
        journal.read(0)?.chunks
    );
    let identity = std::fs::read_to_string(&pid_file)?;
    let mut identity = identity.split_whitespace();
    let detached: i32 = identity.next().ok_or("missing detached PID")?.parse()?;
    let pid_namespace: u64 = identity.next().ok_or("missing PID namespace")?.parse()?;
    assert!(
        pid_namespace_contains_process(detached, pid_namespace)?,
        "fixture did not expose its detached process in the host proc view"
    );
    journal.cancel();
    assert!(
        task.await?.is_err(),
        "cancelled native command unexpectedly succeeded"
    );
    assert!(
        !host.has_pending_cleanup(),
        "cancel did not acknowledge child cleanup"
    );

    assert_process_disappears(detached, pid_namespace, "cancelled descendant")
}

#[cfg(target_os = "linux")]
fn assert_process_disappears(
    pid: i32,
    namespace_inode: u64,
    description: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if !pid_namespace_contains_process(pid, namespace_inode)? {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("{description} {pid} survived cleanup").into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
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

// `prepare` refuses every native jail off Unix before reading any path.
#[cfg(unix)]
#[test]
fn denials_preserve_prospective_roots_and_refuse_unenforceable_overlaps()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let root = home.path().join("project");
    let secrets = home.path().join(".ssh");
    let token = home.path().join(".netrc");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&secrets)?;
    std::fs::write(&token, b"secret")?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let backend = |name| Backend {
        available: true,
        suitable: false,
        name,
        full: true,
    };
    let path = |p: &std::path::Path| p.to_string_lossy().into_owned();
    let mut config = config();
    config.deny_read = vec![
        path(&secrets),
        path(&token),
        path(&home.path().join(".aws")),
    ];
    let canonical_home = home.path().canonicalize()?;
    let mut expected = vec![
        secrets.clone(),
        token.clone(),
        home.path().join(".aws"),
        canonical_home.join(".ssh"),
        canonical_home.join(".netrc"),
        canonical_home.join(".aws"),
    ];
    expected.sort();
    expected.dedup();

    // Outside every grant: retain absent roots so a later-created credential
    // store remains denied by the backend.
    for name in ["fixture", "seatbelt"] {
        let jail = prepare(&root, &config, &command, &backend(name))?;
        assert_eq!(jail.deny_read, expected);
    }

    // Inside a read grant: only a backend that subtracts from grants keeps it.
    config.read_only = vec![path(home.path())];
    assert!(prepare(&root, &config, &command, &backend("fixture")).is_err());
    let jail = prepare(&root, &config, &command, &backend("seatbelt"))?;
    assert_eq!(jail.deny_read, expected);
    config.deny_read = vec![path(&home.path().join(".future-credential-store"))];
    assert!(prepare(&root, &config, &command, &backend("fixture")).is_err());
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_ok());
    config.read_only.clear();
    config.deny_read = vec![path(&root.join(".future-credential-store"))];
    assert!(prepare(&root, &config, &command, &backend("fixture")).is_err());
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_ok());

    // A denial over the root or a writable grant is refused everywhere.
    for denied in [path(home.path()), path(&root)] {
        config.deny_read = vec![denied];
        assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    }
    config.deny_read = vec![path(&secrets)];
    config.read_write = vec![path(&secrets)];
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    config.read_write.clear();

    // Seatbelt's final deny rule can carve a nested path out of a writable
    // grant, but it cannot preserve the grant if the denial contains it.
    config.read_write = vec![path(home.path())];
    config.deny_read = vec![path(&secrets)];
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_ok());
    config.deny_read = vec![path(home.path())];
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    config.read_write.clear();

    // Deeper than a direct child, a rename of the directory in between moves
    // the denied path out from under a path-based rule: refuse it.
    let nested = root.join("a").join("secret");
    config.deny_read = vec![path(&nested)];
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    config.read_write = vec![path(home.path())];
    config.deny_read = vec![path(&home.path().join("a").join("secret"))];
    assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    config.read_write.clear();

    // Malformed denials are refused like malformed grants.
    for bad in ["relative", "/usr/../etc", "/bad\0path"] {
        config.deny_read = vec![bad.into()];
        assert!(prepare(&root, &config, &command, &backend("seatbelt")).is_err());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn allow_list_backend_rejects_denials_over_implicit_baseline_grants()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("workspace");
    let baseline = temp.path().join("implicit-read-root");
    let alias = temp.path().join("implicit-read-alias");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&baseline)?;
    std::os::unix::fs::symlink(&baseline, &alias)?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let mut config = config();
    config.deny_read = vec![
        baseline
            .join("future-credential")
            .to_string_lossy()
            .into_owned(),
    ];

    let backend = BaselineBackend(
        Backend {
            available: true,
            suitable: false,
            name: "allow-list",
            full: true,
        },
        alias,
    );

    assert!(prepare(&root, &config, &command, &backend).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn allow_list_preflight_keeps_future_implicit_grants_protected()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("workspace");
    let future_baseline = temp.path().join("baseline-created-before-spawn");
    std::fs::create_dir(&root)?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let mut config = config();
    config.deny_read = vec![
        future_baseline
            .join("future-credential")
            .to_string_lossy()
            .into_owned(),
    ];
    let backend = BaselineBackend(
        Backend {
            available: true,
            suitable: false,
            name: "allow-list",
            full: true,
        },
        future_baseline,
    );

    assert!(prepare(&root, &config, &command, &backend).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn prospective_denials_resolve_existing_aliases_and_refuse_dangling_symlinks()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir()?;
    let link = dir.path().join("credential-link");
    symlink(dir.path().join("future-target"), &link)?;
    assert!(denials(&[link.to_string_lossy().into_owned()]).is_err());

    let target = dir.path().join("real-home");
    std::fs::create_dir(&target)?;
    let alias = dir.path().join("home-alias");
    symlink(&target, &alias)?;
    let prospective = alias.join(".ssh");
    let roots = denials(&[prospective.to_string_lossy().into_owned()])?;
    let mut expected = vec![prospective.clone(), target.canonicalize()?.join(".ssh")];
    expected.sort();
    expected.dedup();
    assert!(roots.contains(&prospective));
    assert_eq!(roots, expected);

    let first_loop = dir.path().join("loop-a");
    let second_loop = dir.path().join("loop-b");
    symlink(&second_loop, &first_loop)?;
    symlink(&first_loop, &second_loop)?;
    assert!(denials(&[first_loop.to_string_lossy().into_owned()]).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn collector_builds_a_host_from_a_valid_native_jail()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().to_path_buf());

    let backend: Arc<dyn JailBackend> = Arc::new(Backend {
        available: true,
        suitable: true,
        name: "fixture",
        full: true,
    });
    let _collector = collector(root.path(), &config(), &command, backend)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn spawn_rejects_a_prospective_denial_symlinked_into_the_jail()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;
    let home = tempfile::tempdir()?;
    let root = home.path().join("project");
    std::fs::create_dir(&root)?;
    let credential = root.join("credential");
    std::fs::write(&credential, b"secret")?;
    let prospective = home.path().join(".credential-store");
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let backend = Backend {
        available: true,
        suitable: false,
        name: "fixture",
        full: true,
    };
    let mut native = config();
    native.allow_net = true;
    native.allow_subprocess = true;
    native.deny_read = vec![path_string(&prospective)];
    let jail = prepare(&root, &native, &command, &backend)?;

    symlink(&credential, &prospective)?;
    let error =
        tinybox_jail::spawn_captured_with(&backend, &jail, std::process::Command::new("true"))
            .err();
    assert_eq!(
        error.map(|error| error.kind()),
        Some(std::io::ErrorKind::InvalidInput)
    );
    Ok(())
}

fn path_string(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(target_os = "linux")]
#[test]
fn landlock_keeps_a_denied_path_unreadable_when_created_after_preflight()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let backend = tinybox_jail::LandlockBackend::new();
    if !backend.is_available() {
        eprintln!("skipped: Landlock is not supported by this kernel");
        return Ok(());
    }
    let home = tempfile::tempdir()?;
    let root = home.path().join("project");
    std::fs::create_dir(&root)?;
    let credential = home.path().join(".future-store").join("token");
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.clone());
    let mut native = config();
    native.allow_net = true;
    native.allow_subprocess = true;
    native.deny_read = vec![
        home.path()
            .join(".future-store")
            .to_string_lossy()
            .into_owned(),
    ];
    let mut uncarvable_root_child = native.clone();
    uncarvable_root_child.deny_read =
        vec![root.join(".future-store").to_string_lossy().into_owned()];
    assert!(prepare(&root, &uncarvable_root_child, &command, &backend).is_err());
    let jail = prepare(&root, &native, &command, &backend)?;
    assert!(jail.deny_read.contains(&home.path().join(".future-store")));

    std::fs::create_dir(home.path().join(".future-store"))?;
    std::fs::write(&credential, "secret")?;
    let allowed = root.join("allowed.txt");
    std::fs::write(&allowed, "allowed-read-control\n")?;
    let output = tinybox_jail::spawn_captured_with(&backend, &jail, {
        let mut shell = std::process::Command::new("/bin/sh");
        shell.arg("-c").arg(format!(
            "cat '{}' && cat '{}' >/dev/null",
            allowed.display(),
            credential.display()
        ));
        shell
    })?
    .wait_with_output()?;
    assert_eq!(output.stdout, b"allowed-read-control\n");
    assert!(!output.status.success());
    Ok(())
}

/// Isolation that depends on the configuration, as the bubblewrap backend's does.
struct NetworkSensitiveBackend;
impl JailBackend for NetworkSensitiveBackend {
    fn name(&self) -> &'static str {
        "network-sensitive"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::Process
    }
    fn isolation_for(&self, jail: &Jail) -> tinybox_core::IsolationLevel {
        if jail.allow_net {
            tinybox_core::IsolationLevel::Process
        } else {
            tinybox_core::IsolationLevel::Kernel
        }
    }
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
        ConstraintSupport::NONE
            .with(Constraint::Filesystem, Enforcement::Enforced)
            .with(Constraint::Network, Enforcement::Enforced)
    }
    fn spawn(&self, _: &Jail, _: std::process::Command) -> std::io::Result<std::process::Child> {
        Err(std::io::Error::other("preflight fixture never spawns"))
    }
}

#[cfg(unix)]
#[test]
fn process_isolation_is_decided_per_jail_so_shared_network_is_refused()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let mut config = config();
    config.enforcement = JailEnforcement::Enforced;
    config.require_process_isolation = true;
    // tinymcp's default: network allowed, isolation required.
    config.allow_net = true;
    config.allow_subprocess = true;
    let backend = NetworkSensitiveBackend;
    assert!(
        prepare(root.path(), &config, &command, &backend).is_err(),
        "a shared network namespace must not satisfy require_process_isolation"
    );
    config.allow_net = false;
    // Subprocess denial is not enforced by this fixture, so leave it allowed.
    assert!(prepare(root.path(), &config, &command, &backend).is_ok());
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_symlink_planted_in_the_writable_root_cannot_redirect_a_grant()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    let backend = Backend {
        available: true,
        suitable: true,
        name: "fixture",
        full: true,
    };
    let mut command = tinybox_core::ExecRequest::new(["irrelevant"]);
    command.cwd = Some(root.path().into());
    let planted = root.path().join("vendor");
    std::os::unix::fs::symlink(secret.path(), &planted)?;

    let mut read_only = config();
    read_only
        .read_only
        .push(planted.to_string_lossy().into_owned());
    assert!(prepare(root.path(), &read_only, &command, &backend).is_err());

    let mut read_write = config();
    read_write
        .read_write
        .push(planted.to_string_lossy().into_owned());
    assert!(prepare(root.path(), &read_write, &command, &backend).is_err());

    // Also when the root is spelled through an alias of its real path.
    let alias_holder = tempfile::tempdir()?;
    let alias = alias_holder.path().join("alias");
    std::os::unix::fs::symlink(root.path(), &alias)?;
    let mut aliased = config();
    aliased
        .read_only
        .push(planted.to_string_lossy().into_owned());
    assert!(prepare(&alias, &aliased, &command, &backend).is_err());

    // A symlink outside every writable ancestor is still a fine grant.
    let holder = tempfile::tempdir()?;
    let tools = holder.path().join("tools");
    std::os::unix::fs::symlink(secret.path(), &tools)?;
    let mut outside = config();
    outside.read_only.push(tools.to_string_lossy().into_owned());
    assert!(prepare(root.path(), &outside, &command, &backend).is_ok());
    Ok(())
}
