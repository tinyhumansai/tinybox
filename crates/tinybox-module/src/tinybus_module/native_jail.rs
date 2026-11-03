//! Validate approved native grants before reserving or starting a child.
use std::{
    ffi::OsString,
    path::{Component, Path},
    process::{Child, Command},
    sync::{Arc, Mutex},
};
use tinybox_bus::{JailEnforcement, NativeJailConfig, NativeJailRequest};
use tinybox_jail::{Jail, JailBackend};
use tinybus::{Error, Result};

/// Validate native jail policy and resolve every path before process admission.
pub(super) fn prepare(
    root: &Path,
    config: &NativeJailConfig,
    command: &tinybox_core::ExecRequest,
    backend: &dyn JailBackend,
) -> Result<Jail> {
    if !cfg!(unix) || !backend.is_available() || backend.name() == tinybox_jail::NOOP_BACKEND_NAME {
        return Err(unavailable());
    }
    if config.read_only.len() + config.read_write.len() + config.deny_read.len()
        > tinybox_bus::MAX_NATIVE_JAIL_GRANTS
    {
        return Err(invalid());
    }
    // Before anything is canonicalized: a link the jailed program planted
    // (`<root>/vendor -> <secret>`) is only visible in the raw spellings.
    {
        let writable: Vec<&Path> = std::iter::once(root)
            .chain(config.read_write.iter().map(Path::new))
            .collect();
        let nested: Vec<&Path> = config
            .read_only
            .iter()
            .chain(&config.read_write)
            .map(Path::new)
            .collect();
        tinybox_jail::reject_symlinked_grants(&writable, &nested).map_err(|_| invalid())?;
    }
    let root = root.canonicalize().map_err(|_| invalid())?;
    if !root.is_dir() {
        return Err(invalid());
    }
    let cwd = command.cwd.as_ref().ok_or_else(invalid)?;
    if !cwd
        .canonicalize()
        .map_err(|_| invalid())?
        .starts_with(&root)
    {
        return Err(invalid());
    }
    let mut jail = Jail::new(root, "tinybox.module");
    jail.allow_net = config.allow_net;
    jail.allow_subprocess = config.allow_subprocess;
    jail.read_only = grants(&config.read_only)?;
    jail.read_write = grants(&config.read_write)?;
    jail.deny_read = denials(&config.deny_read)?;
    configure_resources(&mut jail, config)?;
    // A denial over the root or a writable grant would leave the command no
    // workspace; a denial nested inside a writable grant is safe only for a
    // backend that applies denials after its write allows.
    if jail.deny_read.iter().any(|denied| {
        jail.root.starts_with(denied)
            || jail.read_write.iter().any(|granted| {
                granted.starts_with(denied)
                    || (!backend.carves_denials() && denied.starts_with(granted))
            })
    }) {
        return Err(invalid());
    }
    // A carving backend may still be unable to hold a deeply nested denial.
    backend
        .validate_carved_denials(&jail)
        .map_err(|_| invalid())?;
    if !backend.carves_denials() {
        let mut implicit_grants = Vec::new();
        for grant in backend.implicit_grants() {
            match canonicalize_prospective(&grant) {
                Ok(canonical) => implicit_grants.push(canonical),
                Err(_) => return Err(unavailable()),
            }
        }
        if jail.deny_read.iter().any(|denied| {
            std::iter::once(&jail.root)
                .chain(&jail.read_only)
                .chain(&implicit_grants)
                .any(|granted| overlaps(denied, granted))
        }) {
            return Err(unavailable());
        }
    }
    // Per-jail, never per-backend: a backend's isolation can depend on the
    // configuration (a shared network namespace under `allow_net`).
    if config.require_process_isolation && !backend.is_suitable_for_untrusted_jail(&jail) {
        return Err(unavailable());
    }
    backend
        .require_resources(&jail)
        .map_err(|_| unavailable())?;
    match config.enforcement {
        JailEnforcement::Enforced => backend.require(&jail).map_err(|_| unavailable())?,
        JailEnforcement::Declared => {
            if backend
                .plan_check(&jail)
                .constraints
                .iter()
                .any(|(_, support)| *support == tinybox_core::Enforcement::Unsupported)
            {
                return Err(unavailable());
            }
        }
    }
    Ok(jail)
}

fn configure_resources(jail: &mut Jail, config: &NativeJailConfig) -> Result<()> {
    jail.resources = config.resources.map(|limits| tinybox_core::Resources {
        cpu_millis: limits.cpu_millis,
        memory_bytes: limits.memory_bytes,
        pids_max: limits.pids_max,
        disk_bytes: limits.disk_bytes,
    });
    jail.hard_requirements
        .extend(required_resource_constraints(config.resources));
    if jail
        .resources
        .is_some_and(|limits| limits.validate().is_err())
    {
        return Err(invalid());
    }
    Ok(())
}

fn required_resource_constraints(
    resources: Option<tinybox_bus::ResourceLimits>,
) -> Vec<tinybox_core::Constraint> {
    if resources.is_some() {
        // An explicitly supplied native jail budget is a hard request. The
        // default values in a BoxSpec remain soft unless its own
        // `hard_requirements` lists a constraint.
        vec![
            tinybox_core::Constraint::Cpu,
            tinybox_core::Constraint::Memory,
            tinybox_core::Constraint::Pids,
            tinybox_core::Constraint::Disk,
        ]
    } else {
        Vec::new()
    }
}

/// Validate and canonicalize each existing absolute grant path.
fn grants(paths: &[String]) -> Result<Vec<std::path::PathBuf>> {
    paths
        .iter()
        .map(|value| {
            let path = Path::new(value);
            if value.len() > tinybox_bus::MAX_FILE_PATH_BYTES
                || value.contains('\0')
                || !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir))
            {
                return Err(invalid());
            }
            path.canonicalize().map_err(|_| invalid())
        })
        .collect()
}
/// Keep lexical prospective paths as well as canonical aliases for existing
/// ancestors so a later-created credential store remains denied.
fn denials(paths: &[String]) -> Result<Vec<std::path::PathBuf>> {
    let mut denied = Vec::new();
    for value in paths {
        let path = Path::new(value);
        if value.len() > tinybox_bus::MAX_FILE_PATH_BYTES
            || value.contains('\0')
            || !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(invalid());
        }
        denied.push(path.to_path_buf());
        match canonicalize_prospective(path) {
            Ok(canonical) if canonical != path => denied.push(canonical),
            Ok(_) => {}
            Err(_) => return Err(invalid()),
        }
    }
    denied.sort();
    denied.dedup();
    Ok(denied)
}

/// Resolve a denial through existing aliases while preserving missing suffixes.
fn canonicalize_prospective(path: &Path) -> std::io::Result<std::path::PathBuf> {
    match path.canonicalize() {
        Ok(canonical) => return Ok(canonical),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                // Resolve existing aliases for prospective descendants, but
                // refuse dangling links and loops that have no stable target.
                let mut canonical = ancestor.canonicalize()?;
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let name = ancestor.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no existing path ancestor")
        })?;
        suffix.push(name.to_os_string());
        ancestor = ancestor.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no existing path ancestor")
        })?;
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
}

/// Return whether either path contains the other by path components.
fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}
fn invalid() -> Error {
    super::resources::failure(
        tinybox_bus::INVALID_FILE_PATH,
        "invalid native jail grant or working directory",
    )
}
fn unavailable() -> Error {
    super::resources::failure(
        tinybox_bus::UNSUPPORTED_OPERATION,
        "requested native jail enforcement is unavailable",
    )
}

/// A private backend whose sole accepted command is the validated launcher
/// constructed by `prepare_with_resources`. It is created per execution and
/// consumes that command exactly once at spawn.
struct NativeResourceBackend {
    expected: Mutex<Option<Vec<OsString>>>,
    requested: Mutex<Option<tinybox_bus::NativeJailResourceRequest>>,
}

impl NativeResourceBackend {
    fn new() -> Self {
        Self {
            expected: Mutex::new(None),
            requested: Mutex::new(None),
        }
    }

    fn bind(&self, argv: &[String]) -> Result<()> {
        let mut expected = self.expected.lock().map_err(|_| unavailable())?;
        if expected.is_some() {
            return Err(unavailable());
        }
        *expected = Some(argv.iter().map(OsString::from).collect());
        Ok(())
    }

    fn bind_resources(&self, resources: tinybox_bus::NativeJailResourceRequest) -> Result<()> {
        let mut requested = self.requested.lock().map_err(|_| unavailable())?;
        if requested.is_some() {
            return Err(unavailable());
        }
        *requested = Some(resources);
        Ok(())
    }
}

impl JailBackend for NativeResourceBackend {
    fn name(&self) -> &'static str {
        "tinybox-linux-native-resources"
    }

    fn is_available(&self) -> bool {
        native_launchers_available()
    }

    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::Kernel
    }

    fn is_suitable_for_untrusted_code(&self) -> bool {
        true
    }

    fn carves_denials(&self) -> bool {
        true
    }

    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
        ConstraintSupport::NONE
            .with(Constraint::Filesystem, Enforcement::Enforced)
            .with(Constraint::Network, Enforcement::Enforced)
            .with(Constraint::Subprocess, Enforcement::Enforced)
            .with(Constraint::Cpu, Enforcement::Enforced)
            .with(Constraint::Memory, Enforcement::Enforced)
            .with(Constraint::Pids, Enforcement::Enforced)
            .with(Constraint::Disk, Enforcement::Unsupported)
    }

    fn spawn(&self, jail: &Jail, mut cmd: Command) -> std::io::Result<Child> {
        if jail.resources.is_some()
            || self
                .requested
                .lock()
                .map_err(|_| std::io::Error::other("native resource request lock poisoned"))?
                .is_none()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "resource backend requires a 2.1 native request",
            ));
        }
        let mut actual = vec![cmd.get_program().to_os_string()];
        actual.extend(cmd.get_args().map(std::ffi::OsStr::to_os_string));
        let mut expected = self
            .expected
            .lock()
            .map_err(|_| std::io::Error::other("resource launcher plan lock poisoned"))?;
        if expected.take().as_deref() != Some(actual.as_slice()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native resource launcher differs from validated plan",
            ));
        }
        // The trusted supervisor shim closes inherited descriptors above
        // stdio before starting the resource launcher. The live manager-FD
        // escape test pins this behavior.
        // JailLocalHost clears inherited variables before installing this
        // fixed launcher environment. The target environment is carried only
        // inside bubblewrap after its namespaces are active.
        cmd.spawn()
    }
}

fn prepare_with_resources(
    root: &Path,
    request: &NativeJailRequest,
    command: &mut tinybox_core::ExecRequest,
    backend: &NativeResourceBackend,
) -> Result<Jail> {
    let resources = request.resources.ok_or_else(invalid)?;
    if request.jail.resources.is_some() || resources.disk_bytes.is_some() {
        return Err(unavailable());
    }
    if [
        resources.cpu_millis,
        resources.memory_bytes,
        resources.pids_max,
    ]
    .into_iter()
    .flatten()
    .any(|value| value == 0)
        || (resources.cpu_millis.is_none()
            && resources.memory_bytes.is_none()
            && resources.pids_max.is_none())
    {
        return Err(invalid());
    }
    backend.bind_resources(resources)?;
    let jail = prepare(root, &request.jail, command, backend)?;
    if request.jail.allow_net || !request.jail.allow_subprocess {
        return Err(unavailable());
    }
    let cwd = command.cwd.as_ref().ok_or_else(invalid)?;
    let native = tinybox_linux::NativeJailCommand {
        root: jail.root.clone(),
        cwd: cwd.canonicalize().map_err(|_| invalid())?,
        read_only: jail.read_only.clone(),
        read_write: jail.read_write.clone(),
        deny_read: jail.deny_read.clone(),
        allow_net: jail.allow_net,
        allow_subprocess: jail.allow_subprocess,
        cpu_millis: resources.cpu_millis,
        memory_bytes: resources.memory_bytes,
        pids_max: resources.pids_max,
        argv: command.argv.clone(),
        env: command
            .env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    };
    configure_resource_launcher(&native, command, backend)?;
    Ok(jail)
}

#[cfg(target_os = "linux")]
fn configure_resource_launcher(
    native: &tinybox_linux::NativeJailCommand,
    command: &mut tinybox_core::ExecRequest,
    backend: &NativeResourceBackend,
) -> Result<()> {
    let bwrap = tinybox_jail::BubblewrapBackend::new()
        .program()
        .map(Path::to_path_buf)
        .ok_or_else(unavailable)?;
    let systemd_run = tinybox_linux::trusted_systemd_run_program().map_err(|_| unavailable())?;
    let argv = tinybox_linux::native_jail_argv_with_programs(native, &systemd_run, &bwrap)
        .map_err(|_| unavailable())?;
    backend.bind(&argv)?;
    command.argv = argv;
    command.env = launcher_environment();
    command.cwd = None;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_resource_launcher(
    _native: &tinybox_linux::NativeJailCommand,
    _command: &mut tinybox_core::ExecRequest,
    _backend: &NativeResourceBackend,
) -> Result<()> {
    Err(unavailable())
}

#[cfg(target_os = "linux")]
fn native_launchers_available() -> bool {
    tinybox_linux::trusted_systemd_run_program().is_ok()
        && tinybox_jail::BubblewrapBackend::new().program().is_some()
}

#[cfg(not(target_os = "linux"))]
fn native_launchers_available() -> bool {
    false
}

fn launcher_environment() -> std::collections::BTreeMap<String, String> {
    let mut env = std::collections::BTreeMap::new();
    for key in [
        "PATH",
        "HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "SYSTEMD_BUS_ADDRESS",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ] {
        if let Some(value) = std::env::var_os(key).and_then(|value| value.into_string().ok()) {
            env.insert(key.to_owned(), value);
        }
    }
    env
}

fn resource_backend() -> Arc<NativeResourceBackend> {
    Arc::new(NativeResourceBackend::new())
}

/// Create an owned collector only after the native jail passes preflight.
pub(super) fn collector(
    root: &Path,
    config: &NativeJailConfig,
    command: &tinybox_core::ExecRequest,
    backend: Arc<dyn JailBackend>,
) -> Result<Arc<tinybox_host::JailLocalHost>> {
    let jail = prepare(root, config, command, backend.as_ref())?;
    tinybox_host::JailLocalHost::with_backend(jail, backend, tinybox_bus::MAX_OUTPUT_BYTES)
        .map(Arc::new)
        .map_err(|_| unavailable())
}

/// Create an owned collector for a separately negotiated contract 2.1 request.
pub(super) fn collector_with_resources(
    root: &Path,
    request: &NativeJailRequest,
    command: &mut tinybox_core::ExecRequest,
) -> Result<Arc<tinybox_host::JailLocalHost>> {
    let backend = resource_backend();
    let jail = prepare_with_resources(root, request, command, backend.as_ref())?;
    tinybox_host::JailLocalHost::with_backend(jail, backend, tinybox_bus::MAX_OUTPUT_BYTES)
        .map(Arc::new)
        .map_err(|_| unavailable())
}

#[cfg(test)]
#[path = "native_jail_tests.rs"]
mod tests;
