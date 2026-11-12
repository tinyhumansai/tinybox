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
    // Owned availability, not `is_available`: Windows `AppContainer` runs work
    // only through the owned-process API every jailed path uses. Off Windows
    // the two are the same.
    if !backend.is_owned_available() || backend.name() == tinybox_jail::NOOP_BACKEND_NAME {
        return Err(refused("no native jail backend is available on this host"));
    }
    if config.read_only.len()
        + config.read_write.len()
        + config.deny_read.len()
        + config.deny_read_names.len()
        > tinybox_bus::MAX_NATIVE_JAIL_GRANTS
    {
        return Err(invalid());
    }
    check_name_denials(config, backend)?;
    // Before anything is canonicalized: a link the jailed program planted
    // (`<root>/vendor -> <secret>`) is only visible in the raw spellings.
    reject_planted_links(root, config)?;
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
    jail.deny_read_names.clone_from(&config.deny_read_names);
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
        return Err(invalid_because(&format!(
            "a read denial covers the jail root or a writable grant, or sits inside a writable \
             grant that backend `{}` cannot carve a denial out of",
            backend.name()
        )));
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
            return Err(refused(&format!(
                "a read denial overlaps the jail root, a read-only grant or a default grant, and \
                 backend `{}` cannot carve denials",
                backend.name()
            )));
        }
    }
    // Per-jail, never per-backend: a backend's isolation can depend on the
    // configuration (a shared network namespace under `allow_net`).
    if config.require_process_isolation && !backend.is_suitable_for_untrusted_jail(&jail) {
        return Err(refused(&format!(
            "the jail requires process isolation, and backend `{}` reports {} isolation for it",
            backend.name(),
            backend.isolation_for(&jail)
        )));
    }
    backend
        .require_resources(&jail)
        .map_err(|_| unavailable())?;
    match config.enforcement {
        JailEnforcement::Enforced => backend
            .require(&jail)
            .map_err(|_| refused(&cannot_enforce(backend, &jail, true)))?,
        JailEnforcement::Declared => {
            if backend
                .plan_check(&jail)
                .constraints
                .iter()
                .any(|(_, support)| *support == tinybox_core::Enforcement::Unsupported)
            {
                return Err(refused(&cannot_enforce(backend, &jail, false)));
            }
        }
    }
    Ok(jail)
}

/// Name denials need a backend that denies by name, and each name must be one
/// plain path component.
fn check_name_denials(config: &NativeJailConfig, backend: &dyn JailBackend) -> Result<()> {
    if !config.deny_read_names.is_empty() && !backend.denies_by_name() {
        return Err(super::resources::failure(
            tinybox_bus::UNSUPPORTED_OPERATION,
            &format!(
                "requested native jail enforcement is unavailable: backend `{}` cannot deny \
                 paths by name",
                backend.name()
            ),
        ));
    }
    if !config
        .deny_read_names
        .iter()
        .all(|name| is_plain_name(name))
    {
        return Err(invalid());
    }
    Ok(())
}

fn configure_resources(jail: &mut Jail, config: &NativeJailConfig) -> Result<()> {
    jail.resources = config.resources.map(|limits| tinybox_core::Resources {
        cpu_millis: limits.cpu_millis,
        memory_bytes: limits.memory_bytes,
        pids_max: limits.pids_max,
        // Required only when the caller set one; see
        // `required_resource_constraints`.
        disk_bytes: limits
            .disk_bytes
            .unwrap_or(tinybox_core::Resources::DEFAULT.disk_bytes),
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
    // An explicitly supplied native jail budget is a hard request, disk
    // included only when the caller set one. The default values in a BoxSpec
    // remain soft unless its own `hard_requirements` lists a constraint.
    resources.map_or_else(Vec::new, |limits| {
        let mut constraints = vec![
            tinybox_core::Constraint::Cpu,
            tinybox_core::Constraint::Memory,
            tinybox_core::Constraint::Pids,
        ];
        if limits.disk_bytes.is_some() {
            constraints.push(tinybox_core::Constraint::Disk);
        }
        constraints
    })
}

/// Before anything is canonicalized: a link the jailed program planted
/// (`<root>/vendor -> <secret>`) is only visible in the raw spellings.
fn reject_planted_links(root: &Path, config: &NativeJailConfig) -> Result<()> {
    let writable: Vec<&Path> = std::iter::once(root)
        .chain(config.read_write.iter().map(Path::new))
        .collect();
    let nested: Vec<&Path> = config
        .read_only
        .iter()
        .chain(&config.read_write)
        .map(Path::new)
        .collect();
    tinybox_jail::reject_symlinked_grants(&writable, &nested).map_err(|_| invalid())
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
/// Whether `name` is one path component a profile rule can match exactly: not
/// empty, not `.` or `..`, bounded, and without a separator, quote or NUL.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= tinybox_bus::MAX_FILE_PATH_BYTES
        && !name.contains(['/', '\\', '"', '\0'])
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
/// [`invalid`], saying which rule the request broke.
fn invalid_because(reason: &str) -> Error {
    super::resources::failure(
        tinybox_bus::INVALID_FILE_PATH,
        &format!("invalid native jail grant or working directory: {reason}"),
    )
}
/// [`unavailable`], saying what the backend cannot provide. The code is the
/// same, so a host that branches on it is unaffected.
fn refused(reason: &str) -> Error {
    super::resources::failure(
        tinybox_bus::UNSUPPORTED_OPERATION,
        &format!("requested native jail enforcement is unavailable: {reason}"),
    )
}
/// The constraints `backend` cannot enforce for `jail`: anything short of
/// `Enforced` when `strict`, otherwise only what it does not support at all.
fn cannot_enforce(backend: &dyn JailBackend, jail: &Jail, strict: bool) -> String {
    let missing: Vec<String> = backend
        .plan_check(jail)
        .constraints
        .iter()
        .filter(|(_, support)| {
            if strict {
                *support != tinybox_core::Enforcement::Enforced
            } else {
                *support == tinybox_core::Enforcement::Unsupported
            }
        })
        .map(|(constraint, _)| format!("{constraint:?}").to_lowercase())
        .collect();
    format!(
        "backend `{}` cannot enforce {}",
        backend.name(),
        if missing.is_empty() {
            "a hard requirement of this jail".to_string()
        } else {
            missing.join(", ")
        }
    )
}

/// A private backend whose sole accepted command is the validated launcher
/// constructed by `prepare_with_resources`. It is created per execution and
/// consumes that command exactly once at spawn.
struct NativeResourceBackend {
    expected: Mutex<Option<Vec<OsString>>>,
    requested: Mutex<Option<tinybox_bus::NativeJailResourceRequest>>,
    scope: tinybox_linux::ScopeProbe,
    launch: Mutex<Option<tinybox_linux::NativeJailLaunch>>,
}

impl NativeResourceBackend {
    fn new() -> Self {
        Self::with_scope(tinybox_linux::ScopeProbe::detect())
    }

    fn with_scope(scope: tinybox_linux::ScopeProbe) -> Self {
        Self {
            expected: Mutex::new(None),
            requested: Mutex::new(None),
            scope,
            launch: Mutex::new(None),
        }
    }

    /// Holds the launch, and with it the private environment file, until this
    /// execution's backend is dropped.
    fn keep(&self, launch: tinybox_linux::NativeJailLaunch) -> Result<()> {
        let mut held = self.launch.lock().map_err(|_| unavailable())?;
        if held.is_some() {
            return Err(unavailable());
        }
        *held = Some(launch);
        Ok(())
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
        // A 2.1 request never shares the host network, so this is the bwrap
        // backend's no-network level: Kernel only when the child is barred
        // from new user namespaces, else none at all.
        if bwrap_disables_userns() {
            tinybox_core::IsolationLevel::Kernel
        } else {
            tinybox_core::IsolationLevel::None
        }
    }

    fn carves_denials(&self) -> bool {
        true
    }

    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
        let scope = self.scope.constraint_support();
        ConstraintSupport::NONE
            .with(Constraint::Filesystem, Enforcement::Enforced)
            .with(Constraint::Network, Enforcement::Enforced)
            // `prepare_with_resources` refuses a request that denies them.
            .with(Constraint::Subprocess, Enforcement::Unsupported)
            // Only what the user manager was delegated a controller for.
            .with(Constraint::Cpu, scope.enforcement(Constraint::Cpu))
            .with(Constraint::Memory, scope.enforcement(Constraint::Memory))
            .with(Constraint::Pids, scope.enforcement(Constraint::Pids))
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
    // A limit the scope cannot apply is refused, never dropped.
    let support = backend.constraint_support();
    if [
        (resources.cpu_millis, tinybox_core::Constraint::Cpu),
        (resources.memory_bytes, tinybox_core::Constraint::Memory),
        (resources.pids_max, tinybox_core::Constraint::Pids),
    ]
    .into_iter()
    .any(|(limit, constraint)| {
        limit.is_some() && support.enforcement(constraint) != tinybox_core::Enforcement::Enforced
    }) {
        return Err(unavailable());
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
        disable_userns: bwrap_disables_userns(),
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
    let launch = tinybox_linux::native_jail_argv_with_programs(native, &systemd_run, &bwrap)
        .map_err(|_| unavailable())?;
    backend.bind(&launch.argv)?;
    command.argv.clone_from(&launch.argv);
    // Held for the execution: the launcher opens and deletes the private file
    // carrying the target's environment, and dropping this removes it if the
    // launcher never ran.
    backend.keep(launch)?;
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

#[cfg(target_os = "linux")]
fn bwrap_disables_userns() -> bool {
    tinybox_jail::BubblewrapBackend::new().disables_userns()
}

#[cfg(not(target_os = "linux"))]
fn bwrap_disables_userns() -> bool {
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
