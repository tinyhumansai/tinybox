//! Validate approved native grants before reserving or starting a child.
use std::{
    path::{Component, Path},
    sync::Arc,
};
use tinybox_bus::{JailEnforcement, NativeJailConfig};
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
    if config.read_only.len()
        + config.read_write.len()
        + config.deny_read.len()
        + config.unix_paths.read_only.len()
        + config.unix_paths.read_write.len()
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
    jail.read_only
        .extend(unix_grants(&config.unix_paths.read_only)?);
    jail.read_write
        .extend(unix_grants(&config.unix_paths.read_write)?);
    configure_denials_and_resources(&mut jail, config, backend)?;
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

fn configure_denials_and_resources(
    jail: &mut Jail,
    config: &NativeJailConfig,
    backend: &dyn JailBackend,
) -> Result<()> {
    jail.deny_read = denials(&config.deny_read)?;
    jail.resources = config.resources.map(|limits| tinybox_core::Resources {
        cpu_millis: limits.cpu_millis,
        memory_bytes: limits.memory_bytes,
        pids_max: limits.pids_max,
        disk_bytes: limits.disk_bytes,
    });
    if jail
        .resources
        .is_some_and(|limits| limits.validate().is_err())
    {
        return Err(invalid());
    }
    if jail.deny_read.iter().any(|denied| {
        jail.root.starts_with(denied)
            || jail.read_write.iter().any(|granted| {
                granted.starts_with(denied)
                    || (!backend.carves_denials() && denied.starts_with(granted))
            })
    }) {
        return Err(invalid());
    }
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
    Ok(())
}

/// Validate and canonicalize byte-preserving Unix grant paths.
fn unix_grants(paths: &[Vec<u8>]) -> Result<Vec<std::path::PathBuf>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        paths
            .iter()
            .map(|bytes| {
                let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes.clone()));
                if bytes.len() > tinybox_bus::MAX_FILE_PATH_BYTES
                    || bytes.contains(&0)
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
    #[cfg(not(unix))]
    {
        Err(unavailable())
    }
}

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

#[cfg(test)]
#[path = "native_jail_tests.rs"]
mod tests;
