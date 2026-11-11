//! Discover canonical local toolchain grants while preserving a host-supplied protected-path floor.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tinybox_bus::{LocalGrantConfig, ProtectedPaths};

/// System toolchain roots granted read-only when present.
const SYSTEM_TOOLCHAIN_DIRS: &[&str] = &["/usr/local", "/opt"];

/// `$HOME`-relative toolchain homes granted read-only when present.
const HOME_READ_ONLY_DIRS: &[&str] = &[".rustup", ".nvm", ".npm"];

/// Files Cargo needs read access to inside `~/.cargo` when the directory also
/// holds registry credentials and so cannot be granted whole.
const CARGO_READ_ONLY_FILES: &[&str] = &["config.toml", "config", "env"];

mod floor;
mod git_config;
mod inspection;
mod types;

use floor::{normalized_floor_path, root_spellings, same_or_descendant};
#[cfg(test)]
use git_config::include_paths;
pub use types::JailGrants;

/// Bound admission work even for attacker-controlled directory trees.
const SUBTREE_MAX_ENTRIES: usize = 1_000_000;
const SUBTREE_MAX_DEPTH: usize = 128;

/// Build the grant set for `home` (the user's home directory, if known).
/// # Errors
/// Returns an error for unsupported Git user-home or installation-prefix
/// includes instead of returning a partially discovered grant set.
pub fn resolve_local_jail_grants(
    home: Option<&Path>,
    cfg: &LocalGrantConfig,
    protected: &ProtectedPaths,
) -> tinybox_core::Result<JailGrants> {
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");
    resolve_local_jail_grants_in(
        home,
        xdg_config_home.as_deref(),
        &ConfiguredHomes::from_env(),
        cfg,
        protected,
    )
}

/// Toolchain homes the user moved away from `~/.cargo` and `~/.rustup`, from
/// `CARGO_HOME` and `RUSTUP_HOME`. A blank or relative value counts as unset,
/// as Cargo and rustup themselves treat a blank one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConfiguredHomes {
    pub(crate) cargo: Option<PathBuf>,
    pub(crate) rustup: Option<PathBuf>,
}

impl ConfiguredHomes {
    fn from_env() -> Self {
        let configured = |name: &str| {
            std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        Self {
            cargo: configured("CARGO_HOME"),
            rustup: configured("RUSTUP_HOME"),
        }
    }
}

/// [`resolve_local_jail_grants`] with `XDG_CONFIG_HOME` and the configured
/// toolchain homes passed in rather than read from the process environment, so
/// callers (and tests) stay hermetic.
pub(crate) fn resolve_local_jail_grants_in(
    home: Option<&Path>,
    xdg_config_home: Option<&std::ffi::OsStr>,
    homes: &ConfiguredHomes,
    cfg: &LocalGrantConfig,
    protected: &ProtectedPaths,
) -> tinybox_core::Result<JailGrants> {
    let home = home.map(|h| h.canonicalize().unwrap_or_else(|_| h.to_path_buf()));
    let mut b = Builder::new(home.as_deref(), protected);
    // Protected whether or not toolchain homes are granted, like `~/.cargo`:
    // a writable extra must not reach host-run parts of a moved home either.
    if let Some(cargo) = &homes.cargo {
        b.protect_cargo_home(cargo);
    }

    if cfg.toolchain_homes {
        if let Some(h) = home.as_deref() {
            b.add_cargo_home(&h.join(".cargo"));
            for dir in HOME_READ_ONLY_DIRS {
                b.fixed_read_only(&h.join(dir), "toolchain");
            }
        }
        // A moved home gets the same treatment as the default one: Cargo's
        // host-run parts and caches read-only, rustup's whole home read-only.
        if let Some(cargo) = &homes.cargo {
            b.add_cargo_home(cargo);
        }
        if let Some(rustup) = &homes.rustup {
            b.fixed_read_only(rustup, "toolchain");
        }
        for dir in SYSTEM_TOOLCHAIN_DIRS {
            b.fixed_read_only(Path::new(dir), "toolchain");
        }
        if let Some(h) = home.as_deref() {
            b.add_gitconfig_at(h, xdg_config_home)?;
        }
    }
    for raw in &cfg.extra_read_only {
        if let Some(p) = b.expand(raw) {
            b.read_only(&p, "config");
        }
    }
    for raw in &cfg.extra_read_write {
        if let Some(p) = b.expand(raw) {
            b.read_write(&p, "config");
        }
    }
    // The one sanctioned route to `/proc`: it bypasses the floor deliberately.
    if cfg.allow_proc && Path::new("/proc").exists() {
        log::debug!("[sandbox:grants] granting read-only /proc (allow_proc = true)");
        b.grants.read_only.push(PathBuf::from("/proc"));
    }
    log::debug!(
        "resolved {} read-only and {} writable local grants",
        b.grants.read_only.len(),
        b.grants.read_write.len()
    );
    Ok(b.grants)
}

struct Builder<'a> {
    home: Option<&'a Path>,
    protected: &'a ProtectedPaths,
    grants: JailGrants,
    seen: HashSet<PathBuf>,
    fixed_read_only: Vec<PathBuf>,
    /// Every Cargo home whose host-run parts a writable grant must not reach:
    /// `~/.cargo`, plus a configured `CARGO_HOME`.
    cargo_homes: Vec<PathBuf>,
}

impl<'a> Builder<'a> {
    fn new(home: Option<&'a Path>, protected: &'a ProtectedPaths) -> Self {
        Self {
            home,
            protected,
            grants: JailGrants::default(),
            seen: HashSet::new(),
            fixed_read_only: Vec::new(),
            cargo_homes: home.map(|home| home.join(".cargo")).into_iter().collect(),
        }
    }

    /// Expand a leading `~` / `~/` against the home directory.
    fn expand(&self, raw: &str) -> Option<PathBuf> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        if raw == "~" {
            return self.home.map(Path::to_path_buf);
        }
        if let Some(rest) = raw.strip_prefix("~/") {
            return self.home.map(|h| h.join(rest));
        }
        Some(PathBuf::from(raw))
    }

    /// Canonicalize `path` and return it only if it exists and clears the
    /// credential floor on both its requested name and resolved target.
    fn admit(&self, path: &Path, source: &str) -> Option<PathBuf> {
        if self.refuses_path(path) {
            log::warn!(
                "refused {source} grant reaching protected paths: {}",
                path.display()
            );
            return None;
        }
        let Ok(canonical) = path.canonicalize() else {
            log::debug!("skipped missing {source} grant: {}", path.display());
            return None;
        };
        if self.refuses_path(&canonical) {
            log::warn!(
                "refused {source} grant reaching protected paths: {}",
                canonical.display()
            );
            return None;
        }
        match self.subtree_is_clear(path, &canonical, SUBTREE_MAX_ENTRIES, SUBTREE_MAX_DEPTH) {
            Ok(true) => Some(canonical),
            Ok(false) => {
                log::warn!(
                    "refused {source} grant containing protected entries: {}",
                    path.display()
                );
                None
            }
            Err(error) => {
                log::warn!(
                    "refused uninspectable {source} grant {}: {error}",
                    path.display()
                );
                None
            }
        }
    }

    fn read_only(&mut self, path: &Path, source: &str) {
        self.add_read_only(path, source, false);
    }

    fn fixed_read_only(&mut self, path: &Path, source: &str) {
        self.add_read_only(path, source, true);
    }

    fn add_read_only(&mut self, path: &Path, source: &str, fixed: bool) {
        if let Some(p) = self.admit(path, source) {
            if fixed {
                self.fixed_read_only.push(path.to_path_buf());
                self.fixed_read_only.push(p.clone());
            }
            if self.seen.insert(p.clone()) {
                self.grants.read_only.push(p);
            }
        }
    }

    fn read_write(&mut self, path: &Path, source: &str) {
        if let Some(p) = self.admit(path, source) {
            let normalized = normalized_floor_path(&p.to_string_lossy());
            let reaches = |root: &Path| {
                root_spellings(root).any(|root| {
                    same_or_descendant(&normalized, &root) || same_or_descendant(&root, &normalized)
                })
            };
            let exposes_fixed = self.fixed_read_only.iter().any(|root| reaches(root));
            let exposes_cargo = self.cargo_homes.iter().any(|cargo| {
                ["bin", "git", "registry"]
                    .into_iter()
                    .chain(CARGO_READ_ONLY_FILES.iter().copied())
                    .any(|entry| reaches(&cargo.join(entry)))
            });
            if exposes_fixed || exposes_cargo {
                log::warn!(
                    "refused writable grant reaching fixed host toolchain state: {}",
                    p.display()
                );
                return;
            }
            // A path granted writable subsumes an earlier read-only grant.
            self.grants.read_only.retain(|g| g != &p);
            self.seen.insert(p.clone());
            if !self.grants.read_write.contains(&p) {
                self.grants.read_write.push(p);
            }
        }
    }

    /// Refuse writable extras on `cargo`, its ancestors and its descendants
    /// (see [`Self::add_cargo_home`]), without granting anything.
    fn protect_cargo_home(&mut self, cargo: &Path) {
        if !self.cargo_homes.iter().any(|known| known == cargo) {
            self.cargo_homes.push(cargo.to_path_buf());
        }
    }

    /// Grant only the parts of `~/.cargo` that jailed Cargo needs. The root is
    /// never writable: `bin` and Cargo configuration run later outside the
    /// jail, so writable access there would persist an escape for host tools.
    /// Shared dependency sources are also read-only: a cached build script can
    /// execute during a later host build. Fetches need a disposable Cargo home.
    fn add_cargo_home(&mut self, cargo: &Path) {
        self.protect_cargo_home(cargo);
        if !cargo.is_dir() {
            return;
        }
        log::debug!("[sandbox:grants] granting ~/.cargo parts with host code read-only");
        self.fixed_read_only(&cargo.join("bin"), "toolchain");
        self.fixed_read_only(&cargo.join("registry"), "toolchain");
        self.fixed_read_only(&cargo.join("git"), "toolchain");
        for f in CARGO_READ_ONLY_FILES {
            self.fixed_read_only(&cargo.join(f), "toolchain");
        }
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
