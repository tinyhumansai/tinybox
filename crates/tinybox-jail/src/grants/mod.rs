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
    let rustup_home = std::env::var_os("RUSTUP_HOME");
    let cargo_home = std::env::var_os("CARGO_HOME");
    resolve_local_jail_grants_with_homes(
        home,
        xdg_config_home.as_deref(),
        rustup_home.as_deref(),
        cargo_home.as_deref(),
        cfg,
        protected,
    )
}

/// [`resolve_local_jail_grants`] with `XDG_CONFIG_HOME` passed in rather than
/// read from the process environment, so callers (and tests) stay hermetic.
#[cfg(test)]
pub(crate) fn resolve_local_jail_grants_in(
    home: Option<&Path>,
    xdg_config_home: Option<&std::ffi::OsStr>,
    cfg: &LocalGrantConfig,
    protected: &ProtectedPaths,
) -> tinybox_core::Result<JailGrants> {
    resolve_local_jail_grants_with_homes(home, xdg_config_home, None, None, cfg, protected)
}

/// Resolve grants with all environment-derived roots supplied explicitly.
/// This keeps discovery testable without changing the process environment.
fn resolve_local_jail_grants_with_homes(
    home: Option<&Path>,
    xdg_config_home: Option<&std::ffi::OsStr>,
    rustup_home: Option<&std::ffi::OsStr>,
    cargo_home: Option<&std::ffi::OsStr>,
    cfg: &LocalGrantConfig,
    protected: &ProtectedPaths,
) -> tinybox_core::Result<JailGrants> {
    let home = home.map(|h| h.canonicalize().unwrap_or_else(|_| h.to_path_buf()));
    let mut b = Builder::new(home.as_deref(), protected);

    if cfg.toolchain_homes {
        if let Some(h) = home.as_deref() {
            b.add_cargo_home(&h.join(".cargo"));
            for dir in HOME_READ_ONLY_DIRS {
                b.toolchain_read_only(&h.join(dir), "toolchain");
            }
        }
        for dir in SYSTEM_TOOLCHAIN_DIRS {
            b.toolchain_read_only(Path::new(dir), "toolchain");
        }
        if let Some(path) = existing_absolute_directory(rustup_home) {
            b.toolchain_read_only(&path, "custom Rustup home");
        }
        if let Some(path) = existing_absolute_directory(cargo_home) {
            b.add_cargo_home(&path);
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

fn existing_absolute_directory(raw: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let path = PathBuf::from(raw?);
    (!path.as_os_str().is_empty() && path.is_absolute() && path.is_dir()).then_some(path)
}

struct Builder<'a> {
    home: Option<&'a Path>,
    protected: &'a ProtectedPaths,
    grants: JailGrants,
    seen: HashSet<PathBuf>,
    fixed_read_only: Vec<PathBuf>,
    cargo_roots: Vec<PathBuf>,
}

impl<'a> Builder<'a> {
    fn new(home: Option<&'a Path>, protected: &'a ProtectedPaths) -> Self {
        Self {
            home,
            protected,
            grants: JailGrants::default(),
            seen: HashSet::new(),
            fixed_read_only: Vec::new(),
            cargo_roots: Vec::new(),
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
        let Some(canonical) = self.admit(path, source) else {
            return;
        };
        if self.exposes_cargo_root(&canonical) {
            log::warn!(
                "refused extra grant containing the Cargo home root: {}",
                path.display()
            );
            return;
        }
        self.record_read_only(canonical);
    }

    fn fixed_read_only(&mut self, path: &Path, source: &str) {
        self.add_read_only(path, source, true);
    }

    /// Reserve toolchain roots even when the floor refuses their grant, so a
    /// later writable extra cannot reintroduce the same host state.
    fn toolchain_read_only(&mut self, path: &Path, source: &str) {
        self.fixed_read_only.push(path.to_path_buf());
        if let Ok(canonical) = path.canonicalize() {
            self.fixed_read_only.push(canonical);
        }
        self.add_read_only(path, source, false);
    }

    fn add_read_only(&mut self, path: &Path, source: &str, fixed: bool) {
        if let Some(p) = self.admit(path, source) {
            if fixed {
                self.fixed_read_only.push(path.to_path_buf());
                self.fixed_read_only.push(p.clone());
            }
            self.record_read_only(p);
        }
    }

    fn record_read_only(&mut self, path: PathBuf) {
        if self.seen.insert(path.clone()) {
            self.grants.read_only.push(path);
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
            let exposes_cargo = self.home.is_some_and(|home| {
                ["bin", "git", "registry"]
                    .into_iter()
                    .chain(CARGO_READ_ONLY_FILES.iter().copied())
                    .any(|entry| reaches(&home.join(".cargo").join(entry)))
            });
            if exposes_fixed || exposes_cargo || self.exposes_cargo_root(&p) {
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

    /// Grant only the parts of `~/.cargo` that jailed Cargo needs. The root is
    /// never writable: `bin` and Cargo configuration run later outside the
    /// jail, so writable access there would persist an escape for host tools.
    /// Shared dependency sources are also read-only: a cached build script can
    /// execute during a later host build. Fetches need a disposable Cargo home.
    fn add_cargo_home(&mut self, cargo: &Path) {
        if !cargo.is_dir() {
            return;
        }
        if let Ok(canonical) = cargo.canonicalize() {
            self.cargo_roots.push(cargo.to_path_buf());
            self.cargo_roots.push(canonical);
        }
        log::debug!("[sandbox:grants] granting ~/.cargo parts with host code read-only");
        self.toolchain_read_only(&cargo.join("bin"), "toolchain");
        self.toolchain_read_only(&cargo.join("registry"), "toolchain");
        self.toolchain_read_only(&cargo.join("git"), "toolchain");
        for f in CARGO_READ_ONLY_FILES {
            self.toolchain_read_only(&cargo.join(f), "toolchain");
        }
    }

    fn exposes_cargo_root(&self, path: &Path) -> bool {
        let normalized = normalized_floor_path(&path.to_string_lossy());
        self.cargo_roots.iter().any(|root| {
            root_spellings(root).any(|cargo_root| same_or_descendant(&cargo_root, &normalized))
        })
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
