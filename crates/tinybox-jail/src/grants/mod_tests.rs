//! Toolchain grant discovery and protected-path regression coverage.
use super::*;
use std::fs;
use std::path::{Path, PathBuf};

/// Resolve grants with `XDG_CONFIG_HOME` unset, so a runner's own value (set
/// on GitHub's Ubuntu images) cannot move the Git config root under test.
fn resolve_hermetic(
    home: Option<&Path>,
    cfg: &LocalGrantConfig,
    protected: &ProtectedPaths,
) -> tinybox_core::Result<JailGrants> {
    resolve_local_jail_grants_in(home, None, cfg, protected)
}

fn fake_home() -> std::io::Result<tempfile::TempDir> {
    let home = tempfile::tempdir()?;
    for d in [
        ".ssh", ".gnupg", ".aws", ".cargo", ".rustup", ".nvm", ".npm",
    ] {
        fs::create_dir_all(home.path().join(d))?;
    }
    Ok(home)
}

fn canon(p: &Path) -> std::io::Result<PathBuf> {
    p.canonicalize()
}

fn has(grants: &[PathBuf], p: &Path) -> bool {
    grants.iter().any(|g| g == p)
}

fn all(g: &JailGrants) -> Vec<PathBuf> {
    g.read_only.iter().chain(&g.read_write).cloned().collect()
}

/// A grant reaches a credential store if it IS one, is inside one, or contains
/// one (Landlock grants are recursive, so a parent grant exposes the child).
fn reaches_credentials(grants: &[PathBuf], home: &Path) -> Option<PathBuf> {
    for cred in [".ssh", ".gnupg", ".aws"] {
        let cred = home.join(cred);
        for g in grants {
            if g.starts_with(&cred) || cred.starts_with(g) {
                return Some(g.clone());
            }
        }
    }
    None
}

#[test]
fn credential_dirs_are_never_granted_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default())?;
    assert_eq!(reaches_credentials(&all(&g), home.path()), None);
    Ok(())
}

#[test]
fn credential_dirs_are_never_granted_even_when_extras_ask() -> Result<(), Box<dyn std::error::Error>>
{
    let home = fake_home()?;
    let cfg = LocalGrantConfig {
        extra_read_only: vec![
            "~/.ssh".into(),
            "~/.gnupg/".into(),
            format!("{}", home.path().join(".aws").display()),
            "~".into(),
            format!("{}", home.path().display()),
            "/".into(),
        ],
        extra_read_write: vec!["~/.ssh".into(), "~".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg)?;
    assert_eq!(reaches_credentials(&all(&g), home.path()), None);
    assert!(!g.read_only.iter().any(|p| p == Path::new("/")));
    Ok(())
}

#[test]
#[cfg(unix)]
fn credential_floor_holds_for_a_symlink_into_a_credential_dir()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    std::os::unix::fs::symlink(home.path().join(".ssh"), home.path().join("innocent"))?;
    let cfg = LocalGrantConfig {
        extra_read_only: vec!["~/innocent".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg)?;
    assert_eq!(reaches_credentials(&all(&g), home.path()), None);
    Ok(())
}

#[test]
fn toolchain_homes_are_granted_when_they_exist() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let cargo = home.path().join(".cargo");
    for dir in ["bin", "registry", "git"] {
        fs::create_dir_all(cargo.join(dir))?;
    }
    for file in ["config.toml", "config", "env"] {
        fs::write(cargo.join(file), "")?;
    }
    let g = resolve(Some(home.path()), &LocalGrantConfig::default())?;
    let h = canon(home.path())?;
    let cargo = h.join(".cargo");
    assert!(
        !has(&g.read_write, &cargo),
        "Cargo home must never be writable"
    );
    assert!(has(&g.read_only, &cargo.join("bin")));
    assert!(has(&g.read_only, &cargo.join("registry")));
    assert!(has(&g.read_only, &cargo.join("git")));
    for file in ["config.toml", "config", "env"] {
        assert!(
            has(&g.read_only, &cargo.join(file)),
            "{file} should be read-only"
        );
    }
    for ro in [".rustup", ".nvm", ".npm"] {
        assert!(has(&g.read_only, &h.join(ro)), "{ro} should be read-only");
        assert!(
            !has(&g.read_write, &h.join(ro)),
            "{ro} must not be writable"
        );
    }
    Ok(())
}

#[test]
fn absent_toolchain_homes_are_not_granted() -> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join(".nvm"))?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default())?;
    let h = canon(home.path())?;
    assert!(has(&g.read_only, &h.join(".nvm")));
    assert!(!all(&g).iter().any(|p| p.starts_with(h.join(".cargo"))));
    assert!(!all(&g).iter().any(|p| p.starts_with(h.join(".rustup"))));
    Ok(())
}

#[test]
fn toolchain_homes_can_be_switched_off() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::write(home.path().join(".gitconfig"), "[user]\n name = x\n")?;
    let cfg = LocalGrantConfig {
        toolchain_homes: false,
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg)?;
    assert!(g.read_only.is_empty() && g.read_write.is_empty(), "{g:?}");
    Ok(())
}

#[test]
fn cargo_home_with_registry_credentials_is_granted_piecewise()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let cargo = home.path().join(".cargo");
    for d in ["bin", "registry", "git"] {
        fs::create_dir_all(cargo.join(d))?;
    }
    fs::write(
        cargo.join("credentials.toml"),
        "[registry]\ntoken = \"x\"\n",
    )?;
    fs::write(cargo.join("config.toml"), "")?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default())?;
    let c = canon(&cargo)?;
    assert!(
        !has(&g.read_write, &c),
        "whole ~/.cargo would expose credentials.toml"
    );
    assert!(!all(&g).iter().any(|p| p.ends_with("credentials.toml")));
    assert!(has(&g.read_only, &c.join("registry")));
    assert!(has(&g.read_only, &c.join("git")));
    assert!(has(&g.read_only, &c.join("bin")));
    assert!(has(&g.read_only, &c.join("config.toml")));
    Ok(())
}

#[test]
fn a_writable_grant_subsumes_the_same_path_read_only() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let cfg = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~/.npm".into()],
        extra_read_write: vec!["~/.npm".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg)?;
    let npm = canon(&home.path().join(".npm"))?;
    assert!(has(&g.read_write, &npm));
    assert!(!has(&g.read_only, &npm));
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn proc_is_off_by_default_and_only_the_toggle_grants_it() -> Result<(), Box<dyn std::error::Error>>
{
    let home = fake_home()?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default())?;
    assert!(!all(&g).iter().any(|p| p.starts_with("/proc")));

    // An `extra_*` entry cannot smuggle it in: only `allow_proc` does.
    let cfg = LocalGrantConfig {
        extra_read_only: vec!["/proc".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg)?;
    assert!(!all(&g).iter().any(|p| p.starts_with("/proc")));

    let cfg = LocalGrantConfig {
        allow_proc: true,
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg)?;
    assert!(has(&g.read_only, Path::new("/proc")));
    assert!(!has(&g.read_write, Path::new("/proc")));
    Ok(())
}

#[test]
fn extras_expand_tilde_and_skip_missing_paths() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::create_dir_all(home.path().join("dotfiles"))?;
    fs::create_dir_all(home.path().join("data"))?;
    let cfg = LocalGrantConfig {
        extra_read_only: vec!["~/dotfiles".into(), "~/nope".into()],
        extra_read_write: vec!["~/data/../data".into()],
        ..LocalGrantConfig::default()
    };
    let g = resolve(Some(home.path()), &cfg)?;
    assert!(has(&g.read_only, &canon(&home.path().join("dotfiles"))?));
    assert!(has(&g.read_write, &canon(&home.path().join("data"))?));
    assert!(!all(&g).iter().any(|p| p.ends_with("nope")));
    Ok(())
}

#[test]
#[cfg(unix)]
fn gitconfig_symlink_and_include_targets_are_canonicalized()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    let dots = home.path().join("dotfiles");
    fs::create_dir_all(&dots)?;
    fs::write(dots.join("work.gitconfig"), "[user]\n email = a@b\n")?;
    fs::write(dots.join("local.gitconfig"), "")?;
    fs::write(
        dots.join("gitconfig"),
        "[user]\n name = x\n[include]\n path = dotfiles/work.gitconfig\n\
         [includeIf \"gitdir:~/w/\"]\n\tpath = ~/dotfiles/local.gitconfig\n\
         [include]\n path = ~/.ssh/leaky\n",
    )?;
    std::os::unix::fs::symlink(dots.join("gitconfig"), home.path().join(".gitconfig"))?;
    // The credential include must be dropped even though the file exists.
    fs::write(home.path().join(".ssh/leaky"), "")?;

    let g = resolve(Some(home.path()), &LocalGrantConfig::default())?;
    let d = canon(&dots)?;
    assert!(has(&g.read_only, &d.join("gitconfig")), "{g:?}");
    assert!(has(&g.read_only, &d.join("work.gitconfig")), "{g:?}");
    assert!(has(&g.read_only, &d.join("local.gitconfig")), "{g:?}");
    assert_eq!(reaches_credentials(&all(&g), home.path()), None);
    Ok(())
}

#[test]
fn gitconfig_include_cycles_terminate() -> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::write(home.path().join(".gitconfig"), "[include]\n path = ~/b\n")?;
    fs::write(home.path().join("b"), "[include]\n path = ~/.gitconfig\n")?;
    let g = resolve(Some(home.path()), &LocalGrantConfig::default())?;
    assert!(has(&g.read_only, &canon(&home.path().join("b"))?));
    Ok(())
}

#[test]
fn no_home_yields_only_system_toolchain_dirs() -> Result<(), Box<dyn std::error::Error>> {
    let g = resolve(None, &LocalGrantConfig::default())?;
    assert_eq!(g.read_write, Vec::<PathBuf>::new());
    assert!(
        g.read_only
            .iter()
            .all(|p| p.starts_with("/usr/local") || p.starts_with("/opt"))
    );
    Ok(())
}

fn floor(home: Option<&Path>) -> ProtectedPaths {
    ProtectedPaths {
        components: [
            ".ssh",
            ".gnupg",
            ".aws",
            ".azure",
            ".kube",
            "keychains",
            ".netrc",
            ".git-credentials",
            ".pgpass",
            ".npmrc",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        component_pairs: vec![
            [".cargo".into(), "credentials.toml".into()],
            [".docker".into(), "config.json".into()],
        ],
        prefixes: [
            "/etc",
            "/root",
            "/boot",
            "/proc",
            "/sys",
            "/system",
            "c:/windows",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        credential_roots: home
            .map(|home| {
                [".ssh", ".gnupg", ".aws", ".azure", ".kube"]
                    .into_iter()
                    .map(|component| home.join(component).to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default(),
    }
}
fn resolve(home: Option<&Path>, config: &LocalGrantConfig) -> tinybox_core::Result<JailGrants> {
    resolve_hermetic(home, config, &floor(home))
}

#[test]
fn custom_host_floor_excludes_direct_and_ancestor_grants() -> Result<(), Box<dyn std::error::Error>>
{
    let home = fake_home()?;
    let private = home.path().join("host-secrets");
    fs::create_dir(&private)?;
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~".into(), "~/host-secrets".into()],
        ..LocalGrantConfig::default()
    };
    let protected = ProtectedPaths {
        credential_roots: vec![private.to_string_lossy().into_owned()],
        ..ProtectedPaths::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &protected)?;
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn host_floor_matches_component_pairs_and_case_insensitive_components()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::create_dir_all(home.path().join(".SSH"))?;
    fs::write(home.path().join(".cargo/credentials.toml"), "secret")?;
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~/.SSH".into(), "~/.cargo/credentials.toml".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve(Some(home.path()), &config)?;
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn extras_without_home_and_empty_values_are_skipped() -> Result<(), Box<dyn std::error::Error>> {
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec![" ".into(), "~".into(), "~/unknown".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve(None, &config)?;
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn include_parser_ignores_non_include_sections_and_empty_paths() {
    assert_eq!(
        include_paths(
            "[user]\npath = wrong\n[INCLUDE]\nignored\n other = wrong\n path = \"\"\n PATH = \"valid\"\n[includeIf \"gitdir:~/project\"]\n path = relative\n"
        ),
        ["valid", "relative"]
    );
}

#[test]
fn host_floor_matches_windows_separators_and_absolute_prefix_boundaries() {
    let protected = ProtectedPaths {
        components: vec![".ssh".into()],
        component_pairs: vec![["Microsoft".into(), "Protect".into()]],
        prefixes: vec!["C:/Windows".into()],
        credential_roots: Vec::new(),
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.is_protected(Path::new(r"C:\Users\x\.SSH\id_rsa")));
    assert!(builder.is_protected(Path::new(r"C:\Users\x\Microsoft\Protect\keys")));
    assert!(builder.is_protected(Path::new(r"C:\WINDOWS\System32")));
    assert!(builder.is_protected(Path::new(r"C:\WINDOWS")));
    assert!(!builder.is_protected(Path::new(r"C:\WINDOWS-tools")));
}

#[test]
fn gitconfig_include_depth_is_bounded_and_non_files_are_skipped()
-> Result<(), Box<dyn std::error::Error>> {
    let home = fake_home()?;
    fs::write(
        home.path().join(".gitconfig"),
        "[include]\n path = ~/next-0\n path = ~/.cargo\n",
    )?;
    for index in 0..12 {
        fs::write(
            home.path().join(format!("next-{index}")),
            format!("[include]\n path = ~/next-{}\n", index + 1),
        )?;
    }
    let grants = resolve(Some(home.path()), &LocalGrantConfig::default())?;
    assert!(has(&grants.read_only, &canon(&home.path().join("next-9"))?));
    assert!(!has(
        &grants.read_only,
        &canon(&home.path().join("next-10"))?
    ));
    Ok(())
}

#[test]
fn protected_absolute_root_blocks_every_descendant() {
    let protected = ProtectedPaths {
        prefixes: vec!["/".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.is_protected(Path::new("/opt")));
    assert!(builder.is_protected(Path::new("/usr/local/toolchain")));
    assert!(!builder.is_protected(Path::new("relative/toolchain")));
}

#[test]
fn protected_prefix_trailing_separators_keep_component_boundaries() {
    let protected = ProtectedPaths {
        prefixes: vec!["/opt/secrets/".into(), r"C:\Windows\".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.is_protected(Path::new("/opt/secrets/key")));
    assert!(builder.is_protected(Path::new("/opt/secrets")));
    assert!(!builder.is_protected(Path::new("/opt/secrets-tools/key")));
    assert!(builder.is_protected(Path::new(r"C:\WINDOWS\System32")));
    assert!(builder.is_protected(Path::new(r"C:\WINDOWS")));
    assert!(!builder.is_protected(Path::new(r"C:\WINDOWS-tools")));
}

#[test]
fn protected_windows_prefixes_match_canonical_extended_path_names() {
    let protected = ProtectedPaths {
        prefixes: vec!["C:/Windows/".into(), "//server/secrets/".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.is_protected(Path::new(r"\\?\C:\WINDOWS\System32")));
    assert!(!builder.is_protected(Path::new(r"\\?\C:\WINDOWS-tools")));
    assert!(builder.is_protected(Path::new(r"\\?\UNC\SERVER\secrets\key")));
    assert!(!builder.is_protected(Path::new(r"\\?\UNC\SERVER\secrets-tools")));
}

#[test]
fn credential_root_ancestors_match_case_and_separator_styles() {
    let protected = ProtectedPaths {
        credential_roots: vec!["c:/users/floor-fixture/.ssh".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.exposes_credentials(Path::new(r"\\?\C:\Users\FLOOR-FIXTURE")));
    assert!(builder.exposes_credentials(Path::new(r"C:\USERS\floor-fixture\.SSH\id_rsa")));
    assert!(!builder.exposes_credentials(Path::new(r"C:\Users\floor-fixture-other")));
}

#[test]
#[cfg(unix)]
fn protected_credential_alias_does_not_grant_its_neutral_target()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir(home.path().join("dotfiles"))?;
    fs::write(home.path().join("dotfiles/npmrc"), "fixture")?;
    std::os::unix::fs::symlink(
        home.path().join("dotfiles/npmrc"),
        home.path().join(".npmrc"),
    )?;
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~/.npmrc".into()],
        ..LocalGrantConfig::default()
    };
    let protected = ProtectedPaths {
        components: vec![".npmrc".into()],
        ..ProtectedPaths::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &protected)?;
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn procfs_extras_cannot_bypass_the_dedicated_toggle_with_an_empty_floor()
-> Result<(), Box<dyn std::error::Error>> {
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["/proc".into(), "/proc/self".into()],
        extra_read_write: vec!["/proc".into(), "/proc/self".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(None, &config, &ProtectedPaths::default())?;
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn procfs_toggle_grants_read_only_access_even_when_extras_ask_for_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let config = LocalGrantConfig {
        toolchain_homes: false,
        allow_proc: true,
        extra_read_write: vec!["/proc".into(), "/proc/self".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(None, &config, &ProtectedPaths::default())?;
    assert_eq!(grants.read_only, vec![PathBuf::from("/proc")]);
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn discovered_cargo_dependency_sources_cannot_be_poisoned_for_later_host_builds()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    for cache in ["git/checkouts/dependency", "registry/src/dependency"] {
        let source = home.path().join(".cargo").join(cache);
        fs::create_dir_all(&source)?;
        fs::write(source.join("build.rs"), "fn main() {}")?;
    }
    let grants = resolve_hermetic(
        Some(home.path()),
        &LocalGrantConfig::default(),
        &ProtectedPaths::default(),
    )?;
    for cache in ["git", "registry"] {
        let source = home.path().join(".cargo").join(cache).canonicalize()?;
        assert!(has(&grants.read_only, &source), "{grants:?}");
        assert!(!has(&grants.read_write, &source), "{grants:?}");
    }
    Ok(())
}

#[test]
fn rejected_git_config_cannot_grant_its_nested_includes() -> Result<(), Box<dyn std::error::Error>>
{
    let home = tempfile::tempdir()?;
    fs::create_dir(home.path().join(".ssh"))?;
    fs::write(
        home.path().join(".gitconfig"),
        "[include]\n path = ~/.ssh/private-config\n",
    )?;
    fs::write(
        home.path().join(".ssh/private-config"),
        "[include]\n path = ~/neutral-secret\n",
    )?;
    fs::write(home.path().join("neutral-secret"), "fixture")?;
    let protected = ProtectedPaths {
        components: vec![".ssh".into()],
        ..ProtectedPaths::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &LocalGrantConfig::default(), &protected)?;
    assert!(
        !has(
            &grants.read_only,
            &home.path().join("neutral-secret").canonicalize()?
        ),
        "{grants:?}"
    );
    Ok(())
}

#[test]
fn protected_prefixes_also_reject_recursive_ancestor_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir(home.path().join("private"))?;
    let protected = ProtectedPaths {
        prefixes: vec![
            home.path()
                .join("private")
                .to_str()
                .ok_or("non-UTF8 fixture")?
                .into(),
        ],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_write: vec![home.path().to_str().ok_or("non-UTF8 fixture")?.into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(None, &config, &protected)?;
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(unix)]
fn protected_prefix_alias_also_blocks_its_canonical_spelling()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let target = home.path().join("neutral");
    fs::create_dir(&target)?;
    std::os::unix::fs::symlink(&target, home.path().join("protected"))?;
    let protected = ProtectedPaths {
        prefixes: vec![
            home.path()
                .join("protected")
                .to_str()
                .ok_or("non-UTF8 fixture")?
                .into(),
        ],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec![target.to_str().ok_or("non-UTF8 fixture")?.into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(None, &config, &protected)?;
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn explicit_writable_grants_cannot_promote_shared_cargo_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    for cache in ["git", "registry"] {
        fs::create_dir_all(home.path().join(".cargo").join(cache))?;
    }
    let config = LocalGrantConfig {
        toolchain_homes: true,
        extra_read_write: vec!["~/.cargo/git".into(), "~/.cargo/registry".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &ProtectedPaths::default())?;
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    for cache in ["git", "registry"] {
        assert!(
            has(
                &grants.read_only,
                &home.path().join(".cargo").join(cache).canonicalize()?
            ),
            "{grants:?}"
        );
    }
    Ok(())
}

#[test]
fn git_ignore_patterns_cannot_add_config_include_grants() -> Result<(), Box<dyn std::error::Error>>
{
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join(".config/git"))?;
    fs::write(
        home.path().join(".config/git/ignore"),
        "[include]\npath = ~/neutral-secret\n",
    )?;
    fs::write(home.path().join("neutral-secret"), "fixture")?;
    let grants = resolve_hermetic(
        Some(home.path()),
        &LocalGrantConfig::default(),
        &ProtectedPaths::default(),
    )?;
    assert!(
        has(
            &grants.read_only,
            &home.path().join(".config/git/ignore").canonicalize()?
        ),
        "{grants:?}"
    );
    assert!(
        !has(
            &grants.read_only,
            &home.path().join("neutral-secret").canonicalize()?
        ),
        "{grants:?}"
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn credential_root_alias_keeps_its_requested_ancestor_protected()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    std::os::unix::fs::symlink(outside.path(), home.path().join(".ssh"))?;
    let protected = ProtectedPaths {
        credential_roots: vec![
            home.path()
                .join(".ssh")
                .to_str()
                .ok_or("non-UTF8 fixture")?
                .into(),
        ],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &protected)?;
    assert_eq!(grants.read_only, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(unix)]
fn credential_floor_preserves_alias_locations_under_aliased_parent_directories()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    fs::create_dir(root.path().join("physical"))?;
    std::os::unix::fs::symlink(
        root.path().join("physical"),
        root.path().join("parent-alias"),
    )?;
    let home = root.path().join("parent-alias/home");
    fs::create_dir(&home)?;
    std::os::unix::fs::symlink(outside.path(), home.join(".ssh"))?;
    for credential in [".ssh", "missing/.ssh"] {
        let protected = ProtectedPaths {
            credential_roots: vec![
                home.join(credential)
                    .to_str()
                    .ok_or("non-UTF8 fixture")?
                    .into(),
            ],
            ..ProtectedPaths::default()
        };
        let config = LocalGrantConfig {
            toolchain_homes: false,
            extra_read_only: vec!["~".into()],
            ..LocalGrantConfig::default()
        };
        let grants = resolve_hermetic(Some(&home), &config, &protected)?;
        assert_eq!(grants.read_only, Vec::<PathBuf>::new(), "{credential}");
    }
    Ok(())
}

#[test]
fn writable_extras_cannot_replace_cargo_executables_or_launch_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join(".cargo/bin"))?;
    for file in ["config.toml", "config", "env"] {
        fs::write(home.path().join(".cargo").join(file), "fixture")?;
    }
    let config = LocalGrantConfig {
        extra_read_write: ["bin", "config.toml", "config", "env"]
            .into_iter()
            .map(|entry| format!("~/.cargo/{entry}"))
            .collect(),
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &ProtectedPaths::default())?;
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn automatic_toolchain_roots_cannot_be_promoted_through_writable_descendants()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    for root in [".rustup", ".nvm", ".npm"] {
        fs::create_dir_all(home.path().join(root).join("nested"))?;
    }
    let config = LocalGrantConfig {
        extra_read_write: [".rustup", ".nvm", ".npm"]
            .into_iter()
            .map(|root| format!("~/{root}/nested"))
            .collect(),
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &ProtectedPaths::default())?;
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(unix)]
fn discovered_git_configuration_cannot_be_poisoned_via_its_target_ancestor()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let dotfiles = home.path().join("dotfiles");
    fs::create_dir(&dotfiles)?;
    fs::write(dotfiles.join("gitconfig"), "[core]\n sshCommand = ssh\n")?;
    std::os::unix::fs::symlink(dotfiles.join("gitconfig"), home.path().join(".gitconfig"))?;
    let config = LocalGrantConfig {
        extra_read_write: vec!["~/dotfiles".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &ProtectedPaths::default())?;
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn directory_extras_cannot_expose_nested_protected_components()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join("project/nested"))?;
    fs::write(home.path().join("project/nested/.npmrc"), "secret")?;
    let protected = ProtectedPaths {
        components: vec![".npmrc".into()],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~/project".into()],
        extra_read_write: vec!["~/project".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &protected)?;
    assert_eq!(grants, JailGrants::default());
    Ok(())
}

#[test]
fn directory_extras_cannot_expose_nested_protected_component_pairs()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join("project/nested/.docker"))?;
    fs::write(
        home.path().join("project/nested/.docker/config.json"),
        "secret",
    )?;
    let protected = ProtectedPaths {
        component_pairs: vec![[".docker".into(), "config.json".into()]],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~/project".into()],
        ..LocalGrantConfig::default()
    };
    assert_eq!(
        resolve_hermetic(Some(home.path()), &config, &protected)?,
        JailGrants::default()
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn aliased_directory_extras_preserve_logical_parent_component_pairs()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir(home.path().join("neutral"))?;
    fs::write(home.path().join("neutral/credentials.toml"), "secret")?;
    std::os::unix::fs::symlink(home.path().join("neutral"), home.path().join(".cargo"))?;
    let protected = ProtectedPaths {
        component_pairs: vec![[".cargo".into(), "credentials.toml".into()]],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec!["~/.cargo".into()],
        ..LocalGrantConfig::default()
    };
    assert_eq!(
        resolve_hermetic(Some(home.path()), &config, &protected)?,
        JailGrants::default()
    );
    Ok(())
}

#[test]
fn subtree_inspection_accepts_safe_trees_and_fails_closed_at_its_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("safe"), "fixture")?;
    let protected = ProtectedPaths {
        components: vec![".npmrc".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.subtree_is_clear(root.path(), root.path(), 1, 1)?);
    assert!(
        builder
            .subtree_is_clear(root.path(), root.path(), 0, 1)
            .is_err()
    );
    fs::create_dir(root.path().join("nested"))?;
    assert!(
        builder
            .subtree_is_clear(root.path(), root.path(), 2, 1)
            .is_err()
    );
    assert!(builder.subtree_is_clear(root.path(), root.path(), 2, 2)?);
    let missing = root.path().join("missing");
    assert!(
        builder
            .subtree_is_clear(&missing, &missing, 10, 10)
            .is_err()
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn subtree_inspection_does_not_follow_cycles_but_rejects_protected_symlink_names()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    std::os::unix::fs::symlink(root.path(), root.path().join("cycle"))?;
    let protected = ProtectedPaths {
        components: vec![".npmrc".into()],
        ..ProtectedPaths::default()
    };
    let builder = Builder::new(None, &protected);
    assert!(builder.subtree_is_clear(root.path(), root.path(), 1, 1)?);
    std::os::unix::fs::symlink(root.path().join("missing"), root.path().join(".npmrc"))?;
    assert!(!builder.subtree_is_clear(root.path(), root.path(), 2, 1)?);
    Ok(())
}

#[test]
#[cfg(unix)]
fn subtree_pair_protection_cannot_be_bypassed_by_a_directory_symlink()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("neutral"))?;
    fs::write(root.path().join("neutral/config.json"), "secret")?;
    std::os::unix::fs::symlink(root.path().join("neutral"), root.path().join(".docker"))?;
    let protected = ProtectedPaths {
        component_pairs: vec![[".docker".into(), "config.json".into()]],
        ..ProtectedPaths::default()
    };
    let config = LocalGrantConfig {
        toolchain_homes: false,
        extra_read_only: vec![root.path().to_str().ok_or("non-UTF8 fixture")?.into()],
        ..LocalGrantConfig::default()
    };
    assert_eq!(
        resolve_hermetic(None, &config, &protected)?,
        JailGrants::default()
    );
    Ok(())
}

#[test]
fn git_includes_strip_unquoted_comments_but_preserve_quoted_markers() {
    assert_eq!(
        include_paths(
            r#"[include]
path = ~/work.conf # local
path = other.conf ; explanation
path = "quoted#name;value.conf" # trailing
path = prefix"quoted#part"suffix.conf ; trailing
"#
        ),
        [
            "~/work.conf",
            "other.conf",
            "quoted#name;value.conf",
            "prefixquoted#partsuffix.conf"
        ]
    );
}

#[test]
fn git_include_with_a_trailing_comment_grants_the_actual_file()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::write(
        home.path().join(".gitconfig"),
        "[include]\npath = ~/work.conf # local\n",
    )?;
    fs::write(home.path().join("work.conf"), "[core]\n")?;
    let grants = resolve_hermetic(
        Some(home.path()),
        &LocalGrantConfig::default(),
        &ProtectedPaths::default(),
    )?;
    assert!(has(
        &grants.read_only,
        &canon(&home.path().join("work.conf"))?
    ));
    Ok(())
}

#[test]
#[cfg(unix)]
fn discovered_git_config_links_cannot_be_replaced_through_writable_parents()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join(".config/git"))?;
    fs::create_dir(home.path().join("dotfiles"))?;
    let target = home.path().join("dotfiles/gitconfig");
    fs::write(&target, "[core]\n")?;
    std::os::unix::fs::symlink(&target, home.path().join(".config/git/config"))?;
    let config = LocalGrantConfig {
        extra_read_write: vec!["~/.config".into(), "~/.config/git".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &ProtectedPaths::default())?;
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(unix)]
fn duplicate_git_config_targets_keep_each_discovered_alias_read_only()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir_all(home.path().join(".config/git"))?;
    fs::create_dir(home.path().join("dotfiles"))?;
    let target = home.path().join("dotfiles/gitconfig");
    fs::write(&target, "[core]\n")?;
    std::os::unix::fs::symlink(&target, home.path().join(".gitconfig"))?;
    std::os::unix::fs::symlink(&target, home.path().join(".config/git/config"))?;
    let config = LocalGrantConfig {
        extra_read_write: vec!["~/.config/git".into()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &ProtectedPaths::default())?;
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
#[cfg(unix)]
fn git_include_aliases_preserve_each_logical_sibling_location()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::write(
        home.path().join(".gitconfig"),
        "[include]\npath = one/alias\npath = two/alias\n",
    )?;
    fs::write(home.path().join("shared"), "[include]\npath = sibling\n")?;
    for directory in ["one", "two"] {
        fs::create_dir(home.path().join(directory))?;
        std::os::unix::fs::symlink(
            home.path().join("shared"),
            home.path().join(directory).join("alias"),
        )?;
        fs::write(home.path().join(directory).join("sibling"), "[core]\n")?;
    }
    let grants = resolve_hermetic(
        Some(home.path()),
        &LocalGrantConfig::default(),
        &ProtectedPaths::default(),
    )?;
    for directory in ["one", "two"] {
        assert!(
            has(
                &grants.read_only,
                &canon(&home.path().join(directory).join("sibling"))?
            ),
            "{directory}"
        );
    }
    Ok(())
}

#[test]
fn empty_xdg_config_home_does_not_grant_relative_git_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let protected = ProtectedPaths::default();
    let mut builder = Builder::new(Some(home.path()), &protected);
    builder.add_gitconfig_at(home.path(), Some(std::ffi::OsStr::new("")))?;
    // No HOME config exists. In particular, the empty value must not make
    // ambient git/config or git/ignore into candidate protected state.
    assert_eq!(
        builder.fixed_read_only,
        [
            home.path().join(".gitconfig"),
            home.path().join(".config/git/config")
        ]
    );
    assert_eq!(builder.grants, JailGrants::default());
    Ok(())
}

#[test]
fn missing_git_include_locations_cannot_be_created_from_writable_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::create_dir(home.path().join("future"))?;
    fs::write(
        home.path().join(".gitconfig"),
        "[include]\npath = future/config\n",
    )?;
    let config = LocalGrantConfig {
        extra_read_write: vec!["~/future".into()],
        ..Default::default()
    };
    let grants = resolve_hermetic(Some(home.path()), &config, &ProtectedPaths::default())?;
    assert_eq!(grants.read_write, Vec::<PathBuf>::new());
    assert!(!has(&grants.read_only, &home.path().join("future/config")));
    Ok(())
}
fn resolve_with_homes(
    home: Option<&Path>,
    rustup_home: Option<&std::ffi::OsStr>,
    cargo_home: Option<&std::ffi::OsStr>,
    cfg: &LocalGrantConfig,
    protected: &ProtectedPaths,
) -> tinybox_core::Result<JailGrants> {
    resolve_local_jail_grants_with_homes(home, None, rustup_home, cargo_home, cfg, protected)
}

#[test]
fn invalid_custom_toolchain_environment_roots_are_skipped() -> Result<(), Box<dyn std::error::Error>>
{
    let home = fake_home()?;
    fs::create_dir_all(home.path().join(".cargo/bin"))?;
    fs::write(home.path().join(".cargo/config.toml"), "")?;
    let relative_rustup = std::ffi::OsStr::new("relative-rustup");
    let missing_cargo = home.path().join("missing-cargo");
    let file_root = home.path().join("file-root");
    fs::write(&file_root, "fixture")?;
    for (rustup, cargo) in [
        (
            Some(std::ffi::OsStr::new("")),
            Some(std::ffi::OsStr::new("")),
        ),
        (Some(relative_rustup), Some(relative_rustup)),
        (Some(file_root.as_os_str()), Some(file_root.as_os_str())),
        (
            Some(missing_cargo.as_os_str()),
            Some(missing_cargo.as_os_str()),
        ),
    ] {
        let grants = resolve_with_homes(
            Some(home.path()),
            rustup,
            cargo,
            &LocalGrantConfig::default(),
            &ProtectedPaths::default(),
        )?;
        let canonical_home = home.path().canonicalize()?;
        assert!(
            has(&grants.read_only, &canonical_home.join(".rustup")),
            "default Rustup home disappeared: {grants:?}"
        );
        assert!(
            has(&grants.read_only, &canonical_home.join(".cargo/bin")),
            "default Cargo bin disappeared: {grants:?}"
        );
        assert!(
            has(
                &grants.read_only,
                &canonical_home.join(".cargo/config.toml")
            ),
            "default Cargo config disappeared: {grants:?}"
        );
        assert!(
            !grants
                .read_only
                .iter()
                .any(|path| path.ends_with("relative-rustup")),
            "relative root was admitted: {grants:?}"
        );
    }
    Ok(())
}

#[test]
fn custom_cargo_credentials_are_excluded_by_the_protected_floor()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let rustup = home.path().join("custom-rustup");
    let cargo = home.path().join("custom-cargo");
    fs::create_dir(&rustup)?;
    fs::create_dir_all(cargo.join("bin"))?;
    fs::create_dir_all(cargo.join("registry"))?;
    fs::create_dir_all(cargo.join("git"))?;
    fs::write(cargo.join("registry/credentials.toml"), "secret")?;
    let protected = ProtectedPaths {
        components: vec!["credentials.toml".into()],
        ..ProtectedPaths::default()
    };
    let grants = resolve_with_homes(
        Some(home.path()),
        Some(rustup.as_os_str()),
        Some(cargo.as_os_str()),
        &LocalGrantConfig::default(),
        &protected,
    )?;
    let cargo = cargo.canonicalize()?;
    assert!(
        !has(&grants.read_only, &cargo.join("registry")),
        "Cargo subtree containing credentials was admitted: {grants:?}"
    );
    assert!(
        !grants
            .read_only
            .iter()
            .any(|path| path.ends_with("credentials.toml")),
        "credential file was granted: {grants:?}"
    );
    Ok(())
}

#[test]
fn writable_extras_cannot_promote_custom_toolchain_roots_or_selected_cargo_state()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let rustup = home.path().join("custom-rustup");
    let cargo = home.path().join("custom-cargo");
    fs::create_dir_all(rustup.join("toolchains/stable"))?;
    fs::create_dir_all(cargo.join("bin"))?;
    fs::create_dir_all(cargo.join("registry/src"))?;
    fs::create_dir_all(cargo.join("git"))?;
    let config = LocalGrantConfig {
        extra_read_only: vec![cargo.to_string_lossy().into_owned()],
        extra_read_write: vec![
            home.path().to_string_lossy().into_owned(),
            rustup.to_string_lossy().into_owned(),
            rustup.join("toolchains").to_string_lossy().into_owned(),
            cargo.to_string_lossy().into_owned(),
            cargo.join("bin").to_string_lossy().into_owned(),
            cargo.join("registry").to_string_lossy().into_owned(),
            cargo.join("registry/src").to_string_lossy().into_owned(),
            cargo.join("git").to_string_lossy().into_owned(),
        ],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_with_homes(
        Some(home.path()),
        Some(rustup.as_os_str()),
        Some(cargo.as_os_str()),
        &config,
        &ProtectedPaths::default(),
    )?;
    assert!(
        !has(&grants.read_only, &cargo.canonicalize()?),
        "whole Cargo root was granted by an extra: {grants:?}"
    );
    assert!(
        grants.read_write.is_empty(),
        "writable extras promoted fixed toolchain state: {grants:?}"
    );
    Ok(())
}

#[test]
fn safe_explicit_cargo_children_keep_their_requested_access()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let cargo = home.path().join("custom-cargo");
    let read_only = cargo.join("private-extension/read-only");
    let read_write = cargo.join("private-extension/read-write");
    fs::create_dir_all(cargo.join("bin"))?;
    fs::create_dir_all(&read_only)?;
    fs::create_dir_all(&read_write)?;
    let config = LocalGrantConfig {
        extra_read_only: vec![read_only.to_string_lossy().into_owned()],
        extra_read_write: vec![read_write.to_string_lossy().into_owned()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_with_homes(
        Some(home.path()),
        None,
        Some(cargo.as_os_str()),
        &config,
        &ProtectedPaths::default(),
    )?;
    assert!(
        has(&grants.read_only, &read_only.canonicalize()?),
        "safe Cargo child read-only extra was refused: {grants:?}"
    );
    assert!(
        has(&grants.read_write, &read_write.canonicalize()?),
        "safe Cargo child writable extra was refused: {grants:?}"
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn extra_read_only_symlink_to_whole_cargo_root_is_refused() -> Result<(), Box<dyn std::error::Error>>
{
    let home = tempfile::tempdir()?;
    let cargo = home.path().join("custom-cargo");
    let alias = home.path().join("unregistered-cargo-root-alias");
    fs::create_dir_all(cargo.join("bin"))?;
    std::os::unix::fs::symlink(&cargo, &alias)?;
    let config = LocalGrantConfig {
        extra_read_only: vec![alias.to_string_lossy().into_owned()],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_with_homes(
        Some(home.path()),
        None,
        Some(cargo.as_os_str()),
        &config,
        &ProtectedPaths::default(),
    )?;
    assert!(
        !has(&grants.read_only, &cargo.canonicalize()?),
        "symlink extra exposed whole Cargo root: {grants:?}"
    );
    assert!(
        has(&grants.read_only, &cargo.join("bin").canonicalize()?),
        "fixed Cargo bin grant was lost: {grants:?}"
    );
    Ok(())
}
#[test]
#[cfg(unix)]
fn custom_toolchain_symlink_aliases_cannot_be_promoted_to_writable()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let rustup = home.path().join("custom-rustup");
    let cargo = home.path().join("custom-cargo");
    fs::create_dir_all(rustup.join("toolchains/stable"))?;
    fs::create_dir_all(cargo.join("bin"))?;
    std::os::unix::fs::symlink(&rustup, home.path().join("rustup-alias"))?;
    std::os::unix::fs::symlink(&cargo, home.path().join("cargo-alias"))?;
    let config = LocalGrantConfig {
        extra_read_write: vec![
            home.path()
                .join("rustup-alias/toolchains")
                .to_string_lossy()
                .into_owned(),
            home.path()
                .join("cargo-alias/bin")
                .to_string_lossy()
                .into_owned(),
        ],
        ..LocalGrantConfig::default()
    };
    let grants = resolve_with_homes(
        Some(home.path()),
        Some(home.path().join("rustup-alias").as_os_str()),
        Some(home.path().join("cargo-alias").as_os_str()),
        &config,
        &ProtectedPaths::default(),
    )?;
    assert!(
        grants.read_write.is_empty(),
        "symlink alias promoted fixed toolchain state: {grants:?}"
    );
    Ok(())
}

#[test]
fn rejected_custom_rustup_root_still_blocks_writable_descendants()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let rustup = home.path().join("custom-rustup");
    fs::create_dir_all(rustup.join("toolchains/stable"))?;
    fs::write(rustup.join(".private-marker"), "protected")?;
    let config = LocalGrantConfig {
        extra_read_write: vec![rustup.join("toolchains").to_string_lossy().into_owned()],
        ..LocalGrantConfig::default()
    };
    let protected = ProtectedPaths {
        components: vec![".private-marker".into()],
        ..ProtectedPaths::default()
    };
    let grants = resolve_with_homes(
        Some(home.path()),
        Some(rustup.as_os_str()),
        None,
        &config,
        &protected,
    )?;
    assert!(
        !has(&grants.read_only, &rustup.canonicalize()?),
        "protected Rustup root was granted: {grants:?}"
    );
    assert!(
        grants.read_write.is_empty(),
        "writable extra promoted a descendant of the rejected Rustup root: {grants:?}"
    );
    Ok(())
}
