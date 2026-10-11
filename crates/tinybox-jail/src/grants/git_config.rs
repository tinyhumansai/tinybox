//! Bounded Git configuration include discovery.
use super::Builder;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Deepest `include` chain followed when collecting git config files.
const GITCONFIG_MAX_DEPTH: usize = 10;

impl Builder<'_> {
    /// Read-only grants for the user's git config files and everything they
    /// `include`, each canonicalized (a config is often a symlink into a
    /// dotfiles repo, and the jail needs the target).
    pub(super) fn add_gitconfig(&mut self, home: &Path) -> tinybox_core::Result<()> {
        self.add_gitconfig_at(home, std::env::var_os("XDG_CONFIG_HOME").as_deref())
    }

    pub(super) fn add_gitconfig_at(
        &mut self,
        home: &Path,
        xdg: Option<&std::ffi::OsStr>,
    ) -> tinybox_core::Result<()> {
        let config_root = xdg_root(xdg)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| home.join(".config"));
        let roots = [home.join(".gitconfig"), config_root.join("git/config")];
        self.fixed_read_only(&home.join(".config/git/ignore"), "gitignore");
        if let Some(xdg) = xdg_root(xdg) {
            self.fixed_read_only(&Path::new(&xdg).join("git/ignore"), "gitignore");
        }
        let mut visited = HashSet::new();
        for root in roots {
            self.add_gitconfig_file(&root, home, 0, &mut visited)?;
        }
        Ok(())
    }

    fn add_gitconfig_file(
        &mut self,
        file: &Path,
        home: &Path,
        depth: usize,
        visited: &mut HashSet<(PathBuf, PathBuf)>,
    ) -> tinybox_core::Result<()> {
        // Missing include targets still affect future host Git execution.
        // Reserve their logical locations without granting absent files.
        self.fixed_read_only.push(file.to_path_buf());
        let Some(canonical) = self.admit(file, "gitconfig") else {
            return Ok(());
        };
        if !canonical.is_file() {
            return Ok(());
        }
        // Protect each requested link location, even when multiple configs
        // resolve to one target. A writable parent could replace that link.
        self.fixed_read_only(file, "gitconfig");
        let base = file.parent().unwrap_or(home);
        let location = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
        if !visited.insert((canonical.clone(), location)) || depth >= GITCONFIG_MAX_DEPTH {
            return Ok(());
        }
        let Ok(text) = std::fs::read_to_string(&canonical) else {
            return Ok(());
        };
        // Relative includes resolve against the directory of the file *as
        // named*, which for a symlinked config is the link's directory.
        for target in include_paths(&text) {
            let resolved = if let Some(rest) = target.strip_prefix("~/") {
                home.join(rest)
            } else if target.starts_with('~') || target.starts_with("%(prefix)") {
                return Err(tinybox_core::Error::UnsupportedGitIncludePath);
            } else if Path::new(&target).is_absolute() {
                PathBuf::from(&target)
            } else {
                base.join(&target)
            };
            self.add_gitconfig_file(&resolved, home, depth + 1, visited)?;
        }
        Ok(())
    }
}

/// `path = …` values inside `[include]` / `[includeIf …]` sections.
pub(super) fn include_paths(config: &str) -> Vec<String> {
    let mut in_include = false;
    let mut out = Vec::new();
    for line in logical_lines(config) {
        let mut line = line.trim();
        if let Some(section) = line.strip_prefix('[') {
            let mut quoted = false;
            let mut escaped = false;
            let end = section.char_indices().find_map(|(index, ch)| {
                if escaped {
                    escaped = false;
                } else {
                    match ch {
                        '\\' => escaped = true,
                        '"' => quoted = !quoted,
                        ']' if !quoted => return Some(index),
                        _ => {}
                    }
                }
                None
            });
            let Some(end) = end else {
                in_include = false;
                continue;
            };
            let name = section[..end].split([' ', '\t', '"']).next().unwrap_or("");
            in_include =
                name.eq_ignore_ascii_case("include") || name.eq_ignore_ascii_case("includeif");
            line = section[end + 1..].trim_start();
        }
        if !in_include {
            continue;
        }
        if let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("path")
            && let Some(value) = include_value(value)
        {
            out.push(value);
        }
    }
    out
}

// Git removes a backslash immediately before a newline, including in quoted
// values. Comments and escaped backslashes do not continue the next line.
fn logical_lines(config: &str) -> Vec<String> {
    let mut lines = config.lines().peekable();
    let mut out = Vec::new();
    let mut logical = String::new();
    while let Some(line) = lines.next() {
        logical.push_str(line);
        let mut quoted = false;
        let mut escaped = false;
        for ch in logical.chars() {
            if escaped {
                escaped = false;
            } else {
                match ch {
                    '\\' => escaped = true,
                    '"' => quoted = !quoted,
                    '#' | ';' if !quoted => {
                        escaped = false;
                        break;
                    }
                    _ => {}
                }
            }
        }
        if escaped && lines.peek().is_some() {
            logical.pop();
        } else {
            out.push(std::mem::take(&mut logical));
        }
    }
    out
}

// Git comments begin only outside double quotes. Decode Git's supported
// escapes and reject malformed values instead of inventing filesystem paths.
fn include_value(value: &str) -> Option<String> {
    let mut chars = value.trim_start().chars();
    let mut quoted = false;
    let mut out = String::new();
    let mut significant = 0;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => quoted = !quoted,
            '#' | ';' if !quoted => break,
            '\\' => {
                let decoded = match chars.next()? {
                    'n' => '\n',
                    't' => '\t',
                    'b' => '\u{0008}',
                    '\\' => '\\',
                    '"' => '"',
                    _ => return None,
                };
                out.push(decoded);
                significant = out.len();
            }
            _ => {
                out.push(ch);
                if quoted || !ch.is_whitespace() {
                    significant = out.len();
                }
            }
        }
    }
    if quoted {
        return None;
    }
    out.truncate(significant);
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
#[path = "git_config_tests.rs"]
mod tests;

fn xdg_root(value: Option<&std::ffi::OsStr>) -> Option<&Path> {
    value.map(Path::new).filter(|path| path.is_absolute())
}
