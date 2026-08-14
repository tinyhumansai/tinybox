//! Deciding what not to send.
//!
//! The cheapest large win available to a workspace runtime: a repository's
//! build output is usually most of its bytes and none of its value. A Rust
//! checkout's `target/` or a Node one's `node_modules/` routinely dwarfs the
//! source, and every one of those bytes crosses the network on the first sync
//! and gets hashed on every one after.
//!
//! The list is not invented. `.gitignore` already records what a project
//! considers derived, maintained by people who care about it, so it is read
//! rather than guessed at — and a `.boxignore` beside it can add or override
//! for the cases where the two genuinely differ, such as a `.env` that git
//! ignores but a running box needs.
//!
//! # Why not a hand-rolled matcher
//!
//! Gitignore semantics are more than globs: negation with `!`, anchoring on a
//! leading or embedded `/`, directory-only patterns with a trailing `/`, `**`
//! spanning directories, per-directory files whose scope is their own subtree,
//! and precedence between all of it. A subset that is *nearly* right silently
//! drops files a caller expected to send, which is worse than sending too many.
//! So the crate that already implements it exactly is used instead.

use std::path::{Path, PathBuf};

use ignore::gitignore::{Gitignore, GitignoreBuilder};
use tinybox_core::{Error, Result};

/// The file a workspace uses to adjust what tinybox sends.
///
/// Read after `.gitignore`, so its rules win — including `!` lines that put
/// back something git ignores.
pub const BOXIGNORE: &str = ".boxignore";

/// The file tinybox reads to learn what a project considers derived.
pub const GITIGNORE: &str = ".gitignore";

/// What a workspace has asked tinybox to leave behind.
#[derive(Debug, Clone)]
pub struct Exclusions {
    matcher: Gitignore,
    sources: Vec<PathBuf>,
}

impl Exclusions {
    /// Read `.gitignore` and `.boxignore` from the root of `workspace`.
    ///
    /// Neither file has to exist; a workspace with no ignore rules excludes
    /// nothing. Only the root files are read, not nested ones — see
    /// [`Exclusions::sources`] for why that is a documented limit rather than
    /// an oversight.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when a rule cannot be parsed, naming the file
    /// and the rule. A malformed pattern is reported rather than skipped: a
    /// silently ignored rule is how a secret ends up being sent.
    pub fn read(workspace: impl AsRef<Path>) -> Result<Self> {
        let workspace = workspace.as_ref();
        let mut builder = GitignoreBuilder::new(workspace);
        let mut sources = Vec::new();

        // Order matters: later rules win, so `.boxignore` can override
        // `.gitignore` rather than merely adding to it.
        for name in [GITIGNORE, BOXIGNORE] {
            let path = workspace.join(name);
            if !path.is_file() {
                continue;
            }
            if let Some(error) = builder.add(&path) {
                return Err(Error::Store {
                    operation: "parse",
                    message: format!("{}: {error}", path.display()),
                });
            }
            sources.push(path);
        }

        let matcher = builder.build().map_err(|error| Error::Store {
            operation: "parse",
            message: format!("{}: {error}", workspace.display()),
        })?;

        Ok(Self { matcher, sources })
    }

    /// Exclude nothing.
    ///
    /// What a caller gets by asking for no exclusions at all, and what makes
    /// "send everything" an explicit choice rather than the absence of one.
    #[must_use]
    pub fn none() -> Self {
        Self {
            matcher: Gitignore::empty(),
            sources: Vec::new(),
        }
    }

    /// Which ignore files were actually read.
    ///
    /// Only the ones at the workspace root. Git also honors a `.gitignore` in
    /// every subdirectory, and tinybox does not: the transfer is of one tree to
    /// one destination, and a nested rule set would make the fingerprint depend
    /// on files that are themselves being filtered. Worth knowing when a
    /// project's rules live deeper than its root.
    #[must_use]
    pub fn sources(&self) -> &[PathBuf] {
        &self.sources
    }

    /// Whether anything is excluded at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matcher.is_empty()
    }

    /// Whether `relative` should be left behind.
    ///
    /// `is_dir` matters because a trailing-slash pattern matches directories
    /// only; getting it wrong would make `build/` fail to match a directory
    /// called `build`.
    #[must_use]
    pub fn excludes(&self, relative: &Path, is_dir: bool) -> bool {
        self.matcher
            .matched_path_or_any_parents(relative, is_dir)
            .is_ignore()
    }
}

#[cfg(test)]
mod test;
