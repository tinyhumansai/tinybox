//! Tests for workspace exclusions.
//!
//! These lean on the cases a hand-rolled matcher gets wrong — negation,
//! anchoring, directory-only patterns, `**` — because getting them wrong means
//! silently not sending a file somebody expected to send.

use std::fs;
use std::path::Path;

use tempfile::TempDir;
use tinybox_core::{Error, Result};

use super::{BOXIGNORE, Exclusions, GITIGNORE};

fn temp_dir() -> Result<TempDir> {
    TempDir::new().map_err(|error| Error::io("tempdir", &error))
}

/// A workspace with the given ignore files written at its root.
fn workspace(files: &[(&str, &str)]) -> Result<TempDir> {
    let dir = temp_dir()?;
    for (name, contents) in files {
        fs::write(dir.path().join(name), contents).map_err(|error| Error::io("write", &error))?;
    }
    Ok(dir)
}

/// Whether `path` is excluded, as a file.
fn excludes_file(exclusions: &Exclusions, path: &str) -> bool {
    exclusions.excludes(Path::new(path), false)
}

/// Whether `path` is excluded, as a directory.
fn excludes_dir(exclusions: &Exclusions, path: &str) -> bool {
    exclusions.excludes(Path::new(path), true)
}

#[test]
fn a_workspace_with_no_ignore_files_excludes_nothing() -> Result<()> {
    let dir = temp_dir()?;

    let exclusions = Exclusions::read(dir.path())?;

    assert!(exclusions.is_empty());
    assert!(exclusions.sources().is_empty());
    assert!(!excludes_file(&exclusions, "anything.txt"));
    Ok(())
}

#[test]
fn nothing_is_excluded_unless_asked_for() {
    let exclusions = Exclusions::none();

    // Sending everything stays an explicit choice rather than the absence of
    // one.
    assert!(exclusions.is_empty());
    assert!(!excludes_dir(&exclusions, "target"));
    assert!(!excludes_file(&exclusions, ".env"));
}

#[test]
fn gitignore_rules_are_honored() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "target/\nnode_modules/\n*.log\n")])?;

    let exclusions = Exclusions::read(dir.path())?;

    // The bytes that dwarf a checkout, left behind without anyone listing them.
    assert!(excludes_dir(&exclusions, "target"));
    assert!(excludes_dir(&exclusions, "node_modules"));
    assert!(excludes_file(&exclusions, "build.log"));
    assert!(!excludes_file(&exclusions, "src/main.rs"));
    assert_eq!(exclusions.sources().len(), 1);
    Ok(())
}

#[test]
fn a_directory_only_pattern_does_not_match_a_file() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "build/\n")])?;
    let exclusions = Exclusions::read(dir.path())?;

    // The trailing slash is the whole difference, and a matcher that ignores it
    // would drop a file called `build`.
    assert!(excludes_dir(&exclusions, "build"));
    assert!(!excludes_file(&exclusions, "build"));
    Ok(())
}

#[test]
fn a_negation_puts_a_file_back() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "*.log\n!keep.log\n")])?;
    let exclusions = Exclusions::read(dir.path())?;

    assert!(excludes_file(&exclusions, "build.log"));
    // The case a naive glob list cannot express at all.
    assert!(!excludes_file(&exclusions, "keep.log"));
    Ok(())
}

#[test]
fn an_anchored_pattern_matches_only_at_the_root() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "/config.toml\n")])?;
    let exclusions = Exclusions::read(dir.path())?;

    assert!(excludes_file(&exclusions, "config.toml"));
    // A leading slash anchors; without honoring it, a nested config would
    // vanish too.
    assert!(!excludes_file(&exclusions, "nested/config.toml"));
    Ok(())
}

#[test]
fn an_unanchored_pattern_matches_at_any_depth() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "secrets.txt\n")])?;
    let exclusions = Exclusions::read(dir.path())?;

    assert!(excludes_file(&exclusions, "secrets.txt"));
    assert!(excludes_file(&exclusions, "deep/nested/secrets.txt"));
    Ok(())
}

#[test]
fn a_double_star_spans_directories() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "docs/**/generated\n")])?;
    let exclusions = Exclusions::read(dir.path())?;

    assert!(excludes_dir(&exclusions, "docs/a/b/generated"));
    assert!(!excludes_dir(&exclusions, "other/generated"));
    Ok(())
}

#[test]
fn a_file_inside_an_excluded_directory_is_excluded_too() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "target/\n")])?;
    let exclusions = Exclusions::read(dir.path())?;

    // Matching parents matters: the walk asks about the directory, but a
    // caller checking a leaf path directly must get the same answer.
    assert!(excludes_file(&exclusions, "target/debug/binary"));
    Ok(())
}

#[test]
fn boxignore_is_read_alongside_gitignore() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "target/\n"), (BOXIGNORE, "scratch/\n")])?;

    let exclusions = Exclusions::read(dir.path())?;

    assert!(excludes_dir(&exclusions, "target"));
    assert!(excludes_dir(&exclusions, "scratch"));
    assert_eq!(exclusions.sources().len(), 2);
    Ok(())
}

#[test]
fn boxignore_can_put_back_something_git_ignores() -> Result<()> {
    // The case the second file exists for: git ignores `.env` because it should
    // not be committed, but a box that has to run the code needs it.
    let dir = workspace(&[(GITIGNORE, ".env\n"), (BOXIGNORE, "!.env\n")])?;

    let exclusions = Exclusions::read(dir.path())?;

    assert!(!excludes_file(&exclusions, ".env"));
    Ok(())
}

#[test]
fn boxignore_alone_works_without_a_gitignore() -> Result<()> {
    let dir = workspace(&[(BOXIGNORE, "big/\n")])?;

    let exclusions = Exclusions::read(dir.path())?;

    assert!(excludes_dir(&exclusions, "big"));
    assert_eq!(exclusions.sources().len(), 1);
    Ok(())
}

#[test]
fn comments_and_blank_lines_are_ignored() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "# a comment\n\n   \ntarget/\n")])?;

    let exclusions = Exclusions::read(dir.path())?;

    assert!(excludes_dir(&exclusions, "target"));
    assert!(!excludes_file(&exclusions, "# a comment"));
    Ok(())
}

#[test]
fn a_directory_named_like_an_ignore_file_is_not_read_as_one() -> Result<()> {
    let dir = temp_dir()?;
    fs::create_dir(dir.path().join(GITIGNORE)).map_err(|error| Error::io("mkdir", &error))?;

    // `is_file` rather than `exists`, or this would try to parse a directory.
    let exclusions = Exclusions::read(dir.path())?;

    assert!(exclusions.is_empty());
    Ok(())
}

#[test]
fn a_missing_workspace_reads_as_no_exclusions() -> Result<()> {
    // A directory that does not exist has no ignore files, which is not an
    // error here — the caller will fail on its own when it tries to read it.
    let exclusions = Exclusions::read("/tinybox-no-such-workspace")?;

    assert!(exclusions.is_empty());
    Ok(())
}

#[test]
fn a_malformed_pattern_is_reported_rather_than_skipped() -> Result<()> {
    // An unclosed brace. Skipping a rule tinybox could not parse is how a file
    // somebody meant to exclude ends up being sent instead.
    let dir = workspace(&[(GITIGNORE, "**/*{\n")])?;

    let outcome = Exclusions::read(dir.path());

    assert!(
        matches!(
            outcome,
            Err(Error::Store {
                operation: "parse",
                ..
            })
        ),
        "a malformed pattern should be reported"
    );
    Ok(())
}

#[test]
fn a_malformed_boxignore_is_reported_too() -> Result<()> {
    let dir = workspace(&[(GITIGNORE, "target/\n"), (BOXIGNORE, "**/*{\n")])?;

    assert!(matches!(
        Exclusions::read(dir.path()),
        Err(Error::Store {
            operation: "parse",
            ..
        })
    ));
    Ok(())
}
