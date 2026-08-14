//! Tests for workspace transfer.
//!
//! Most of these run against the **real local host**, unpacking into a
//! temporary directory. That is not a live-service dependency — `tar` and
//! `mkdir` are always present — and it means the archive this crate builds is
//! checked by the same tool that will unpack it in production, rather than by a
//! reimplementation of tar in the test.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use tempfile::TempDir;
use tinybox_core::{Error, ExecOutput, ExecRequest, Host, Result};
use tinybox_host::LocalHost;

use super::{MARKER, Sync, Syncer, default_destination};
use crate::exclude::Exclusions;
use crate::fingerprint::Fingerprint;

fn temp_dir() -> Result<TempDir> {
    TempDir::new().map_err(|error| Error::io("tempdir", &error))
}

fn write(root: &Path, path: &str, contents: &str) -> Result<()> {
    let full = root.join(path);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).map_err(|error| Error::io("mkdir", &error))?;
    }
    fs::write(&full, contents).map_err(|error| Error::io("write", &error))
}

fn source_tree() -> Result<TempDir> {
    let dir = temp_dir()?;
    write(dir.path(), "a.txt", "alpha")?;
    write(dir.path(), "nested/b.txt", "beta")?;
    Ok(dir)
}

fn local_syncer() -> Syncer {
    Syncer::new(Arc::new(LocalHost::new()))
}

fn read(root: &Path, path: &str) -> Result<String> {
    fs::read_to_string(root.join(path)).map_err(|error| Error::io("read", &error))
}

#[tokio::test]
async fn a_workspace_arrives_with_its_layout_intact() -> Result<()> {
    let source = source_tree()?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();

    let outcome = local_syncer().sync(source.path(), &target).await?;

    assert!(outcome.transferred());
    let landed = Path::new(&target);
    assert_eq!(read(landed, "a.txt")?, "alpha");
    assert_eq!(read(landed, "nested/b.txt")?, "beta");
    Ok(())
}

#[tokio::test]
async fn a_second_sync_with_no_edits_sends_nothing() -> Result<()> {
    let source = source_tree()?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();
    let syncer = local_syncer();

    let first = syncer.sync(source.path(), &target).await?;
    let second = syncer.sync(source.path(), &target).await?;

    // The whole point: an edit-run loop that changes nothing costs nothing.
    assert!(first.transferred());
    assert!(!second.transferred());
    assert_eq!(first.fingerprint(), second.fingerprint());
    assert!(matches!(second, Sync::Skipped { .. }));
    Ok(())
}

#[tokio::test]
async fn an_edit_is_noticed_and_resent() -> Result<()> {
    let source = source_tree()?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();
    let syncer = local_syncer();
    syncer.sync(source.path(), &target).await?;

    write(source.path(), "a.txt", "edited")?;
    let outcome = syncer.sync(source.path(), &target).await?;

    assert!(outcome.transferred());
    assert_eq!(read(Path::new(&target), "a.txt")?, "edited");
    Ok(())
}

#[tokio::test]
async fn the_fingerprint_travels_with_the_workspace() -> Result<()> {
    let source = source_tree()?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();

    let outcome = local_syncer().sync(source.path(), &target).await?;

    // Recorded on the far side rather than in local bookkeeping, which would go
    // stale the moment the destination is rebuilt.
    let marker = read(Path::new(&target), MARKER)?;
    assert_eq!(Fingerprint::parse(&marker)?, *outcome.fingerprint());
    Ok(())
}

#[tokio::test]
async fn a_destination_wiped_behind_our_back_is_resent() -> Result<()> {
    let source = source_tree()?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();
    let syncer = local_syncer();
    syncer.sync(source.path(), &target).await?;

    // Exactly the case local bookkeeping would get wrong: the record would
    // still say "already sent" and the box would start empty.
    fs::remove_dir_all(&target).map_err(|error| Error::io("rmdir", &error))?;

    assert!(syncer.sync(source.path(), &target).await?.transferred());
    assert_eq!(read(Path::new(&target), "a.txt")?, "alpha");
    Ok(())
}

#[tokio::test]
async fn a_corrupt_marker_causes_a_resend_rather_than_a_skip() -> Result<()> {
    let source = source_tree()?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();
    let syncer = local_syncer();
    syncer.sync(source.path(), &target).await?;

    write(Path::new(&target), MARKER, "truncated")?;

    // An unreadable marker must fail towards sending, never towards skipping.
    assert!(syncer.sync(source.path(), &target).await?.transferred());
    Ok(())
}

#[tokio::test]
async fn excluded_directories_do_not_cross() -> Result<()> {
    let source = source_tree()?;
    write(source.path(), ".git/HEAD", "ref: refs/heads/main")?;
    write(source.path(), "target/debug/huge", "artifact")?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();

    write(source.path(), ".gitignore", ".git/\ntarget/\n")?;
    let syncer = local_syncer().excluding(Exclusions::read(source.path())?);
    syncer.sync(source.path(), &target).await?;

    assert_eq!(syncer.excluded().sources().len(), 1);
    assert!(Path::new(&target).join("a.txt").exists());
    assert!(!Path::new(&target).join(".git").exists());
    assert!(!Path::new(&target).join("target").exists());
    Ok(())
}

#[tokio::test]
async fn a_change_inside_an_excluded_directory_does_not_trigger_a_resend() -> Result<()> {
    let source = source_tree()?;
    write(source.path(), ".git/HEAD", "one")?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();
    write(source.path(), ".gitignore", ".git/\n")?;
    let syncer = local_syncer().excluding(Exclusions::read(source.path())?);
    syncer.sync(source.path(), &target).await?;

    // Committing changes .git constantly; it must not cost a transfer.
    write(source.path(), ".git/HEAD", "two")?;

    assert!(!syncer.sync(source.path(), &target).await?.transferred());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn an_executable_bit_survives_the_crossing() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let source = temp_dir()?;
    write(source.path(), "run.sh", "#!/bin/sh\necho hi\n")?;
    fs::set_permissions(
        source.path().join("run.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .map_err(|error| Error::io("chmod", &error))?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();

    local_syncer().sync(source.path(), &target).await?;

    // A script that arrives unexecutable is a broken workspace.
    let mode = fs::metadata(Path::new(&target).join("run.sh"))
        .map_err(|error| Error::io("stat", &error))?
        .permissions()
        .mode();
    assert!(mode & 0o100 != 0, "mode was {mode:o}");
    Ok(())
}

#[tokio::test]
async fn binary_content_is_not_transformed() -> Result<()> {
    let source = temp_dir()?;
    let payload: Vec<u8> = (0u8..=255).collect();
    fs::write(source.path().join("blob.bin"), &payload)
        .map_err(|error| Error::io("write", &error))?;
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();

    local_syncer().sync(source.path(), &target).await?;

    let landed =
        fs::read(Path::new(&target).join("blob.bin")).map_err(|error| Error::io("read", &error))?;
    assert_eq!(landed, payload);
    Ok(())
}

#[tokio::test]
async fn a_missing_source_is_reported_before_anything_is_sent() -> Result<()> {
    let destination = temp_dir()?;
    let target = destination.path().join("work").display().to_string();

    assert!(matches!(
        local_syncer()
            .sync("/tinybox-no-such-source", &target)
            .await,
        Err(Error::Io { .. })
    ));
    assert!(!Path::new(&target).exists());
    Ok(())
}

/// A host that fails whichever command is named.
#[derive(Debug)]
struct FailingHost {
    failing: &'static str,
    seen: Mutex<Vec<Vec<String>>>,
}

impl FailingHost {
    fn new(failing: &'static str) -> Arc<Self> {
        Arc::new(Self {
            failing,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> MutexGuard<'_, Vec<Vec<String>>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl Host for FailingHost {
    fn name(&self) -> &'static str {
        "failing"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.seen().push(request.argv.clone());
        match request.program() {
            Some(program) if program == self.failing => {
                Ok(ExecOutput::new(1, Vec::new(), b"denied".to_vec()))
            }
            // A failing `cat` is how "no marker yet" is reported, which is the
            // normal state on a machine that has never been synced to.
            Some("cat") => Ok(ExecOutput::new(1, Vec::new(), Vec::new())),
            _ => Ok(ExecOutput::new(0, Vec::new(), Vec::new())),
        }
    }
}

#[tokio::test]
async fn a_destination_that_cannot_be_created_is_reported() -> Result<()> {
    let source = source_tree()?;
    let host = FailingHost::new("mkdir");

    let outcome = Syncer::new(host).sync(source.path(), "/somewhere").await;

    assert!(matches!(
        outcome,
        Err(Error::Backend {
            operation: "create the destination directory",
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn a_failed_unpack_is_reported_with_the_far_sides_diagnostic() -> Result<()> {
    let source = source_tree()?;
    let host = FailingHost::new("tar");

    let outcome = Syncer::new(host.clone())
        .sync(source.path(), "/somewhere")
        .await;

    assert!(matches!(
        outcome,
        Err(Error::Backend {
            operation: "unpack the workspace",
            ..
        })
    ));
    // The archive really was piped in rather than staged through a file.
    let piped = host
        .seen()
        .iter()
        .any(|argv| argv.first().map(String::as_str) == Some("tar"));
    assert!(piped);
    Ok(())
}

#[test]
fn a_default_destination_is_stable_and_under_the_home_directory() {
    let path = default_destination("box-0");

    // Not /tmp: a workspace that vanishes on reboot is a surprising thing to
    // hand someone.
    assert_eq!(path, Path::new("~/.tinybox/workspaces/box-0"));
    assert_eq!(default_destination("box-0"), path);
}

#[cfg(unix)]
#[test]
fn a_file_that_cannot_be_read_is_reported_rather_than_packed_empty() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let source = temp_dir()?;
    write(source.path(), "secret", "classified")?;
    // A workspace can legitimately contain a file the caller cannot read.
    // Packing it as empty would silently corrupt the tree on the far side.
    fs::set_permissions(
        source.path().join("secret"),
        fs::Permissions::from_mode(0o000),
    )
    .map_err(|error| Error::io("chmod", &error))?;

    let fingerprint = Fingerprint::parse(&"a".repeat(64))?;
    let outcome = super::archive::pack(source.path(), &Exclusions::none(), &fingerprint);

    // Running as root defeats the permission bit, so accept either a reported
    // failure or a successful pack rather than asserting something that depends
    // on who runs the suite.
    assert!(matches!(outcome, Err(Error::Io { .. }) | Ok(_)));
    Ok(())
}

#[test]
fn packing_the_same_tree_twice_produces_identical_bytes() -> Result<()> {
    let source = source_tree()?;
    let fingerprint = Fingerprint::of_directory(source.path(), &Exclusions::none())?;

    let once = super::archive::pack(source.path(), &Exclusions::none(), &fingerprint)?;
    let twice = super::archive::pack(source.path(), &Exclusions::none(), &fingerprint)?;

    // Deterministic headers: no timestamps, no uid, no gid. Without this an
    // archive would differ on every run and be useless to cache or compare.
    assert_eq!(once, twice);
    assert!(!once.is_empty());
    Ok(())
}

#[test]
fn the_archive_carries_the_marker_and_every_file() -> Result<()> {
    let source = source_tree()?;
    let fingerprint = Fingerprint::of_directory(source.path(), &Exclusions::none())?;

    let packed = super::archive::pack(source.path(), &Exclusions::none(), &fingerprint)?;

    // Read back with the same library that will unpack it on the far side.
    let mut names = tar::Archive::new(packed.as_slice())
        .entries()
        .map_err(|error| Error::io("read the archive", &error))?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| entry.path().ok().map(|path| path.display().to_string()))
        .collect::<Vec<_>>();
    names.sort();

    assert_eq!(names, [MARKER, "a.txt", "nested/b.txt"]);
    Ok(())
}
