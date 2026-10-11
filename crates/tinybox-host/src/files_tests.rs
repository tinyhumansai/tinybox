//! Tests for confined workspace file handles.

use super::{LocalFileWriter, begin_writer, open_reader, open_root};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tinybox_core::{Error, Result, WorkspaceFileWriter};

#[tokio::test]
async fn reads_bounded_binary_ranges_from_the_workspace() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    std::fs::write(directory.path().join("report.bin"), [0, 1, 2, 255])
        .map_err(|error| Error::io("write fixture", &error))?;

    let mut reader = open_reader(directory.path(), Path::new("report.bin"))?;
    assert_eq!(reader.size(), 4);
    assert_eq!(reader.read_chunk(1, 2).await?, [1, 2]);
    assert_eq!(reader.read_chunk(3, 8).await?, [255]);
    assert_eq!(reader.read_chunk(4, 8).await?, Vec::<u8>::new());
    assert_eq!(reader.read_chunk(0, 0).await?, Vec::<u8>::new());
    Ok(())
}

#[tokio::test]
async fn staged_writes_publish_atomically_and_abort_without_replacing_the_target() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let target = directory.path().join("nested/report.bin");
    std::fs::create_dir_all(target.parent().unwrap_or(directory.path()))
        .map_err(|error| Error::io("create fixture directory", &error))?;
    std::fs::write(&target, b"old").map_err(|error| Error::io("write fixture", &error))?;

    let mut writer = begin_writer(directory.path(), Path::new("nested/report.bin"), "one")?;
    assert_eq!(
        std::fs::read(&target).map_err(|error| Error::io("read fixture", &error))?,
        b"old"
    );
    assert_eq!(writer.write_chunk(0, b"new").await?, 3);
    assert_eq!(
        writer.write_chunk(4, b"gap").await.err(),
        Some(Error::InvalidFileTransfer {
            reason: "write offset or state is invalid"
        })
    );
    assert_eq!(writer.finish().await?, 3);
    assert_eq!(
        std::fs::read(&target).map_err(|error| Error::io("read fixture", &error))?,
        b"new"
    );

    let mut aborted = begin_writer(directory.path(), Path::new("nested/report.bin"), "two")?;
    assert_eq!(aborted.write_chunk(0, b"discard").await?, 7);
    aborted.abort().await?;
    assert_eq!(
        std::fs::read(&target).map_err(|error| Error::io("read fixture", &error))?,
        b"new"
    );
    let files = std::fs::read_dir(target.parent().unwrap_or(directory.path()))
        .map_err(|error| Error::io("list fixture", &error))?
        .count();
    assert_eq!(files, 1);
    Ok(())
}

#[tokio::test]
async fn rejects_non_normalized_and_absolute_workspace_paths() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    for path in [
        "",
        ".",
        "../escape",
        "nested/../escape",
        "/tmp/outside",
        "bad\0name",
        &"x".repeat(4097),
    ] {
        assert_eq!(
            open_reader(directory.path(), Path::new(path)).err(),
            Some(Error::InvalidWorkspacePath)
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_transfer_ids_missing_roots_and_directory_reads() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    std::fs::create_dir(directory.path().join("folder"))
        .map_err(|error| Error::io("create fixture directory", &error))?;

    for id in ["", "has space", "../escape", &"x".repeat(129)] {
        assert!(begin_writer(directory.path(), Path::new("new.bin"), id).is_err());
    }
    assert!(open_reader(directory.path(), Path::new("folder")).is_err());
    assert!(open_reader(&directory.path().join("missing"), Path::new("file")).is_err());
    assert!(
        begin_writer(
            &directory.path().join("missing"),
            Path::new("file"),
            "missing-root"
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn finished_and_aborted_writers_are_idempotent_and_staging_collisions_are_refused()
-> Result<()> {
    let directory = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let mut writer = begin_writer(directory.path(), Path::new("result.bin"), "stable")?;
    assert!(begin_writer(directory.path(), Path::new("result.bin"), "stable").is_err());
    assert_eq!(writer.write_chunk(0, b"saved").await?, 5);
    assert_eq!(writer.finish().await?, 5);
    assert_eq!(writer.finish().await?, 5);
    writer.abort().await?;

    let mut aborted = begin_writer(directory.path(), Path::new("discard.bin"), "discard")?;
    aborted.write_chunk(0, b"temporary").await?;
    std::fs::remove_file(directory.path().join(".discard.bin.tinybox-discard.tmp"))
        .map_err(|error| Error::io("remove staging fixture", &error))?;
    aborted.abort().await?;
    assert!(!directory.path().join("discard.bin").exists());
    Ok(())
}

#[tokio::test]
async fn publish_failure_preserves_the_target_and_drop_reclaims_staging() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let mut writer = begin_writer(directory.path(), Path::new("blocked"), "publish-failure")?;
    writer.write_chunk(0, b"staged").await?;
    std::fs::create_dir(directory.path().join("blocked"))
        .map_err(|error| Error::io("create conflicting target", &error))?;
    assert!(writer.finish().await.is_err());
    drop(writer);
    assert_eq!(
        std::fs::read_dir(directory.path())
            .map_err(|error| Error::io("list fixture", &error))?
            .count(),
        1,
        "the failed publish must not leave its temporary sibling"
    );

    let writer = begin_writer(directory.path(), Path::new("abandoned"), "drop-cleanup")?;
    drop(writer);
    assert_eq!(
        std::fs::read_dir(directory.path())
            .map_err(|error| Error::io("list fixture", &error))?
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn writer_handles_a_missing_staging_handle_without_panicking() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let mut writer = LocalFileWriter {
        dir: open_root(directory.path())?,
        temporary: PathBuf::from("missing.tmp"),
        destination: PathBuf::from("result.bin"),
        file: None,
        next_offset: 0,
        finished: false,
    };
    assert!(writer.write_chunk(0, b"data").await.is_err());
    writer.abort().await?;
    assert!(writer.write_chunk(0, b"data").await.is_err());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_cannot_escape_the_approved_workspace() -> Result<()> {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let outside =
        tempfile::tempdir().map_err(|error| Error::io("create outside fixture", &error))?;
    std::fs::write(outside.path().join("secret"), b"keep")
        .map_err(|error| Error::io("write outside fixture", &error))?;
    symlink(outside.path(), root.path().join("escape"))
        .map_err(|error| Error::io("create fixture symlink", &error))?;

    assert!(open_reader(root.path(), Path::new("escape/secret")).is_err());
    assert!(begin_writer(root.path(), Path::new("escape/secret"), "escape").is_err());
    assert_eq!(
        std::fs::read(outside.path().join("secret"))
            .map_err(|error| Error::io("read outside fixture", &error))?,
        b"keep"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn concurrent_symlink_rename_cannot_redirect_a_staged_write_outside() -> Result<()> {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let outside =
        tempfile::tempdir().map_err(|error| Error::io("create outside fixture", &error))?;
    let inside = root.path().join("inside");
    std::fs::create_dir(&inside).map_err(|error| Error::io("create inside fixture", &error))?;
    std::fs::write(outside.path().join("marker"), b"protected")
        .map_err(|error| Error::io("write outside marker", &error))?;
    std::fs::write(inside.join("marker"), b"inside")
        .map_err(|error| Error::io("write inside marker", &error))?;
    let alias = root.path().join("alias");
    symlink(&inside, &alias).map_err(|error| Error::io("create inside symlink", &error))?;

    let swap_root = root.path().to_path_buf();
    let swap_alias = alias.clone();
    let swap_outside = outside.path().to_path_buf();
    let swapper = std::thread::spawn(move || -> Result<()> {
        for index in 0..200 {
            let outside_link = swap_root.join(format!("outside-link-{index}"));
            symlink(&swap_outside, &outside_link)
                .map_err(|error| Error::io("create outside symlink", &error))?;
            std::fs::rename(&outside_link, &swap_alias)
                .map_err(|error| Error::io("replace fixture symlink", &error))?;

            let inside_link = swap_root.join(format!("inside-link-{index}"));
            symlink(swap_root.join("inside"), &inside_link)
                .map_err(|error| Error::io("create inside symlink", &error))?;
            std::fs::rename(&inside_link, &swap_alias)
                .map_err(|error| Error::io("restore fixture symlink", &error))?;
        }
        Ok(())
    });

    for index in 0..200 {
        let id = format!("race-{index}");
        if let Ok(mut writer) = begin_writer(root.path(), Path::new("alias/marker"), &id) {
            if writer.write_chunk(0, b"changed").await.is_ok() {
                let _ = writer.finish().await;
            } else {
                let _ = writer.abort().await;
            }
        }
    }
    swapper.join().map_err(|_| {
        Error::io(
            "join symlink fixture",
            &std::io::Error::from(ErrorKind::Other),
        )
    })??;

    assert_eq!(
        std::fs::read(outside.path().join("marker"))
            .map_err(|error| Error::io("read outside marker", &error))?,
        b"protected"
    );
    Ok(())
}
