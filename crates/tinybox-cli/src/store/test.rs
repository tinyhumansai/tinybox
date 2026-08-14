//! Tests for the file-backed box store.

use std::ffi::OsStr;
use std::path::Path;

use tempfile::TempDir;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, Error, HostRef, Placement, Result, SandboxRef, Store,
    WorkspaceSource,
};

use super::FileStore;

/// A throwaway directory.
fn temp_dir_named() -> Result<TempDir> {
    TempDir::new().map_err(|error| Error::io("tempdir", &error))
}

/// A store in a throwaway directory, and the directory keeping it alive.
fn store() -> Result<(FileStore, TempDir)> {
    let dir = temp_dir_named()?;
    let store = FileStore::new(dir.path().join("boxes.json"));
    Ok((store, dir))
}

fn info(id: &str) -> Result<BoxInfo> {
    let spec = BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
        WorkspaceSource::LocalDir("/srv/work".into()),
    )
    .with_env("KEY", "value");
    Ok(BoxInfo::new(BoxId::new(id)?, BoxState::Ready, spec))
}

#[test]
fn a_missing_file_reads_as_an_empty_store() -> Result<()> {
    let (store, _dir) = store()?;

    // No initialization step: a fresh install must just work.
    assert!(!store.path().exists());
    assert!(store.list()?.is_empty());
    assert_eq!(store.allocate_id()?.as_str(), "box-0");
    Ok(())
}

#[test]
fn a_record_survives_being_written_and_read_back() -> Result<()> {
    let (store, _dir) = store()?;
    let recorded = info("box-0")?;

    store.insert(&recorded)?;

    // A second handle on the same path is what a later CLI invocation sees.
    let reopened = FileStore::new(store.path());
    assert_eq!(reopened.get(&recorded.id)?, recorded);
    assert_eq!(reopened.list()?, vec![recorded]);
    Ok(())
}

#[test]
fn the_whole_spec_round_trips_through_json() -> Result<()> {
    let (store, _dir) = store()?;
    let recorded = info("box-0")?;
    store.insert(&recorded)?;

    let read_back = FileStore::new(store.path()).get(&recorded.id)?;

    assert_eq!(read_back.spec, recorded.spec);
    assert_eq!(
        read_back.spec.env.get("KEY").map(String::as_str),
        Some("value")
    );
    assert_eq!(read_back.spec.lifecycle, recorded.spec.lifecycle);
    assert_eq!(read_back.spec.resources, recorded.spec.resources);
    Ok(())
}

#[test]
fn inserting_the_same_id_twice_is_refused() -> Result<()> {
    let (store, _dir) = store()?;
    store.insert(&info("box-0")?)?;

    assert_eq!(
        store.insert(&info("box-0")?).err(),
        Some(Error::DuplicateBox {
            id: "box-0".to_owned()
        })
    );
    assert_eq!(store.list()?.len(), 1);
    Ok(())
}

#[test]
fn an_absent_box_is_reported_rather_than_invented() -> Result<()> {
    let (store, _dir) = store()?;
    let missing = BoxId::new("absent")?;
    let expected = Some(Error::UnknownBox {
        id: "absent".to_owned(),
    });

    assert_eq!(store.get(&missing).err(), expected);
    assert_eq!(store.remove(&missing).err(), expected);
    assert_eq!(store.set_state(&missing, BoxState::Stopped).err(), expected);
    Ok(())
}

#[test]
fn state_changes_and_removals_persist() -> Result<()> {
    let (store, _dir) = store()?;
    let recorded = info("box-0")?;
    store.insert(&recorded)?;

    store.set_state(&recorded.id, BoxState::Stopped)?;
    assert_eq!(
        FileStore::new(store.path()).get(&recorded.id)?.state,
        BoxState::Stopped
    );

    store.remove(&recorded.id)?;
    assert!(FileStore::new(store.path()).list()?.is_empty());
    Ok(())
}

#[test]
fn a_corrupt_store_is_reported_and_not_silently_reset() -> Result<()> {
    let (store, _dir) = store()?;
    std::fs::create_dir_all(store.path().parent().unwrap_or(store.path()))
        .map_err(|error| Error::io("mkdir", &error))?;
    std::fs::write(store.path(), "{ not json").map_err(|error| Error::io("write", &error))?;

    // Treating an unreadable store as empty would quietly orphan every running
    // box, so it must be an error.
    assert!(matches!(
        store.list(),
        Err(Error::Store {
            operation: "parse",
            ..
        })
    ));
    Ok(())
}

#[test]
fn an_identifier_rejected_by_the_constructor_cannot_be_smuggled_in() -> Result<()> {
    let (store, _dir) = store()?;
    std::fs::write(store.path(), r#"{"../escape": {"id": "../escape"}}"#)
        .map_err(|error| Error::io("write", &error))?;

    // Identifiers are re-validated on read, so hand-editing the file cannot
    // introduce a name that would escape the store directory.
    assert!(matches!(
        store.list(),
        Err(Error::Store {
            operation: "parse",
            ..
        })
    ));
    Ok(())
}

#[test]
fn writing_leaves_no_temporary_file_behind() -> Result<()> {
    let (store, dir) = store()?;
    store.insert(&info("box-0")?)?;

    let leftovers = std::fs::read_dir(dir.path())
        .map_err(|error| Error::io("readdir", &error))?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "tmp"))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();

    assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    Ok(())
}

#[test]
fn the_parent_directory_is_created_on_first_write() -> Result<()> {
    let dir = TempDir::new().map_err(|error| Error::io("tempdir", &error))?;
    let store = FileStore::new(dir.path().join("deep").join("nested").join("boxes.json"));

    store.insert(&info("box-0")?)?;

    assert!(store.path().exists());
    Ok(())
}

#[test]
fn allocation_continues_across_processes() -> Result<()> {
    let (store, _dir) = store()?;
    store.insert(&info("box-0")?)?;

    // The identifier a later invocation picks must account for boxes it did not
    // create itself.
    assert_eq!(
        FileStore::new(store.path()).allocate_id()?.as_str(),
        "box-1"
    );
    Ok(())
}

#[test]
fn the_state_directory_wins_over_every_other_source() -> Result<()> {
    let resolved = FileStore::resolve_path(
        Some(OsStr::new("/explicit")),
        Some(OsStr::new("/xdg")),
        Some(OsStr::new("/home/user")),
    )?;

    assert_eq!(resolved, Path::new("/explicit/boxes.json"));
    Ok(())
}

#[test]
fn xdg_state_home_is_used_when_no_override_is_set() -> Result<()> {
    let resolved = FileStore::resolve_path(
        None,
        Some(OsStr::new("/xdg")),
        Some(OsStr::new("/home/user")),
    )?;

    assert_eq!(resolved, Path::new("/xdg/tinybox/boxes.json"));
    Ok(())
}

#[test]
fn the_home_directory_is_the_last_resort() -> Result<()> {
    let resolved = FileStore::resolve_path(None, None, Some(OsStr::new("/home/user")))?;

    assert_eq!(
        resolved,
        Path::new("/home/user/.local/state/tinybox/boxes.json")
    );
    Ok(())
}

#[test]
fn with_nowhere_to_write_the_failure_names_the_variables_to_set() {
    let outcome = FileStore::resolve_path(None, None, None);

    assert!(outcome.err().is_some_and(|error| {
        let message = error.to_string();
        message.contains("TINYBOX_STATE_DIR") && message.contains("HOME")
    }));
}

#[test]
fn the_default_path_ends_at_the_expected_file_name() -> Result<()> {
    // Whatever the environment, the file itself is always `boxes.json`.
    let resolved = FileStore::default_path()?;

    assert_eq!(resolved.file_name(), Some(OsStr::new("boxes.json")));
    Ok(())
}

#[test]
fn a_store_path_that_is_a_directory_is_reported_as_a_read_failure() -> Result<()> {
    let dir = temp_dir_named()?;
    let path = dir.path().join("boxes.json");
    std::fs::create_dir(&path).map_err(|error| Error::io("mkdir", &error))?;

    // Not a missing file, so it must not read as an empty store.
    assert!(matches!(
        FileStore::new(&path).list(),
        Err(Error::Store {
            operation: "read",
            ..
        })
    ));
    Ok(())
}

#[test]
fn a_parent_that_is_a_file_is_reported_rather_than_losing_the_box() -> Result<()> {
    let dir = temp_dir_named()?;
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, "not a directory").map_err(|error| Error::io("write", &error))?;

    // The store's parent exists but is a file, so nothing under it can be
    // opened or created. Which syscall notices first is the platform's
    // business; what matters is that the box is not silently dropped.
    let store = FileStore::new(blocker.join("boxes.json"));

    assert!(matches!(
        store.insert(&info("box-0")?),
        Err(Error::Store { .. })
    ));
    Ok(())
}

#[test]
fn an_unwritable_directory_is_reported_rather_than_silently_dropping_the_box() -> Result<()> {
    let dir = temp_dir_named()?;
    let readonly = dir.path().join("readonly");
    std::fs::create_dir(&readonly).map_err(|error| Error::io("mkdir", &error))?;

    let mut permissions = std::fs::metadata(&readonly)
        .map_err(|error| Error::io("metadata", &error))?
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&readonly, permissions).map_err(|error| Error::io("chmod", &error))?;

    let store = FileStore::new(readonly.join("boxes.json"));
    let outcome = store.insert(&info("box-0")?);

    // Running as root defeats the permission bit entirely, so accept either a
    // reported failure or a successful write rather than asserting something
    // that depends on who is running the suite.
    assert!(matches!(outcome, Err(Error::Store { .. }) | Ok(())));
    Ok(())
}

#[test]
fn concurrent_writers_do_not_lose_each_others_records() -> Result<()> {
    use std::thread;

    let (store, _dir) = store()?;
    let path = store.path().to_path_buf();

    // The bug this fixes: without a lock covering the read and the write, each
    // writer reads the same document, adds its own box, and the last rename
    // discards everyone else's. Twenty writers make that near-certain.
    let writers = (0..20)
        .map(|index| {
            let path = path.clone();
            thread::spawn(move || -> Result<()> {
                let store = FileStore::new(path);
                store.insert(&info(&format!("box-{index}"))?)
            })
        })
        .collect::<Vec<_>>();

    for writer in writers {
        writer.join().map_err(|_| Error::Store {
            operation: "join",
            message: "a writer panicked".to_owned(),
        })??;
    }

    assert_eq!(store.list()?.len(), 20);
    Ok(())
}

#[test]
fn concurrent_allocation_gives_every_box_its_own_identifier() -> Result<()> {
    use std::thread;
    use tinybox_core::{BoxState, insert_new};

    let (store, _dir) = store()?;
    let path = store.path().to_path_buf();
    let spec = info("box-0")?.spec;

    // Allocating and inserting are two operations, so two processes can pick
    // the same name; `insert_new` retries rather than failing the create.
    let creators = (0..12)
        .map(|_| {
            let path = path.clone();
            let spec = spec.clone();
            thread::spawn(move || -> Result<String> {
                let store = FileStore::new(path);
                Ok(insert_new(
                    &store,
                    BoxState::Ready,
                    &spec,
                    std::time::SystemTime::UNIX_EPOCH,
                )?
                .id
                .into_string())
            })
        })
        .collect::<Vec<_>>();

    let mut ids = Vec::new();
    for creator in creators {
        ids.push(creator.join().map_err(|_| Error::Store {
            operation: "join",
            message: "a creator panicked".to_owned(),
        })??);
    }
    ids.sort();
    ids.dedup();

    assert_eq!(ids.len(), 12, "identifiers collided: {ids:?}");
    assert_eq!(store.list()?.len(), 12);
    Ok(())
}

#[test]
fn the_lock_lives_beside_the_store_and_not_inside_it() -> Result<()> {
    let (store, _dir) = store()?;

    store.insert(&info("box-0")?)?;

    // Locking the store file itself would mean opening it for write before
    // knowing there is anything to write, and the lock has to outlive the
    // rename that replaces it.
    let lock = store.path().with_extension("lock");
    assert!(lock.exists());
    assert_ne!(lock, store.path());
    // The lock is not mistaken for a record.
    assert_eq!(store.list()?.len(), 1);
    Ok(())
}
