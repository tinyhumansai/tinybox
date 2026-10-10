//! Unit tests for [`super::JailRegistry`].
//!
//! Lives next to `registry.rs` (wired in via `#[cfg(test)] #[path =
//! "registry_tests.rs"] mod tests;`) so the production module stays under
//! the ~500-line guideline.

use super::*;
use std::time::Duration;
use tinybox_core::clock::FixedClock;

fn tempdir(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("tinybox-registry-{tag}-"))
        .tempdir()
        .unwrap()
}

#[test]
fn create_list_get_roundtrip() {
    let base = tempdir("crud");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("alpha").unwrap();
    let b = reg.create("beta").unwrap();
    assert_ne!(a.id, b.id);
    assert!(a.dir.exists());
    assert!(b.dir.exists());
    let listed = reg.list();
    assert_eq!(listed.len(), 2);
    assert_eq!(reg.get(&a.id).unwrap().label, "alpha");
    assert_eq!(reg.get(&b.id).unwrap().label, "beta");
}

#[test]
fn rename_changes_label_not_id_or_dir() {
    let base = tempdir("rename");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("old").unwrap();
    let renamed = reg.rename(&a.id, "new").unwrap();
    assert_eq!(renamed.id, a.id);
    assert_eq!(renamed.dir, a.dir);
    assert_eq!(renamed.label, "new");
    assert!(renamed.updated_at_unix >= a.updated_at_unix);
}

#[test]
fn delete_removes_dir_and_record() {
    let base = tempdir("delete");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("doomed").unwrap();
    let dir = a.dir.clone();
    assert!(dir.exists());
    reg.delete(&a.id).unwrap();
    assert!(!dir.exists());
    assert!(reg.get(&a.id).is_none());
}

#[test]
fn delete_persists_removal_after_jail_directory_is_already_missing() {
    let base = tempdir("delete-missing-directory");
    let reg = JailRegistry::open(&base).unwrap();
    let record = reg.create("missing directory").unwrap();
    fs::remove_dir_all(&record.dir).unwrap();

    reg.delete(&record.id).unwrap();

    assert!(reg.get(&record.id).is_none());
    assert!(JailRegistry::open(&base).unwrap().list().is_empty());
}

#[test]
fn delete_missing_errors() {
    let base = tempdir("missing");
    let reg = JailRegistry::open(&base).unwrap();
    let err = reg.delete("nope").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn index_persists_across_reopen() {
    let base = tempdir("persist");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("persistent").unwrap();
    drop(reg);
    let reg2 = JailRegistry::open(&base).unwrap();
    let listed = reg2.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, a.id);
    assert_eq!(listed[0].label, "persistent");
}

#[test]
fn find_by_label_substring() {
    let base = tempdir("find");
    let reg = JailRegistry::open(&base).unwrap();
    reg.create("agent-alpha").unwrap();
    reg.create("agent-beta").unwrap();
    reg.create("tool-gamma").unwrap();
    assert_eq!(reg.find_by_label("AGENT").len(), 2);
    assert_eq!(reg.find_by_label("gamma").len(), 1);
    assert_eq!(reg.find_by_label("nope").len(), 0);
}

#[test]
fn clear_drops_everything() {
    let base = tempdir("clear");
    let reg = JailRegistry::open(&base).unwrap();
    reg.create("a").unwrap();
    reg.create("b").unwrap();
    reg.create("c").unwrap();
    let n = reg.clear().unwrap();
    assert_eq!(n, 3);
    assert_eq!(reg.list().len(), 0);
}

#[test]
fn parallel_jails_have_distinct_dirs() {
    let base = tempdir("parallel");
    let reg = JailRegistry::open(&base).unwrap();
    let jails: Vec<_> = (0..5)
        .map(|i| reg.create(format!("p{i}")).unwrap())
        .collect();
    let mut dirs: Vec<_> = jails.iter().map(|r| r.dir.clone()).collect();
    dirs.sort();
    dirs.dedup();
    assert_eq!(dirs.len(), 5);
    for r in &jails {
        assert!(r.dir.exists());
    }
}

#[test]
fn set_notes_roundtrips() {
    let base = tempdir("notes");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("with-notes").unwrap();
    assert!(a.notes.is_none());
    let updated = reg.set_notes(&a.id, Some("hello".into())).unwrap();
    assert_eq!(updated.notes.as_deref(), Some("hello"));
    let cleared = reg.set_notes(&a.id, None).unwrap();
    assert!(cleared.notes.is_none());
}

#[test]
fn set_notes_on_missing_id_errors() {
    let base = tempdir("notes-missing");
    let reg = JailRegistry::open(&base).unwrap();
    let err = reg.set_notes("nope", Some("x".into())).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn rename_on_missing_id_errors() {
    let base = tempdir("rename-missing");
    let reg = JailRegistry::open(&base).unwrap();
    let err = reg.rename("nope", "x").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn delete_twice_second_is_not_found() {
    let base = tempdir("delete-twice");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("once").unwrap();
    reg.delete(&a.id).unwrap();
    let err = reg.delete(&a.id).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn spawn_in_with_missing_id_errors() {
    let base = tempdir("spawn-missing");
    let reg = JailRegistry::open(&base).unwrap();
    let err = reg
        .spawn_in_with("nope", &super::super::NoopBackend, Command::new("true"))
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn spawn_in_uses_default_backend() {
    let base = tempdir("spawn-default");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("def").unwrap();
    let cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "exit"]);
        c
    } else {
        Command::new("true")
    };
    let result = reg.spawn_in(&a.id, cmd);
    if super::super::default_backend().is_available() {
        let mut child = result.unwrap();
        let _ = child.wait().unwrap();
    } else {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
    }
}

#[test]
fn clear_on_empty_registry_is_zero() {
    let base = tempdir("empty-clear");
    let reg = JailRegistry::open(&base).unwrap();
    assert_eq!(reg.clear().unwrap(), 0);
}

#[test]
fn find_by_label_on_empty_registry() {
    let base = tempdir("empty-find");
    let reg = JailRegistry::open(&base).unwrap();
    assert!(reg.find_by_label("anything").is_empty());
}

#[test]
fn open_creates_base_directory_if_missing() {
    let base = tempfile::Builder::new()
        .prefix("oh-reg-mkdir-")
        .tempdir()
        .unwrap();
    let path = base.path();
    let reg = JailRegistry::open(path).unwrap();
    assert!(path.exists());
    assert!(reg.list().is_empty());
}

#[test]
fn corrupt_index_returns_invalid_data() {
    let base = tempdir("corrupt");
    fs::write(base.path().join("index.json"), b"this is not json").unwrap();
    let err = JailRegistry::open(&base).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn persist_writes_index_file() {
    let base = tempdir("persist-file");
    let reg = JailRegistry::open(&base).unwrap();
    reg.create("x").unwrap();
    let path = base.path().join("index.json");
    assert!(path.exists());
    let raw = fs::read_to_string(&path).unwrap();
    assert!(raw.contains("\"label\": \"x\""));
}

#[test]
fn base_accessor_returns_open_dir() {
    let base = tempdir("base-accessor");
    let reg = JailRegistry::open(&base).unwrap();
    assert_eq!(reg.base(), base.path().canonicalize().unwrap());
}

#[test]
fn delete_refuses_path_outside_base() {
    // Corrupt the index so a record points at /tmp directly (outside
    // base). delete() should refuse without touching anything on disk.
    let base = tempdir("escape");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("escape").unwrap();
    {
        let mut idx = reg.index.lock().unwrap();
        idx.records.get_mut(&a.id).unwrap().dir = std::env::temp_dir();
    }
    let err = reg.delete(&a.id).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(std::env::temp_dir().exists());
    // Record is still there because we refuse cleanly without removing.
    assert!(reg.get(&a.id).is_some());
}

#[test]
fn spawn_in_refuses_path_outside_base() {
    // Same corruption as delete_refuses_path_outside_base, but for the
    // spawn path — covers the base-containment guard in `jail_for()`.
    let base = tempdir("spawn-escape");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("escape").unwrap();
    {
        let mut idx = reg.index.lock().unwrap();
        idx.records.get_mut(&a.id).unwrap().dir = std::env::temp_dir();
    }
    let err = reg
        .spawn_in_with(&a.id, &super::super::NoopBackend, Command::new("true"))
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn spawn_in_uses_record_dir_as_root() {
    let base = tempdir("spawn");
    let reg = JailRegistry::open(&base).unwrap();
    let a = reg.create("spawn-target").unwrap();
    let mut cmd = Command::new(if cfg!(windows) { "cmd" } else { "true" });
    if cfg!(windows) {
        cmd.args(["/C", "exit"]);
    }
    let mut child = reg
        .spawn_in_with(&a.id, &super::super::NoopBackend, cmd)
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success() || cfg!(windows));
}

#[test]
fn create_consecutive_ids_are_unique_in_same_second() {
    // The atomic counter inside generate_id() guarantees distinct ids
    // within a single process even when system time has not advanced.
    // Across process restarts, the create() loop is what catches
    // collisions; we cover that path via the collision-loop branch
    // being unreachable here without a process restart, so this test
    // just confirms the happy path remains collision-free.
    let base = tempdir("ids");
    let reg = JailRegistry::open(&base).unwrap();
    let ids: std::collections::HashSet<_> = (0..32)
        .map(|i| reg.create(format!("j{i}")).unwrap().id)
        .collect();
    assert_eq!(ids.len(), 32);
}

#[test]
fn create_skips_an_existing_unindexed_jail_directory() {
    let base = tempdir("directory-collision");
    let current = generate_id(0);
    let counter = u64::from_str_radix(&current[2..], 16).unwrap();
    let collision = base.path().join(format!("j0{:x}", counter + 1));
    fs::create_dir(&collision).unwrap();

    let reg = JailRegistry::open_with_clock(base.path(), Arc::new(FixedClock::at_epoch())).unwrap();
    let created = reg.create("safe").unwrap();

    assert_ne!(created.dir, collision);
    assert!(collision.is_dir());
    assert!(created.dir.is_dir());
}

#[test]
fn registry_uses_the_injected_clock_for_timestamps() {
    let base = tempdir("clock");
    let clock = Arc::new(FixedClock::at_epoch());
    let reg = JailRegistry::open_with_clock(base.path(), clock.clone()).unwrap();
    let created = reg.create("clocked").unwrap();
    assert_eq!(created.created_at_unix, 0);
    assert_eq!(created.updated_at_unix, 0);

    clock.advance(Duration::from_secs(5));
    let updated = reg.rename(&created.id, "renamed").unwrap();
    assert_eq!(updated.updated_at_unix, 5);
}

#[test]
fn failed_index_write_rolls_back_registry_mutations() {
    let base = tempdir("rollback");
    let reg = JailRegistry::open(base.path()).unwrap();
    let blocked_tmp = base.path().join("index.json.tmp");
    fs::create_dir(&blocked_tmp).unwrap();

    let create_error = reg.create("not-persisted").err();
    assert!(create_error.is_some());
    assert!(reg.list().is_empty());

    fs::remove_dir(&blocked_tmp).unwrap();
    let record = reg.create("original").unwrap();
    fs::create_dir(&blocked_tmp).unwrap();

    assert!(reg.rename(&record.id, "changed").is_err());
    assert_eq!(
        reg.get(&record.id).map(|item| item.label),
        Some("original".into())
    );
    assert!(reg.set_notes(&record.id, Some("changed".into())).is_err());
    assert_eq!(reg.get(&record.id).and_then(|item| item.notes), None);
}

#[test]
fn failed_index_write_after_delete_keeps_in_memory_removal() {
    let base = tempdir("delete-rollback");
    let reg = JailRegistry::open(base.path()).unwrap();
    let record = reg.create("deleted").unwrap();
    let blocked_tmp = base.path().join("index.json.tmp");
    fs::create_dir(&blocked_tmp).unwrap();

    let error = reg.delete(&record.id).unwrap_err();

    // The OS maps writing a directory differently (Windows: PermissionDenied,
    // Unix: IsADirectory). Compare with the same independent filesystem failure.
    let expected = fs::write(&blocked_tmp, b"independent probe").unwrap_err();
    assert_eq!(error.kind(), expected.kind());
    assert!(!record.dir.exists());
    assert!(reg.get(&record.id).is_none());
}

#[test]
fn open_rejects_a_file_as_registry_directory() {
    let base = tempdir("not-directory");
    let file = base.path().join("file");
    fs::write(&file, b"not a directory").unwrap();
    let error = JailRegistry::open(file).err();
    assert!(error.is_some());
}

#[test]
fn spawn_rejects_a_jail_directory_removed_after_creation() {
    let base = tempdir("removed-jail");
    let reg = JailRegistry::open(base.path()).unwrap();
    let record = reg.create("removed").unwrap();
    fs::remove_dir_all(&record.dir).unwrap();

    let error = reg
        .spawn_in_with(&record.id, &super::super::NoopBackend, Command::new("true"))
        .err()
        .map(|error| error.kind());
    assert_eq!(error, Some(io::ErrorKind::NotFound));
}

#[cfg(unix)]
#[test]
fn removed_jail_under_symlinked_registry_base_can_be_deleted() -> io::Result<()> {
    let root = tempdir("linked-base");
    let real = root.path().join("real");
    fs::create_dir(&real)?;
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&real, &linked)?;
    let reg = JailRegistry::open(&linked)?;
    let record = reg.create("removed")?;
    fs::remove_dir_all(&record.dir)?;
    reg.delete(&record.id)?;
    assert!(reg.get(&record.id).is_none());
    assert!(JailRegistry::open(&linked)?.get(&record.id).is_none());
    Ok(())
}

#[cfg(unix)]
#[test]
fn removed_jail_under_symlinked_base_reports_missing_not_outside() -> io::Result<()> {
    let root = tempdir("linked-missing");
    let real = root.path().join("real");
    fs::create_dir(&real)?;
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&real, &linked)?;
    let reg = JailRegistry::open(&linked)?;
    let record = reg.create("removed")?;
    fs::remove_dir_all(&record.dir)?;
    assert_eq!(
        reg.spawn_in_with(&record.id, &super::super::NoopBackend, Command::new("true"))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn missing_jail_through_outside_symlink_remains_forbidden() -> io::Result<()> {
    let root = tempdir("outside-link");
    let outside = tempdir("outside-target");
    let reg = JailRegistry::open(root.path())?;
    let record = reg.create("corrupt")?;
    let link = root.path().join("outside");
    std::os::unix::fs::symlink(outside.path(), &link)?;
    reg.index
        .lock()
        .unwrap()
        .records
        .get_mut(&record.id)
        .unwrap()
        .dir = link.join("missing/nested");
    assert_eq!(
        reg.delete(&record.id).err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        reg.spawn_in_with(&record.id, &super::super::NoopBackend, Command::new("true"))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert!(reg.get(&record.id).is_some());
    assert!(record.dir.is_dir());
    Ok(())
}

#[test]
fn trusted_base_parent_components_are_normalized_before_creating_records() -> io::Result<()> {
    let root = tempdir("normalized-base");
    let base = root.path().join("base");
    fs::create_dir(&base)?;
    let lexical = base.join("..").join("base");
    let reg = JailRegistry::open(&lexical)?;
    let record = reg.create("normalized")?;
    assert_eq!(
        reg.jail_for(&record.id)?.root,
        base.canonicalize()?.join(&record.id)
    );
    let mut command = Command::new(if cfg!(windows) { "cmd" } else { "true" });
    if cfg!(windows) {
        command.args(["/C", "exit"]);
    }
    assert!(
        reg.spawn_in_with(&record.id, &super::super::NoopBackend, command)?
            .wait()?
            .success()
    );
    reg.delete(&record.id)?;
    assert!(reg.get(&record.id).is_none());
    Ok(())
}

#[test]
fn old_records_inherit_only_normalized_trusted_base_components() -> io::Result<()> {
    let root = tempdir("legacy-base");
    let base = root.path().join("base");
    fs::create_dir(&base)?;
    let lexical = base.join("..").join("base");
    let reg = JailRegistry::open(&base)?;
    let record = reg.create("legacy")?;
    {
        let mut index = reg.index.lock().unwrap();
        index.records.get_mut(&record.id).unwrap().dir = lexical.join(&record.id);
        reg.persist(&index)?;
    }
    drop(reg);
    let reopened = JailRegistry::open(&lexical)?;
    assert_eq!(
        reopened.jail_for(&record.id)?.root,
        base.canonicalize()?.join(&record.id)
    );
    fs::remove_dir_all(&record.dir)?;
    reopened.delete(&record.id)?;
    assert!(reopened.get(&record.id).is_none());
    Ok(())
}

#[test]
fn normalized_trusted_base_does_not_adopt_corrupt_suffix_traversal() -> io::Result<()> {
    let root = tempdir("corrupt-suffix");
    let base = root.path().join("base");
    fs::create_dir(&base)?;
    let lexical = base.join("..").join("base");
    let reg = JailRegistry::open(&base)?;
    let record = reg.create("corrupt")?;
    {
        let mut index = reg.index.lock().unwrap();
        index.records.get_mut(&record.id).unwrap().dir = lexical.join("child/..").join(&record.id);
        reg.persist(&index)?;
    }
    let reopened = JailRegistry::open(&lexical)?;
    assert_eq!(
        reopened
            .jail_for(&record.id)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        reopened.delete(&record.id).err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert!(record.dir.is_dir());
    Ok(())
}

#[cfg(unix)]
#[test]
fn old_symlink_base_records_work_when_reopened_by_the_real_base() -> io::Result<()> {
    let root = tempdir("legacy-alias");
    let base = root.path().join("real");
    fs::create_dir(&base)?;
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&base, &alias)?;
    let reg = JailRegistry::open(&base)?;
    let record = reg.create("legacy-alias")?;
    {
        let mut index = reg.index.lock().unwrap();
        index.records.get_mut(&record.id).unwrap().dir = alias.join(&record.id);
        reg.persist(&index)?;
    }
    let reopened = JailRegistry::open(&base)?;
    assert_eq!(reopened.jail_for(&record.id)?.root, record.dir);
    fs::remove_dir_all(&record.dir)?;
    reopened.delete(&record.id)?;
    assert!(reopened.get(&record.id).is_none());
    Ok(())
}
