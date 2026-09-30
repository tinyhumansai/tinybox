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
        match result {
            Ok(mut child) => {
                let _ = child.wait();
            }
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
        }
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
fn open_creates_a_missing_nested_base_directory() {
    let parent = tempdir("missing-parent");
    let base = parent.path().join("nested").join("registry");
    assert!(!base.exists());

    let registry = JailRegistry::open(&base).unwrap();

    assert!(base.is_dir());
    assert!(registry.list().is_empty());
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
    assert_eq!(reg.base(), base.path());
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
fn create_rolls_back_when_index_persistence_fails() {
    let base = tempdir("create-persist-failure");
    fs::create_dir(base.path().join("index.json.tmp")).unwrap();
    let reg = JailRegistry::open(base.path()).unwrap();

    assert!(reg.create("not-persisted").is_err());
    assert!(reg.list().is_empty());
    assert_eq!(fs::read_dir(base.path()).unwrap().count(), 1);
}

#[test]
fn rename_and_notes_roll_back_when_index_persistence_fails() {
    let base = tempdir("update-persist-failure");
    let reg = JailRegistry::open(base.path()).unwrap();
    let created = reg.create("original").unwrap();
    fs::create_dir(base.path().join("index.json.tmp")).unwrap();

    assert!(reg.rename(&created.id, "changed").is_err());
    assert!(reg.set_notes(&created.id, Some("changed".into())).is_err());
    let current = reg.get(&created.id).unwrap();
    assert_eq!(current.label, "original");
    assert!(current.notes.is_none());
}

#[test]
fn delete_keeps_memory_aligned_when_index_persistence_fails() {
    let base = tempdir("delete-persist-failure");
    let reg = JailRegistry::open(base.path()).unwrap();
    let created = reg.create("remove").unwrap();
    fs::create_dir(base.path().join("index.json.tmp")).unwrap();

    assert!(reg.delete(&created.id).is_err());
    assert!(reg.get(&created.id).is_none());
    assert!(!created.dir.exists());
}

#[test]
fn delete_persists_when_the_jail_directory_is_already_missing() {
    let base = tempdir("delete-missing-directory");
    let reg = JailRegistry::open(base.path()).unwrap();
    let created = reg.create("removed-outside").unwrap();
    fs::remove_dir_all(&created.dir).unwrap();

    reg.delete(&created.id).unwrap();

    assert!(reg.get(&created.id).is_none());
}

#[test]
fn open_rejects_a_file_as_registry_directory() {
    let base = tempdir("not-directory");
    let file = base.path().join("file");
    fs::write(&file, b"not a directory").unwrap();
    assert!(JailRegistry::open(file).is_err());
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
