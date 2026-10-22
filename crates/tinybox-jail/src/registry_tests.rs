//! Unit tests for [`super::JailRegistry`].
//!
//! Lives next to `registry.rs` (wired in via `#[cfg(test)] #[path =
//! "registry_tests.rs"] mod tests;`) so the production module stays under
//! the ~500-line guideline.

use super::*;
use std::sync::Arc;
use std::time::Duration;
use tinybox_core::clock::{Clock, FixedClock, SystemClock};
use tinystoragedrivers_api::{DocumentStore, Storage, StorageBackend};
use tinystoragedrivers_testkit::{FaultPlan, MemoryBackend};
use tinystoragedrivers_types::{CollectionSpec, ErrorKind, Precondition, Scope, WriteOptions};

const TEST_INDEX_COLLECTION: &str = "tinybox.test_jail_registry";

fn block_storage<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[derive(Debug)]
struct TestDocumentIndexStore {
    documents: Arc<dyn DocumentStore>,
    key: String,
    faults: Option<FaultPlan>,
}

impl IndexStore for TestDocumentIndexStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let documents = Arc::clone(&self.documents);
        let key = self.key.clone();
        let record = block_storage(async move { documents.get(TEST_INDEX_COLLECTION, &key).await })
            .map_err(|error| io::Error::other(error.to_string()))?;
        record
            .map(|record| {
                serde_json::from_value::<Vec<u8>>(record.doc["bytes"].clone())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })
            .transpose()
    }

    fn save(&self, bytes: &[u8]) -> io::Result<()> {
        if let Some(faults) = &self.faults {
            faults
                .check("save")
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        let documents = Arc::clone(&self.documents);
        let key = self.key.clone();
        let body = serde_json::json!({ "bytes": bytes });
        block_storage(async move {
            documents
                .put_with(
                    TEST_INDEX_COLLECTION,
                    &key,
                    body,
                    Precondition::None,
                    WriteOptions::new(),
                )
                .await
        })
        .map(|_| ())
        .map_err(|error| io::Error::other(error.to_string()))
    }
}

#[derive(Debug)]
struct TestRegistry {
    directory: tempfile::TempDir,
    _storage: Storage,
    store: Arc<TestDocumentIndexStore>,
}

impl TestRegistry {
    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn open(&self) -> io::Result<JailRegistry> {
        self.open_with_clock(Arc::new(SystemClock::new()))
    }

    fn open_with_clock(&self, clock: Arc<dyn Clock>) -> io::Result<JailRegistry> {
        JailRegistry::open_with_store(self.path(), clock, self.store.clone())
    }

    fn open_with_index(&self, store: Arc<dyn IndexStore>) -> io::Result<JailRegistry> {
        JailRegistry::open_with_store(self.path(), Arc::new(SystemClock::new()), store)
    }

    fn open_at(&self, path: impl AsRef<Path>) -> io::Result<JailRegistry> {
        JailRegistry::open_with_store(path, Arc::new(SystemClock::new()), self.store.clone())
    }

    fn fail_next_save(&self) -> Arc<dyn IndexStore> {
        let faults = FaultPlan::new();
        faults.fail_operation_nth("save", 1, ErrorKind::Backend);
        Arc::new(TestDocumentIndexStore {
            documents: Arc::clone(&self.store.documents),
            key: self.store.key.clone(),
            faults: Some(faults),
        })
    }
}

fn tempdir(tag: &str) -> TestRegistry {
    let directory = tempfile::Builder::new()
        .prefix(&format!("tinybox-registry-{tag}-"))
        .tempdir()
        .unwrap();
    let scope_name = format!("tinybox-registry-test-{tag}-{}", directory.path().display());
    let scope = Scope::new(&scope_name).unwrap();
    let backend = MemoryBackend::new();
    let storage = backend.for_scope(&scope).unwrap();
    let documents = Arc::clone(storage.documents());
    block_storage(async {
        documents
            .ensure_collection(&CollectionSpec::new(TEST_INDEX_COLLECTION))
            .await
    })
    .unwrap();
    let store = Arc::new(TestDocumentIndexStore {
        documents,
        key: "jail-registry".to_owned(),
        faults: None,
    });
    TestRegistry {
        directory,
        _storage: storage,
        store,
    }
}

#[test]
fn create_list_get_roundtrip() {
    let base = tempdir("crud");
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
    let record = reg.create("missing directory").unwrap();
    fs::remove_dir_all(&record.dir).unwrap();

    reg.delete(&record.id).unwrap();

    assert!(reg.get(&record.id).is_none());
    assert!(base.open().unwrap().list().is_empty());
}

#[test]
fn delete_missing_errors() {
    let base = tempdir("missing");
    let reg = base.open().unwrap();
    let err = reg.delete("nope").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn index_persists_across_reopen() {
    let base = tempdir("persist");
    let reg = base.open().unwrap();
    let a = reg.create("persistent").unwrap();
    drop(reg);
    let reg2 = base.open().unwrap();
    let listed = reg2.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, a.id);
    assert_eq!(listed[0].label, "persistent");
}

#[test]
fn find_by_label_substring() {
    let base = tempdir("find");
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
    let err = reg.set_notes("nope", Some("x".into())).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn rename_on_missing_id_errors() {
    let base = tempdir("rename-missing");
    let reg = base.open().unwrap();
    let err = reg.rename("nope", "x").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn delete_twice_second_is_not_found() {
    let base = tempdir("delete-twice");
    let reg = base.open().unwrap();
    let a = reg.create("once").unwrap();
    reg.delete(&a.id).unwrap();
    let err = reg.delete(&a.id).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn spawn_in_with_missing_id_errors() {
    let base = tempdir("spawn-missing");
    let reg = base.open().unwrap();
    let err = reg
        .spawn_in_with("nope", &super::super::NoopBackend, Command::new("true"))
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn spawn_in_uses_default_backend() -> io::Result<()> {
    let base = tempdir("converted-tempdir");
    let reg = base.open()?;
    let a = reg.create("def")?;
    let cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "exit"]);
        c
    } else {
        Command::new("true")
    };
    let result = reg.spawn_in(&a.id, cmd);
    if super::super::default_backend().is_available() {
        assert!(result?.wait()?.success());
    } else {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}

#[test]
fn clear_on_empty_registry_is_zero() {
    let base = tempdir("empty-clear");
    let reg = base.open().unwrap();
    assert_eq!(reg.clear().unwrap(), 0);
}

#[test]
fn find_by_label_on_empty_registry() {
    let base = tempdir("empty-find");
    let reg = base.open().unwrap();
    assert!(reg.find_by_label("anything").is_empty());
}

#[test]
fn open_creates_base_directory_if_missing() {
    let base = tempdir("mkdir");
    let path = base.path().join("registry");
    let reg = base.open_at(&path).unwrap();
    assert!(path.exists());
    assert!(reg.list().is_empty());
}

#[test]
fn open_creates_a_missing_nested_base_directory() -> io::Result<()> {
    let fixture = tempdir("nested");
    let parent = tempfile::tempdir()?;
    let path = parent.path().join("nested").join("registry");
    assert!(!path.exists());

    let registry = fixture.open_at(&path)?;

    assert!(path.is_dir());
    assert!(registry.list().is_empty());
    Ok(())
}

#[test]
fn corrupt_index_returns_invalid_data() {
    let base = tempdir("corrupt");
    base.store.save(b"not json").unwrap();
    assert_eq!(base.open().unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn persist_writes_through_supplied_index_store() {
    let base = tempdir("persist-file");
    let reg = base.open().unwrap();
    reg.create("x").unwrap();
    let raw = String::from_utf8(base.store.load().unwrap().unwrap()).unwrap();
    assert!(raw.contains("\"label\": \"x\""));
}

#[test]
fn base_accessor_returns_open_dir() {
    let base = tempdir("base-accessor");
    let reg = base.open().unwrap();
    assert_eq!(reg.base(), base.path().canonicalize().unwrap());
}

#[test]
fn delete_refuses_path_outside_base() {
    // Corrupt the index so a record points at /tmp directly (outside
    // base). delete() should refuse without touching anything on disk.
    let base = tempdir("escape");
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
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
    let reg = base.open().unwrap();
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

    let reg = base
        .open_with_clock(Arc::new(FixedClock::at_epoch()))
        .unwrap();
    let created = reg.create("safe").unwrap();

    assert_ne!(created.dir, collision);
    assert!(collision.is_dir());
    assert!(created.dir.is_dir());
}

#[test]
fn registry_uses_the_injected_clock_for_timestamps() {
    let base = tempdir("clock");
    let clock = Arc::new(FixedClock::at_epoch());
    let reg = base.open_with_clock(clock.clone()).unwrap();
    let created = reg.create("clocked").unwrap();
    assert_eq!(created.created_at_unix, 0);
    assert_eq!(created.updated_at_unix, 0);

    clock.advance(Duration::from_secs(5));
    let updated = reg.rename(&created.id, "renamed").unwrap();
    assert_eq!(updated.updated_at_unix, 5);
}

#[test]
fn create_rolls_back_when_index_persistence_fails() -> io::Result<()> {
    let base = tempdir("create-failure");
    let reg = base.open_with_index(base.fail_next_save())?;

    assert!(reg.create("not-persisted").is_err());
    assert!(reg.list().is_empty());
    assert_eq!(fs::read_dir(base.path())?.count(), 0);
    Ok(())
}

#[test]
fn rename_and_notes_roll_back_when_index_persistence_fails() -> io::Result<()> {
    let base = tempdir("rename-failure");
    let initial = base.open()?;
    let created = initial.create("original")?;
    drop(initial);
    let rename_reg = base.open_with_index(base.fail_next_save())?;
    assert!(rename_reg.rename(&created.id, "changed").is_err());
    drop(rename_reg);
    let notes_reg = base.open_with_index(base.fail_next_save())?;
    assert!(
        notes_reg
            .set_notes(&created.id, Some("changed".into()))
            .is_err()
    );
    let current = base
        .open()?
        .get(&created.id)
        .ok_or_else(|| io::Error::other("record disappeared"))?;
    assert_eq!(current.label, "original");
    assert!(current.notes.is_none());
    Ok(())
}

#[test]
fn delete_keeps_memory_aligned_when_index_persistence_fails() -> io::Result<()> {
    let base = tempdir("delete-failure");
    let initial = base.open()?;
    let created = initial.create("remove")?;
    drop(initial);
    let reg = base.open_with_index(base.fail_next_save())?;

    assert!(reg.delete(&created.id).is_err());
    assert!(reg.get(&created.id).is_none());
    assert!(!created.dir.exists());
    Ok(())
}

#[test]
fn delete_persists_when_the_jail_directory_is_already_missing() -> io::Result<()> {
    let base = tempdir("converted-tempdir");
    let reg = base.open()?;
    let created = reg.create("removed-outside")?;
    fs::remove_dir_all(&created.dir)?;

    reg.delete(&created.id)?;

    assert!(reg.get(&created.id).is_none());
    Ok(())
}

#[test]
fn failed_index_write_after_delete_keeps_in_memory_removal() {
    let base = tempdir("delete-rollback");
    let initial = base.open().unwrap();
    let record = initial.create("deleted").unwrap();
    drop(initial);
    let reg = base.open_with_index(base.fail_next_save()).unwrap();

    let error = reg.delete(&record.id).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(!record.dir.exists());
    assert!(reg.get(&record.id).is_none());
}

#[test]
fn open_rejects_a_file_as_registry_directory() {
    let base = tempdir("not-directory");
    let file = base.path().join("file");
    fs::write(&file, b"not a directory").unwrap();
    assert!(base.open_at(file).is_err());
}

#[test]
fn spawn_rejects_a_jail_directory_removed_after_creation() -> io::Result<()> {
    let base = tempdir("converted-tempdir");
    let reg = base.open()?;
    let record = reg.create("removed")?;
    fs::remove_dir_all(&record.dir)?;

    let error = reg
        .spawn_in_with(&record.id, &super::super::NoopBackend, Command::new("true"))
        .err()
        .map(|error| error.kind());
    assert_eq!(error, Some(io::ErrorKind::NotFound));
    Ok(())
}

#[cfg(unix)]
#[test]
fn removed_jail_under_symlinked_registry_base_can_be_deleted() -> io::Result<()> {
    let root = tempdir("linked-base");
    let real = root.path().join("real");
    fs::create_dir(&real)?;
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&real, &linked)?;
    let reg = root.open_at(&linked)?;
    let record = reg.create("removed")?;
    fs::remove_dir_all(&record.dir)?;
    reg.delete(&record.id)?;
    assert!(reg.get(&record.id).is_none());
    assert!(root.open_at(&linked)?.get(&record.id).is_none());
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
    let reg = root.open_at(&linked)?;
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
    let reg = root.open_at(root.path())?;
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
    let reg = root.open_at(&lexical)?;
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
    let reg = root.open_at(&base)?;
    let record = reg.create("legacy")?;
    {
        let mut index = reg.index.lock().unwrap();
        index.records.get_mut(&record.id).unwrap().dir = lexical.join(&record.id);
        reg.persist(&index)?;
    }
    drop(reg);
    let reopened = root.open_at(&lexical)?;
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
    let reg = root.open_at(&base)?;
    let record = reg.create("corrupt")?;
    {
        let mut index = reg.index.lock().unwrap();
        index.records.get_mut(&record.id).unwrap().dir = lexical.join("child/..").join(&record.id);
        reg.persist(&index)?;
    }
    let reopened = root.open_at(&lexical)?;
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
    let reg = root.open_at(&base)?;
    let record = reg.create("legacy-alias")?;
    {
        let mut index = reg.index.lock().unwrap();
        index.records.get_mut(&record.id).unwrap().dir = alias.join(&record.id);
        reg.persist(&index)?;
    }
    let reopened = root.open_at(&base)?;
    assert_eq!(reopened.jail_for(&record.id)?.root, record.dir);
    fs::remove_dir_all(&record.dir)?;
    reopened.delete(&record.id)?;
    assert!(reopened.get(&record.id).is_none());
    Ok(())
}
