use super::*;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef, WorkspaceSource,
};
use tinystoragedrivers_api::{DocumentStore, Storage};
use tinystoragedrivers_testkit::{Failing, memory_storage};
use tinystoragedrivers_types::{
    Capabilities, CollectionSpec, ErrorKind, Filter, Page, Precondition, Query, Scope, Sort,
    StorageError, Version, Versioned, WriteOptions,
};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
    values.iter().map(std::ffi::OsString::from).collect()
}

fn is_exit_code(actual: ExitCode, expected: ExitCode) -> bool {
    format!("{actual:?}") == format!("{expected:?}")
}

fn sample_box(
    id: &str,
    workspace: &str,
) -> std::result::Result<BoxInfo, Box<dyn std::error::Error>> {
    Ok(BoxInfo::new(
        BoxId::new(id)?,
        BoxState::Ready,
        BoxSpec::new(
            Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
            WorkspaceSource::LocalDir(workspace.into()),
        ),
    ))
}

async fn file_test_storage(
    directory: &Path,
    identity: &str,
) -> std::result::Result<Storage, Box<dyn std::error::Error>> {
    let backend = tinystoragedrivers::open(&StorageConfig::File {
        dir: directory.to_owned(),
    })
    .await?;
    let scope_name = format!("tinybox.cli.{identity}");
    let scope = Scope::new(&scope_name)?;
    Ok(backend.for_scope(&scope)?)
}

type RaceInsert = (Arc<dyn Store>, BoxInfo);
type PostWriteChange = (Arc<dyn Store>, BoxId, BoxState);

#[derive(Debug)]
struct ImportDocumentPort {
    inner: Failing<dyn DocumentStore>,
    race_store: Mutex<Option<RaceInsert>>,
    after_write: Mutex<Option<PostWriteChange>>,
    race_started: AtomicBool,
}

impl ImportDocumentPort {
    fn new(inner: Arc<dyn DocumentStore>) -> Arc<Self> {
        Arc::new(Self {
            inner: Failing::new(inner),
            race_store: Mutex::new(None),
            after_write: Mutex::new(None),
            race_started: AtomicBool::new(false),
        })
    }

    fn race_insert(&self, store: Arc<dyn Store>, info: BoxInfo) {
        *self
            .race_store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((store, info));
    }

    fn change_state_after_write(&self, store: Arc<dyn Store>, id: BoxId, state: BoxState) {
        *self
            .after_write
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((store, id, state));
    }
}

#[async_trait]
impl DocumentStore for ImportDocumentPort {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    async fn ensure_collection(
        &self,
        spec: &CollectionSpec,
    ) -> std::result::Result<(), StorageError> {
        self.inner.ensure_collection(spec).await
    }

    async fn get(
        &self,
        collection: &str,
        id: &str,
    ) -> std::result::Result<Option<Versioned<Value>>, StorageError> {
        self.inner.get(collection, id).await
    }

    async fn put(
        &self,
        collection: &str,
        id: &str,
        value: Value,
        precondition: Precondition,
    ) -> std::result::Result<Version, StorageError> {
        self.put_with(collection, id, value, precondition, WriteOptions::default())
            .await
    }

    async fn put_with(
        &self,
        collection: &str,
        id: &str,
        value: Value,
        precondition: Precondition,
        options: WriteOptions,
    ) -> std::result::Result<Version, StorageError> {
        let race = if collection == tinybox_bus::storage::BOX_COLLECTION
            && self
                .race_started
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.race_store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        } else {
            None
        };
        if let Some((store, info)) = race {
            std::thread::spawn(move || store.insert(&info))
                .join()
                .map_err(|_| StorageError::backend("race writer panicked"))?
                .map_err(|error| StorageError::backend(format!("race writer failed: {error}")))?;
        }
        let version = self
            .inner
            .put_with(collection, id, value, precondition, options)
            .await?;
        let post_write = if collection == tinybox_bus::storage::BOX_COLLECTION {
            self.after_write
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        } else {
            None
        };
        if let Some((store, box_id, state)) = post_write {
            std::thread::spawn(move || store.set_state(&box_id, state))
                .join()
                .map_err(|_| StorageError::backend("post-write mutation panicked"))?
                .map_err(|error| {
                    StorageError::backend(format!("post-write mutation failed: {error}"))
                })?;
        }
        Ok(version)
    }

    async fn delete(
        &self,
        collection: &str,
        id: &str,
        precondition: Precondition,
    ) -> std::result::Result<bool, StorageError> {
        self.inner.delete(collection, id, precondition).await
    }

    async fn query(
        &self,
        collection: &str,
        query: &Query,
    ) -> std::result::Result<Page<Versioned<Value>>, StorageError> {
        self.inner.query(collection, query).await
    }

    async fn count(
        &self,
        collection: &str,
        filter: &Filter,
    ) -> std::result::Result<u64, StorageError> {
        self.inner.count(collection, filter).await
    }

    async fn delete_where(
        &self,
        collection: &str,
        filter: &Filter,
    ) -> std::result::Result<u64, StorageError> {
        self.inner.delete_where(collection, filter).await
    }

    async fn claim(
        &self,
        collection: &str,
        filter: &Filter,
        sort: &[Sort],
        patch: &Value,
    ) -> std::result::Result<Option<Versioned<Value>>, StorageError> {
        self.inner.claim(collection, filter, sort, patch).await
    }

    async fn drop_collection(&self, collection: &str) -> std::result::Result<(), StorageError> {
        self.inner.drop_collection(collection).await
    }
}

fn import_test_storage(storage: &Storage, documents: Arc<dyn DocumentStore>) -> Storage {
    Storage::new(
        documents,
        Arc::clone(storage.streams()),
        Arc::clone(storage.kv()),
        Arc::clone(storage.blobs()),
        Arc::clone(storage.queues()),
        Arc::clone(storage.secrets()),
    )
}

async fn import_test_store(
    identity: &str,
) -> std::result::Result<
    (Storage, Arc<ImportDocumentPort>, DocumentBoxStore),
    Box<dyn std::error::Error>,
> {
    let scope_name = format!("tinybox.cli.import.{identity}");
    let scope = Scope::new(&scope_name)?;
    let base = memory_storage(&scope);
    let documents = ImportDocumentPort::new(Arc::clone(base.documents()));
    let storage = import_test_storage(&base, documents.clone());
    let store = DocumentBoxStore::open(storage.clone()).await?;
    Ok((storage, documents, store))
}

fn write_legacy_box(path: &Path, key: &str, record: &BoxInfo) -> TestResult {
    let bytes = serde_json::to_vec(
        &[(key.to_owned(), record.clone())]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
    )?;
    std::fs::write(path, bytes)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_run_dispatches_with_explicit_store_and_reports_parse_errors() -> TestResult {
    let root = TempDir::new()?;
    let path = root.path().join("boxes.json");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let success = run(
        args(&[
            "tinybox",
            "--store",
            path.to_str().ok_or("unicode path")?,
            "ls",
        ]),
        &mut stdout,
        &mut stderr,
    )
    .await;
    assert!(is_exit_code(success, ExitCode::SUCCESS));
    assert_eq!(stderr.as_slice(), b"");
    assert!(root.path().join(".tinybox-storage").is_dir());

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let help = run(args(&["tinybox", "--help"]), &mut stdout, &mut stderr).await;
    assert!(is_exit_code(help, ExitCode::SUCCESS));
    assert!(stdout.windows(6).any(|window| window == b"Usage:"));
    assert_eq!(stderr.as_slice(), b"");

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let dispatch_error = run(
        args(&[
            "tinybox",
            "--store",
            path.to_str().ok_or("unicode path")?,
            "template",
            "rm",
            "missing",
        ]),
        &mut stdout,
        &mut stderr,
    )
    .await;
    assert!(is_exit_code(
        dispatch_error,
        ExitCode::from(EXIT_TINYBOX_ERROR)
    ));
    assert_ne!(stderr.as_slice(), b"");

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let invalid = run(
        args(&["tinybox", "--not-an-option"]),
        &mut stdout,
        &mut stderr,
    )
    .await;
    assert!(is_exit_code(invalid, ExitCode::from(2)));
    assert!(stderr.windows(6).any(|window| window == b"error:"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executable_run_rejects_a_store_path_without_a_filename() -> TestResult {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = run(
        args(&["tinybox", "--store", "/", "ls"]),
        &mut stdout,
        &mut stderr,
    )
    .await;

    assert!(is_exit_code(result, ExitCode::from(EXIT_TINYBOX_ERROR)));
    assert!(stderr.windows(6).any(|window| window == b"error:"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opening_a_backend_below_a_regular_file_reports_the_open_context() -> TestResult {
    let root = TempDir::new()?;
    let blocker = root.path().join("not-a-directory");
    std::fs::write(&blocker, b"keep")?;
    let error = open_stores(
        &blocker.join("backend"),
        "isolated",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("backend open must fail"))?;

    assert!(matches!(
        error,
        Error::Store {
            operation: "open",
            ..
        }
    ));
    assert_eq!(std::fs::read(blocker)?, b"keep");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_composition_imports_once_and_preserves_later_box_changes() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    std::fs::write(
        &boxes_path,
        include_bytes!("../tests/fixtures/legacy-v0.1.40/boxes.json"),
    )?;
    std::fs::write(
        &templates_path,
        include_bytes!("../tests/fixtures/legacy-v0.1.40/templates.json"),
    )?;

    let (store, templates) = open_stores(
        &storage_dir,
        "independent-store",
        &boxes_path,
        &templates_path,
    )
    .await?;
    let id = BoxId::new("box-released")?;
    let original = store.get(&id)?;
    assert_eq!(original.id, id);
    store.remove(&id)?;
    templates.save(
        &TemplateName::new("released-template")?,
        &SnapshotId::new("later-snapshot")?,
    )?;

    let (reopened, reopened_templates) = open_stores(
        &storage_dir,
        "independent-store",
        &boxes_path,
        &templates_path,
    )
    .await?;
    assert!(matches!(reopened.get(&id), Err(Error::UnknownBox { .. })));
    assert_eq!(
        reopened_templates.get(&TemplateName::new("released-template")?)?,
        SnapshotId::new("later-snapshot")?
    );
    assert!(
        boxes_path.exists(),
        "the importer never consumes its source"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_import_accepts_an_identical_destination_without_rewriting_it() -> TestResult {
    let root = TempDir::new()?;
    let storage = file_test_storage(&root.path().join("storage"), "same-box").await?;
    let boxes = DocumentBoxStore::open(storage.clone()).await?;
    let record = sample_box("existing", "/workspace")?;
    boxes.insert(&record)?;
    let legacy_path = root.path().join("boxes.json");
    let records = [("existing".to_owned(), record.clone())]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    std::fs::write(&legacy_path, serde_json::to_vec(&records)?)?;

    import_legacy_boxes(&legacy_path, &boxes, &Arc::clone(storage.documents())).await?;

    assert_eq!(boxes.get(&record.id)?, record);
    assert!(
        storage
            .documents()
            .get(CLI_IMPORTS_COLLECTION, "boxes")
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_current_box_is_not_mistaken_for_a_missing_destination() -> TestResult {
    let root = TempDir::new()?;
    let storage = file_test_storage(&root.path().join("storage"), "bad-current-box").await?;
    let boxes = DocumentBoxStore::open(storage.clone()).await?;
    let record = sample_box("existing", "/legacy")?;
    storage
        .documents()
        .put_with(
            tinybox_bus::storage::BOX_COLLECTION,
            "existing",
            serde_json::json!({"state": "not-a-box"}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await?;
    let legacy_path = root.path().join("boxes.json");
    std::fs::write(
        &legacy_path,
        serde_json::to_vec(
            &[("existing".to_owned(), record)]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        )?,
    )?;

    let error = import_legacy_boxes(&legacy_path, &boxes, &Arc::clone(storage.documents()))
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("malformed current record must fail closed"))?;

    assert!(matches!(error, Error::Store { .. }));
    assert!(
        storage
            .documents()
            .get(CLI_IMPORTS_COLLECTION, "boxes")
            .await?
            .is_none()
    );
    assert_eq!(
        std::fs::read(legacy_path)?,
        serde_json::to_vec(
            &[("existing".to_owned(), sample_box("existing", "/legacy")?)]
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        )?
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_legacy_json_fails_open_without_replacing_the_source() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    let bytes = b"{not-json";
    std::fs::write(&boxes_path, bytes)?;

    let error = open_stores(
        &storage_dir,
        "malformed-store",
        &boxes_path,
        &templates_path,
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("malformed source must fail closed"))?;

    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));
    assert_eq!(std::fs::read(&boxes_path)?, bytes);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_legacy_source_is_rejected_after_import_completion() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    std::fs::write(
        &boxes_path,
        include_bytes!("../tests/fixtures/legacy-v0.1.40/boxes.json"),
    )?;
    open_stores(&storage_dir, "changed-source", &boxes_path, &templates_path).await?;
    std::fs::write(&boxes_path, b"{}")?;

    let error = open_stores(&storage_dir, "changed-source", &boxes_path, &templates_path)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("changed legacy source must be rejected"))?;

    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));
    assert_eq!(std::fs::read(&boxes_path)?, b"{}");
    Ok(())
}

#[test]
fn path_identity_requires_an_existing_parent_and_unicode_names() -> TestResult {
    let root = TempDir::new()?;
    let missing = root.path().join("missing").join("boxes.json");
    assert!(normalized_path(&missing).is_err());

    let plain = root.path().join("boxes.json");
    let (directory, identity) = store_location(&plain)?;
    assert!(directory.ends_with(&identity));
    let canonical_root = std::fs::canonicalize(root.path())?;
    assert!(directory.starts_with(canonical_root));
    Ok(())
}

#[test]
fn normalized_paths_reject_root_and_non_unicode_names() -> TestResult {
    assert!(normalized_path(Path::new("/")).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let root = TempDir::new()?;
        let non_unicode = root
            .path()
            .join(std::ffi::OsStr::from_bytes(b"box-\xff.json"));
        assert!(normalized_path(&non_unicode).is_err());
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let invalid = Path::new(std::ffi::OsStr::from_bytes(b"bad\0path"));
        assert!(matches!(
            legacy_source(invalid, "fixture"),
            Err(Error::Io {
                operation: "inspect",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn legacy_source_verification_detects_disappearance_and_changed_bytes() -> TestResult {
    let root = TempDir::new()?;
    let path = root.path().join("boxes.json");
    std::fs::write(&path, b"{}")?;
    let (_, identity) =
        legacy_source(&path, "box store")?.ok_or_else(|| std::io::Error::other("source exists"))?;
    let original = blake3::hash(b"{}").to_hex().to_string();
    verify_legacy_unchanged(&path, &identity, &original, "box store")?;

    std::fs::write(&path, b"{\"changed\":true}")?;
    assert!(matches!(
        verify_legacy_unchanged(&path, &identity, &original, "box store"),
        Err(Error::Store {
            operation: "migrate",
            ..
        })
    ));
    std::fs::remove_file(&path)?;
    assert!(matches!(
        verify_legacy_unchanged(&path, &identity, &original, "box store"),
        Err(Error::Store {
            operation: "migrate",
            ..
        })
    ));
    Ok(())
}

#[test]
fn state_path_uses_explicit_store_then_state_home_fallbacks_in_order() -> TestResult {
    let explicit = Cli::try_parse_from(args(&["tinybox", "--store", "/chosen/boxes.json", "ls"]))?;
    assert_eq!(
        state_path_from_environment(
            &explicit,
            Some("state".into()),
            Some("xdg".into()),
            Some("home".into()),
        )?,
        PathBuf::from("/chosen/boxes.json")
    );

    let default = Cli::try_parse_from(args(&["tinybox", "ls"]))?;
    assert_eq!(
        state_path_from_environment(
            &default,
            Some("state".into()),
            Some("xdg".into()),
            Some("home".into()),
        )?,
        PathBuf::from("state/boxes.json")
    );
    assert_eq!(
        state_path_from_environment(&default, None, Some("xdg".into()), Some("home".into()))?,
        PathBuf::from("xdg/tinybox/boxes.json")
    );
    assert_eq!(
        state_path_from_environment(&default, None, None, Some("home".into()))?,
        PathBuf::from("home/.local/state/tinybox/boxes.json")
    );
    assert!(state_path_from_environment(&default, None, None, None).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn legacy_source_requires_a_regular_nonsymlink_file() -> TestResult {
    use std::os::unix::fs::symlink;

    let root = TempDir::new()?;
    let missing = root.path().join("missing.json");
    assert!(legacy_source(&missing, "fixture")?.is_none());
    assert!(legacy_source(root.path(), "fixture").is_err());

    let source = root.path().join("source.json");
    std::fs::write(&source, b"{}")?;
    let link = root.path().join("link.json");
    symlink(&source, &link)?;
    assert!(legacy_source(&link, "fixture").is_err());
    Ok(())
}

#[test]
fn a_file_cannot_be_used_as_the_state_directory() -> TestResult {
    let root = TempDir::new()?;
    let file = root.path().join("not-a-directory");
    std::fs::write(&file, b"sentinel")?;
    assert!(store_location(&file.join("boxes.json")).is_err());
    assert_eq!(std::fs::read(&file)?, b"sentinel");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_box_import_checks_keys_and_store_race_outcomes() -> TestResult {
    let root = TempDir::new()?;
    let source = root.path().join("boxes.json");
    let record = sample_box("expected", "/legacy")?;
    write_legacy_box(&source, "different-key", &record)?;
    let (_bad_key_storage, bad_key_documents, bad_key_store) = import_test_store("bad-key").await?;
    let bad_key_docs: Arc<dyn DocumentStore> = bad_key_documents;
    let error = import_legacy_boxes(&source, &bad_key_store, &bad_key_docs)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("mismatched key must fail"))?;
    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));

    write_legacy_box(&source, "expected", &record)?;
    let (matching_storage, matching_documents, matching_store) =
        import_test_store("matching-race").await?;
    let matching_base = import_test_storage(
        &matching_storage,
        Arc::clone(&matching_documents.inner.inner),
    );
    let matching_writer = Arc::new(DocumentBoxStore::open(matching_base).await?);
    matching_documents.race_insert(matching_writer, record.clone());
    let matching_docs: Arc<dyn DocumentStore> = matching_documents.clone();
    import_legacy_boxes(&source, &matching_store, &matching_docs).await?;
    assert_eq!(matching_store.get(&record.id)?, record);

    let (differing_storage, differing_documents, differing_store) =
        import_test_store("differing-race").await?;
    let differing_base = import_test_storage(
        &differing_storage,
        Arc::clone(&differing_documents.inner.inner),
    );
    let differing_writer = Arc::new(DocumentBoxStore::open(differing_base).await?);
    let differing = sample_box("expected", "/concurrent-writer")?;
    differing_documents.race_insert(differing_writer, differing);
    let differing_docs: Arc<dyn DocumentStore> = differing_documents.clone();
    let error = import_legacy_boxes(&source, &differing_store, &differing_docs)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("different concurrent record must fail"))?;
    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));

    let (changed_storage, changed_documents, changed_store) =
        import_test_store("readback-change").await?;
    let changed_base =
        import_test_storage(&changed_storage, Arc::clone(&changed_documents.inner.inner));
    let changed_writer = Arc::new(DocumentBoxStore::open(changed_base).await?);
    changed_documents.change_state_after_write(
        changed_writer,
        record.id.clone(),
        BoxState::Stopped,
    );
    let changed_docs: Arc<dyn DocumentStore> = changed_documents;
    let error = import_legacy_boxes(&source, &changed_store, &changed_docs)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("changed post-insert readback must fail"))?;
    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));
    assert_eq!(changed_store.get(&record.id)?.state, BoxState::Stopped);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_box_import_propagates_storage_read_and_write_failures() -> TestResult {
    let root = TempDir::new()?;
    let source = root.path().join("boxes.json");
    let record = sample_box("expected", "/legacy")?;
    write_legacy_box(&source, "expected", &record)?;

    let (_, failing_read_documents, failing_read_store) = import_test_store("read-error").await?;
    failing_read_documents
        .inner
        .faults
        .fail_operation_nth("documents.get", 2, ErrorKind::Backend);
    let failing_read_docs: Arc<dyn DocumentStore> = failing_read_documents;
    let error = import_legacy_boxes(&source, &failing_read_store, &failing_read_docs)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("store read error must propagate"))?;
    assert!(matches!(
        error,
        Error::Store {
            operation: "read",
            ..
        }
    ));

    let (_, failing_write_documents, failing_write_store) =
        import_test_store("write-error").await?;
    failing_write_documents.inner.faults.fail_operation_nth(
        "documents.put_with",
        1,
        ErrorKind::Backend,
    );
    let failing_write_docs: Arc<dyn DocumentStore> = failing_write_documents;
    let error = import_legacy_boxes(&source, &failing_write_store, &failing_write_docs)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("storage write error must propagate"))?;
    assert!(matches!(error, Error::Store { .. }));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_receipts_validate_schema_and_reconcile_conditional_write_races() -> TestResult {
    let root = TempDir::new()?;
    let storage = file_test_storage(&root.path().join("storage"), "receipt").await?;
    let documents = Arc::clone(storage.documents());
    let _stores = open_stores(
        &root.path().join("storage"),
        "receipt",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await?;

    complete_import(&documents, "boxes", "source", "digest").await?;
    complete_import(&documents, "boxes", "source", "digest").await?;
    let conflict = complete_import(&documents, "boxes", "other-source", "digest")
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("different receipt must conflict"))?;
    assert!(matches!(
        conflict,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));

    let malformed_storage = file_test_storage(&root.path().join("malformed"), "malformed").await?;
    let malformed_documents = Arc::clone(malformed_storage.documents());
    let _malformed_stores = open_stores(
        &root.path().join("malformed"),
        "malformed",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await?;
    malformed_documents
        .put_with(
            CLI_IMPORTS_COLLECTION,
            "boxes",
            serde_json::json!({"unexpected": true}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await?;
    let error = import_already_complete(&malformed_documents, "boxes", "source", "digest")
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("malformed receipt must fail closed"))?;
    assert!(matches!(error, Error::Store { .. }));

    let schema_storage = file_test_storage(&root.path().join("schema"), "schema").await?;
    let schema_documents = Arc::clone(schema_storage.documents());
    let _schema_stores = open_stores(
        &root.path().join("schema"),
        "schema",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await?;
    schema_documents
        .put_with(
            CLI_IMPORTS_COLLECTION,
            "boxes",
            serde_json::json!({"source": "source", "digest": "digest", "version": 1}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION + 1),
        )
        .await?;
    assert!(
        import_already_complete(&schema_documents, "boxes", "source", "digest")
            .await
            .is_err()
    );

    let invalid_version_storage =
        file_test_storage(&root.path().join("version"), "version").await?;
    let invalid_version_documents = Arc::clone(invalid_version_storage.documents());
    let _version_stores = open_stores(
        &root.path().join("version"),
        "version",
        &root.path().join("missing-boxes.json"),
        &root.path().join("missing-templates.json"),
    )
    .await?;
    invalid_version_documents
        .put_with(
            CLI_IMPORTS_COLLECTION,
            "boxes",
            serde_json::json!({"source": "source", "digest": "digest", "version": 2}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await?;
    assert!(
        import_already_complete(&invalid_version_documents, "boxes", "source", "digest")
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn import_path_and_error_helpers_preserve_operation_context() -> TestResult {
    let root = TempDir::new()?;
    let missing_parent = root.path().join("missing").join("boxes.json");
    assert!(normalized_path(&missing_parent).is_err());
    assert!(store_location(Path::new("/")).is_err());

    let mapped = storage_error(
        "read import receipt",
        &StorageError::backend("injected backend failure"),
    );
    assert!(matches!(
        mapped,
        Error::Store {
            operation: "read import receipt",
            ..
        }
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conflicting_current_box_blocks_legacy_import() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    let (store, _) = open_stores(
        &storage_dir,
        "conflicting-import",
        &boxes_path,
        &templates_path,
    )
    .await?;
    let current = sample_box("same-id", "/new-state")?;
    store.insert(&current)?;
    let legacy = sample_box("same-id", "/old-state")?;
    std::fs::write(
        &boxes_path,
        serde_json::to_vec(
            &[("same-id".to_owned(), legacy)]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        )?,
    )?;

    let error = open_stores(
        &storage_dir,
        "conflicting-import",
        &boxes_path,
        &templates_path,
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("conflicting destination must fail closed"))?;
    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));
    assert_eq!(store.get(&BoxId::new("same-id")?)?, current);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_template_name_is_not_recorded_as_imported() -> TestResult {
    let root = TempDir::new()?;
    let storage_dir = root.path().join("storage");
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    let bytes = br#"{"":"snapshot"}"#;
    std::fs::write(&templates_path, bytes)?;

    let error = open_stores(
        &storage_dir,
        "invalid-template-name",
        &boxes_path,
        &templates_path,
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("empty template key must fail validation"))?;
    assert!(matches!(
        error,
        Error::InvalidIdentifier {
            kind: "template name",
            ..
        }
    ));
    assert_eq!(std::fs::read(&templates_path)?, bytes);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conflicting_template_blocks_legacy_import() -> TestResult {
    let root = TempDir::new()?;
    let boxes_path = root.path().join("boxes.json");
    let templates_path = root.path().join("templates.json");
    let (store, templates) = open_stores(
        &root.path().join("storage"),
        "conflicting-template",
        &boxes_path,
        &templates_path,
    )
    .await?;
    drop(store);

    let name = TemplateName::new("released-template")?;
    templates.save(&name, &SnapshotId::new("current-snapshot")?)?;
    let records = [(
        "released-template".to_owned(),
        SnapshotId::new("legacy-snapshot")?,
    )]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    std::fs::write(&templates_path, serde_json::to_vec(&records)?)?;

    let storage = file_test_storage(&root.path().join("storage"), "conflicting-template").await?;
    let error = import_legacy_templates(
        &templates_path,
        &DocumentTemplateStore::open(storage.clone()).await?,
        &Arc::clone(storage.documents()),
    )
    .await
    .err()
    .ok_or_else(|| std::io::Error::other("different destination template must fail closed"))?;
    assert!(matches!(
        error,
        Error::Store {
            operation: "migrate",
            ..
        }
    ));
    assert_eq!(templates.get(&name)?, SnapshotId::new("current-snapshot")?);
    Ok(())
}

#[test]
fn legacy_box_parser_rejects_unknown_fields_at_object_and_array_depths() -> TestResult {
    let mut value = serde_json::to_value(sample_box("unknown-field", "/legacy")?)?;
    value["unexpected"] = serde_json::json!(true);
    let unknown = [("unknown-field".to_owned(), value)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert!(matches!(
        parse_legacy_boxes(&serde_json::to_vec(&unknown)?),
        Err(Error::Store {
            operation: "migrate",
            ..
        })
    ));

    let mut record = sample_box("array-field", "/legacy")?;
    record.spec.network = tinybox_core::NetworkPolicy::Allowlist(
        tinybox_core::EgressAllowlist::new(["example.test"], [443]),
    );
    let mut value = serde_json::to_value(record)?;
    value["spec"]["network"]["Allowlist"]["hosts"] =
        serde_json::json!(["example.test", "second.example.test"]);
    let array = [("array-field".to_owned(), value)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert!(parse_legacy_boxes(&serde_json::to_vec(&array)?).is_ok());
    Ok(())
}
