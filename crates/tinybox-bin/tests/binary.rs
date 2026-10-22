//! Process-level coverage for the executable's storage composition.

use std::io;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef, SnapshotId, TemplateName,
    Templates, WorkspaceSource,
};
use tinybox_drivers::DocumentTemplateStore;
use tinystoragedrivers::StorageConfig;
use tinystoragedrivers_types::Scope;

fn tinybox(state: &Path, args: &[&str]) -> io::Result<Output> {
    tinybox_at(&state.join("boxes.json"), args)
}

fn tinybox_at(store: &Path, args: &[&str]) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_tinybox"))
        .arg("--store")
        .arg(store)
        .args(args)
        .output()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn old_box(id: &str) -> Result<BoxInfo, Box<dyn std::error::Error>> {
    let spec = BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
        WorkspaceSource::LocalDir("/srv/work".into()),
    );
    Ok(BoxInfo::new(BoxId::new(id)?, BoxState::Ready, spec))
}

#[test]
fn separate_processes_share_document_storage_without_recreating_json_state_files() -> io::Result<()>
{
    let state = TempDir::new()?;
    let workspace = TempDir::new()?;
    let workspace_path = workspace.path().display().to_string();

    let created = tinybox(state.path(), &["create", "--dir", &workspace_path])?;
    assert!(created.status.success(), "{}", stderr(&created));
    assert_eq!(stdout(&created).trim(), "box-0");
    assert!(!state.path().join("boxes.json").exists());

    let listed = tinybox(state.path(), &["ls"])?;
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert!(stdout(&listed).contains("box-0"));
    Ok(())
}

#[test]
fn legacy_box_file_is_imported_idempotently_and_kept_as_the_source()
-> Result<(), Box<dyn std::error::Error>> {
    let state = TempDir::new()?;
    let path = state.path().join("boxes.json");
    let records = [("box-legacy", old_box("box-legacy")?)]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let bytes = serde_json::to_vec(&records)?;
    std::fs::write(&path, &bytes)?;

    let first = tinybox(state.path(), &["ls"])?;
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(stdout(&first).contains("box-legacy"));
    assert_eq!(std::fs::read(&path)?, bytes);

    let removed = tinybox(state.path(), &["rm", "box-legacy"])?;
    assert!(removed.status.success(), "{}", stderr(&removed));

    let second = tinybox(state.path(), &["ls"])?;
    assert!(second.status.success(), "{}", stderr(&second));
    assert!(!stdout(&second).contains("box-legacy"));
    assert_eq!(std::fs::read(&path)?, bytes);
    Ok(())
}

#[test]
fn unsupported_legacy_box_fields_fail_closed_without_recording_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let state = TempDir::new()?;
    let path = state.path().join("boxes.json");
    let mut record = serde_json::to_value(old_box("box-future")?)?;
    record["spec"]["future_policy"] = serde_json::json!({"mode": "new"});
    let bytes = serde_json::to_vec(
        &[("box-future".to_owned(), record)]
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>(),
    )?;
    std::fs::write(&path, &bytes)?;

    let rejected = tinybox(state.path(), &["ls"])?;
    assert_eq!(rejected.status.code(), Some(70));
    assert!(stderr(&rejected).contains("unsupported field `future_policy`"));
    assert_eq!(std::fs::read(&path)?, bytes);

    let mut record = serde_json::to_value(old_box("box-future")?)?;
    // Historical files may omit the supported ports field; that remains valid.
    record
        .get_mut("spec")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("serialized box spec was not an object")?
        .remove("ports");
    let valid = [("box-future".to_owned(), record)]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    std::fs::write(&path, serde_json::to_vec(&valid)?)?;
    let imported = tinybox(state.path(), &["ls"])?;
    assert!(imported.status.success(), "{}", stderr(&imported));
    assert!(stdout(&imported).contains("box-future"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_unicode_store_paths_are_rejected_instead_of_collapsed() -> io::Result<()> {
    use std::os::unix::ffi::OsStringExt;

    let state = TempDir::new()?;
    let path = state
        .path()
        .join(std::ffi::OsString::from_vec(b"box-\xff.json".to_vec()));
    let output = Command::new(env!("CARGO_BIN_EXE_tinybox"))
        .arg("--store")
        .arg(path)
        .arg("ls")
        .output()?;
    assert_eq!(output.status.code(), Some(70));
    assert!(String::from_utf8_lossy(&output.stderr).contains("store path is not valid Unicode"));
    Ok(())
}

#[test]
fn released_v0140_public_writer_files_import_and_read_back() -> io::Result<()> {
    let state = TempDir::new()?;
    let boxes = state.path().join("boxes.json");
    let templates = state.path().join("templates.json");
    let box_bytes = include_bytes!("fixtures/legacy-v0.1.40/boxes.json");
    let template_bytes = include_bytes!("fixtures/legacy-v0.1.40/templates.json");
    std::fs::write(&boxes, box_bytes)?;
    std::fs::write(&templates, template_bytes)?;

    let listed_boxes = tinybox(state.path(), &["ls"])?;
    assert!(listed_boxes.status.success(), "{}", stderr(&listed_boxes));
    assert!(stdout(&listed_boxes).contains("box-released"));
    let listed_templates = tinybox(state.path(), &["template", "ls"])?;
    assert!(
        listed_templates.status.success(),
        "{}",
        stderr(&listed_templates)
    );
    assert!(stdout(&listed_templates).contains("released-template\tsnapshot-released"));
    assert_eq!(std::fs::read(boxes)?, box_bytes);
    assert_eq!(std::fs::read(templates)?, template_bytes);
    Ok(())
}

#[test]
fn distinct_store_paths_in_one_directory_have_isolated_state() -> io::Result<()> {
    let state = TempDir::new()?;
    let workspace = TempDir::new()?;
    let workspace_path = workspace.path().display().to_string();
    let first_path = state.path().join("first.json");
    let second_path = state.path().join("second.json");

    for path in [&first_path, &second_path] {
        let created = tinybox_at(path, &["create", "--dir", &workspace_path])?;
        assert!(created.status.success(), "{}", stderr(&created));
        assert_eq!(stdout(&created).trim(), "box-0");
    }
    let first = tinybox_at(&first_path, &["ls"])?;
    let second = tinybox_at(&second_path, &["ls"])?;
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(second.status.success(), "{}", stderr(&second));
    assert_eq!(stdout(&first).matches("box-0").count(), 1);
    assert_eq!(stdout(&second).matches("box-0").count(), 1);
    Ok(())
}

#[test]
fn changed_legacy_source_fails_closed_after_a_completed_import()
-> Result<(), Box<dyn std::error::Error>> {
    let state = TempDir::new()?;
    let path = state.path().join("boxes.json");
    let records = [("box-legacy", old_box("box-legacy")?)]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let bytes = serde_json::to_vec(&records)?;
    std::fs::write(&path, &bytes)?;
    let imported = tinybox(state.path(), &["ls"])?;
    assert!(imported.status.success(), "{}", stderr(&imported));

    std::fs::write(&path, b"{}")?;
    let changed = tinybox(state.path(), &["ls"])?;

    assert_eq!(changed.status.code(), Some(70));
    assert!(stderr(&changed).contains("source changed after import"));
    assert_eq!(std::fs::read(&path)?, b"{}");
    Ok(())
}

#[test]
fn an_older_box_record_without_ports_is_imported() -> Result<(), Box<dyn std::error::Error>> {
    let state = TempDir::new()?;
    let path = state.path().join("boxes.json");
    let bytes = br#"{"box-0":{"id":"box-0","state":"Ready","spec":{
        "runner":{"host":"local","sandbox":"passthrough"},
        "workspace":{"host":"local","sandbox":"passthrough"},
        "source":{"LocalDir":"/tmp"},
        "resources":{"cpu_millis":2000,"memory_bytes":2147483648,"pids_max":512,"disk_bytes":8589934592},
        "lifecycle":{"Ephemeral":{"ttl":{"secs":3600,"nanos":0}}},
        "network":"Denied","env":{}}}}"#;
    std::fs::write(&path, bytes)?;

    let listed = tinybox(state.path(), &["ls"])?;

    assert!(listed.status.success(), "{}", stderr(&listed));
    assert!(stdout(&listed).contains("box-0"));
    assert_eq!(std::fs::read(&path)?, bytes);
    Ok(())
}

#[test]
fn invalid_legacy_json_fails_closed_and_keeps_the_source() -> Result<(), Box<dyn std::error::Error>>
{
    let state = TempDir::new()?;
    let path = state.path().join("boxes.json");
    let bytes = b"{ not json";
    std::fs::write(&path, bytes)?;

    let outcome = tinybox(state.path(), &["ls"])?;

    assert_eq!(outcome.status.code(), Some(70));
    assert!(stderr(&outcome).contains("legacy box store is invalid JSON"));
    assert_eq!(std::fs::read(&path)?, bytes);
    Ok(())
}

#[test]
fn legacy_template_file_is_imported_without_overwriting_its_source()
-> Result<(), Box<dyn std::error::Error>> {
    let state = TempDir::new()?;
    let path = state.path().join("templates.json");
    let records = [("release", SnapshotId::new("snap-a")?)]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let bytes = serde_json::to_vec(&records)?;
    std::fs::write(&path, &bytes)?;

    let listed = tinybox(state.path(), &["template", "ls"])?;
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert!(stdout(&listed).contains("release"));
    assert!(stdout(&listed).contains("snap-a"));
    assert_eq!(std::fs::read(&path)?, bytes);
    Ok(())
}

#[test]
fn a_legacy_box_key_mismatch_fails_closed_and_preserves_the_source()
-> Result<(), Box<dyn std::error::Error>> {
    let state = TempDir::new()?;
    let path = state.path().join("boxes.json");
    let records = [("wrong-key", old_box("box-legacy")?)]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let bytes = serde_json::to_vec(&records)?;
    std::fs::write(&path, &bytes)?;

    let result = tinybox(state.path(), &["ls"])?;
    assert_eq!(result.status.code(), Some(70));
    assert!(stderr(&result).contains("does not match its embedded id"));
    assert_eq!(std::fs::read(&path)?, bytes);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_template_conflict_does_not_overwrite_current_state()
-> Result<(), Box<dyn std::error::Error>> {
    let state = TempDir::new()?;
    let legacy_path = state.path().join("templates.json");
    let legacy = [("release", SnapshotId::new("snap-old")?)]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let legacy_bytes = serde_json::to_vec(&legacy)?;
    std::fs::write(&legacy_path, &legacy_bytes)?;

    let identity = std::fs::canonicalize(state.path())?
        .join("boxes.json")
        .to_string_lossy()
        .into_owned();
    let digest = blake3::hash(identity.as_bytes()).to_hex().to_string();
    let backend = tinystoragedrivers::open(&StorageConfig::File {
        dir: state.path().join(".tinybox-storage").join(&digest),
    })
    .await?;
    let scope_name = format!("tinybox.cli.{digest}");
    let scope = Scope::new(&scope_name)?;
    let storage = backend.for_scope(&scope)?;
    let templates = DocumentTemplateStore::open(storage).await?;
    let name = TemplateName::new("release")?;
    templates.save(&name, &SnapshotId::new("snap-new")?)?;

    let result = tinybox(state.path(), &["template", "ls"])?;

    assert_eq!(result.status.code(), Some(70));
    assert!(stderr(&result).contains("legacy template `release`"));
    assert_eq!(std::fs::read(&legacy_path)?, legacy_bytes);
    assert_eq!(templates.get(&name)?.as_str(), "snap-new");
    Ok(())
}
