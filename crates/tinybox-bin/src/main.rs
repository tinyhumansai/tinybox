//! The `tinybox` executable and the local storage composition root.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tinybox_bus::storage::{BODY_VERSION, CLI_IMPORTS_COLLECTION};
use tinybox_cli::Cli;
use tinybox_core::{BoxInfo, Error, SnapshotId, Store, TemplateName, Templates};
use tinybox_drivers::{DocumentBoxStore, DocumentTemplateStore};
use tinybox_host::LocalHost;
use tinystoragedrivers::StorageConfig;
use tinystoragedrivers_api::DocumentStore;
use tinystoragedrivers_types::{ErrorKind, Precondition, Scope, StorageError, WriteOptions};

const EXIT_TINYBOX_ERROR: u8 = 70;

#[tokio::main]
async fn main() -> ExitCode {
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    run(std::env::args_os().collect(), &mut out, &mut err).await
}

async fn run(args: Vec<std::ffi::OsString>, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(parse) => {
            let stream: &mut dyn Write = if parse.use_stderr() { err } else { out };
            let _ = write!(stream, "{parse}");
            let code = u8::try_from(parse.exit_code()).unwrap_or(EXIT_TINYBOX_ERROR);
            return ExitCode::from(code);
        }
    };

    let path = match state_path(&cli) {
        Ok(path) => path,
        Err(error) => {
            let _ = writeln!(err, "error: {error}");
            return ExitCode::from(EXIT_TINYBOX_ERROR);
        }
    };
    let (directory, store_identity) = match store_location(&path) {
        Ok(location) => location,
        Err(error) => {
            let _ = writeln!(err, "error: {error}");
            return ExitCode::from(EXIT_TINYBOX_ERROR);
        }
    };
    let templates_path = path.with_file_name("templates.json");

    let (store, templates) =
        match open_stores(&directory, &store_identity, &path, &templates_path).await {
            Ok(stores) => stores,
            Err(error) => {
                let _ = writeln!(err, "error: {error}");
                return ExitCode::from(EXIT_TINYBOX_ERROR);
            }
        };

    let code = match cli
        .dispatch(Arc::new(LocalHost::new()), store, templates, out, err)
        .await
    {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(err, "error: {error}");
            EXIT_TINYBOX_ERROR
        }
    };
    let _ = out.flush();
    let _ = err.flush();
    ExitCode::from(code)
}

fn state_path(cli: &Cli) -> Result<PathBuf, Error> {
    state_path_from_environment(
        cli,
        std::env::var_os("TINYBOX_STATE_DIR"),
        std::env::var_os("XDG_STATE_HOME"),
        std::env::var_os("HOME"),
    )
}

fn state_path_from_environment(
    cli: &Cli,
    state_dir: Option<std::ffi::OsString>,
    xdg_state_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf, Error> {
    if let Some(path) = cli.requested_store_path() {
        return Ok(path.to_owned());
    }
    if let Some(dir) = state_dir {
        return Ok(PathBuf::from(dir).join("boxes.json"));
    }
    if let Some(dir) = xdg_state_home {
        return Ok(PathBuf::from(dir).join("tinybox").join("boxes.json"));
    }
    home.map(|home| {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("tinybox")
            .join("boxes.json")
    })
    .ok_or_else(|| Error::Store {
        operation: "locate",
        message: "set TINYBOX_STATE_DIR, XDG_STATE_HOME, or HOME".to_owned(),
    })
}

async fn open_stores(
    directory: &Path,
    store_identity: &str,
    legacy_boxes: &Path,
    legacy_templates: &Path,
) -> Result<(Arc<dyn Store>, Arc<dyn Templates>), Error> {
    let backend = tinystoragedrivers::open(&StorageConfig::File {
        dir: directory.to_owned(),
    })
    .await
    .map_err(|error| storage_error("open", &error))?;
    let scope_name = format!("tinybox.cli.{store_identity}");
    let scope = Scope::new(&scope_name).map_err(|error| storage_error("scope", &error))?;
    let storage = backend
        .for_scope(&scope)
        .map_err(|error| storage_error("scope", &error))?;
    let boxes = DocumentBoxStore::open(storage.clone()).await?;
    let templates = DocumentTemplateStore::open(storage.clone()).await?;
    let documents = Arc::clone(storage.documents());

    import_legacy_boxes(legacy_boxes, &boxes, &documents).await?;
    import_legacy_templates(legacy_templates, &templates, &documents).await?;
    Ok((Arc::new(boxes), Arc::new(templates)))
}

async fn import_legacy_boxes(
    path: &Path,
    store: &dyn Store,
    documents: &Arc<dyn DocumentStore>,
) -> Result<(), Error> {
    let Some((bytes, identity)) = legacy_source(path, "box store")? else {
        return Ok(());
    };
    let digest = blake3::hash(&bytes).to_hex().to_string();
    if import_already_complete(documents, "boxes", &identity, &digest).await? {
        return Ok(());
    }
    let records: BTreeMap<String, BoxInfo> = parse_legacy_boxes(&bytes)?;
    for (key, record) in records {
        if record.id.as_str() != key {
            return Err(Error::Store {
                operation: "migrate",
                message: format!("legacy box key `{key}` does not match its embedded id"),
            });
        }
        match store.get(&record.id) {
            Ok(found) if found == record => continue,
            Ok(_) => {
                return Err(Error::Store {
                    operation: "migrate",
                    message: format!("legacy box `{key}` conflicts with the stored record"),
                });
            }
            Err(Error::UnknownBox { .. }) => {}
            Err(error) => return Err(error),
        }
        match store.insert(&record) {
            Ok(()) => {
                if store.get(&record.id)? != record {
                    return Err(Error::Store {
                        operation: "migrate",
                        message: format!("legacy box `{key}` failed readback verification"),
                    });
                }
            }
            Err(Error::DuplicateBox { .. }) => {
                if store.get(&record.id)? != record {
                    return Err(Error::Store {
                        operation: "migrate",
                        message: format!("legacy box `{key}` changed during import"),
                    });
                }
            }
            Err(error) => return Err(error),
        }
    }
    verify_legacy_unchanged(path, &identity, &digest, "box store")?;
    complete_import(documents, "boxes", &identity, &digest).await
}

async fn import_legacy_templates(
    path: &Path,
    store: &DocumentTemplateStore,
    documents: &Arc<dyn DocumentStore>,
) -> Result<(), Error> {
    let Some((bytes, identity)) = legacy_source(path, "template index")? else {
        return Ok(());
    };
    let digest = blake3::hash(&bytes).to_hex().to_string();
    if import_already_complete(documents, "templates", &identity, &digest).await? {
        return Ok(());
    }
    let records: BTreeMap<String, SnapshotId> = parse_legacy(&bytes, "template index")?;
    for (key, snapshot) in records {
        let name = TemplateName::new(key.clone())?;
        store
            .import_if_missing(&name, &snapshot)
            .map_err(|error| Error::Store {
                operation: "migrate",
                message: format!("legacy template `{key}`: {error}"),
            })?;
    }
    verify_legacy_unchanged(path, &identity, &digest, "template index")?;
    complete_import(documents, "templates", &identity, &digest).await
}

fn legacy_source(path: &Path, label: &str) -> Result<Option<(Vec<u8>, String)>, Error> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::io("inspect", &error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::Store {
            operation: "migrate",
            message: format!("legacy {label} path is not a regular file"),
        });
    }
    let bytes = std::fs::read(path).map_err(|error| Error::io("read", &error))?;
    Ok(Some((bytes, normalized_path(path)?)))
}

fn parse_legacy<T: serde::de::DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, Error> {
    serde_json::from_slice(bytes).map_err(|error| Error::Store {
        operation: "migrate",
        message: format!("legacy {label} is invalid JSON: {error}"),
    })
}

fn parse_legacy_boxes(bytes: &[u8]) -> Result<BTreeMap<String, BoxInfo>, Error> {
    let input: serde_json::Value = parse_legacy(bytes, "box store")?;
    let records: BTreeMap<String, BoxInfo> =
        serde_json::from_value(input.clone()).map_err(|error| Error::Store {
            operation: "migrate",
            message: format!("legacy box store is invalid JSON: {error}"),
        })?;
    let canonical = serde_json::to_value(&records).map_err(|error| Error::Store {
        operation: "migrate",
        message: format!("legacy box store could not be validated: {error}"),
    })?;
    reject_unknown_legacy_fields(&input, &canonical, "box store")?;
    Ok(records)
}

fn reject_unknown_legacy_fields(
    input: &serde_json::Value,
    canonical: &serde_json::Value,
    label: &str,
) -> Result<(), Error> {
    match (input, canonical) {
        (serde_json::Value::Object(input), serde_json::Value::Object(canonical)) => {
            for (key, value) in input {
                let Some(canonical_value) = canonical.get(key) else {
                    return Err(Error::Store {
                        operation: "migrate",
                        message: format!("legacy {label} contains unsupported field `{key}`"),
                    });
                };
                reject_unknown_legacy_fields(value, canonical_value, label)?;
            }
        }
        (serde_json::Value::Array(input), serde_json::Value::Array(canonical)) => {
            for (value, canonical_value) in input.iter().zip(canonical) {
                reject_unknown_legacy_fields(value, canonical_value, label)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn verify_legacy_unchanged(
    path: &Path,
    expected_identity: &str,
    expected_digest: &str,
    label: &str,
) -> Result<(), Error> {
    let (bytes, identity) = legacy_source(path, label)?.ok_or_else(|| Error::Store {
        operation: "migrate",
        message: format!("legacy {label} disappeared during import"),
    })?;
    if identity != expected_identity || blake3::hash(&bytes).to_hex().as_str() != expected_digest {
        return Err(Error::Store {
            operation: "migrate",
            message: format!("legacy {label} changed during import"),
        });
    }
    Ok(())
}

fn normalized_path(path: &Path) -> Result<String, Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| Error::Store {
        operation: "identify",
        message: "store path has no filename".to_owned(),
    })?;
    let parent =
        std::fs::canonicalize(parent).map_err(|error| Error::io("canonicalize", &error))?;
    parent
        .join(name)
        .into_os_string()
        .into_string()
        .map_err(|_| Error::Store {
            operation: "identify",
            message: "store path is not valid Unicode".to_owned(),
        })
}

fn store_location(path: &Path) -> Result<(PathBuf, String), Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| Error::io("create state directory", &error))?;
    let identity = normalized_path(path)?;
    let digest = blake3::hash(identity.as_bytes()).to_hex().to_string();
    let parent = Path::new(&identity).parent().ok_or_else(|| Error::Store {
        operation: "locate",
        message: "state file has no parent directory".to_owned(),
    })?;
    Ok((parent.join(".tinybox-storage").join(&digest), digest))
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ImportReceipt {
    source: String,
    digest: String,
    version: u32,
}

async fn import_already_complete(
    documents: &Arc<dyn DocumentStore>,
    kind: &str,
    source: &str,
    digest: &str,
) -> Result<bool, Error> {
    let Some(receipt) = documents
        .get(CLI_IMPORTS_COLLECTION, kind)
        .await
        .map_err(|error| storage_error("read import receipt", &error))?
    else {
        return Ok(false);
    };
    let receipt_doc: ImportReceipt = serde_json::from_value(receipt.doc).map_err(|error| {
        storage_error(
            "decode import receipt",
            &StorageError::serialization(error.to_string()),
        )
    })?;
    if receipt.meta.schema != BODY_VERSION || receipt_doc.version != 1 {
        return Err(Error::Store {
            operation: "migrate",
            message: format!("unsupported legacy {kind} import receipt"),
        });
    }
    if receipt_doc.source != source || receipt_doc.digest != digest {
        return Err(Error::Store {
            operation: "migrate",
            message: format!("legacy {kind} source changed after import"),
        });
    }
    Ok(true)
}

async fn complete_import(
    documents: &Arc<dyn DocumentStore>,
    kind: &str,
    source: &str,
    digest: &str,
) -> Result<(), Error> {
    let receipt = ImportReceipt {
        source: source.to_owned(),
        digest: digest.to_owned(),
        version: 1,
    };
    let body = serde_json::to_value(receipt).map_err(|error| {
        storage_error(
            "encode import receipt",
            &StorageError::serialization(error.to_string()),
        )
    })?;
    match documents
        .put_with(
            CLI_IMPORTS_COLLECTION,
            kind,
            body,
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if matches!(error.kind(), ErrorKind::Conflict | ErrorKind::AlreadyExists) => {
            if import_already_complete(documents, kind, source, digest).await? {
                Ok(())
            } else {
                Err(storage_error("record import receipt", &error))
            }
        }
        Err(error) => Err(storage_error("record import receipt", &error)),
    }
}

fn storage_error(operation: &'static str, error: &impl std::fmt::Display) -> Error {
    Error::Store {
        operation,
        message: error.to_string(),
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
