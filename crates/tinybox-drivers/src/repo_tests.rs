//! Tests for the typed repository: its debug form and how `update` ends.

use super::*;
use crate::faulty::{Faults, Faulty};
use serde_json::{Value, json};
use tinystoragedrivers_testkit::memory_storage;
use tinystoragedrivers_types::{CollectionSpec, Scope};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

const COLLECTION: &str = tinybox_bus::storage::BOX_COLLECTION;

async fn seeded() -> std::result::Result<Arc<dyn DocumentStore>, Box<dyn std::error::Error>> {
    let docs = memory_storage(&Scope::new("tinybox-repo-tests")?)
        .documents()
        .clone();
    docs.ensure_collection(&CollectionSpec::new(COLLECTION))
        .await?;
    Repo::<Value>::new(&docs, COLLECTION)?
        .put("a", &json!({ "n": 1 }))
        .await?;
    Ok(docs)
}

fn bump(current: Option<Value>) -> Value {
    let n = current.and_then(|doc| doc["n"].as_u64()).unwrap_or(0);
    json!({ "n": n + 1 })
}

#[tokio::test]
async fn the_debug_form_names_the_collection_and_not_the_backend() -> TestResult {
    let repo = Repo::<Value>::new(&seeded().await?, COLLECTION)?;
    let debug = format!("{repo:?}");
    assert!(debug.starts_with("Repo"), "{debug}");
    assert!(debug.contains(COLLECTION), "{debug}");
    assert!(!debug.contains("docs"), "{debug}");
    Ok(())
}

#[tokio::test]
async fn an_update_whose_write_fails_returns_that_error_without_retrying() -> TestResult {
    let inner = seeded().await?;
    let faults = Faults {
        put: true,
        ..Faults::default()
    };
    let docs: Arc<dyn DocumentStore> = Faulty::new(Arc::clone(&inner), faults);
    let mut calls = 0;
    let result = Repo::<Value>::new(&docs, COLLECTION)?
        .update("a", |current| {
            calls += 1;
            Ok(Some(bump(current)))
        })
        .await;
    let error = result
        .err()
        .ok_or("a failed write was reported as written")?;
    assert_ne!(error.kind(), ErrorKind::Conflict, "{error}");
    assert_eq!(calls, 1, "only a conflict is retried");
    let stored = Repo::<Value>::new(&inner, COLLECTION)?.get("a").await?;
    assert_eq!(stored.map(|found| found.doc), Some(json!({ "n": 1 })));
    Ok(())
}

#[tokio::test]
async fn an_update_that_always_conflicts_returns_the_last_conflict_after_its_budget() -> TestResult
{
    let inner = seeded().await?;
    let docs: Arc<dyn DocumentStore> = Faulty::with_conflicts(Arc::clone(&inner), usize::MAX);
    let mut repo = Repo::<Value>::new(&docs, COLLECTION)?;
    repo.attempts = 3;
    let mut calls = 0;
    let result = repo
        .update("a", |current| {
            calls += 1;
            Ok(Some(bump(current)))
        })
        .await;
    let error = result
        .err()
        .ok_or("an update that never landed succeeded")?;
    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(error.to_string().contains("injected conflict"), "{error}");
    assert_eq!(calls, 3, "one try per attempt");
    Ok(())
}
