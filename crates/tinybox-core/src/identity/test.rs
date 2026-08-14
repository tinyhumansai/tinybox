//! Tests for identifier validation.
//!
//! Tests return [`Result`] and use `?` for the paths that should succeed, so
//! that no test needs `unwrap` or `expect` — the same lint applies here as to
//! library code.

use std::collections::HashSet;
use std::str::FromStr;

use super::{BoxId, HostRef, SandboxRef, SnapshotId};
use crate::error::{Error, Result};

#[test]
fn accepts_the_permitted_character_set() -> Result<()> {
    let id = BoxId::new("Build-7f3a_v1.2")?;
    assert_eq!(id.as_str(), "Build-7f3a_v1.2");
    Ok(())
}

#[test]
fn rejects_an_empty_identifier() {
    assert_eq!(
        BoxId::new("").err(),
        Some(Error::InvalidIdentifier {
            kind: "box id",
            value: String::new(),
        })
    );
}

#[test]
fn rejects_an_identifier_longer_than_the_limit() -> Result<()> {
    let at_limit = "a".repeat(64);
    assert_eq!(BoxId::new(&at_limit)?.as_str(), at_limit);

    let too_long = "a".repeat(65);
    assert!(BoxId::new(&too_long).is_err());
    Ok(())
}

#[test]
fn rejects_path_traversal_and_separators() {
    for value in ["..", ".", "../escape", "a/b", "a\\b"] {
        assert!(
            BoxId::new(value).is_err(),
            "{value:?} should be rejected as a box id"
        );
    }
}

#[test]
fn rejects_whitespace_and_shell_metacharacters() {
    for value in ["a b", "a;b", "a$b", "a\nb", "a\"b"] {
        assert!(
            BoxId::new(value).is_err(),
            "{value:?} should be rejected as a box id"
        );
    }
}

#[test]
fn names_the_kind_it_was_validating() {
    for (kind, error) in [
        (
            "snapshot id",
            SnapshotId::new("").err().map(|e| e.to_string()),
        ),
        (
            "host reference",
            HostRef::new("").err().map(|e| e.to_string()),
        ),
        (
            "sandbox reference",
            SandboxRef::new("").err().map(|e| e.to_string()),
        ),
    ] {
        assert!(
            error.is_some_and(|message| message.contains(kind)),
            "the error should name {kind}"
        );
    }
}

#[test]
fn round_trips_through_string_conversions() -> Result<()> {
    let id = BoxId::new("build-1")?;

    assert_eq!(id.to_string(), "build-1");
    assert_eq!(id.as_ref() as &str, "build-1");
    assert_eq!(id.clone().into_string(), "build-1");
    assert_eq!(BoxId::from_str("build-1")?, id);
    assert!(BoxId::from_str("bad id").is_err());
    Ok(())
}

#[test]
fn distinct_identifiers_order_and_hash_independently() -> Result<()> {
    let mut ids = [BoxId::new("c")?, BoxId::new("a")?, BoxId::new("b")?];
    ids.sort();

    let sorted = ids.iter().map(BoxId::as_str).collect::<Vec<_>>();
    assert_eq!(sorted, ["a", "b", "c"]);
    assert_eq!(ids.iter().cloned().collect::<HashSet<_>>().len(), 3);
    Ok(())
}
