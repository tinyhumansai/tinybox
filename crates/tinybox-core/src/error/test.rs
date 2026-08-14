//! Tests for the crate-wide error type.
//!
//! Every variant needs a test that produces its rendered message, because the
//! message is what an operator sees and the variant data is what a caller
//! matches on.

use super::Error;
use crate::capability::Capability;
use crate::runtime::BoxState;

#[test]
fn an_invalid_identifier_reports_the_kind_and_the_text() {
    let error = Error::InvalidIdentifier {
        kind: "box id",
        value: "../escape".to_owned(),
    };

    assert_eq!(
        error.to_string(),
        r#"identifier "../escape" is not a valid box id"#
    );
}

#[test]
fn an_unsupported_capability_names_the_sandbox() {
    let error = Error::Unsupported {
        sandbox: "passthrough".to_owned(),
        capability: Capability::MemorySnapshot,
    };

    assert_eq!(
        error.to_string(),
        "sandbox passthrough does not support memory snapshots"
    );
}

#[test]
fn a_zero_resource_limit_names_the_field() {
    let error = Error::ZeroResourceLimit {
        limit: "memory_bytes",
    };

    assert_eq!(
        error.to_string(),
        "resource limit memory_bytes must be greater than zero"
    );
}

#[test]
fn a_missing_box_and_a_missing_snapshot_read_differently() {
    let missing_box = Error::UnknownBox {
        id: "build-1".to_owned(),
    };
    let missing_snapshot = Error::UnknownSnapshot {
        id: "snap-1".to_owned(),
    };

    assert_eq!(missing_box.to_string(), "no box with id build-1");
    assert_eq!(missing_snapshot.to_string(), "no snapshot with id snap-1");
    assert_ne!(missing_box, missing_snapshot);
}

#[test]
fn an_invalid_state_reports_both_the_actual_and_the_required_state() {
    let error = Error::InvalidState {
        id: "build-1".to_owned(),
        actual: BoxState::Archived,
        expected: BoxState::Ready,
    };

    assert_eq!(
        error.to_string(),
        "box build-1 is archived but must be ready for this operation"
    );
}

#[test]
fn errors_implement_the_standard_error_trait() {
    let error = Error::UnknownBox {
        id: "build-1".to_owned(),
    };
    let as_std: &dyn std::error::Error = &error;

    assert_eq!(as_std.to_string(), "no box with id build-1");
    assert!(as_std.source().is_none());
}
