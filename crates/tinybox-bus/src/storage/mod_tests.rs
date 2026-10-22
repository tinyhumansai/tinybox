//! Tests for `TinyBox`'s pure storage collection contract.

use super::*;

#[test]
fn the_owner_collections_are_stable_and_include_migration_receipts() {
    let names: Vec<_> = collections().into_iter().map(|spec| spec.name).collect();
    assert_eq!(
        names,
        [
            BOX_COLLECTION,
            JAIL_INDEX_COLLECTION,
            TEMPLATE_COLLECTION,
            MIGRATIONS_COLLECTION,
            CLI_IMPORTS_COLLECTION,
        ]
    );
}

#[test]
fn current_and_legacy_collection_names_are_distinct() {
    assert_ne!(BOX_COLLECTION, V1_BOX_COLLECTION);
    assert_ne!(JAIL_INDEX_COLLECTION, V1_JAIL_INDEX_COLLECTION);
}

#[test]
fn every_declared_collection_has_a_valid_v2_spec() {
    for spec in collections() {
        assert!(spec.validate().is_ok(), "invalid collection {}", spec.name);
    }
    assert_eq!(BODY_VERSION, 2);
}
