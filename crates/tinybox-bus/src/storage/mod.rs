//! `TinyBox`'s host-independent storage collection and legacy-body vocabulary.
//!
//! Owners declare these collections with [`collections`] and migrate their
//! legacy rows when their storage adapters open. The bus contract describes
//! names and conversions only; it has no engine or migration runner.

use tinystoragedrivers_types::CollectionSpec;

pub mod box_v1;
pub mod jail_index;

/// The collection that holds one document per box, keyed by box id.
pub const BOX_COLLECTION: &str = "box.boxes";

/// The collection that holds one index document per jail registry.
pub const JAIL_INDEX_COLLECTION: &str = "box.jail_index";

/// The collection that holds named snapshot templates.
pub const TEMPLATE_COLLECTION: &str = "box.templates";

/// The per-owner migration receipts collection.
pub const MIGRATIONS_COLLECTION: &str = "box.migrations";
/// Completed one-time imports of legacy CLI JSON files.
pub const CLI_IMPORTS_COLLECTION: &str = "box.cli_imports";

/// The v1 name of [`BOX_COLLECTION`].
pub const V1_BOX_COLLECTION: &str = "tinybox_boxes";

/// The v1 name of [`JAIL_INDEX_COLLECTION`].
pub const V1_JAIL_INDEX_COLLECTION: &str = "tinybox_jail_index";

/// The body schema version used by `TinyBox`'s current documents.
pub const BODY_VERSION: u32 = 2;

/// Collections owned by `TinyBox`, as pure declarations for the host to ensure.
#[must_use]
pub fn collections() -> Vec<CollectionSpec> {
    [
        BOX_COLLECTION,
        JAIL_INDEX_COLLECTION,
        TEMPLATE_COLLECTION,
        MIGRATIONS_COLLECTION,
        CLI_IMPORTS_COLLECTION,
    ]
    .into_iter()
    .map(CollectionSpec::new)
    .collect()
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
