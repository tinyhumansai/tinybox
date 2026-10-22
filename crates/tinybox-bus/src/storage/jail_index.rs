//! Converting a jail registry's index between its own JSON and the v2 body.
//!
//! Both directions live here, in the contract, so the migration step and the
//! store that reads the migrated body share one definition.
//!
//! The registry (`tinybox-jail`) owns the index shape and keeps it in seconds
//! (`created_at_unix`, `updated_at_unix`) next to a `schema_version`, because
//! the same JSON is the legacy `index.json` file. The `box.jail_index` body
//! holds the same records with one millisecond field per instant
//! (`created_ms`, `updated_ms`) and no version field: the document's metadata
//! carries the body version.

use std::io;

use serde_json::Value;

/// The index version the registry writes; restored on read.
const REGISTRY_SCHEMA_VERSION: u64 = 1;

/// (registry field, body field)
const TIMES: [(&str, &str); 2] = [
    ("created_at_unix", "created_ms"),
    ("updated_at_unix", "updated_ms"),
];

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The v2 body for a registry's index JSON.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] when a time field is not a whole number of
/// seconds that fits in milliseconds.
pub fn to_body(mut index: Value) -> io::Result<Value> {
    if let Some(object) = index.as_object_mut() {
        object.remove("schema_version");
    }
    for record in records_mut(&mut index) {
        for (seconds_field, ms_field) in TIMES {
            let Some(raw) = record.remove(seconds_field) else {
                continue;
            };
            let ms = raw
                .as_u64()
                .and_then(|seconds| seconds.checked_mul(1000))
                .and_then(|ms| i64::try_from(ms).ok())
                .ok_or_else(|| invalid(format!("{seconds_field} is not a time in seconds")))?;
            record.insert(ms_field.to_owned(), Value::from(ms));
        }
    }
    Ok(index)
}

/// The registry's index JSON for a stored v2 body.
#[must_use]
pub fn from_body(mut body: Value) -> Value {
    for record in records_mut(&mut body) {
        for (seconds_field, ms_field) in TIMES {
            if let Some(ms) = record.remove(ms_field).and_then(|raw| raw.as_i64()) {
                let seconds = u64::try_from(ms.div_euclid(1000)).unwrap_or(0);
                record.insert(seconds_field.to_owned(), Value::from(seconds));
            }
        }
    }
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "schema_version".to_owned(),
            Value::from(REGISTRY_SCHEMA_VERSION),
        );
    }
    body
}

fn records_mut(index: &mut Value) -> impl Iterator<Item = &mut serde_json::Map<String, Value>> {
    index
        .get_mut("records")
        .and_then(Value::as_object_mut)
        .into_iter()
        .flat_map(|records| records.values_mut())
        .filter_map(Value::as_object_mut)
}

#[cfg(test)]
#[path = "jail_index_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
