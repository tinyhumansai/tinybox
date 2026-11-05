//! The retention pass as a pure plan: given a listing of the workspace, which
//! instance a retained create adopts and which expired ones it deletes.
//!
//! Keeping the decision pure means the rules that protect other tenants of the
//! shared workspace (never touch an instance without a `tinybox.key` entry,
//! never delete one that is awake, never delete the box being adopted, never
//! delete more than [`MAX_EXPIRIES_PER_PASS`]) are tested without a transport.

use tinybox_core::BoxState;

use crate::api::InstanceView;

/// The most instances one pass deletes, so a workspace with a long backlog
/// never turns a single create into an unbounded burst of delete calls. The
/// rest go on later passes.
pub(crate) const MAX_EXPIRIES_PER_PASS: usize = 20;

/// What one retention pass decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetentionPlan {
    /// The existing instance to hand back instead of creating one.
    pub(crate) adopt: Option<InstanceView>,
    /// Ids to delete, longest-asleep first, at most [`MAX_EXPIRIES_PER_PASS`].
    pub(crate) expired: Vec<String>,
}

/// Decide a pass over `instances` for the owner `key` at `now_secs` (unix
/// seconds), deleting boxes that have slept longer than `delete_after_secs`.
///
/// - **Adopt** the oldest instance (by `created`; one without it counts as the
///   newest) whose `tinybox.key` equals `key` and whose status can run a
///   command now or soon, that is [`BoxState::Ready`] or [`BoxState::Creating`].
/// - **Expire** every other instance that has a `tinybox.key` entry, is
///   `sleeping`, and whose `slept_at` is strictly older than
///   `now_secs - delete_after_secs`. Instances without that entry belong to
///   someone else and are never listed here, and neither is one force-slept by
///   an unpaid wallet: that sleep says nothing about whether it is in use.
#[must_use]
pub(crate) fn plan(
    instances: &[InstanceView],
    key: &str,
    now_secs: u64,
    delete_after_secs: u64,
) -> RetentionPlan {
    let adopt = instances
        .iter()
        .filter(|view| view.retention_key() == Some(key))
        .filter(|view| matches!(view.state(), BoxState::Ready | BoxState::Creating))
        .min_by_key(|view| view.created.unwrap_or(u64::MAX))
        .cloned();

    let cutoff = now_secs.saturating_sub(delete_after_secs);
    let mut expired: Vec<(u64, &str)> = instances
        .iter()
        .filter(|view| view.has_retention_key() && view.is_sleeping() && !view.past_due)
        .filter(|view| adopt.as_ref().is_none_or(|adopted| adopted.id != view.id))
        .filter_map(|view| {
            view.slept_at
                .filter(|slept_at| *slept_at < cutoff)
                .map(|slept_at| (slept_at, view.id.as_str()))
        })
        .collect();
    expired.sort_unstable();
    RetentionPlan {
        adopt,
        expired: expired
            .into_iter()
            .take(MAX_EXPIRIES_PER_PASS)
            .map(|(_, id)| id.to_owned())
            .collect(),
    }
}

#[cfg(test)]
#[path = "retention_tests.rs"]
mod tests;
