//! The retention pass as a pure plan: which listed instance a create adopts and
//! which expired ones it deletes, with no transport involved.

use super::*;

use std::collections::BTreeMap;

use crate::api::KEY_METADATA_KEY;

const NOW: u64 = 10_000_000;
const DAY: u64 = 86_400;

fn view(
    id: &str,
    status: &str,
    key: Option<&str>,
    created: u64,
    slept_at: Option<u64>,
) -> InstanceView {
    let mut view = InstanceView::new(id, status);
    view.created = Some(created);
    view.slept_at = slept_at;
    view.metadata = key
        .map(|key| BTreeMap::from([(KEY_METADATA_KEY.to_owned(), serde_json::Value::from(key))]));
    view
}

fn plan_for(instances: &[InstanceView]) -> RetentionPlan {
    plan(instances, "user-42", NOW, 30 * DAY)
}

#[test]
fn nothing_is_adopted_when_no_instance_carries_the_key() {
    let listed = [
        view("a", "running", Some("someone-else"), 1, None),
        view("b", "running", None, 2, None),
    ];
    assert_eq!(plan_for(&listed).adopt, None);
}

#[test]
fn the_oldest_usable_match_is_adopted() {
    let listed = [
        view("newer", "running", Some("user-42"), 300, None),
        view("oldest", "sleeping", Some("user-42"), 100, Some(NOW - 5)),
        view("middle", "running", Some("user-42"), 200, None),
    ];
    assert_eq!(
        plan_for(&listed).adopt.map(|v| v.id),
        Some("oldest".to_owned())
    );
}

#[test]
fn a_transitional_match_is_usable_but_a_stopped_or_failed_one_is_not() {
    let listed = [
        view("stopped", "stopped", Some("user-42"), 1, None),
        view("broken", "error", Some("user-42"), 2, None),
        view("waking", "waking", Some("user-42"), 3, None),
    ];
    assert_eq!(
        plan_for(&listed).adopt.map(|v| v.id),
        Some("waking".to_owned())
    );
}

#[test]
fn an_instance_without_a_created_time_counts_as_newest() {
    let mut undated = view("undated", "running", Some("user-42"), 0, None);
    undated.created = None;
    let listed = [
        undated,
        view("dated", "running", Some("user-42"), 500, None),
    ];
    assert_eq!(
        plan_for(&listed).adopt.map(|v| v.id),
        Some("dated".to_owned())
    );
}

#[test]
fn only_sleeping_boxes_slept_longer_than_the_delay_expire() {
    let cutoff = NOW - 30 * DAY;
    let listed = [
        view(
            "old-sleeper",
            "sleeping",
            Some("other"),
            1,
            Some(cutoff - 1),
        ),
        view(
            "exactly-at-the-limit",
            "sleeping",
            Some("other"),
            1,
            Some(cutoff),
        ),
        view(
            "recent-sleeper",
            "sleeping",
            Some("other"),
            1,
            Some(NOW - DAY),
        ),
        view(
            "old-but-running",
            "running",
            Some("other"),
            1,
            Some(cutoff - 100),
        ),
        view(
            "sleeping-without-a-time",
            "sleeping",
            Some("other"),
            1,
            None,
        ),
    ];
    assert_eq!(plan_for(&listed).expired, ["old-sleeper"]);
}

#[test]
fn an_instance_without_the_key_entry_is_never_expired() {
    let listed = [view("foreign", "sleeping", None, 1, Some(1))];
    assert!(plan_for(&listed).expired.is_empty());
}

#[test]
fn the_adopted_box_is_never_expired() {
    let listed = [
        view("mine", "sleeping", Some("user-42"), 1, Some(1)),
        view("duplicate", "sleeping", Some("user-42"), 2, Some(1)),
    ];
    let plan = plan_for(&listed);
    assert_eq!(plan.adopt.map(|v| v.id), Some("mine".to_owned()));
    // A newer duplicate for the same owner is expired like any other.
    assert_eq!(plan.expired, ["duplicate"]);
}

#[test]
fn at_most_twenty_are_expired_per_pass_oldest_sleepers_first() {
    let listed: Vec<InstanceView> = (0..25)
        .map(|n| {
            view(
                &format!("box-{n:02}"),
                "sleeping",
                Some("other"),
                1,
                Some(100 + (24 - n)),
            )
        })
        .collect();
    let expired = plan_for(&listed).expired;
    assert_eq!(expired.len(), MAX_EXPIRIES_PER_PASS);
    assert_eq!(MAX_EXPIRIES_PER_PASS, 20);
    // box-24 slept at 100, the earliest; box-05 is the 20th earliest.
    assert_eq!(expired.first().map(String::as_str), Some("box-24"));
    assert_eq!(expired.last().map(String::as_str), Some("box-05"));
}

#[test]
fn a_delay_longer_than_the_clock_expires_nothing() {
    let listed = [view("a", "sleeping", Some("other"), 1, Some(0))];
    assert!(plan(&listed, "user-42", 10, u64::MAX).expired.is_empty());
}
