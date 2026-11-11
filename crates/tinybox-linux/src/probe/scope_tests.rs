//! The scope probe claims a limit only for a delegated controller.

use super::*;

#[test]
fn each_limit_follows_its_own_delegated_controller() {
    let probe = ScopeProbe::from_parts(true, Some("cpuset cpu io memory\n"));
    let support = probe.constraint_support();

    assert_eq!(support.enforcement(Constraint::Cpu), Enforcement::Enforced);
    assert_eq!(
        support.enforcement(Constraint::Memory),
        Enforcement::Enforced
    );
    assert_eq!(
        support.enforcement(Constraint::Pids),
        Enforcement::Unsupported
    );
}

#[test]
fn nothing_is_claimed_without_a_reachable_manager() {
    let probe = ScopeProbe::from_parts(false, Some("cpu memory pids"));

    assert_eq!(probe, ScopeProbe::default());
    for constraint in [Constraint::Cpu, Constraint::Memory, Constraint::Pids] {
        assert_eq!(
            probe.constraint_support().enforcement(constraint),
            Enforcement::Unsupported
        );
    }
}

#[test]
fn nothing_is_claimed_without_a_delegated_cgroup() {
    // cgroup v1, or no user manager cgroup at all.
    let probe = ScopeProbe::from_parts(true, None);

    assert!(!probe.cpu && !probe.memory && !probe.pids);
    assert_eq!(
        probe.constraint_support().enforcement(Constraint::Memory),
        Enforcement::Unsupported
    );
}

#[test]
fn a_controller_name_must_match_exactly() {
    // `cpuset` is not `cpu`.
    let probe = ScopeProbe::from_parts(true, Some("cpuset"));
    assert!(!probe.cpu);
}
