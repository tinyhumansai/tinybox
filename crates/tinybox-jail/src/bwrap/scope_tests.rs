//! Tests for which limits a bubblewrap jail claims and when it applies them.

use super::*;

fn delegated(controllers: &str) -> ResourceScope {
    ResourceScope::with_probe(
        "/nonexistent/systemd-run",
        ScopeProbe::from_parts(true, Some(controllers)),
    )
}

fn limited_jail(root: &Path) -> Jail {
    let mut jail = Jail::new(root, "t").deny_net();
    jail.resources = Some(tinybox_core::Resources::DEFAULT);
    jail
}

#[test]
fn only_delegated_controllers_are_claimed_and_none_without_a_scope() {
    let support = with_limits(ConstraintSupport::NONE, Some(&delegated("cpu memory")));
    assert_eq!(support.enforcement(Constraint::Cpu), Enforcement::Enforced);
    assert_eq!(support.enforcement(Constraint::Memory), Enforcement::Enforced);
    assert_eq!(support.enforcement(Constraint::Pids), Enforcement::Unsupported);

    let none = with_limits(ConstraintSupport::NONE, None);
    for limit in LIMITS {
        assert_eq!(none.enforcement(limit), Enforcement::Unsupported);
    }
}

#[test]
fn no_resources_or_no_scope_means_no_scope_command() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let unlimited = Jail::new(root.path(), "t").deny_net();
    assert!(prefix_for(&unlimited, Some(&delegated("cpu memory pids")), true)?.is_none());
    assert!(prefix_for(&limited_jail(root.path()), None, true)?.is_none());
    // Nothing delegated: a soft request has nothing to apply.
    assert!(prefix_for(&limited_jail(root.path()), Some(&delegated("")), true)?.is_none());
    Ok(())
}

#[test]
fn a_soft_request_runs_unlimited_when_the_scope_command_cannot_be_built() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    // The stand-in `systemd-run` does not exist, so building its command fails.
    let prefix = prefix_for(
        &limited_jail(root.path()),
        Some(&delegated("cpu memory pids")),
        true,
    )?;
    assert!(prefix.is_none());
    Ok(())
}

#[test]
fn a_hard_request_fails_closed_when_the_scope_command_cannot_be_built() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let jail = limited_jail(root.path()).with_hard_requirements([Constraint::Pids]);
    let kind = prefix_for(&jail, Some(&delegated("pids")), true)
        .err()
        .map(|error| error.kind());
    assert_eq!(kind, Some(io::ErrorKind::Unsupported));
    Ok(())
}

#[test]
fn a_hard_limit_is_refused_for_a_jail_sharing_the_host_network() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let mut jail = Jail::new(root.path(), "t").with_hard_requirements([Constraint::Memory]);
    jail.resources = Some(tinybox_core::Resources::DEFAULT);
    assert!(jail.allow_net);

    let error = prefix_for(&jail, Some(&delegated("memory")), false)
        .err()
        .ok_or_else(|| io::Error::other("a shared-network hard limit was accepted"))?;
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("host network"), "{error}");
    Ok(())
}

#[test]
fn a_hard_limit_is_refused_for_a_jail_granted_the_manager_or_cgroup_paths() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    for granted in ["/run/user/1000", "/sys/fs/cgroup", "/run"] {
        let jail = limited_jail(root.path())
            .add_read_only(granted)
            .with_hard_requirements([Constraint::Cpu]);
        let error = prefix_for(&jail, Some(&delegated("cpu")), true)
            .err()
            .ok_or_else(|| io::Error::other(format!("a grant of {granted} was accepted")))?;
        assert!(error.to_string().contains("/run or /sys"), "{granted}: {error}");
    }
    Ok(())
}

#[test]
fn an_unrelated_grant_and_a_private_network_leave_no_escape_route() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let jail = limited_jail(root.path()).add_read_only("/srv/data");
    assert!(escape_route(&jail, true).is_none());
    // `allow_net` is fine once the network is private (pasta).
    let mut open = jail.clone();
    open.allow_net = true;
    assert!(escape_route(&open, true).is_none());
    assert!(escape_route(&open, false).is_some());
    Ok(())
}
