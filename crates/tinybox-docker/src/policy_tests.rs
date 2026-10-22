use super::*;

fn mounts(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|p| (*p).to_owned()).collect()
}

#[test]
fn ordinary_run_has_no_issues() {
    assert_eq!(
        run_policy_issues(
            Some("none"),
            Some("/home/u/project"),
            &mounts(&["/usr/lib"])
        )
        .len(),
        0
    );
    assert_eq!(run_policy_issues(None, None, &[]).len(), 0);
}

#[test]
fn host_network_is_reported() {
    let issues = run_policy_issues(Some("host"), Some("/work"), &[]);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].contains("host network"));
}

#[test]
fn dangerous_read_only_mounts_are_reported() {
    let issues = run_policy_issues(
        None,
        Some("/work"),
        &mounts(&["/", "/etc", "/var/run/docker.sock", "/proc", "/sys", "/usr"]),
    );
    assert_eq!(issues.len(), 5);
}

#[test]
fn trailing_separator_does_not_hide_a_dangerous_path() {
    assert_eq!(
        run_policy_issues(None, Some("/etc/"), &mounts(&["/sys/"])).len(),
        2
    );
}

#[test]
fn dangerous_workspace_is_reported() {
    let issues = run_policy_issues(None, Some("/"), &[]);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].contains("Workspace"));
}

#[test]
fn skipped_workspace_is_not_checked() {
    assert_eq!(run_policy_issues(None, None, &[]).len(), 0);
}

#[test]
fn files_inside_a_dangerous_directory_are_allowed() {
    assert_eq!(
        run_policy_issues(None, Some("/etc/nginx"), &mounts(&["/etc/hosts"])).len(),
        0
    );
}

#[cfg(unix)]
#[test]
fn audit_h1_aliases_of_dangerous_mounts_are_reported() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let link = tmp.path().join("root");
    std::os::unix::fs::symlink("/", &link)?;
    let link = link.display().to_string();
    let accepted: Vec<&str> = [
        "/run/docker.sock",
        "/var/run",
        "/etc/../etc",
        link.as_str(),
        "/proc/self/root",
        "/run/user/1000/docker.sock",
        "/var/lib/docker/volumes",
        "/var",
        "relative/dir",
        "/work:/etc",
    ]
    .into_iter()
    .filter(|m| run_policy_issues(None, None, &mounts(&[m])).is_empty())
    .collect();
    assert!(
        accepted.is_empty(),
        "policy accepted dangerous mount aliases {accepted:?}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_symlink_to_a_socket_is_reported() -> std::io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let socket = tmp.path().join("agent.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket)?;
    let link = tmp.path().join("innocent");
    std::os::unix::fs::symlink(&socket, &link)?;
    let link = link.display().to_string();
    assert_eq!(run_policy_issues(None, Some(&link), &[]).len(), 1);
    Ok(())
}
