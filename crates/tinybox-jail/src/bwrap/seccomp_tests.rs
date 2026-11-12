//! The seccomp deny list: what it holds and that it compiles per architecture.

use super::*;

#[test]
fn a_kernel_release_reads_as_major_and_minor() {
    assert_eq!(kernel_version("6.8.0-45-generic\n"), Some((6, 8)));
    assert_eq!(kernel_version("4.4.0"), Some((4, 4)));
    assert_eq!(
        kernel_version("5.15.167.4-microsoft-standard-WSL2"),
        Some((5, 15))
    );
    assert_eq!(kernel_version("garbage"), None);
}

#[test]
fn ptrace_is_denied_only_before_linux_4_8() {
    assert!(always_denied((4, 4)).contains(&libc::SYS_ptrace));
    assert!(!always_denied((4, 8)).contains(&libc::SYS_ptrace));
    assert!(!always_denied((6, 8)).contains(&libc::SYS_ptrace));
}

#[test]
fn the_escape_and_attack_surface_calls_are_denied() {
    let denied = always_denied((6, 8));
    for nr in [
        libc::SYS_keyctl,
        libc::SYS_bpf,
        libc::SYS_io_uring_setup,
        libc::SYS_mount,
        libc::SYS_setns,
        libc::SYS_open_by_handle_at,
        libc::SYS_process_vm_readv,
    ] {
        assert!(denied.contains(&nr), "syscall {nr} is not denied");
    }
}

#[test]
fn an_architecture_without_a_filter_is_refused() {
    let kind = target_arch("riscv64").err().map(|error| error.kind());
    assert_eq!(kind, Some(io::ErrorKind::Unsupported));
    assert!(target_arch("x86_64").is_ok() && target_arch("aarch64").is_ok());
}

#[test]
fn both_filters_compile_to_whole_bpf_instructions() -> io::Result<()> {
    let filters = filters((6, 8))?;

    assert_eq!(
        filters.len(),
        2,
        "the EPERM list and the clone3 ENOSYS filter"
    );
    for filter in &filters {
        assert!(
            !filter.is_empty() && filter.len() % 8 == 0,
            "{}",
            filter.len()
        );
    }
    Ok(())
}

#[test]
fn namespace_flags_are_matched_one_rule_each() -> io::Result<()> {
    // Any one flag must match on its own: rules in a chain are alternatives.
    assert_eq!(any_flag(&CLONE_NEW)?.len(), CLONE_NEW.len());
    Ok(())
}
