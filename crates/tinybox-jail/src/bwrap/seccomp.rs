//! The seccomp filters a bubblewrap jail starts under.
//!
//! A deny list, not an allow list: jailed programs are arbitrary (MCP servers on
//! Node, Python or Go, shell commands), so the filter removes kernel attack
//! surface and escape primitives no ordinary tool needs rather than guessing
//! what every runtime calls. A denied call fails with `EPERM`; `clone3` fails
//! with `ENOSYS` instead, because its flags live in memory a filter cannot read
//! and the C library only falls back to `clone`, whose flags it can, on
//! `ENOSYS`. Seccomp takes one action per filter, so that is a second filter.
//!
//! `bwrap --add-seccomp-fd` installs them on the child after its own mount and
//! namespace setup. A program built for another architecture (an i386 binary on
//! `x86_64`) is killed by the architecture check every filter starts with.
//!
//! Left reachable on purpose: `ptrace` on Linux 4.8 and later, where seccomp is
//! re-checked after a tracer changes a call and the jail's pid namespace limits
//! it to the jail's own processes (on older kernels it is denied); `unshare`
//! and `clone` without a `CLONE_NEW*` flag; `personality`; and socket families,
//! which the network namespace already confines.

use std::collections::BTreeMap;
use std::io;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// The namespace-creating `clone`/`unshare` flags. `CLONE_NEWTIME` is
/// `unshare`-only: in `clone` its bit is part of the exit signal.
const CLONE_NEW: [u64; 7] = [
    0x0002_0000, // CLONE_NEWNS
    0x0200_0000, // CLONE_NEWCGROUP
    0x0400_0000, // CLONE_NEWUTS
    0x0800_0000, // CLONE_NEWIPC
    0x1000_0000, // CLONE_NEWUSER
    0x2000_0000, // CLONE_NEWPID
    0x4000_0000, // CLONE_NEWNET
];
const CLONE_NEWTIME: u64 = 0x80;

/// `ioctl` requests that type into the controlling terminal.
const TIOCSTI: u64 = 0x5412;
const TIOCLINUX: u64 = 0x541C;

/// The x32 ABI's syscall numbers on `x86_64`: same numbers with this bit set,
/// under the same architecture value, so each denial is repeated with it.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: i64 = 0x4000_0000;

/// Syscalls denied whatever their arguments.
fn always_denied(kernel: (u32, u32)) -> Vec<i64> {
    let mut denied = vec![
        // The user's kernel keyrings hold credentials.
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        // Other processes' memory.
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        // Kernel programs, perf and fault handling: privilege-escalation surface.
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // The jail's view is fixed by bwrap; nothing inside remounts it.
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_setns,
        // File handles open any file on a mount, granted or not.
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        // Host-wide or privileged state.
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_clock_adjtime,
        libc::SYS_adjtimex,
        libc::SYS_syslog,
        libc::SYS_quotactl,
        libc::SYS_vhangup,
    ];
    #[cfg(target_arch = "x86_64")]
    denied.extend([
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_modify_ldt,
        libc::SYS_uselib,
        libc::SYS__sysctl,
    ]);
    // Before 4.8 a tracer could rewrite a call after seccomp had allowed it.
    if kernel < (4, 8) {
        denied.push(libc::SYS_ptrace);
    }
    denied
}

/// One rule per flag: the call matches when any of them is set in argument 0.
fn any_flag(flags: &[u64]) -> io::Result<Vec<SeccompRule>> {
    flags
        .iter()
        .map(|&flag| {
            condition(0, SeccompCmpOp::MaskedEq(flag), flag)
                .and_then(|condition| rule(vec![condition]))
        })
        .collect()
}

fn condition(arg: u8, op: SeccompCmpOp, value: u64) -> io::Result<SeccompCondition> {
    SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value).map_err(|error| invalid(&error))
}

fn rule(conditions: Vec<SeccompCondition>) -> io::Result<SeccompRule> {
    SeccompRule::new(conditions).map_err(|error| invalid(&error))
}

fn invalid(error: &seccompiler::BackendError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

/// The seccomp target for an architecture name (`std::env::consts::ARCH`),
/// if a filter is defined for it.
fn target_arch(name: &str) -> io::Result<TargetArch> {
    match name {
        "x86_64" => Ok(TargetArch::x86_64),
        "aarch64" => Ok(TargetArch::aarch64),
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("no seccomp filter is defined for {other}; the jail is refused"),
        )),
    }
}

/// `major.minor` of a `uname -r` style release (`6.8.0-45-generic`).
pub(super) fn kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Every rule keyed by syscall, with the x32 twin of each on `x86_64`.
fn with_x32(rules: BTreeMap<i64, Vec<SeccompRule>>) -> BTreeMap<i64, Vec<SeccompRule>> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut rules = rules;
        let twins: Vec<(i64, Vec<SeccompRule>)> = rules
            .iter()
            .filter(|(nr, _)| **nr & X32_SYSCALL_BIT == 0)
            .map(|(nr, chain)| (nr | X32_SYSCALL_BIT, chain.clone()))
            .collect();
        rules.extend(twins);
        rules
    }
    #[cfg(not(target_arch = "x86_64"))]
    rules
}

/// The two filters, compiled for this process's architecture and serialized
/// as `bwrap` reads them: the `EPERM` deny list, then `clone3` → `ENOSYS`.
///
/// # Errors
/// `Unsupported` on an architecture without a filter; `InvalidInput` if the
/// filter does not compile.
pub(super) fn filters(kernel: (u32, u32)) -> io::Result<Vec<Vec<u8>>> {
    let arch = target_arch(std::env::consts::ARCH)?;
    let mut denied: BTreeMap<i64, Vec<SeccompRule>> = always_denied(kernel)
        .into_iter()
        .map(|nr| (nr, Vec::new()))
        .collect();
    denied.insert(libc::SYS_clone, any_flag(&CLONE_NEW)?);
    let mut unshare = CLONE_NEW.to_vec();
    unshare.push(CLONE_NEWTIME);
    denied.insert(libc::SYS_unshare, any_flag(&unshare)?);
    denied.insert(
        libc::SYS_ioctl,
        [TIOCSTI, TIOCLINUX]
            .into_iter()
            .map(|request| condition(1, SeccompCmpOp::Eq, request).and_then(|c| rule(vec![c])))
            .collect::<io::Result<_>>()?,
    );
    let eperm = errno(libc::EPERM)?;
    let enosys = errno(libc::ENOSYS)?;
    [
        (with_x32(denied), eperm),
        (
            with_x32(BTreeMap::from([(libc::SYS_clone3, Vec::new())])),
            enosys,
        ),
    ]
    .into_iter()
    .map(|(rules, action)| {
        let filter = SeccompFilter::new(rules, SeccompAction::Allow, action, arch)
            .map_err(|error| invalid(&error))?;
        BpfProgram::try_from(filter)
            .map(|program| serialize(&program))
            .map_err(|error| invalid(&error))
    })
    .collect()
}

fn errno(value: i32) -> io::Result<SeccompAction> {
    u32::try_from(value)
        .map(SeccompAction::Errno)
        .map_err(io::Error::other)
}

/// `struct sock_filter` as the kernel lays it out: `u16 code, u8 jt, u8 jf,
/// u32 k`, native endian.
fn serialize(program: &BpfProgram) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for instruction in program {
        bytes.extend(instruction.code.to_ne_bytes());
        bytes.push(instruction.jt);
        bytes.push(instruction.jf);
        bytes.extend(instruction.k.to_ne_bytes());
    }
    bytes
}

#[cfg(test)]
#[path = "seccomp_tests.rs"]
mod tests;
