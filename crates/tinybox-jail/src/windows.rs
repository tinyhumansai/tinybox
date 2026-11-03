//! Windows backend: `AppContainer`.
//!
//! `AppContainer` is Microsoft's strict process-isolation model — the same one
//! UWP apps and Edge's renderer use. Each container gets a unique SID; the
//! process can only touch filesystem objects whose DACL explicitly grants
//! that SID access. To jail an agent in `jail.root`:
//!
//! 1. `CreateAppContainerProfile` → derive a per-jail SID.
//! 2. Grant the SID `GENERIC_READ | GENERIC_WRITE | DELETE` on `jail.root`
//!    and every `jail.read_write` path via `SetNamedSecurityInfoW` (additive
//!    ACE on the existing DACL).
//! 3. Build `STARTUPINFOEXW` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`.
//! 4. `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT`.
//!
//! Things this backend deliberately does not do:
//!
//! - Network capability requests. By default an `AppContainer` has *no*
//!   network capabilities — we honor `jail.allow_net` by adding the
//!   `internetClient` capability (outbound client only, matching the
//!   `jail.allow_net` docstring of "Allow outbound network"). LAN /
//!   inbound capabilities are intentionally not granted; see
//!   `NET_CAPABILITY_NAMES` for the rationale.
//! - Persistent profile cleanup. We use a deterministic profile name
//!   derived from `jail.label` so reruns reuse the same SID. The host
//!   should call `DeleteAppContainerProfile` on uninstall — out of scope.
//!
//! Validated paths: this implementation has been compile-checked on
//! Windows targets but **must be tested on real Windows hardware** before
//! shipping. Win32 has many subtle wrong-trees you can bark up.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]
// Written for edition 2021, where the body of an `unsafe fn` is an unsafe
// context. Each fn documents its own safety contract; re-scoping them into
// per-call blocks is a separate, hardware-tested change.
#![allow(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::ptr;

use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree, SetHandleInformation, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, DeriveCapabilitySidsFromName, FreeSid, PSID,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows_sys::core::PWSTR;

// Well-known Win32 access masks. `windows-sys` has moved these constants
// between modules across releases (0.59 had GENERIC_READ in
// `Win32::Storage::FileSystem`, 0.60+ shuffled them around). Inlining the
// canonical values is both stable and avoids guessing which module the
// installed minor version exposes them through. Source: WinNT.h.
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const DELETE: u32 = 0x0001_0000;
const OBJECT_INHERIT_ACE: u32 = 0x01;
const CONTAINER_INHERIT_ACE: u32 = 0x02;
/// `SE_GROUP_ENABLED` — marks a SID in a `SID_AND_ATTRIBUTES` entry as active.
/// Required for capability SIDs passed to `AppContainer` `SECURITY_CAPABILITIES`.
/// Source: WinNT.h.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

/// `AppContainer` capability names granted when `jail.allow_net == true`.
///
/// Per `jail.rs`, `allow_net` is documented as **"Allow outbound network"**
/// — so the capability set here is strictly outbound-client only:
///
/// - `internetClient` — outbound TCP/UDP to the public internet (client only).
///
/// Intentionally NOT granted (each would over-grant relative to the
/// documented `allow_net` contract):
///
/// - `internetClientServer` — would let the child `bind()` and accept
///   inbound public-internet connections.
/// - `privateNetworkClientServer` — would let the child `bind()` on the
///   LAN, granting inbound LAN reachability beyond the documented
///   outbound-only semantics. Excluding it keeps this backend faithful to
///   the `Jail.allow_net` doc-string contract ("Allow outbound network"),
///   which is the invariant being enforced here — not the actual network
///   posture of the other backends (macOS Seatbelt grants `allow default`,
///   i.e. full network, on `allow_net == true`, and the Linux Landlock
///   backend does not gate network at all).
///
/// If a future caller needs LAN inbound or public server roles, add a
/// dedicated `Jail` flag (e.g. `allow_private_lan_server`) and extend
/// this list conditionally — do NOT silently expand `allow_net`.
const NET_CAPABILITY_NAMES: &[&str] = &["internetClient"];
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectCpuRateControlInformation,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Memory::{LPTR, LocalAlloc};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::jail::{Jail, JailBackend};

/// Windows `AppContainer` backend.
#[derive(Debug)]
pub struct AppContainerBackend;

impl AppContainerBackend {
    /// Creates the backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for AppContainerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl JailBackend for AppContainerBackend {
    fn name(&self) -> &'static str {
        "appcontainer"
    }

    fn is_available(&self) -> bool {
        // std::process::Child cannot wrap a Win32 handle. Legacy callers use
        // the owned-child availability path instead.
        false
    }

    fn is_owned_available(&self) -> bool {
        true
    }

    fn spawn_owned_captured(
        &self,
        jail: &Jail,
        cmd: Command,
    ) -> io::Result<super::jail::OwnedChild> {
        let env = command_environment(&cmd)?;
        self.spawn_owned_captured_with_env(jail, cmd, &env)
    }

    fn spawn_owned_captured_with_env(
        &self,
        jail: &Jail,
        cmd: Command,
        env: &BTreeMap<String, String>,
    ) -> io::Result<super::jail::OwnedChild> {
        unsafe { spawn_in_container(jail, &cmd, env) }
    }

    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        windows_constraint_support(self.is_owned_available())
    }

    fn spawn(&self, jail: &Jail, cmd: Command) -> io::Result<Child> {
        let _ = (jail, cmd);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AppContainer requires the owned-child spawn API on Windows",
        ))
    }
}

/// The variables `cmd` sets explicitly. An `AppContainer` child inherits
/// nothing from the parent, so a removal has nothing to remove.
fn command_environment(cmd: &Command) -> io::Result<BTreeMap<String, String>> {
    cmd.get_envs()
        .filter_map(|(key, value)| Some((key, value?)))
        .map(|(key, value)| match (key.to_str(), value.to_str()) {
            (Some(key), Some(value)) => Ok((key.to_owned(), value.to_owned())),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows environment entries must be Unicode",
            )),
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JobObjectLimitPlan {
    process_memory_bytes: Option<usize>,
    active_processes: Option<u32>,
    cpu_rate: Option<u32>,
    kill_on_close: bool,
}

fn job_object_limit_plan(
    resources: tinybox_core::Resources,
    processor_count: u32,
    hard_requirements: &[tinybox_core::Constraint],
) -> io::Result<JobObjectLimitPlan> {
    resources
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let processor_count = u64::from(processor_count.max(1));
    let total_cpu_millis = processor_count * 1_000;
    let cpu_rate = if hard_requirements.contains(&tinybox_core::Constraint::Cpu) {
        // Rounding up to the smallest rate would grant more than requested.
        let rate = (u64::from(resources.cpu_millis) * 10_000) / total_cpu_millis;
        if rate == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CPU limit is below the smallest Windows job CPU rate",
            ));
        }
        Some(rate.min(10_000) as u32)
    } else {
        None
    };
    let process_memory_bytes = if hard_requirements.contains(&tinybox_core::Constraint::Memory) {
        Some(usize::try_from(resources.memory_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory limit exceeds Windows address size",
            )
        })?)
    } else {
        None
    };
    Ok(JobObjectLimitPlan {
        process_memory_bytes,
        active_processes: hard_requirements
            .contains(&tinybox_core::Constraint::Pids)
            .then_some(resources.pids_max),
        cpu_rate,
        kill_on_close: true,
    })
}

fn windows_constraint_support(available: bool) -> tinybox_core::ConstraintSupport {
    use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
    if !available {
        return ConstraintSupport::NONE;
    }
    [
        Constraint::Filesystem,
        Constraint::Network,
        Constraint::Cpu,
        Constraint::Memory,
        Constraint::Pids,
    ]
    .into_iter()
    .fold(ConstraintSupport::NONE, |support, constraint| {
        support.with(constraint, Enforcement::Enforced)
    })
}

unsafe fn create_job_object(
    resources: Option<tinybox_core::Resources>,
    hard_requirements: &[tinybox_core::Constraint],
) -> io::Result<OwnedHandle> {
    let mut system_info: SYSTEM_INFO = std::mem::zeroed();
    GetSystemInfo(&raw mut system_info);
    let plan = resources
        .map(|resources| {
            job_object_limit_plan(
                resources,
                system_info.dwNumberOfProcessors,
                hard_requirements,
            )
        })
        .transpose()?;
    let job = CreateJobObjectW(ptr::null(), ptr::null());
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    let job = OwnedHandle::from_raw_handle(job.cast());

    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
    let mut flags = if plan.is_none_or(|limits| limits.kill_on_close) {
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    } else {
        0
    };
    if let Some(plan) = plan {
        if let Some(active_processes) = plan.active_processes {
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = active_processes;
        }
        if let Some(memory_bytes) = plan.process_memory_bytes {
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            limits.JobMemoryLimit = memory_bytes;
        }
    }
    limits.BasicLimitInformation.LimitFlags = flags;
    if SetInformationJobObject(
        job.as_raw_handle().cast(),
        JobObjectExtendedLimitInformation,
        (&raw const limits).cast(),
        size_as_u32(std::mem::size_of_val(&limits))?,
    ) == 0
    {
        return Err(io::Error::last_os_error());
    }

    if let Some(cpu_rate) = plan.and_then(|plan| plan.cpu_rate) {
        let cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 { CpuRate: cpu_rate },
        };
        if SetInformationJobObject(
            job.as_raw_handle().cast(),
            JobObjectCpuRateControlInformation,
            (&raw const cpu).cast(),
            size_as_u32(std::mem::size_of_val(&cpu))?,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(job)
}

fn size_as_u32(value: usize) -> io::Result<u32> {
    u32::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Win32 structure size exceeds u32",
        )
    })
}

fn environment_block(
    env: &BTreeMap<String, String>,
    local_app_data: &OsStr,
    system_root: &OsStr,
) -> io::Result<Vec<u16>> {
    let mut entries: Vec<(OsString, OsString)> = env
        .iter()
        .filter(|(key, _)| {
            !key.eq_ignore_ascii_case("LOCALAPPDATA") && !key.eq_ignore_ascii_case("SYSTEMROOT")
        })
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    // CreateProcessW needs the profile root to resolve the AppContainer
    // profile. Forward this single OS-required value even when the requested
    // child environment is otherwise empty; do not inherit the parent block.
    entries.push((OsString::from("LOCALAPPDATA"), local_app_data.to_owned()));
    // Windows child processes need SystemRoot to locate system runtime files.
    // This is the only other parent value forwarded into the block.
    entries.push((OsString::from("SystemRoot"), system_root.to_owned()));
    entries.sort_by_key(|(key, _)| key.to_string_lossy().to_ascii_lowercase());
    let mut block = Vec::new();
    for (key, value) in entries {
        if key.is_empty()
            || key.to_string_lossy().contains('=')
            || key.to_string_lossy().contains('\0')
            || value.to_string_lossy().contains('\0')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows environment entries must have valid names and no NUL bytes",
            ));
        }
        block.extend(key.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn required_environment_variable(name: &'static str) -> io::Result<OsString> {
    std::env::var_os(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{name} is required to launch an AppContainer process"),
        )
    })
}

#[allow(clippy::too_many_lines)] // Win32 startup structures must share their backing lifetimes.
unsafe fn spawn_in_container(
    jail: &Jail,
    cmd: &Command,
    env: &BTreeMap<String, String>,
) -> io::Result<super::jail::OwnedChild> {
    // 1. Create or open the AppContainer profile and obtain its SID.
    let profile_name = sanitize_profile_name(&jail.label);
    let wide_name = to_wide(&profile_name);
    let display = to_wide(&format!("openhuman {}", jail.label));
    let desc = to_wide("openhuman spawnd agent process");

    let mut sid: PSID = ptr::null_mut();
    let hr = CreateAppContainerProfile(
        wide_name.as_ptr(),
        display.as_ptr(),
        desc.as_ptr(),
        ptr::null_mut(),
        0,
        &raw mut sid,
    );
    if hr != 0 {
        // 0x800700B7 = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS).
        // In that case derive the SID from the existing profile.
        if hr.cast_unsigned() == 0x8007_00B7 {
            let mut existing: PSID = ptr::null_mut();
            let drv =
                DeriveAppContainerSidFromAppContainerName(wide_name.as_ptr(), &raw mut existing);
            if drv != 0 {
                return Err(io::Error::from_raw_os_error(drv));
            }
            sid = existing;
        } else {
            return Err(io::Error::from_raw_os_error(hr));
        }
    }
    let _sid_guard = SidGuard(sid);

    // 2. Grant the container SID access to the root, the extra read/write
    //    paths, and the read-only paths.
    for (path, access) in path_grants(jail) {
        grant_sid_access(path, sid, access)?;
    }

    // 3. Build SECURITY_CAPABILITIES. AppContainers start with no network
    //    access by default; honour `jail.allow_net` by deriving the
    //    capability SIDs in `NET_CAPABILITY_NAMES` via
    //    `DeriveCapabilitySidsFromName` and attaching them as
    //    SE_GROUP_ENABLED entries. `cap_derivations` owns the
    //    OS-allocated SID buffers and frees them via Drop after
    //    CreateProcessW has captured the values into the child process.
    //    `cap_attrs` must outlive CreateProcessW (the attribute list
    //    references it by pointer) — it stays in scope until the end of
    //    `spawn_in_container`.
    let mut cap_attrs: Vec<SID_AND_ATTRIBUTES> = Vec::new();
    let mut cap_derivations: Vec<CapabilityDerivation> = Vec::new();
    if jail.allow_net {
        let mut any_derived = false;
        for &name in NET_CAPABILITY_NAMES {
            match derive_capability(name) {
                Ok(deriv) => {
                    for &cap_sid in &deriv.capability_sids {
                        cap_attrs.push(SID_AND_ATTRIBUTES {
                            Sid: cap_sid,
                            Attributes: SE_GROUP_ENABLED,
                        });
                        any_derived = true;
                    }
                    cap_derivations.push(deriv);
                }
                Err(e) => log::warn!(
                    "[cwd_jail] DeriveCapabilitySidsFromName({name}) failed: \
                     {e}; this capability will not be granted"
                ),
            }
        }
        if !any_derived {
            log::error!(
                "[cwd_jail] jail.allow_net=true but NO network capability \
                 could be derived; the AppContainer child will have no \
                 network access. Check Userenv.dll availability."
            );
        }
    }
    let mut caps = SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: if cap_attrs.is_empty() {
            ptr::null_mut()
        } else {
            cap_attrs.as_mut_ptr()
        },
        CapabilityCount: size_as_u32(cap_attrs.len())?,
        Reserved: 0,
    };

    // 4. Build STARTUPINFOEXW with the security-capabilities attribute.
    let mut size: usize = 0;
    InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &raw mut size);
    let attr_buf = LocalAlloc(LPTR, size) as LPPROC_THREAD_ATTRIBUTE_LIST;
    if attr_buf.is_null() {
        return Err(io::Error::last_os_error());
    }
    let _attr_guard = AttrListGuard(attr_buf);
    if InitializeProcThreadAttributeList(attr_buf, 2, 0, &raw mut size) == 0 {
        return Err(io::Error::last_os_error());
    }
    if UpdateProcThreadAttribute(
        attr_buf,
        0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        (&raw mut caps).cast(),
        std::mem::size_of::<SECURITY_CAPABILITIES>(),
        ptr::null_mut(),
        ptr::null_mut(),
    ) == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut si: STARTUPINFOEXW = std::mem::zeroed();
    si.StartupInfo.cb = size_as_u32(std::mem::size_of::<STARTUPINFOEXW>())?;
    si.lpAttributeList = attr_buf;

    // Inherit only the child-facing pipe ends. The host keeps the opposite
    // ends as ordinary Files on the OwnedChild.
    let (stdin_read, stdin_write) = create_pipe_pair()?;
    let (stdout_read, stdout_write) = create_pipe_pair()?;
    let (stderr_read, stderr_write) = create_pipe_pair()?;
    set_noninheritable(&stdin_write)?;
    set_noninheritable(&stdout_read)?;
    set_noninheritable(&stderr_read)?;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = stdin_read.as_raw_handle().cast();
    si.StartupInfo.hStdOutput = stdout_write.as_raw_handle().cast();
    si.StartupInfo.hStdError = stderr_write.as_raw_handle().cast();
    let inherited_handles: [HANDLE; 3] = [
        stdin_read.as_raw_handle().cast(),
        stdout_write.as_raw_handle().cast(),
        stderr_write.as_raw_handle().cast(),
    ];
    if UpdateProcThreadAttribute(
        attr_buf,
        0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        inherited_handles.as_ptr() as *mut _,
        std::mem::size_of_val(&inherited_handles),
        ptr::null_mut(),
        ptr::null_mut(),
    ) == 0
    {
        return Err(io::Error::last_os_error());
    }

    // 5. Build the command line and current directory.
    let cmdline = build_command_line(cmd);
    let mut cmdline_w = to_wide(&cmdline);
    let cwd_w = cmd.get_current_dir().map(|p| to_wide(&p.to_string_lossy()));
    let local_app_data = required_environment_variable("LOCALAPPDATA")?;
    let system_root = required_environment_variable("SystemRoot")?;
    let mut environment = environment_block(env, &local_app_data, &system_root)?;

    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let ok = CreateProcessW(
        ptr::null(),
        cmdline_w.as_mut_ptr() as PWSTR,
        ptr::null_mut(),
        ptr::null_mut(),
        1, // bInheritHandles: only the three inheritable child pipe ends.
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        environment.as_mut_ptr().cast(),
        cwd_w.as_ref().map_or(ptr::null(), std::vec::Vec::as_ptr),
        (&raw mut si).cast::<STARTUPINFOW>(),
        &raw mut pi,
    );
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let process = OwnedHandle::from_raw_handle(pi.hProcess.cast());
    let thread = OwnedHandle::from_raw_handle(pi.hThread.cast());
    let resource_requirements: Vec<_> = jail
        .hard_requirements
        .iter()
        .copied()
        .filter(|constraint| {
            matches!(
                constraint,
                tinybox_core::Constraint::Cpu
                    | tinybox_core::Constraint::Memory
                    | tinybox_core::Constraint::Pids
            )
        })
        .collect();
    let resources = jail.resources.or_else(|| {
        jail.hard_requirements
            .iter()
            .any(|constraint| {
                matches!(
                    constraint,
                    tinybox_core::Constraint::Cpu
                        | tinybox_core::Constraint::Memory
                        | tinybox_core::Constraint::Pids
                        | tinybox_core::Constraint::Disk
                )
            })
            .then_some(tinybox_core::Resources::DEFAULT)
    });
    let job = match create_job_object(resources, &resource_requirements) {
        Ok(job) => job,
        Err(error) => {
            let _ = TerminateProcess(process.as_raw_handle().cast(), 1);
            return Err(error);
        }
    };
    if AssignProcessToJobObject(job.as_raw_handle().cast(), process.as_raw_handle().cast()) == 0 {
        let error = io::Error::last_os_error();
        let _ = TerminateProcess(process.as_raw_handle().cast(), 1);
        return Err(error);
    }
    if ResumeThread(thread.as_raw_handle().cast()) == u32::MAX {
        let error = io::Error::last_os_error();
        let _ = TerminateJobObject(job.as_raw_handle().cast(), 1);
        return Err(error);
    }

    Ok(super::jail::OwnedChild::new(
        AppContainerOwnedProcess { process, job },
        Some(std::fs::File::from(stdin_write)),
        Some(std::fs::File::from(stdout_read)),
        Some(std::fs::File::from(stderr_read)),
    ))
}

unsafe fn create_pipe_pair() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let security = SECURITY_ATTRIBUTES {
        nLength: size_as_u32(std::mem::size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    if CreatePipe(&raw mut read, &raw mut write, &raw const security, 0) == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        OwnedHandle::from_raw_handle(read.cast()),
        OwnedHandle::from_raw_handle(write.cast()),
    ))
}

unsafe fn set_noninheritable(handle: &OwnedHandle) -> io::Result<()> {
    if SetHandleInformation(handle.as_raw_handle().cast(), HANDLE_FLAG_INHERIT, 0) == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct AppContainerOwnedProcess {
    process: OwnedHandle,
    job: OwnedHandle,
}

impl super::jail::OwnedProcess for AppContainerOwnedProcess {
    fn id(&self) -> Option<u32> {
        Some(unsafe {
            windows_sys::Win32::System::Threading::GetProcessId(self.process.as_raw_handle().cast())
        })
    }

    fn try_wait(&mut self) -> io::Result<Option<super::jail::ChildStatus>> {
        let wait = unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle().cast(), &raw mut exit_code) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(super::jail::ChildStatus::from_code(Some(
            exit_code.cast_signed(),
        ))))
    }

    fn terminate(&mut self) -> io::Result<()> {
        if unsafe { TerminateJobObject(self.job.as_raw_handle().cast(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// The DACL grants a jail needs: the root and every `read_write` path get
/// read, write and delete; every `read_only` path gets read.
fn path_grants(jail: &Jail) -> Vec<(&Path, u32)> {
    let read_write = GENERIC_READ | GENERIC_WRITE | DELETE;
    std::iter::once(jail.root.as_path())
        .chain(jail.read_write.iter().map(PathBuf::as_path))
        .map(|path| (path, read_write))
        .chain(
            jail.read_only
                .iter()
                .filter(|path| {
                    path.as_path() != jail.root.as_path()
                        && !jail.read_write.iter().any(|rw| rw == *path)
                })
                .map(|path| (path.as_path(), GENERIC_READ)),
        )
        .collect()
}

unsafe fn grant_sid_access(path: &Path, sid: PSID, access: u32) -> io::Result<()> {
    let path_w = to_wide(&path.to_string_lossy());

    // First, fetch the *existing* DACL from the path. Passing
    // `ptr::null_mut()` as the old-ACL argument to `SetEntriesInAclW`
    // would build a fresh DACL containing only the AppContainer ACE,
    // and `SetNamedSecurityInfoW` would then replace the entire DACL —
    // locking out the owner / SYSTEM / Administrators. Merge instead.
    let mut sd_ptr: *mut std::ffi::c_void = ptr::null_mut();
    let mut existing_dacl: *mut ACL = ptr::null_mut();
    let dacl_present: i32 = 0;
    let rc = GetNamedSecurityInfoW(
        path_w.as_ptr(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        ptr::null_mut(),
        ptr::null_mut(),
        &raw mut existing_dacl,
        ptr::null_mut(),
        &raw mut sd_ptr,
    );
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    let _sd_guard = LocalGuard(sd_ptr as HLOCAL);
    let _ = dacl_present;

    let mut ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
    ea.grfAccessPermissions = access;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    ea.Trustee = TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_GROUP,
        ptstrName: sid.cast(),
    };

    let mut new_acl: *mut ACL = ptr::null_mut();
    let rc = SetEntriesInAclW(1, &raw const ea, existing_dacl, &raw mut new_acl);
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    let _acl_guard = LocalGuard(new_acl as HLOCAL);

    let rc = SetNamedSecurityInfoW(
        path_w.as_ptr().cast_mut(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        ptr::null_mut(),
        ptr::null_mut(),
        new_acl,
        ptr::null_mut(),
    );
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    Ok(())
}

fn build_command_line(cmd: &Command) -> String {
    // Minimal CommandLineToArgvW-compatible quoting. std's internal
    // `make_command_line` is private; this mirrors the same rules.
    let mut out = String::new();
    let prog = cmd.get_program().to_string_lossy().into_owned();
    push_arg(&mut out, &prog);
    for a in cmd.get_args() {
        out.push(' ');
        push_arg(&mut out, &a.to_string_lossy());
    }
    out
}

fn push_arg(out: &mut String, a: &str) {
    let needs_quotes = a.is_empty() || a.contains([' ', '\t', '"']);
    if !needs_quotes {
        out.push_str(a);
        return;
    }
    out.push('"');
    let mut backslashes = 0;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..=(backslashes * 2) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn sanitize_profile_name(label: &str) -> String {
    // AppContainer profile names must be ≤ 64 chars and use a restricted
    // charset. Keep ASCII alnum + dot and map everything else to `_`; then a
    // hash of the full label keeps labels that sanitize or truncate alike
    // (`a-b` and `a_b`) on separate profiles, and so separate SIDs.
    let hash = label.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    let mut s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // "openhuman." (10) + 37 + "." (1) + 16 hex digits = 64.
    s.truncate(37);
    format!("openhuman.{s}.{hash:016x}")
}

struct SidGuard(PSID);
impl Drop for SidGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // MSDN: SIDs returned by both `CreateAppContainerProfile`
            // and `DeriveAppContainerSidFromAppContainerName` must be
            // freed with `FreeSid`. The older comment that said
            // `LocalFree` is "safer" was wrong — the buffers are not
            // necessarily LocalAlloc-backed, and using the wrong free
            // function corrupts the heap on some Windows builds.
            unsafe {
                FreeSid(self.0);
            }
        }
    }
}

struct AttrListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
impl Drop for AttrListGuard {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.0);
            LocalFree(self.0 as HLOCAL);
        }
    }
}

struct LocalGuard(HLOCAL);
impl Drop for LocalGuard {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

/// Owned wrapper around the SID arrays returned by
/// `DeriveCapabilitySidsFromName`. MSDN: each inner SID AND each array
/// itself is `LocalAlloc`-backed; `Drop` releases all of them in the
/// reverse order they were allocated.
///
/// The `capability_sids` are the ones we actually want for an
/// `AppContainer`'s `SECURITY_CAPABILITIES.Capabilities`; the
/// `group_sids` come along because the Win32 API returns both, and we
/// hold them here purely so we can free them.
struct CapabilityDerivation {
    capability_sids: Vec<PSID>,
    capability_sids_ptr: *mut PSID,
    group_sids: Vec<PSID>,
    group_sids_ptr: *mut PSID,
}

impl Drop for CapabilityDerivation {
    fn drop(&mut self) {
        unsafe {
            for &sid in &self.capability_sids {
                if !sid.is_null() {
                    LocalFree(sid as HLOCAL);
                }
            }
            if !self.capability_sids_ptr.is_null() {
                LocalFree(self.capability_sids_ptr as HLOCAL);
            }
            for &sid in &self.group_sids {
                if !sid.is_null() {
                    LocalFree(sid as HLOCAL);
                }
            }
            if !self.group_sids_ptr.is_null() {
                LocalFree(self.group_sids_ptr as HLOCAL);
            }
        }
    }
}

/// Resolves a capability name (e.g. `"internetClient"`) to its SIDs via
/// `DeriveCapabilitySidsFromName`. The returned [`CapabilityDerivation`]
/// owns the OS allocations; drop it to free them. Use the
/// `capability_sids` slice as the SID values for
/// `SECURITY_CAPABILITIES.Capabilities` entries.
///
/// # Safety
/// FFI into `userenv.dll`. Safe to call from any thread on Windows.
fn derive_capability(name: &str) -> io::Result<CapabilityDerivation> {
    unsafe { derive_capability_ffi(name) }
}

unsafe fn derive_capability_ffi(name: &str) -> io::Result<CapabilityDerivation> {
    let name_w = to_wide(name);
    let mut group_sids: *mut PSID = ptr::null_mut();
    let mut group_count: u32 = 0;
    let mut cap_sids: *mut PSID = ptr::null_mut();
    let mut cap_count: u32 = 0;
    let ok = DeriveCapabilitySidsFromName(
        name_w.as_ptr(),
        &raw mut group_sids,
        &raw mut group_count,
        &raw mut cap_sids,
        &raw mut cap_count,
    );
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let capability_sids: Vec<PSID> = (0..cap_count as usize).map(|i| *cap_sids.add(i)).collect();
    let group_sids_vec: Vec<PSID> = (0..group_count as usize)
        .map(|i| *group_sids.add(i))
        .collect();
    Ok(CapabilityDerivation {
        capability_sids,
        capability_sids_ptr: cap_sids,
        group_sids: group_sids_vec,
        group_sids_ptr: group_sids,
    })
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
