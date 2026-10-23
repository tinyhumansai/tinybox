//! Retained native collector and scratch ownership.
use tinybox_bus::ShellExecRequest;
pub(in crate::tinybus_module) struct ShellContext {
    pub(super) request: ShellExecRequest,
    pub(super) environment: std::collections::BTreeMap<String, std::ffi::OsString>,
    pub(super) scratch: std::sync::Arc<std::sync::Mutex<Option<tempfile::TempDir>>>,
    pub(super) scratch_cleanup_failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(super) host: ShellHost,
    #[cfg(test)]
    pub(in crate::tinybus_module) scratch_deletion_blocked: std::sync::atomic::AtomicBool,
}
pub(super) enum ShellHost {
    Local(tinybox_host::LimitedLocalHost),
    Jailed(tinybox_host::JailLocalHost),
}
