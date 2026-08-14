//! Translating Docker's container status into a tinybox box state.

use tinybox_core::BoxState;

/// Map a `docker inspect` status onto a [`BoxState`].
///
/// Docker's `running` becomes [`BoxState::Ready`] rather than
/// [`BoxState::Running`]: a tinybox box is `Running` when a command is
/// executing in it, and Docker's keepalive loop is not a command. `Ready` is
/// the honest reading — provisioned, idle, and able to accept work.
///
/// An unrecognized status maps to [`BoxState::Failed`] rather than being
/// guessed at. Docker's status vocabulary is small and stable, so a value
/// outside it means something has gone wrong that a caller should see.
pub(super) fn from_docker(status: &str) -> BoxState {
    match status.trim() {
        "running" => BoxState::Ready,
        "paused" => BoxState::Paused,
        // `created` is a container that exists but was never started, and
        // `exited` is one that has stopped. Neither can accept a command, and
        // both still hold a filesystem, which is exactly `Stopped`.
        "created" | "exited" => BoxState::Stopped,
        // Docker reports `restarting` while a restart policy is cycling the
        // container. It is not usable yet, and it is not broken.
        "restarting" => BoxState::Creating,
        // `removing` and `dead` are both terminal from tinybox's side.
        "removing" => BoxState::Archived,
        _ => BoxState::Failed,
    }
}
