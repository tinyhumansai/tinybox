//! The `tinybox` binary.
//!
//! Deliberately almost empty: everything testable lives in the library so it
//! can be driven without spawning a process. What remains here is the parts
//! that only make sense as a process — owning the runtime, locking the real
//! standard streams, and turning a code into an exit status.

use std::io::Write;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();

    let code = tinybox_cli::run(std::env::args_os(), &mut out, &mut err).await;

    // Flush before exiting: `ExitCode` returns through `main`, and a buffered
    // stdout that is never flushed loses the output entirely when piped.
    let _ = out.flush();
    let _ = err.flush();
    ExitCode::from(code)
}
