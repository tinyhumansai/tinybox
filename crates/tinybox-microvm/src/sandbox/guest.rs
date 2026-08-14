//! Building the guest a microVM boots into.
//!
//! Everything here is pure: given a workspace and a command, it produces the
//! bytes of an initramfs and the kernel command line that goes with them. The
//! boot itself is somebody else's problem, which is what makes the interesting
//! decisions — how a command crosses into the guest, how output comes back —
//! testable without a hypervisor.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use tinybox_core::{Error, ExecRequest, Result};

use crate::cpio::{Entry, archive};

/// Where the workspace appears inside the guest.
pub const WORKSPACE_MOUNT: &str = "/workspace";

/// Printed by the guest immediately before the command's own output.
///
/// The serial console also carries kernel boot messages, so the output has to
/// be delimited rather than simply read from the top.
pub(super) const BEGIN: &str = "TINYBOX-BEGIN";

/// Printed by the guest after the command, carrying its status.
pub(super) const EXIT: &str = "TINYBOX-EXIT:";

/// The kernel command-line key the encoded command travels in.
const COMMAND_KEY: &str = "tinybox_cmd";

/// The longest command line an x86 kernel will accept.
///
/// Exceeding it does not fail cleanly — the line is silently truncated and the
/// guest runs whatever survived, which could be a prefix of the intended
/// command. Refusing early is the only safe response.
const MAX_CMDLINE: usize = 2048;

/// The guest's `init`, which is `pid 1` inside the VM.
///
/// It reads the command from `/proc/cmdline`, runs it, and resets the machine.
/// `reboot -f` rather than `poweroff -f`: halting leaves the vCPU parked and
/// the hypervisor waiting forever, whereas a reset is something it observes and
/// exits on. That difference is the whole gap between a boot that takes 800 ms
/// and one that hangs until a timeout.
const INIT: &str = r#"#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
cmd=$(/bin/busybox sed -n 's/.*tinybox_cmd=\([^ ]*\).*/\1/p' /proc/cmdline)
cd /workspace 2>/dev/null
/bin/busybox echo "TINYBOX-BEGIN"
if [ -n "$cmd" ]; then
  /bin/busybox echo "$cmd" | /bin/busybox base64 -d > /tinybox-run
  /bin/busybox sh /tinybox-run
  /bin/busybox echo "TINYBOX-EXIT:$?"
else
  /bin/busybox echo "TINYBOX-EXIT:1"
fi
/bin/busybox reboot -f
"#;

/// The busybox applets the guest's `init` reaches for by name.
const APPLETS: [&str; 9] = [
    "sh", "mount", "sed", "base64", "echo", "cat", "reboot", "ls", "env",
];

/// One file to place in the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GuestFile {
    /// Where it lands, relative to the guest root.
    pub(super) path: String,
    /// What it contains.
    pub(super) contents: Vec<u8>,
    /// Whether it should be runnable.
    pub(super) executable: bool,
}

/// Build the initramfs a box boots from.
///
/// `busybox` must be a statically linked binary: the initramfs carries no
/// libraries, and a dynamically linked one would fail to start with an error
/// the guest has no way to report.
///
/// # Errors
///
/// Returns [`Error::Backend`] when a workspace file is too large for the `newc`
/// format to describe.
pub(super) fn initramfs(busybox: &[u8], workspace: &[GuestFile]) -> Result<Vec<u8>> {
    let mut entries = vec![
        Entry::directory("bin"),
        Entry::directory("dev"),
        Entry::directory("proc"),
        Entry::directory("sys"),
        Entry::directory("workspace"),
        Entry::program("bin/busybox", busybox.to_vec()),
        Entry::program("init", INIT),
    ];

    // The applets are copies rather than symlinks. `newc` can express a
    // symlink, but a copy of a multi-megabyte binary per applet would be
    // wasteful — so instead `init` calls `/bin/busybox <applet>` explicitly and
    // these exist only for anything the command itself invokes by bare name.
    for applet in APPLETS {
        entries.push(Entry::file(format!("bin/{applet}.applet"), applet));
    }

    // Directories must precede the files inside them, so the parents of every
    // workspace path are emitted first, in order.
    let mut seen = BTreeSet::new();
    for file in workspace {
        let path = format!("workspace/{}", file.path.trim_start_matches('/'));
        seen.extend(parents(&path));
    }
    for parent in seen {
        entries.push(Entry::directory(parent));
    }
    for file in workspace {
        let path = format!("workspace/{}", file.path.trim_start_matches('/'));
        entries.push(if file.executable {
            Entry::program(path, file.contents.clone())
        } else {
            Entry::file(path, file.contents.clone())
        });
    }

    archive(&entries)
}

/// Every directory that has to exist before `path` can, shallowest first.
fn parents(path: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut prefix = String::new();
    let mut parts = path.split('/').collect::<Vec<_>>();
    parts.pop();

    for part in parts {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        found.push(prefix.clone());
    }
    found
}

/// The kernel command line for a boot that runs `request`.
///
/// The command crosses as base64 in a single cmdline value. The kernel splits
/// its command line on whitespace and performs no quoting of any kind, so a
/// shell command written literally would be torn apart at the first space —
/// and an argument containing `tinybox_cmd=` would be able to displace the real
/// one. Base64 has neither problem: it is one word, from an alphabet with no
/// shell meaning.
///
/// # Errors
///
/// Returns [`Error::EmptyCommand`] when the request names no program, and
/// [`Error::Backend`] when the encoded command would exceed what the kernel
/// accepts — truncation would run a prefix of the intended command, which is
/// far worse than refusing.
pub(super) fn cmdline(request: &ExecRequest, sandbox: &str) -> Result<String> {
    if request.argv.is_empty() {
        return Err(Error::EmptyCommand {
            sandbox: sandbox.to_owned(),
        });
    }

    let encoded = base64(script(request).as_bytes());
    // `console=ttyS0` is how output comes back at all; `reboot=k` is what makes
    // the guest's reset something the hypervisor observes; `pci=off` and
    // `i8042.noaux` cut probing that costs tens of milliseconds of boot.
    let line = format!(
        "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux \
         i8042.nopnp i8042.dumbkbd {COMMAND_KEY}={encoded}"
    );

    if line.len() > MAX_CMDLINE {
        return Err(Error::Backend {
            sandbox: sandbox.to_owned(),
            operation: "encode the command for the guest",
            message: format!(
                "the command needs {} bytes of kernel command line and the limit is {MAX_CMDLINE}",
                line.len()
            ),
        });
    }
    Ok(line)
}

/// The shell script the guest runs.
///
/// The environment is applied inside the guest rather than through the kernel
/// command line, which has no notion of one.
fn script(request: &ExecRequest) -> String {
    let mut script = String::new();
    for (key, value) in &request.env {
        let _ = writeln!(script, "export {}={}", key, quote(value));
    }
    if let Some(cwd) = &request.cwd {
        let _ = writeln!(script, "cd {} || exit 1", quote(&cwd.display().to_string()));
    }

    script.push_str("exec");
    for argument in &request.argv {
        script.push(' ');
        script.push_str(&quote(argument));
    }
    script.push('\n');
    script
}

/// Quote one argument for the guest's shell.
///
/// The same problem SSH has, for the same reason: the command becomes text
/// before it becomes an argument vector again. Single quotes suppress every
/// expansion; the only character they cannot hold is a single quote, which is
/// closed, escaped, and reopened.
fn quote(argument: &str) -> String {
    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('\'');
    for character in argument.chars() {
        if character == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

/// Encode `bytes` as base64.
///
/// Written out rather than taken as a dependency: it is a dozen lines, it is
/// the only encoding this crate needs, and the guest decodes it with busybox.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let packed =
            (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);

        for index in 0..4 {
            if index <= chunk.len() {
                let shift = 18 - index * 6;
                out.push(ALPHABET[((packed >> shift) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Pull the command's output and status out of the serial console.
///
/// The console carries the kernel's boot messages too, so the guest brackets
/// its own output with markers. Everything before `BEGIN` and after `EXIT` is
/// the kernel talking.
///
/// # Errors
///
/// Returns [`Error::Backend`] when the markers are absent, which means the
/// guest never reached its `init` — a broken initramfs, a kernel that failed to
/// boot, or a VM that was killed.
pub(super) fn parse_console(console: &str, sandbox: &str) -> Result<(String, i32)> {
    let failed = |message: String| Error::Backend {
        sandbox: sandbox.to_owned(),
        operation: "read the guest's output",
        message,
    };

    let after_begin = console
        .split_once(BEGIN)
        .map(|(_, rest)| rest)
        .ok_or_else(|| failed("the guest never started; it may have failed to boot".to_owned()))?;

    let (body, tail) = after_begin
        .split_once(EXIT)
        .ok_or_else(|| failed("the guest started but never finished".to_owned()))?;

    let status = tail
        .split_whitespace()
        .next()
        .and_then(|code| code.trim().parse::<i32>().ok())
        .ok_or_else(|| failed("the guest reported no exit status".to_owned()))?;

    // The serial console is a terminal, so every newline arrives as CRLF.
    Ok((
        body.replace("\r\n", "\n")
            .trim_start_matches('\n')
            .to_owned(),
        status,
    ))
}

#[cfg(test)]
mod test;
