//! Tests for the guest image and the command that crosses into it.

use std::collections::BTreeMap;

use tinybox_core::{Error, ExecRequest};

use tinybox_core::Result;

use super::{BEGIN, EXIT, GuestFile, cmdline, initramfs, parse_console};

const SANDBOX: &str = "microvm";

fn file(path: &str, contents: &str) -> GuestFile {
    GuestFile {
        path: path.to_owned(),
        contents: contents.as_bytes().to_vec(),
        executable: false,
    }
}

/// The archive as text, for looking up names.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn the_initramfs_carries_an_init_and_a_userland() -> Result<()> {
    let bytes = initramfs(b"fake-busybox", &[])?;
    let archive = text(&bytes);

    // Without both of these the kernel panics with no init found, and the only
    // symptom is a VM that produces nothing.
    assert!(archive.contains("init"));
    assert!(archive.contains("bin/busybox"));
    assert!(bytes.windows(12).any(|window| window == b"fake-busybox"));
    Ok(())
}

#[test]
fn the_guest_init_resets_rather_than_halting() -> Result<()> {
    let archive = text(&initramfs(b"x", &[])?);

    // `poweroff -f` parks the vCPU and the hypervisor waits forever; `reboot -f`
    // is a reset it observes and exits on. That is the difference between an
    // 800 ms boot and one that hangs until a timeout.
    assert!(archive.contains("reboot -f"));
    assert!(!archive.contains("poweroff"));
    Ok(())
}

#[test]
fn the_guest_init_brackets_its_output() -> Result<()> {
    let archive = text(&initramfs(b"x", &[])?);

    // The serial console also carries kernel messages, so the command's own
    // output has to be delimited rather than read from the top.
    assert!(archive.contains(BEGIN));
    assert!(archive.contains(EXIT));
    Ok(())
}

#[test]
fn workspace_files_land_under_the_workspace_directory() -> Result<()> {
    let archive = text(&initramfs(b"x", &[file("main.rs", "fn main() {}")])?);

    assert!(archive.contains("workspace/main.rs"));
    assert!(archive.contains("fn main() {}"));
    Ok(())
}

#[test]
fn nested_workspace_files_get_their_directories_first() -> Result<()> {
    let bytes = initramfs(b"x", &[file("src/deep/mod.rs", "nested")])?;
    let archive = text(&bytes);

    // The kernel unpacks in order and has nowhere to put a file whose parent
    // does not exist yet, so it is silently dropped.
    let directory = archive.find("workspace/src/deep").unwrap_or(usize::MAX);
    let entry = archive.find("workspace/src/deep/mod.rs").unwrap_or(0);
    assert!(directory < entry, "the directory must be written first");
    Ok(())
}

#[test]
fn a_command_crosses_as_one_base64_word() {
    let request = ExecRequest::new(["echo", "hello world"]);

    let line = cmdline(&request, SANDBOX).unwrap_or_default();

    // The kernel splits its command line on whitespace and quotes nothing, so
    // a literal shell command would be torn apart at the first space.
    let value = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix("tinybox_cmd="))
        .unwrap_or_default();
    assert!(!value.is_empty());
    assert!(
        value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
        "{value} must be base64"
    );
}

#[test]
fn an_argument_cannot_displace_the_encoded_command() {
    // Written literally, this argument would introduce a second `tinybox_cmd=`
    // and the guest would run whichever the kernel reported.
    let request = ExecRequest::new(["echo", "tinybox_cmd=aW5qZWN0"]);

    let line = cmdline(&request, SANDBOX).unwrap_or_default();

    assert_eq!(line.matches("tinybox_cmd=").count(), 1);
}

#[test]
fn the_console_and_reset_settings_are_present() {
    let line = cmdline(&ExecRequest::new(["true"]), SANDBOX).unwrap_or_default();

    // Output comes back over the serial console, and `reboot=k` is what makes
    // the guest's reset visible to the hypervisor.
    assert!(line.contains("console=ttyS0"));
    assert!(line.contains("reboot=k"));
}

#[test]
fn a_command_too_long_for_the_kernel_is_refused() {
    // Truncation is silent: the guest would run a prefix of the intended
    // command, which is far worse than an error.
    let huge = "x".repeat(4096);
    let outcome = cmdline(&ExecRequest::new(["echo", &huge]), SANDBOX);

    assert!(matches!(
        outcome,
        Err(Error::Backend {
            operation: "encode the command for the guest",
            ..
        })
    ));
}

#[test]
fn a_command_with_no_program_is_refused() {
    let empty: Vec<String> = Vec::new();

    assert!(matches!(
        cmdline(&ExecRequest::new(empty), SANDBOX),
        Err(Error::EmptyCommand { .. })
    ));
}

#[test]
fn output_is_taken_from_between_the_markers() {
    let console = format!(
        "[ 0.00] Linux version 6.1\r\n[ 0.12] booting\r\n{BEGIN}\r\nhello\r\nworld\r\n{EXIT}0\r\n\
         [ 0.58] reboot: Restarting"
    );

    let (body, status) = parse_console(&console, SANDBOX).unwrap_or_default();

    // The kernel's own chatter is on the same wire and must not reach the
    // caller as if the command had printed it.
    assert_eq!(body, "hello\nworld\n");
    assert_eq!(status, 0);
    assert!(!body.contains("Linux version"));
    assert!(!body.contains("Restarting"));
}

#[test]
fn a_failing_status_comes_back() {
    let console = format!("{BEGIN}\r\noops\r\n{EXIT}7\r\n");

    let (_, status) = parse_console(&console, SANDBOX).unwrap_or_default();

    assert_eq!(status, 7);
}

#[test]
fn a_guest_that_never_started_is_distinguished_from_one_that_never_finished() {
    let never_started = parse_console("[ 0.00] Kernel panic\r\n", SANDBOX);
    let never_finished = parse_console(&format!("{BEGIN}\r\npartial output"), SANDBOX);

    // Different failures with different causes: a broken initramfs versus a
    // command that took the machine down with it.
    let started = never_started
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    let finished = never_finished
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(started.contains("never started"), "{started}");
    assert!(finished.contains("never finished"), "{finished}");
}

#[test]
fn carriage_returns_from_the_serial_line_are_removed() {
    let console = format!("{BEGIN}\r\na\r\nb\r\n{EXIT}0\r\n");

    let (body, _) = parse_console(&console, SANDBOX).unwrap_or_default();

    // A terminal turns every newline into CRLF, and a caller comparing output
    // to an expected string should not have to know that.
    assert_eq!(body, "a\nb\n");
    assert!(!body.contains('\r'));
}

#[test]
fn the_environment_and_directory_are_applied_inside_the_guest() {
    let mut env = BTreeMap::new();
    env.insert("KEY".to_owned(), "value".to_owned());
    let request = ExecRequest::new(["printenv"])
        .with_cwd("/workspace/src")
        .with_env("KEY", "value");

    let line = cmdline(&request, SANDBOX).unwrap_or_default();
    let encoded = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix("tinybox_cmd="))
        .unwrap_or_default();
    let decoded = decode(encoded);

    // A kernel command line has no notion of either, so both become shell.
    assert!(decoded.contains("export KEY='value'"), "{decoded}");
    assert!(decoded.contains("cd '/workspace/src'"), "{decoded}");
    assert!(decoded.contains("exec 'printenv'"), "{decoded}");
    let _ = env;
}

#[test]
fn an_injection_attempt_stays_one_argument_inside_the_guest() {
    let request = ExecRequest::new(["echo", "; rm -rf /"]);

    let line = cmdline(&request, SANDBOX).unwrap_or_default();
    let encoded = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix("tinybox_cmd="))
        .unwrap_or_default();

    // The guest runs this through a shell, so it needs the same quoting SSH
    // does, for the same reason.
    assert!(decode(encoded).contains(r"exec 'echo' '; rm -rf /'"));
}

/// Decode base64, for checking what the guest would receive.
fn decode(encoded: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut bits = Vec::new();
    for byte in encoded.bytes().filter(|byte| *byte != b'=') {
        let Some(index) = ALPHABET.iter().position(|candidate| *candidate == byte) else {
            continue;
        };
        for shift in (0..6).rev() {
            bits.push(u8::try_from((index >> shift) & 1).unwrap_or_default());
        }
    }

    let bytes = bits
        .chunks_exact(8)
        .map(|chunk| chunk.iter().fold(0u8, |acc, bit| (acc << 1) | *bit))
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn the_encoder_round_trips() {
    // The decoder above is only trustworthy if it agrees with the encoder on
    // something known.
    let request = ExecRequest::new(["echo", "round trip"]);
    let line = cmdline(&request, SANDBOX).unwrap_or_default();
    let encoded = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix("tinybox_cmd="))
        .unwrap_or_default();

    assert_eq!(decode(encoded), "exec 'echo' 'round trip'\n");
}
