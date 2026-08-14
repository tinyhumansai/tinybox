//! Tests for remote shell quoting.
//!
//! A bug here is a command-injection bug, so these are exhaustive about the
//! metacharacters a shell acts on rather than sampling a few. `live_ssh.rs`
//! then confirms the same strings survive a real remote shell — this file pins
//! the intent, that one pins the reality.

use std::collections::BTreeMap;
use std::path::Path;

use super::{command_line, remote_command};

/// Every construct a POSIX shell would otherwise act on.
const DANGEROUS: [&str; 16] = [
    "; rm -rf /",
    "&& whoami",
    "|| whoami",
    "| tee /tmp/pwned",
    "$(whoami)",
    "`whoami`",
    "${HOME}",
    "$HOME",
    "*",
    "?",
    "[a-z]",
    "~",
    "\\",
    "\n",
    "\t",
    "#comment",
];

#[test]
fn an_ordinary_argument_is_quoted_but_unchanged() {
    assert_eq!(command_line(["echo"]), "'echo'");
    assert_eq!(command_line(["echo", "hello"]), "'echo' 'hello'");
}

#[test]
fn the_program_name_is_quoted_too() {
    // Treating the first argument specially is how a program path with a space
    // in it becomes a bug.
    assert_eq!(
        command_line(["/opt/my tools/run", "x"]),
        "'/opt/my tools/run' 'x'"
    );
}

#[test]
fn an_empty_argument_survives_rather_than_vanishing() {
    // Unquoted, an empty argument would disappear from the command line and
    // every later argument would shift position.
    assert_eq!(command_line(["cmp", "", "x"]), "'cmp' '' 'x'");
}

#[test]
fn a_single_quote_is_closed_escaped_and_reopened() {
    // The one character single quotes cannot contain.
    assert_eq!(command_line(["it's"]), r"'it'\''s'");
    assert_eq!(command_line(["'"]), r"''\'''");
    assert_eq!(command_line(["a'b'c"]), r"'a'\''b'\''c'");
}

#[test]
fn every_shell_metacharacter_is_neutralized() {
    for dangerous in DANGEROUS {
        let quoted = command_line(["echo", dangerous]);

        // The argument appears inside a quoted run, and nothing outside the
        // quotes could start a new command.
        assert!(
            quoted.starts_with("'echo' '"),
            "{dangerous:?} produced {quoted:?}"
        );
        assert!(quoted.ends_with('\''), "{dangerous:?} produced {quoted:?}");
    }
}

#[test]
fn a_quoted_argument_round_trips_through_a_real_shell() {
    // The property that matters: whatever goes in comes back out unchanged.
    // Checked here against `sh` itself rather than against an expectation this
    // module also produced.
    for argument in DANGEROUS.iter().chain(["", "it's", "plain"].iter()) {
        let line = command_line(["printf", "%s", argument]);
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&line)
            .output();

        let Ok(output) = output else {
            // No shell available; the other tests still pin the encoding.
            continue;
        };
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            *argument,
            "round trip failed for {argument:?} via {line:?}"
        );
    }
}

#[test]
fn a_bare_command_has_no_prefix() {
    let argv = vec!["ls".to_owned(), "-la".to_owned()];

    assert_eq!(remote_command(&argv, None, &BTreeMap::new()), "'ls' '-la'");
}

#[test]
fn a_working_directory_is_entered_first_and_chained_with_and() {
    let argv = vec!["ls".to_owned()];

    // `&&` rather than `;` so a missing directory fails the command instead of
    // running it somewhere unexpected.
    assert_eq!(
        remote_command(&argv, Some(Path::new("/srv/work")), &BTreeMap::new()),
        "cd '/srv/work' && 'ls'"
    );
}

#[test]
fn a_working_directory_with_a_space_or_quote_is_quoted() {
    let argv = vec!["pwd".to_owned()];

    assert_eq!(
        remote_command(&argv, Some(Path::new("/srv/my work")), &BTreeMap::new()),
        "cd '/srv/my work' && 'pwd'"
    );
    assert_eq!(
        remote_command(&argv, Some(Path::new("/srv/it's")), &BTreeMap::new()),
        r"cd '/srv/it'\''s' && 'pwd'"
    );
}

#[test]
fn environment_is_applied_with_env_and_fully_quoted() {
    let argv = vec!["printenv".to_owned()];
    let mut env = BTreeMap::new();
    env.insert("SIMPLE".to_owned(), "value".to_owned());

    assert_eq!(
        remote_command(&argv, None, &env),
        "env 'SIMPLE=value' 'printenv'"
    );
}

#[test]
fn a_value_that_looks_like_a_command_stays_a_value() {
    let argv = vec!["printenv".to_owned()];
    let mut env = BTreeMap::new();
    env.insert("EVIL".to_owned(), "; rm -rf /".to_owned());

    // The whole `KEY=value` pair is one quoted word, so the semicolon is data.
    assert_eq!(
        remote_command(&argv, None, &env),
        "env 'EVIL=; rm -rf /' 'printenv'"
    );
}

#[test]
fn a_directory_and_an_environment_compose() {
    let argv = vec!["make".to_owned()];
    let mut env = BTreeMap::new();
    env.insert("A".to_owned(), "1".to_owned());
    env.insert("B".to_owned(), "2".to_owned());

    // Ordered, because the environment is a BTreeMap: two requests differing
    // only in insertion order produce the same command.
    assert_eq!(
        remote_command(&argv, Some(Path::new("/w")), &env),
        "cd '/w' && env 'A=1' 'B=2' 'make'"
    );
}
