//! Turning an argument vector into something a remote shell will not mangle.
//!
//! # Why this exists at all
//!
//! tinybox passes commands as argument vectors precisely so that no backend has
//! to quote and no caller can inject through a filename. SSH breaks that
//! guarantee: its exec channel carries a command *string*, which the remote
//! login shell then parses. That is true of the protocol, not of shelling out —
//! an SSH library would face exactly the same problem.
//!
//! So this is the one place in tinybox where the no-quoting property has to be
//! re-established by hand, which makes it the one place where a bug is a
//! command-injection bug. It is a pure function for that reason: every case can
//! be pinned in a test.

/// Wrap one argument so a POSIX shell reproduces it exactly.
///
/// Single quotes suppress every form of expansion a shell performs — variables,
/// globs, command substitution, word splitting, backslashes. The only character
/// they cannot contain is a single quote itself, which is closed, escaped, and
/// reopened: `it's` becomes `'it'\''s'`.
///
/// An empty argument still needs quoting, or it would vanish from the command
/// line rather than arriving as an empty string.
fn quote(argument: &str) -> String {
    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('\'');
    for character in argument.chars() {
        if character == '\'' {
            // Close the quoted run, emit an escaped quote, reopen.
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

/// Join an argument vector into a single shell command.
///
/// Every argument is quoted, including the program name: a program path
/// containing a space is unusual but not invalid, and treating the first
/// argument specially is how that becomes a bug.
pub(super) fn command_line<I, S>(argv: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    argv.into_iter()
        .map(|argument| quote(argument.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build the full remote command, including working directory and environment.
///
/// SSH does not carry the caller's environment or working directory, so both
/// are applied by the remote shell. `cd` runs first and is chained with `&&`,
/// so a missing directory fails the command rather than silently running it
/// somewhere else — which for a build command would be worse than an error.
///
/// `env` is used rather than `KEY=value command` prefixes because it applies
/// cleanly whatever the command is, including a shell builtin.
pub(super) fn remote_command(
    argv: &[String],
    cwd: Option<&std::path::Path>,
    env: &std::collections::BTreeMap<String, String>,
) -> String {
    let mut parts = Vec::new();

    if let Some(cwd) = cwd {
        parts.push(format!("cd {} &&", quote(&cwd.display().to_string())));
    }
    if !env.is_empty() {
        parts.push("env".to_owned());
        for (key, value) in env {
            parts.push(quote(&format!("{key}={value}")));
        }
    }
    parts.push(command_line(argv));
    parts.join(" ")
}

#[cfg(test)]
mod test;
