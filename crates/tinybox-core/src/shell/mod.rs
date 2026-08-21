//! Turning an argument vector into something a POSIX shell will not mangle.
//!
//! # Why this exists at all
//!
//! tinybox passes commands as argument vectors precisely so that no backend has
//! to quote and no caller can inject through a filename. Two things break that
//! guarantee, and both are properties of a protocol rather than of shelling
//! out:
//!
//! - **SSH** carries a command *string* on its exec channel, which the remote
//!   login shell then parses. An embedded SSH client would face this too.
//! - **A detached process** ([`crate::detach`]) needs a shell on the far side to
//!   background the command and record its pid, because no transport tinybox
//!   speaks returns a process handle a caller could hold.
//!
//! So this is the one place in tinybox where the no-quoting property has to be
//! re-established by hand, which makes it the one place where a bug is a
//! command-injection bug. It lives in core, and is public, so that it stays
//! *one* place: a second copy is a second chance to get it wrong, and the two
//! callers are in different crates. Every function here is pure, so every case
//! can be pinned in a test.

/// Wrap one argument so a POSIX shell reproduces it exactly.
///
/// Single quotes suppress every form of expansion a shell performs — variables,
/// globs, command substitution, word splitting, backslashes. The only character
/// they cannot contain is a single quote itself, which is closed, escaped, and
/// reopened: `it's` becomes `'it'\''s'`.
///
/// An empty argument still needs quoting, or it would vanish from the command
/// line rather than arriving as an empty string.
#[must_use]
pub fn quote(argument: &str) -> String {
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
#[must_use]
pub fn command_line<I, S>(argv: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    argv.into_iter()
        .map(|argument| quote(argument.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build a full command, including working directory and environment.
///
/// A shell does not inherit the caller's working directory or environment
/// across any of the transports tinybox uses, so both are applied by the shell
/// that runs the command. `cd` runs first and is chained with `&&`, so a
/// missing directory fails the command rather than silently running it
/// somewhere else — which for a build command would be worse than an error.
///
/// `env` is used rather than `KEY=value command` prefixes because it applies
/// cleanly whatever the command is, including a shell builtin.
#[must_use]
pub fn script(
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
