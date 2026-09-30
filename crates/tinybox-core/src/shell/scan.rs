//! Quote-aware scanning of a shell command *string*.
//!
//! These helpers are lexical only: they split a command on unquoted
//! separators, find unquoted control characters, blank quoted-heredoc bodies,
//! and normalise a command word. They decide nothing about whether a command
//! is safe; a host that gates execution builds its policy on top of them.
//! Every function is pure and none of them expands or evaluates anything.

use std::borrow::Cow;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    None,
    Single,
    Double,
}

/// Split a shell command into sub-commands by unquoted separators.
///
/// Separators:
/// - `;` and newline
/// - `|`
/// - `&&`, `||`
///
/// Characters inside single or double quotes are treated as literals, so
/// `sqlite3 db "SELECT 1; SELECT 2;"` remains a single segment.
#[must_use]
pub fn split_unquoted_segments(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = command.chars().peekable();

    let push_segment = |segments: &mut Vec<String>, current: &mut String| {
        let trimmed = current.trim();
        if !trimmed.is_empty() {
            segments.push(trimmed.to_string());
        }
        current.clear();
    };

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
                current.push(ch);
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    current.push(ch);
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    current.push(ch);
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
                current.push(ch);
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    current.push(ch);
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    current.push(ch);
                    continue;
                }

                match ch {
                    '\'' => {
                        quote = QuoteState::Single;
                        current.push(ch);
                    }
                    '"' => {
                        quote = QuoteState::Double;
                        current.push(ch);
                    }
                    ';' | '\n' => push_segment(&mut segments, &mut current),
                    '|' => {
                        if chars.next_if_eq(&'|').is_some() {
                            // Consume full `||`; both characters are separators.
                        }
                        push_segment(&mut segments, &mut current);
                    }
                    '&' => {
                        if chars.next_if_eq(&'&').is_some() {
                            // `&&` is a separator; single `&` is handled separately.
                            push_segment(&mut segments, &mut current);
                        } else {
                            current.push(ch);
                        }
                    }
                    _ => current.push(ch),
                }
            }
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        segments.push(trimmed.to_string());
    }

    segments
}

/// Detect a single unquoted `&` operator (background/chain). `&&` is allowed.
///
/// We treat any standalone `&` as unsafe in policy validation because it can
/// chain hidden sub-commands and escape foreground timeout expectations.
#[must_use]
pub fn contains_unquoted_single_ampersand(command: &str) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    '&' if chars.next_if_eq(&'&').is_none() => {
                        return true;
                    }
                    _ => {}
                }
            }
        }
    }

    false
}

/// Like [`contains_unquoted_single_ampersand`] but ignores file-descriptor
/// duplication redirects, where the `&` is part of a redirect operator rather
/// than a background/separator: `2>&1`, `>&2` (prev char `>`), and `&>file`
/// (next char `>`). Used by a hidden-execution guard so
/// a benign `… 2>&1` — which a classifier already accounts for as a
/// `Write` redirect — is not mistaken for a backgrounded command and
/// hard-blocked after the human approved it. A standalone `&` (e.g. `cmd &`,
/// `a & b`) still returns true, since it can run a second command
/// a classifier wouldn't see.
#[must_use]
pub fn contains_unquoted_background_ampersand(command: &str) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut prev = '\0';
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    prev = ch;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    prev = ch;
                    continue;
                }
                if ch == '$' && chars.peek() == Some(&'(') {
                    chars.next();
                    let mut nested = String::new();
                    let mut depth = 1usize;
                    let mut nested_quote = QuoteState::None;
                    let mut nested_escaped = false;
                    for inner in chars.by_ref() {
                        if nested_escaped {
                            nested_escaped = false;
                            nested.push(inner);
                            continue;
                        }
                        match nested_quote {
                            QuoteState::Single if inner == '\'' => nested_quote = QuoteState::None,
                            QuoteState::Double => match inner {
                                '\\' => nested_escaped = true,
                                '"' => nested_quote = QuoteState::None,
                                _ => {}
                            },
                            QuoteState::None => match inner {
                                '\\' => nested_escaped = true,
                                '\'' => nested_quote = QuoteState::Single,
                                '"' => nested_quote = QuoteState::Double,
                                '(' => depth += 1,
                                ')' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        break;
                                    }
                                }
                                _ => {}
                            },
                            QuoteState::Single => {}
                        }
                        nested.push(inner);
                    }
                    if contains_unquoted_background_ampersand(&nested) {
                        return true;
                    }
                    continue;
                }
                if ch == '`' {
                    let mut nested = String::new();
                    let mut escaped_tick = false;
                    for inner in chars.by_ref() {
                        if inner == '`' && !escaped_tick {
                            break;
                        }
                        escaped_tick = inner == '\\' && !escaped_tick;
                        nested.push(inner);
                    }
                    if contains_unquoted_background_ampersand(&nested) {
                        return true;
                    }
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    prev = ch;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    prev = ch;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    '&' => {
                        if chars.next_if_eq(&'&').is_some() {
                            // `&&` logical AND — consume both, not background.
                        } else {
                            let next = chars.peek().copied().unwrap_or('\0');
                            // Skip fd-dup redirects: `2>&1`/`>&2` (prev `>`) and
                            // `&>file` (next `>`).
                            if prev != '>' && next != '>' {
                                return true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        prev = ch;
    }

    false
}

/// Detect an unquoted character in a shell command.
#[must_use]
pub fn contains_unquoted_char(command: &str, target: char) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;

    for ch in command.chars() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    _ if ch == target => return true,
                    _ => {}
                }
            }
        }
    }

    false
}

/// Blank out the body of every **quoted-delimiter** heredoc in `command`.
///
/// A command classifier and structural guards scan the raw command string, so
/// until now a heredoc body was read as live shell text. That is wrong for a
/// quoted delimiter: in `cat > f << 'EOF' … EOF` the shell performs no
/// expansion inside the body, so an `&`, a `` ` `` or a `$(` there is data.
/// Measured consequence : a recipe document was
/// refused as "background (&) is not allowed" because four dinner titles read
/// "Chicken & Spinach".
///
/// An **unquoted** delimiter (`<< EOF`) is deliberately left alone — expansion
/// *is* live inside that body, so `$(rm -rf ~)` there really would execute and
/// must keep tripping the guard.
///
/// Body lines are replaced by empty lines rather than removed, so line counts,
/// the surrounding command text and the `>` of the redirect are all preserved:
/// a heredoc write still classifies as a write and still
/// prompts. Returns [`Cow::Borrowed`] when the command has no quoted heredoc,
/// which is the overwhelmingly common case.
#[must_use]
pub fn strip_quoted_heredoc_bodies(command: &str) -> Cow<'_, str> {
    if !command.contains("<<") {
        return Cow::Borrowed(command);
    }

    let mut out = String::with_capacity(command.len());
    let mut active_delimiters = VecDeque::new();
    let mut changed = false;

    for line in command.split_inclusive('\n') {
        if let Some((delim, quoted)) = active_delimiters.front() {
            if line.trim() == delim {
                out.push_str(line);
                active_delimiters.pop_front();
            } else if *quoted {
                // Blank only bodies the shell does not expand.
                if line.ends_with('\n') {
                    out.push('\n');
                }
                changed = true;
            } else {
                out.push_str(line);
            }
            continue;
        }

        out.push_str(line);
        let declarations = heredoc_declarations(line);
        if declarations.iter().any(|(_, quoted)| *quoted) {
            changed = true;
        }
        active_delimiters.extend(declarations);
    }

    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(command)
    }
}

/// Finds heredocs declared on one executable shell line. Callers must skip
/// heredoc body lines before invoking this function, since their text is data.
fn heredoc_declarations(line: &str) -> VecDeque<(String, bool)> {
    let mut declarations = VecDeque::new();
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = line.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                match ch {
                    '\\' => escaped = true,
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    '<' if chars.next_if(|(_, next)| *next == '<').is_some() => {
                        // `<<<` is a here-string, not a heredoc.
                        if chars.next_if(|(_, next)| *next == '<').is_some() {
                            continue;
                        }
                        if let Some((delimiter, quoted, consumed)) =
                            heredoc_delimiter(&line[index + 2..])
                        {
                            declarations.push_back((delimiter, quoted));
                            for _ in 0..consumed {
                                chars.next();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    declarations
}

/// Parse one complete shell delimiter word after `<<`, preserving whether any
/// part was quoted or escaped and how many characters it occupies.
fn heredoc_delimiter(rest: &str) -> Option<(String, bool, usize)> {
    let mut consumed = 0usize;
    let mut chars = rest.chars().peekable();

    if chars.peek() == Some(&'-') {
        chars.next();
        consumed += 1;
    }
    while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
        chars.next();
        consumed += 1;
    }

    let mut delim = String::new();
    let mut quote = None;
    let mut quoted = false;
    let mut escaped = false;
    for c in chars {
        consumed += 1;
        if escaped {
            delim.push(c);
            escaped = false;
            quoted = true;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escaped = true;
            quoted = true;
            continue;
        }
        if let Some(active) = quote {
            if c == '\n' {
                return None;
            }
            if c == active {
                quote = None;
            } else {
                delim.push(c);
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            quoted = true;
        } else if c.is_whitespace() || ";&|<>()".contains(c) {
            consumed -= 1;
            break;
        } else {
            delim.push(c);
        }
    }
    (quote.is_none() && !escaped && !delim.is_empty()).then_some((delim, quoted, consumed))
}

/// The last path component of a command word, splitting on both `/` and `\`.
#[must_use]
pub fn command_basename(command: &str) -> &str {
    command.split(['/', '\\']).next_back().unwrap_or(command)
}

/// The lowercased basename of a command word with a trailing `.exe` removed.
#[must_use]
pub fn normalized_command_name(command: &str) -> String {
    let command = command_basename(command).to_ascii_lowercase();
    command
        .strip_suffix(".exe")
        .unwrap_or(command.as_str())
        .to_string()
}

/// Returns true if `s` starts with at least one inline env-var
/// assignment of the shape `NAME=...`, where `NAME` begins with an ASCII
/// letter or underscore. Matches any name, so `GIT_SSH=…`, `SSH_ASKPASS=…`, `LD_PRELOAD=…` and
/// `IFS=…` all count; deciding which of them are dangerous is the caller's job.
#[must_use]
pub fn has_leading_env_assignment(s: &str) -> bool {
    let Some(word) = s.split_whitespace().next() else {
        return false;
    };
    let Some((name, _value)) = word.split_once('=') else {
        return false;
    };
    if name.is_empty() {
        return false;
    }
    // Identifier shape: first char letter or `_`, the rest alphanumeric
    // or `_`. Anything else (e.g. `foo[bar]=`) is not a shell assignment.
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    true
}

/// Skip leading environment variable assignments (e.g. `FOO=bar cmd args`).
/// Returns the remainder starting at the first non-assignment word.
#[must_use]
pub fn skip_env_assignments(s: &str) -> &str {
    let mut rest = s;
    loop {
        rest = rest.trim_start();
        let Some(word) = rest.split_whitespace().next() else {
            return rest;
        };
        // Environment assignment: contains '=' and starts with a letter or underscore
        if word.contains('=')
            && word
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            // Advance past this word
            rest = &rest[word.len()..];
        } else {
            return rest;
        }
    }
}
