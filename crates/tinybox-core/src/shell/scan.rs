//! Quote-aware scanning of a shell command *string*.
//!
//! These helpers are lexical only: they split a command on unquoted
//! separators, find unquoted control characters, blank quoted-heredoc bodies,
//! and normalise a command word. They decide nothing about whether a command
//! is safe; a host that gates execution builds its policy on top of them.
//! Every function is pure and none of them expands or evaluates anything.

use std::borrow::Cow;

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
                    for inner in chars.by_ref() {
                        match nested_quote {
                            QuoteState::Single if inner == '\'' => nested_quote = QuoteState::None,
                            QuoteState::Double if inner == '"' => nested_quote = QuoteState::None,
                            QuoteState::None if inner == '\'' => nested_quote = QuoteState::Single,
                            QuoteState::None if inner == '"' => nested_quote = QuoteState::Double,
                            QuoteState::None if inner == '(' => depth += 1,
                            QuoteState::None if inner == ')' => {
                                depth -= 1;
                                if depth == 0 { break; }
                            }
                            _ => {}
                        }
                        nested.push(inner);
                    }
                    if contains_unquoted_background_ampersand(&nested) { return true; }
                    continue;
                }
                if ch == '`' {
                    let mut nested = String::new();
                    let mut escaped_tick = false;
                    for inner in chars.by_ref() {
                        if inner == '`' && !escaped_tick { break; }
                        escaped_tick = inner == '\\' && !escaped_tick;
                        nested.push(inner);
                    }
                    if contains_unquoted_background_ampersand(&nested) { return true; }
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

    let mut delimiters: Vec<String> = Vec::new();
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = command.char_indices().peekable();
    // Byte offsets of the `<<` operators whose delimiter is quoted, in order.
    let mut operators: Vec<usize> = Vec::new();

    while let Some((idx, ch)) = chars.next() {
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
                match ch {
                    '\\' => escaped = true,
                    '"' => quote = QuoteState::None,
                    _ => {}
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
                    '<' if chars.next_if(|(_, c)| *c == '<').is_some() => {
                        // `<<<` is a here-string, not a heredoc: no body follows.
                        if chars.next_if(|(_, c)| *c == '<').is_some() {
                            continue;
                        }
                        let rest = &command[idx + 2..];
                        if let Some((delim, consumed)) = quoted_heredoc_delimiter(rest) {
                            delimiters.push(delim);
                            operators.push(idx);
                            // Skip past the delimiter token so its quotes do not
                            // re-enter the quote state machine.
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

    if operators.is_empty() {
        return Cow::Borrowed(command);
    }

    // Walk the lines. Once the line carrying the Nth operator ends, every
    // following line is body until its terminator line appears.
    let mut out = String::with_capacity(command.len());
    let mut next_delim = 0usize;
    let mut open: Option<String> = None;
    let mut consumed_bytes = 0usize;

    for line in command.split_inclusive('\n') {
        let line_start = consumed_bytes;
        consumed_bytes += line.len();

        if let Some(delim) = open.clone() {
            if line.trim() == delim {
                open = None;
                out.push_str(line);
            } else {
                // Blank the body, keeping the newline so offsets stay sane.
                if line.ends_with('\n') {
                    out.push('\n');
                }
            }
            continue;
        }

        out.push_str(line);
        let line_end = line_start + line.len();
        while next_delim < operators.len() && operators[next_delim] < line_end {
            // The last operator on a line wins: `cat << 'A' << 'B'` reads A's
            // body first, but only tracking one at a time is enough for the
            // guard, and a nested case simply keeps scanning as today.
            open = Some(delimiters[next_delim].clone());
            next_delim += 1;
        }
    }

    Cow::Owned(out)
}

/// Parse a heredoc delimiter token immediately after `<<`, returning the
/// delimiter and how many chars of `rest` it spans — **only** when the token is
/// quoted (`'EOF'` or `"EOF"`), optionally preceded by `-` and whitespace.
/// An unquoted delimiter returns `None`, because its body is still expanded.
fn quoted_heredoc_delimiter(rest: &str) -> Option<(String, usize)> {
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

    let Some(quote @ ('\'' | '"')) = chars.next() else {
        return None;
    };
    consumed += 1;

    let mut delim = String::new();
    for c in chars {
        consumed += 1;
        if c == quote {
            return (!delim.is_empty()).then_some((delim, consumed));
        }
        if c == '\n' {
            return None;
        }
        delim.push(c);
    }
    None
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
            rest = rest[word.len()..].trim_start();
        } else {
            return rest;
        }
    }
}
