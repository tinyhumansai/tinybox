//! Structural scanning of shell command text for transport and display.
//!
//! These helpers split unquoted segments, detect unquoted characters, and blank
//! heredoc bodies. They never classify a command or decide whether it is allowed.

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
/// A quoted delimiter makes the heredoc body data: the shell does not expand
/// operators or substitutions inside it. This helper blanks those body lines
/// while preserving line counts and the surrounding command text.
///
/// An **unquoted** delimiter (`<< EOF`) is deliberately left alone because the
/// shell still expands substitutions in that body.
///
/// Returns [`Cow::Borrowed`] when the command has no quoted heredoc.
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

/// Blank out every heredoc body, regardless of whether its delimiter is
/// quoted. Use this for structural facts such as redirects, where body text is
/// data even when the shell expands it before passing it to the command.
#[must_use]
pub fn strip_heredoc_bodies(command: &str) -> Cow<'_, str> {
    if !command.contains("<<") {
        return Cow::Borrowed(command);
    }

    let mut output = String::with_capacity(command.len());
    let mut pending = std::collections::VecDeque::<(String, bool)>::new();
    let mut changed = false;
    let mut arithmetic = Vec::new();
    for line in command.split_inclusive('\n') {
        if let Some((delimiter, strip_tabs)) = pending.front() {
            let body = line.trim_end_matches(['\n', '\r']);
            let terminator = if *strip_tabs {
                body.trim_start_matches('\t')
            } else {
                body
            };
            if terminator == delimiter {
                pending.pop_front();
                output.push_str(line);
            } else {
                changed = true;
                if line.ends_with('\n') {
                    output.push('\n');
                }
            }
            continue;
        }

        output.push_str(line);
        pending.extend(heredoc_delimiters(line, &mut arithmetic));
    }
    if changed {
        Cow::Owned(output)
    } else {
        Cow::Borrowed(command)
    }
}

fn heredoc_delimiters(line: &str, arithmetic: &mut Vec<bool>) -> Vec<(String, bool)> {
    let mut delimiters = Vec::new();
    let mut chars = line.char_indices().peekable();
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut at_word_start = true;
    while let Some((index, character)) = chars.next() {
        match quote {
            QuoteState::Single => {
                if character == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    at_word_start = false;
                    continue;
                }
                match character {
                    '\\' => escaped = true,
                    '\'' => {
                        quote = QuoteState::Single;
                        at_word_start = false;
                    }
                    '"' => {
                        quote = QuoteState::Double;
                        at_word_start = false;
                    }
                    '#' if at_word_start => break,
                    '(' => {
                        // A command substitution inside arithmetic resumes shell syntax.
                        if chars.next_if(|(_, value)| *value == '(').is_some() {
                            arithmetic.extend([true, true]);
                        } else if line[..index].ends_with('$') {
                            arithmetic.push(false);
                        } else {
                            arithmetic.push(arithmetic.last().copied().unwrap_or(false));
                        }
                        at_word_start = true;
                    }
                    ')' => {
                        arithmetic.pop();
                        at_word_start = true;
                    }
                    '<' if arithmetic.last().copied().unwrap_or(false) => {
                        at_word_start = true;
                    }
                    '<' if chars.next_if(|(_, value)| *value == '<').is_some() => {
                        if chars.next_if(|(_, value)| *value == '<').is_some() {
                            at_word_start = true;
                            continue;
                        }
                        if let Some((delimiter, strip_tabs)) =
                            structural_heredoc_delimiter(&line[index + 2..])
                        {
                            delimiters.push((delimiter, strip_tabs));
                        }
                        at_word_start = true;
                    }
                    character if character.is_whitespace() || ";|&()<>".contains(character) => {
                        at_word_start = true;
                    }
                    _ => at_word_start = false,
                }
            }
        }
    }
    delimiters
}

fn structural_heredoc_delimiter(rest: &str) -> Option<(String, bool)> {
    let mut chars = rest.chars().peekable();
    let strip_tabs = chars.next_if_eq(&'-').is_some();
    while chars
        .peek()
        .is_some_and(|character| matches!(character, ' ' | '\t'))
    {
        chars.next();
    }
    let mut delimiter = String::new();
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut started = false;
    for character in chars {
        match quote {
            QuoteState::Single => {
                if character == '\'' {
                    quote = QuoteState::None;
                } else {
                    delimiter.push(character);
                }
            }
            QuoteState::Double => {
                if escaped {
                    if !matches!(character, '$' | '`' | '"' | '\\' | '\n') {
                        delimiter.push('\\');
                    }
                    delimiter.push(character);
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quote = QuoteState::None;
                } else {
                    delimiter.push(character);
                }
            }
            QuoteState::None => {
                if escaped {
                    delimiter.push(character);
                    escaped = false;
                    started = true;
                    continue;
                }
                match character {
                    '\'' => {
                        quote = QuoteState::Single;
                        started = true;
                    }
                    '"' => {
                        quote = QuoteState::Double;
                        started = true;
                    }
                    '\\' => {
                        escaped = true;
                        started = true;
                    }
                    character if character.is_whitespace() || ";|&()<>".contains(character) => {
                        break;
                    }
                    _ => {
                        delimiter.push(character);
                        started = true;
                    }
                }
            }
        }
    }
    (started && !delimiter.is_empty()).then_some((delimiter, strip_tabs))
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
