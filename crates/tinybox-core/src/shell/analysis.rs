//! Generic parser facts; hosts own path authorization and approval policy.

use super::{classify, env_guard, executor, scan};
use tinybox_bus::{CommandAnalysis, CommandSegment};

/// Analyze live shell text without interpreting quoted heredoc bodies as commands.
#[must_use]
pub fn analyze_command(command: &str) -> CommandAnalysis {
    let stripped = scan::strip_quoted_heredoc_bodies(command);
    let segments = scan::split_unquoted_segments(&stripped)
        .into_iter()
        .filter_map(|source| {
            let command = scan::skip_env_assignments(&source);
            let mut words = command.split_whitespace();
            let base_raw = words.next()?;
            let normalized_name = scan::normalized_command_name(base_raw);
            let arguments = words.map(str::to_ascii_lowercase).collect::<Vec<_>>();
            let class = classify::classify_segment(
                &normalized_name,
                &arguments,
                &command.to_ascii_lowercase(),
            );
            Some(CommandSegment {
                command: command.to_owned(),
                basename: scan::command_basename(base_raw).to_owned(),
                executor: executor::is_command_executor(&normalized_name),
                normalized_name,
                arguments,
                class,
                leading_env_assignment: scan::has_leading_env_assignment(&source),
                dangerous_env_prefix: env_guard::has_dangerous_env_prefix(&source),
                source,
            })
        })
        .collect();
    let literal_words = stripped
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '\'' | '"' | '(' | ')' | '[' | ']' | ',' | ';' | '='
                )
        })
        .map(|word| word.trim_matches([':', '<', '>', '&', '|']))
        .filter(|word| !word.is_empty() && !word.contains("://"))
        .map(str::to_owned)
        .collect();
    CommandAnalysis {
        segments,
        hidden_execution: classify::has_hidden_execution(command),
        redirection: scan::contains_unquoted_char(&stripped, '>'),
        expansion: ["`", "$(", "${", "<(", ">("]
            .iter()
            .any(|marker| stripped.contains(marker)),
        tee: stripped
            .split_whitespace()
            .any(|word| word == "tee" || word.ends_with("/tee")),
        background: scan::contains_unquoted_single_ampersand(&stripped),
        literal_words,
    }
}
