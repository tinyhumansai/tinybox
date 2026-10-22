//! Tests for the quote-aware shell scanners.
//!
//! Structural cases retained by `TinyBox` for generic shell scanning.

use std::borrow::Cow;

use super::scan::{
    contains_unquoted_char, split_unquoted_segments, strip_heredoc_bodies,
    strip_quoted_heredoc_bodies,
};

fn segs(command: &str) -> Vec<String> {
    split_unquoted_segments(command)
}

#[test]
fn splits_on_every_unquoted_separator() {
    assert_eq!(segs("a; b"), ["a", "b"]);
    assert_eq!(segs("a\nb"), ["a", "b"]);
    assert_eq!(segs("a | b"), ["a", "b"]);
    assert_eq!(segs("a && b"), ["a", "b"]);
    assert_eq!(segs("a || b"), ["a", "b"]);
    assert_eq!(segs("a && b || c; d | e"), ["a", "b", "c", "d", "e"]);
}

#[test]
fn quotes_hide_separators() {
    assert_eq!(
        segs(r#"sqlite3 db "SELECT 1; SELECT 2;""#),
        [r#"sqlite3 db "SELECT 1; SELECT 2;""#]
    );
    assert_eq!(segs("echo 'a | b && c'"), ["echo 'a | b && c'"]);
    assert_eq!(segs("echo 'a'; echo \"b\""), ["echo 'a'", "echo \"b\""]);
}

#[test]
fn backslash_escapes_a_separator_outside_and_inside_double_quotes() {
    assert_eq!(segs(r"echo a\; b"), [r"echo a\; b"]);
    assert_eq!(segs(r#"echo "a\"; b""#), [r#"echo "a\"; b""#]);
    // Inside single quotes a backslash is literal, so the quote still closes.
    assert_eq!(segs(r"echo 'a\'; b"), [r"echo 'a\'", "b"]);
}

#[test]
fn single_ampersand_stays_inside_its_segment() {
    assert_eq!(segs("a & b"), ["a & b"]);
    assert_eq!(segs("cmd 2>&1 && next"), ["cmd 2>&1", "next"]);
}

#[test]
fn empty_and_blank_segments_are_dropped() {
    assert_eq!(segs("").len(), 0);
    assert_eq!(segs("  ;  ;\n").len(), 0);
    assert_eq!(segs(";;a;;"), ["a"]);
}

#[test]
fn unquoted_char_detection() {
    assert!(contains_unquoted_char("echo hi > out", '>'));
    assert!(!contains_unquoted_char("echo '>'", '>'));
    assert!(!contains_unquoted_char(r#"echo ">""#, '>'));
    assert!(!contains_unquoted_char(r"echo \>", '>'));
    assert!(contains_unquoted_char(r#"echo "x" > f"#, '>'));
    assert!(contains_unquoted_char("a`b", '`'));
    assert!(!contains_unquoted_char("", '>'));
    // An escaped quote inside double quotes does not close them.
    assert!(!contains_unquoted_char(r#"echo "a\" > b""#, '>'));
}

const MEAL_PLAN: &str = "cat > out/meal_plan.md << 'EOF'\n\
                         # Dinners\n\
                         - Chicken & Spinach\n\
                         - `backtick` and $(subshell)\n\
                         EOF";

#[test]
fn quoted_heredoc_body_is_blanked_and_shape_preserved() {
    let out = strip_quoted_heredoc_bodies(MEAL_PLAN);
    assert_eq!(out, "cat > out/meal_plan.md << 'EOF'\n\n\n\nEOF");
    assert_eq!(out.lines().count(), MEAL_PLAN.lines().count());
    assert!(out.contains('>'));
}

#[test]
fn heredocs_are_consumed_in_input_order_and_delimiters_are_complete_words() {
    let mixed = "cat <<EOF <<'END'\n$(danger)\nEOF\nsafe\nEND\necho live";
    assert_eq!(
        strip_quoted_heredoc_bodies(mixed),
        "cat <<EOF <<'END'\n$(danger)\nEOF\n\nEND\necho live"
    );
    let concatenated = "cat <<'EOF'x\nbody\nEOFx\necho live";
    assert_eq!(
        strip_quoted_heredoc_bodies(concatenated),
        "cat <<'EOF'x\n\nEOFx\necho live"
    );
}

#[test]
fn heredoc_after_an_intervening_command_does_not_hide_that_command() {
    let command = "cat <<'A'\none\nA\necho DANGER &\ncat <<'B'\ntwo\nB";
    assert_eq!(
        strip_quoted_heredoc_bodies(command),
        "cat <<'A'\n\nA\necho DANGER &\ncat <<'B'\n\nB"
    );
}

#[test]
fn heredoc_operators_inside_a_heredoc_body_are_data() {
    let command = "cat <<'EOF'\n<<'FAKE'\nEOF\necho DANGER &";
    assert_eq!(
        strip_quoted_heredoc_bodies(command),
        "cat <<'EOF'\n\nEOF\necho DANGER &"
    );
}

#[test]
fn heredoc_delimiter_ends_at_a_shell_operator() {
    let command = "cat <<'EOF'; echo okay\nbody\nEOF\necho DANGER &";
    assert_eq!(
        strip_quoted_heredoc_bodies(command),
        "cat <<'EOF'; echo okay\n\nEOF\necho DANGER &"
    );
}

#[test]
fn double_quoted_and_dash_delimiters_count_as_quoted() {
    let out = strip_quoted_heredoc_bodies("cat << \"END\"\na & b\nEND\n");
    assert_eq!(out, "cat << \"END\"\n\nEND\n");
    let out = strip_quoted_heredoc_bodies("cat <<-'END'\na & b\nEND");
    assert_eq!(out, "cat <<-'END'\n\nEND");
    let out = strip_quoted_heredoc_bodies("cat <<'END'\na & b\nEND");
    assert_eq!(out, "cat <<'END'\n\nEND");
}

#[test]
fn unquoted_heredoc_delimiter_is_left_alone() {
    let live = "cat > out/x.md << EOF\nhello $(rm -rf ~)\nEOF";
    assert!(matches!(
        strip_quoted_heredoc_bodies(live),
        Cow::Borrowed(_)
    ));
    let dash = "cat <<-EOF\n$(x)\nEOF";
    assert!(matches!(
        strip_quoted_heredoc_bodies(dash),
        Cow::Borrowed(_)
    ));
}

#[test]
fn all_heredoc_bodies_are_blank_for_structural_scans() {
    let body_only = strip_heredoc_bodies("cat << EOF\nbody > is not a redirect\nEOF\n");
    assert!(!contains_unquoted_char(&body_only, '>'));
    let outside =
        strip_heredoc_bodies("cat << EOF\nbody > is not a redirect\nEOF\nprintf done > out\n");
    assert!(contains_unquoted_char(&outside, '>'));
    assert!(outside.contains("printf done > out"));
}

#[test]
fn heredoc_structural_scan_handles_tabs_quoting_and_multiple_bodies() {
    let tabs = strip_heredoc_bodies("cat <<- EOF\n\tbody > data\n\tEOF\n");
    assert!(!contains_unquoted_char(&tabs, '>'));

    let mixed_quote = strip_heredoc_bodies("cat <<'E'OF\nbody > data\nEOF\n");
    assert!(!contains_unquoted_char(&mixed_quote, '>'));

    let double_quote = strip_heredoc_bodies("cat << \"E\\\"OF\"\nbody > data\nE\"OF\n");
    assert!(!contains_unquoted_char(&double_quote, '>'));

    let multiple = strip_heredoc_bodies(
        "cat << FIRST << SECOND\nfirst > data\nFIRST\nsecond > data\nSECOND\n",
    );
    assert!(!contains_unquoted_char(&multiple, '>'));

    assert!(matches!(
        strip_heredoc_bodies("echo \"<< not a heredoc\""),
        Cow::Borrowed(_)
    ));
    assert!(matches!(
        strip_heredoc_bodies("cat <<< \"text > data\""),
        Cow::Borrowed(_)
    ));
    assert!(matches!(
        strip_heredoc_bodies("cat << EOF"),
        Cow::Borrowed(_)
    ));
}

#[test]
fn heredoc_comment_does_not_consume_the_next_command() {
    let command = "# << EOF\nprintf done > out\n";
    let stripped = strip_heredoc_bodies(command);

    assert!(contains_unquoted_char(&stripped, '>'));
    assert!(stripped.contains("printf done > out"));
}

#[test]
fn arithmetic_shifts_do_not_hide_following_redirects() {
    for command in [
        "echo $((1 << 2))\nprintf done > out\n",
        "((1 << 2))\nprintf done > out\n",
        "echo $((1 + (2 << 3)))\nprintf done > out\n",
        "echo $((1\n << 2))\nprintf done > out\n",
    ] {
        let stripped = strip_heredoc_bodies(command);
        assert!(contains_unquoted_char(&stripped, '>'), "{command}");
        assert!(stripped.contains("printf done > out"), "{command}");
    }
}

#[test]
fn heredoc_inside_arithmetic_command_substitution_remains_data() {
    let command = "echo $((1 + $(cat <<'EOF'\n2 > data\nEOF\n)))\nprintf done > out\n";
    let stripped = strip_heredoc_bodies(command);
    assert!(!stripped.contains("2 > data"));
    assert!(stripped.contains("printf done > out"));
}

#[test]
fn double_quoted_heredoc_delimiter_preserves_literal_backslash() {
    let command = "cat << \"E\\OF\"\nbody > data\nE\\OF\nprintf done > out\n";
    let stripped = strip_heredoc_bodies(command);

    assert!(contains_unquoted_char(&stripped, '>'));
    assert!(stripped.contains("printf done > out"));
}

#[test]
fn here_string_is_not_a_heredoc() {
    let command = "cat <<< 'plain'\necho $(whoami)";
    assert!(matches!(
        strip_quoted_heredoc_bodies(command),
        Cow::Borrowed(_)
    ));
}

#[test]
fn commands_without_heredocs_are_borrowed() {
    assert!(matches!(
        strip_quoted_heredoc_bodies("ls -la"),
        Cow::Borrowed(_)
    ));
    // `<<` present but only inside quotes.
    assert!(matches!(
        strip_quoted_heredoc_bodies("echo '<< EOF'"),
        Cow::Borrowed(_)
    ));
    assert!(matches!(
        strip_quoted_heredoc_bodies(r#"echo "<<'EOF'""#),
        Cow::Borrowed(_)
    ));
}

#[test]
fn text_outside_the_heredoc_is_kept() {
    let command = "cat > out/$(whoami).md << 'EOF'\nplain text\nEOF\nrm -rf /tmp/x";
    let out = strip_quoted_heredoc_bodies(command);
    assert_eq!(out, "cat > out/$(whoami).md << 'EOF'\n\nEOF\nrm -rf /tmp/x");
}

#[test]
fn unterminated_heredoc_blanks_to_the_end() {
    let out = strip_quoted_heredoc_bodies("cat << 'EOF'\nbody & more\nstill body");
    assert_eq!(out, "cat << 'EOF'\n\n");
}

#[test]
fn delimiter_line_is_matched_after_trimming() {
    let out = strip_quoted_heredoc_bodies("cat << 'EOF'\nEOF is not it\n  EOF  \nnext");
    assert_eq!(out, "cat << 'EOF'\n\n  EOF  \nnext");
}

#[test]
fn empty_or_multiline_quoted_delimiter_is_not_a_heredoc() {
    assert!(matches!(
        strip_quoted_heredoc_bodies("cat << ''\nbody\n"),
        Cow::Borrowed(_)
    ));
    assert!(matches!(
        strip_quoted_heredoc_bodies("cat << 'EO\nF'\nbody\n"),
        Cow::Borrowed(_)
    ));
}
