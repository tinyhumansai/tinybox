//! Tests for the quote-aware shell scanners.
//!
//! A host that gates command execution relies on these, so every case here is
//! one such a host was found to depend on: quoting that must hide a separator,
//! an escape that must not, and heredoc bodies that are data only when their
//! delimiter is quoted.

use std::borrow::Cow;

use super::scan::{
    command_basename, contains_unquoted_background_ampersand, contains_unquoted_char,
    contains_unquoted_single_ampersand, has_leading_env_assignment, normalized_command_name,
    skip_env_assignments, split_unquoted_segments, strip_heredoc_bodies,
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
fn single_ampersand_detection() {
    assert!(contains_unquoted_single_ampersand("sleep 1 &"));
    assert!(contains_unquoted_single_ampersand("a & b"));
    assert!(!contains_unquoted_single_ampersand("a && b"));
    assert!(!contains_unquoted_single_ampersand("echo 'a & b'"));
    assert!(!contains_unquoted_single_ampersand(r#"echo "a & b""#));
    assert!(contains_unquoted_single_ampersand(r"echo \& &"));
    assert!(!contains_unquoted_single_ampersand(r"echo \&"));
    // The fd-dup redirect counts here; the background variant is the lenient one.
    assert!(contains_unquoted_single_ampersand("cmd 2>&1"));
}

#[test]
fn background_ampersand_ignores_fd_duplication() {
    assert!(!contains_unquoted_background_ampersand("cmd 2>&1"));
    assert!(!contains_unquoted_background_ampersand("cmd >&2"));
    assert!(!contains_unquoted_background_ampersand("cmd &>out.log"));
    assert!(!contains_unquoted_background_ampersand("a && b"));
    assert!(contains_unquoted_background_ampersand("cmd &"));
    assert!(contains_unquoted_background_ampersand("a & b"));
    assert!(contains_unquoted_background_ampersand("cmd 2>&1 &"));
    assert!(!contains_unquoted_background_ampersand("echo 'a & b'"));
    assert!(!contains_unquoted_background_ampersand(r#"echo "a & b""#));
    assert!(!contains_unquoted_background_ampersand(r"echo a\&b"));
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

#[test]
fn basename_handles_both_separators() {
    assert_eq!(command_basename("/usr/bin/git"), "git");
    assert_eq!(command_basename(r"C:\Windows\System32\cmd.exe"), "cmd.exe");
    assert_eq!(command_basename("git"), "git");
    assert_eq!(command_basename(""), "");
    assert_eq!(command_basename("/bin/"), "");
}

#[test]
fn normalized_name_lowercases_and_strips_exe() {
    assert_eq!(normalized_command_name("/usr/bin/GIT"), "git");
    assert_eq!(
        normalized_command_name(r"C:\x\PowerShell.EXE"),
        "powershell"
    );
    assert_eq!(normalized_command_name("python3"), "python3");
    assert_eq!(normalized_command_name("a.exe.exe"), "a.exe");
}

#[test]
fn leading_env_assignment_shape() {
    assert!(has_leading_env_assignment("FOO=bar cmd"));
    assert!(has_leading_env_assignment("  _x1=1 cmd"));
    assert!(has_leading_env_assignment("LD_PRELOAD=/x ls"));
    assert!(has_leading_env_assignment("A= cmd"));
    assert!(!has_leading_env_assignment("cmd FOO=bar"));
    assert!(!has_leading_env_assignment("=bar cmd"));
    assert!(!has_leading_env_assignment("1A=b cmd"));
    assert!(!has_leading_env_assignment("foo[bar]=1 cmd"));
    assert!(!has_leading_env_assignment("git log"));
    assert!(!has_leading_env_assignment(""));
}

#[test]
fn skipping_env_assignments() {
    assert_eq!(skip_env_assignments("A=1 B=2 git log"), "git log");
    assert_eq!(skip_env_assignments("git log"), "git log");
    assert_eq!(skip_env_assignments("A=1"), "");
    assert_eq!(skip_env_assignments(""), "");
    // `=` in a non-identifier word is a command, not an assignment.
    assert_eq!(skip_env_assignments("1A=b cmd"), "1A=b cmd");
    // The assignment filter is intentionally looser than the shape check.
    assert_eq!(skip_env_assignments("foo[bar]=1 cmd"), "cmd");
}
