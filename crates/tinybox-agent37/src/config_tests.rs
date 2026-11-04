//! The config defaults to agent37's public hosts, trims explicit bases, and
//! never prints the key.

use super::*;

#[test]
fn an_api_key_never_prints_itself() {
    let key = ApiKey::new("super-secret-value");
    let shown = format!("{key:?}");
    assert!(!shown.contains("super-secret-value"), "key leaked: {shown}");
    assert_eq!(key.expose(), "super-secret-value");
}

#[test]
fn new_uses_the_public_agent37_hosts() {
    let config = Agent37Config::new("k");
    assert_eq!(config.api_base, DEFAULT_API_BASE);
    assert_eq!(config.sandbox_base, DEFAULT_SANDBOX_BASE);
    assert_eq!(config.api_key.expose(), "k");
}

#[test]
fn with_bases_trims_a_trailing_slash_from_each_base() {
    let config = Agent37Config::with_bases("https://api.example/", "https://sandbox.example/", "k");
    assert_eq!(config.api_base, "https://api.example");
    assert_eq!(config.sandbox_base, "https://sandbox.example");
}

#[test]
fn a_config_debug_does_not_leak_the_key() {
    let config = Agent37Config::new("top-secret");
    let shown = format!("{config:?}");
    assert!(
        !shown.contains("top-secret"),
        "key leaked in config debug: {shown}"
    );
}
