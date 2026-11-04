//! The config defaults to agent37's public hosts, trims explicit bases, never
//! prints the key, and reads a required key (with optional base overrides) from
//! a lookup.

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

/// A lookup that answers from fixed pairs, like a slice of the environment.
fn lookup_from(pairs: Vec<(&'static str, &'static str)>) -> impl Fn(&str) -> Option<String> {
    move |key| {
        pairs
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| (*value).to_owned())
    }
}

#[test]
fn from_lookup_with_only_the_key_uses_the_default_hosts() -> Result<()> {
    let config = Agent37Config::from_lookup(lookup_from(vec![(API_KEY_VAR, "sk_test")]))?;
    assert_eq!(config.api_base, DEFAULT_API_BASE);
    assert_eq!(config.sandbox_base, DEFAULT_SANDBOX_BASE);
    assert_eq!(config.api_key.expose(), "sk_test");
    Ok(())
}

#[test]
fn from_lookup_honours_and_trims_base_overrides() -> Result<()> {
    let config = Agent37Config::from_lookup(lookup_from(vec![
        (API_KEY_VAR, "sk_test"),
        (API_BASE_VAR, "https://api.acme.test/"),
        (SANDBOX_BASE_VAR, "https://sandbox.acme.test/"),
    ]))?;
    assert_eq!(config.api_base, "https://api.acme.test");
    assert_eq!(config.sandbox_base, "https://sandbox.acme.test");
    Ok(())
}

#[test]
fn from_lookup_treats_a_blank_override_as_unset() -> Result<()> {
    let config = Agent37Config::from_lookup(lookup_from(vec![
        (API_KEY_VAR, "sk_test"),
        (API_BASE_VAR, "   "),
    ]))?;
    assert_eq!(config.api_base, DEFAULT_API_BASE);
    Ok(())
}

#[test]
fn from_lookup_without_the_key_is_a_backend_error() {
    let result = Agent37Config::from_lookup(lookup_from(vec![]));
    assert!(matches!(result, Err(Error::Backend { .. })));
}

#[test]
fn from_lookup_with_a_blank_key_is_a_backend_error() {
    let result = Agent37Config::from_lookup(lookup_from(vec![(API_KEY_VAR, "  ")]));
    assert!(matches!(result, Err(Error::Backend { .. })));
}
