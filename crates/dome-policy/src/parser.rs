use serde::Deserialize;

use crate::types::Rule;

/// Top-level structure of a MCPDome policy TOML file.
/// We only care about the `[[rules]]` array for the policy engine;
/// other sections (auth, audit, rate_limit) are consumed by their
/// respective crates.
#[derive(Debug, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub mcpdome: Option<McpDomeConfig>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct McpDomeConfig {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_effect")]
    pub default_effect: String,
}

fn default_version() -> String {
    "1".to_string()
}

fn default_effect() -> String {
    "deny".to_string()
}

/// Parse a TOML string into a list of `Rule`s, sorted by priority (ascending).
pub fn parse_policy(toml_str: &str) -> Result<Vec<Rule>, PolicyParseError> {
    let file: PolicyFile =
        toml::from_str(toml_str).map_err(|e| PolicyParseError::Toml(e.to_string()))?;

    let mut rules = file.rules;

    if rules.is_empty() {
        tracing::warn!("policy file contains no rules; all requests will be default-denied");
    }

    // Sort by priority ascending (lowest number = highest priority = evaluated first).
    rules.sort_by_key(|r| r.priority);

    // Validate: check for duplicate IDs.
    let mut seen = std::collections::HashSet::new();
    for rule in &rules {
        if !seen.insert(&rule.id) {
            return Err(PolicyParseError::DuplicateRuleId(rule.id.clone()));
        }
    }

    Ok(rules)
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyParseError {
    #[error("TOML parse error: {0}")]
    Toml(String),
    #[error("duplicate rule id: {0}")]
    DuplicateRuleId(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_policy() {
        let toml = r#"
[[rules]]
id = "allow-all"
priority = 100
effect = "allow"
identities = "*"
tools = "*"
"#;
        let rules = parse_policy(toml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "allow-all");
    }

    #[test]
    fn parse_sorts_by_priority() {
        let toml = r#"
[[rules]]
id = "low-priority"
priority = 200
effect = "allow"
identities = "*"
tools = "*"

[[rules]]
id = "high-priority"
priority = 10
effect = "deny"
identities = "*"
tools = "*"
"#;
        let rules = parse_policy(toml).unwrap();
        assert_eq!(rules[0].id, "high-priority");
        assert_eq!(rules[1].id, "low-priority");
    }

    #[test]
    fn rejects_duplicate_ids() {
        let toml = r#"
[[rules]]
id = "same"
priority = 1
effect = "deny"
identities = "*"
tools = "*"

[[rules]]
id = "same"
priority = 2
effect = "allow"
identities = "*"
tools = "*"
"#;
        let err = parse_policy(toml).unwrap_err();
        assert!(err.to_string().contains("duplicate rule id"));
    }

    #[test]
    fn parse_structured_identities() {
        let toml = r#"
[[rules]]
id = "dev-tools"
priority = 100
effect = "allow"
identities = { labels = ["role:developer"] }
tools = ["read_file", "grep"]
"#;
        let rules = parse_policy(toml).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn parse_argument_constraints() {
        let toml = r#"
[[rules]]
id = "with-args"
priority = 50
effect = "allow"
identities = "*"
tools = ["write_file"]
arguments = [
    { param = "path", allow_glob = ["/tmp/**"], deny_regex = [".*\\.env$"] },
]
"#;
        let rules = parse_policy(toml).unwrap();
        assert_eq!(rules[0].arguments.len(), 1);
        assert_eq!(rules[0].arguments[0].param, "path");
    }
}
