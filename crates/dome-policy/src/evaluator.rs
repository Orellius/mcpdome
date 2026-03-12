use regex::Regex;
use serde_json::Value;

use crate::types::{ArgConstraint, Decision, Identity, Rule};

/// Recursively collect all string values from any JSON structure.
///
/// Descends into nested objects and arrays, returning references to
/// every string leaf value. This prevents evasion by hiding malicious
/// content inside nested JSON structures.
fn extract_strings(value: &Value) -> Vec<&str> {
    let mut out = Vec::new();
    extract_strings_inner(value, &mut out);
    out
}

fn extract_strings_inner<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::String(s) => out.push(s.as_str()),
        Value::Array(arr) => {
            for item in arr {
                extract_strings_inner(item, out);
            }
        }
        Value::Object(map) => {
            for (_key, val) in map {
                extract_strings_inner(val, out);
            }
        }
        _ => {}
    }
}

/// The core policy engine. Holds rules sorted by priority and evaluates
/// incoming requests against them. First matching rule wins; no match = deny.
pub struct PolicyEngine {
    rules: Vec<Rule>,
    /// Pre-compiled deny regexes, indexed parallel to rules then to arg constraints.
    /// Structure: compiled_regexes[rule_idx][constraint_idx] = Vec<Regex>
    compiled_regexes: Vec<Vec<Vec<Regex>>>,
}

impl PolicyEngine {
    /// Create a new engine from rules that are already sorted by priority (ascending).
    /// Panics on invalid regex in deny_regex -- callers should validate first.
    pub fn new(rules: Vec<Rule>) -> Result<Self, PolicyBuildError> {
        let mut compiled_regexes = Vec::with_capacity(rules.len());

        for rule in &rules {
            let mut rule_regexes = Vec::with_capacity(rule.arguments.len());
            for constraint in &rule.arguments {
                let mut constraint_regexes = Vec::new();
                if let Some(patterns) = &constraint.deny_regex {
                    for pattern in patterns {
                        let re =
                            Regex::new(pattern).map_err(|e| PolicyBuildError::InvalidRegex {
                                rule_id: rule.id.clone(),
                                pattern: pattern.clone(),
                                reason: e.to_string(),
                            })?;
                        constraint_regexes.push(re);
                    }
                }
                rule_regexes.push(constraint_regexes);
            }
            compiled_regexes.push(rule_regexes);
        }

        Ok(Self {
            rules,
            compiled_regexes,
        })
    }

    /// Evaluate a tools/call request against the policy.
    ///
    /// - `identity`: the resolved caller identity
    /// - `tool`: the tool name being called
    /// - `args`: the arguments JSON object (may be null/empty)
    pub fn evaluate(&self, identity: &Identity, tool: &str, args: &Value) -> Decision {
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            if !rule.identities.matches(identity) {
                continue;
            }
            if !rule.tools.matches(tool) {
                continue;
            }
            if !self.check_arguments(rule_idx, rule, args) {
                continue;
            }

            tracing::debug!(
                rule_id = %rule.id,
                effect = ?rule.effect,
                tool = %tool,
                principal = %identity.principal,
                "policy rule matched"
            );

            return Decision {
                effect: rule.effect.clone(),
                rule_id: rule.id.clone(),
                reason: format!("matched rule '{}'", rule.id),
            };
        }

        tracing::debug!(
            tool = %tool,
            principal = %identity.principal,
            "no policy rule matched, default deny"
        );

        Decision::default_deny()
    }

    /// Check all argument constraints for a rule. Returns true if the args
    /// satisfy every constraint (or if the rule has no constraints).
    ///
    /// Semantics depend on the rule's effect:
    ///
    /// **Allow/AuditOnly rules**: constraints act as restrictions. The rule
    /// matches only if all constraints pass (allow_glob matches, deny_regex
    /// does NOT match, max_length not exceeded).
    ///
    /// **Deny rules**: constraints act as trigger conditions. The rule matches
    /// if any constraint's deny_regex fires (i.e., the pattern IS found).
    /// This enables the "block-secret-patterns" idiom from the spec.
    fn check_arguments(&self, rule_idx: usize, rule: &Rule, args: &Value) -> bool {
        use crate::types::Effect;

        if rule.arguments.is_empty() {
            return true;
        }

        let args_obj = match args.as_object() {
            Some(obj) => obj,
            None => {
                // No arguments provided but rule has constraints.
                // For allow rules: constraints can't be satisfied if allow_glob is required.
                // For deny rules: nothing to scan, so the deny trigger doesn't fire.
                return match rule.effect {
                    Effect::Deny => false,
                    _ => rule.arguments.iter().all(|c| c.allow_glob.is_none()),
                };
            }
        };

        match rule.effect {
            Effect::Deny => self.check_arguments_deny(rule_idx, rule, args_obj),
            _ => self.check_arguments_allow(rule_idx, rule, args_obj),
        }
    }

    /// For allow/audit_only rules: all constraints must pass.
    ///
    /// Recursively descends into nested objects and arrays to check
    /// all string leaf values against the constraint.
    #[allow(clippy::collapsible_if)]
    fn check_arguments_allow(
        &self,
        rule_idx: usize,
        rule: &Rule,
        args_obj: &serde_json::Map<String, Value>,
    ) -> bool {
        for (constraint_idx, constraint) in rule.arguments.iter().enumerate() {
            let deny_regexes = &self.compiled_regexes[rule_idx][constraint_idx];

            if constraint.param == "*" {
                for (_key, val) in args_obj {
                    let strings = extract_strings(val);
                    for s in strings {
                        if !self.value_passes_constraint(constraint, deny_regexes, s) {
                            return false;
                        }
                    }
                }
            } else if let Some(val) = args_obj.get(&constraint.param) {
                let strings = extract_strings(val);
                for s in strings {
                    if !self.value_passes_constraint(constraint, deny_regexes, s) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// For deny rules: the rule matches (returns true) if ANY constraint's
    /// deny_regex fires on ANY argument, or if allow_glob is set and the value
    /// falls outside the allowed set. This is the trigger-based model.
    ///
    /// Recursively descends into nested objects and arrays to check
    /// all string leaf values against the constraint.
    #[allow(clippy::collapsible_if)]
    fn check_arguments_deny(
        &self,
        rule_idx: usize,
        rule: &Rule,
        args_obj: &serde_json::Map<String, Value>,
    ) -> bool {
        for (constraint_idx, constraint) in rule.arguments.iter().enumerate() {
            let deny_regexes = &self.compiled_regexes[rule_idx][constraint_idx];

            if constraint.param == "*" {
                for (_key, val) in args_obj {
                    let strings = extract_strings(val);
                    for s in strings {
                        if self.value_triggers_deny(constraint, deny_regexes, s) {
                            return true;
                        }
                    }
                }
            } else if let Some(val) = args_obj.get(&constraint.param) {
                let strings = extract_strings(val);
                for s in strings {
                    if self.value_triggers_deny(constraint, deny_regexes, s) {
                        return true;
                    }
                }
            }
        }
        // No constraint triggered -- deny rule does not match.
        false
    }

    /// Returns true if the value satisfies the constraint (for allow rules).
    /// - allow_glob: value must match at least one glob.
    /// - deny_regex: value must NOT match any regex.
    /// - max_length: value must not exceed the limit.
    #[allow(clippy::collapsible_if)]
    fn value_passes_constraint(
        &self,
        constraint: &ArgConstraint,
        deny_regexes: &[Regex],
        value: &str,
    ) -> bool {
        if let Some(max) = constraint.max_length {
            if value.len() > max {
                return false;
            }
        }

        if let Some(globs) = &constraint.allow_glob {
            if !globs.iter().any(|g| glob_match::glob_match(g, value)) {
                return false;
            }
        }

        for re in deny_regexes {
            if re.is_match(value) {
                return false;
            }
        }

        true
    }

    /// Returns true if the value triggers a deny (for deny rules).
    /// - deny_regex: fires if ANY regex matches.
    /// - max_length: fires if exceeded.
    #[allow(clippy::collapsible_if)]
    fn value_triggers_deny(
        &self,
        constraint: &ArgConstraint,
        deny_regexes: &[Regex],
        value: &str,
    ) -> bool {
        if let Some(max) = constraint.max_length {
            if value.len() > max {
                return true;
            }
        }

        for re in deny_regexes {
            if re.is_match(value) {
                return true;
            }
        }

        false
    }

    /// Returns the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyBuildError {
    #[error("invalid regex in rule '{rule_id}', pattern '{pattern}': {reason}")]
    InvalidRegex {
        rule_id: String,
        pattern: String,
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_policy;
    use crate::types::{Effect, Identity};
    use serde_json::json;
    use std::collections::HashSet;

    fn identity(principal: &str, labels: &[&str]) -> Identity {
        Identity {
            principal: principal.to_string(),
            labels: labels.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
        }
    }

    fn engine_from_toml(toml: &str) -> PolicyEngine {
        let rules = parse_policy(toml).unwrap();
        PolicyEngine::new(rules).unwrap()
    }

    // --- Default deny ---

    #[test]
    fn default_deny_when_no_rules() {
        let engine = PolicyEngine::new(vec![]).unwrap();
        let id = identity("user:alice", &[]);
        let decision = engine.evaluate(&id, "read_file", &json!({}));
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, "__default_deny");
        assert!(!decision.is_allowed());
    }

    #[test]
    fn default_deny_when_no_rule_matches() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "only-admins"
priority = 100
effect = "allow"
identities = { labels = ["role:admin"] }
tools = "*"
"#,
        );
        let id = identity("user:bob", &["role:viewer"]);
        let decision = engine.evaluate(&id, "read_file", &json!({}));
        assert_eq!(decision.effect, Effect::Deny);
        assert!(!decision.is_allowed());
    }

    // --- Allow rule matching ---

    #[test]
    fn allow_rule_matches() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "allow-read"
priority = 100
effect = "allow"
identities = { labels = ["role:developer"] }
tools = ["read_file", "grep"]
"#,
        );
        let id = identity("user:alice", &["role:developer"]);
        let decision = engine.evaluate(&id, "read_file", &json!({}));
        assert_eq!(decision.effect, Effect::Allow);
        assert_eq!(decision.rule_id, "allow-read");
        assert!(decision.is_allowed());
    }

    #[test]
    fn allow_wildcard_identity_and_tools() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "allow-everything"
priority = 100
effect = "allow"
identities = "*"
tools = "*"
"#,
        );
        let id = identity("anyone", &[]);
        let decision = engine.evaluate(&id, "anything", &json!({}));
        assert_eq!(decision.effect, Effect::Allow);
    }

    // --- Deny rule overrides allow ---

    #[test]
    fn deny_overrides_allow_by_priority() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "deny-destructive"
priority = 50
effect = "deny"
identities = { labels = ["role:developer"] }
tools = ["delete_file", "drop_table"]

[[rules]]
id = "allow-all-tools"
priority = 100
effect = "allow"
identities = { labels = ["role:developer"] }
tools = "*"
"#,
        );
        let id = identity("user:alice", &["role:developer"]);

        // delete_file hits the deny rule first (priority 50 < 100)
        let decision = engine.evaluate(&id, "delete_file", &json!({}));
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, "deny-destructive");

        // read_file skips the deny rule (tool doesn't match), hits the allow
        let decision = engine.evaluate(&id, "read_file", &json!({}));
        assert_eq!(decision.effect, Effect::Allow);
        assert_eq!(decision.rule_id, "allow-all-tools");
    }

    // --- Priority ordering ---

    #[test]
    fn priority_ordering_first_match_wins() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "high-priority-deny"
priority = 1
effect = "deny"
identities = "*"
tools = ["dangerous_tool"]

[[rules]]
id = "medium-allow"
priority = 50
effect = "allow"
identities = "*"
tools = "*"

[[rules]]
id = "low-priority-deny"
priority = 200
effect = "deny"
identities = "*"
tools = ["safe_tool"]
"#,
        );
        let id = identity("user:x", &[]);

        // dangerous_tool matches the priority-1 deny
        let d = engine.evaluate(&id, "dangerous_tool", &json!({}));
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "high-priority-deny");

        // safe_tool matches the priority-50 allow (before the priority-200 deny)
        let d = engine.evaluate(&id, "safe_tool", &json!({}));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.rule_id, "medium-allow");

        // random_tool also matches the priority-50 allow
        let d = engine.evaluate(&id, "random_tool", &json!({}));
        assert_eq!(d.effect, Effect::Allow);
    }

    // --- Argument constraint: path globs ---

    #[test]
    fn arg_allow_glob_passes() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "write-tmp"
priority = 100
effect = "allow"
identities = "*"
tools = ["write_file"]
arguments = [
    { param = "path", allow_glob = ["/tmp/**", "/home/*/projects/**"] },
]
"#,
        );
        let id = identity("user:a", &[]);

        let d = engine.evaluate(&id, "write_file", &json!({"path": "/tmp/foo.txt"}));
        assert_eq!(d.effect, Effect::Allow);

        let d = engine.evaluate(
            &id,
            "write_file",
            &json!({"path": "/home/alice/projects/x/y.rs"}),
        );
        assert_eq!(d.effect, Effect::Allow);
    }

    #[test]
    fn arg_allow_glob_rejects_outside_path() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "write-tmp"
priority = 100
effect = "allow"
identities = "*"
tools = ["write_file"]
arguments = [
    { param = "path", allow_glob = ["/tmp/**"] },
]
"#,
        );
        let id = identity("user:a", &[]);

        // /etc/passwd does not match /tmp/** so the rule does not match,
        // and default deny kicks in
        let d = engine.evaluate(&id, "write_file", &json!({"path": "/etc/passwd"}));
        assert_eq!(d.effect, Effect::Deny);
    }

    // --- Argument constraint: deny_regex for secrets ---

    #[test]
    fn arg_deny_regex_blocks_aws_key() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "block-secrets"
priority = 1
effect = "deny"
identities = "*"
tools = "*"
arguments = [
    { param = "*", deny_regex = ["AKIA[A-Z0-9]{16}", "ghp_[a-zA-Z0-9]{36}"] },
]

[[rules]]
id = "allow-all"
priority = 100
effect = "allow"
identities = "*"
tools = "*"
"#,
        );
        let id = identity("user:a", &[]);

        // Contains an AWS key -- should match the deny rule
        let d = engine.evaluate(
            &id,
            "send_message",
            &json!({"text": "my key is AKIAIOSFODNN7EXAMPLE"}),
        );
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "block-secrets");

        // Contains a GitHub PAT
        let d = engine.evaluate(
            &id,
            "send_message",
            &json!({"content": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}),
        );
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "block-secrets");

        // Clean message passes through to allow-all
        let d = engine.evaluate(&id, "send_message", &json!({"text": "hello world"}));
        assert_eq!(d.effect, Effect::Allow);
    }

    #[test]
    fn arg_deny_regex_blocks_private_key() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "block-secrets"
priority = 1
effect = "deny"
identities = "*"
tools = "*"
arguments = [
    { param = "*", deny_regex = ["-----BEGIN.*PRIVATE KEY-----"] },
]

[[rules]]
id = "allow-all"
priority = 100
effect = "allow"
identities = "*"
tools = "*"
"#,
        );
        let id = identity("user:a", &[]);

        let d = engine.evaluate(
            &id,
            "write_file",
            &json!({"content": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}),
        );
        assert_eq!(d.effect, Effect::Deny);
    }

    // --- Identity label matching ---

    #[test]
    fn identity_label_matching_requires_all_labels() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "prod-infra"
priority = 100
effect = "allow"
identities = { labels = ["role:admin", "env:prod"] }
tools = "*"
"#,
        );

        // Has both labels
        let id = identity("user:a", &["role:admin", "env:prod"]);
        let d = engine.evaluate(&id, "anything", &json!({}));
        assert_eq!(d.effect, Effect::Allow);

        // Missing env:prod
        let id = identity("user:b", &["role:admin"]);
        let d = engine.evaluate(&id, "anything", &json!({}));
        assert_eq!(d.effect, Effect::Deny);

        // Has extra labels -- still OK
        let id = identity("user:c", &["role:admin", "env:prod", "team:sre"]);
        let d = engine.evaluate(&id, "anything", &json!({}));
        assert_eq!(d.effect, Effect::Allow);
    }

    #[test]
    fn identity_principal_matching() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "ci-bot"
priority = 100
effect = "allow"
identities = { principals = ["oauth:ci-bot@example.com"] }
tools = ["run_tests", "deploy_staging"]
"#,
        );

        let id = identity("oauth:ci-bot@example.com", &[]);
        let d = engine.evaluate(&id, "run_tests", &json!({}));
        assert_eq!(d.effect, Effect::Allow);

        let id = identity("oauth:hacker@evil.com", &[]);
        let d = engine.evaluate(&id, "run_tests", &json!({}));
        assert_eq!(d.effect, Effect::Deny);
    }

    // --- Wildcard tool matching ---

    #[test]
    fn wildcard_tool_matching_with_glob() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "allow-fs-read"
priority = 100
effect = "allow"
identities = "*"
tools = ["filesystem_read*", "git_*"]
"#,
        );
        let id = identity("user:a", &[]);

        let d = engine.evaluate(&id, "filesystem_read", &json!({}));
        assert_eq!(d.effect, Effect::Allow);

        let d = engine.evaluate(&id, "filesystem_read_dir", &json!({}));
        assert_eq!(d.effect, Effect::Allow);

        let d = engine.evaluate(&id, "git_status", &json!({}));
        assert_eq!(d.effect, Effect::Allow);

        let d = engine.evaluate(&id, "git_push_force", &json!({}));
        assert_eq!(d.effect, Effect::Allow);

        // Does not match
        let d = engine.evaluate(&id, "filesystem_write", &json!({}));
        assert_eq!(d.effect, Effect::Deny);
    }

    // --- AuditOnly effect ---

    #[test]
    fn audit_only_is_allowed() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "audit-sensitive"
priority = 100
effect = "audit_only"
identities = "*"
tools = ["read_secret"]
"#,
        );
        let id = identity("user:a", &[]);
        let d = engine.evaluate(&id, "read_secret", &json!({}));
        assert_eq!(d.effect, Effect::AuditOnly);
        assert!(d.is_allowed());
    }

    // --- Max length constraint ---

    #[test]
    fn max_length_constraint() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "limited-input"
priority = 100
effect = "allow"
identities = "*"
tools = ["echo"]
arguments = [
    { param = "text", max_length = 10 },
]
"#,
        );
        let id = identity("user:a", &[]);

        let d = engine.evaluate(&id, "echo", &json!({"text": "short"}));
        assert_eq!(d.effect, Effect::Allow);

        let d = engine.evaluate(&id, "echo", &json!({"text": "this is way too long"}));
        assert_eq!(d.effect, Effect::Deny); // default deny, rule didn't match
    }

    // --- Combined allow_glob and deny_regex ---

    #[test]
    fn combined_allow_glob_and_deny_regex() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "write-safe-paths"
priority = 100
effect = "allow"
identities = "*"
tools = ["write_file"]
arguments = [
    { param = "path", allow_glob = ["/home/*/projects/**"], deny_regex = [".*\\.env$", ".*credentials.*"] },
]
"#,
        );
        let id = identity("user:a", &[]);

        // Good path
        let d = engine.evaluate(
            &id,
            "write_file",
            &json!({"path": "/home/alice/projects/app/main.rs"}),
        );
        assert_eq!(d.effect, Effect::Allow);

        // Path matches glob but also matches deny_regex
        let d = engine.evaluate(
            &id,
            "write_file",
            &json!({"path": "/home/alice/projects/.env"}),
        );
        assert_eq!(d.effect, Effect::Deny);

        let d = engine.evaluate(
            &id,
            "write_file",
            &json!({"path": "/home/alice/projects/credentials.json"}),
        );
        assert_eq!(d.effect, Effect::Deny);
    }

    // --- Edge case: rule with no arguments on a request that has args ---

    #[test]
    fn rule_without_arg_constraints_ignores_args() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "allow-all"
priority = 100
effect = "allow"
identities = "*"
tools = "*"
"#,
        );
        let id = identity("user:a", &[]);
        let d = engine.evaluate(
            &id,
            "write_file",
            &json!({"path": "/etc/shadow", "content": "AKIAIOSFODNN7EXAMPLE"}),
        );
        // No arg constraints on this rule, so it matches
        assert_eq!(d.effect, Effect::Allow);
    }

    // --- Comprehensive integration-like test mimicking the full mcpdome.toml ---

    #[test]
    fn full_policy_scenario() {
        let toml = r#"
[[rules]]
id = "block-secrets"
priority = 1
effect = "deny"
identities = "*"
tools = "*"
arguments = [
    { param = "*", deny_regex = ["AKIA[A-Z0-9]{16}", "ghp_[a-zA-Z0-9]{36}"] },
]

[[rules]]
id = "admin-full"
priority = 10
effect = "allow"
identities = { labels = ["role:admin"] }
tools = "*"

[[rules]]
id = "dev-no-destructive"
priority = 50
effect = "deny"
identities = { labels = ["role:developer"] }
tools = ["delete_file", "drop_table"]

[[rules]]
id = "dev-read"
priority = 100
effect = "allow"
identities = { labels = ["role:developer"] }
tools = ["read_file", "grep", "git_status"]

[[rules]]
id = "dev-write"
priority = 110
effect = "allow"
identities = { labels = ["role:developer"] }
tools = ["write_file"]
arguments = [
    { param = "path", allow_glob = ["/tmp/**", "/home/*/projects/**"] },
]
"#;
        let engine = engine_from_toml(toml);
        assert_eq!(engine.rule_count(), 5);

        let admin = identity("user:root", &["role:admin"]);
        let dev = identity("user:alice", &["role:developer"]);
        let nobody = identity("user:anon", &[]);

        // Admin can do anything (clean args)
        let d = engine.evaluate(&admin, "delete_file", &json!({"path": "/important"}));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.rule_id, "admin-full");

        // Admin blocked by secret detection (priority 1 > 10)
        let d = engine.evaluate(&admin, "send", &json!({"msg": "AKIAIOSFODNN7EXAMPLE"}));
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "block-secrets");

        // Dev can read
        let d = engine.evaluate(&dev, "read_file", &json!({"path": "/etc/hosts"}));
        assert_eq!(d.effect, Effect::Allow);

        // Dev cannot delete
        let d = engine.evaluate(&dev, "delete_file", &json!({}));
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "dev-no-destructive");

        // Dev can write to /tmp
        let d = engine.evaluate(&dev, "write_file", &json!({"path": "/tmp/output.txt"}));
        assert_eq!(d.effect, Effect::Allow);

        // Dev cannot write to /etc
        let d = engine.evaluate(&dev, "write_file", &json!({"path": "/etc/shadow"}));
        assert_eq!(d.effect, Effect::Deny);

        // Unknown user -- default deny
        let d = engine.evaluate(&nobody, "read_file", &json!({}));
        assert_eq!(d.effect, Effect::Deny);
    }

    // --- Recursive argument inspection ---

    #[test]
    fn deny_regex_catches_secret_in_nested_object() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "block-secrets"
priority = 1
effect = "deny"
identities = "*"
tools = "*"
arguments = [
    { param = "*", deny_regex = ["AKIA[A-Z0-9]{16}"] },
]

[[rules]]
id = "allow-all"
priority = 100
effect = "allow"
identities = "*"
tools = "*"
"#,
        );
        let id = identity("user:a", &[]);

        // Secret hidden inside a nested object
        let d = engine.evaluate(
            &id,
            "send_message",
            &json!({"data": {"nested": {"deep": "my key AKIAIOSFODNN7EXAMPLE"}}}),
        );
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "block-secrets");
    }

    #[test]
    fn deny_regex_catches_secret_in_array() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "block-secrets"
priority = 1
effect = "deny"
identities = "*"
tools = "*"
arguments = [
    { param = "*", deny_regex = ["AKIA[A-Z0-9]{16}"] },
]

[[rules]]
id = "allow-all"
priority = 100
effect = "allow"
identities = "*"
tools = "*"
"#,
        );
        let id = identity("user:a", &[]);

        // Secret hidden inside an array
        let d = engine.evaluate(
            &id,
            "send_message",
            &json!({"messages": ["hello", "AKIAIOSFODNN7EXAMPLE", "world"]}),
        );
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.rule_id, "block-secrets");
    }

    #[test]
    fn allow_rule_rejects_nested_deny_regex_match() {
        let engine = engine_from_toml(
            r#"
[[rules]]
id = "safe-write"
priority = 100
effect = "allow"
identities = "*"
tools = ["write_file"]
arguments = [
    { param = "content", deny_regex = ["-----BEGIN.*PRIVATE KEY-----"] },
]
"#,
        );
        let id = identity("user:a", &[]);

        // Private key hidden in nested structure
        let d = engine.evaluate(
            &id,
            "write_file",
            &json!({"content": {"parts": ["-----BEGIN RSA PRIVATE KEY-----\nMIIE..."]}}),
        );
        assert_eq!(d.effect, Effect::Deny); // default deny because allow rule didn't match
    }
}
