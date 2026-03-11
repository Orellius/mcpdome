use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Identity -- lightweight representation for policy evaluation.
// dome-core doesn't export an Identity type yet, so we define one here that
// the rest of the gateway can construct when handing off to the policy engine.
// ---------------------------------------------------------------------------

/// Caller identity as seen by the policy engine.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Principal identifier, e.g. "uid:501", "oauth:user@example.com".
    pub principal: String,
    /// Free-form labels that policy rules can match against,
    /// e.g. "role:admin", "team:infra", "env:prod".
    pub labels: HashSet<String>,
}

impl Identity {
    pub fn new(principal: impl Into<String>, labels: impl IntoIterator<Item = String>) -> Self {
        Self {
            principal: principal.into(),
            labels: labels.into_iter().collect(),
        }
    }

    /// Anonymous identity with no labels.
    pub fn anonymous() -> Self {
        Self {
            principal: "anonymous".to_string(),
            labels: HashSet::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rule types
// ---------------------------------------------------------------------------

/// What happens when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
    /// Allow, but flag the call for review in the audit log.
    AuditOnly,
}

/// How to match the caller identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IdentityMatcher {
    /// Wildcard -- matches any identity.
    Any(String), // expected value: "*"
    /// Structured matcher with optional principals and/or labels.
    Structured {
        #[serde(default)]
        principals: Vec<String>,
        #[serde(default)]
        labels: Vec<String>,
    },
}

impl IdentityMatcher {
    pub fn matches(&self, identity: &Identity) -> bool {
        match self {
            Self::Any(s) if s == "*" => true,
            Self::Any(_) => false,
            Self::Structured {
                principals,
                labels,
            } => {
                let principal_ok =
                    principals.is_empty() || principals.iter().any(|p| p == &identity.principal);

                let labels_ok = labels.is_empty()
                    || labels.iter().all(|l| identity.labels.contains(l));

                principal_ok && labels_ok
            }
        }
    }
}

/// How to match the tool being invoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolMatcher {
    /// Wildcard -- matches any tool.
    Wildcard(String), // expected value: "*"
    /// Exact list of tool names (or glob patterns).
    List(Vec<String>),
}

impl ToolMatcher {
    pub fn matches(&self, tool: &str) -> bool {
        match self {
            Self::Wildcard(s) if s == "*" => true,
            Self::Wildcard(_) => false,
            Self::List(patterns) => patterns.iter().any(|p| {
                if p.contains('*') || p.contains('?') || p.contains('[') {
                    glob_match::glob_match(p, tool)
                } else {
                    p == tool
                }
            }),
        }
    }
}

/// Constraint on a single tool argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgConstraint {
    /// JSON key name in the tool's arguments object, or "*" for all string args.
    pub param: String,
    /// If set, the argument value must match at least one of these glob patterns.
    #[serde(default)]
    pub allow_glob: Option<Vec<String>>,
    /// If set, the argument value must NOT match any of these regexes.
    #[serde(default)]
    pub deny_regex: Option<Vec<String>>,
    /// Maximum allowed string length.
    #[serde(default)]
    pub max_length: Option<usize>,
}

/// Per-rule rate limit override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max: u64,
    pub window: String,
}

/// A single authorization rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub priority: u32,
    pub effect: Effect,
    pub identities: IdentityMatcher,
    pub tools: ToolMatcher,
    #[serde(default)]
    pub arguments: Vec<ArgConstraint>,
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
}

// ---------------------------------------------------------------------------
// Decision -- the output of policy evaluation
// ---------------------------------------------------------------------------

/// The result of evaluating a request against the policy rule set.
#[derive(Debug, Clone)]
pub struct Decision {
    pub effect: Effect,
    pub rule_id: String,
    pub reason: String,
}

impl Decision {
    /// The implicit decision when no rule matches: deny.
    pub fn default_deny() -> Self {
        Self {
            effect: Effect::Deny,
            rule_id: "__default_deny".to_string(),
            reason: "no matching rule (default deny)".to_string(),
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self.effect, Effect::Allow | Effect::AuditOnly)
    }
}
