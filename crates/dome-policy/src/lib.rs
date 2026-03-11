//! `dome-policy` -- TOML-based policy engine for MCPDome.
//!
//! This crate provides:
//! - Policy TOML parsing and validation (`parser`)
//! - Authorization types: Rule, Effect, Decision, matchers (`types`)
//! - The core PolicyEngine that evaluates requests against rules (`evaluator`)
//!
//! The engine is **default-deny**: if no rule matches a request, it is denied.
//! Rules are evaluated in priority order (lowest number = highest priority).
//! First matching rule wins.

pub mod evaluator;
pub mod parser;
pub mod types;

// Re-exports for convenience.
pub use evaluator::{PolicyBuildError, PolicyEngine};
pub use parser::{PolicyParseError, parse_policy};
pub use types::{
    ArgConstraint, Decision, Effect, Identity, IdentityMatcher, RateLimit, Rule, ToolMatcher,
};
