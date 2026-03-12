use std::collections::HashSet;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use dome_gate::{Gate, GateConfig};
use dome_ledger::{AuditEntry, Ledger, StderrSink};
use dome_policy::{PolicyEngine, PolicyWatcher, SharedPolicyEngine, parse_policy};
use dome_sentinel::{AnonymousAuthenticator, PskAuthenticator, PskEntry};
use dome_throttle::{BudgetTrackerConfig, RateLimiterConfig};
#[cfg(test)]
use dome_ward::SchemaPinStore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::info;
use tracing_subscriber::EnvFilter;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "mcpdome",
    about = "Protective Dome for AI Agents -- MCP security gateway proxy",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the security proxy
    Proxy {
        /// The MCP server command to wrap (e.g. "npx -y @modelcontextprotocol/server-filesystem /tmp")
        #[arg(long)]
        upstream: String,

        /// Path to the MCPDome configuration file (TOML)
        #[arg(long, default_value = "./mcpdome.toml")]
        config: String,

        /// Log level (off, error, warn, info, debug, trace)
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Enable policy enforcement
        #[arg(long, default_value_t = false)]
        enforce_policy: bool,

        /// Enable injection detection (ward)
        #[arg(long, default_value_t = false)]
        enable_ward: bool,

        /// Enable schema pinning
        #[arg(long, default_value_t = false)]
        enable_schema_pin: bool,

        /// Enable rate limiting
        #[arg(long, default_value_t = false)]
        enable_rate_limit: bool,
    },

    /// Validate a policy TOML file without starting the proxy
    Validate {
        /// Path to the policy TOML file
        #[arg(value_name = "POLICY_FILE")]
        path: PathBuf,
    },

    /// Verify audit log hash chain integrity
    VerifyLog {
        /// Path to the NDJSON audit log file
        #[arg(value_name = "AUDIT_FILE")]
        path: PathBuf,
    },

    /// Compute SHA-256 schema pin hashes for tools in a tools/list response
    HashSchema {
        /// Path to a JSON file containing a tools/list response
        #[arg(value_name = "TOOLS_JSON")]
        path: PathBuf,
    },

    /// Generate a cryptographically random pre-shared key
    Keygen,
}

// ---------------------------------------------------------------------------
// Unified config file structures
// ---------------------------------------------------------------------------

/// Top-level structure of the mcpdome.toml config file.
#[derive(Debug, Deserialize)]
struct McpDomeConfig {
    #[serde(default)]
    mcpdome: Option<McpDomeSection>,
    #[serde(default)]
    rules: Vec<dome_policy::Rule>,
    #[serde(default)]
    psk: Vec<PskConfigEntry>,
}

#[derive(Debug, Deserialize)]
struct McpDomeSection {
    #[serde(default = "default_version")]
    #[allow(dead_code)]
    version: String,
    #[serde(default = "default_effect")]
    #[allow(dead_code)]
    default_effect: String,
    #[serde(default)]
    log_level: Option<String>,
    #[serde(default)]
    auth: Option<AuthConfig>,
    #[serde(default)]
    rate_limit: Option<RateLimitGlobalConfig>,
    #[serde(default)]
    ward: Option<WardConfig>,
}

#[derive(Debug, Deserialize)]
struct AuthConfig {
    #[serde(default)]
    allow_anonymous: bool,
}

#[derive(Debug, Deserialize)]
struct RateLimitGlobalConfig {
    #[serde(default)]
    global_rps: Option<f64>,
    #[serde(default)]
    per_identity_rps: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct WardConfig {
    #[serde(default)]
    enable_injection_scan: bool,
    #[serde(default)]
    enable_schema_pin: bool,
}

#[derive(Debug, Deserialize)]
struct PskConfigEntry {
    key_id: String,
    secret: String,
    #[serde(default)]
    labels: Vec<String>,
}

fn default_version() -> String {
    "1".to_string()
}

fn default_effect() -> String {
    "deny".to_string()
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

/// Validate a policy TOML file. Returns a summary on success, or an error message.
fn run_validate(path: &PathBuf) -> Result<ValidateSummary, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;

    validate_policy_content(&content)
}

/// Core validation logic operating on the TOML string (testable without filesystem).
fn validate_policy_content(content: &str) -> Result<ValidateSummary, String> {
    // Step 1: Parse TOML syntax and rule structure.
    let rules = parse_policy(content).map_err(|e| format!("policy validation failed: {e}"))?;

    // Step 2: Build the policy engine (compiles regexes, validates globs).
    PolicyEngine::new(rules.clone()).map_err(|e| format!("policy build failed: {e}"))?;

    // Step 3: Collect summary statistics.
    let mut identities = HashSet::new();
    let mut tools = HashSet::new();

    for rule in &rules {
        match &rule.identities {
            dome_policy::IdentityMatcher::Any(s) => {
                identities.insert(s.clone());
            }
            dome_policy::IdentityMatcher::Structured {
                principals, labels, ..
            } => {
                for p in principals {
                    identities.insert(p.clone());
                }
                for l in labels {
                    identities.insert(l.clone());
                }
            }
        }

        match &rule.tools {
            dome_policy::ToolMatcher::Wildcard(s) => {
                tools.insert(s.clone());
            }
            dome_policy::ToolMatcher::List(list) => {
                for t in list {
                    tools.insert(t.clone());
                }
            }
        }
    }

    Ok(ValidateSummary {
        rule_count: rules.len(),
        identity_count: identities.len(),
        tool_count: tools.len(),
    })
}

#[derive(Debug)]
struct ValidateSummary {
    rule_count: usize,
    identity_count: usize,
    tool_count: usize,
}

/// Verify audit log hash chain integrity.
fn run_verify_log(path: &PathBuf) -> Result<VerifyLogResult, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;

    verify_log_content(&content)
}

/// Core verification logic operating on the NDJSON string (testable without filesystem).
fn verify_log_content(content: &str) -> Result<VerifyLogResult, String> {
    let mut entries: Vec<AuditEntry> = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(trimmed)
            .map_err(|e| format!("line {}: invalid JSON: {e}", line_num + 1))?;
        entries.push(entry);
    }

    let total_entries = entries.len();

    match dome_ledger::verify_chain(&entries) {
        Ok(()) => Ok(VerifyLogResult {
            total_entries,
            chain_intact: true,
            error_detail: None,
        }),
        Err(e) => Ok(VerifyLogResult {
            total_entries,
            chain_intact: false,
            error_detail: Some(e.to_string()),
        }),
    }
}

#[derive(Debug)]
struct VerifyLogResult {
    total_entries: usize,
    chain_intact: bool,
    error_detail: Option<String>,
}

/// Compute schema pin hashes for each tool in a tools/list JSON file.
fn run_hash_schema(path: &PathBuf) -> Result<Vec<ToolHash>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;

    hash_schema_content(&content)
}

/// Core hash-schema logic operating on the JSON string (testable without filesystem).
fn hash_schema_content(content: &str) -> Result<Vec<ToolHash>, String> {
    let value: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("invalid JSON: {e}"))?;

    // Accept either a raw {"tools": [...]} or a JSON-RPC response with
    // {"result": {"tools": [...]}}.
    let tools_container = if value.get("tools").is_some() {
        &value
    } else if let Some(result) = value.get("result") {
        if result.get("tools").is_some() {
            result
        } else {
            return Err(
                "JSON does not contain a 'tools' array (checked top-level and result.tools)"
                    .to_string(),
            );
        }
    } else {
        return Err(
            "JSON does not contain a 'tools' array (checked top-level and result.tools)"
                .to_string(),
        );
    };

    let tools = tools_container
        .get("tools")
        .and_then(|t| t.as_array())
        .ok_or_else(|| "'tools' field is not an array".to_string())?;

    let mut results = Vec::new();

    for tool in tools {
        let name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>");

        // Use dome-ward's canonical hashing for individual fields.
        let description_hash = dome_ward::hash_field(tool.get("description"));
        let schema_hash = dome_ward::hash_field(tool.get("inputSchema"));

        // Combined pin hash: SHA-256(name || description_hash || schema_hash).
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.update(description_hash);
        hasher.update(schema_hash);
        let combined = hasher.finalize();

        results.push(ToolHash {
            name: name.to_string(),
            pin_hash: hex_encode(&combined),
            description_hash: hex_encode(&description_hash),
            schema_hash: hex_encode(&schema_hash),
        });
    }

    Ok(results)
}

#[derive(Debug)]
struct ToolHash {
    name: String,
    pin_hash: String,
    description_hash: String,
    schema_hash: String,
}

/// Generate a cryptographically random pre-shared key.
fn run_keygen() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let hex = hex_encode(&bytes);

    format!(
        "# MCPDome Pre-Shared Key (generated)\n\
         # Base64 (URL-safe, 32 bytes):\n\
         {b64}\n\n\
         # Hex (64 chars):\n\
         {hex}"
    )
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Proxy {
            upstream,
            config,
            log_level,
            enforce_policy,
            enable_ward,
            enable_schema_pin,
            enable_rate_limit,
        } => {
            // Attempt to load the unified config file.
            let config_path = std::path::Path::new(&config);
            let loaded_config = if config_path.exists() {
                let raw = std::fs::read_to_string(config_path)?;
                Some(
                    toml::from_str::<McpDomeConfig>(&raw)
                        .map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?,
                )
            } else {
                None
            };

            // Merge config file settings with CLI flags. CLI flags act as
            // overrides when they are explicitly set to true.
            let section = loaded_config.as_ref().and_then(|c| c.mcpdome.as_ref());

            let effective_log_level = section
                .and_then(|s| s.log_level.clone())
                .unwrap_or(log_level);

            let allow_anonymous = section
                .and_then(|s| s.auth.as_ref())
                .is_none_or(|a| a.allow_anonymous);

            let ward_cfg = section.and_then(|s| s.ward.as_ref());

            let has_rules = loaded_config.as_ref().is_some_and(|c| !c.rules.is_empty());

            let gate_config = GateConfig {
                enforce_policy: enforce_policy || has_rules,
                enable_ward: enable_ward || ward_cfg.is_some_and(|w| w.enable_injection_scan),
                enable_schema_pin: enable_schema_pin
                    || ward_cfg.is_some_and(|w| w.enable_schema_pin),
                enable_rate_limit: enable_rate_limit
                    || section.and_then(|s| s.rate_limit.as_ref()).is_some(),
                enable_budget: false,
                allow_anonymous,
            };

            // Build rate limiter config.
            let rl_config = if let Some(rl) = section.and_then(|s| s.rate_limit.as_ref()) {
                let per_id = rl.per_identity_rps.unwrap_or(100.0);
                let global = rl.global_rps.unwrap_or(1000.0);
                RateLimiterConfig {
                    per_identity_max: per_id,
                    per_identity_rate: per_id,
                    global_limit: Some((global, global)),
                    ..RateLimiterConfig::default()
                }
            } else {
                RateLimiterConfig::default()
            };

            // Build authenticators from config PSK entries + anonymous fallback.
            let mut authenticators: Vec<Box<dyn dome_sentinel::Authenticator>> = Vec::new();
            if let Some(ref cfg) = loaded_config
                && !cfg.psk.is_empty()
            {
                let entries: Vec<PskEntry> = cfg
                    .psk
                    .iter()
                    .map(|p| PskEntry {
                        key_id: p.key_id.clone(),
                        secret: p.secret.clone(),
                        labels: p.labels.iter().cloned().collect(),
                    })
                    .collect();
                authenticators.push(Box::new(PskAuthenticator::new(entries)));
            }
            authenticators.push(Box::new(AnonymousAuthenticator));

            // Initialize tracing.
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| EnvFilter::new(&effective_log_level)),
                )
                .with_target(false)
                .with_writer(std::io::stderr)
                .init();

            info!(upstream = upstream.as_str(), "MCPDome starting");

            let parts: Vec<&str> = upstream.split_whitespace().collect();
            if parts.is_empty() {
                anyhow::bail!("--upstream cannot be empty");
            }

            let command = parts[0];
            let args = &parts[1..];

            // Load policy engine with hot-reload if enforcement is enabled.
            let policy_engine: Option<SharedPolicyEngine> =
                if gate_config.enforce_policy && config_path.exists() {
                    let (watcher, shared_engine) = PolicyWatcher::new(config_path).await?;
                    tokio::spawn(watcher.run());
                    Some(shared_engine)
                } else if gate_config.enforce_policy {
                    // No config file. Default-deny engine (empty rules).
                    info!(
                        path = %config_path.display(),
                        "policy file not found -- using default-deny (no rules)"
                    );
                    let engine = PolicyEngine::new(vec![])?;
                    Some(Arc::new(ArcSwap::from_pointee(engine)))
                } else {
                    None
                };

            let ledger = Ledger::new(vec![Box::new(StderrSink::new())]);

            let gate = Gate::new(
                gate_config,
                authenticators,
                policy_engine,
                rl_config,
                BudgetTrackerConfig::default(),
                ledger,
            );

            gate.run_stdio(command, args).await?;
        }

        Commands::Validate { path } => match run_validate(&path) {
            Ok(summary) => {
                println!("Policy is valid: {}", path.display());
                println!("  Rules:      {}", summary.rule_count);
                println!("  Identities: {}", summary.identity_count);
                println!("  Tools:      {}", summary.tool_count);
            }
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        },

        Commands::VerifyLog { path } => match run_verify_log(&path) {
            Ok(result) => {
                println!("Audit log: {}", path.display());
                println!("  Total entries: {}", result.total_entries);
                if result.chain_intact {
                    println!("  Chain status:  INTACT");
                } else {
                    println!("  Chain status:  BROKEN");
                    if let Some(detail) = &result.error_detail {
                        println!("  First error:   {detail}");
                    }
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        },

        Commands::HashSchema { path } => match run_hash_schema(&path) {
            Ok(hashes) => {
                if hashes.is_empty() {
                    println!("No tools found in {}", path.display());
                } else {
                    println!("Schema pin hashes for {}:", path.display());
                    println!();
                    for h in &hashes {
                        println!("  Tool: {}", h.name);
                        println!("    Pin hash:         {}", h.pin_hash);
                        println!("    Description hash: {}", h.description_hash);
                        println!("    Schema hash:      {}", h.schema_hash);
                        println!();
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        },

        Commands::Keygen => {
            println!("{}", run_keygen());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- validate tests ----

    #[test]
    fn validate_valid_policy() {
        let toml = r#"
[[rules]]
id = "allow-all"
priority = 100
effect = "allow"
identities = "*"
tools = "*"
"#;
        let result = validate_policy_content(toml);
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert_eq!(summary.rule_count, 1);
        assert_eq!(summary.identity_count, 1); // "*"
        assert_eq!(summary.tool_count, 1); // "*"
    }

    #[test]
    fn validate_complex_policy() {
        let toml = r#"
[mcpdome]
version = "1"
default_effect = "deny"

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
id = "dev-read"
priority = 100
effect = "allow"
identities = { labels = ["role:developer"] }
tools = ["read_file", "grep"]
"#;
        let result = validate_policy_content(toml);
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert_eq!(summary.rule_count, 3);
    }

    #[test]
    fn validate_invalid_toml_syntax() {
        let bad = r#"
[[rules]]
id = "broken
"#;
        let result = validate_policy_content(bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TOML parse error"));
    }

    #[test]
    fn validate_duplicate_rule_ids() {
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
        let result = validate_policy_content(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate rule id"));
    }

    #[test]
    fn validate_invalid_regex() {
        let toml = r#"
[[rules]]
id = "bad-regex"
priority = 1
effect = "deny"
identities = "*"
tools = "*"
arguments = [
    { param = "*", deny_regex = ["[invalid(regex"] },
]
"#;
        let result = validate_policy_content(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("policy build failed"));
    }

    #[test]
    fn validate_empty_rules() {
        let toml = r#"
[mcpdome]
version = "1"
"#;
        let result = validate_policy_content(toml);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().rule_count, 0);
    }

    // ---- verify-log tests ----

    #[test]
    fn verify_log_intact_chain() {
        let mut chain = dome_ledger::HashChain::new();
        let mut ndjson_lines = Vec::new();

        for i in 0..3u64 {
            let mut entry = sample_audit_entry();
            entry.seq = i;
            entry.prev_hash = chain.current_hash().to_string();
            chain.append(&entry).unwrap();
            ndjson_lines.push(serde_json::to_string(&entry).unwrap());
        }

        let content = ndjson_lines.join("\n");
        let result = verify_log_content(&content).unwrap();
        assert_eq!(result.total_entries, 3);
        assert!(result.chain_intact);
        assert!(result.error_detail.is_none());
    }

    #[test]
    fn verify_log_broken_chain() {
        let mut chain = dome_ledger::HashChain::new();
        let mut entries = Vec::new();

        for i in 0..3u64 {
            let mut entry = sample_audit_entry();
            entry.seq = i;
            entry.prev_hash = chain.current_hash().to_string();
            chain.append(&entry).unwrap();
            entries.push(entry);
        }

        // Tamper with the middle entry.
        entries[1].decision = "deny:tampered".to_string();

        let content: String = entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        let result = verify_log_content(&content).unwrap();
        assert_eq!(result.total_entries, 3);
        assert!(!result.chain_intact);
        assert!(result.error_detail.is_some());
    }

    #[test]
    fn verify_log_empty_file() {
        let result = verify_log_content("").unwrap();
        assert_eq!(result.total_entries, 0);
        assert!(result.chain_intact);
    }

    #[test]
    fn verify_log_invalid_json() {
        let result = verify_log_content("not json at all");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid JSON"));
    }

    // ---- hash-schema tests ----

    #[test]
    fn hash_schema_basic() {
        let json = r#"{
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read the contents of a file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" }
                        },
                        "required": ["path"]
                    }
                }
            ]
        }"#;

        let result = hash_schema_content(json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "read_file");
        assert_eq!(result[0].pin_hash.len(), 64);
        assert_eq!(result[0].description_hash.len(), 64);
        assert_eq!(result[0].schema_hash.len(), 64);
    }

    #[test]
    fn hash_schema_deterministic() {
        let json = r#"{
            "tools": [
                {
                    "name": "my_tool",
                    "description": "A tool",
                    "inputSchema": { "type": "object" }
                }
            ]
        }"#;

        let r1 = hash_schema_content(json).unwrap();
        let r2 = hash_schema_content(json).unwrap();
        assert_eq!(r1[0].pin_hash, r2[0].pin_hash);
    }

    #[test]
    fn hash_schema_multiple_tools() {
        let json = r#"{
            "tools": [
                { "name": "tool_a", "description": "A" },
                { "name": "tool_b", "description": "B", "inputSchema": { "type": "object" } }
            ]
        }"#;

        let result = hash_schema_content(json).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "tool_a");
        assert_eq!(result[1].name, "tool_b");
        assert_ne!(result[0].pin_hash, result[1].pin_hash);
    }

    #[test]
    fn hash_schema_accepts_jsonrpc_response() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    { "name": "wrapped_tool", "description": "Inside a JSON-RPC response" }
                ]
            }
        }"#;

        let result = hash_schema_content(json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "wrapped_tool");
    }

    #[test]
    fn hash_schema_no_tools_key() {
        let json = r#"{ "something_else": true }"#;
        let result = hash_schema_content(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tools"));
    }

    #[test]
    fn hash_schema_invalid_json() {
        let result = hash_schema_content("not json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid JSON"));
    }

    #[test]
    fn hash_schema_consistent_with_schema_pin_store() {
        let json_str = r#"{
            "tools": [
                {
                    "name": "test_tool",
                    "description": "Test description",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "arg": { "type": "string" } }
                    }
                }
            ]
        }"#;

        let value: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let mut store = SchemaPinStore::new();
        store.pin_tools(&value);
        let pin = store.get_pin("test_tool").unwrap();

        let hashes = hash_schema_content(json_str).unwrap();
        assert_eq!(
            hashes[0].description_hash,
            hex_encode(&pin.description_hash)
        );
        assert_eq!(hashes[0].schema_hash, hex_encode(&pin.schema_hash));
    }

    // ---- keygen tests ----

    #[test]
    fn keygen_produces_output() {
        let output = run_keygen();
        assert!(output.contains("Base64"));
        assert!(output.contains("Hex"));
        // Hex line should be 64 chars (32 bytes).
        let lines: Vec<&str> = output.lines().collect();
        let hex_line = lines.iter().find(|l| !l.starts_with('#') && l.len() == 64);
        assert!(hex_line.is_some(), "should contain a 64-char hex line");
    }

    #[test]
    fn keygen_is_random() {
        let output1 = run_keygen();
        let output2 = run_keygen();
        assert_ne!(output1, output2);
    }

    // ---- Helper ----

    fn sample_audit_entry() -> AuditEntry {
        AuditEntry {
            seq: 0,
            timestamp: chrono::Utc::now(),
            request_id: uuid::Uuid::new_v4(),
            identity: "uid:501".to_string(),
            direction: dome_ledger::Direction::Inbound,
            method: "tools/call".to_string(),
            tool: Some("read_file".to_string()),
            decision: "allow".to_string(),
            rule_id: Some("r1".to_string()),
            latency_us: 100,
            prev_hash: String::new(),
            annotations: std::collections::HashMap::new(),
        }
    }
}
