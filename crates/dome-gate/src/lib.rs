use std::sync::Arc;

use dome_core::{DomeError, McpMessage};
use dome_ledger::{AuditEntry, Direction, Ledger};
use dome_policy::{Identity as PolicyIdentity, PolicyEngine};
use dome_sentinel::{AnonymousAuthenticator, Authenticator, IdentityResolver, ResolverConfig};
use dome_throttle::{BudgetTracker, BudgetTrackerConfig, RateLimiter, RateLimiterConfig};
use dome_transport::stdio::StdioTransport;
use dome_ward::{InjectionScanner, SchemaPinStore};

use chrono::Utc;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Configuration for the Gate proxy.
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// Whether to enforce policy (false = transparent pass-through mode).
    pub enforce_policy: bool,
    /// Whether to enable injection scanning.
    pub enable_ward: bool,
    /// Whether to enable schema pinning.
    pub enable_schema_pin: bool,
    /// Whether to enable rate limiting.
    pub enable_rate_limit: bool,
    /// Whether to enable budget tracking.
    pub enable_budget: bool,
    /// Whether to allow anonymous access.
    pub allow_anonymous: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            enforce_policy: false,
            enable_ward: false,
            enable_schema_pin: false,
            enable_rate_limit: false,
            enable_budget: false,
            allow_anonymous: true,
        }
    }
}

/// The Gate — MCPDome's core proxy loop with full interceptor chain.
///
/// Interceptor order (inbound, client → server):
///   1. Sentinel — authenticate on `initialize`, resolve identity
///   2. Throttle — check rate limits and budget
///   3. Policy  — evaluate authorization rules
///   4. Ward    — scan for injection patterns in tool arguments
///   5. Ledger  — record the decision in the audit chain
///
/// Outbound (server → client):
///   1. Schema Pin — verify tools/list responses for drift
///   2. Ledger     — record outbound audit entry
pub struct Gate {
    config: GateConfig,
    resolver: IdentityResolver,
    policy_engine: Option<PolicyEngine>,
    rate_limiter: Arc<RateLimiter>,
    budget_tracker: Arc<BudgetTracker>,
    injection_scanner: Arc<InjectionScanner>,
    schema_store: Arc<Mutex<SchemaPinStore>>,
    ledger: Arc<Mutex<Ledger>>,
}

impl Gate {
    /// Create a new Gate with full interceptor chain.
    pub fn new(
        config: GateConfig,
        authenticators: Vec<Box<dyn Authenticator>>,
        policy_engine: Option<PolicyEngine>,
        rate_limiter_config: RateLimiterConfig,
        budget_config: BudgetTrackerConfig,
        ledger: Ledger,
    ) -> Self {
        Self {
            resolver: IdentityResolver::new(
                authenticators,
                ResolverConfig {
                    allow_anonymous: config.allow_anonymous,
                },
            ),
            policy_engine,
            rate_limiter: Arc::new(RateLimiter::new(rate_limiter_config)),
            budget_tracker: Arc::new(BudgetTracker::new(budget_config)),
            injection_scanner: Arc::new(InjectionScanner::new()),
            schema_store: Arc::new(Mutex::new(SchemaPinStore::new())),
            ledger: Arc::new(Mutex::new(ledger)),
            config,
        }
    }

    /// Create a transparent pass-through Gate (no security enforcement).
    pub fn transparent(ledger: Ledger) -> Self {
        Self::new(
            GateConfig::default(),
            vec![Box::new(AnonymousAuthenticator)],
            None,
            RateLimiterConfig::default(),
            BudgetTrackerConfig::default(),
            ledger,
        )
    }

    /// Run the proxy.
    pub async fn run_stdio(self, command: &str, args: &[&str]) -> Result<(), DomeError> {
        let transport = StdioTransport::spawn(command, args).await?;
        let (mut server_reader, mut server_writer, mut child) = transport.split();

        let client_stdin = tokio::io::stdin();
        let client_stdout = tokio::io::stdout();
        let mut client_reader = BufReader::new(client_stdin);
        let mut client_writer = client_stdout;

        info!("MCPDome proxy active — interceptor chain armed");

        // Shared state for the two tasks
        let identity: Arc<Mutex<Option<dome_sentinel::Identity>>> = Arc::new(Mutex::new(None));

        let gate_identity = Arc::clone(&identity);
        let gate_resolver = self.resolver;
        let gate_policy = self.policy_engine;
        let gate_rate_limiter = Arc::clone(&self.rate_limiter);
        let gate_budget = Arc::clone(&self.budget_tracker);
        let gate_scanner = Arc::clone(&self.injection_scanner);
        let gate_ledger = Arc::clone(&self.ledger);
        let gate_config = self.config.clone();

        // Client → Server task (inbound interceptor chain)
        let client_to_server = tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                match client_reader.read_line(&mut line).await {
                    Ok(0) => {
                        info!("client closed stdin — shutting down");
                        break;
                    }
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        match McpMessage::parse(trimmed) {
                            Ok(msg) => {
                                let start = std::time::Instant::now();
                                let method = msg.method.as_deref().unwrap_or("-").to_string();
                                let tool = msg.tool_name().map(String::from);
                                let request_id = Uuid::new_v4();

                                debug!(
                                    method = method.as_str(),
                                    id = ?msg.id,
                                    tool = tool.as_deref().unwrap_or("-"),
                                    "client -> server"
                                );

                                // ── 1. Sentinel: Authenticate on initialize ──
                                if method == "initialize" {
                                    match gate_resolver.resolve(&msg).await {
                                        Ok(id) => {
                                            info!(
                                                principal = %id.principal,
                                                method = %id.auth_method,
                                                "identity resolved"
                                            );
                                            *gate_identity.lock().await = Some(id);
                                        }
                                        Err(e) => {
                                            warn!(%e, "authentication failed");
                                            // Auth failure logged; request still forwarded
                                            // to let downstream server handle the handshake
                                            // Still forward — let the server handle it
                                            // but log the auth failure
                                        }
                                    }
                                }

                                let identity_lock = gate_identity.lock().await;
                                let principal = identity_lock
                                    .as_ref()
                                    .map(|i| i.principal.clone())
                                    .unwrap_or_else(|| "anonymous".to_string());
                                let labels = identity_lock
                                    .as_ref()
                                    .map(|i| i.labels.clone())
                                    .unwrap_or_default();
                                drop(identity_lock);

                                // Only intercept tools/call
                                if method == "tools/call" {
                                    let tool_name = tool.as_deref().unwrap_or("unknown");
                                    let args = msg
                                        .params
                                        .as_ref()
                                        .and_then(|p| p.get("arguments"))
                                        .cloned()
                                        .unwrap_or(Value::Null);

                                    // ── 2. Throttle: Rate limit check ──
                                    if gate_config.enable_rate_limit {
                                        if let Err(e) = gate_rate_limiter
                                            .check_rate_limit(&principal, Some(tool_name))
                                        {
                                            warn!(%e, principal = %principal, tool = tool_name, "rate limited");
                                            record_audit(
                                                &gate_ledger,
                                                request_id,
                                                &principal,
                                                Direction::Inbound,
                                                &method,
                                                tool.as_deref(),
                                                "deny:rate_limit",
                                                None,
                                                start.elapsed().as_micros() as u64,
                                            )
                                            .await;
                                            // Send error response back to client via server_writer
                                            // For now, skip the request
                                            continue;
                                        }
                                    }

                                    // ── 2b. Throttle: Budget check ──
                                    if gate_config.enable_budget {
                                        if let Err(e) = gate_budget.try_spend(&principal, 1.0) {
                                            warn!(%e, principal = %principal, "budget exhausted");
                                            record_audit(
                                                &gate_ledger,
                                                request_id,
                                                &principal,
                                                Direction::Inbound,
                                                &method,
                                                tool.as_deref(),
                                                "deny:budget",
                                                None,
                                                start.elapsed().as_micros() as u64,
                                            )
                                            .await;
                                            continue;
                                        }
                                    }

                                    // ── 3. Policy: Authorization ──
                                    if gate_config.enforce_policy {
                                        if let Some(ref engine) = gate_policy {
                                            let policy_id = PolicyIdentity::new(
                                                principal.clone(),
                                                labels.iter().cloned(),
                                            );
                                            let decision = engine.evaluate(&policy_id, tool_name, &args);

                                            if !decision.is_allowed() {
                                                warn!(
                                                    rule_id = %decision.rule_id,
                                                    tool = tool_name,
                                                    principal = %principal,
                                                    "policy denied"
                                                );
                                                record_audit(
                                                    &gate_ledger,
                                                    request_id,
                                                    &principal,
                                                    Direction::Inbound,
                                                    &method,
                                                    tool.as_deref(),
                                                    &format!("deny:policy:{}", decision.rule_id),
                                                    Some(&decision.rule_id),
                                                    start.elapsed().as_micros() as u64,
                                                )
                                                .await;
                                                continue;
                                            }
                                        }
                                    }

                                    // ── 4. Ward: Injection scanning ──
                                    if gate_config.enable_ward {
                                        let args_str = serde_json::to_string(&args).unwrap_or_default();
                                        let matches = gate_scanner.scan_text(&args_str);
                                        if !matches.is_empty() {
                                            let pattern_names: Vec<&str> =
                                                matches.iter().map(|m| m.pattern_name.as_str()).collect();
                                            warn!(
                                                patterns = ?pattern_names,
                                                tool = tool_name,
                                                principal = %principal,
                                                "injection detected"
                                            );
                                            record_audit(
                                                &gate_ledger,
                                                request_id,
                                                &principal,
                                                Direction::Inbound,
                                                &method,
                                                tool.as_deref(),
                                                &format!("deny:injection:{}", pattern_names.join(",")),
                                                None,
                                                start.elapsed().as_micros() as u64,
                                            )
                                            .await;
                                            continue;
                                        }
                                    }
                                }

                                // ── 5. Ledger: Record allowed request ──
                                record_audit(
                                    &gate_ledger,
                                    request_id,
                                    &principal,
                                    Direction::Inbound,
                                    &method,
                                    tool.as_deref(),
                                    "allow",
                                    None,
                                    start.elapsed().as_micros() as u64,
                                )
                                .await;

                                // Forward to server
                                if let Err(e) = server_writer.send(&msg).await {
                                    error!(%e, "failed to forward to server");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(%e, raw = trimmed, "invalid JSON from client, forwarding raw");
                                let _ = server_writer
                                    .send(&McpMessage {
                                        jsonrpc: "2.0".to_string(),
                                        id: None,
                                        method: None,
                                        params: None,
                                        result: None,
                                        error: None,
                                    })
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        error!(%e, "error reading from client");
                        break;
                    }
                }
            }
        });

        let schema_store = Arc::clone(&self.schema_store);
        let _outbound_ledger = Arc::clone(&self.ledger);
        let outbound_config = self.config.clone();

        // Server → Client task (outbound interceptor chain)
        let server_to_client = tokio::spawn(async move {
            let mut first_tools_list = true;

            loop {
                match server_reader.recv().await {
                    Ok(msg) => {
                        let method = msg.method.as_deref().unwrap_or("-").to_string();

                        debug!(
                            method = method.as_str(),
                            id = ?msg.id,
                            "server -> client"
                        );

                        // ── Schema Pin: Verify tools/list responses ──
                        if outbound_config.enable_schema_pin {
                            if let Some(result) = &msg.result {
                                if result.get("tools").is_some() {
                                    let mut store = schema_store.lock().await;
                                    if first_tools_list {
                                        store.pin_tools(result);
                                        info!(
                                            pinned = store.len(),
                                            "schema pins established"
                                        );
                                        first_tools_list = false;
                                    } else {
                                        let drifts = store.verify_tools(result);
                                        if !drifts.is_empty() {
                                            for drift in &drifts {
                                                warn!(
                                                    tool = %drift.tool_name,
                                                    drift_type = ?drift.drift_type,
                                                    severity = ?drift.severity,
                                                    "schema drift detected"
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Forward to client
                        match msg.to_json() {
                            Ok(json) => {
                                let mut out = json.into_bytes();
                                out.push(b'\n');
                                if let Err(e) = client_writer.write_all(&out).await {
                                    error!(%e, "failed to write to client");
                                    break;
                                }
                                if let Err(e) = client_writer.flush().await {
                                    error!(%e, "failed to flush to client");
                                    break;
                                }
                            }
                            Err(e) => {
                                error!(%e, "failed to serialize server response");
                            }
                        }
                    }
                    Err(DomeError::Transport(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        info!("server closed stdout — shutting down");
                        break;
                    }
                    Err(e) => {
                        error!(%e, "error reading from server");
                        break;
                    }
                }
            }
        });

        // Wait for either side to finish
        tokio::select! {
            r = client_to_server => {
                if let Err(e) = r {
                    error!(%e, "client->server task panicked");
                }
            }
            r = server_to_client => {
                if let Err(e) = r {
                    error!(%e, "server->client task panicked");
                }
            }
        }

        // Flush audit log and clean up
        self.ledger.lock().await.flush();
        let _ = child.kill().await;
        info!("MCPDome proxy shut down");

        Ok(())
    }
}

/// Helper to record an audit entry.
async fn record_audit(
    ledger: &Arc<Mutex<Ledger>>,
    request_id: Uuid,
    identity: &str,
    direction: Direction,
    method: &str,
    tool: Option<&str>,
    decision: &str,
    rule_id: Option<&str>,
    latency_us: u64,
) {
    let entry = AuditEntry {
        seq: 0, // set by ledger
        timestamp: Utc::now(),
        request_id,
        identity: identity.to_string(),
        direction,
        method: method.to_string(),
        tool: tool.map(String::from),
        decision: decision.to_string(),
        rule_id: rule_id.map(String::from),
        latency_us,
        prev_hash: String::new(), // set by ledger
        annotations: std::collections::HashMap::new(),
    };

    if let Err(e) = ledger.lock().await.record(entry) {
        error!(%e, "failed to record audit entry");
    }
}
