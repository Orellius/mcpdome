#![allow(clippy::collapsible_if, clippy::too_many_arguments)]

use std::sync::Arc;

use dome_core::{DomeError, McpMessage};
use dome_ledger::{AuditEntry, Direction, Ledger};
use dome_policy::{Identity as PolicyIdentity, SharedPolicyEngine};
use dome_sentinel::{
    AnonymousAuthenticator, ApiKeyAuthenticator, Authenticator, IdentityResolver, PskAuthenticator,
    ResolverConfig,
};
use dome_throttle::{BudgetTracker, BudgetTrackerConfig, RateLimiter, RateLimiterConfig};
use dome_transport::stdio::StdioTransport;
use dome_ward::schema_pin::DriftSeverity;
use dome_ward::{InjectionScanner, SchemaPinStore};

use chrono::Utc;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};
use tracing::{debug, error, info, warn};

const MAX_LINE_SIZE: usize = 10 * 1024 * 1024; // 10 MB
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
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
    /// Whether to block outbound responses that contain injection patterns.
    /// When false (default), outbound injection is logged but not blocked.
    pub block_outbound_injection: bool,
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
            block_outbound_injection: false,
        }
    }
}

/// The Gate -- MCPDome's core proxy loop with full interceptor chain.
///
/// Interceptor order (inbound, client -> server):
///   1. Sentinel -- authenticate on `initialize`, resolve identity
///   2. Throttle -- check rate limits and budget
///   3. Ward    -- scan for injection patterns in tool arguments
///   4. Policy  -- evaluate authorization rules
///   5. Ledger  -- record the decision in the audit chain
///
/// Outbound (server -> client):
///   1. Schema Pin -- verify tools/list responses for drift (block Critical/High)
///   2. Ward       -- scan outbound tool results for injection patterns
///   3. Ledger     -- record outbound audit entry
pub struct Gate {
    config: GateConfig,
    resolver: IdentityResolver,
    policy_engine: Option<SharedPolicyEngine>,
    rate_limiter: Arc<RateLimiter>,
    budget_tracker: Arc<BudgetTracker>,
    injection_scanner: Arc<InjectionScanner>,
    schema_store: Arc<Mutex<SchemaPinStore>>,
    ledger: Arc<Mutex<Ledger>>,
}

impl Gate {
    /// Create a new Gate with full interceptor chain.
    ///
    /// The `policy_engine` parameter accepts an optional `SharedPolicyEngine`
    /// (`Arc<ArcSwap<PolicyEngine>>`), which enables hot-reload. The gate reads
    /// the current policy atomically on every request via `load()`, so swaps
    /// performed by a [`PolicyWatcher`] are immediately visible without restart.
    pub fn new(
        config: GateConfig,
        authenticators: Vec<Box<dyn Authenticator>>,
        policy_engine: Option<SharedPolicyEngine>,
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
        let client_writer: Arc<Mutex<tokio::io::Stdout>> = Arc::new(Mutex::new(client_stdout));

        info!("MCPDome proxy active -- interceptor chain armed");

        // Shared state for the two tasks
        let identity: Arc<Mutex<Option<dome_sentinel::Identity>>> = Arc::new(Mutex::new(None));

        let gate_identity = Arc::clone(&identity);
        let gate_resolver = self.resolver;
        let gate_policy = self.policy_engine.clone();
        let gate_rate_limiter = Arc::clone(&self.rate_limiter);
        let gate_budget = Arc::clone(&self.budget_tracker);
        let gate_scanner = Arc::clone(&self.injection_scanner);
        let gate_ledger = Arc::clone(&self.ledger);
        let gate_config = self.config.clone();
        let gate_client_writer = Arc::clone(&client_writer);

        // Client -> Server task (inbound interceptor chain)
        let client_to_server = tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                let read_result =
                    timeout(CLIENT_READ_TIMEOUT, client_reader.read_line(&mut line)).await;
                let read_result = match read_result {
                    Ok(inner) => inner,
                    Err(_) => {
                        warn!("client read timed out");
                        break;
                    }
                };
                match read_result {
                    Ok(0) => {
                        info!("client closed stdin -- shutting down");
                        break;
                    }
                    Ok(_) => {
                        if line.len() > MAX_LINE_SIZE {
                            warn!(
                                size = line.len(),
                                max = MAX_LINE_SIZE,
                                "client message exceeds size limit, dropping"
                            );
                            let err_resp = McpMessage::error_response(
                                Value::Null,
                                -32600,
                                "Message too large",
                            );
                            if let Err(we) = write_to_client(&gate_client_writer, &err_resp).await {
                                error!(%we, "failed to send size error to client");
                                break;
                            }
                            continue;
                        }
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
                                let mut msg = msg;
                                if method == "initialize" {
                                    match gate_resolver.resolve(&msg).await {
                                        Ok(id) => {
                                            info!(
                                                principal = %id.principal,
                                                method = %id.auth_method,
                                                "identity resolved"
                                            );
                                            *gate_identity.lock().await = Some(id);

                                            // Strip all credential fields before forwarding
                                            // so the downstream server never sees them.
                                            msg = PskAuthenticator::strip_psk(&msg);
                                            msg = ApiKeyAuthenticator::strip_api_key(&msg);
                                        }
                                        Err(e) => {
                                            // Fix 1: On auth failure during initialize,
                                            // send error response and do NOT forward.
                                            warn!(%e, "authentication failed");
                                            let err_id = msg.id.clone().unwrap_or(Value::Null);
                                            let err_resp = McpMessage::error_response(
                                                err_id,
                                                -32600,
                                                "Authentication failed",
                                            );
                                            if let Err(we) =
                                                write_to_client(&gate_client_writer, &err_resp)
                                                    .await
                                            {
                                                error!(%we, "failed to send auth error to client");
                                                break;
                                            }
                                            continue;
                                        }
                                    }
                                }

                                // Fix 1: Block all non-initialize requests before
                                // the session has been initialized (identity resolved).
                                if method != "initialize" {
                                    let identity_lock = gate_identity.lock().await;
                                    if identity_lock.is_none() {
                                        drop(identity_lock);
                                        warn!(method = %method, "request before initialize");
                                        let err_id = msg.id.clone().unwrap_or(Value::Null);
                                        let err_resp = McpMessage::error_response(
                                            err_id,
                                            -32600,
                                            "Session not initialized",
                                        );
                                        if let Err(we) =
                                            write_to_client(&gate_client_writer, &err_resp).await
                                        {
                                            error!(%we, "failed to send not-initialized error to client");
                                            break;
                                        }
                                        continue;
                                    }
                                    drop(identity_lock);
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

                                // Fix 2: Apply interceptor chain to ALL methods,
                                // not just tools/call.

                                // Extract tool-specific fields conditionally.
                                let tool_name = if method == "tools/call" {
                                    tool.as_deref().unwrap_or("unknown")
                                } else {
                                    "-"
                                };

                                let args = msg
                                    .params
                                    .as_ref()
                                    .and_then(|p| p.get("arguments"))
                                    .cloned()
                                    .unwrap_or(Value::Null);

                                // ── 2. Throttle: Rate limit check ──
                                if gate_config.enable_rate_limit {
                                    let rl_tool = if method == "tools/call" {
                                        Some(tool_name)
                                    } else {
                                        None
                                    };
                                    if let Err(e) =
                                        gate_rate_limiter.check_rate_limit(&principal, rl_tool)
                                    {
                                        warn!(%e, principal = %principal, method = %method, "rate limited");
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
                                        // Fix 3: Send JSON-RPC error on rate limit deny.
                                        let err_id = msg.id.clone().unwrap_or(Value::Null);
                                        let err_resp = McpMessage::error_response(
                                            err_id,
                                            -32000,
                                            "Rate limit exceeded",
                                        );
                                        if let Err(we) =
                                            write_to_client(&gate_client_writer, &err_resp).await
                                        {
                                            error!(%we, "failed to send rate limit error to client");
                                            break;
                                        }
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
                                        // Fix 3: Send JSON-RPC error on budget deny.
                                        let err_id = msg.id.clone().unwrap_or(Value::Null);
                                        let err_resp = McpMessage::error_response(
                                            err_id,
                                            -32000,
                                            "Budget exhausted",
                                        );
                                        if let Err(we) =
                                            write_to_client(&gate_client_writer, &err_resp).await
                                        {
                                            error!(%we, "failed to send budget error to client");
                                            break;
                                        }
                                        continue;
                                    }
                                }

                                // ── 3. Ward: Injection scanning ──
                                // Fix 8: Ward runs BEFORE policy so injection detection
                                // is applied regardless of authorization level.
                                if gate_config.enable_ward {
                                    // Scan params/arguments if present.
                                    let scan_text = if method == "tools/call" {
                                        serde_json::to_string(&args).unwrap_or_default()
                                    } else if let Some(ref params) = msg.params {
                                        serde_json::to_string(params).unwrap_or_default()
                                    } else {
                                        String::new()
                                    };

                                    if !scan_text.is_empty() {
                                        let matches = gate_scanner.scan_text(&scan_text);
                                        if !matches.is_empty() {
                                            let pattern_names: Vec<&str> = matches
                                                .iter()
                                                .map(|m| m.pattern_name.as_str())
                                                .collect();
                                            warn!(
                                                patterns = ?pattern_names,
                                                method = %method,
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
                                                &format!(
                                                    "deny:injection:{}",
                                                    pattern_names.join(",")
                                                ),
                                                None,
                                                start.elapsed().as_micros() as u64,
                                            )
                                            .await;
                                            // Fix 3: Send JSON-RPC error on injection deny.
                                            let err_id = msg.id.clone().unwrap_or(Value::Null);
                                            let err_resp = McpMessage::error_response(
                                                err_id,
                                                -32003,
                                                "Request blocked: injection pattern detected",
                                            );
                                            if let Err(we) =
                                                write_to_client(&gate_client_writer, &err_resp)
                                                    .await
                                            {
                                                error!(%we, "failed to send injection error to client");
                                                break;
                                            }
                                            continue;
                                        }
                                    }
                                }

                                // ── 4. Policy: Authorization ──
                                if gate_config.enforce_policy {
                                    if let Some(ref shared_engine) = gate_policy {
                                        // Load the current policy atomically. This is
                                        // lock-free and picks up hot-reloaded changes
                                        // immediately.
                                        let engine = shared_engine.load();

                                        // For tools/call, evaluate with the tool name;
                                        // for other methods, evaluate with the method itself.
                                        let policy_resource = if method == "tools/call" {
                                            tool_name
                                        } else {
                                            method.as_str()
                                        };
                                        let policy_id = PolicyIdentity::new(
                                            principal.clone(),
                                            labels.iter().cloned(),
                                        );
                                        let decision =
                                            engine.evaluate(&policy_id, policy_resource, &args);

                                        if !decision.is_allowed() {
                                            warn!(
                                                rule_id = %decision.rule_id,
                                                method = %method,
                                                resource = policy_resource,
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
                                            // Fix 3: Send JSON-RPC error on policy deny.
                                            let err_id = msg.id.clone().unwrap_or(Value::Null);
                                            let err_resp = McpMessage::error_response(
                                                err_id,
                                                -32003,
                                                format!("Denied by policy: {}", decision.rule_id),
                                            );
                                            if let Err(we) =
                                                write_to_client(&gate_client_writer, &err_resp)
                                                    .await
                                            {
                                                error!(%we, "failed to send policy error to client");
                                                break;
                                            }
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
                                // Fix 7: Drop invalid JSON. Send a JSON-RPC parse
                                // error back to the client instead of forwarding.
                                warn!(%e, raw = trimmed, "invalid JSON from client, dropping");
                                let err_resp = McpMessage::error_response(
                                    Value::Null,
                                    -32700,
                                    "Parse error: invalid JSON",
                                );
                                if let Err(we) =
                                    write_to_client(&gate_client_writer, &err_resp).await
                                {
                                    error!(%we, "failed to send parse error to client");
                                    break;
                                }
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
        let outbound_ledger = Arc::clone(&self.ledger);
        let outbound_scanner = Arc::clone(&self.injection_scanner);
        let outbound_config = self.config.clone();
        let outbound_client_writer = Arc::clone(&client_writer);

        // Server -> Client task (outbound interceptor chain)
        let server_to_client = tokio::spawn(async move {
            let mut first_tools_list = true;
            // Cache the last known-good tools/list response for fallback
            // when critical schema drift is detected.
            let mut last_good_tools_result: Option<Value> = None;

            loop {
                match server_reader.recv().await {
                    Ok(msg) => {
                        let start = std::time::Instant::now();
                        let method = msg.method.as_deref().unwrap_or("-").to_string();
                        let outbound_request_id = Uuid::new_v4();

                        debug!(
                            method = method.as_str(),
                            id = ?msg.id,
                            "server -> client"
                        );

                        let mut forward_msg = msg;

                        // ── Schema Pin: Verify tools/list responses ──
                        if outbound_config.enable_schema_pin {
                            if let Some(result) = &forward_msg.result {
                                if result.get("tools").is_some() {
                                    let mut store = schema_store.lock().await;
                                    if first_tools_list {
                                        store.pin_tools(result);
                                        info!(pinned = store.len(), "schema pins established");
                                        // Cache the first (known-good) tools result.
                                        last_good_tools_result = Some(result.clone());
                                        first_tools_list = false;
                                    } else {
                                        let drifts = store.verify_tools(result);
                                        if !drifts.is_empty() {
                                            let mut has_critical_or_high = false;
                                            for drift in &drifts {
                                                warn!(
                                                    tool = %drift.tool_name,
                                                    drift_type = ?drift.drift_type,
                                                    severity = ?drift.severity,
                                                    "schema drift detected"
                                                );
                                                if matches!(
                                                    drift.severity,
                                                    DriftSeverity::Critical | DriftSeverity::High
                                                ) {
                                                    has_critical_or_high = true;
                                                }
                                            }

                                            // Fix 5: Block Critical/High schema drift.
                                            // Send the previously pinned (known-good)
                                            // schema instead of the drifted response.
                                            if has_critical_or_high {
                                                warn!(
                                                    "critical/high schema drift detected -- blocking drifted tools/list"
                                                );
                                                // Fix 9: Record outbound drift block.
                                                record_audit(
                                                    &outbound_ledger,
                                                    outbound_request_id,
                                                    "server",
                                                    Direction::Outbound,
                                                    "tools/list",
                                                    None,
                                                    "deny:schema_drift",
                                                    None,
                                                    start.elapsed().as_micros() as u64,
                                                )
                                                .await;

                                                if let Some(ref good_result) =
                                                    last_good_tools_result
                                                {
                                                    // Replace with the known-good schema.
                                                    forward_msg.result = Some(good_result.clone());
                                                } else {
                                                    // No known-good schema available; send error.
                                                    let err_id = forward_msg
                                                        .id
                                                        .clone()
                                                        .unwrap_or(Value::Null);
                                                    let err_resp = McpMessage::error_response(
                                                        err_id,
                                                        -32003,
                                                        "Schema drift detected: tool definitions have been tampered with",
                                                    );
                                                    if let Err(we) = write_to_client(
                                                        &outbound_client_writer,
                                                        &err_resp,
                                                    )
                                                    .await
                                                    {
                                                        error!(%we, "failed to send schema drift error to client");
                                                        break;
                                                    }
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // ── Outbound response scanning ──
                        if outbound_config.enable_ward {
                            if let Some(ref result) = forward_msg.result {
                                let scan_target = if let Some(content) = result.get("content") {
                                    serde_json::to_string(content).unwrap_or_default()
                                } else {
                                    serde_json::to_string(result).unwrap_or_default()
                                };

                                if !scan_target.is_empty() {
                                    let matches = outbound_scanner.scan_text(&scan_target);
                                    if !matches.is_empty() {
                                        let pattern_names: Vec<&str> = matches
                                            .iter()
                                            .map(|m| m.pattern_name.as_str())
                                            .collect();
                                        let decision = if outbound_config.block_outbound_injection {
                                            "deny:outbound_injection"
                                        } else {
                                            "warn:outbound_injection"
                                        };
                                        warn!(
                                            patterns = ?pattern_names,
                                            direction = "outbound",
                                            blocked = outbound_config.block_outbound_injection,
                                            "injection detected in server response"
                                        );
                                        record_audit(
                                            &outbound_ledger,
                                            outbound_request_id,
                                            "server",
                                            Direction::Outbound,
                                            &method,
                                            None,
                                            &format!("{}:{}", decision, pattern_names.join(",")),
                                            None,
                                            start.elapsed().as_micros() as u64,
                                        )
                                        .await;

                                        if outbound_config.block_outbound_injection {
                                            let err_id =
                                                forward_msg.id.clone().unwrap_or(Value::Null);
                                            let err_resp = McpMessage::error_response(
                                                err_id,
                                                -32005,
                                                "Response blocked: injection pattern detected in server output",
                                            );
                                            if let Err(we) =
                                                write_to_client(&outbound_client_writer, &err_resp)
                                                    .await
                                            {
                                                error!(%we, "failed to send outbound injection error");
                                                break;
                                            }
                                            continue;
                                        }
                                    }
                                }
                            }
                        }

                        // Record outbound audit entry
                        record_audit(
                            &outbound_ledger,
                            outbound_request_id,
                            "server",
                            Direction::Outbound,
                            &method,
                            None,
                            "forward",
                            None,
                            start.elapsed().as_micros() as u64,
                        )
                        .await;

                        // Forward to client
                        if let Err(e) = write_to_client(&outbound_client_writer, &forward_msg).await
                        {
                            error!(%e, "failed to write to client");
                            break;
                        }
                    }
                    Err(DomeError::Transport(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        info!("server closed stdout -- shutting down");
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

/// Write a McpMessage to the client's stdout, with newline and flush.
async fn write_to_client(
    writer: &Arc<Mutex<tokio::io::Stdout>>,
    msg: &McpMessage,
) -> Result<(), std::io::Error> {
    match msg.to_json() {
        Ok(json) => {
            let mut out = json.into_bytes();
            out.push(b'\n');
            let mut w = writer.lock().await;
            w.write_all(&out).await?;
            w.flush().await?;
            Ok(())
        }
        Err(e) => {
            error!(%e, "failed to serialize message for client");
            Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
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
