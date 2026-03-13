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

// ---------------------------------------------------------------------------
// Interceptor chain action types
// ---------------------------------------------------------------------------

/// Result of processing an inbound message through the interceptor chain.
enum InboundAction {
    /// Forward the (possibly modified) message to the upstream server.
    Forward(McpMessage),
    /// Send this error response back to the client (do NOT forward).
    Deny(McpMessage),
}

/// Result of processing an outbound message through the interceptor chain.
enum OutboundAction {
    /// Forward the (possibly modified) message to the client.
    Forward(McpMessage),
    /// Block the message; send this error response to the client instead.
    Block(McpMessage),
}

/// Per-session state for the outbound interceptor chain.
struct OutboundContext {
    first_tools_list: bool,
    last_good_tools_result: Option<Value>,
}

impl OutboundContext {
    fn new() -> Self {
        Self {
            first_tools_list: true,
            last_good_tools_result: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Gate configuration
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Gate — public API
// ---------------------------------------------------------------------------

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

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("config", &self.config)
            .field("has_policy_engine", &self.policy_engine.is_some())
            .finish_non_exhaustive()
    }
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

    /// Convert the Gate into a shared ProxyState for the proxy loop.
    fn into_proxy_state(self) -> Arc<ProxyState> {
        Arc::new(ProxyState {
            identity: Mutex::new(None),
            resolver: self.resolver,
            config: self.config,
            policy: self.policy_engine,
            rate_limiter: self.rate_limiter,
            budget: self.budget_tracker,
            scanner: self.injection_scanner,
            schema_store: self.schema_store,
            ledger: self.ledger,
        })
    }

    /// Run the proxy over stdio (stdin/stdout for the client, child process for the server).
    pub async fn run_stdio(self, command: &str, args: &[&str]) -> Result<(), DomeError> {
        let state = self.into_proxy_state();

        let transport = StdioTransport::spawn(command, args).await?;
        let (mut server_reader, mut server_writer, mut child) = transport.split();

        let client_stdin = tokio::io::stdin();
        let client_stdout = tokio::io::stdout();
        let mut client_reader = BufReader::new(client_stdin);
        let client_writer: Arc<Mutex<tokio::io::Stdout>> = Arc::new(Mutex::new(client_stdout));

        info!("MCPDome proxy active -- interceptor chain armed");

        let inbound_state = Arc::clone(&state);
        let inbound_writer = Arc::clone(&client_writer);

        // Client -> Server task (inbound interceptor chain)
        let mut client_to_server = tokio::spawn(async move {
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
                            if let Err(we) = write_to_client(&inbound_writer, &err_resp).await {
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
                            Ok(msg) => match inbound_state.process_inbound(msg).await {
                                InboundAction::Forward(msg) => {
                                    if let Err(e) = server_writer.send(&msg).await {
                                        error!(%e, "failed to forward to server");
                                        break;
                                    }
                                }
                                InboundAction::Deny(err_resp) => {
                                    if let Err(we) =
                                        write_to_client(&inbound_writer, &err_resp).await
                                    {
                                        error!(%we, "failed to send error to client");
                                        break;
                                    }
                                }
                            },
                            Err(e) => {
                                warn!(%e, raw = trimmed, "invalid JSON from client, dropping");
                                let err_resp = McpMessage::error_response(
                                    Value::Null,
                                    -32700,
                                    "Parse error: invalid JSON",
                                );
                                if let Err(we) = write_to_client(&inbound_writer, &err_resp).await {
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

        let outbound_state = Arc::clone(&state);
        let outbound_writer = Arc::clone(&client_writer);

        // Server -> Client task (outbound interceptor chain)
        let mut server_to_client = tokio::spawn(async move {
            let mut ctx = OutboundContext::new();
            loop {
                match server_reader.recv().await {
                    Ok(msg) => match outbound_state.process_outbound(msg, &mut ctx).await {
                        OutboundAction::Forward(msg) => {
                            if let Err(e) = write_to_client(&outbound_writer, &msg).await {
                                error!(%e, "failed to write to client");
                                break;
                            }
                        }
                        OutboundAction::Block(err_resp) => {
                            if let Err(e) = write_to_client(&outbound_writer, &err_resp).await {
                                error!(%e, "failed to send outbound error to client");
                                break;
                            }
                        }
                    },
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

        // Wait for either side to finish, then abort the other.
        tokio::select! {
            r = &mut client_to_server => {
                if let Err(e) = r {
                    error!(%e, "client->server task panicked");
                }
                server_to_client.abort();
            }
            r = &mut server_to_client => {
                if let Err(e) = r {
                    error!(%e, "server->client task panicked");
                }
                client_to_server.abort();
            }
        }

        // Flush audit log.
        state.ledger.lock().await.flush();

        // Graceful child termination: the child's stdin pipe was closed when
        // the writer task ended/was aborted, so the child should see EOF and
        // exit. Wait up to 5 seconds, then force-kill as a last resort.
        match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(Ok(status)) => info!(%status, "upstream server exited"),
            Ok(Err(e)) => warn!(%e, "error waiting for upstream server"),
            Err(_) => {
                warn!("upstream server did not exit within 5s, forcing termination");
                let _ = child.kill().await;
            }
        }

        info!("MCPDome proxy shut down");
        Ok(())
    }

    /// Run the proxy over HTTP+SSE (HTTP server for the client, child process
    /// for the upstream MCP server).
    #[cfg(feature = "http")]
    pub async fn run_http(
        self,
        command: &str,
        args: &[&str],
        http_config: dome_transport::http::HttpTransportConfig,
    ) -> Result<(), DomeError> {
        let state = self.into_proxy_state();

        let transport = StdioTransport::spawn(command, args).await?;
        let (mut server_reader, mut server_writer, mut child) = transport.split();

        let http = dome_transport::http::HttpTransport::start(http_config).await?;
        let (mut http_reader, http_writer, http_handle) = http.split();
        let http_writer = Arc::new(http_writer);

        info!("MCPDome HTTP+SSE proxy active -- interceptor chain armed");

        let inbound_state = Arc::clone(&state);
        let inbound_http_writer = Arc::clone(&http_writer);

        // Client -> Server task (inbound interceptor chain via HTTP)
        let mut client_to_server = tokio::spawn(async move {
            loop {
                match http_reader.recv().await {
                    Ok(msg) => match inbound_state.process_inbound(msg).await {
                        InboundAction::Forward(msg) => {
                            if let Err(e) = server_writer.send(&msg).await {
                                error!(%e, "failed to forward to server");
                                break;
                            }
                        }
                        InboundAction::Deny(err_resp) => {
                            if let Err(e) = inbound_http_writer.send(&err_resp).await {
                                warn!(%e, "failed to send error to HTTP client");
                            }
                        }
                    },
                    Err(e) => {
                        info!(%e, "HTTP client transport closed");
                        break;
                    }
                }
            }
        });

        let outbound_state = Arc::clone(&state);
        let outbound_http_writer = Arc::clone(&http_writer);

        // Server -> Client task (outbound interceptor chain via HTTP)
        let mut server_to_client = tokio::spawn(async move {
            let mut ctx = OutboundContext::new();
            loop {
                match server_reader.recv().await {
                    Ok(msg) => match outbound_state.process_outbound(msg, &mut ctx).await {
                        OutboundAction::Forward(msg) => {
                            if let Err(e) = outbound_http_writer.send(&msg).await {
                                warn!(%e, "failed to send to HTTP client");
                                break;
                            }
                        }
                        OutboundAction::Block(err_resp) => {
                            if let Err(e) = outbound_http_writer.send(&err_resp).await {
                                warn!(%e, "failed to send outbound error to HTTP client");
                                break;
                            }
                        }
                    },
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

        // Wait for either side to finish, then abort the other.
        tokio::select! {
            r = &mut client_to_server => {
                if let Err(e) = r {
                    error!(%e, "client->server task panicked");
                }
                server_to_client.abort();
            }
            r = &mut server_to_client => {
                if let Err(e) = r {
                    error!(%e, "server->client task panicked");
                }
                client_to_server.abort();
            }
        }

        // Flush audit log.
        state.ledger.lock().await.flush();

        // Shut down HTTP server.
        http_handle.shutdown().await;

        // Graceful child termination.
        match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(Ok(status)) => info!(%status, "upstream server exited"),
            Ok(Err(e)) => warn!(%e, "error waiting for upstream server"),
            Err(_) => {
                warn!("upstream server did not exit within 5s, forcing termination");
                let _ = child.kill().await;
            }
        }

        info!("MCPDome HTTP+SSE proxy shut down");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProxyState — shared interceptor chain state
// ---------------------------------------------------------------------------

/// Internal shared state for the proxy loop. Created from a [`Gate`] at the
/// start of a proxy session. Holds all interceptor chain components behind
/// appropriate synchronization primitives so both the inbound (client → server)
/// and outbound (server → client) tasks can share it via `Arc`.
struct ProxyState {
    identity: Mutex<Option<dome_sentinel::Identity>>,
    resolver: IdentityResolver,
    config: GateConfig,
    policy: Option<SharedPolicyEngine>,
    rate_limiter: Arc<RateLimiter>,
    budget: Arc<BudgetTracker>,
    scanner: Arc<InjectionScanner>,
    schema_store: Arc<Mutex<SchemaPinStore>>,
    ledger: Arc<Mutex<Ledger>>,
}

impl ProxyState {
    /// Process an inbound (client → server) message through the full
    /// interceptor chain: Sentinel → Throttle → Ward → Policy → Ledger.
    async fn process_inbound(&self, msg: McpMessage) -> InboundAction {
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
            match self.resolver.resolve(&msg).await {
                Ok(id) => {
                    info!(
                        principal = %id.principal,
                        method = %id.auth_method,
                        "identity resolved"
                    );
                    *self.identity.lock().await = Some(id);

                    // Strip all credential fields before forwarding.
                    msg = PskAuthenticator::strip_psk(&msg);
                    msg = ApiKeyAuthenticator::strip_api_key(&msg);
                }
                Err(e) => {
                    warn!(%e, "authentication failed");
                    let err_id = msg.id.clone().unwrap_or(Value::Null);
                    return InboundAction::Deny(McpMessage::error_response(
                        err_id,
                        -32600,
                        "Authentication failed",
                    ));
                }
            }
        }

        // Block all non-initialize requests before the session has been
        // initialized (identity resolved).
        if method != "initialize" {
            let identity_lock = self.identity.lock().await;
            if identity_lock.is_none() {
                drop(identity_lock);
                warn!(method = %method, "request before initialize");
                let err_id = msg.id.clone().unwrap_or(Value::Null);
                return InboundAction::Deny(McpMessage::error_response(
                    err_id,
                    -32600,
                    "Session not initialized",
                ));
            }
            drop(identity_lock);
        }

        let identity_lock = self.identity.lock().await;
        let principal = identity_lock
            .as_ref()
            .map(|i| i.principal.clone())
            .unwrap_or_else(|| "anonymous".to_string());
        let labels = identity_lock
            .as_ref()
            .map(|i| i.labels.clone())
            .unwrap_or_default();
        drop(identity_lock);

        // Extract the method-specific resource name for policy evaluation.
        let resource_name = msg.method_resource_name().unwrap_or("-").to_string();
        let tool_name = resource_name.as_str();

        let args = msg
            .params
            .as_ref()
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);

        // ── 2. Throttle: Rate limit check ──
        if self.config.enable_rate_limit {
            let rl_tool = if tool_name != "-" {
                Some(tool_name)
            } else {
                None
            };
            if let Err(e) = self.rate_limiter.check_rate_limit(&principal, rl_tool) {
                warn!(%e, principal = %principal, method = %method, "rate limited");
                record_audit(
                    &self.ledger,
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
                let err_id = msg.id.clone().unwrap_or(Value::Null);
                return InboundAction::Deny(McpMessage::error_response(
                    err_id,
                    -32000,
                    "Rate limit exceeded",
                ));
            }
        }

        // ── 2b. Throttle: Budget check ──
        if self.config.enable_budget {
            if let Err(e) = self.budget.try_spend(&principal, 1.0) {
                warn!(%e, principal = %principal, "budget exhausted");
                record_audit(
                    &self.ledger,
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
                let err_id = msg.id.clone().unwrap_or(Value::Null);
                return InboundAction::Deny(McpMessage::error_response(
                    err_id,
                    -32000,
                    "Budget exhausted",
                ));
            }
        }

        // ── 3. Ward: Injection scanning ──
        // Ward runs BEFORE policy so injection detection is applied regardless
        // of authorization level.
        if self.config.enable_ward {
            let scan_text = if method == "tools/call" {
                serde_json::to_string(&args).unwrap_or_default()
            } else if let Some(ref params) = msg.params {
                serde_json::to_string(params).unwrap_or_default()
            } else {
                String::new()
            };

            if !scan_text.is_empty() {
                let matches = self.scanner.scan_text(&scan_text);
                if !matches.is_empty() {
                    let pattern_names: Vec<&str> =
                        matches.iter().map(|m| m.pattern_name.as_str()).collect();
                    warn!(
                        patterns = ?pattern_names,
                        method = %method,
                        tool = tool_name,
                        principal = %principal,
                        "injection detected"
                    );
                    record_audit(
                        &self.ledger,
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
                    let err_id = msg.id.clone().unwrap_or(Value::Null);
                    return InboundAction::Deny(McpMessage::error_response(
                        err_id,
                        -32003,
                        "Request blocked: injection pattern detected",
                    ));
                }
            }
        }

        // ── 4. Policy: Authorization ──
        if self.config.enforce_policy {
            if let Some(ref shared_engine) = self.policy {
                // Load the current policy atomically. This is lock-free and
                // picks up hot-reloaded changes immediately.
                let engine = shared_engine.load();

                let policy_resource = if method == "tools/call" {
                    tool_name
                } else {
                    method.as_str()
                };
                let policy_id = PolicyIdentity::new(principal.clone(), labels.iter().cloned());
                let decision = engine.evaluate(&policy_id, policy_resource, &args);

                if !decision.is_allowed() {
                    warn!(
                        rule_id = %decision.rule_id,
                        method = %method,
                        resource = policy_resource,
                        principal = %principal,
                        "policy denied"
                    );
                    record_audit(
                        &self.ledger,
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
                    let err_id = msg.id.clone().unwrap_or(Value::Null);
                    return InboundAction::Deny(McpMessage::error_response(
                        err_id,
                        -32003,
                        format!("Denied by policy: {}", decision.rule_id),
                    ));
                }
            }
        }

        // ── 5. Ledger: Record allowed request ──
        record_audit(
            &self.ledger,
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

        InboundAction::Forward(msg)
    }

    /// Process an outbound (server → client) message through the outbound
    /// interceptor chain: Schema Pin → Ward → Ledger.
    async fn process_outbound(&self, msg: McpMessage, ctx: &mut OutboundContext) -> OutboundAction {
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
        if self.config.enable_schema_pin {
            if let Some(result) = &forward_msg.result {
                if result.get("tools").is_some() {
                    let mut store = self.schema_store.lock().await;
                    if ctx.first_tools_list {
                        store.pin_tools(result);
                        info!(pinned = store.len(), "schema pins established");
                        ctx.last_good_tools_result = Some(result.clone());
                        ctx.first_tools_list = false;
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

                            if has_critical_or_high {
                                warn!(
                                    "critical/high schema drift detected -- blocking drifted tools/list"
                                );
                                record_audit(
                                    &self.ledger,
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

                                if let Some(ref good_result) = ctx.last_good_tools_result {
                                    forward_msg.result = Some(good_result.clone());
                                } else {
                                    let err_id = forward_msg.id.clone().unwrap_or(Value::Null);
                                    return OutboundAction::Block(McpMessage::error_response(
                                        err_id,
                                        -32003,
                                        "Schema drift detected: tool definitions have been tampered with",
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Outbound response scanning ──
        if self.config.enable_ward {
            if let Some(ref result) = forward_msg.result {
                let scan_target = if let Some(content) = result.get("content") {
                    serde_json::to_string(content).unwrap_or_default()
                } else {
                    serde_json::to_string(result).unwrap_or_default()
                };

                if !scan_target.is_empty() {
                    let matches = self.scanner.scan_text(&scan_target);
                    if !matches.is_empty() {
                        let pattern_names: Vec<&str> =
                            matches.iter().map(|m| m.pattern_name.as_str()).collect();
                        let decision = if self.config.block_outbound_injection {
                            "deny:outbound_injection"
                        } else {
                            "warn:outbound_injection"
                        };
                        warn!(
                            patterns = ?pattern_names,
                            direction = "outbound",
                            blocked = self.config.block_outbound_injection,
                            "injection detected in server response"
                        );
                        record_audit(
                            &self.ledger,
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

                        if self.config.block_outbound_injection {
                            let err_id = forward_msg.id.clone().unwrap_or(Value::Null);
                            return OutboundAction::Block(McpMessage::error_response(
                                err_id,
                                -32005,
                                "Response blocked: injection pattern detected in server output",
                            ));
                        }
                    }
                }
            }
        }

        // Record outbound audit entry.
        record_audit(
            &self.ledger,
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

        OutboundAction::Forward(forward_msg)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;
    use dome_ledger::MemorySink;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Create a Ledger backed by a MemorySink for test inspection.
    fn test_ledger() -> Ledger {
        Ledger::new(vec![Box::new(MemorySink::new())])
    }

    /// Create a Ledger with no sinks (sufficient when we only care about
    /// entry count, not sink contents).
    fn empty_ledger() -> Ledger {
        Ledger::new(vec![])
    }

    // -----------------------------------------------------------------------
    // GateConfig defaults
    // -----------------------------------------------------------------------

    #[test]
    fn gate_config_defaults_all_security_disabled() {
        let config = GateConfig::default();

        assert!(
            !config.enforce_policy,
            "enforce_policy should default to false"
        );
        assert!(!config.enable_ward, "enable_ward should default to false");
        assert!(
            !config.enable_schema_pin,
            "enable_schema_pin should default to false"
        );
        assert!(
            !config.enable_rate_limit,
            "enable_rate_limit should default to false"
        );
        assert!(
            !config.enable_budget,
            "enable_budget should default to false"
        );
        assert!(
            config.allow_anonymous,
            "allow_anonymous should default to true"
        );
        assert!(
            !config.block_outbound_injection,
            "block_outbound_injection should default to false"
        );
    }

    #[test]
    fn gate_config_with_all_enabled() {
        let config = GateConfig {
            enforce_policy: true,
            enable_ward: true,
            enable_schema_pin: true,
            enable_rate_limit: true,
            enable_budget: true,
            allow_anonymous: false,
            block_outbound_injection: true,
        };

        assert!(config.enforce_policy);
        assert!(config.enable_ward);
        assert!(config.enable_schema_pin);
        assert!(config.enable_rate_limit);
        assert!(config.enable_budget);
        assert!(!config.allow_anonymous);
        assert!(config.block_outbound_injection);
    }

    #[test]
    fn gate_config_is_cloneable() {
        let original = GateConfig {
            enforce_policy: true,
            enable_ward: true,
            enable_schema_pin: false,
            enable_rate_limit: true,
            enable_budget: false,
            allow_anonymous: false,
            block_outbound_injection: true,
        };
        let cloned = original.clone();

        assert_eq!(cloned.enforce_policy, original.enforce_policy);
        assert_eq!(cloned.enable_ward, original.enable_ward);
        assert_eq!(cloned.enable_schema_pin, original.enable_schema_pin);
        assert_eq!(cloned.enable_rate_limit, original.enable_rate_limit);
        assert_eq!(cloned.enable_budget, original.enable_budget);
        assert_eq!(cloned.allow_anonymous, original.allow_anonymous);
        assert_eq!(
            cloned.block_outbound_injection,
            original.block_outbound_injection
        );
    }

    #[test]
    fn gate_config_is_debug_printable() {
        let config = GateConfig::default();
        let debug_output = format!("{:?}", config);

        assert!(debug_output.contains("GateConfig"));
        assert!(debug_output.contains("enforce_policy"));
        assert!(debug_output.contains("enable_ward"));
    }

    // -----------------------------------------------------------------------
    // Gate::transparent
    // -----------------------------------------------------------------------

    #[test]
    fn transparent_gate_has_correct_config_defaults() {
        let gate = Gate::transparent(empty_ledger());

        assert!(
            !gate.config.enforce_policy,
            "transparent gate should not enforce policy"
        );
        assert!(
            !gate.config.enable_ward,
            "transparent gate should not enable ward"
        );
        assert!(
            !gate.config.enable_schema_pin,
            "transparent gate should not enable schema pinning"
        );
        assert!(
            !gate.config.enable_rate_limit,
            "transparent gate should not enable rate limiting"
        );
        assert!(
            !gate.config.enable_budget,
            "transparent gate should not enable budget tracking"
        );
        assert!(
            gate.config.allow_anonymous,
            "transparent gate should allow anonymous access"
        );
        assert!(
            !gate.config.block_outbound_injection,
            "transparent gate should not block outbound injection"
        );
    }

    #[test]
    fn transparent_gate_has_no_policy_engine() {
        let gate = Gate::transparent(empty_ledger());
        assert!(
            gate.policy_engine.is_none(),
            "transparent gate should have no policy engine"
        );
    }

    // -----------------------------------------------------------------------
    // Gate::new with custom config
    // -----------------------------------------------------------------------

    #[test]
    fn gate_new_with_custom_config_preserves_flags() {
        let config = GateConfig {
            enforce_policy: true,
            enable_ward: true,
            enable_schema_pin: true,
            enable_rate_limit: true,
            enable_budget: true,
            allow_anonymous: false,
            block_outbound_injection: true,
        };

        let gate = Gate::new(
            config,
            vec![Box::new(AnonymousAuthenticator)],
            None,
            RateLimiterConfig::default(),
            BudgetTrackerConfig::default(),
            empty_ledger(),
        );

        assert!(gate.config.enforce_policy);
        assert!(gate.config.enable_ward);
        assert!(gate.config.enable_schema_pin);
        assert!(gate.config.enable_rate_limit);
        assert!(gate.config.enable_budget);
        assert!(!gate.config.allow_anonymous);
        assert!(gate.config.block_outbound_injection);
    }

    #[test]
    fn gate_new_without_policy_engine_stores_none() {
        let gate = Gate::new(
            GateConfig::default(),
            vec![Box::new(AnonymousAuthenticator)],
            None,
            RateLimiterConfig::default(),
            BudgetTrackerConfig::default(),
            empty_ledger(),
        );

        assert!(gate.policy_engine.is_none());
    }

    // -----------------------------------------------------------------------
    // Gate Debug impl
    // -----------------------------------------------------------------------

    #[test]
    fn gate_is_debug_printable() {
        let gate = Gate::transparent(empty_ledger());
        let debug_output = format!("{:?}", gate);

        assert!(debug_output.contains("Gate"));
        assert!(debug_output.contains("config"));
        assert!(debug_output.contains("has_policy_engine"));
    }

    // -----------------------------------------------------------------------
    // record_audit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn record_audit_creates_entry_with_correct_fields() {
        let ledger = Arc::new(Mutex::new(test_ledger()));
        let request_id = Uuid::new_v4();

        record_audit(
            &ledger,
            request_id,
            "test-user",
            Direction::Inbound,
            "tools/call",
            Some("read_file"),
            "allow",
            Some("rule-1"),
            42,
        )
        .await;

        let ledger_guard = ledger.lock().await;
        assert_eq!(
            ledger_guard.entry_count(),
            1,
            "should have recorded exactly one entry"
        );
    }

    #[tokio::test]
    async fn record_audit_with_no_tool_and_no_rule() {
        let ledger = Arc::new(Mutex::new(test_ledger()));
        let request_id = Uuid::new_v4();

        record_audit(
            &ledger,
            request_id,
            "anonymous",
            Direction::Outbound,
            "initialize",
            None,
            "forward",
            None,
            0,
        )
        .await;

        let ledger_guard = ledger.lock().await;
        assert_eq!(ledger_guard.entry_count(), 1);
    }

    #[tokio::test]
    async fn record_audit_multiple_entries_increment_count() {
        let ledger = Arc::new(Mutex::new(test_ledger()));

        for i in 0..5 {
            record_audit(
                &ledger,
                Uuid::new_v4(),
                &format!("user-{i}"),
                Direction::Inbound,
                "tools/call",
                Some("test_tool"),
                "allow",
                None,
                i * 10,
            )
            .await;
        }

        let ledger_guard = ledger.lock().await;
        assert_eq!(ledger_guard.entry_count(), 5);
    }

    #[tokio::test]
    async fn record_audit_deny_decisions_are_recorded() {
        let ledger = Arc::new(Mutex::new(test_ledger()));

        record_audit(
            &ledger,
            Uuid::new_v4(),
            "malicious-user",
            Direction::Inbound,
            "tools/call",
            Some("exec_command"),
            "deny:policy:no-exec",
            Some("no-exec"),
            150,
        )
        .await;

        record_audit(
            &ledger,
            Uuid::new_v4(),
            "spammer",
            Direction::Inbound,
            "tools/call",
            Some("spam_tool"),
            "deny:rate_limit",
            None,
            5,
        )
        .await;

        record_audit(
            &ledger,
            Uuid::new_v4(),
            "attacker",
            Direction::Inbound,
            "tools/call",
            Some("read_file"),
            "deny:injection:prompt_injection",
            None,
            200,
        )
        .await;

        let ledger_guard = ledger.lock().await;
        assert_eq!(ledger_guard.entry_count(), 3);
    }

    #[tokio::test]
    async fn record_audit_outbound_schema_drift() {
        let ledger = Arc::new(Mutex::new(test_ledger()));

        record_audit(
            &ledger,
            Uuid::new_v4(),
            "server",
            Direction::Outbound,
            "tools/list",
            None,
            "deny:schema_drift",
            None,
            75,
        )
        .await;

        let ledger_guard = ledger.lock().await;
        assert_eq!(ledger_guard.entry_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn max_line_size_is_ten_megabytes() {
        assert_eq!(MAX_LINE_SIZE, 10 * 1024 * 1024);
    }

    #[test]
    fn client_read_timeout_is_five_minutes() {
        assert_eq!(CLIENT_READ_TIMEOUT, Duration::from_secs(300));
    }

    // -----------------------------------------------------------------------
    // GateConfig partial overrides (common patterns)
    // -----------------------------------------------------------------------

    #[test]
    fn gate_config_ward_only_mode() {
        let config = GateConfig {
            enable_ward: true,
            ..GateConfig::default()
        };

        assert!(config.enable_ward);
        assert!(!config.enforce_policy, "policy should remain off");
        assert!(!config.enable_rate_limit, "rate limit should remain off");
        assert!(!config.enable_budget, "budget should remain off");
        assert!(!config.enable_schema_pin, "schema pin should remain off");
        assert!(config.allow_anonymous, "anonymous should remain on");
    }

    #[test]
    fn gate_config_full_security_mode() {
        let config = GateConfig {
            enforce_policy: true,
            enable_ward: true,
            enable_schema_pin: true,
            enable_rate_limit: true,
            enable_budget: true,
            allow_anonymous: false,
            block_outbound_injection: true,
        };

        // Every security feature is active
        assert!(config.enforce_policy);
        assert!(config.enable_ward);
        assert!(config.enable_schema_pin);
        assert!(config.enable_rate_limit);
        assert!(config.enable_budget);
        assert!(!config.allow_anonymous);
        assert!(config.block_outbound_injection);
    }

    // -----------------------------------------------------------------------
    // Gate construction does not panic
    // -----------------------------------------------------------------------

    #[test]
    fn gate_new_with_multiple_authenticators_does_not_panic() {
        let _gate = Gate::new(
            GateConfig::default(),
            vec![
                Box::new(AnonymousAuthenticator),
                Box::new(AnonymousAuthenticator),
            ],
            None,
            RateLimiterConfig::default(),
            BudgetTrackerConfig::default(),
            empty_ledger(),
        );
    }

    #[test]
    fn gate_new_with_empty_authenticators_does_not_panic() {
        let _gate = Gate::new(
            GateConfig::default(),
            vec![],
            None,
            RateLimiterConfig::default(),
            BudgetTrackerConfig::default(),
            empty_ledger(),
        );
    }

    // -----------------------------------------------------------------------
    // Audit entry construction (verifying the shape record_audit produces)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn record_audit_entry_fields_populated_correctly() {
        // Use a MemorySink so entries are recorded and inspectable.
        let ledger = Arc::new(Mutex::new(Ledger::new(vec![Box::new(MemorySink::new())])));
        let request_id = Uuid::new_v4();

        record_audit(
            &ledger,
            request_id,
            "psk:dev-key-1",
            Direction::Inbound,
            "tools/call",
            Some("read_file"),
            "deny:policy:no-read",
            Some("no-read"),
            999,
        )
        .await;

        // Verify the ledger recorded it
        let guard = ledger.lock().await;
        assert_eq!(guard.entry_count(), 1);
    }

    #[tokio::test]
    async fn record_audit_handles_empty_identity() {
        let ledger = Arc::new(Mutex::new(test_ledger()));

        record_audit(
            &ledger,
            Uuid::new_v4(),
            "",
            Direction::Inbound,
            "initialize",
            None,
            "allow",
            None,
            0,
        )
        .await;

        let guard = ledger.lock().await;
        assert_eq!(
            guard.entry_count(),
            1,
            "empty identity should not prevent recording"
        );
    }

    #[tokio::test]
    async fn record_audit_handles_long_decision_string() {
        let ledger = Arc::new(Mutex::new(test_ledger()));
        let long_decision = format!("deny:injection:{}", "pattern_name,".repeat(50));

        record_audit(
            &ledger,
            Uuid::new_v4(),
            "test-user",
            Direction::Inbound,
            "tools/call",
            Some("risky_tool"),
            &long_decision,
            None,
            500,
        )
        .await;

        let guard = ledger.lock().await;
        assert_eq!(
            guard.entry_count(),
            1,
            "long decision strings should be accepted"
        );
    }
}
