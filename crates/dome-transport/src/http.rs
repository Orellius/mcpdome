//! HTTP+SSE transport for MCP.
//!
//! Implements the MCP HTTP+SSE transport protocol:
//! - `GET /sse` — establishes a Server-Sent Events stream for server-to-client messages.
//!   On connection, the server sends an `endpoint` event containing the POST URL.
//! - `POST /message?sessionId=<id>` — accepts JSON-RPC messages from client-to-server.
//!
//! The transport exposes [`HttpReader`] and [`HttpWriter`] halves that match the
//! same recv/send pattern used by [`crate::stdio::StdioReader`] and
//! [`crate::stdio::StdioWriter`], allowing [`dome_gate::Gate`] to use either
//! transport interchangeably.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use dome_core::{DomeError, McpMessage};
use futures::Stream;
use serde::Deserialize;
use tokio::sync::{Mutex, Notify, broadcast, mpsc};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the HTTP+SSE transport server.
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Address to bind the HTTP server to.
    pub bind_addr: SocketAddr,
    /// Allowed CORS origins. `None` restricts to `http://localhost` only.
    pub allowed_origins: Option<Vec<String>>,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 3100)),
            allowed_origins: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------

/// Per-session state for a connected SSE client.
struct Session {
    /// Channel for sending SSE events to this session's stream.
    sse_tx: broadcast::Sender<String>,
}

/// Shared state across all HTTP handlers.
struct ServerState {
    /// Active sessions keyed by session ID.
    sessions: Mutex<HashMap<String, Session>>,
    /// Channel where inbound client messages (from POST /message) are queued
    /// for the proxy to consume via `HttpReader::recv`.
    inbound_tx: mpsc::Sender<McpMessage>,
    /// Notification for graceful shutdown.
    shutdown: Notify,
}

// ---------------------------------------------------------------------------
// Public transport types
// ---------------------------------------------------------------------------

/// Handle to the running HTTP+SSE server. Holds the resources needed to
/// interact with connected clients.
pub struct HttpTransport {
    /// The address the server is actually listening on (useful when port 0 is used).
    pub local_addr: SocketAddr,
    /// Join handle for the server task.
    server_handle: tokio::task::JoinHandle<()>,
    /// Shared state so we can trigger shutdown.
    state: Arc<ServerState>,
    /// Receiver half for inbound client messages.
    inbound_rx: mpsc::Receiver<McpMessage>,
}

/// Reader half — receives JSON-RPC messages posted by SSE clients.
pub struct HttpReader {
    inbound_rx: mpsc::Receiver<McpMessage>,
}

/// Writer half — sends JSON-RPC messages to connected SSE clients.
pub struct HttpWriter {
    state: Arc<ServerState>,
}

impl HttpTransport {
    /// Start the HTTP+SSE server. Returns once the server is listening.
    pub async fn start(config: HttpTransportConfig) -> Result<Self, DomeError> {
        let (inbound_tx, inbound_rx) = mpsc::channel::<McpMessage>(512);

        let state = Arc::new(ServerState {
            sessions: Mutex::new(HashMap::new()),
            inbound_tx,
            shutdown: Notify::new(),
        });

        let cors = build_cors_layer(&config.allowed_origins);

        let app = Router::new()
            .route("/sse", get(handle_sse))
            .route("/message", post(handle_message))
            .layer(DefaultBodyLimit::max(256 * 1024))
            .layer(cors)
            .with_state(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind(config.bind_addr)
            .await
            .map_err(DomeError::Transport)?;

        let local_addr = listener.local_addr().map_err(DomeError::Transport)?;

        info!(%local_addr, "HTTP+SSE transport listening");

        let shutdown_state = Arc::clone(&state);
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown_state.shutdown.notified().await;
                })
                .await
                .ok();
        });

        Ok(Self {
            local_addr,
            server_handle,
            state,
            inbound_rx,
        })
    }

    /// Split into independent reader and writer halves for concurrent use.
    pub fn split(self) -> (HttpReader, HttpWriter, HttpTransportHandle) {
        (
            HttpReader {
                inbound_rx: self.inbound_rx,
            },
            HttpWriter {
                state: Arc::clone(&self.state),
            },
            HttpTransportHandle {
                state: self.state,
                server_handle: self.server_handle,
                local_addr: self.local_addr,
            },
        )
    }
}

/// Handle that owns the server lifecycle. Drop or call `shutdown()` to stop.
pub struct HttpTransportHandle {
    state: Arc<ServerState>,
    server_handle: tokio::task::JoinHandle<()>,
    pub local_addr: SocketAddr,
}

impl HttpTransportHandle {
    /// Gracefully shut down the HTTP server and clean up all sessions.
    pub async fn shutdown(self) {
        info!("shutting down HTTP+SSE transport");
        self.state.shutdown.notify_one();
        let _ = self.server_handle.await;
        // Drop all sessions
        self.state.sessions.lock().await.clear();
    }
}

impl HttpReader {
    /// Read the next JSON-RPC message sent by a client via `POST /message`.
    pub async fn recv(&mut self) -> Result<McpMessage, DomeError> {
        self.inbound_rx.recv().await.ok_or_else(|| {
            DomeError::Transport(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "all HTTP clients disconnected",
            ))
        })
    }
}

impl HttpWriter {
    /// Send a JSON-RPC message to a specific session via its SSE stream.
    pub async fn send_to(&self, session_id: &str, msg: &McpMessage) -> Result<(), DomeError> {
        let json = msg.to_json().map_err(DomeError::Json)?;
        let sessions = self.state.sessions.lock().await;
        if let Some(session) = sessions.get(session_id) {
            session.sse_tx.send(json).map_err(|_| {
                DomeError::Transport(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("SSE client disconnected: session {session_id}"),
                ))
            })?;
            Ok(())
        } else {
            Err(DomeError::Transport(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("no active session: {session_id}"),
            )))
        }
    }

    /// Broadcast a JSON-RPC message to all connected SSE sessions.
    pub async fn send(&self, msg: &McpMessage) -> Result<(), DomeError> {
        let json = msg.to_json().map_err(DomeError::Json)?;
        let sessions = self.state.sessions.lock().await;
        if sessions.is_empty() {
            return Err(DomeError::Transport(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "no active SSE sessions",
            )));
        }
        for (id, session) in sessions.iter() {
            if session.sse_tx.send(json.clone()).is_err() {
                warn!(session_id = %id, "failed to send to disconnected SSE client");
            }
        }
        Ok(())
    }

    /// Return the IDs of all currently connected sessions.
    pub async fn active_sessions(&self) -> Vec<String> {
        self.state.sessions.lock().await.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Axum handlers
// ---------------------------------------------------------------------------

/// Query params for the POST /message endpoint.
#[derive(Deserialize)]
struct MessageQuery {
    #[serde(rename = "sessionId")]
    session_id: String,
}

/// `GET /sse` — establish an SSE stream for server-to-client messages.
///
/// On connection the server sends an `endpoint` event with the URL the client
/// should POST messages to, including the assigned session ID.
async fn handle_sse(
    State(state): State<Arc<ServerState>>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let session_id = Uuid::new_v4().to_string();
    let (sse_tx, sse_rx) = broadcast::channel::<String>(256);

    state
        .sessions
        .lock()
        .await
        .insert(session_id.clone(), Session { sse_tx });

    info!(session_id = %session_id, "SSE client connected");

    // Build the endpoint URL the client should use for POSTing messages.
    let endpoint_url = format!("/message?sessionId={session_id}");

    let stream = async_stream::stream! {
        // First event: tell the client where to POST.
        yield Ok(Event::default().event("endpoint").data(endpoint_url));

        // Subsequent events: relay server messages.
        let mut rx = BroadcastStream::new(sse_rx);
        while let Some(item) = rx.next().await {
            match item {
                Ok(json) => {
                    yield Ok(Event::default().event("message").data(json));
                }
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                    warn!(lagged = n, "SSE client lagged, dropped messages");
                    continue;
                }
            }
        }
    };

    // Clean up session when the stream ends.
    // We use a wrapper stream that removes the session on drop.
    let cleanup_state = Arc::clone(&state);
    let cleanup_id = session_id.clone();
    let stream = CleanupStream {
        inner: Box::pin(stream),
        state: cleanup_state,
        session_id: cleanup_id,
        cleaned: false,
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// `POST /message?sessionId=<id>` — receive a JSON-RPC message from a client.
async fn handle_message(
    State(state): State<Arc<ServerState>>,
    Query(query): Query<MessageQuery>,
    Json(msg): Json<McpMessage>,
) -> impl IntoResponse {
    let session_id = &query.session_id;

    // Verify the session exists.
    {
        let sessions = state.sessions.lock().await;
        if !sessions.contains_key(session_id) {
            debug!(session_id = %session_id, "POST to unknown session");
            return StatusCode::NOT_FOUND;
        }
    }

    debug!(
        session_id = %session_id,
        method = msg.method.as_deref().unwrap_or("-"),
        "inbound message from HTTP client"
    );

    // Forward to the proxy's inbound channel.
    if state.inbound_tx.send(msg).await.is_err() {
        error!("inbound channel closed — proxy shut down?");
        return StatusCode::SERVICE_UNAVAILABLE;
    }

    StatusCode::ACCEPTED
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

fn build_cors_layer(allowed_origins: &Option<Vec<String>>) -> CorsLayer {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT]);

    match allowed_origins {
        Some(origins) if !origins.is_empty() => {
            let parsed: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
            cors.allow_origin(AllowOrigin::list(parsed))
        }
        _ => cors.allow_origin(AllowOrigin::exact(
            "http://localhost"
                .parse()
                .expect("static 'http://localhost' is always a valid HeaderValue"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Cleanup stream wrapper — removes session on drop
// ---------------------------------------------------------------------------

use std::pin::Pin;
use std::task::{Context, Poll};

/// A wrapper stream that cleans up the session from the server state when the
/// SSE connection is dropped (client disconnects).
struct CleanupStream {
    inner: Pin<Box<dyn Stream<Item = Result<Event, std::convert::Infallible>> + Send>>,
    state: Arc<ServerState>,
    session_id: String,
    cleaned: bool,
}

impl Drop for CleanupStream {
    fn drop(&mut self) {
        if !self.cleaned {
            self.cleaned = true;
            let state = Arc::clone(&self.state);
            let id = self.session_id.clone();
            tokio::spawn(async move {
                info!(session_id = %id, "SSE client disconnected — cleaning up session");
                state.sessions.lock().await.remove(&id);
            });
        }
    }
}

impl Stream for CleanupStream {
    type Item = Result<Event, std::convert::Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    /// Helper: start a transport on an ephemeral port.
    async fn start_test_transport() -> (HttpReader, HttpWriter, HttpTransportHandle) {
        let config = HttpTransportConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            allowed_origins: Some(vec!["https://example.com".to_string()]),
        };
        let transport = HttpTransport::start(config).await.unwrap();
        transport.split()
    }

    /// Connect to SSE, spawn a background task that reads chunks, and return
    /// the session ID plus a channel for receiving subsequent SSE data lines.
    async fn connect_sse(
        addr: SocketAddr,
    ) -> (String, mpsc::Receiver<String>, tokio::task::JoinHandle<()>) {
        let (data_tx, data_rx) = mpsc::channel::<String>(64);
        let (session_tx, mut session_rx) = mpsc::channel::<String>(1);

        let handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut resp = client
                .get(format!("http://{addr}/sse"))
                .header("Accept", "text/event-stream")
                .send()
                .await
                .unwrap();

            let mut buf = String::new();
            let mut session_sent = false;

            while let Some(chunk) = resp.chunk().await.unwrap() {
                buf.push_str(&String::from_utf8_lossy(&chunk));

                // Process all complete lines.
                while let Some(newline_pos) = buf.find('\n') {
                    let line: String = buf.drain(..=newline_pos).collect();
                    let trimmed = line.trim();
                    if let Some(data) = trimmed.strip_prefix("data: ") {
                        if !session_sent {
                            let _ = session_tx
                                .send(data.replace("/message?sessionId=", ""))
                                .await;
                            session_sent = true;
                        } else {
                            let _ = data_tx.send(data.to_string()).await;
                        }
                    }
                }
            }
        });

        let session_id = timeout(Duration::from_secs(3), session_rx.recv())
            .await
            .expect("timed out waiting for session ID")
            .expect("SSE task closed before sending session ID");

        (session_id, data_rx, handle)
    }

    #[tokio::test]
    async fn test_sse_connection_establishment() {
        let (_reader, writer, handle) = start_test_transport().await;
        let addr = handle.local_addr;

        let (session_id, _data_rx, sse_handle) = connect_sse(addr).await;

        // Verify a session was registered.
        let sessions = writer.active_sessions().await;
        assert!(
            sessions.contains(&session_id),
            "session {session_id} should be in active sessions: {sessions:?}"
        );

        sse_handle.abort();
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_message_roundtrip() {
        let (mut reader, writer, handle) = start_test_transport().await;
        let addr = handle.local_addr;

        let (session_id, mut data_rx, sse_handle) = connect_sse(addr).await;

        // POST a JSON-RPC message.
        let client = reqwest::Client::new();
        let msg_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"capabilities": {}}
        });

        let post_resp = client
            .post(format!("http://{addr}/message?sessionId={session_id}"))
            .json(&msg_json)
            .send()
            .await
            .unwrap();

        assert_eq!(post_resp.status(), 202);

        // The reader should receive the message.
        let received = timeout(Duration::from_secs(2), reader.recv())
            .await
            .expect("timed out waiting for inbound message")
            .expect("error receiving message");

        assert_eq!(received.method.as_deref(), Some("initialize"));
        assert_eq!(received.id, Some(serde_json::json!(1)));

        // Send a response back through the writer to the SSE stream.
        let response_msg = McpMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: None,
            params: None,
            result: Some(serde_json::json!({"capabilities": {}})),
            error: None,
        };
        writer.send_to(&session_id, &response_msg).await.unwrap();

        // Read the SSE data line from the background reader.
        let received_json = timeout(Duration::from_secs(2), data_rx.recv())
            .await
            .expect("timed out reading SSE response")
            .expect("SSE channel closed");

        let received_msg: McpMessage = serde_json::from_str(&received_json)
            .expect("failed to parse SSE response as McpMessage");
        assert!(received_msg.is_response());
        assert_eq!(received_msg.id, Some(serde_json::json!(1)));

        sse_handle.abort();
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_cors_headers() {
        let (_reader, _writer, handle) = start_test_transport().await;
        let addr = handle.local_addr;

        let client = reqwest::Client::new();

        let resp = client
            .request(
                reqwest::Method::OPTIONS,
                format!("http://{addr}/message?sessionId=test"),
            )
            .header("Origin", "https://example.com")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "content-type")
            .send()
            .await
            .unwrap();

        let headers = resp.headers();
        let allow_origin = headers
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or(""));

        assert!(
            allow_origin.is_some(),
            "expected access-control-allow-origin header"
        );

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_post_to_unknown_session_returns_404() {
        let (_reader, _writer, handle) = start_test_transport().await;
        let addr = handle.local_addr;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/message?sessionId=nonexistent"))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "test"
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_connection_close_cleanup() {
        let (_reader, writer, handle) = start_test_transport().await;
        let addr = handle.local_addr;

        let (session_id, _data_rx, sse_handle) = connect_sse(addr).await;

        // Verify session is active.
        let sessions = writer.active_sessions().await;
        assert!(sessions.contains(&session_id), "session should be active");

        // Abort the SSE reader task (simulates client disconnect).
        sse_handle.abort();

        // Give the cleanup task time to run.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let sessions_after = writer.active_sessions().await;
        assert!(
            !sessions_after.contains(&session_id),
            "session should have been cleaned up after disconnect"
        );

        handle.shutdown().await;
    }
}
