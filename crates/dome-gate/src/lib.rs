use dome_core::{DomeError, McpMessage};
use dome_transport::stdio::StdioTransport;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info, warn};

/// The Gate — MCPDome's core proxy loop.
///
/// Phase 1 (v0.1): Transparent pass-through. Every message from the client
/// is forwarded to the server, and every response is forwarded back.
/// No interception, no modification. Proves the proxy works.
///
/// Later phases will insert the interceptor chain here.
pub struct Gate;

impl Gate {
    /// Run the transparent proxy.
    ///
    /// Reads from our own stdin (the MCP client), forwards to the child server,
    /// reads the child server's responses, and writes them to our stdout.
    pub async fn run_stdio(command: &str, args: &[&str]) -> Result<(), DomeError> {
        // Spawn the downstream MCP server
        let transport = StdioTransport::spawn(command, args).await?;
        let (mut server_reader, mut server_writer, mut child) = transport.split();

        // Our stdin/stdout — the MCP client talks to us here
        let client_stdin = tokio::io::stdin();
        let client_stdout = tokio::io::stdout();
        let mut client_reader = BufReader::new(client_stdin);
        let mut client_writer = client_stdout;

        info!("MCPDome proxy active — forwarding traffic");

        // Two concurrent tasks: client→server and server→client
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

                        // Parse to validate it's valid JSON-RPC
                        match McpMessage::parse(trimmed) {
                            Ok(msg) => {
                                debug!(
                                    method = msg.method.as_deref().unwrap_or("-"),
                                    id = ?msg.id,
                                    tool = msg.tool_name().unwrap_or("-"),
                                    "client -> server"
                                );

                                // v0.1: pass through unchanged
                                // TODO: interceptor chain goes here
                                if let Err(e) = server_writer.send(&msg).await {
                                    error!(%e, "failed to forward to server");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(%e, raw = trimmed, "invalid JSON from client, forwarding raw");
                                // Forward raw even if we can't parse — be transparent
                                let _ = server_writer.send(&McpMessage {
                                    jsonrpc: "2.0".to_string(),
                                    id: None,
                                    method: None,
                                    params: None,
                                    result: None,
                                    error: None,
                                }).await;
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

        let server_to_client = tokio::spawn(async move {
            loop {
                match server_reader.recv().await {
                    Ok(msg) => {
                        debug!(
                            method = msg.method.as_deref().unwrap_or("-"),
                            id = ?msg.id,
                            "server -> client"
                        );

                        // v0.1: pass through unchanged
                        // TODO: outbound interceptor chain goes here
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

        // Clean up child process
        let _ = child.kill().await;
        info!("MCPDome proxy shut down");

        Ok(())
    }
}
