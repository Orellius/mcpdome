use async_trait::async_trait;
use dome_core::{DomeError, McpMessage};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::{Duration, timeout};
use tracing::{debug, info};

use crate::Transport;

const MAX_LINE_SIZE: usize = 10 * 1024 * 1024; // 10 MB
const READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Stdio transport that spawns an MCP server as a child process
/// and communicates via stdin/stdout (newline-delimited JSON-RPC).
pub struct StdioTransport {
    child: Child,
    reader: BufReader<ChildStdout>,
    writer: ChildStdin,
}

/// Reader half — reads messages from a child process stdout.
pub struct StdioReader {
    reader: BufReader<ChildStdout>,
}

/// Writer half — writes messages to a child process stdin.
pub struct StdioWriter {
    writer: ChildStdin,
}

impl StdioTransport {
    /// Spawn the downstream MCP server and capture its stdio.
    pub async fn spawn(command: &str, args: &[&str]) -> Result<Self, DomeError> {
        info!(command, ?args, "spawning MCP server");

        let mut child = Command::new(command)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit()) // let server stderr pass through
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| DomeError::Internal("failed to capture child stdout".into()))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| DomeError::Internal("failed to capture child stdin".into()))?;

        Ok(Self {
            child,
            reader: BufReader::new(stdout),
            writer: stdin,
        })
    }

    /// Split into independent reader and writer halves for concurrent use.
    pub fn split(self) -> (StdioReader, StdioWriter, Child) {
        (
            StdioReader {
                reader: self.reader,
            },
            StdioWriter {
                writer: self.writer,
            },
            self.child,
        )
    }
}

impl StdioReader {
    /// Read the next newline-delimited JSON-RPC message.
    pub async fn recv(&mut self) -> Result<McpMessage, DomeError> {
        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = timeout(READ_TIMEOUT, self.reader.read_line(&mut line))
                .await
                .map_err(|_| {
                    DomeError::Transport(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "read from server timed out",
                    ))
                })??;
            if bytes_read == 0 {
                return Err(DomeError::Transport(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "server closed stdout",
                )));
            }

            if line.len() > MAX_LINE_SIZE {
                return Err(DomeError::Transport(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("line exceeds maximum size of {MAX_LINE_SIZE} bytes"),
                )));
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            debug!(raw = trimmed, "recv from server");
            return McpMessage::parse(trimmed).map_err(DomeError::Json);
        }
    }
}

impl StdioWriter {
    /// Send a JSON-RPC message followed by a newline.
    pub async fn send(&mut self, msg: &McpMessage) -> Result<(), DomeError> {
        let json = msg.to_json()?;
        debug!(raw = json.as_str(), "send to server");
        timeout(WRITE_TIMEOUT, async {
            self.writer.write_all(json.as_bytes()).await?;
            self.writer.write_all(b"\n").await?;
            self.writer.flush().await?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| {
            DomeError::Transport(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write to server timed out",
            ))
        })??;
        Ok(())
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn recv(&mut self) -> Result<McpMessage, DomeError> {
        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = timeout(READ_TIMEOUT, self.reader.read_line(&mut line))
                .await
                .map_err(|_| {
                    DomeError::Transport(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "read from server timed out",
                    ))
                })??;
            if bytes_read == 0 {
                return Err(DomeError::Transport(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "server closed stdout",
                )));
            }

            if line.len() > MAX_LINE_SIZE {
                return Err(DomeError::Transport(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("line exceeds maximum size of {MAX_LINE_SIZE} bytes"),
                )));
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            debug!(raw = trimmed, "recv from server");
            return McpMessage::parse(trimmed).map_err(DomeError::Json);
        }
    }

    async fn send(&mut self, msg: &McpMessage) -> Result<(), DomeError> {
        let json = msg.to_json()?;
        debug!(raw = json.as_str(), "send to server");
        timeout(WRITE_TIMEOUT, async {
            self.writer.write_all(json.as_bytes()).await?;
            self.writer.write_all(b"\n").await?;
            self.writer.flush().await?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| {
            DomeError::Transport(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write to server timed out",
            ))
        })??;
        Ok(())
    }

    async fn close(&mut self) -> Result<(), DomeError> {
        info!("shutting down child process");
        drop(self.child.stdin.take());
        self.child.wait().await?;
        Ok(())
    }
}
