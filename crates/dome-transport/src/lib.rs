pub mod stdio;

#[cfg(feature = "http")]
pub mod http;

use async_trait::async_trait;
use dome_core::{DomeError, McpMessage};

/// Transport abstraction — read/write MCP messages over any wire protocol.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Read the next message from this transport.
    async fn recv(&mut self) -> Result<McpMessage, DomeError>;

    /// Send a message through this transport.
    async fn send(&mut self, msg: &McpMessage) -> Result<(), DomeError>;

    /// Graceful shutdown.
    async fn close(&mut self) -> Result<(), DomeError>;
}
