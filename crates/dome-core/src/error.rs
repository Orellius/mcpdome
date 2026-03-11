use thiserror::Error;

/// Unified error taxonomy for MCPDome.
///
/// Every error maps to a JSON-RPC error code so we can send
/// meaningful responses back to the MCP client.
#[derive(Debug, Error)]
pub enum DomeError {
    #[error("authentication failed: {reason}")]
    AuthFailed { reason: String },

    #[error("denied by policy: rule={rule_id}, tool={tool}")]
    PolicyDenied { rule_id: String, tool: String },

    #[error("rate limit exceeded: {limit} req/{window}")]
    RateLimited { limit: u64, window: String },

    #[error("budget exhausted: {spent}/{cap} {unit}")]
    BudgetExhausted { spent: f64, cap: f64, unit: String },

    #[error("injection detected: {pattern} in {field}")]
    InjectionDetected { pattern: String, field: String },

    #[error("schema drift: tool={tool}, field={field}")]
    SchemaDrift { tool: String, field: String },

    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),

    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl DomeError {
    /// Map this error to a JSON-RPC error code.
    pub fn rpc_code(&self) -> i64 {
        match self {
            Self::AuthFailed { .. } => -32001,
            Self::PolicyDenied { .. } => -32002,
            Self::RateLimited { .. } => -32003,
            Self::BudgetExhausted { .. } => -32004,
            Self::InjectionDetected { .. } => -32005,
            Self::SchemaDrift { .. } => -32006,
            Self::Transport(_) => -32000,
            Self::Json(_) => -32700,       // Parse error (JSON-RPC standard)
            Self::Upstream(_) => -32000,
            Self::Internal(_) => -32603,   // Internal error (JSON-RPC standard)
        }
    }
}
