use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;

/// How a caller proved their identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMethod {
    /// Kernel-attested Unix peer credentials (uid/gid/pid).
    UnixPeerCreds { uid: u32, gid: u32, pid: u32 },

    /// Pre-shared key sent in initialize params.
    PreSharedKey { key_id: String },

    /// API key sent in initialize params.
    ApiKey { key_id: String },

    /// OAuth 2.0 JWT bearer token.
    OAuth2 {
        issuer: String,
        subject: String,
        scopes: Vec<String>,
    },

    /// Mutual TLS client certificate.
    MutualTls { fingerprint: String, cn: String },

    /// No credentials provided.
    Anonymous,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnixPeerCreds { uid, gid, pid } => {
                write!(f, "unix_peer_creds(uid={uid}, gid={gid}, pid={pid})")
            }
            Self::PreSharedKey { key_id } => write!(f, "psk(key_id={key_id})"),
            Self::ApiKey { key_id } => write!(f, "api_key(key_id={key_id})"),
            Self::OAuth2 {
                issuer, subject, ..
            } => write!(f, "oauth2(issuer={issuer}, subject={subject})"),
            Self::MutualTls { fingerprint, cn } => {
                write!(f, "mtls(cn={cn}, fingerprint={fingerprint})")
            }
            Self::Anonymous => write!(f, "anonymous"),
        }
    }
}

/// Resolved identity of an MCP caller.
///
/// Created by an `Authenticator` during the initialize handshake,
/// then carried through the interceptor chain for policy evaluation.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Principal identifier, e.g. "psk:dev-key-1", "uid:501", "anonymous".
    pub principal: String,

    /// How the identity was authenticated.
    pub auth_method: AuthMethod,

    /// Policy-matchable labels, e.g. {"role:developer", "env:staging"}.
    pub labels: HashSet<String>,

    /// When this identity was resolved. Not serialized (Instant is monotonic).
    pub resolved_at: Instant,
}

impl Identity {
    /// Create an anonymous identity with no labels.
    pub fn anonymous() -> Self {
        Self {
            principal: "anonymous".to_string(),
            auth_method: AuthMethod::Anonymous,
            labels: HashSet::new(),
            resolved_at: Instant::now(),
        }
    }

    /// Check whether this identity carries a specific label.
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.contains(label)
    }
}
