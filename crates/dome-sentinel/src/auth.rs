use std::collections::{HashMap, HashSet};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use password_hash::rand_core::OsRng;
use async_trait::async_trait;
use dome_core::McpMessage;
use serde_json::Value;
use tracing::{debug, warn};

use crate::identity::{AuthMethod, Identity};

/// Outcome of a single authenticator attempt.
#[derive(Debug)]
pub enum AuthOutcome {
    /// Authentication succeeded; here is the identity.
    Authenticated(Identity),

    /// This authenticator does not apply to the given message
    /// (e.g. no PSK field found). The resolver should try the next one.
    NotApplicable,

    /// Credentials were present but invalid. Stop the chain and reject.
    Failed(String),
}

/// Trait implemented by each authentication strategy (PSK, Unix creds, etc.).
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Attempt to authenticate from the given initialize message.
    ///
    /// Returns `NotApplicable` if this authenticator's credential type
    /// is not present, allowing the resolver to try the next strategy.
    async fn authenticate(&self, msg: &McpMessage) -> AuthOutcome;

    /// Human-readable name for logging.
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// PSK Authenticator
// ---------------------------------------------------------------------------

/// Configuration for a single pre-shared key.
#[derive(Debug, Clone)]
pub struct PskEntry {
    /// The raw key value clients must send.
    pub secret: String,

    /// A stable identifier for this key (used in Identity.principal and audit logs).
    pub key_id: String,

    /// Labels assigned to anyone authenticating with this key.
    pub labels: HashSet<String>,
}

/// Internal entry storing the Argon2id hash of the PSK secret.
struct HashedPskEntry {
    /// Argon2id hash of the secret (PHC string format).
    hashed_secret: String,

    /// A stable identifier for this key.
    key_id: String,

    /// Labels assigned to anyone authenticating with this key.
    labels: HashSet<String>,
}

/// Authenticates clients via a `_mcpdome_psk` field in the `initialize` params.
///
/// On construction, all PSK secrets are hashed with Argon2id so that the
/// raw secrets are never stored in memory beyond initialization. On
/// authentication, the provided PSK is hashed and verified using constant-time
/// comparison (provided by the argon2 crate's verify method).
pub struct PskAuthenticator {
    /// Map from key_id to hashed entry. Keyed by identifier, not raw secret.
    entries: HashMap<String, HashedPskEntry>,
}

/// Create an Argon2id hasher with secure defaults.
fn argon2_hasher() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(16 * 1024, 2, 1, None).expect("valid Argon2 params"),
    )
}

impl PskAuthenticator {
    pub fn new(entries: Vec<PskEntry>) -> Self {
        let argon2 = argon2_hasher();
        let hashed_entries: HashMap<String, HashedPskEntry> = entries
            .into_iter()
            .map(|e| {
                let salt = SaltString::generate(&mut OsRng);
                let hashed = argon2
                    .hash_password(e.secret.as_bytes(), &salt)
                    .expect("Argon2 hashing should not fail with valid params")
                    .to_string();

                (
                    e.key_id.clone(),
                    HashedPskEntry {
                        hashed_secret: hashed,
                        key_id: e.key_id,
                        labels: e.labels,
                    },
                )
            })
            .collect();

        Self {
            entries: hashed_entries,
        }
    }

    /// Extract the `_mcpdome_psk` value from an initialize message's params, if present.
    pub fn extract_psk(msg: &McpMessage) -> Option<String> {
        let params = msg.params.as_ref()?;
        params.get("_mcpdome_psk")?.as_str().map(String::from)
    }

    /// Remove the `_mcpdome_psk` field from the message params so it is not
    /// forwarded to the downstream MCP server. Returns a new message.
    pub fn strip_psk(msg: &McpMessage) -> McpMessage {
        let mut stripped = msg.clone();
        if let Some(Value::Object(ref mut map)) = stripped.params {
            map.remove("_mcpdome_psk");
        }
        stripped
    }

    /// Verify a provided PSK against all stored hashes.
    ///
    /// Uses Argon2id verification which performs constant-time comparison
    /// internally, preventing timing side-channel attacks.
    fn verify_psk(&self, provided_secret: &str) -> Option<&HashedPskEntry> {
        let argon2 = argon2_hasher();

        for entry in self.entries.values() {
            let parsed_hash = match PasswordHash::new(&entry.hashed_secret) {
                Ok(h) => h,
                Err(_) => continue,
            };
            if argon2
                .verify_password(provided_secret.as_bytes(), &parsed_hash)
                .is_ok()
            {
                return Some(entry);
            }
        }
        None
    }
}

#[async_trait]
impl Authenticator for PskAuthenticator {
    async fn authenticate(&self, msg: &McpMessage) -> AuthOutcome {
        // Only applies to initialize requests.
        if msg.method.as_deref() != Some("initialize") {
            return AuthOutcome::NotApplicable;
        }

        let psk_value = match Self::extract_psk(msg) {
            Some(v) => v,
            None => return AuthOutcome::NotApplicable,
        };

        match self.verify_psk(&psk_value) {
            Some(entry) => {
                debug!(key_id = %entry.key_id, "PSK authentication succeeded");
                AuthOutcome::Authenticated(Identity {
                    principal: format!("psk:{}", entry.key_id),
                    auth_method: AuthMethod::PreSharedKey {
                        key_id: entry.key_id.clone(),
                    },
                    labels: entry.labels.clone(),
                    resolved_at: std::time::Instant::now(),
                })
            }
            None => {
                warn!("PSK authentication failed: unknown key");
                AuthOutcome::Failed("invalid pre-shared key".to_string())
            }
        }
    }

    fn name(&self) -> &'static str {
        "psk"
    }
}

// ---------------------------------------------------------------------------
// Anonymous Authenticator
// ---------------------------------------------------------------------------

/// Fallback authenticator that always succeeds with an anonymous identity.
/// Whether anonymous access is actually permitted is controlled by the
/// `IdentityResolver` configuration, not by this authenticator itself.
pub struct AnonymousAuthenticator;

#[async_trait]
impl Authenticator for AnonymousAuthenticator {
    async fn authenticate(&self, _msg: &McpMessage) -> AuthOutcome {
        debug!("anonymous authentication fallback");
        AuthOutcome::Authenticated(Identity::anonymous())
    }

    fn name(&self) -> &'static str {
        "anonymous"
    }
}
