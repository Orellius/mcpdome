use dome_core::DomeError;
use tracing::{debug, info};

use crate::auth::{AuthOutcome, Authenticator};
use crate::identity::Identity;

/// Configuration for the identity resolver.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// If true, anonymous access is permitted when no authenticator succeeds.
    /// If false, a missing/invalid credential results in AuthFailed.
    pub allow_anonymous: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            allow_anonymous: false,
        }
    }
}

/// Chains multiple `Authenticator` implementations and resolves the first
/// successful identity. Order matters: authenticators are tried sequentially,
/// and the first definitive result wins.
///
/// - `Authenticated` => stop, use that identity
/// - `NotApplicable` => skip, try next authenticator
/// - `Failed` => stop immediately, reject the request (credentials were
///   present but invalid, so we should not fall through to anonymous)
pub struct IdentityResolver {
    authenticators: Vec<Box<dyn Authenticator>>,
    config: ResolverConfig,
}

impl IdentityResolver {
    pub fn new(authenticators: Vec<Box<dyn Authenticator>>, config: ResolverConfig) -> Self {
        Self {
            authenticators,
            config,
        }
    }

    /// Resolve the caller's identity from an MCP message (typically `initialize`).
    pub async fn resolve(
        &self,
        msg: &dome_core::McpMessage,
    ) -> Result<Identity, DomeError> {
        for auth in &self.authenticators {
            match auth.authenticate(msg).await {
                AuthOutcome::Authenticated(identity) => {
                    info!(
                        principal = %identity.principal,
                        method = %identity.auth_method,
                        "identity resolved via {}",
                        auth.name()
                    );
                    return Ok(identity);
                }
                AuthOutcome::NotApplicable => {
                    debug!(authenticator = auth.name(), "not applicable, trying next");
                    continue;
                }
                AuthOutcome::Failed(reason) => {
                    info!(
                        authenticator = auth.name(),
                        reason = %reason,
                        "authentication failed"
                    );
                    return Err(DomeError::AuthFailed { reason });
                }
            }
        }

        // No authenticator matched. Fall back to anonymous if allowed.
        if self.config.allow_anonymous {
            info!("no credentials found, allowing anonymous access");
            Ok(Identity::anonymous())
        } else {
            Err(DomeError::AuthFailed {
                reason: "no valid credentials provided".to_string(),
            })
        }
    }
}
