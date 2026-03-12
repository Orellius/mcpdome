//! OAuth 2.0 authenticator stub for MCPDome.
//!
//! This module provides the structural scaffolding for JWT-based OAuth 2.0
//! authentication. The actual JWT validation (JWKS fetching, signature
//! verification, claims extraction) will be implemented in a future phase.

use async_trait::async_trait;
use dome_core::McpMessage;

use crate::auth::{AuthOutcome, Authenticator};

/// OAuth 2.0 authenticator configuration.
///
/// Validates JWT access tokens against a JWKS endpoint published by the
/// identity provider. Currently a stub that rejects all attempts with a
/// clear "not yet implemented" message.
pub struct OAuth2Authenticator {
    /// The expected token issuer (e.g. "https://auth.example.com").
    pub issuer: String,

    /// URL to fetch the JSON Web Key Set for token verification.
    pub jwks_url: String,

    /// The expected audience claim in the JWT.
    pub audience: String,
}

impl OAuth2Authenticator {
    pub fn new(issuer: String, jwks_url: String, audience: String) -> Self {
        Self {
            issuer,
            jwks_url,
            audience,
        }
    }
}

#[async_trait]
impl Authenticator for OAuth2Authenticator {
    async fn authenticate(&self, msg: &McpMessage) -> AuthOutcome {
        // Only applies to initialize requests.
        if msg.method.as_deref() != Some("initialize") {
            return AuthOutcome::NotApplicable;
        }

        // Check if the message contains an OAuth2 token field.
        let has_token = msg
            .params
            .as_ref()
            .and_then(|p| p.get("_mcpdome_oauth_token"))
            .is_some();

        if !has_token {
            return AuthOutcome::NotApplicable;
        }

        // Stub: reject with a clear message indicating this is not yet implemented.
        AuthOutcome::Failed("OAuth2 not yet implemented".to_string())
    }

    fn name(&self) -> &'static str {
        "oauth2"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_initialize_msg(token: Option<&str>) -> McpMessage {
        let mut params = json!({"capabilities": {}});
        if let Some(t) = token {
            params
                .as_object_mut()
                .unwrap()
                .insert("_mcpdome_oauth_token".to_string(), json!(t));
        }
        McpMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: Some("initialize".to_string()),
            params: Some(params),
            result: None,
            error: None,
        }
    }

    #[tokio::test]
    async fn oauth2_stub_returns_not_applicable_without_token() {
        let auth = OAuth2Authenticator::new(
            "https://auth.example.com".to_string(),
            "https://auth.example.com/.well-known/jwks.json".to_string(),
            "mcpdome".to_string(),
        );
        let msg = make_initialize_msg(None);

        match auth.authenticate(&msg).await {
            AuthOutcome::NotApplicable => {} // correct
            other => panic!("expected NotApplicable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oauth2_stub_returns_failed_with_token() {
        let auth = OAuth2Authenticator::new(
            "https://auth.example.com".to_string(),
            "https://auth.example.com/.well-known/jwks.json".to_string(),
            "mcpdome".to_string(),
        );
        let msg = make_initialize_msg(Some("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."));

        match auth.authenticate(&msg).await {
            AuthOutcome::Failed(reason) => {
                assert!(
                    reason.contains("not yet implemented"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oauth2_stub_not_applicable_for_non_initialize() {
        let auth = OAuth2Authenticator::new(
            "https://auth.example.com".to_string(),
            "https://auth.example.com/.well-known/jwks.json".to_string(),
            "mcpdome".to_string(),
        );
        let msg = McpMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: Some("tools/call".to_string()),
            params: Some(json!({"name": "read_file"})),
            result: None,
            error: None,
        };

        match auth.authenticate(&msg).await {
            AuthOutcome::NotApplicable => {} // correct
            other => panic!("expected NotApplicable, got {other:?}"),
        }
    }
}
