//! `dome-sentinel` -- Authentication & identity resolution for MCPDome.
//!
//! This crate resolves raw MCP connections into typed `Identity` values
//! by chaining pluggable `Authenticator` strategies. Phase 2 (stdio)
//! supports pre-shared key and anonymous authentication.

pub mod auth;
pub mod identity;
pub mod oauth;
pub mod resolver;

pub use auth::{
    AnonymousAuthenticator, ApiKeyAuthenticator, ApiKeyEntry, AuthOutcome, Authenticator,
    PskAuthenticator, PskEntry,
};
pub use identity::{AuthMethod, Identity};
pub use oauth::OAuth2Authenticator;
pub use resolver::{IdentityResolver, ResolverConfig};

#[cfg(test)]
mod tests {
    use super::*;
    use dome_core::McpMessage;
    use serde_json::json;
    use std::collections::HashSet;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_initialize_msg(psk: Option<&str>) -> McpMessage {
        let mut params = json!({"capabilities": {}});
        if let Some(key) = psk {
            params
                .as_object_mut()
                .unwrap()
                .insert("_mcpdome_psk".to_string(), json!(key));
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

    fn make_psk_entries() -> Vec<PskEntry> {
        vec![
            PskEntry {
                secret: "secret-dev-123".to_string(),
                key_id: "dev-key-1".to_string(),
                labels: HashSet::from(["role:developer".to_string(), "env:staging".to_string()]),
            },
            PskEntry {
                secret: "secret-admin-456".to_string(),
                key_id: "admin-key-1".to_string(),
                labels: HashSet::from(["role:admin".to_string()]),
            },
        ]
    }

    // -----------------------------------------------------------------------
    // PSK extraction and validation
    // -----------------------------------------------------------------------

    #[test]
    fn extract_psk_from_initialize_params() {
        let msg = make_initialize_msg(Some("secret-dev-123"));
        let psk = PskAuthenticator::extract_psk(&msg);
        assert_eq!(psk, Some("secret-dev-123".to_string()));
    }

    #[test]
    fn extract_psk_returns_none_when_absent() {
        let msg = make_initialize_msg(None);
        let psk = PskAuthenticator::extract_psk(&msg);
        assert_eq!(psk, None);
    }

    #[tokio::test]
    async fn psk_authenticator_succeeds_with_valid_key() {
        let auth = PskAuthenticator::new(make_psk_entries());
        let msg = make_initialize_msg(Some("secret-dev-123"));

        match auth.authenticate(&msg).await {
            AuthOutcome::Authenticated(id) => {
                assert_eq!(id.principal, "psk:dev-key-1");
                assert!(matches!(
                    id.auth_method,
                    AuthMethod::PreSharedKey { ref key_id } if key_id == "dev-key-1"
                ));
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn psk_authenticator_fails_with_invalid_key() {
        let auth = PskAuthenticator::new(make_psk_entries());
        let msg = make_initialize_msg(Some("wrong-key"));

        match auth.authenticate(&msg).await {
            AuthOutcome::Failed(reason) => {
                assert!(reason.contains("invalid"), "reason: {reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn psk_authenticator_not_applicable_for_non_initialize() {
        let auth = PskAuthenticator::new(make_psk_entries());
        let msg = McpMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: Some("tools/call".to_string()),
            params: Some(json!({"name": "read_file", "_mcpdome_psk": "secret-dev-123"})),
            result: None,
            error: None,
        };

        match auth.authenticate(&msg).await {
            AuthOutcome::NotApplicable => {} // correct
            other => panic!("expected NotApplicable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn psk_authenticator_not_applicable_when_no_psk_field() {
        let auth = PskAuthenticator::new(make_psk_entries());
        let msg = make_initialize_msg(None);

        match auth.authenticate(&msg).await {
            AuthOutcome::NotApplicable => {} // correct
            other => panic!("expected NotApplicable, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // PSK stripping from forwarded message
    // -----------------------------------------------------------------------

    #[test]
    fn strip_psk_removes_field_from_params() {
        let msg = make_initialize_msg(Some("secret-dev-123"));

        // Verify the field is present before stripping.
        assert!(msg.params.as_ref().unwrap().get("_mcpdome_psk").is_some());

        let stripped = PskAuthenticator::strip_psk(&msg);

        // Field must be gone.
        assert!(
            stripped
                .params
                .as_ref()
                .unwrap()
                .get("_mcpdome_psk")
                .is_none()
        );

        // Other params must survive.
        assert!(
            stripped
                .params
                .as_ref()
                .unwrap()
                .get("capabilities")
                .is_some()
        );
    }

    #[test]
    fn strip_psk_is_noop_when_field_absent() {
        let msg = make_initialize_msg(None);
        let stripped = PskAuthenticator::strip_psk(&msg);
        assert_eq!(
            msg.params.as_ref().unwrap().to_string(),
            stripped.params.as_ref().unwrap().to_string(),
        );
    }

    // -----------------------------------------------------------------------
    // Anonymous fallback
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn anonymous_authenticator_always_succeeds() {
        let auth = AnonymousAuthenticator;
        let msg = make_initialize_msg(None);

        match auth.authenticate(&msg).await {
            AuthOutcome::Authenticated(id) => {
                assert_eq!(id.principal, "anonymous");
                assert_eq!(id.auth_method, AuthMethod::Anonymous);
                assert!(id.labels.is_empty());
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Identity label assignment
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn psk_auth_assigns_configured_labels() {
        let auth = PskAuthenticator::new(make_psk_entries());
        let msg = make_initialize_msg(Some("secret-dev-123"));

        match auth.authenticate(&msg).await {
            AuthOutcome::Authenticated(id) => {
                assert!(id.has_label("role:developer"));
                assert!(id.has_label("env:staging"));
                assert!(!id.has_label("role:admin"));
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn different_psk_gets_different_labels() {
        let auth = PskAuthenticator::new(make_psk_entries());
        let msg = make_initialize_msg(Some("secret-admin-456"));

        match auth.authenticate(&msg).await {
            AuthOutcome::Authenticated(id) => {
                assert_eq!(id.principal, "psk:admin-key-1");
                assert!(id.has_label("role:admin"));
                assert!(!id.has_label("role:developer"));
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Authenticator chain resolution order (IdentityResolver)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn resolver_returns_first_authenticated_identity() {
        let resolver = IdentityResolver::new(
            vec![
                Box::new(PskAuthenticator::new(make_psk_entries())),
                Box::new(AnonymousAuthenticator),
            ],
            ResolverConfig {
                allow_anonymous: true,
            },
        );

        let msg = make_initialize_msg(Some("secret-dev-123"));
        let identity = resolver.resolve(&msg).await.unwrap();

        // PSK should win over anonymous since it matched first.
        assert_eq!(identity.principal, "psk:dev-key-1");
    }

    #[tokio::test]
    async fn resolver_falls_through_to_anonymous_when_allowed() {
        let resolver = IdentityResolver::new(
            vec![Box::new(PskAuthenticator::new(make_psk_entries()))],
            ResolverConfig {
                allow_anonymous: true,
            },
        );

        // No PSK in the message, so PSK auth returns NotApplicable.
        let msg = make_initialize_msg(None);
        let identity = resolver.resolve(&msg).await.unwrap();

        assert_eq!(identity.principal, "anonymous");
        assert_eq!(identity.auth_method, AuthMethod::Anonymous);
    }

    #[tokio::test]
    async fn resolver_rejects_when_anonymous_denied() {
        let resolver = IdentityResolver::new(
            vec![Box::new(PskAuthenticator::new(make_psk_entries()))],
            ResolverConfig {
                allow_anonymous: false,
            },
        );

        let msg = make_initialize_msg(None);
        let result = resolver.resolve(&msg).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("no valid credentials"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn resolver_stops_on_failed_auth_does_not_fall_through() {
        // If PSK is present but invalid, the resolver must NOT fall
        // through to anonymous. Failed means "credentials were wrong",
        // not "credentials were absent".
        let resolver = IdentityResolver::new(
            vec![
                Box::new(PskAuthenticator::new(make_psk_entries())),
                Box::new(AnonymousAuthenticator),
            ],
            ResolverConfig {
                allow_anonymous: true,
            },
        );

        let msg = make_initialize_msg(Some("totally-wrong-key"));
        let result = resolver.resolve(&msg).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("invalid pre-shared key"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn resolver_with_empty_chain_and_anonymous_allowed() {
        let resolver = IdentityResolver::new(
            vec![],
            ResolverConfig {
                allow_anonymous: true,
            },
        );

        let msg = make_initialize_msg(None);
        let identity = resolver.resolve(&msg).await.unwrap();
        assert_eq!(identity.principal, "anonymous");
    }

    #[tokio::test]
    async fn resolver_with_empty_chain_and_anonymous_denied() {
        let resolver = IdentityResolver::new(
            vec![],
            ResolverConfig {
                allow_anonymous: false,
            },
        );

        let msg = make_initialize_msg(None);
        let result = resolver.resolve(&msg).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // API Key Authenticator
    // -----------------------------------------------------------------------

    fn make_initialize_msg_with_api_key(api_key: Option<&str>) -> McpMessage {
        let mut params = json!({"capabilities": {}});
        if let Some(key) = api_key {
            params
                .as_object_mut()
                .unwrap()
                .insert("_mcpdome_api_key".to_string(), json!(key));
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

    fn make_api_key_entries() -> Vec<ApiKeyEntry> {
        vec![
            ApiKeyEntry {
                secret: "mcpdome_dev_abc123".to_string(),
                key_id: "dev-api-1".to_string(),
                labels: HashSet::from(["role:developer".to_string(), "env:staging".to_string()]),
            },
            ApiKeyEntry {
                secret: "mcpdome_admin_xyz789".to_string(),
                key_id: "admin-api-1".to_string(),
                labels: HashSet::from(["role:admin".to_string()]),
            },
        ]
    }

    #[test]
    fn extract_api_key_from_initialize_params() {
        let msg = make_initialize_msg_with_api_key(Some("mcpdome_dev_abc123"));
        let key = ApiKeyAuthenticator::extract_api_key(&msg);
        assert_eq!(key, Some("mcpdome_dev_abc123".to_string()));
    }

    #[test]
    fn extract_api_key_returns_none_when_absent() {
        let msg = make_initialize_msg_with_api_key(None);
        let key = ApiKeyAuthenticator::extract_api_key(&msg);
        assert_eq!(key, None);
    }

    #[tokio::test]
    async fn api_key_authenticator_succeeds_with_valid_key() {
        let auth = ApiKeyAuthenticator::new(make_api_key_entries());
        let msg = make_initialize_msg_with_api_key(Some("mcpdome_dev_abc123"));

        match auth.authenticate(&msg).await {
            AuthOutcome::Authenticated(id) => {
                assert_eq!(id.principal, "api_key:dev-api-1");
                assert!(matches!(
                    id.auth_method,
                    AuthMethod::ApiKey { ref key_id } if key_id == "dev-api-1"
                ));
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn api_key_authenticator_fails_with_invalid_key() {
        let auth = ApiKeyAuthenticator::new(make_api_key_entries());
        let msg = make_initialize_msg_with_api_key(Some("wrong-key"));

        match auth.authenticate(&msg).await {
            AuthOutcome::Failed(reason) => {
                assert!(reason.contains("invalid"), "reason: {reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn api_key_authenticator_not_applicable_for_non_initialize() {
        let auth = ApiKeyAuthenticator::new(make_api_key_entries());
        let msg = McpMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: Some("tools/call".to_string()),
            params: Some(json!({"name": "read_file", "_mcpdome_api_key": "mcpdome_dev_abc123"})),
            result: None,
            error: None,
        };

        match auth.authenticate(&msg).await {
            AuthOutcome::NotApplicable => {} // correct
            other => panic!("expected NotApplicable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn api_key_authenticator_not_applicable_when_no_field() {
        let auth = ApiKeyAuthenticator::new(make_api_key_entries());
        let msg = make_initialize_msg_with_api_key(None);

        match auth.authenticate(&msg).await {
            AuthOutcome::NotApplicable => {} // correct
            other => panic!("expected NotApplicable, got {other:?}"),
        }
    }

    #[test]
    fn strip_api_key_removes_field_from_params() {
        let msg = make_initialize_msg_with_api_key(Some("mcpdome_dev_abc123"));
        assert!(
            msg.params
                .as_ref()
                .unwrap()
                .get("_mcpdome_api_key")
                .is_some()
        );

        let stripped = ApiKeyAuthenticator::strip_api_key(&msg);
        assert!(
            stripped
                .params
                .as_ref()
                .unwrap()
                .get("_mcpdome_api_key")
                .is_none()
        );
        assert!(
            stripped
                .params
                .as_ref()
                .unwrap()
                .get("capabilities")
                .is_some()
        );
    }

    #[test]
    fn strip_api_key_is_noop_when_field_absent() {
        let msg = make_initialize_msg_with_api_key(None);
        let stripped = ApiKeyAuthenticator::strip_api_key(&msg);
        assert_eq!(
            msg.params.as_ref().unwrap().to_string(),
            stripped.params.as_ref().unwrap().to_string(),
        );
    }

    #[tokio::test]
    async fn api_key_auth_assigns_configured_labels() {
        let auth = ApiKeyAuthenticator::new(make_api_key_entries());
        let msg = make_initialize_msg_with_api_key(Some("mcpdome_dev_abc123"));

        match auth.authenticate(&msg).await {
            AuthOutcome::Authenticated(id) => {
                assert!(id.has_label("role:developer"));
                assert!(id.has_label("env:staging"));
                assert!(!id.has_label("role:admin"));
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn different_api_key_gets_different_labels() {
        let auth = ApiKeyAuthenticator::new(make_api_key_entries());
        let msg = make_initialize_msg_with_api_key(Some("mcpdome_admin_xyz789"));

        match auth.authenticate(&msg).await {
            AuthOutcome::Authenticated(id) => {
                assert_eq!(id.principal, "api_key:admin-api-1");
                assert!(id.has_label("role:admin"));
                assert!(!id.has_label("role:developer"));
            }
            other => panic!("expected Authenticated, got {other:?}"),
        }
    }
}
