//! Provider presets and the authorization-code + PKCE request builder.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openmail_core::{Error, ErrorCode, Result};
use reqwest::Url;
use sha2::{Digest, Sha256};

/// Bytes of entropy in a PKCE verifier (RFC 7636 §4.1 allows 32..=96 octets).
const PKCE_VERIFIER_BYTES: usize = 32;
/// Bytes of entropy in the `state` CSRF token.
const STATE_BYTES: usize = 16;

/// Endpoints and scopes for one identity provider. Values are copied from the
/// providers' public docs; see NOTES.md for sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPreset {
    pub name: &'static str,
    pub auth_url: String,
    pub token_url: String,
    pub device_url: String,
    pub scopes: Vec<String>,
}

impl ProviderPreset {
    pub fn google() -> Self {
        Self {
            name: "google",
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_url: "https://oauth2.googleapis.com/token".into(),
            device_url: "https://oauth2.googleapis.com/device/code".into(),
            // Full-mailbox scope is what Gmail IMAP/SMTP XOAUTH2 requires.
            scopes: vec!["https://mail.google.com/".into()],
        }
    }

    /// `tenant` is `common`, `organizations`, `consumers`, or a tenant id/domain.
    pub fn microsoft(tenant: &str) -> Result<Self> {
        if tenant.is_empty()
            || !tenant
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
        {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                "invalid Microsoft tenant",
            ));
        }
        let base = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0");
        Ok(Self {
            name: "microsoft",
            auth_url: format!("{base}/authorize"),
            token_url: format!("{base}/token"),
            device_url: format!("{base}/devicecode"),
            scopes: vec![
                "https://outlook.office.com/IMAP.AccessAsUser.All".into(),
                "https://outlook.office.com/SMTP.Send".into(),
                // Required to receive a refresh token.
                "offline_access".into(),
            ],
        })
    }

    pub fn scope_string(&self) -> String {
        self.scopes.join(" ")
    }
}

/// A PKCE authorization request: open `url`, keep `verifier` and `state` secret
/// until the redirect comes back.
#[derive(Clone)]
pub struct PkceRequest {
    pub url: Url,
    pub state: String,
    pub verifier: String,
}

impl std::fmt::Debug for PkceRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkceRequest")
            .field("url", &self.url.as_str())
            .field("verifier", &"<redacted>")
            .finish()
    }
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_token(len: usize) -> Result<String> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf)
        .map_err(|_| Error::new(ErrorCode::Internal, "system randomness unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

impl ProviderPreset {
    /// Build an auth-code + PKCE (S256) URL with fresh random verifier and state.
    pub fn pkce_request(&self, client_id: &str, redirect_uri: &str) -> Result<PkceRequest> {
        self.pkce_request_with(
            client_id,
            redirect_uri,
            random_token(PKCE_VERIFIER_BYTES)?,
            random_token(STATE_BYTES)?,
        )
    }

    /// Deterministic variant (known verifier/state) for tests and callers with their own RNG.
    pub fn pkce_request_with(
        &self,
        client_id: &str,
        redirect_uri: &str,
        verifier: String,
        state: String,
    ) -> Result<PkceRequest> {
        let mut url = Url::parse(&self.auth_url)
            .map_err(|_| Error::new(ErrorCode::ConfigInvalid, "invalid auth_url"))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &self.scope_string())
            .append_pair("state", &state)
            .append_pair("code_challenge", &pkce_challenge(&verifier))
            .append_pair("code_challenge_method", "S256");
        Ok(PkceRequest {
            url,
            state,
            verifier,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b_vector() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn microsoft_endpoints_and_tenant_validation() {
        let p = ProviderPreset::microsoft("common").unwrap();
        assert_eq!(
            p.token_url,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        );
        assert!(p.scopes.contains(&"offline_access".to_string()));
        assert!(ProviderPreset::microsoft("a/b").is_err());
        assert!(ProviderPreset::microsoft("").is_err());
    }

    #[test]
    fn pkce_url_carries_s256_challenge_and_scopes() {
        let p = ProviderPreset::google();
        let r = p
            .pkce_request_with(
                "cid",
                "http://127.0.0.1:8080/cb",
                "v".repeat(43),
                "st".into(),
            )
            .unwrap();
        let q: std::collections::HashMap<_, _> = r.url.query_pairs().into_owned().collect();
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"], pkce_challenge(&"v".repeat(43)));
        assert_eq!(q["scope"], "https://mail.google.com/");
        assert_eq!(q["state"], "st");
        assert!(!format!("{r:?}").contains(&"v".repeat(43)));
    }

    #[test]
    fn random_requests_differ() {
        let p = ProviderPreset::google();
        let a = p.pkce_request("c", "http://localhost/cb").unwrap();
        let b = p.pkce_request("c", "http://localhost/cb").unwrap();
        assert_ne!(a.verifier, b.verifier);
        assert!(a.verifier.len() >= 43);
    }
}
