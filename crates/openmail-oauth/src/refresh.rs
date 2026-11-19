//! Token exchange, device-code polling, refresh-with-rotation and the XOAUTH2
//! initial-response builder. Tokens live in `SecretString` and never in `Debug`.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use openmail_core::{Error, ErrorCode, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::providers::ProviderPreset;

/// Refresh this long before real expiry so a token is never presented while expiring.
pub const EXPIRY_SKEW_SECS: u64 = 60;
/// Google/Microsoft document 5s as the minimum device-code poll interval; `slow_down` adds this (RFC 8628 §3.5).
const SLOW_DOWN_STEP_SECS: u64 = 5;
/// Fallback when a provider omits `expires_in`: one hour is the documented default for both presets.
const DEFAULT_EXPIRES_IN_SECS: u64 = 3600;

/// Injected time source so expiry logic is testable.
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

#[derive(Clone)]
pub struct TokenSet {
    pub access_token: SecretString,
    pub refresh_token: Option<SecretString>,
    /// Unix seconds at which the access token stops being valid.
    pub expires_at: u64,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl TokenSet {
    pub fn needs_refresh(&self, clock: &dyn Clock) -> bool {
        clock.now_unix() + EXPIRY_SKEW_SECS >= self.expires_at
    }
}

#[derive(Clone)]
pub struct DeviceAuthorization {
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
    device_code: SecretString,
}

impl std::fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("device_code", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct DeviceResponse {
    device_code: String,
    user_code: String,
    // Google names this `verification_url`; RFC 8628 and Microsoft use `verification_uri`.
    #[serde(alias = "verification_url")]
    verification_uri: String,
    expires_in: Option<u64>,
    interval: Option<u64>,
}

#[derive(Debug)]
pub struct OAuthClient<C: Clock = SystemClock> {
    http: reqwest::Client,
    preset: ProviderPreset,
    client_id: String,
    client_secret: Option<SecretString>,
    clock: C,
}

impl OAuthClient<SystemClock> {
    pub fn new(
        preset: ProviderPreset,
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
    ) -> Result<Self> {
        Self::with_clock(preset, client_id, client_secret, SystemClock)
    }
}

impl<C: Clock> OAuthClient<C> {
    pub fn with_clock(
        preset: ProviderPreset,
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
        clock: C,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Error::new(ErrorCode::Internal, "failed to build HTTP client"))?;
        Ok(Self {
            http,
            preset,
            client_id: client_id.into(),
            client_secret,
            clock,
        })
    }

    async fn post_form(
        &self,
        url: &str,
        mut form: Vec<(&str, String)>,
    ) -> Result<reqwest::Response> {
        form.push(("client_id", self.client_id.clone()));
        if let Some(secret) = &self.client_secret {
            form.push(("client_secret", secret.expose_secret().to_owned()));
        }
        self.http.post(url).form(&form).send().await.map_err(|e| {
            tracing::warn!(is_timeout = e.is_timeout(), "oauth request failed");
            Error::new(
                if e.is_timeout() {
                    ErrorCode::Timeout
                } else {
                    ErrorCode::ConnectionFailed
                },
                "oauth endpoint unreachable",
            )
        })
    }

    /// Complete the auth-code + PKCE flow.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        verifier: &str,
    ) -> Result<TokenSet> {
        let form = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("redirect_uri", redirect_uri.to_owned()),
            ("code_verifier", verifier.to_owned()),
        ];
        let resp = self.post_form(&self.preset.token_url, form).await?;
        self.parse_tokens(resp, None).await
    }

    /// Refresh. If the provider rotates the refresh token the new one replaces the
    /// old; if it omits one (Google), the existing one is carried over.
    pub async fn refresh(&self, current: &TokenSet) -> Result<TokenSet> {
        let Some(rt) = &current.refresh_token else {
            return Err(Error::new(
                ErrorCode::AuthFailed,
                "no refresh token; re-authorize the account",
            ));
        };
        let form = vec![
            ("grant_type", "refresh_token".to_owned()),
            ("refresh_token", rt.expose_secret().to_owned()),
            ("scope", self.preset.scope_string()),
        ];
        let resp = self.post_form(&self.preset.token_url, form).await?;
        self.parse_tokens(resp, Some(rt)).await
    }

    /// Return `current` untouched while valid, else a refreshed set.
    pub async fn ensure_fresh(&self, current: &TokenSet) -> Result<TokenSet> {
        if current.needs_refresh(&self.clock) {
            self.refresh(current).await
        } else {
            Ok(current.clone())
        }
    }

    pub async fn start_device_flow(&self) -> Result<DeviceAuthorization> {
        let form = vec![("scope", self.preset.scope_string())];
        let resp = self.post_form(&self.preset.device_url, form).await?;
        if !resp.status().is_success() {
            return Err(Error::new(
                ErrorCode::AuthFailed,
                format!(
                    "device authorization rejected (HTTP {})",
                    resp.status().as_u16()
                ),
            ));
        }
        let d: DeviceResponse = resp.json().await.map_err(|_| {
            Error::new(
                ErrorCode::AuthFailed,
                "malformed device authorization response",
            )
        })?;
        Ok(DeviceAuthorization {
            user_code: d.user_code,
            verification_uri: d.verification_uri,
            expires_in: d.expires_in.unwrap_or(DEFAULT_EXPIRES_IN_SECS / 6),
            interval: d.interval.unwrap_or(SLOW_DOWN_STEP_SECS),
            device_code: SecretString::from(d.device_code),
        })
    }

    /// Poll until the user approves, denies, or the code expires.
    pub async fn poll_device_flow(&self, auth: &DeviceAuthorization) -> Result<TokenSet> {
        let mut interval = auth.interval;
        let max_attempts = auth.expires_in / interval.max(1) + 1;
        for _ in 0..max_attempts {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            let form = vec![
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
                ),
                ("device_code", auth.device_code.expose_secret().to_owned()),
            ];
            let resp = self.post_form(&self.preset.token_url, form).await?;
            let status = resp.status();
            let body: TokenResponse = resp
                .json()
                .await
                .map_err(|_| Error::new(ErrorCode::AuthFailed, "malformed token response"))?;
            match body.error.as_deref() {
                None if status.is_success() => return self.build_tokens(body, None),
                Some("authorization_pending") => {}
                Some("slow_down") => interval += SLOW_DOWN_STEP_SECS,
                Some(code) => {
                    return Err(Error::new(
                        ErrorCode::AuthFailed,
                        format!("device flow failed: {code}"),
                    ));
                }
                None => {
                    return Err(Error::new(
                        ErrorCode::AuthFailed,
                        format!("token endpoint HTTP {}", status.as_u16()),
                    ));
                }
            }
        }
        Err(Error::new(
            ErrorCode::Timeout,
            "device code expired before approval",
        ))
    }

    async fn parse_tokens(
        &self,
        resp: reqwest::Response,
        previous_refresh: Option<&SecretString>,
    ) -> Result<TokenSet> {
        let status = resp.status();
        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|_| Error::new(ErrorCode::AuthFailed, "malformed token response"))?;
        if let Some(code) = &body.error {
            // `error` is a short RFC 6749 code (e.g. invalid_grant); descriptions can echo input, so they are dropped.
            return Err(Error::new(
                ErrorCode::AuthFailed,
                format!("token endpoint error: {code}"),
            ));
        }
        if !status.is_success() {
            return Err(Error::new(
                ErrorCode::AuthFailed,
                format!("token endpoint HTTP {}", status.as_u16()),
            ));
        }
        self.build_tokens(body, previous_refresh)
    }

    fn build_tokens(
        &self,
        body: TokenResponse,
        previous_refresh: Option<&SecretString>,
    ) -> Result<TokenSet> {
        let access = body.access_token.ok_or_else(|| {
            Error::new(ErrorCode::AuthFailed, "token response lacks access_token")
        })?;
        let refresh_token = match body.refresh_token {
            Some(new) => Some(SecretString::from(new)),
            None => previous_refresh.cloned(),
        };
        Ok(TokenSet {
            access_token: SecretString::from(access),
            refresh_token,
            expires_at: self.clock.now_unix() + body.expires_in.unwrap_or(DEFAULT_EXPIRES_IN_SECS),
        })
    }
}

/// SASL XOAUTH2 initial client response, base64-encoded, ready for
/// `AUTHENTICATE XOAUTH2 <resp>` (IMAP) or `AUTH XOAUTH2 <resp>` (SMTP).
pub fn xoauth2_initial_response(user: &str, access_token: &SecretString) -> Result<SecretString> {
    // \x01 is the field separator; either field containing it would let a caller inject fields.
    if user.contains('\x01') || access_token.expose_secret().contains('\x01') {
        return Err(Error::new(
            ErrorCode::InvalidInput,
            "control character in XOAUTH2 field",
        ));
    }
    let raw = format!(
        "user={user}\x01auth=Bearer {}\x01\x01",
        access_token.expose_secret()
    );
    Ok(SecretString::from(STANDARD.encode(raw)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Clone)]
    struct FakeClock(Arc<Mutex<u64>>);
    impl Clock for FakeClock {
        fn now_unix(&self) -> u64 {
            *self.0.lock().unwrap()
        }
    }

    /// Serves canned `(status, json)` responses in order; records each request body.
    async fn token_server(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let seen = bodies.clone();
        tokio::spawn(async move {
            for (status, json) in responses {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let body = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .to_ascii_lowercase()
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if body.len() >= len || n == 0 {
                            break body.to_owned();
                        }
                    }
                };
                seen.lock().unwrap().push(body);
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                    json.len()
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        (url, bodies)
    }

    fn client(token_url: &str, now: u64) -> (OAuthClient<FakeClock>, FakeClock) {
        let mut p = ProviderPreset::google();
        p.token_url = token_url.to_owned();
        p.device_url = token_url.to_owned();
        let clock = FakeClock(Arc::new(Mutex::new(now)));
        (
            OAuthClient::with_clock(p, "test-client", None, clock.clone()).unwrap(),
            clock,
        )
    }

    fn tokens(refresh: Option<&str>, expires_at: u64) -> TokenSet {
        TokenSet {
            access_token: SecretString::from("old-access"),
            refresh_token: refresh.map(SecretString::from),
            expires_at,
        }
    }

    #[tokio::test]
    async fn refresh_rotates_refresh_token() {
        let (url, bodies) = token_server(vec![(
            200,
            r#"{"access_token":"new-a","refresh_token":"new-r","expires_in":100}"#,
        )])
        .await;
        let (c, _) = client(&url, 1000);
        let t = c.refresh(&tokens(Some("old-r"), 0)).await.unwrap();
        assert_eq!(t.access_token.expose_secret(), "new-a");
        assert_eq!(t.refresh_token.unwrap().expose_secret(), "new-r");
        assert_eq!(t.expires_at, 1100);
        let b = bodies.lock().unwrap()[0].clone();
        assert!(
            b.contains("grant_type=refresh_token")
                && b.contains("refresh_token=old-r")
                && b.contains("client_id=test-client")
        );
    }

    #[tokio::test]
    async fn refresh_keeps_old_refresh_token_when_not_rotated() {
        let (url, _) =
            token_server(vec![(200, r#"{"access_token":"a2","expires_in":3600}"#)]).await;
        let (c, _) = client(&url, 0);
        let t = c.refresh(&tokens(Some("keep-me"), 0)).await.unwrap();
        assert_eq!(t.refresh_token.unwrap().expose_secret(), "keep-me");
    }

    #[tokio::test]
    async fn invalid_grant_is_auth_failed_without_leaking_secrets() {
        let (url, _) = token_server(vec![(
            400,
            r#"{"error":"invalid_grant","error_description":"secret-echo"}"#,
        )])
        .await;
        let (c, _) = client(&url, 0);
        let err = c.refresh(&tokens(Some("rt-secret"), 0)).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthFailed);
        let msg = err.to_string();
        assert!(
            msg.contains("invalid_grant")
                && !msg.contains("rt-secret")
                && !msg.contains("secret-echo")
        );
    }

    #[tokio::test]
    async fn refresh_without_refresh_token_fails() {
        let (c, _) = client("http://127.0.0.1:1/token", 0);
        assert_eq!(
            c.refresh(&tokens(None, 0)).await.unwrap_err().code(),
            ErrorCode::AuthFailed
        );
    }

    #[tokio::test]
    async fn ensure_fresh_skips_network_until_skew_window() {
        let (c, clock) = client("http://127.0.0.1:1/token", 1000);
        let t = tokens(Some("r"), 1000 + EXPIRY_SKEW_SECS + 10);
        assert_eq!(
            c.ensure_fresh(&t)
                .await
                .unwrap()
                .access_token
                .expose_secret(),
            "old-access"
        );
        *clock.0.lock().unwrap() = 1011;
        // Now inside the skew window: it tries the (dead) endpoint, proving a refresh was attempted.
        assert_eq!(
            c.ensure_fresh(&t).await.unwrap_err().code(),
            ErrorCode::ConnectionFailed
        );
    }

    #[tokio::test]
    async fn exchange_code_sends_pkce_verifier() {
        let (url, bodies) = token_server(vec![(
            200,
            r#"{"access_token":"a","refresh_token":"r","expires_in":5}"#,
        )])
        .await;
        let (c, _) = client(&url, 0);
        let t = c
            .exchange_code("the-code", "http://127.0.0.1/cb", "ver123")
            .await
            .unwrap();
        assert_eq!(t.refresh_token.unwrap().expose_secret(), "r");
        let b = bodies.lock().unwrap()[0].clone();
        assert!(
            b.contains("grant_type=authorization_code")
                && b.contains("code_verifier=ver123")
                && b.contains("code=the-code")
        );
    }

    #[tokio::test]
    async fn device_flow_polls_through_pending_and_slow_down() {
        let (url, bodies) = token_server(vec![
            (200, r#"{"device_code":"dc","user_code":"ABCD-EFGH","verification_url":"https://example.test/device","expires_in":900,"interval":0}"#),
            (400, r#"{"error":"authorization_pending"}"#),
            (200, r#"{"access_token":"dev-a","refresh_token":"dev-r","expires_in":60}"#),
        ])
        .await;
        let (c, _) = client(&url, 10);
        let auth = c.start_device_flow().await.unwrap();
        assert_eq!(auth.user_code, "ABCD-EFGH");
        assert_eq!(auth.verification_uri, "https://example.test/device");
        assert!(!format!("{auth:?}").contains("dc\""));
        let t = c.poll_device_flow(&auth).await.unwrap();
        assert_eq!(t.access_token.expose_secret(), "dev-a");
        let seen = bodies.lock().unwrap();
        assert!(seen[1].contains("device_code=dc") && seen[1].contains("device_code"));
    }

    #[tokio::test]
    async fn device_flow_denied_is_auth_failed() {
        let (url, _) = token_server(vec![
            (200, r#"{"device_code":"dc","user_code":"U","verification_uri":"https://e.test","expires_in":10,"interval":0}"#),
            (400, r#"{"error":"access_denied"}"#),
        ])
        .await;
        let (c, _) = client(&url, 0);
        let auth = c.start_device_flow().await.unwrap();
        assert_eq!(
            c.poll_device_flow(&auth).await.unwrap_err().code(),
            ErrorCode::AuthFailed
        );
    }

    #[test]
    fn debug_never_prints_tokens() {
        let t = tokens(Some("super-refresh"), 5);
        let s = format!("{t:?}");
        assert!(!s.contains("super-refresh") && !s.contains("old-access"));
    }

    #[test]
    fn xoauth2_matches_google_documented_shape() {
        let r = xoauth2_initial_response(
            "someuser@example.com",
            &SecretString::from("ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg"),
        )
        .unwrap();
        let decoded = String::from_utf8(STANDARD.decode(r.expose_secret()).unwrap()).unwrap();
        assert_eq!(
            decoded,
            "user=someuser@example.com\x01auth=Bearer ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01"
        );
        assert!(xoauth2_initial_response("a\x01b", &SecretString::from("t")).is_err());
    }
}
