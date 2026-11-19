//! The authorization server end to end through its HTTP surface (no network): registration,
//! consent with the owner password, PKCE code exchange, JWT verification against the published
//! JWKS, refresh rotation, and the refusals that matter (bad redirect, bad PKCE, code reuse,
//! wrong resource, brute force).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt as _;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use openmail_authserver::{AuthServer, Config, hash_password, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

const ISSUER: &str = "https://mail.example.test";
const RESOURCE: &str = "https://mail.example.test/mcp";
const PASSWORD: &str = "correct horse battery staple";
const REDIRECT: &str = "https://chatgpt.com/connector_platform_oauth_redirect";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // RFC 7636 appendix B

struct Env {
    app: Router,
    server: Arc<AuthServer>,
    _dir: tempfile::TempDir,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let server = AuthServer::open(Config {
        issuer: ISSUER.into(),
        resource: RESOURCE.into(),
        owner_password_hash: hash_password(PASSWORD).unwrap(),
        state_dir: dir.path().to_owned(),
        scopes: vec![
            "mail:read".into(),
            "mail:organize".into(),
            "mail:send".into(),
        ],
        allowed_redirect_hosts: vec!["chatgpt.com".into()],
        access_ttl: Duration::from_secs(3600),
        refresh_ttl: Duration::from_secs(86_400),
    })
    .unwrap();
    Env {
        app: router(Arc::clone(&server)),
        server,
        _dir: dir,
    }
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (status, headers, body)
}

fn form(uri: &str, body: &str) -> Request<Body> {
    Request::post(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn register(app: &Router, redirect: &str) -> (StatusCode, Value) {
    let (st, _, body) = send(
        app,
        Request::post("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"client_name": "ChatGPT", "redirect_uris": [redirect]}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    (st, serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn authorize_url(client_id: &str, extra: &str) -> String {
    format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=xyz&resource={}{extra}",
        urlencode(REDIRECT),
        challenge(),
        urlencode(RESOURCE)
    )
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// GET /authorize, return the tx id from the consent page.
async fn open_consent(app: &Router, client_id: &str) -> String {
    let (st, _, html) = send(
        app,
        Request::get(authorize_url(client_id, ""))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{html}");
    let marker = "name=\"tx\" value=\"";
    let i = html.find(marker).unwrap() + marker.len();
    html[i..html[i..].find('"').unwrap() + i].to_owned()
}

fn location(h: &axum::http::HeaderMap) -> url::Url {
    url::Url::parse(h.get(header::LOCATION).unwrap().to_str().unwrap()).unwrap()
}

async fn approve(
    app: &Router,
    tx: &str,
    password: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    send(
        app,
        form(
            "/authorize",
            &format!("tx={tx}&decision=allow&password={}", urlencode(password)),
        ),
    )
    .await
}

async fn token(app: &Router, body: &str) -> (StatusCode, Value) {
    let (st, _, b) = send(app, form("/token", body)).await;
    (st, serde_json::from_str(&b).unwrap())
}

async fn full_login(e: &Env) -> (String, Value) {
    let (_, reg) = register(&e.app, REDIRECT).await;
    let cid = reg["client_id"].as_str().unwrap().to_owned();
    let tx = open_consent(&e.app, &cid).await;
    let (st, h, _) = approve(&e.app, &tx, PASSWORD).await;
    assert_eq!(st, StatusCode::FOUND);
    let loc = location(&h);
    let code = loc
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let (st, tok) = token(
        &e.app,
        &format!(
            "grant_type=authorization_code&client_id={cid}&code={code}&redirect_uri={}&code_verifier={VERIFIER}",
            urlencode(REDIRECT)
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{tok}");
    (cid, tok)
}

#[tokio::test]
async fn full_flow_issues_a_jwt_that_verifies_against_the_published_jwks() {
    let e = env();
    let (_, meta) = {
        let (_, _, b) = send(
            &e.app,
            Request::get("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        ((), serde_json::from_str::<Value>(&b).unwrap())
    };
    assert_eq!(meta["issuer"], ISSUER);
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        meta["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );

    let (_cid, tok) = full_login(&e).await;
    assert_eq!(tok["token_type"], "Bearer");
    assert_eq!(tok["scope"], "mail:read");

    // Validate exactly as a resource server would: ES256, issuer, audience, expiry, JWKS key.
    let jwks: Value = serde_json::from_slice(&e.server.jwks_json()).unwrap();
    let k = &jwks["keys"][0];
    let key = DecodingKey::from_ec_components(k["x"].as_str().unwrap(), k["y"].as_str().unwrap())
        .unwrap();
    let mut v = Validation::new(Algorithm::ES256);
    v.set_issuer(&[ISSUER]);
    v.set_audience(&[RESOURCE]);
    let data =
        jsonwebtoken::decode::<Value>(tok["access_token"].as_str().unwrap(), &key, &v).unwrap();
    assert_eq!(data.claims["scope"], "mail:read");
    assert_eq!(data.header.kid.as_deref(), k["kid"].as_str());
    // A different audience must not validate.
    let mut wrong = Validation::new(Algorithm::ES256);
    wrong.set_audience(&["https://other.example/mcp"]);
    assert!(
        jsonwebtoken::decode::<Value>(tok["access_token"].as_str().unwrap(), &key, &wrong).is_err()
    );
}

#[tokio::test]
async fn refresh_tokens_rotate_and_cannot_be_replayed() {
    let e = env();
    let (cid, tok) = full_login(&e).await;
    let rt = tok["refresh_token"].as_str().unwrap();
    let (st, next) = token(
        &e.app,
        &format!("grant_type=refresh_token&client_id={cid}&refresh_token={rt}"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_ne!(next["refresh_token"], tok["refresh_token"]);
    let (st, replay) = token(
        &e.app,
        &format!("grant_type=refresh_token&client_id={cid}&refresh_token={rt}"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(replay["error"], "invalid_grant");
    // Another client cannot redeem it either.
    let (_, other) = register(&e.app, REDIRECT).await;
    let nrt = next["refresh_token"].as_str().unwrap();
    let ocid = other["client_id"].as_str().unwrap();
    let (st, _) = token(
        &e.app,
        &format!("grant_type=refresh_token&client_id={ocid}&refresh_token={nrt}"),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pkce_code_reuse_and_redirect_mismatch_are_refused() {
    let e = env();
    let (_, reg) = register(&e.app, REDIRECT).await;
    let cid = reg["client_id"].as_str().unwrap().to_owned();
    let redeem = |code: String, verifier: &'static str, redirect: &'static str| {
        let app = e.app.clone();
        let cid = cid.clone();
        async move {
            token(
                &app,
                &format!(
                    "grant_type=authorization_code&client_id={cid}&code={code}&redirect_uri={}&code_verifier={verifier}",
                    urlencode(redirect)
                ),
            )
            .await
        }
    };
    let get_code = |tx: String| {
        let app = e.app.clone();
        async move {
            let (_, h, _) = approve(&app, &tx, PASSWORD).await;
            location(&h)
                .query_pairs()
                .find(|(k, _)| k == "code")
                .unwrap()
                .1
                .into_owned()
        }
    };
    // Wrong verifier.
    let code = get_code(open_consent(&e.app, &cid).await).await;
    let (st, body) = redeem(code, "A".repeat(43).leak(), REDIRECT).await;
    assert_eq!(
        (st, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    // Wrong redirect_uri.
    let code = get_code(open_consent(&e.app, &cid).await).await;
    let (st, _) = redeem(code, VERIFIER, "https://chatgpt.com/other").await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // Success once, then the same code is dead.
    let code = get_code(open_consent(&e.app, &cid).await).await;
    assert_eq!(
        redeem(code.clone(), VERIFIER, REDIRECT).await.0,
        StatusCode::OK
    );
    assert_eq!(
        redeem(code, VERIFIER, REDIRECT).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn registration_and_authorization_reject_unsafe_requests() {
    let e = env();
    for bad in [
        "https://evil.example/cb",
        "http://chatgpt.com/cb",
        "javascript:alert(1)",
        "https://chatgpt.com/cb#frag",
        "https://user:pw@chatgpt.com/cb",
    ] {
        assert_eq!(
            register(&e.app, bad).await.0,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    assert_eq!(
        register(&e.app, "http://127.0.0.1:8123/cb").await.0,
        StatusCode::CREATED
    );
    let (_, reg) = register(&e.app, REDIRECT).await;
    let cid = reg["client_id"].as_str().unwrap();

    // Unregistered redirect_uri: an error page, never a redirect.
    let bad_redirect = format!(
        "/authorize?response_type=code&client_id={cid}&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
        urlencode("https://chatgpt.com/evil"),
        challenge()
    );
    let (st, h, _) = send(
        &e.app,
        Request::get(bad_redirect).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(h.get(header::LOCATION).is_none());

    // Missing PKCE, plain PKCE, wrong resource, unknown scope: redirected errors.
    let base = authorize_url(cid, "");
    for (url, code) in [
        (
            base.replace("code_challenge_method=S256", "code_challenge_method=plain"),
            "invalid_request",
        ),
        (
            base.replace(&format!("&code_challenge={}", challenge()), ""),
            "invalid_request",
        ),
        (
            base.replace(
                &urlencode(RESOURCE),
                &urlencode("https://other.example/mcp"),
            ),
            "invalid_target",
        ),
        (format!("{base}&scope=mail:delete"), "invalid_scope"),
        (
            base.replace("response_type=code", "response_type=token"),
            "unsupported_response_type",
        ),
    ] {
        let (st, h, _) = send(&e.app, Request::get(&url).body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::FOUND, "{url}");
        let q: Vec<_> = location(&h)
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(q.contains(&("error".into(), code.into())), "{url}: {q:?}");
        assert!(q.contains(&("iss".into(), ISSUER.into())));
        assert!(!q.iter().any(|(k, _)| k == "code"));
    }
}

#[tokio::test]
async fn wrong_password_is_refused_and_repeated_failures_pause_sign_in() {
    let e = env();
    let (_, reg) = register(&e.app, REDIRECT).await;
    let cid = reg["client_id"].as_str().unwrap();
    let tx = open_consent(&e.app, cid).await;
    for _ in 0..5 {
        let (st, h, _) = approve(&e.app, &tx, "not the password").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert!(h.get(header::LOCATION).is_none());
    }
    // Even the right password is paused now.
    assert_eq!(
        approve(&e.app, &tx, PASSWORD).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn deny_redirects_with_access_denied_and_pages_are_not_framable() {
    let e = env();
    let (_, reg) = register(&e.app, REDIRECT).await;
    let cid = reg["client_id"].as_str().unwrap();
    let (_, h, _) = send(
        &e.app,
        Request::get(authorize_url(cid, ""))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert!(
        h.get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    let tx = open_consent(&e.app, cid).await;
    let (st, h, _) = send(
        &e.app,
        form("/authorize", &format!("tx={tx}&decision=deny")),
    )
    .await;
    assert_eq!(st, StatusCode::FOUND);
    assert!(
        location(&h)
            .query_pairs()
            .any(|(k, v)| k == "error" && v == "access_denied")
    );
    assert!(
        location(&h)
            .query_pairs()
            .any(|(k, v)| k == "state" && v == "xyz")
    );
}

#[tokio::test]
async fn signing_key_persists_across_restarts_and_weak_passwords_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mk = || {
        AuthServer::open(Config {
            issuer: ISSUER.into(),
            resource: RESOURCE.into(),
            owner_password_hash: hash_password(PASSWORD).unwrap(),
            state_dir: dir.path().to_owned(),
            scopes: vec!["mail:read".into()],
            allowed_redirect_hosts: vec![],
            access_ttl: Duration::from_secs(60),
            refresh_ttl: Duration::from_secs(60),
        })
        .unwrap()
    };
    assert_eq!(mk().jwks_json(), mk().jwks_json());
    assert!(hash_password("short").is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("oauth-signing-key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "signing key must be owner-only");
    }
}

async fn granted_scope(e: &Env, extra: &str) -> (StatusCode, Option<String>) {
    let (_, reg) = register(&e.app, REDIRECT).await;
    let cid = reg["client_id"].as_str().unwrap().to_owned();
    let tx = open_consent(&e.app, &cid).await;
    let (st, h, _) = send(
        &e.app,
        form(
            "/authorize",
            &format!("tx={tx}&password={}&{extra}", urlencode(PASSWORD)),
        ),
    )
    .await;
    if st != StatusCode::FOUND {
        return (st, None);
    }
    let code = location(&h)
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let (_, tok) = token(
        &e.app,
        &format!(
            "grant_type=authorization_code&client_id={cid}&code={code}&redirect_uri={}&code_verifier={VERIFIER}",
            urlencode(REDIRECT)
        ),
    )
    .await;
    (st, tok["scope"].as_str().map(str::to_owned))
}

#[tokio::test]
async fn the_owner_chooses_the_permissions_and_can_approve_all() {
    let e = env();
    // The page offers every scope; only read-only is pre-ticked when the client asked for none.
    let (_, reg) = register(&e.app, REDIRECT).await;
    let cid = reg["client_id"].as_str().unwrap();
    let (_, _, html) = send(
        &e.app,
        Request::get(authorize_url(cid, ""))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    for s in ["mail:read", "mail:organize", "mail:send"] {
        assert!(html.contains(&format!("value=\"{s}\"")), "{s} not offered");
    }
    assert!(html.contains("value=\"mail:read\" checked"));
    assert!(!html.contains("value=\"mail:send\" checked"));
    assert!(html.contains("Approve ALL permissions"));

    // No boxes sent: what was requested (read-only).
    assert_eq!(
        granted_scope(&e, "decision=allow").await.1.as_deref(),
        Some("mail:read")
    );
    // A chosen subset.
    assert_eq!(
        granted_scope(&e, "decision=allow&scope=mail:read&scope=mail:organize")
            .await
            .1
            .as_deref(),
        Some("mail:read mail:organize")
    );
    // Approve ALL grants every scope this server defines, and only those.
    assert_eq!(
        granted_scope(&e, "decision=allow_all").await.1.as_deref(),
        Some("mail:read mail:organize mail:send")
    );
    // Scopes the server does not define are dropped; nothing valid ticked is refused.
    assert_eq!(
        granted_scope(&e, "decision=allow&scope=mail:read&scope=mail:delete")
            .await
            .1
            .as_deref(),
        Some("mail:read")
    );
    assert_eq!(
        granted_scope(&e, "decision=allow&scope=mail:delete")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}
