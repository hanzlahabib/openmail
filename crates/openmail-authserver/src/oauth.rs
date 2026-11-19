//! HTTP surface: metadata, JWKS, registration, authorize (consent) and token endpoints.
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use url::Url;

use crate::pages;
use crate::store::Client;
use crate::{AuthServer, Code, Error, Pending, lock, now, random_token};

type Srv = State<Arc<AuthServer>>;

/// All bodies here are tiny forms or JSON documents.
const MAX_BODY_BYTES: usize = 16 * 1024;
const MAX_REDIRECT_URIS: usize = 5;
const MAX_CLIENT_NAME_CHARS: usize = 100;
/// RFC 7636: verifier is 43..=128 characters from the unreserved set.
const VERIFIER_LEN: std::ops::RangeInclusive<usize> = 43..=128;
const SUBJECT: &str = "owner";

pub fn router(server: Arc<AuthServer>) -> Router {
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/.well-known/openid-configuration", get(metadata))
        .route("/jwks.json", get(jwks))
        .route("/register", post(register))
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/token", post(token))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(server)
}

fn no_store(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

fn page(status: StatusCode, html: String) -> Response {
    let mut r = (status, Html(html)).into_response();
    let h = r.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    no_store(r)
}

fn json_error(status: StatusCode, code: &str, description: &str) -> Response {
    no_store(
        (
            status,
            Json(json!({"error": code, "error_description": description})),
        )
            .into_response(),
    )
}

fn server_error(e: &Error) -> Response {
    tracing::error!(error = %e, "authorization server internal error");
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "internal error",
    )
}

async fn metadata(State(s): Srv) -> Response {
    let i = &s.cfg.issuer;
    Json(json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "registration_endpoint": format!("{i}/register"),
        "jwks_uri": format!("{i}/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": s.cfg.scopes,
        "authorization_response_iss_parameter_supported": true,
    }))
    .into_response()
}

async fn jwks(State(s): Srv) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], s.jwks_json()).into_response()
}

// --- registration ------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterRequest {
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
}

/// Exact-match redirect URIs only. https on an allowlisted host, or loopback http (native apps).
fn redirect_allowed(s: &AuthServer, raw: &str) -> bool {
    let Ok(u) = Url::parse(raw) else { return false };
    if u.fragment().is_some() || !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    let Some(host) = u.host_str() else {
        return false;
    };
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    match u.scheme() {
        "http" => loopback,
        "https" => {
            loopback
                || s.cfg
                    .allowed_redirect_hosts
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(host))
        }
        _ => false,
    }
}

async fn register(State(s): Srv, Json(req): Json<RegisterRequest>) -> Response {
    let bad = |d: &str| json_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", d);
    if req.redirect_uris.is_empty() || req.redirect_uris.len() > MAX_REDIRECT_URIS {
        return bad("redirect_uris needs 1 to 5 entries");
    }
    if let Some(bad_uri) = req.redirect_uris.iter().find(|u| !redirect_allowed(&s, u)) {
        tracing::warn!(uri = %bad_uri, "client registration refused: redirect not allowed");
        return bad("a redirect_uri is not allowed on this server");
    }
    if req
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|m| m != "none")
    {
        return bad("only public clients (token_endpoint_auth_method none) are supported");
    }
    let name: String = req
        .client_name
        .unwrap_or_else(|| "Unnamed application".into())
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_CLIENT_NAME_CHARS)
        .collect();
    let client_id = match random_token() {
        Ok(t) => t,
        Err(e) => return server_error(&e),
    };
    let client = Client {
        client_id: client_id.clone(),
        name: name.clone(),
        redirect_uris: req.redirect_uris.clone(),
    };
    match s.store.add_client(&client, now()) {
        Ok(()) => {}
        Err(Error::TooManyClients) => {
            return json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "client registration is full",
            );
        }
        Err(e) => return server_error(&e),
    }
    no_store(
        (
            StatusCode::CREATED,
            Json(json!({
                "client_id": client_id,
                "client_name": name,
                "redirect_uris": req.redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "client_id_issued_at": now(),
            })),
        )
            .into_response(),
    )
}

// --- authorize ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

/// 302 back to the client with query parameters (`iss` per RFC 9207).
fn redirect_to(s: &AuthServer, base: &str, params: &[(&str, &str)]) -> Response {
    let Ok(mut u) = Url::parse(base) else {
        return page(StatusCode::BAD_REQUEST, pages::error("invalid redirect"));
    };
    {
        let mut q = u.query_pairs_mut();
        for (k, v) in params {
            q.append_pair(k, v);
        }
        q.append_pair("iss", &s.cfg.issuer);
    }
    let mut r = Response::new(axum::body::Body::empty());
    *r.status_mut() = StatusCode::FOUND;
    if let Ok(v) = HeaderValue::from_str(u.as_str()) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    no_store(r)
}

fn err_redirect(s: &AuthServer, base: &str, state: Option<&str>, code: &str) -> Response {
    let mut p = vec![("error", code)];
    if let Some(st) = state {
        p.push(("state", st));
    }
    redirect_to(s, base, &p)
}

async fn authorize_get(State(s): Srv, Query(q): Query<AuthorizeQuery>) -> Response {
    // Until the client and redirect_uri are verified nothing may redirect: show an error page.
    let fail = |m: &str| page(StatusCode::BAD_REQUEST, pages::error(m));
    let (Some(client_id), Some(redirect_uri)) = (q.client_id.as_deref(), q.redirect_uri.as_deref())
    else {
        return fail("client_id and redirect_uri are required");
    };
    let client = match s.store.client(client_id) {
        Ok(Some(c)) => c,
        Ok(None) => return fail("unknown client"),
        Err(e) => return server_error(&e),
    };
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return fail("redirect_uri does not match the registered one");
    }
    let state = q.state.as_deref();
    if q.response_type.as_deref() != Some("code") {
        return err_redirect(&s, redirect_uri, state, "unsupported_response_type");
    }
    let Some(challenge) = q
        .code_challenge
        .as_deref()
        .filter(|c| (43..=128).contains(&c.len()))
    else {
        return err_redirect(&s, redirect_uri, state, "invalid_request");
    };
    if q.code_challenge_method.as_deref() != Some("S256") {
        return err_redirect(&s, redirect_uri, state, "invalid_request");
    }
    if q.resource.as_deref().is_some_and(|r| r != s.cfg.resource) {
        return err_redirect(&s, redirect_uri, state, "invalid_target");
    }
    let granted: Vec<String> = match q.scope.as_deref().filter(|x| !x.trim().is_empty()) {
        None => s.cfg.scopes.clone(),
        Some(req) => {
            let g: Vec<String> = req
                .split_whitespace()
                .filter(|r| s.cfg.scopes.iter().any(|a| a == r))
                .map(str::to_owned)
                .collect();
            if g.is_empty() {
                return err_redirect(&s, redirect_uri, state, "invalid_scope");
            }
            g
        }
    };
    if s.in_flight_full() {
        return fail("the server is busy; try again in a few minutes");
    }
    let tx = match random_token() {
        Ok(t) => t,
        Err(e) => return server_error(&e),
    };
    lock(&s.pending).insert(
        tx.clone(),
        Pending {
            client_id: client.client_id.clone(),
            redirect_uri: redirect_uri.to_owned(),
            challenge: challenge.to_owned(),
            scope: granted.join(" "),
            state: q.state.clone(),
            expires: now() + AuthServer::pending_ttl(),
        },
    );
    page(
        StatusCode::OK,
        pages::consent(&tx, &client.name, &granted, None),
    )
}

#[derive(Deserialize)]
struct AuthorizeForm {
    tx: String,
    password: Option<String>,
    decision: String,
}

async fn authorize_post(State(s): Srv, Form(f): Form<AuthorizeForm>) -> Response {
    let t = now();
    let snapshot = {
        let p = lock(&s.pending);
        p.get(&f.tx).filter(|x| x.expires > t).map(|x| {
            (
                x.client_id.clone(),
                x.redirect_uri.clone(),
                x.state.clone(),
                x.scope.clone(),
            )
        })
    };
    let Some((client_id, redirect_uri, state, scope)) = snapshot else {
        return page(
            StatusCode::BAD_REQUEST,
            pages::error("this request expired"),
        );
    };
    if f.decision != "allow" {
        lock(&s.pending).remove(&f.tx);
        return err_redirect(&s, &redirect_uri, state.as_deref(), "access_denied");
    }
    let name = s
        .store
        .client(&client_id)
        .ok()
        .flatten()
        .map_or_else(|| "Application".to_owned(), |c| c.name);
    let scopes: Vec<String> = scope.split(' ').map(str::to_owned).collect();
    let retry = |status: StatusCode, msg: &str| {
        page(status, pages::consent(&f.tx, &name, &scopes, Some(msg)))
    };
    if s.login_locked() {
        return retry(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed attempts. Try again in a few minutes.",
        );
    }
    if !verify_owner(&s, f.password.as_deref().unwrap_or_default()) {
        s.note_login_failure();
        tracing::warn!("owner sign-in failed on the authorization page");
        return retry(StatusCode::UNAUTHORIZED, "Wrong password.");
    }
    s.clear_login_failures();
    let Some(pending) = lock(&s.pending).remove(&f.tx) else {
        return page(
            StatusCode::BAD_REQUEST,
            pages::error("this request expired"),
        );
    };
    let code = match random_token() {
        Ok(c) => c,
        Err(e) => return server_error(&e),
    };
    lock(&s.codes).insert(
        code.clone(),
        Code {
            client_id: pending.client_id,
            redirect_uri: pending.redirect_uri.clone(),
            challenge: pending.challenge,
            scope: pending.scope,
            expires: now() + AuthServer::code_ttl(),
        },
    );
    let mut p = vec![("code", code.as_str())];
    if let Some(st) = pending.state.as_deref() {
        p.push(("state", st));
    }
    redirect_to(&s, &pending.redirect_uri, &p)
}

fn verify_owner(s: &AuthServer, password: &str) -> bool {
    use argon2::PasswordVerifier as _;
    argon2::Argon2::default()
        .verify_password(password.as_bytes(), s.cfg.owner_password_hash.as_str())
        .is_ok()
}

// --- token -------------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct AccessClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    client_id: &'a str,
    scope: &'a str,
    iat: i64,
    exp: i64,
    jti: String,
}

fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    if !VERIFIER_LEN.contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    {
        return false;
    }
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

fn hash_refresh(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn issue(s: &AuthServer, client_id: &str, scope: &str) -> Result<Response, Error> {
    let t = now();
    let ttl = i64::try_from(s.cfg.access_ttl.as_secs()).unwrap_or(3600);
    let claims = AccessClaims {
        iss: &s.cfg.issuer,
        aud: &s.cfg.resource,
        sub: SUBJECT,
        client_id,
        scope,
        iat: t,
        exp: t + ttl,
        jti: random_token()?,
    };
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(s.key.kid.clone());
    header.typ = Some("at+jwt".into());
    let access = jsonwebtoken::encode(&header, &claims, &s.key.encoding)
        .map_err(|e| Error::Key(format!("signing failed: {e}")))?;
    let refresh = random_token()?;
    let refresh_ttl = i64::try_from(s.cfg.refresh_ttl.as_secs()).unwrap_or(0);
    s.store
        .put_refresh(&hash_refresh(&refresh), client_id, scope, t + refresh_ttl)?;
    Ok(no_store(
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ttl,
            "refresh_token": refresh,
            "scope": scope,
        }))
        .into_response(),
    ))
}

async fn token(State(s): Srv, _h: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    let invalid = |d: &str| json_error(StatusCode::BAD_REQUEST, "invalid_grant", d);
    let Some(client_id) = f.client_id.as_deref() else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client_id is required",
        );
    };
    match s.store.client(client_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return json_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client");
        }
        Err(e) => return server_error(&e),
    }
    let result = match f.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(redirect_uri), Some(verifier)) = (
                f.code.as_deref(),
                f.redirect_uri.as_deref(),
                f.code_verifier.as_deref(),
            ) else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code, redirect_uri and code_verifier are required",
                );
            };
            // Single use: removed whether or not the checks below pass.
            let Some(c) = lock(&s.codes).remove(code) else {
                return invalid("unknown or already used code");
            };
            if c.expires <= now() || c.client_id != client_id || c.redirect_uri != redirect_uri {
                return invalid("code does not match this request");
            }
            if !pkce_ok(verifier, &c.challenge) {
                return invalid("PKCE verification failed");
            }
            issue(&s, client_id, &c.scope)
        }
        "refresh_token" => {
            let Some(rt) = f.refresh_token.as_deref() else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required",
                );
            };
            match s.store.take_refresh(&hash_refresh(rt), now()) {
                Ok(Some(g)) if g.client_id == client_id => issue(&s, client_id, &g.scope),
                Ok(_) => return invalid("refresh token is invalid, used or expired"),
                Err(e) => Err(e),
            }
        }
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "unsupported grant_type",
            );
        }
    };
    result.unwrap_or_else(|e| server_error(&e))
}
