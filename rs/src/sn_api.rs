//! Port of `src/sn-api.ts` — the Standard Notes API client: PKCE login with
//! MFA challenge handling, session refresh, logout with 404/405 fallback,
//! and paged sync. Response parsing stays dynamic (serde_json::Value), the
//! way the TS module treats bodies as `unknown` — the server's shapes are
//! steering data, not a contract to model.

use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::http::{
    cookie_pair, delete_request, post_request, send_json, ApiError, Fetch, HttpError,
    HttpRequest, HttpResponse, SendResult, API_VERSION,
};
use crate::kdf::{self, KdfParams};
use crate::proto004::EncryptedItem;

/// `src/session-file.ts`'s SessionSecrets. The db_key is the one secret this
/// struct carries; it moves to a Zeroizing type when the session-file port
/// lands and the field stops crossing module boundaries as a plain string.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionSecrets {
    pub account_email: String,
    pub refresh_token: String,
    pub access_token: String,
    pub access_expiration_ms: u64,
    pub refresh_expiration_ms: u64,
    pub access_cookie: String,
    pub refresh_cookie: String,
    pub db_key: String,
}

impl core::fmt::Debug for SessionSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionSecrets")
            .field("account_email", &self.account_email)
            .field("refresh_token", &"[redacted]")
            .field("access_token", &"[redacted]")
            .field("access_expiration_ms", &self.access_expiration_ms)
            .field("refresh_expiration_ms", &self.refresh_expiration_ms)
            .field("access_cookie", &"[redacted]")
            .field("refresh_cookie", &"[redacted]")
            .field("db_key", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ApiClientError {
    Api(ApiError),
    User(String),
    Network(String),
    NonJson(u16),
    Kdf(kdf::KdfError),
}

impl core::fmt::Display for ApiClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Api(error) => f.write_str(&error.message),
            Self::User(message) => f.write_str(message),
            Self::Network(detail) => write!(f, "network failure: {detail}"),
            Self::NonJson(status) => write!(f, "HTTP {status} returned a non-JSON body"),
            Self::Kdf(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ApiClientError {}

impl From<HttpError> for ApiClientError {
    fn from(error: HttpError) -> Self {
        match error {
            HttpError::Api(error) => Self::Api(error),
            HttpError::NonJsonBody(status) => Self::NonJson(status),
            HttpError::Network(detail) => Self::Network(detail),
        }
    }
}

impl From<kdf::KdfError> for ApiClientError {
    fn from(error: kdf::KdfError) -> Self {
        Self::Kdf(error)
    }
}

pub fn pkce_challenge(verifier: &str) -> String {
    let hex = hex::encode(Sha256::digest(verifier.as_bytes()));
    URL_SAFE_NO_PAD.encode(hex.as_bytes())
}

/// PKCE pair. The verifier keeps base64 padding; Standard Notes hashes that
/// string.
pub fn create_pkce() -> (String, String) {
    let mut bytes = [0u8; 64];
    getrandom::fill(&mut bytes).expect("system rng");
    let verifier = BASE64.encode(bytes).replace('+', "-").replace('/', "_");
    let challenge = pkce_challenge(&verifier);
    (verifier, challenge)
}

pub fn random_db_key() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("system rng");
    hex::encode(bytes)
}

static EMPTY_OBJECT: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);

fn as_record(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

/// TS's `??` chain over field names: the first present, non-null value wins —
/// a JSON `null` under the primary name falls through to the alias.
fn field<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    names
        .iter()
        .filter_map(|name| object.get(*name))
        .find(|value| !value.is_null())
}

/// `data` when it is an object, else the root itself — the TS `unwrap`.
fn unwrapped(body: &Value) -> &Map<String, Value> {
    let data = body.as_object().and_then(|object| object.get("data")).and_then(Value::as_object);
    data.unwrap_or_else(|| body.as_object().unwrap_or(&*EMPTY_OBJECT))
}

fn coerce_string(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(other) => other.to_string(),
    }
}

fn number_or_undefined(value: Option<&Value>) -> Option<f64> {
    match value {
        // Integer-backed JSON numbers are common (kdf_iterations: 5); only
        // non-finite floats are rejected.
        Some(Value::Number(number)) => number.as_f64().filter(|value| value.is_finite()),
        Some(Value::String(text)) if !text.is_empty() => text.parse::<f64>().ok().filter(|value| value.is_finite()),
        _ => None,
    }
}

/// Server-controlled numbers become integer params only when finite and in
/// range: an "inf" or 5e9 kdf_iterations must fall back to the default, not
/// saturate into a decades-long Argon2id run.
fn bounded_u32(value: f64) -> Option<u32> {
    if (0.0..=u32::MAX as f64).contains(&value) {
        Some(value as u32)
    } else {
        None
    }
}

fn bounded_u64(value: f64) -> Option<u64> {
    if (0.0..=u64::MAX as f64).contains(&value) {
        Some(value as u64)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaChallenge {
    pub mfa_key: String,
    pub message: String,
}

/// An MFA challenge whether the server answers with it in a 200 body or (the
/// real shape) an HTTP error body.
pub fn mfa_challenge(body: &Value) -> Option<MfaChallenge> {
    let data = unwrapped(body);
    // TS's asRecord() chains: a non-object error under `data` falls through
    // to the root's error.
    let error = data
        .get("error")
        .filter(|value| value.is_object())
        .or_else(|| as_record(body).and_then(|object| object.get("error")))
        .filter(|value| value.is_object())?;
    let tag = coerce_string(error.get("tag"));
    if tag != "mfa-required" && tag != "mfa-invalid" {
        return None;
    }
    // TS requires typeof mfa_key === "string" — a number is no challenge.
    let mfa_key = match error.get("payload").and_then(|payload| payload.get("mfa_key")) {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => return None,
    };
    let message = match error.get("message") {
        Some(Value::String(text)) => text.clone(),
        _ => "Two-factor code required".to_string(),
    };
    Some(MfaChallenge { mfa_key, message })
}

pub fn parse_key_params(body: &Value) -> Result<KdfParams, ApiClientError> {
    let data = unwrapped(body);
    let version = coerce_string(data.get("version"));
    let identifier = coerce_string(data.get("identifier"));
    let pw_nonce = coerce_string(field(data, &["pw_nonce", "pwNonce"]));
    let iterations = number_or_undefined(data.get("kdf_iterations")).and_then(bounded_u32);
    let memory = number_or_undefined(data.get("kdf_memory")).and_then(bounded_u64);
    let parallelism = number_or_undefined(data.get("kdf_parallelism")).and_then(bounded_u32);
    if version.is_empty() || identifier.is_empty() || pw_nonce.is_empty() {
        return Err(ApiClientError::User(
            "login parameters were missing version, identifier, or salt seed".into(),
        ));
    }
    Ok(KdfParams { version, identifier, pw_nonce, iterations, memory, parallelism })
}

/// `n < 1e12` means seconds; anything larger is already milliseconds.
fn expiration_ms(value: Option<&Value>) -> u64 {
    let number = number_or_undefined(value).unwrap_or(0.0);
    if !number.is_finite() || number <= 0.0 {
        return 0;
    }
    let scaled = if number < 1e12 { number * 1000.0 } else { number };
    scaled as u64
}

pub fn parse_session_body(
    body: &Value,
    set_cookies: &[String],
    db_key: &str,
) -> Result<SessionSecrets, ApiClientError> {
    let data = unwrapped(body);
    let session = data
        .get("session")
        .and_then(Value::as_object)
        .or_else(|| data.get("Session").and_then(Value::as_object))
        .unwrap_or(&*EMPTY_OBJECT);
    let access_token = coerce_string(session.get("access_token"));
    let refresh_token = coerce_string(session.get("refresh_token"));
    if access_token.is_empty() || refresh_token.is_empty() {
        return Err(ApiClientError::User("login response did not include session tokens".into()));
    }
    let access_expiration = field(session, &["access_expiration", "access_token_expiration"]);
    let refresh_expiration = field(session, &["refresh_expiration", "refresh_token_expiration"]);
    Ok(SessionSecrets {
        account_email: String::new(),
        refresh_token,
        access_token,
        access_expiration_ms: expiration_ms(access_expiration),
        refresh_expiration_ms: expiration_ms(refresh_expiration),
        access_cookie: cookie_pair(set_cookies, "access_token"),
        refresh_cookie: cookie_pair(set_cookies, "refresh_token"),
        db_key: db_key.to_string(),
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncPage {
    pub items: Vec<EncryptedItem>,
    pub sync_token: Option<String>,
    pub cursor_token: Option<String>,
    pub conflicts: usize,
}

pub fn parse_sync_page(body: &Value) -> SyncPage {
    let data = unwrapped(body);
    let items = data
        .get("retrieved_items")
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|item| EncryptedItem::deserialize(item).ok())
                .collect()
        })
        .unwrap_or_default();
    let conflicts = data.get("conflicts").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    let token = |value: Option<&Value>| match value {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    };
    SyncPage {
        items,
        sync_token: token(data.get("sync_token")),
        cursor_token: token(data.get("cursor_token")),
        conflicts,
    }
}

/// The API client over an injected transport.
pub struct ApiClient {
    base: String,
    fetch: Box<dyn Fetch>,
}

/// `FnMut`-based transport for tests — canned responses, captured requests.
pub struct FnFetch<F: FnMut(HttpRequest) -> Result<HttpResponse, HttpError>> {
    function: std::cell::RefCell<F>,
}

impl<F: FnMut(HttpRequest) -> Result<HttpResponse, HttpError>> FnFetch<F> {
    pub fn new(function: F) -> Self {
        Self { function: RefCell::new(function) }
    }
}

impl<F: FnMut(HttpRequest) -> Result<HttpResponse, HttpError>> Fetch for FnFetch<F> {
    fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        (self.function.borrow_mut())(request)
    }
}

use std::cell::RefCell;

fn merge_body(base: &Map<String, Value>, extra: &Map<String, Value>) -> Value {
    let mut merged = base.clone();
    for (key, value) in extra {
        merged.insert(key.clone(), value.clone());
    }
    Value::Object(merged)
}

impl ApiClient {
    pub fn new(api_url: &str, fetch: Box<dyn Fetch>) -> Self {
        Self { base: api_url.trim_end_matches('/').to_string(), fetch }
    }

    fn post(&self, path: &str, body: &Value, headers: &[(String, String)]) -> Result<SendResult, HttpError> {
        send_json(
            self.fetch.as_ref(),
            post_request(format!("{}{}", self.base, path), headers.to_vec(), body.to_string()),
            &mut crate::http::HttpOptions::new(),
        )
    }

    /// One POST that handles an MFA challenge whether the server answers with
    /// it in a 200 body or (the real shape) an HTTP error body. Prompts at
    /// most once; a second challenge is a rejection, not another prompt.
    fn post_with_mfa(
        &self,
        path: &str,
        base_body: &Map<String, Value>,
        headers: &[(String, String)],
        mfa_code: &mut dyn FnMut() -> Result<String, ApiClientError>,
        seeded_extra: Option<&Map<String, Value>>,
    ) -> Result<(SendResult, Map<String, Value>), ApiClientError> {
        let mut extra = seeded_extra.cloned().unwrap_or_default();
        for attempt in 0..2 {
            let merged = merge_body(base_body, &extra);
            match self.post(path, &merged, headers) {
                Err(HttpError::Api(api_error)) => {
                    let challenge = mfa_challenge(&api_error.body);
                    let Some(challenge) = challenge else { return Err(ApiClientError::Api(api_error)) };
                    if attempt > 0 {
                        return Err(ApiClientError::User("two-factor authentication was rejected".into()));
                    }
                    let code = mfa_code()?;
                    extra.insert(challenge.mfa_key, Value::String(code));
                }
                Err(error) => return Err(error.into()),
                Ok(response) => {
                    let Some(challenge) = mfa_challenge(&response.body) else {
                        return Ok((response, extra));
                    };
                    if attempt > 0 {
                        return Err(ApiClientError::User("two-factor authentication was rejected".into()));
                    }
                    let code = mfa_code()?;
                    extra.insert(challenge.mfa_key, Value::String(code));
                }
            }
        }
        Err(ApiClientError::User("could not complete two-factor authentication".into()))
    }

    pub fn key_params(
        &self,
        email: &str,
        mfa_code: &mut dyn FnMut() -> Result<String, ApiClientError>,
    ) -> Result<KdfParams, ApiClientError> {
        let (_, challenge) = create_pkce();
        let body = json!({ "api": API_VERSION, "email": email, "code_challenge": challenge });
        let (response, _) = self.post_with_mfa("/v2/login-params", body.as_object().expect("object"), &[], mfa_code, None)?;
        parse_key_params(&response.body)
    }

    /// Full login: key params, Argon2id derivation, then the session POST.
    /// Returns the secrets plus the master key (which the caller persists in
    /// the session under its own name).
    pub fn login(
        &self,
        email: &str,
        password: &str,
        mfa_code: &mut dyn FnMut() -> Result<String, ApiClientError>,
        db_key: &str,
    ) -> Result<(SessionSecrets, String), ApiClientError> {
        let (verifier, challenge) = create_pkce();
        let params_body = json!({ "api": API_VERSION, "email": email, "code_challenge": challenge });
        let (params_response, params_extra) =
            self.post_with_mfa("/v2/login-params", params_body.as_object().expect("object"), &[], mfa_code, None)?;
        let params = parse_key_params(&params_response.body)?;
        let root = kdf::derive_root_key(password, &params)?;
        let login_body = json!({
            "api": API_VERSION,
            "email": email,
            "password": root.server_password_hex(),
            "code_verifier": verifier,
            "ephemeral": false,
        });
        let (login_response, _) = self.post_with_mfa(
            "/v2/login",
            login_body.as_object().expect("object"),
            &[],
            mfa_code,
            Some(&params_extra),
        )?;
        let secrets = parse_session_body(&login_response.body, &login_response.set_cookies, db_key)?;
        Ok((secrets, root.master_key_hex()))
    }

    pub fn refresh(&self, secrets: &SessionSecrets) -> Result<SessionSecrets, ApiClientError> {
        let mut headers: Vec<(String, String)> = vec![("Authorization".into(), format!("Bearer {}", secrets.refresh_token))];
        if !secrets.refresh_cookie.is_empty() {
            headers.push(("Cookie".into(), secrets.refresh_cookie.clone()));
        }
        let response = self.post("/v1/sessions/refresh", &json!({ "api": API_VERSION }), &headers)?;
        let mut next = parse_session_body(&response.body, &response.set_cookies, &secrets.db_key)?;
        if next.account_email.is_empty() {
            next.account_email = secrets.account_email.clone();
        }
        if next.access_cookie.is_empty() {
            next.access_cookie = secrets.access_cookie.clone();
        }
        if next.refresh_cookie.is_empty() {
            next.refresh_cookie = secrets.refresh_cookie.clone();
        }
        Ok(next)
    }

    pub fn logout(&self, secrets: &SessionSecrets) -> Result<(), ApiClientError> {
        let headers = access_headers(secrets, false);
        match self.post("/v1/logout", &json!({ "api": API_VERSION }), &headers) {
            Ok(_) => Ok(()),
            Err(HttpError::Api(error)) if error.status == 404 || error.status == 405 => {
                send_json(
                    self.fetch.as_ref(),
                    delete_request(format!("{}/v1/sessions", self.base), headers),
                    &mut crate::http::HttpOptions::new(),
                )
                .map_err(ApiClientError::from)?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn sync_page(
        &self,
        secrets: &SessionSecrets,
        sync_token: Option<&str>,
        cursor_token: Option<&str>,
    ) -> Result<SyncPage, ApiClientError> {
        let mut body = Map::new();
        body.insert("api".into(), json!(API_VERSION));
        body.insert("items".into(), json!([]));
        body.insert("limit".into(), json!(150));
        if let Some(token) = sync_token {
            body.insert("sync_token".into(), json!(token));
        }
        if let Some(token) = cursor_token {
            body.insert("cursor_token".into(), json!(token));
        }
        let response = self.post("/v1/items", &Value::Object(body), &access_headers(secrets, true))?;
        Ok(parse_sync_page(&response.body))
    }
}

fn is_auth_failure(error: &ApiClientError) -> bool {
    matches!(error, ApiClientError::Api(error) if error.status == 401 || error.status == 498)
}

/// One copy of the access credentials: the Bearer header, plus the cookie
/// only for legacy `2:`-prefixed tokens. `bearer_always` is true on the sync
/// path (TS sends the header unconditionally there) and gated on logout.
fn access_headers(secrets: &SessionSecrets, bearer_unconditional: bool) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if bearer_unconditional || !secrets.access_token.is_empty() {
        headers.push(("Authorization".into(), format!("Bearer {}", secrets.access_token)));
    }
    if !secrets.access_cookie.is_empty() && secrets.access_token.starts_with("2:") {
        headers.push(("Cookie".into(), secrets.access_cookie.clone()));
    }
    headers
}

/// Run one authenticated call. Refreshes an expired access token first, and
/// on 401/498 refreshes and retries the call exactly once.
pub fn with_access<R>(
    secrets: &SessionSecrets,
    save: &mut dyn FnMut(&SessionSecrets) -> Result<(), ApiClientError>,
    api: &ApiClient,
    now_ms: u64,
    run: &mut dyn FnMut(&SessionSecrets) -> Result<R, ApiClientError>,
) -> Result<R, ApiClientError> {
    let mut current = secrets.clone();
    let expiring = current.access_expiration_ms > 0 && current.access_expiration_ms <= now_ms + 30_000;
    if current.access_token.is_empty() || expiring {
        current = api.refresh(&current)?;
        save(&current)?;
    }
    match run(&current) {
        Ok(value) => Ok(value),
        Err(error) => {
            if !is_auth_failure(&error) {
                return Err(error);
            }
            let refreshed = api.refresh(&current).and_then(|next| {
                save(&next)?;
                Ok(next)
            });
            let Ok(next) = refreshed else {
                return Err(ApiClientError::User("session expired — run sns login".into()));
            };
            match run(&next) {
                Ok(value) => Ok(value),
                Err(again) => {
                    if is_auth_failure(&again) {
                        Err(ApiClientError::User("session expired — run sns login".into()))
                    } else {
                        Err(again)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpRequest, HttpResponse, HttpOptions};
    use std::cell::RefCell;
    use std::rc::Rc;

    const SESSION_JSON: &str = r#"{
        "data": { "session": {
            "access_token": "access-1", "refresh_token": "refresh-1",
            "access_expiration": 1800000000000, "refresh_expiration": 1900000000000
        } }
    }"#;

    fn canned(status: u16, body: &str) -> HttpResponse {
        HttpResponse { status, body: body.to_string(), set_cookies: Vec::new() }
    }

    fn api_json(status: u16, body: &str) -> Result<HttpResponse, HttpError> {
        Ok(canned(status, body))
    }

    fn no_mfa() -> Result<String, ApiClientError> {
        Err(ApiClientError::User("no mfa".into()))
    }

    fn fixed_code() -> Result<String, ApiClientError> {
        Ok("123456".into())
    }

    #[test]
    fn pkce_matches_the_node_crypto_vector() {
        let verifier = "u".repeat(86);
        assert_eq!(
            pkce_challenge(&verifier),
            "NTY4M2Y5OThlYjhhZTg4OWU0ZmQ2YzVlOGY3NmYxNzFkN2FjM2JlMzI4ODg0OTVhMzA2ZjBmNGQwOThkODkzOA"
        );
    }

    #[test]
    fn pkce_pair_keeps_padding_and_avoids_url_unsafe_chars() {
        let (verifier, challenge) = create_pkce();
        assert_eq!(verifier.len(), 88, "64 bytes of base64, padding kept");
        assert!(!verifier.contains('+') && !verifier.contains('/'));
        assert_eq!(challenge, pkce_challenge(&verifier));
    }

    #[test]
    fn mfa_challenge_reads_both_the_200_and_error_shapes() {
        let error_body = json!({
            "data": { "error": { "tag": "mfa-required", "message": "code", "payload": { "mfa_key": "mfa_abc" } } }
        });
        let challenge = mfa_challenge(&error_body).expect("error shape");
        assert_eq!(challenge.mfa_key, "mfa_abc");
        assert_eq!(challenge.message, "code");

        let ok_body = json!({ "error": { "tag": "mfa-invalid", "payload": { "mfa_key": "mfa_xyz" } } });
        let challenge = mfa_challenge(&ok_body).expect("200 shape");
        assert_eq!(challenge.mfa_key, "mfa_xyz");
        assert_eq!(challenge.message, "Two-factor code required", "default message");

        assert_eq!(mfa_challenge(&json!({ "error": { "tag": "invalid-auth" } })), None);
        assert_eq!(mfa_challenge(&json!({ "error": { "tag": "mfa-required", "payload": {} } })), None);
        assert_eq!(mfa_challenge(&json!({})), None);
    }

    #[test]
    fn key_params_parse_the_server_shape() {
        let body = json!({
            "data": { "version": "004", "identifier": "a@b.c", "pw_nonce": "aa", "kdf_iterations": 5, "kdf_memory": 67108864, "kdf_parallelism": 1 }
        });
        let params = parse_key_params(&body).expect("parses");
        assert_eq!(params.version, "004");
        assert_eq!(params.identifier, "a@b.c");
        assert_eq!(params.pw_nonce, "aa");
        assert_eq!(params.iterations, Some(5));
        assert_eq!(params.memory, Some(67_108_864));
        assert_eq!(params.parallelism, Some(1));

        let missing = parse_key_params(&json!({ "data": { "version": "004" } }))
            .expect_err("missing fields refuse");
        assert_eq!(
            missing,
            ApiClientError::User("login parameters were missing version, identifier, or salt seed".into())
        );
    }

    #[test]
    fn session_body_harvests_tokens_expirations_and_cookies() {
        let body: Value = serde_json::from_str(SESSION_JSON).expect("json");
        let cookies = vec![
            "access_token=a; Path=/; HttpOnly".to_string(),
            "refresh_token=r; Path=/; HttpOnly".to_string(),
        ];
        let secrets = parse_session_body(&body, &cookies, "cd").expect("parses");
        assert_eq!(secrets.access_token, "access-1");
        assert_eq!(secrets.refresh_token, "refresh-1");
        assert_eq!(secrets.access_expiration_ms, 1_800_000_000_000);
        assert_eq!(secrets.refresh_cookie, "refresh_token=r");

        // Seconds-style expirations scale to milliseconds; legacy field name works.
        let legacy = json!({ "Session": { "access_token": "a", "refresh_token": "r", "access_token_expiration": 1800 } });
        let secrets = parse_session_body(&legacy, &[], "cd").expect("parses");
        assert_eq!(secrets.access_expiration_ms, 1_800_000);

        let empty = parse_session_body(&json!({}), &[], "cd").expect_err("tokens required");
        assert_eq!(empty, ApiClientError::User("login response did not include session tokens".into()));
    }

    #[test]
    fn sync_page_parses_items_tokens_and_conflicts() {
        let body = json!({
            "data": {
                "retrieved_items": [
                    { "uuid": "u1", "content_type": "Note", "deleted": false, "updated_at_timestamp": 123 },
                    { "uuid": "u2", "content_type": "SN|ItemsKey", "enc_item_key": "k" }
                ],
                "sync_token": "t1",
                "cursor_token": null,
                "conflicts": [ {}, {} ]
            }
        });
        let page = parse_sync_page(&body);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].uuid, "u1");
        assert_eq!(page.items[0].deleted, Some(false));
        assert_eq!(page.items[1].enc_item_key.as_deref(), Some("k"));
        assert_eq!(page.sync_token.as_deref(), Some("t1"));
        assert_eq!(page.cursor_token, None);
        assert_eq!(page.conflicts, 2);

        let empty = parse_sync_page(&json!({}));
        assert_eq!(empty.items.len(), 0);
        assert_eq!(empty.sync_token, None);
        assert_eq!(empty.conflicts, 0);
    }

    #[test]
    fn cookie_pair_takes_the_first_matching_pair() {
        let cookies = vec![
            "other=x; Path=/".to_string(),
            "access_token=a; HttpOnly".to_string(),
            "access_token=b; HttpOnly".to_string(),
        ];
        assert_eq!(cookie_pair(&cookies, "access_token"), "access_token=a");
        assert_eq!(cookie_pair(&cookies, "refresh_token"), "");
    }

    #[test]
    fn login_sends_the_server_password_and_stores_tokens() {
        let email = "sn004@lessknown.co.uk";
        let pw_nonce = "2c409996650e46c748856fbd6aa549f89f35be055a8f9bfacdf0c4b29b2152e9";
        let root = kdf::derive_root_key(
            "debugtest",
            &KdfParams {
                version: "004".into(),
                identifier: email.into(),
                pw_nonce: pw_nonce.into(),
                iterations: None,
                memory: None,
                parallelism: None,
            },
        )
        .expect("derives");
        let seen_password: Rc<RefCell<String>> = Rc::new(RefCell::new(String::new()));
        let seen = seen_password.clone();
        let fetch = FnFetch::new(move |request: HttpRequest| {
            if request.url.ends_with("/v2/login-params") {
                return api_json(200, &format!(r#"{{"data":{{"version":"004","identifier":"{email}","pw_nonce":"{pw_nonce}"}}}}"#));
            }
            if request.url.ends_with("/v2/login") {
                let body: Value = serde_json::from_str(request.body.as_deref().unwrap_or("null")).expect("body json");
                *seen.borrow_mut() = coerce_string(body.get("password"));
                return api_json(200, SESSION_JSON);
            }
            api_json(404, "no")
        });
        let api = ApiClient::new("http://127.0.0.1:1", Box::new(fetch));
        let (secrets, master_key) = api.login(email, "debugtest", &mut no_mfa, &"cd".repeat(32)).expect("logs in");
        assert_eq!(*seen_password.borrow(), root.server_password_hex());
        assert_eq!(secrets.refresh_token, "refresh-1");
        assert_eq!(secrets.db_key, "cd".repeat(32));
        assert_eq!(master_key, root.master_key_hex());
    }

    #[test]
    fn login_completes_when_mfa_arrives_as_an_http_error_challenge() {
        let seen_mfa_params: Rc<RefCell<String>> = Rc::new(RefCell::new(String::new()));
        let seen_mfa_login: Rc<RefCell<String>> = Rc::new(RefCell::new(String::new()));
        let params_calls = Rc::new(RefCell::new(0));
        let seen_params = seen_mfa_params.clone();
        let seen_login = seen_mfa_login.clone();
        let calls = params_calls.clone();
        let fetch = FnFetch::new(move |request: HttpRequest| {
            if request.url.ends_with("/v2/login-params") {
                *calls.borrow_mut() += 1;
                let body: Value = serde_json::from_str(request.body.as_deref().unwrap_or("null")).expect("json");
                *seen_params.borrow_mut() = coerce_string(body.get("mfa_abc"));
                if *calls.borrow() == 1 {
                    // The real challenge shape: an HTTP error carrying the mfa tag.
                    return api_json(
                        401,
                        r#"{"data":{"error":{"tag":"mfa-required","message":"code","payload":{"mfa_key":"mfa_abc"}}}}"#,
                    );
                }
                return api_json(200, r#"{"data":{"version":"004","identifier":"mfa@example.test","pw_nonce":"aa"}}"#);
            }
            if request.url.ends_with("/v2/login") {
                let body: Value = serde_json::from_str(request.body.as_deref().unwrap_or("null")).expect("json");
                *seen_login.borrow_mut() = coerce_string(body.get("mfa_abc"));
                return api_json(200, SESSION_JSON);
            }
            api_json(404, "no")
        });
        let api = ApiClient::new("http://127.0.0.1:1", Box::new(fetch));
        let prompts = Rc::new(RefCell::new(0));
        let prompts_clone = prompts.clone();
        let mut mfa = move || {
            *prompts_clone.borrow_mut() += 1;
            fixed_code()
        };
        let (secrets, _) = api.login("mfa@example.test", "pw", &mut mfa, &"cd".repeat(32)).expect("logs in");
        assert_eq!(*prompts.borrow(), 1, "prompted once, code reused for both calls");
        assert_eq!(*params_calls.borrow(), 2);
        assert_eq!(*seen_mfa_params.borrow(), "123456");
        assert_eq!(*seen_mfa_login.borrow(), "123456");
        assert_eq!(secrets.refresh_token, "refresh-1");
    }

    #[test]
    fn a_persistent_mfa_challenge_is_a_rejection_not_a_prompt_loop() {
        let fetch = FnFetch::new(|_: HttpRequest| {
            api_json(401, r#"{"data":{"error":{"tag":"mfa-required","message":"code","payload":{"mfa_key":"mfa_abc"}}}}"#)
        });
        let api = ApiClient::new("http://127.0.0.1:1", Box::new(fetch));
        let error = api.key_params("x@y.z", &mut fixed_code).expect_err("persistent challenge rejects");
        assert!(error.to_string().contains("two-factor"), "got: {error}");
    }

    #[test]
    fn logout_falls_back_to_delete_on_404() {
        let methods: Rc<RefCell<Vec<&'static str>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = methods.clone();
        let fetch = FnFetch::new(move |request: HttpRequest| {
            seen.borrow_mut().push(request.method);
            if request.method == "POST" {
                return api_json(404, "{}");
            }
            api_json(200, "{}")
        });
        let api = ApiClient::new("http://127.0.0.1:1", Box::new(fetch));
        let secrets = parse_session_body(&serde_json::from_str::<Value>(SESSION_JSON).expect("json"), &[], "cd").expect("secrets");
        api.logout(&secrets).expect("logout succeeds via fallback");
        assert_eq!(*methods.borrow(), vec!["POST", "DELETE"]);
    }

    #[test]
    fn with_access_refreshes_once_on_a_401_and_retries_with_the_new_token() {
        let sync_calls = Rc::new(RefCell::new(0));
        let refresh_calls = Rc::new(RefCell::new(0));
        let last_auth = Rc::new(RefCell::new(String::new()));
        let sync_seen = sync_calls.clone();
        let refresh_seen = refresh_calls.clone();
        let auth_seen = last_auth.clone();
        let fetch = FnFetch::new(move |request: HttpRequest| {
            if let Some((_, value)) = request.headers.iter().find(|(name, _)| name == "Authorization") {
                *auth_seen.borrow_mut() = value.clone();
            }
            if request.url.ends_with("/v1/items") {
                *sync_seen.borrow_mut() += 1;
                if *sync_seen.borrow() == 1 {
                    return api_json(401, "{}");
                }
                return api_json(200, r#"{"data":{"retrieved_items":[],"sync_token":"t1","conflicts":[]}}"#);
            }
            if request.url.ends_with("/v1/sessions/refresh") {
                *refresh_seen.borrow_mut() += 1;
                return api_json(200, SESSION_JSON);
            }
            api_json(404, "no")
        });
        let api = ApiClient::new("http://127.0.0.1:1", Box::new(fetch));
        let secrets = SessionSecrets {
            account_email: "me@example.test".into(),
            refresh_token: "refresh-1".into(),
            access_token: "access-1".into(),
            access_expiration_ms: 0,
            refresh_expiration_ms: 1_900_000_000_000,
            access_cookie: String::new(),
            refresh_cookie: String::new(),
            db_key: "cd".repeat(32),
        };
        let saved: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let saved_seen = saved.clone();
        let mut save = |next: &SessionSecrets| {
            saved_seen.borrow_mut().push(next.access_token.clone());
            Ok(())
        };
        let mut run = |current: &SessionSecrets| api.sync_page(current, None, None);
        let page = with_access(&secrets, &mut save, &api, 0, &mut run).expect("call succeeds");
        assert_eq!(page.sync_token.as_deref(), Some("t1"));
        assert_eq!(*refresh_calls.borrow(), 1);
        assert_eq!(*sync_calls.borrow(), 2);
        assert_eq!(*saved.borrow(), vec!["access-1".to_string()]);
        assert_eq!(*last_auth.borrow(), "Bearer access-1");
    }

    #[test]
    fn send_json_429_backs_off_and_stops_after_three_tries() {
        let fetch = FnFetch::new(|_: HttpRequest| api_json(429, r#"{"error":{"message":"slow down"}}"#));
        let sleeps: Rc<RefCell<Vec<u64>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = sleeps.clone();
        {
            let mut sleep_fn = |ms: u64| seen.borrow_mut().push(ms);
            let mut options = HttpOptions { sleep: Some(&mut sleep_fn), on_unauthorized: None };
            let request = HttpRequest { url: "https://example.test/items".into(), method: "POST", headers: Vec::new(), body: None };
            let error = send_json(&fetch, request, &mut options).expect_err("429 exhausts");
            assert!(error.to_string().contains("HTTP 429"), "got: {error}");
        }
        assert_eq!(*sleeps.borrow(), vec![1000, 2000]);
    }

    #[test]
    fn send_json_401_invokes_refresh_once_and_does_not_loop() {
        let fetch = FnFetch::new(|_: HttpRequest| api_json(401, r#"{"error":{"tag":"invalid-auth","message":"no"}}"#));
        let mut refreshed = 0;
        {
            let mut hook = || {
                refreshed += 1;
                Ok(())
            };
            let mut options = HttpOptions { sleep: None, on_unauthorized: Some(&mut hook) };
            let request = HttpRequest { url: "https://example.test/items".into(), method: "POST", headers: Vec::new(), body: None };
            let error = send_json(&fetch, request, &mut options).expect_err("401 exhausts");
            assert!(error.to_string().contains("HTTP 401"));
        }
        assert_eq!(refreshed, 1);
    }

    #[test]
    fn send_json_a_recovered_401_returns_the_second_response() {
        let calls = Rc::new(RefCell::new(0));
        let seen = calls.clone();
        let fetch = FnFetch::new(move |_: HttpRequest| {
            *seen.borrow_mut() += 1;
            if *seen.borrow() == 1 {
                api_json(498, "{}")
            } else {
                api_json(200, r#"{"data":{"ok":true}}"#)
            }
        });
        let mut hook = || Ok(());
        let mut options = HttpOptions { sleep: None, on_unauthorized: Some(&mut hook) };
        let request = HttpRequest { url: "https://example.test/items".into(), method: "GET", headers: Vec::new(), body: None };
        let result = send_json(&fetch, request, &mut options).expect("recovers");
        assert_eq!(result.status, 200);
        assert_eq!(*calls.borrow(), 2);
    }

    #[test]
    fn http_failures_keep_status_and_parsed_body() {
        let fetch = FnFetch::new(|_: HttpRequest| {
            api_json(401, r#"{"data":{"error":{"tag":"mfa-required","payload":{"mfa_key":"mfa_abc"}}}}"#)
        });
        let mut options = HttpOptions::new();
        let request = HttpRequest { url: "https://example.test/login-params".into(), method: "POST", headers: Vec::new(), body: None };
        let error = send_json(&fetch, request, &mut options).expect_err("api failure");
        let HttpError::Api(api_error) = error else {
            panic!("expected an Api error");
        };
        assert_eq!(api_error.status, 401);
        assert_eq!(api_error.body["data"]["error"]["tag"], "mfa-required");
        assert!(api_error.message.contains("HTTP 401"));
    }

    /// The production transport over a real socket — one canned response with
    /// two Set-Cookie headers, proving header parsing end to end.
    #[test]
    fn reqwest_transport_parses_a_real_http_response() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let mut stream = stream;
            let mut buffer = [0u8; 2048];
            let _ = std::io::Read::read(&mut stream, &mut buffer);
            let body = br#"{"data":{"ok":true}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: access_token=a; Path=/; HttpOnly\r\nSet-Cookie: refresh_token=r; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(body)
            );
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
        });
        let fetch = crate::http::ReqwestFetch::new().expect("client builds");
        let response = fetch
            .fetch(HttpRequest { url: format!("http://127.0.0.1:{port}/v1/ok"), method: "GET", headers: Vec::new(), body: None })
            .expect("real request succeeds");
        server.join().expect("server thread");
        assert_eq!(response.status, 200);
        assert_eq!(response.set_cookies.len(), 2);
        assert_eq!(cookie_pair(&response.set_cookies, "access_token"), "access_token=a");
        assert_eq!(cookie_pair(&response.set_cookies, "refresh_token"), "refresh_token=r");
    }
}
