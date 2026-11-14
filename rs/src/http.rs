//! Port of `src/http.ts` — one JSON request with 429 backoff (3 tries) and a
//! single 401/498 refresh. The transport is injectable: production uses
//! `ReqwestFetch`, tests use canned closures, mirroring the TS `fetch` hook.

use serde_json::Value;

pub const API_VERSION: &str = "20240226";

/// The client identity the server expects, verbatim from the TS client.
pub const CLIENT_HEADERS: [(&str, &str); 5] = [
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) StandardNotes/3.198.18 Chrome/134.0.6998.205 Electron/35.2.0 Safari/537.36",
    ),
    ("X-SNJS-Version", "2.211.7"),
    ("X-Application-Version", "Desktop-3.201.27"),
    ("Content-Type", "application/json"),
    ("Accept", "application/json"),
];

#[derive(Clone)]
pub struct HttpRequest {
    pub url: String,
    pub method: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub set_cookies: Vec<String>,
}

pub trait Fetch {
    fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpError>;
}

/// Production transport: blocking reqwest over rustls (ring provider, so the
/// C story stays zig-friendly on every target).
pub struct ReqwestFetch {
    client: reqwest::blocking::Client,
}

impl ReqwestFetch {
    pub fn new() -> Result<Self, HttpError> {
        // Install the ring provider once; a second install is a no-op.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::blocking::Client::builder()
            // The TS client sets no timeout; this guards against hung
            // connections without cutting off slow syncs.
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|error| HttpError::Network(error.to_string()))?;
        Ok(Self { client })
    }
}

impl Fetch for ReqwestFetch {
    fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|error| HttpError::Network(error.to_string()))?;
        let mut pending = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            pending = pending.header(name, value);
        }
        if let Some(body) = &request.body {
            pending = pending.body(body.clone());
        }
        let response = pending.send().map_err(|error| HttpError::Network(error.to_string()))?;
        let status = response.status().as_u16();
        let set_cookies = response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_string))
            .collect();
        let body = response.text().map_err(|error| HttpError::Network(error.to_string()))?;
        Ok(HttpResponse { status, body, set_cookies })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub body: Value,
    pub message: String,
}

impl core::fmt::Display for ApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug, PartialEq, Eq)]
pub enum HttpError {
    /// HTTP >= 400 — keeps status and parsed body so callers can steer on
    /// facts (MFA tags, 404/405 fallbacks, auth retries). The message still
    /// summarizes the failure; it never contains secrets.
    Api(ApiError),
    /// `HTTP {status} returned a non-JSON body`
    NonJsonBody(u16),
    Network(String),
}

impl core::fmt::Display for HttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Api(error) => f.write_str(&error.message),
            Self::NonJsonBody(status) => write!(f, "HTTP {status} returned a non-JSON body"),
            Self::Network(detail) => write!(f, "network failure: {detail}"),
        }
    }
}

impl std::error::Error for HttpError {}

fn error_summary(status: u16, body: &str) -> String {
    let parsed: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return format!("HTTP {status}"),
    };
    let root = parsed.as_object();
    let error = root
        .and_then(|object| object.get("data"))
        .and_then(|data| data.get("error"))
        .or_else(|| root.and_then(|object| object.get("error")));
    let tag = error.and_then(|error| error.get("tag")).and_then(Value::as_str).unwrap_or("");
    let message = error
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .or_else(|| root.and_then(|object| object.get("message")).and_then(Value::as_str))
        .unwrap_or("");
    let detail: String = [tag, message].iter().filter(|part| !part.is_empty()).copied().collect::<Vec<_>>().join(": ");
    let detail: String = detail.chars().take(180).collect();
    if detail.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status} {detail}")
    }
}

pub type SleepFn<'a> = &'a mut dyn FnMut(u64);
pub type UnauthorizedFn<'a> = &'a mut dyn FnMut() -> Result<(), HttpError>;

pub struct HttpOptions<'a> {
    pub sleep: Option<SleepFn<'a>>,
    /// Called at most once when the server returns 401 or 498.
    pub on_unauthorized: Option<UnauthorizedFn<'a>>,
}

impl<'a> HttpOptions<'a> {
    pub fn new() -> Self {
        Self { sleep: None, on_unauthorized: None }
    }
}

impl Default for HttpOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SendResult {
    pub status: u16,
    pub body: Value,
    pub set_cookies: Vec<String>,
}

/// One request: 429 backs off (1s, 2s, then gives up); 401/498 triggers the
/// unauthorized hook at most once, so a bad refresh cannot loop.
pub fn send_json(
    fetch: &dyn Fetch,
    request: HttpRequest,
    options: &mut HttpOptions<'_>,
) -> Result<SendResult, HttpError> {
    let mut unauthorized_used = false;
    let mut attempt: u32 = 0;
    loop {
        let response = fetch.fetch(request.clone())?;
        if response.status == 429 && attempt < 2 {
            let ms = 1000 * 2u64.pow(attempt);
            match options.sleep.as_mut() {
                Some(sleep) => sleep(ms),
                None => std::thread::sleep(std::time::Duration::from_millis(ms)),
            }
            attempt += 1;
            continue;
        }
        if (response.status == 401 || response.status == 498)
            && !unauthorized_used
            && options.on_unauthorized.is_some()
        {
            unauthorized_used = true;
            if let Some(hook) = options.on_unauthorized.as_mut() {
                hook()?;
            }
            continue;
        }
        let status = response.status;
        let text = response.body;
        if status >= 400 {
            let message = error_summary(status, &text);
            let body = serde_json::from_str(&text).unwrap_or(Value::Null);
            return Err(HttpError::Api(ApiError { status, body, message }));
        }
        let body = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).map_err(|_| HttpError::NonJsonBody(status))?
        };
        return Ok(SendResult { status, body, set_cookies: response.set_cookies });
    }
}

/// First `name=value` pair among the Set-Cookie headers whose pair starts
/// with `prefix` — how the session's cookie halves are harvested.
pub fn cookie_pair(set_cookies: &[String], prefix: &str) -> String {
    for header in set_cookies {
        let pair = header.split(';').next().unwrap_or("").trim();
        if pair.starts_with(prefix) {
            return pair.to_string();
        }
    }
    String::new()
}

fn client_request(url: String, headers: Vec<(String, String)>, method: &'static str, body: Option<String>) -> HttpRequest {
    let mut all: Vec<(String, String)> = CLIENT_HEADERS
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    all.extend(headers);
    HttpRequest { url, method, headers: all, body }
}

/// Helper for building POST requests with the client identity headers.
pub fn post_request(url: String, headers: Vec<(String, String)>, body: String) -> HttpRequest {
    client_request(url, headers, "POST", Some(body))
}

/// The logout fallback's DELETE carries the same identity headers as a POST.
pub fn delete_request(url: String, headers: Vec<(String, String)>) -> HttpRequest {
    client_request(url, headers, "DELETE", None)
}
