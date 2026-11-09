//! Linear OAuth app token from the client_credentials grant, for the live tracker
//! when LINEAR_API_KEY is not set (tracker.rs, LinearTracker::from_vars).
//!
//! Request (as Henry's oauth-token.sh did on the real Linear test workspace,
//! T14, 2026-11-04): POST <token URL>, Content-Type
//! application/x-www-form-urlencoded, body
//!   grant_type=client_credentials, client_id, client_secret, scope (comma-separated)
//! Answer: {"access_token", "token_type": "Bearer", "expires_in": seconds, "scope"}.
//! Linear (OAuth 2.0 authentication doc, read 2026-11-04): the grant must be
//! turned on for the app; the token acts as the app on all public teams, lives 30
//! days, has no refresh token; asking for different scopes revokes the app's
//! existing client_credentials tokens. So the scope default equals the script's.
//!
//! Settings:
//!   LINEAR_CLIENT_ID, LINEAR_CLIENT_SECRET   both, or neither (one alone is a Config error)
//!   LINEAR_OAUTH_SCOPE   default DEFAULT_SCOPE
//!   LINEAR_TOKEN_URL     default: the origin of LINEAR_API_URL + /oauth/token
//!                        (https://api.linear.app/oauth/token; the compose lab's
//!                        linear-mock serves the same path)
//!
//! Token life: requested lazily before the first GraphQL call, then kept in memory
//! in a process-wide cache (one entry per token URL + client id + scope), so all
//! trackers of one process (run, monthly close, serve) share one token. It is
//! renewed when less than REFRESH_MARGIN_SECS is left (for a token living under
//! twice that, at half its life); a 30-day token is therefore requested once per
//! process run. A refused request (HTTP 4xx) is remembered and not repeated in the
//! same process. Nothing is written to state; the secret and the token never
//! appear in errors, logs or the page (error texts pass through redact()).

use std::sync::Mutex;

use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};
use serde_json::Value;

use super::tracker::TrackerError;
use crate::feeds::common;

/// Scopes asked for; the same as oauth-token.sh, so a run does not revoke a token
/// issued by the script (and vice versa).
pub const DEFAULT_SCOPE: &str = "read,write,issues:create,comments:create";
/// A token is renewed when less than this is left.
pub const REFRESH_MARGIN_SECS: i64 = 300;
/// Path of the token endpoint on the GraphQL endpoint's origin.
pub const TOKEN_PATH: &str = "/oauth/token";

/// What the client_credentials request needs. Debug hides the secret.
#[derive(Clone)]
pub struct ClientCredentials {
    pub token_url: String,
    pub client_id: String,
    client_secret: String,
    pub scope: String,
}

impl std::fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("scope", &self.scope)
            .finish()
    }
}

impl ClientCredentials {
    pub fn new(token_url: &str, client_id: &str, client_secret: &str, scope: &str) -> Self {
        Self { token_url: token_url.into(), client_id: client_id.into(), client_secret: client_secret.into(), scope: scope.into() }
    }

    /// None when neither LINEAR_CLIENT_ID nor LINEAR_CLIENT_SECRET is set; Config
    /// error (naming variables, never values) when only one is, or the token URL is bad.
    pub fn from_vars(get: &dyn Fn(&str) -> Option<String>, api_url: &str) -> Result<Option<Self>, TrackerError> {
        let var = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let (id, secret) = match (var("LINEAR_CLIENT_ID"), var("LINEAR_CLIENT_SECRET")) {
            (None, None) => return Ok(None),
            (Some(id), Some(secret)) => (id, secret),
            (Some(_), None) => return Err(TrackerError::Config(
                "LINEAR_CLIENT_ID is set but LINEAR_CLIENT_SECRET is not (the client_credentials grant needs both)".into())),
            (None, Some(_)) => return Err(TrackerError::Config(
                "LINEAR_CLIENT_SECRET is set but LINEAR_CLIENT_ID is not (the client_credentials grant needs both)".into())),
        };
        let token_url = match var("LINEAR_TOKEN_URL") {
            Some(u) => u,
            None => token_url_from(api_url)?,
        };
        let scope = var("LINEAR_OAUTH_SCOPE").unwrap_or_else(|| DEFAULT_SCOPE.into());
        Ok(Some(Self::new(&token_url, &id, &secret, &scope)))
    }

    fn cache_key(&self) -> String {
        format!("{}\n{}\n{}", self.token_url, self.client_id, self.scope)
    }

    /// `s` with the secret replaced (and, when given, the token).
    fn redact(&self, s: &str, token: Option<&str>) -> String {
        let mut out = s.replace(&self.client_secret, "<redacted>");
        if let Some(t) = token.filter(|t| !t.is_empty()) {
            out = out.replace(t, "<redacted>");
        }
        out
    }
}

/// The token endpoint on the origin of the GraphQL endpoint `api_url`.
pub fn token_url_from(api_url: &str) -> Result<String, TrackerError> {
    let u = Url::parse(api_url).map_err(|e| TrackerError::Config(format!("LINEAR_API_URL={api_url:?} is not a URL: {e}")))?;
    let origin = u.origin();
    if !origin.is_tuple() {
        return Err(TrackerError::Config(format!("LINEAR_API_URL={api_url:?} has no http(s) origin; set LINEAR_TOKEN_URL")));
    }
    Ok(format!("{}{TOKEN_PATH}", origin.ascii_serialization()))
}

/// application/x-www-form-urlencoded body of `pairs`.
fn form_body(pairs: &[(&str, &str)]) -> String {
    let mut u = Url::parse("http://form.invalid/").expect("static URL");
    u.query_pairs_mut().extend_pairs(pairs);
    u.query().unwrap_or("").to_string()
}

/// One issued token. `refresh_at` None: the answer had no expires_in, keep it.
#[derive(Clone)]
struct Issued {
    token: String,
    refresh_at: Option<i64>,
}

/// Tokens of this process, by ClientCredentials::cache_key.
static CACHE: Mutex<Vec<(String, Issued)>> = Mutex::new(Vec::new());

/// A token source for one tracker: the credentials, the HTTP client for the token
/// endpoint and a remembered refusal. The token itself lives in CACHE.
pub struct TokenSource {
    creds: ClientCredentials,
    http: Client,
    refused: Option<TrackerError>,
    /// Token requests this source sent (tests, and the at-most-one-per-run check).
    pub requests: usize,
}

impl TokenSource {
    /// Uses the shared client (HTTP(S)_PROXY / NO_PROXY apply, as for the GraphQL calls).
    pub fn new(creds: ClientCredentials) -> Self {
        Self::with_client(creds, common::client().clone())
    }

    pub fn with_client(creds: ClientCredentials, http: Client) -> Self {
        Self { creds, http, refused: None, requests: 0 }
    }

    #[cfg(test)]
    pub fn creds(&self) -> &ClientCredentials {
        &self.creds
    }

    /// The access token for the next GraphQL call.
    pub fn token(&mut self) -> Result<String, TrackerError> {
        self.token_at(chrono::Utc::now().timestamp())
    }

    /// token() at Unix time `now` (tests).
    pub fn token_at(&mut self, now: i64) -> Result<String, TrackerError> {
        if let Some(e) = &self.refused {
            return Err(e.clone());
        }
        let key = self.creds.cache_key();
        // Held across the request: concurrent callers wait for the one token.
        let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, i)) = cache.iter().find(|(k, _)| *k == key)
            && i.refresh_at.is_none_or(|r| now < r)
        {
            return Ok(i.token.clone());
        }
        self.requests += 1;
        match self.request(now) {
            Ok(i) => {
                cache.retain(|(k, _)| *k != key);
                cache.push((key, i.clone()));
                Ok(i.token)
            }
            Err((e, remember)) => {
                if remember {
                    self.refused = Some(e.clone());
                }
                Err(e)
            }
        }
    }

    /// POST the client_credentials grant. Err carries whether to remember the refusal.
    fn request(&self, now: i64) -> Result<Issued, (TrackerError, bool)> {
        let c = &self.creds;
        let body = form_body(&[
            ("grant_type", "client_credentials"),
            ("client_id", &c.client_id),
            ("client_secret", &c.client_secret),
            ("scope", &c.scope),
        ]);
        let r = self
            .http
            .post(&c.token_url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, common::user_agent())
            .body(body)
            .send()
            .map_err(|e| {
                let m = c.redact(&err_chain(&e), None);
                (TrackerError::Network(format!("OAuth token: {}", one_line(&m, 240))), false)
            })?;
        let status = r.status().as_u16();
        let bytes = r.bytes().map_err(|e| {
            (TrackerError::Network(format!("OAuth token: {}", one_line(&c.redact(&err_chain(&e), None), 240))), false)
        })?;
        let j: Option<Value> = serde_json::from_slice(&bytes).ok();

        if !(200..300).contains(&status) {
            // An error answer carries no token; show the OAuth error fields, or the start of the body.
            let detail = match j.as_ref().and_then(|j| j.get("error")).and_then(Value::as_str) {
                Some(err) => {
                    let desc = j.as_ref().and_then(|j| j.get("error_description")).and_then(Value::as_str).unwrap_or("");
                    if desc.is_empty() { err.to_string() } else { format!("{err}: {desc}") }
                }
                None => String::from_utf8_lossy(&bytes).into_owned(),
            };
            let detail = one_line(&c.redact(&detail, None), 200);
            if (400..500).contains(&status) && status != 429 {
                let e = TrackerError::Config(format!(
                    "Linear OAuth token refused (HTTP {status}: {detail}); check LINEAR_CLIENT_ID, LINEAR_CLIENT_SECRET, \
                     that the app allows client credentials, and LINEAR_OAUTH_SCOPE"
                ));
                return Err((e, true));
            }
            return Err((TrackerError::Http { status, body: format!("OAuth token: {detail}") }, false));
        }

        // From here on the body may hold a token: never echo it.
        let Some(j) = j else {
            return Err((TrackerError::Reply(format!("OAuth token: HTTP {status} answer is not JSON ({} bytes)", bytes.len())), false));
        };
        let token = j.get("access_token").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if token.is_empty() {
            return Err((TrackerError::Reply(format!("OAuth token: HTTP {status} answer has no access_token")), false));
        }
        let ty = j.get("token_type").and_then(Value::as_str).unwrap_or("Bearer");
        if !ty.eq_ignore_ascii_case("bearer") {
            let ty = c.redact(ty, Some(&token));
            return Err((TrackerError::Reply(format!("OAuth token: token_type {:?}, expected Bearer", one_line(&ty, 40))), false));
        }
        let expires_in = j.get("expires_in").and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())));
        let refresh_at = expires_in.map(|s| now + (s - REFRESH_MARGIN_SECS).max(s / 2));
        Ok(Issued { token, refresh_at })
    }
}

/// Error text with its source chain.
fn err_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let t = s.to_string();
        if !out.contains(&t) {
            out.push_str(": ");
            out.push_str(&t);
        }
        src = s.source();
    }
    out
}

/// Whitespace collapsed, cut to `n` characters with "…".
fn one_line(s: &str, n: usize) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= n { s } else { format!("{}…", s.chars().take(n - 1).collect::<String>()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wiki::testing::{Canned, canned, client, serve};

    const SECRET: &str = "s3cr3t-Value+/=";

    fn vars(v: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let v: Vec<(String, String)> = v.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect();
        move |k| v.iter().find(|(n, _)| n == k).map(|(_, x)| x.clone())
    }

    /// A TokenSource against a canned server (its URL is unique, so is the cache entry).
    fn source(replies: Vec<Canned>) -> (TokenSource, std::sync::mpsc::Receiver<String>) {
        let (base, rx) = serve(replies);
        let creds = ClientCredentials::new(&format!("{base}/oauth/token"), "client-1", SECRET, DEFAULT_SCOPE);
        (TokenSource::with_client(creds, client()), rx)
    }

    fn ok(token: &str, expires_in: i64) -> Canned {
        canned(200, &format!(r#"{{"access_token":"{token}","token_type":"Bearer","expires_in":{expires_in},"scope":"read,write"}}"#))
    }

    #[test]
    fn token_url_derived_from_the_api_url() {
        assert_eq!(token_url_from("https://api.linear.app/graphql").unwrap(), "https://api.linear.app/oauth/token");
        assert_eq!(token_url_from("http://linear-mock:8080/graphql").unwrap(), "http://linear-mock:8080/oauth/token");
        assert!(matches!(token_url_from("not a url"), Err(TrackerError::Config(m)) if m.contains("LINEAR_API_URL")));
        assert!(matches!(token_url_from("data:,x"), Err(TrackerError::Config(m)) if m.contains("LINEAR_TOKEN_URL")));
    }

    #[test]
    fn credentials_from_vars() {
        let api = "https://api.linear.app/graphql";
        assert!(ClientCredentials::from_vars(&vars(&[]), api).unwrap().is_none());
        assert!(ClientCredentials::from_vars(&vars(&[("LINEAR_CLIENT_ID", " "), ("LINEAR_CLIENT_SECRET", "")]), api).unwrap().is_none());
        let c = ClientCredentials::from_vars(&vars(&[("LINEAR_CLIENT_ID", " id "), ("LINEAR_CLIENT_SECRET", SECRET)]), api)
            .unwrap().unwrap();
        assert_eq!((c.token_url.as_str(), c.client_id.as_str(), c.scope.as_str()),
                   ("https://api.linear.app/oauth/token", "id", DEFAULT_SCOPE));
        let dbg = format!("{c:?}");
        assert!(dbg.contains("<redacted>") && !dbg.contains(SECRET), "{dbg}");
        let c = ClientCredentials::from_vars(&vars(&[("LINEAR_CLIENT_ID", "id"), ("LINEAR_CLIENT_SECRET", "x"),
                                                     ("LINEAR_TOKEN_URL", "http://t/tok"), ("LINEAR_OAUTH_SCOPE", "read")]), api)
            .unwrap().unwrap();
        assert_eq!((c.token_url.as_str(), c.scope.as_str()), ("http://t/tok", "read"));
        for (vs, want) in [(&[("LINEAR_CLIENT_ID", "id")][..], "LINEAR_CLIENT_ID is set but LINEAR_CLIENT_SECRET is not"),
                           (&[("LINEAR_CLIENT_SECRET", SECRET)][..], "LINEAR_CLIENT_SECRET is set but LINEAR_CLIENT_ID is not")] {
            let e = ClientCredentials::from_vars(&vars(vs), api).unwrap_err();
            assert!(matches!(&e, TrackerError::Config(m) if m.starts_with(want)), "{e:?}");
            assert!(!e.to_string().contains(SECRET));
        }
    }

    #[test]
    fn request_is_the_client_credentials_form() {
        let (mut s, rx) = source(vec![ok("lin_oauth_tok1", 2_592_000)]);
        assert_eq!(s.token_at(1_000).unwrap(), "lin_oauth_tok1");
        let req = rx.recv().unwrap();
        let low = req.to_lowercase();
        assert!(req.starts_with("POST /oauth/token "), "{req}");
        assert!(low.contains("\r\ncontent-type: application/x-www-form-urlencoded\r\n"), "{req}");
        assert!(!low.contains("authorization"), "{req}");
        let body = req.split("\r\n\r\n").nth(1).unwrap();
        assert_eq!(body, "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t-Value%2B%2F%3D\
                          &scope=read%2Cwrite%2Cissues%3Acreate%2Ccomments%3Acreate");
    }

    #[test]
    fn token_is_cached_and_renewed_inside_the_margin() {
        let (mut s, rx) = source(vec![ok("tok1", 3_600), ok("tok2", 3_600)]);
        assert_eq!(s.token_at(0).unwrap(), "tok1");
        assert_eq!(s.token_at(3_600 - REFRESH_MARGIN_SECS - 1).unwrap(), "tok1");
        assert_eq!(s.requests, 1);
        assert_eq!(s.token_at(3_600 - REFRESH_MARGIN_SECS).unwrap(), "tok2", "less than 5 min left");
        assert_eq!(s.requests, 2);
        assert_eq!(rx.try_iter().count(), 2);

        // A second source with the same credentials (another tracker in this process) reuses the token.
        let mut other = TokenSource::with_client(s.creds().clone(), client());
        assert_eq!(other.token_at(3_600).unwrap(), "tok2");
        assert_eq!(other.requests, 0, "at most one token per process");

        // Short-lived token: renewed at half its life, not on every call.
        let (mut s, _rx) = source(vec![ok("short1", 120), ok("short2", 120)]);
        assert_eq!(s.token_at(0).unwrap(), "short1");
        assert_eq!(s.token_at(59).unwrap(), "short1");
        assert_eq!(s.token_at(60).unwrap(), "short2");

        // No expires_in: kept for the process.
        let (mut s, _rx) = source(vec![canned(200, r#"{"access_token":"forever","token_type":"bearer"}"#)]);
        assert_eq!(s.token_at(0).unwrap(), "forever");
        assert_eq!(s.token_at(100 * 86_400).unwrap(), "forever");
        assert_eq!(s.requests, 1);
    }

    #[test]
    fn refusals_are_config_errors_remembered_without_secrets() {
        let body = format!(r#"{{"error":"invalid_client","error_description":"Client authentication failed for {SECRET}"}}"#);
        let (mut s, rx) = source(vec![canned(401, &body)]);
        let e = s.token_at(0).unwrap_err();
        assert!(matches!(&e, TrackerError::Config(m) if m.starts_with("Linear OAuth token refused (HTTP 401: invalid_client: \
                 Client authentication failed for <redacted>); check LINEAR_CLIENT_ID")), "{e:?}");
        assert!(!e.to_string().contains(SECRET));
        assert_eq!(s.token_at(1).unwrap_err(), e, "remembered");
        assert_eq!(s.requests, 1, "not asked again");
        assert_eq!(rx.try_iter().count(), 1);

        let (mut s, _rx) = source(vec![canned(400, "<html>bad request</html>")]);
        assert!(matches!(s.token_at(0).unwrap_err(), TrackerError::Config(m) if m.contains("HTTP 400: <html>bad request</html>")));
    }

    #[test]
    fn server_errors_and_odd_answers_are_retried_and_never_echo_a_token() {
        let (mut s, _rx) = source(vec![
            canned(503, "upstream down"),
            canned(429, r#"{"error":"rate_limited"}"#),
            canned(200, r#"{"access_token":"","token_type":"Bearer"}"#),
            canned(200, r#"{"access_token":"tok-in-garbage""#),
            canned(200, r#"{"access_token":"tokX","token_type":"mac"}"#),
            ok("tok3", 3_600),
        ]);
        assert_eq!(s.token_at(0).unwrap_err(), TrackerError::Http { status: 503, body: "OAuth token: upstream down".into() });
        assert_eq!(s.token_at(0).unwrap_err(), TrackerError::Http { status: 429, body: "OAuth token: rate_limited".into() });
        assert_eq!(s.token_at(0).unwrap_err(), TrackerError::Reply("OAuth token: HTTP 200 answer has no access_token".into()));
        let e = s.token_at(0).unwrap_err().to_string();
        assert!(e.contains("not JSON") && !e.contains("tok-in-garbage"), "{e}");
        assert_eq!(s.token_at(0).unwrap_err(), TrackerError::Reply("OAuth token: token_type \"mac\", expected Bearer".into()));
        assert_eq!(s.token_at(0).unwrap(), "tok3", "temporary failures are not remembered");

        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/oauth/token", l.local_addr().unwrap());
        drop(l);
        let mut s = TokenSource::with_client(ClientCredentials::new(&url, "c", SECRET, "read"), client());
        let e = s.token_at(0).unwrap_err();
        assert!(matches!(&e, TrackerError::Network(m) if m.starts_with("OAuth token: ")), "{e:?}");
        assert!(!e.to_string().contains(SECRET));
    }

    #[test]
    fn form_body_encoding() {
        assert_eq!(form_body(&[("a", "x y"), ("b", "&=+")]), "a=x+y&b=%26%3D%2B");
    }
}
