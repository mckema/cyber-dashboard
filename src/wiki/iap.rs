//! The Google Cloud IAP credential on every wiki request of the job (GraphQL,
//! asset upload, asset read-back): an OIDC ID token sent as
//! `Proxy-Authorization: Bearer <token>` (bot_auth in mod.rs).
//!
//! Where the token comes from (Source::from_vars, first match wins):
//!
//!   IAP_ID_TOKEN   set: that value as is (override; it expires after ~1 h and is
//!                  never refreshed, so it suits a manual run, not a schedule)
//!   IAP_AUDIENCE   set: minted at runtime from the metadata server of the
//!                  runtime (Cloud Run, GCE) for the service account the job runs as:
//!                  GET http://<GCE_METADATA_HOST>/computeMetadata/v1/instance/
//!                      service-accounts/default/identity?audience=<aud>&format=full
//!                  with `Metadata-Flavor: Google`. The audience is the OAuth client
//!                  ID of the IAP resource. GCE_METADATA_HOST (host[:port], default
//!                  metadata.google.internal) is the variable Google's client
//!                  libraries use too.
//!   neither        no IAP header (the wiki is not behind IAP, e.g. the compose lab)
//!
//! A minted token is kept in-process until its `exp` claim minus
//! REFRESH_MARGIN_SECS, then fetched again; the JWT is only base64url-decoded to
//! read `exp`, never verified (the job is its consumer's client, not its judge).
//! The metadata request never goes through HTTP(S)_PROXY. The token never
//! appears in errors or logs.
//!
//! Variants to come: when IAP uses a Google-managed OAuth client, a programmatic
//! caller may need a JWT signed by the service account (IAM Credentials
//! `signJwt`) with the resource URL as audience. That is one more Source variant
//! plus its fetch arm in TokenCache::mint; callers do not change.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use reqwest::Url;
use reqwest::blocking::Client;

use super::{err_chain, head};
use crate::feeds::common::{self, Fatal};

pub const DEFAULT_METADATA_HOST: &str = "metadata.google.internal";
/// A cached token is replaced this long before its `exp`.
pub const REFRESH_MARGIN_SECS: i64 = 300;
/// Per-request timeout of the metadata client (the server is link-local and fast).
const METADATA_TIMEOUT_SECS: u64 = 10;

/// Where the IAP token comes from. Debug never shows a token.
#[derive(Clone, PartialEq, Eq)]
pub enum Source {
    /// No IAP header.
    None,
    /// IAP_ID_TOKEN as is.
    Static(String),
    /// Minted by the metadata server at `host` (host[:port]) for `audience`.
    Metadata { host: String, audience: String },
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::None => f.write_str("None"),
            Source::Static(_) => f.write_str("Static(<redacted>)"),
            Source::Metadata { host, audience } => {
                f.debug_struct("Metadata").field("host", host).field("audience", audience).finish()
            }
        }
    }
}

impl Source {
    /// IAP_ID_TOKEN, else IAP_AUDIENCE (+ GCE_METADATA_HOST), else None. Blank values count as unset.
    pub fn from_vars(get: &dyn Fn(&str) -> Option<String>) -> Self {
        let var = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        if let Some(t) = var("IAP_ID_TOKEN") {
            return Source::Static(t);
        }
        if let Some(audience) = var("IAP_AUDIENCE") {
            let host = var("GCE_METADATA_HOST").unwrap_or_else(|| DEFAULT_METADATA_HOST.into());
            let host = host.trim_start_matches("http://").trim_end_matches('/').to_string();
            return Source::Metadata { host, audience };
        }
        Source::None
    }
}

/// A Source plus the last minted token and its `exp` (Unix seconds).
pub struct TokenCache {
    source: Source,
    client: Client,
    cached: Mutex<Option<(String, i64)>>,
}

impl TokenCache {
    /// `client` is used for the metadata server only (see metadata_client()).
    pub fn new(source: Source, client: Client) -> Self {
        Self { source, client, cached: Mutex::new(None) }
    }

    /// The token for the next wiki request(s), "" when there is none.
    pub fn token(&self) -> Result<String, Fatal> {
        self.token_at(chrono::Utc::now().timestamp())
    }

    /// token() at Unix time `now` (tests).
    pub fn token_at(&self, now: i64) -> Result<String, Fatal> {
        match &self.source {
            Source::None => Ok(String::new()),
            Source::Static(t) => Ok(t.clone()),
            Source::Metadata { .. } => {
                let mut cached = self.cached.lock().unwrap_or_else(|e| e.into_inner());
                if let Some((t, exp)) = cached.as_ref()
                    && now < exp - REFRESH_MARGIN_SECS
                {
                    return Ok(t.clone());
                }
                let (t, exp) = self.mint()?;
                *cached = Some((t.clone(), exp));
                Ok(t)
            }
        }
    }

    /// A fresh token and its exp from the Source (minting variants only).
    fn mint(&self) -> Result<(String, i64), Fatal> {
        match &self.source {
            Source::Metadata { host, audience } => fetch_identity(&self.client, host, audience),
            Source::None | Source::Static(_) => unreachable!("only minted sources are fetched"),
        }
    }
}

/// HTTP client for the metadata server: never through HTTP(S)_PROXY.
pub fn metadata_client() -> Client {
    Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(METADATA_TIMEOUT_SECS))
        .build()
        .expect("HTTP client")
}

/// The identity URL for `audience` on the metadata server at `host`.
pub fn identity_url(host: &str, audience: &str) -> Result<Url, Fatal> {
    let mut u = Url::parse(&format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/identity"))
        .map_err(|e| Fatal(format!("GCE_METADATA_HOST={host:?} does not make a URL: {e}")))?;
    u.query_pairs_mut().append_pair("audience", audience).append_pair("format", "full");
    Ok(u)
}

/// Ask the metadata server for an ID token for `audience`; returns (token, exp).
pub fn fetch_identity(client: &Client, host: &str, audience: &str) -> Result<(String, i64), Fatal> {
    let url = identity_url(host, audience)?;
    let what = format!("IAP ID token from the metadata server at {host}");
    let r = client
        .get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .map_err(|e| Fatal(format!("{what}: cannot reach it (IAP_AUDIENCE set outside Google Cloud?): {}", err_chain(&e))))?;
    let status = r.status().as_u16();
    let body = common::read_capped(r, common::MAX_TOKEN_BODY).map_err(|e| Fatal(format!("{what}: {}", err_chain(&e))))?;
    let text = String::from_utf8_lossy(&body).into_owned();
    if !(200..300).contains(&status) {
        // An error answer carries no token.
        return Err(Fatal(format!("{what}: HTTP {status}: {}", head(text.trim(), 200))));
    }
    let token = text.trim().to_string();
    let exp = jwt_exp(&token)
        .ok_or_else(|| Fatal(format!("{what}: the answer is not a JWT with an exp claim ({} bytes)", token.len())))?;
    Ok((token, exp))
}

/// `exp` (Unix seconds) from a JWT's payload, without verifying the signature.
pub fn jwt_exp(jwt: &str) -> Option<i64> {
    let mut parts = jwt.split('.');
    let (_header, payload, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let claims: serde_json::Value = serde_json::from_slice(&b64url_decode(payload)?).ok()?;
    let exp = claims.get("exp")?;
    exp.as_i64().or_else(|| exp.as_f64().map(|f| f as i64))
}

/// Base64url (RFC 4648 §5) without or with `=` padding.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // One leftover symbol (6 bits) cannot end a valid encoding.
    if bits >= 6 {
        return None;
    }
    Some(out)
}

/// The process-wide token cache, set up from the environment on first use.
fn global() -> &'static TokenCache {
    static C: OnceLock<TokenCache> = OnceLock::new();
    C.get_or_init(|| TokenCache::new(Source::from_vars(&|k| std::env::var(k).ok()), metadata_client()))
}

/// The IAP token for the job's next wiki request(s), "" when no IAP is configured.
pub fn token() -> Result<String, Fatal> {
    global().token()
}

#[cfg(test)]
mod tests {
    use super::super::testing::{canned, client, serve};
    use super::*;

    /// header.payload.signature with `claims` as the payload.
    fn jwt(claims: &str) -> String {
        format!("eyJhbGciOiJSUzI1NiJ9.{}.c2ln", b64url(claims.as_bytes()))
    }

    fn b64url(b: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for ch in b.chunks(3) {
            let n = ch.iter().enumerate().fold(0u32, |n, (i, &x)| n | u32::from(x) << (16 - 8 * i));
            for i in 0..=ch.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        out
    }

    fn vars(v: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let v: Vec<(String, String)> = v.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect();
        move |k| v.iter().find(|(n, _)| n == k).map(|(_, x)| x.clone())
    }

    #[test]
    fn source_precedence() {
        let src = |v: &[(&str, &str)]| Source::from_vars(&vars(v));
        assert_eq!(src(&[]), Source::None);
        assert_eq!(src(&[("IAP_ID_TOKEN", " "), ("IAP_AUDIENCE", "")]), Source::None, "blank is unset");
        assert_eq!(src(&[("IAP_ID_TOKEN", "tok"), ("IAP_AUDIENCE", "aud")]), Source::Static("tok".into()), "override wins");
        assert_eq!(src(&[("IAP_AUDIENCE", " 123-x.apps.googleusercontent.com ")]),
                   Source::Metadata { host: DEFAULT_METADATA_HOST.into(), audience: "123-x.apps.googleusercontent.com".into() });
        assert_eq!(src(&[("IAP_AUDIENCE", "a"), ("GCE_METADATA_HOST", "http://127.0.0.1:8099/")]),
                   Source::Metadata { host: "127.0.0.1:8099".into(), audience: "a".into() });
        assert_eq!(format!("{:?}", Source::Static("secret".into())), "Static(<redacted>)");
    }

    #[test]
    fn b64url_and_jwt_exp() {
        assert_eq!(b64url_decode("").unwrap(), b"");
        assert_eq!(b64url_decode("Zg").unwrap(), b"f");
        assert_eq!(b64url_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(b64url_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(b64url_decode("-_8").unwrap(), [0xfb, 0xff]);
        assert!(b64url_decode("Z").is_none(), "a lone symbol is not an encoding");
        assert!(b64url_decode("Zm+v").is_none(), "standard alphabet is refused");
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar", "\u{ff}\u{fe}"] {
            assert_eq!(b64url_decode(&b64url(s.as_bytes())).unwrap(), s.as_bytes(), "{s}");
        }

        assert_eq!(jwt_exp(&jwt(r#"{"aud":"a","exp":1793696400,"iat":1793692800}"#)), Some(1793696400));
        assert_eq!(jwt_exp(&jwt(r#"{"exp":1793696400.0}"#)), Some(1793696400));
        assert_eq!(jwt_exp(&jwt(r#"{"iat":1}"#)), None);
        assert_eq!(jwt_exp(&jwt("not json")), None);
        assert_eq!(jwt_exp("a.b"), None);
        assert_eq!(jwt_exp("a.b.c.d"), None);
        assert_eq!(jwt_exp("a.!!.c"), None);
    }

    #[test]
    fn identity_url_encodes_the_audience() {
        let u = identity_url("metadata.google.internal", "https://wiki.example/ x&y").unwrap();
        assert_eq!(u.as_str(), "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/\
                                identity?audience=https%3A%2F%2Fwiki.example%2F+x%26y&format=full");
        assert!(identity_url("bad host/", "a").is_err());
    }

    #[test]
    fn static_and_none_never_call_out() {
        let c = TokenCache::new(Source::Static("T".into()), client());
        assert_eq!(c.token_at(0).unwrap(), "T");
        assert_eq!(TokenCache::new(Source::None, client()).token_at(0).unwrap(), "");
    }

    #[test]
    fn metadata_token_is_fetched_with_headers_and_cached_until_exp_minus_margin() {
        let t1 = jwt(r#"{"exp":10000}"#);
        let t2 = jwt(r#"{"exp":20000}"#);
        let (base, rx) = serve(vec![canned(200, &t1), canned(200, &format!("{t2}\n"))]);
        let host = base.trim_start_matches("http://").to_string();
        let c = TokenCache::new(Source::Metadata { host, audience: "123-x.apps.googleusercontent.com".into() }, client());

        assert_eq!(c.token_at(1000).unwrap(), t1);
        assert_eq!(c.token_at(10000 - REFRESH_MARGIN_SECS - 1).unwrap(), t1, "cached");
        assert_eq!(rx.try_iter().count(), 1, "one fetch so far");
        assert_eq!(c.token_at(10000 - REFRESH_MARGIN_SECS).unwrap(), t2, "refreshed inside the margin");
        assert_eq!(c.token_at(15000).unwrap(), t2);

        let (base, rx) = serve(vec![canned(200, &t1)]);
        let c = TokenCache::new(Source::Metadata { host: base.trim_start_matches("http://").into(), audience: "aud-1".into() },
                                client());
        c.token_at(0).unwrap();
        let req = rx.recv().unwrap();
        let low = req.to_lowercase();
        assert!(req.starts_with("GET /computeMetadata/v1/instance/service-accounts/default/identity?audience=aud-1&format=full "),
                "{req}");
        assert!(low.contains("\r\nmetadata-flavor: google\r\n"), "{req}");
        assert!(!low.contains("authorization"), "{req}");
    }

    #[test]
    fn metadata_errors_name_the_cause_without_a_token() {
        let (base, _rx) = serve(vec![canned(404, "Not Found\n"), canned(200, "opaque-token-not-a-jwt")]);
        let host = base.trim_start_matches("http://").to_string();
        let c = TokenCache::new(Source::Metadata { host: host.clone(), audience: "a".into() }, client());
        assert_eq!(c.token_at(0).unwrap_err().0, format!("IAP ID token from the metadata server at {host}: HTTP 404: Not Found"));
        let e = c.token_at(0).unwrap_err().0;
        assert_eq!(e, format!("IAP ID token from the metadata server at {host}: the answer is not a JWT with an exp claim (22 bytes)"));
        assert!(!e.contains("opaque"));

        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let host = l.local_addr().unwrap().to_string();
        drop(l);
        let e = fetch_identity(&client(), &host, "a").unwrap_err().0;
        assert!(e.starts_with(&format!("IAP ID token from the metadata server at {host}: cannot reach it")), "{e}");
    }
}
