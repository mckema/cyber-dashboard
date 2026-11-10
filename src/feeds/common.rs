//! Shared contract for every feed module.
//!
//! A feed module exposes:
//!
//!   NAME      display name, e.g. "CISA KEV"               (shown in the health table)
//!   CADENCE   minimum seconds between real fetches (0 = every run). Between fetches
//!             run.rs reuses the items cached from the last success.
//!   fetch(start, end) -> Result<FetchOutput, SourceError>
//!             start/end bound the 7-day window (UTC). Return Err on any failure;
//!             never a partial list.
//!
//! Item.extra keys per page table (run.rs decides which feed fills which table;
//! render reads these keys, anything else is ignored; triage/matcher.rs also reads
//! the ones marked *). Values are strings unless marked otherwise:
//!
//!   kev    vendor*, product*, due (YYYY-MM-DD, CISA only), euvd_id, exploited_since,
//!          sources (list of feed NAMEs, filled when run.rs merges KEV + EUVD)
//!          (EUVD: vendor/product are the first 3 names joined with ", ")
//!   adv    version, products (list), probability, impact (NCSC-NL "Kans"/"Schade": H/M/L)
//!   dep    ghsa, ecosystems (list), packages (list), fixed (list), npkg (number),
//!          eco_packages* (list of "ecosystem:package", not rendered)
//!   cve    score_source ("CNA" | "CISA-ADP" | "NVD"), vector, av, pr, vendors* (list, first 3),
//!          ssvc_exploitation ("none" | "poc" | "active" | ""), assigner,
//!          nvd_score (number, or "" when NVD has none),
//!          products*, cpes* (lists, untruncated, not rendered)
//!   nvd    vector, vendors (list)      -- enrichment only, merged into "cve" items
//!   any    summary (short description, optional)
//!
//! Health rows: see render::HealthRow.
//!
//! On-disk formats (state/) are kept stable so existing state never needs a
//! backfill. Keep field names as they are.

use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE, USER_AGENT};
use reqwest::redirect;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha1::{Digest, Sha1};

use super::state;

pub const TIMEOUT_SECS: u64 = 90;
/// USER_AGENT overrides it (e.g. to add a contact URL some feeds ask for).
const DEFAULT_UA: &str = concat!("exploit-watch/", env!("CARGO_PKG_VERSION"));

const MIB: u64 = 1024 * 1024;
/// Default cap on a feed response body, after gzip decoding (GetOpts::max_bytes).
/// The feeds without their own cap answer far less: an EUVD or GitHub page of 100
/// rows is ~0.5 MB, a CERT-EU or NCSC-NL advisory ~0.1 MB, changes.csv ~70 KB.
/// Without a cap a 1 MB gzip answer can decode to 1 GiB, the whole Cloud Run job.
pub const MAX_BODY: u64 = 16 * MIB;
/// Cap on the JSON answers of our own services (Wiki.js GraphQL, Linear GraphQL,
/// the GCS JSON API): the largest is the dashboard page read back (~1 MB).
pub const MAX_API_BODY: u64 = 16 * MIB;
/// Cap on a token answer (metadata server, Linear OAuth): a few KB at most.
pub const MAX_TOKEN_BODY: u64 = 64 * 1024;
/// Redirect hops the feed client follows (reqwest's default).
const MAX_REDIRECTS: usize = 10;

/// Abort without writing. A half-populated threat brief is worse than a stale one.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Fatal(pub String);

/// One feed failed. run.rs decides whether that is fatal for the run.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct SourceError {
    pub message: String,
    /// HTTP status when the failure was an HTTP answer (lets callers spot a 404).
    pub status: Option<u16>,
}

impl SourceError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), status: None }
    }
}

impl From<SourceError> for Fatal {
    fn from(e: SourceError) -> Self {
        Fatal(e.message)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub source: String,     // feed NAME that produced the item
    pub id: String,         // source-native id: CVE-…, GHSA-…, NCSC-2026-0464, 2026-018
    pub url: String,        // link to the publisher's own page for this item
    pub title: String,
    pub published: String,  // ISO 8601 UTC "2026-11-03T02:31:19Z", or "2026-11-03" if date only
    #[serde(default)]
    pub updated: String,    // same format; empty when the source has no revision time
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub score: f64,         // CVSS base score, 0 when unscored
    #[serde(default)]
    pub severity: String,   // CRITICAL | HIGH | MEDIUM | LOW | ""
    #[serde(default)]
    pub extra: Map<String, Value>,
}

impl Item {
    pub fn new(source: &str, id: &str, url: &str, title: &str, published: &str) -> Self {
        Self {
            source: source.into(), id: id.into(), url: url.into(), title: title.into(),
            published: published.into(), updated: String::new(), cves: vec![], score: 0.0,
            severity: String::new(), extra: Map::new(),
        }
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.source, self.id)
    }

    /// extra[k] as a string ("" when missing or not a string).
    pub fn x(&self, k: &str) -> &str {
        self.extra.get(k).and_then(Value::as_str).unwrap_or("")
    }

    /// extra[k] as a list of strings (empty when missing or not a list; non-string elements are skipped).
    pub fn x_list(&self, k: &str) -> Vec<&str> {
        self.extra.get(k).and_then(Value::as_array).map_or_else(Vec::new, |a| a.iter().filter_map(Value::as_str).collect())
    }

    /// extra[k] as a number (None when missing or not a number).
    pub fn x_num(&self, k: &str) -> Option<f64> {
        self.extra.get(k).and_then(Value::as_f64)
    }
}

/// What a module's fetch() returns: the items plus free-form stats for the health note.
#[derive(Debug, Default, Clone)]
pub struct FetchOutput {
    pub items: Vec<Item>,
    pub stats: Map<String, Value>,
}

impl From<Vec<Item>> for FetchOutput {
    fn from(items: Vec<Item>) -> Self {
        Self { items, stats: Map::new() }
    }
}

// ---------------------------------------------------------------- time

/// datetime -> "2026-11-03T02:31:19Z" (seconds precision, UTC).
pub fn iso_utc(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Parse ISO 8601 with or without "Z"/offset/fraction, or a bare date. Naive values are UTC.
pub fn parse_iso(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%:z") {
        return Some(dt.with_timezone(&Utc));
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, f) {
            return Some(n.and_utc());
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok().map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc())
}

pub fn severity_for(score: f64) -> &'static str {
    if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MEDIUM"
    } else if score > 0.0 {
        "LOW"
    } else {
        ""
    }
}

// ---------------------------------------------------------------- http

pub fn user_agent() -> String {
    // A non-empty value only: compose passes USER_AGENT= from .env as an empty
    // string, and CERT-EU answers 403 to a request without a User-Agent.
    std::env::var("USER_AGENT").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| DEFAULT_UA.into())
}

/// Shared blocking client for our own services (Wiki.js, Linear, GCS). Proxy
/// settings come from HTTP(S)_PROXY / NO_PROXY. Plain http stays allowed: the lab
/// wiki is http://dev-wiki:3000. The public feeds go through feed_client() instead.
pub fn client() -> &'static Client {
    static C: OnceLock<Client> = OnceLock::new();
    C.get_or_init(|| {
        Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .build()
            .expect("HTTP client")
    })
}

/// Client for the public feeds (get()): https only, and a redirect may not change
/// the host (redirect_allowed), so a header a feed adds itself (NVD's apiKey)
/// never reaches another host. reqwest drops Authorization on a cross-host
/// redirect, but not custom headers.
fn feed_client() -> &'static Client {
    static C: OnceLock<Client> = OnceLock::new();
    C.get_or_init(|| {
        let policy = redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > MAX_REDIRECTS {
                return attempt.error(format!("more than {MAX_REDIRECTS} redirects"));
            }
            let ok = attempt.previous().last().is_some_and(|from| redirect_allowed(from, attempt.url()));
            if ok {
                attempt.follow()
            } else {
                let msg = format!("redirect to {} refused (only same-host https redirects are followed)", attempt.url());
                attempt.error(msg)
            }
        });
        Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .https_only(true)
            .redirect(policy)
            .build()
            .expect("HTTP client")
    })
}

/// A feed redirect is followed only to https on the same host and port. One
/// exception: github.com serves release assets (the cvelist backfill zips) by a
/// redirect to its object storage under *.githubusercontent.com; those requests
/// carry no header of ours.
pub fn redirect_allowed(from: &Url, to: &Url) -> bool {
    if to.scheme() != "https" {
        return false;
    }
    let same = from.host_str() == to.host_str() && from.port_or_known_default() == to.port_or_known_default();
    let release_asset = from.host_str() == Some("github.com")
        && to.port_or_known_default() == Some(443)
        && to.host_str().is_some_and(|h| h.ends_with(".githubusercontent.com"));
    same || release_asset
}

/// True for an absolute http(s) URL (case-insensitive scheme). Anything else
/// (javascript:, data:, file:, relative) must not become a link.
pub fn is_http_url(u: &str) -> bool {
    let has = |p: &str| u.get(..p.len()).is_some_and(|h| h.eq_ignore_ascii_case(p));
    has("http://") || has("https://")
}

/// A response body that could not be read in full within its cap.
#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    #[error("{what} is larger than the {limit}-byte limit; not read")]
    TooLarge { what: String, limit: u64 },
    #[error("cannot read {what}: {source}")]
    Read { what: String, source: std::io::Error },
}

impl BodyError {
    pub fn too_large(&self) -> bool {
        matches!(self, Self::TooLarge { .. })
    }
}

/// Read at most `limit` bytes from `r` (`what` names it in the error). One byte
/// more than the limit is read to tell "exactly the limit" from "too large".
pub fn read_limited(r: impl Read, limit: u64, what: &str) -> Result<Vec<u8>, BodyError> {
    let mut out = Vec::new();
    r.take(limit.saturating_add(1)).read_to_end(&mut out)
        .map_err(|source| BodyError::Read { what: what.to_string(), source })?;
    if out.len() as u64 > limit {
        return Err(BodyError::TooLarge { what: what.to_string(), limit });
    }
    Ok(out)
}

/// The body of a response, at most `limit` bytes after gzip decoding (reqwest
/// decodes as it reads, so the cap holds against a gzip bomb too). Use this for
/// every remote body instead of bytes() / text(), which read without limit.
pub fn read_capped(r: reqwest::blocking::Response, limit: u64) -> Result<Vec<u8>, BodyError> {
    let what = format!("the response from {}", r.url());
    read_limited(r, limit, &what)
}

pub struct Response {
    pub status: u16, // 200, 206, or 304 (body then comes from the cache)
    pub content: Vec<u8>,
    pub headers: HeaderMap,
    pub url: String,
    pub from_cache: bool,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.content).into_owned()
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> serde_json::Result<T> {
        serde_json::from_slice(&self.content)
    }

    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
    }
}

pub struct GetOpts<'a> {
    pub headers: &'a [(&'a str, &'a str)],
    pub conditional: bool,
    pub byte_range: Option<(u64, u64)>,
    pub params: &'a [(&'a str, &'a str)],
    /// Most bytes the body may have after decoding (MAX_BODY unless the feed sets
    /// its own); a 206 answer is also held to the requested range length.
    pub max_bytes: u64,
}

impl Default for GetOpts<'_> {
    fn default() -> Self {
        Self { headers: &[], conditional: true, byte_range: None, params: &[], max_bytes: MAX_BODY }
    }
}

/// Body cap for an answer with `status` to a request with `opts`.
fn body_limit(opts: &GetOpts, status: u16) -> u64 {
    match opts.byte_range {
        Some((a, b)) if status == 206 => opts.max_bytes.min(b.saturating_sub(a) + 1),
        _ => opts.max_bytes,
    }
}

fn cache_name(url: &str) -> String {
    format!("http/{}", hex::encode(Sha1::digest(url.as_bytes())))
}

/// Full URL with params encoded the way the cache key expects.
pub fn full_url(url: &str, params: &[(&str, &str)]) -> Result<String, SourceError> {
    if params.is_empty() {
        return Ok(url.to_string());
    }
    reqwest::Url::parse_with_params(url, params)
        .map(|u| u.to_string())
        .map_err(|e| SourceError::new(format!("bad URL {url}: {e}")))
}

/// GET with a polite User-Agent, conditional request and on-disk body cache.
///
/// conditional=true sends If-None-Match / If-Modified-Since from the last 200
/// and, on 304, returns the cached body with from_cache=true, so callers can
/// always parse .content. byte_range=(first, last) sends a Range header and
/// skips the cache. Any network error or non-2xx/304 status is a SourceError, and
/// so is a body over opts.max_bytes or a redirect to another host (feed_client).
pub fn get(url: &str, label: &str, opts: GetOpts) -> Result<Response, SourceError> {
    let full = full_url(url, opts.params)?;
    let use_cache = opts.conditional && opts.byte_range.is_none();
    let meta: Option<Value> = if use_cache { state::load_json(&format!("{}.json", cache_name(&full))) } else { None };

    let mut req = feed_client().get(&full).header(USER_AGENT, user_agent());
    for (k, v) in opts.headers {
        req = req.header(*k, *v);
    }
    if let Some(m) = &meta {
        if let Some(e) = m.get("etag").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            req = req.header(IF_NONE_MATCH, e);
        }
        if let Some(l) = m.get("last_modified").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            req = req.header(IF_MODIFIED_SINCE, l);
        }
    }
    if let Some((a, b)) = opts.byte_range {
        req = req.header(RANGE, format!("bytes={a}-{b}"));
    }

    let r = req.send().map_err(|e| {
        // A refused redirect is only named in the source chain.
        let why = std::error::Error::source(&e).map(|s| format!(": {s}")).unwrap_or_default();
        SourceError::new(format!("{label}: network error: {e}{why}"))
    })?;
    let status = r.status().as_u16();
    let headers = r.headers().clone();
    let err = |m: String| SourceError { message: m, status: Some(status) };

    if status == 304 && meta.is_some() {
        return match state::load_bytes(&format!("{}.body", cache_name(&full))) {
            Some(body) => Ok(Response { status, content: body, headers, url: full, from_cache: true }),
            None => Err(err(format!("{label}: 304 but the cached body is missing; delete state/http and rerun"))),
        };
    }
    if status == 403 || status == 429 {
        return Err(err(format!("{label}: HTTP {status} (blocked or rate limited)")));
    }
    if status >= 400 {
        return Err(err(format!("{label}: HTTP {status}")));
    }
    let limit = body_limit(&opts, status);
    let content = read_capped(r, limit).map_err(|e| match e {
        BodyError::Read { source, .. } => SourceError::new(format!("{label}: network error: {source}")),
        too_large => SourceError::new(format!("{label}: {too_large}")),
    })?;

    let etag = headers.get(ETAG).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let lm = headers.get(LAST_MODIFIED).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if use_cache && status == 200 && (!etag.is_empty() || !lm.is_empty()) {
        let name = cache_name(&full);
        state::save_bytes(&format!("{name}.body"), &content);
        state::save_json(&format!("{name}.json"), &json!({"url": full, "etag": etag, "last_modified": lm}));
    }
    Ok(Response { status, content, headers, url: full, from_cache: false })
}

#[cfg(test)]
pub mod testutil {
    use std::io::{Cursor, Write};

    /// gzip of `n` zero bytes (a decompression bomb: ~1000:1). Built from the
    /// deflate stream of a zip entry, so no gzip crate is needed: local file
    /// header = crc32 at 14, compressed size at 18, name and extra lengths at
    /// 26 and 28, data after the 30-byte header, name and extra.
    pub fn gzip_zeros(n: usize) -> Vec<u8> {
        let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        z.start_file("z", opts).unwrap();
        z.write_all(&vec![0u8; n]).unwrap();
        let raw = z.finish().unwrap().into_inner();
        let u32_at = |i: usize| u32::from_le_bytes(raw[i..i + 4].try_into().unwrap());
        let u16_at = |i: usize| u16::from_le_bytes(raw[i..i + 2].try_into().unwrap()) as usize;
        let (crc, size) = (u32_at(14), u32_at(18) as usize);
        let data = 30 + u16_at(26) + u16_at(28);
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
        gz.extend_from_slice(&raw[data..data + size]);
        gz.extend_from_slice(&crc.to_le_bytes());
        gz.extend_from_slice(&(n as u32).to_le_bytes());
        gz
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iso_variants() {
        let want = "2026-11-03T02:31:19Z";
        for s in ["2026-11-03T02:31:19Z", "2026-11-03T02:31:19.933Z", "2026-11-03T02:31:19.006979+00:00",
                  "2026-11-03T02:31:19", "2026-11-03T03:31:19+01:00"] {
            assert_eq!(iso_utc(parse_iso(s).unwrap()), want, "{s}");
        }
        assert_eq!(iso_utc(parse_iso("2026-11-03").unwrap()), "2026-11-03T00:00:00Z");
        assert!(parse_iso("not a date").is_none());
    }

    #[test]
    fn severity_bands() {
        assert_eq!(severity_for(9.0), "CRITICAL");
        assert_eq!(severity_for(8.9), "HIGH");
        assert_eq!(severity_for(4.0), "MEDIUM");
        assert_eq!(severity_for(0.1), "LOW");
        assert_eq!(severity_for(0.0), "");
    }

    #[test]
    fn item_json_roundtrip() {
        // Shape of state/items/*.json (integer score, spaces after separators).
        let stored = r#"{"source": "CISA KEV", "id": "CVE-1", "url": "u", "title": "t",
                     "published": "2026-11-03", "updated": "", "cves": ["CVE-1"], "score": 0,
                     "severity": "", "extra": {"vendor": "Ivanti", "sources": ["CISA KEV"], "npkg": 5}}"#;
        let it: Item = serde_json::from_str(stored).unwrap();
        assert_eq!(it.key(), "CISA KEV:CVE-1");
        assert_eq!(it.x("vendor"), "Ivanti");
        assert_eq!(it.x("npkg"), "");
        assert_eq!(it.x_list("sources"), ["CISA KEV"]);
        assert!(it.x_list("vendor").is_empty());
        assert_eq!((it.x_num("npkg"), it.x_num("vendor")), (Some(5.0), None));
        let back: Item = serde_json::from_str(&serde_json::to_string(&it).unwrap()).unwrap();
        assert_eq!(back, it);
    }

    #[test]
    fn cache_key_is_stable() {
        // sha1 of the full URL, with params encoded as below; the http/ cache
        // already on disk is keyed this way.
        assert_eq!(cache_name("https://example.org/a"), "http/579f2a2ceeee0bc369f88d8b2b891d6263265b30");
        assert_eq!(
            full_url("https://api.github.com/advisories", &[("published", "2026-10-27..2026-11-03"),
                ("type", "reviewed"), ("modified", ">2026-11-03T02:31:19Z"), ("q", "a b/c")]).unwrap(),
            "https://api.github.com/advisories?published=2026-10-27..2026-11-03&type=reviewed&modified=%3E2026-11-03T02%3A31%3A19Z&q=a+b%2Fc"
        );
    }

    #[test]
    fn body_cap() {
        assert_eq!(read_limited(&b"12345"[..], 5, "x").unwrap(), b"12345");
        let e = read_limited(&b"123456"[..], 5, "the response from https://a.example/f").unwrap_err();
        assert!(e.too_large(), "{e}");
        assert_eq!(e.to_string(), "the response from https://a.example/f is larger than the 5-byte limit; not read");
        // a 206 is held to the range it asked for, a 200 (Range ignored) to max_bytes
        let o = GetOpts { byte_range: Some((10, 19)), max_bytes: 1000, ..Default::default() };
        assert_eq!((body_limit(&o, 206), body_limit(&o, 200)), (10, 1000));
        assert_eq!(body_limit(&GetOpts::default(), 200), MAX_BODY);
    }

    #[test]
    fn gzip_bomb_is_cut_off() {
        use crate::wiki::testing::{Canned, client, serve};
        let n = 8 * MIB as usize;
        let gz = testutil::gzip_zeros(n);
        assert!(gz.len() < 64 * 1024, "{} bytes on the wire", gz.len());
        let reply = || Canned { status: 200, headers: vec![("Content-Encoding".into(), "gzip".into())], body: gz.clone() };
        let (base, _rx) = serve(vec![reply(), reply()]);
        let c = client();
        let e = read_capped(c.get(format!("{base}/bomb")).send().unwrap(), MIB).unwrap_err();
        let msg = e.to_string();
        assert!(e.too_large() && msg.contains(&format!("{base}/bomb")) && msg.contains("1048576-byte limit"), "{msg}");
        // the same body within its cap decodes in full
        assert_eq!(read_capped(c.get(format!("{base}/ok")).send().unwrap(), n as u64).unwrap().len(), n);
    }

    #[test]
    fn feed_redirects_stay_on_host() {
        let u = |s: &str| Url::parse(s).unwrap();
        let nvd = u("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0");
        assert!(redirect_allowed(&nvd, &u("https://services.nvd.nist.gov/rest/json/cves/2.0/")));
        assert!(!redirect_allowed(&nvd, &u("https://evil.example/steal")));
        assert!(!redirect_allowed(&nvd, &u("http://services.nvd.nist.gov/rest/json/cves/2.0")));
        assert!(!redirect_allowed(&nvd, &u("https://services.nvd.nist.gov:8443/")));
        let rel = u("https://github.com/CVEProject/cvelistV5/releases/download/t/a.zip");
        assert!(redirect_allowed(&rel, &u("https://release-assets.githubusercontent.com/github-production-release-asset/1")));
        assert!(!redirect_allowed(&rel, &u("https://githubusercontent.com.evil.example/")));
        assert!(!redirect_allowed(&u("https://api.github.com/advisories"), &u("https://objects.githubusercontent.com/x")));
    }

    #[test]
    fn feed_client_refuses_plain_http() {
        let Err(e) = get("http://127.0.0.1:9/x", "T", GetOpts { conditional: false, ..Default::default() }) else {
            panic!("plain http must be refused");
        };
        assert!(e.message.starts_with("T: network error"), "{e}");
    }

    #[test]
    fn http_urls_only() {
        for ok in ["https://a.example/", "HTTP://a.example", "http://localhost:3000/x"] {
            assert!(is_http_url(ok), "{ok}");
        }
        for bad in ["javascript:alert(1)", " https://a.example", "data:text/html,x", "file:///etc/passwd", "/rel", "", "é"] {
            assert!(!is_http_url(bad), "{bad}");
        }
    }

    /// Live: proxy from env, 200 then 304 from the on-disk cache.
    /// cargo test -- --ignored live_conditional_get
    #[test]
    #[ignore]
    fn live_conditional_get() {
        let _t = state::testing::temp_state("live-get");
        let u = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";
        let a = get(u, "KEV", GetOpts::default()).unwrap();
        let b = get(u, "KEV", GetOpts::default()).unwrap();
        assert_eq!((a.status, a.from_cache), (200, false));
        assert_eq!((b.status, b.from_cache), (304, true));
        assert_eq!(a.content, b.content);
        let r = get("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json", "delta",
                    GetOpts { byte_range: Some((0, 1023)), headers: &[("Accept-Encoding", "identity")], ..Default::default() }).unwrap();
        assert_eq!((r.status, r.content.len()), (206, 1024));
        let e = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "KEV (cisa.gov)",
                    GetOpts::default()).err().unwrap();
        eprintln!("cisa.gov: {e}");
    }
}
