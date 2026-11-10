//! Google Cloud Storage (JSON API) without an SDK: the state mirror, the run
//! lease and the copy of a month's evidence (report/close.rs).
//!
//! State mode is on when STATE_BUCKET is set (STATE_PREFIX optional). The local
//! STATE_DIR is then a mirror of gs://STATE_BUCKET/STATE_PREFIX/: code keeps
//! reading local files (state.rs), and
//!   - sync() brings the mirror up to date: list the objects (paged), download
//!     the new and changed ones (by generation), delete local files whose object
//!     is gone. Done once when state is first used (state::init, or lazily on
//!     the first state::dir()) and again each time the run lock is taken;
//!   - push() uploads a file right after every local write, with
//!     ifGenerationMatch=<generation this process knows> (0 = new object). HTTP 412
//!     means another writer changed it: the lock was lost, so it panics;
//!   - the run lock is the object run.lock, created with ifGenerationMatch=0
//!     (lease with expires_at, see Mirror::acquire).
//!
//! Writes go to the bucket only while this process holds the lease; a write
//! without it (a `locked` runs.jsonl line, `report --month`) stays local and is
//! replaced by the bucket's copy at the next sync.
//!
//! All writes are `uploadType=multipart`: fake-gcs-server (the emulator, 1.52.2)
//! honours ifGenerationMatch only there; real GCS honours it everywhere.
//!
//! Auth: GCS_ENDPOINT set (emulator) = that base URL, no auth, no proxy.
//! Otherwise https://storage.googleapis.com with an access token from the
//! metadata server (GCE_METADATA_HOST, default metadata.google.internal), cached
//! until 60 s before it expires; the metadata server is always reached without
//! a proxy.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::common::{BodyError, MAX_TOKEN_BODY, TIMEOUT_SECS, parse_iso, read_capped, user_agent};
use super::state;

pub const DEFAULT_ENDPOINT: &str = "https://storage.googleapis.com";
const DEFAULT_METADATA_HOST: &str = "metadata.google.internal";
/// A cached access token is renewed this long before it expires.
const TOKEN_MARGIN_SECS: u64 = 60;
/// Attempts per request on a network error, HTTP 408, 429 or 5xx.
const ATTEMPTS: u32 = 3;
/// Cap on a GCS answer: an object download (the largest state files, cvelist and NVD
/// record stores, are ~5 MB each at 2026-11 volume; events.jsonl grows by month)
/// or a JSON API answer (a list page of 1,000 names is ~100 KB).
pub const MAX_GCS_BODY: u64 = 64 * 1024 * 1024;

fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(250 << attempt)
}

/// Client without proxy: the metadata server and the emulator are local.
fn direct_client() -> &'static Client {
    static C: OnceLock<Client> = OnceLock::new();
    C.get_or_init(|| {
        Client::builder().no_proxy().timeout(Duration::from_secs(TIMEOUT_SECS)).build().expect("HTTP client")
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------- errors

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct GcsError {
    /// HTTP status of the answer; None for a network or decoding error.
    pub status: Option<u16>,
    pub message: String,
    /// Worth another attempt (network error, 408, 429, 5xx).
    pub transient: bool,
}

impl GcsError {
    fn net(what: &str, e: &reqwest::Error) -> Self {
        Self { status: None, message: format!("{what}: network error: {e}"), transient: true }
    }

    /// A body that broke off is retried like a network error; one over its cap is not.
    fn body(what: &str, e: BodyError) -> Self {
        Self { status: None, transient: !e.too_large(), message: format!("{what}: {e}") }
    }

    fn bad(what: &str, m: impl std::fmt::Display) -> Self {
        Self { status: None, message: format!("{what}: {m}"), transient: false }
    }

    fn http(what: &str, status: u16, body: &[u8]) -> Self {
        let text: String = String::from_utf8_lossy(body).split_whitespace().collect::<Vec<_>>().join(" ");
        let text: String = text.chars().take(200).collect();
        Self {
            status: Some(status),
            message: format!("{what}: HTTP {status} {text}").trim_end().to_string(),
            transient: status == 408 || status == 429 || status >= 500,
        }
    }

    /// HTTP 412: the object's generation is not the one the request named.
    pub fn conflict(&self) -> bool {
        self.status == Some(412)
    }

    pub fn not_found(&self) -> bool {
        self.status == Some(404)
    }
}

// ---------------------------------------------------------------- encoding

/// Percent-encode everything but RFC 3986 unreserved characters ("/" -> "%2F").
pub fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// GCS sends int64 fields (generation, size) as JSON strings.
fn int_of(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str()?.parse().ok())
}

/// `multipart/related` upload body: JSON metadata {"name"} + the bytes. Returns
/// (Content-Type header, body). The boundary is derived from the data's sha256,
/// so it cannot occur in the data.
pub fn multipart(name: &str, data: &[u8]) -> (String, Vec<u8>) {
    let boundary = format!("ew_{}", &hex::encode(Sha256::digest(data))[..32]);
    let mut body = Vec::with_capacity(data.len() + 256);
    body.extend_from_slice(format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n").as_bytes());
    body.extend_from_slice(json!({"name": name}).to_string().as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/related; boundary={boundary}"), body)
}

// ---------------------------------------------------------------- auth

/// Access token from the metadata server, cached until TOKEN_MARGIN_SECS before expiry.
pub struct TokenSource {
    url: String,
    cache: Mutex<Option<(String, Instant)>>,
}

impl TokenSource {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), cache: Mutex::new(None) }
    }

    pub fn get(&self) -> Result<String, GcsError> {
        let mut c = lock(&self.cache);
        if let Some((t, until)) = c.as_ref()
            && Instant::now() < *until {
            return Ok(t.clone());
        }
        let what = "GCS access token (metadata server)";
        let r = direct_client().get(&self.url).header("Metadata-Flavor", "Google").send()
            .map_err(|e| GcsError::net(what, &e))?;
        let status = r.status().as_u16();
        let body = read_capped(r, MAX_TOKEN_BODY).map_err(|e| GcsError::body(what, e))?;
        if status != 200 {
            return Err(GcsError::http(what, status, &body));
        }
        let v: Value = serde_json::from_slice(&body).map_err(|e| GcsError::bad(what, e))?;
        let token = v["access_token"].as_str().filter(|t| !t.is_empty())
            .ok_or_else(|| GcsError::bad(what, "no access_token in the answer"))?.to_string();
        let secs = v["expires_in"].as_u64().unwrap_or(0).saturating_sub(TOKEN_MARGIN_SECS);
        *c = Some((token.clone(), Instant::now() + Duration::from_secs(secs)));
        Ok(token)
    }
}

// ---------------------------------------------------------------- client

/// One GCS endpoint with its auth.
pub struct Gcs {
    base: String,
    client: Client,
    token: Option<TokenSource>,
}

impl Gcs {
    /// GCS_ENDPOINT (emulator, no auth, no proxy), else storage.googleapis.com with
    /// a metadata-server token (GCE_METADATA_HOST) through the shared client.
    pub fn from_var(var: &dyn Fn(&str) -> Option<String>) -> Self {
        let set = |k: &str| var(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        match set("GCS_ENDPOINT") {
            Some(e) => Self { base: e.trim_end_matches('/').to_string(), client: direct_client().clone(), token: None },
            None => {
                let host = set("GCE_METADATA_HOST").unwrap_or_else(|| DEFAULT_METADATA_HOST.into());
                let url = format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/token");
                Self { base: DEFAULT_ENDPOINT.into(), client: super::common::client().clone(), token: Some(TokenSource::new(url)) }
            }
        }
    }

    #[cfg(test)]
    pub fn test(base: &str, token_url: Option<String>) -> Self {
        Self { base: base.into(), client: direct_client().clone(), token: token_url.map(TokenSource::new) }
    }

    fn object_url(&self, bucket: &str, name: &str) -> String {
        format!("{}/storage/v1/b/{}/o/{}", self.base, enc(bucket), enc(name))
    }

    /// One attempt; Ok(body) for a 2xx answer.
    fn attempt(&self, what: &str, req: RequestBuilder) -> Result<Vec<u8>, GcsError> {
        let mut req = req.header(USER_AGENT, user_agent());
        if let Some(t) = &self.token {
            req = req.bearer_auth(t.get()?);
        }
        let r = req.send().map_err(|e| GcsError::net(what, &e))?;
        let status = r.status().as_u16();
        let body = read_capped(r, MAX_GCS_BODY).map_err(|e| GcsError::body(what, e))?;
        if (200..300).contains(&status) {
            Ok(body)
        } else {
            Err(GcsError::http(what, status, &body))
        }
    }

    /// Idempotent request, retried on transient errors.
    fn retry(&self, what: &str, build: impl Fn() -> RequestBuilder) -> Result<Vec<u8>, GcsError> {
        let mut i = 0;
        loop {
            match self.attempt(what, build()) {
                Err(e) if e.transient && i + 1 < ATTEMPTS => {
                    std::thread::sleep(backoff(i));
                    i += 1;
                }
                r => return r,
            }
        }
    }

    /// (name, generation) of every object under `prefix`, all pages.
    pub fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<(String, i64)>, GcsError> {
        let what = format!("list gs://{bucket}/{prefix}");
        let mut out = Vec::new();
        let mut token = String::new();
        loop {
            let mut url = format!("{}/storage/v1/b/{}/o?prefix={}&fields={}", self.base, enc(bucket), enc(prefix),
                                  enc("items(name,generation),nextPageToken"));
            if !token.is_empty() {
                url.push_str(&format!("&pageToken={}", enc(&token)));
            }
            let body = self.retry(&what, || self.client.get(&url))?;
            let v: Value = serde_json::from_slice(&body).map_err(|e| GcsError::bad(&what, e))?;
            for it in v["items"].as_array().into_iter().flatten() {
                let (Some(name), Some(g)) = (it["name"].as_str(), int_of(&it["generation"])) else {
                    return Err(GcsError::bad(&what, format!("object without name or generation: {it}")));
                };
                out.push((name.to_string(), g));
            }
            match v["nextPageToken"].as_str().filter(|t| !t.is_empty()) {
                Some(t) => token = t.to_string(),
                None => return Ok(out),
            }
        }
    }

    pub fn download(&self, bucket: &str, name: &str) -> Result<Vec<u8>, GcsError> {
        let url = format!("{}?alt=media", self.object_url(bucket, name));
        self.retry(&format!("download gs://{bucket}/{name}"), || self.client.get(&url))
    }

    /// The object's metadata (generation, size, timeCreated, …).
    pub fn metadata(&self, bucket: &str, name: &str) -> Result<Value, GcsError> {
        let what = format!("read gs://{bucket}/{name}");
        let url = self.object_url(bucket, name);
        let body = self.retry(&what, || self.client.get(&url))?;
        serde_json::from_slice(&body).map_err(|e| GcsError::bad(&what, e))
    }

    /// Upload `data` as `name` if the object's generation is `if_generation`
    /// (0: only if it does not exist). Returns the new generation; 412 = conflict.
    /// After an attempt whose outcome is unknown (network error, 5xx), a 412 on the
    /// retry is checked: when the object now holds exactly `data`, that attempt
    /// succeeded and its generation is returned.
    pub fn upload(&self, bucket: &str, name: &str, data: &[u8], if_generation: i64) -> Result<i64, GcsError> {
        let what = format!("upload gs://{bucket}/{name}");
        let url = format!("{}/upload/storage/v1/b/{}/o?uploadType=multipart&ifGenerationMatch={if_generation}",
                          self.base, enc(bucket));
        let (ct, body) = multipart(name, data);
        let mut unsure = false;
        let mut i = 0;
        loop {
            match self.attempt(&what, self.client.post(&url).header(CONTENT_TYPE, &ct).body(body.clone())) {
                Ok(b) => {
                    let v: Value = serde_json::from_slice(&b).map_err(|e| GcsError::bad(&what, e))?;
                    return int_of(&v["generation"]).ok_or_else(|| GcsError::bad(&what, "no generation in the answer"));
                }
                Err(e) if e.conflict() && unsure => {
                    return match self.holds(bucket, name, data) {
                        Ok(Some(g)) => Ok(g),
                        _ => Err(e),
                    };
                }
                Err(e) if e.transient && i + 1 < ATTEMPTS => {
                    unsure = true;
                    std::thread::sleep(backoff(i));
                    i += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Some(generation) when the object holds exactly `data`.
    fn holds(&self, bucket: &str, name: &str, data: &[u8]) -> Result<Option<i64>, GcsError> {
        let m = self.metadata(bucket, name)?;
        if int_of(&m["size"]) != Some(data.len() as i64) {
            return Ok(None);
        }
        Ok((self.download(bucket, name)? == data).then(|| int_of(&m["generation"])).flatten())
    }

    /// Delete `name`, only at `if_generation` when given. 404 is an error here.
    pub fn delete(&self, bucket: &str, name: &str, if_generation: Option<i64>) -> Result<(), GcsError> {
        let mut url = self.object_url(bucket, name);
        if let Some(g) = if_generation {
            url.push_str(&format!("?ifGenerationMatch={g}"));
        }
        self.retry(&format!("delete gs://{bucket}/{name}"), || self.client.delete(&url)).map(|_| ())
    }
}

// ---------------------------------------------------------------- mirror

/// What this process knows about the bucket.
#[derive(Default)]
struct Known {
    /// Relative path -> generation of the object the local file matches.
    gens: HashMap<String, i64>,
    /// Local files that may differ from the bucket (failed or lease-less write):
    /// the next sync replaces them with the bucket's copy, or deletes them.
    dirty: HashSet<String>,
    /// Generation of run.lock while this process holds the lease.
    lease: Option<i64>,
    /// A write met HTTP 412 under this lease (the object that did): every later
    /// write stops too, also when the first panic was caught (feed modules).
    lost: Option<String>,
}

impl Known {
    /// Under the lease and not lost: Ok(true) = upload; Ok(false) = no lease, keep
    /// local only; Err(message) = the lock was lost earlier.
    fn may_write(&mut self, rel: &str) -> Result<bool, String> {
        if self.lease.is_none() {
            self.dirty.insert(rel.to_string());
            return Ok(false);
        }
        if let Some(url) = &self.lost {
            self.dirty.insert(rel.to_string());
            return Err(format!("state: the run lock was lost ({url} was changed by another writer); not writing {rel}"));
        }
        Ok(true)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Synced {
    pub objects: usize,
    pub downloaded: usize,
    pub removed: usize,
}

pub struct Mirror {
    gcs: Gcs,
    bucket: String,
    prefix: String,
    known: Mutex<Known>,
    warned: AtomicBool,
}

/// Mirrored at all: not temp files, not the lock, no odd path components.
fn mirrored(rel: &str) -> bool {
    !rel.is_empty() && !rel.ends_with('/') && !rel.starts_with('/') && !rel.ends_with(".tmp")
        && rel != state::LOCK_FILE && !rel.split('/').any(|c| c.is_empty() || c == "." || c == ".." || c.contains('\\'))
}

fn write_local(p: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = std::path::PathBuf::from(format!("{}.tmp", p.display()));
    fs::write(&tmp, data)?;
    fs::rename(&tmp, p)
}

impl Mirror {
    pub fn new(gcs: Gcs, bucket: &str, prefix: &str) -> Self {
        Self {
            gcs, bucket: bucket.trim().to_string(), prefix: prefix.trim().trim_matches('/').to_string(),
            known: Mutex::new(Known::default()), warned: AtomicBool::new(false),
        }
    }

    /// None when STATE_BUCKET is not set (local state only).
    pub fn from_var(var: &dyn Fn(&str) -> Option<String>) -> Option<Self> {
        let bucket = var("STATE_BUCKET").filter(|b| !b.trim().is_empty())?;
        Some(Self::new(Gcs::from_var(var), &bucket, &var("STATE_PREFIX").unwrap_or_default()))
    }

    /// Object name of a state path: "<prefix>/<rel>", or "<rel>" without a prefix.
    pub fn object(&self, rel: &str) -> String {
        if self.prefix.is_empty() { rel.to_string() } else { format!("{}/{rel}", self.prefix) }
    }

    /// "gs://bucket/object" for messages.
    pub fn url(&self, rel: &str) -> String {
        format!("gs://{}/{}", self.bucket, self.object(rel))
    }

    /// Bring the local mirror under `dir` up to date with the bucket (module doc).
    pub fn sync(&self, dir: &Path) -> Result<Synced, GcsError> {
        let list_prefix = if self.prefix.is_empty() { String::new() } else { format!("{}/", self.prefix) };
        let listed = self.gcs.list(&self.bucket, &list_prefix)?;
        let mut k = lock(&self.known);
        let mut st = Synced::default();
        let mut seen = HashSet::new();
        for (name, generation) in listed {
            let Some(rel) = name.strip_prefix(&list_prefix).filter(|r| mirrored(r)) else { continue };
            seen.insert(rel.to_string());
            st.objects += 1;
            let p = dir.join(rel);
            if k.gens.get(rel) == Some(&generation) && !k.dirty.contains(rel) && p.exists() {
                continue;
            }
            let data = self.gcs.download(&self.bucket, &name)?;
            write_local(&p, &data).map_err(|e| GcsError::bad(&format!("sync {}", p.display()), e))?;
            k.gens.insert(rel.to_string(), generation);
            k.dirty.remove(rel);
            st.downloaded += 1;
        }
        let gone: HashSet<String> = k.gens.keys().chain(k.dirty.iter()).filter(|r| !seen.contains(*r)).cloned().collect();
        for rel in gone {
            let _ = fs::remove_file(dir.join(&rel));
            k.gens.remove(&rel);
            k.dirty.remove(&rel);
            st.removed += 1;
        }
        Ok(st)
    }

    /// Write-through of a local write: upload the whole file at the known
    /// generation. Panics on failure (412: another writer; the lock was lost).
    pub fn push(&self, rel: &str, data: &[u8]) {
        if !mirrored(rel) {
            return;
        }
        let mut k = lock(&self.known);
        match k.may_write(rel) {
            Ok(true) => {}
            Ok(false) => {
                if !self.warned.swap(true, Ordering::Relaxed) {
                    eprintln!("state: this process does not hold the run lock; {rel} and later writes stay local (not in {})",
                              self.url(""));
                }
                return;
            }
            Err(m) => {
                drop(k);
                panic!("{m}");
            }
        }
        let expected = k.gens.get(rel).copied().unwrap_or(0);
        match self.gcs.upload(&self.bucket, &self.object(rel), data, expected) {
            Ok(g) => {
                k.gens.insert(rel.to_string(), g);
                k.dirty.remove(rel);
            }
            Err(e) => {
                k.dirty.insert(rel.to_string());
                if e.conflict() {
                    k.lost = Some(self.url(rel));
                }
                drop(k);
                if e.conflict() {
                    panic!("state: {} was changed by another writer (HTTP 412 at generation {expected}); \
                            the run lock was lost, stopping", self.url(rel));
                }
                panic!("state: cannot upload {}: {e}", self.url(rel));
            }
        }
    }

    /// The local file `rel` was deleted: delete its object (at the known generation).
    pub fn remove(&self, rel: &str) {
        if !mirrored(rel) {
            return;
        }
        let mut k = lock(&self.known);
        match k.may_write(rel) {
            Ok(true) => {}
            Ok(false) => return,
            Err(m) => {
                drop(k);
                panic!("{m}");
            }
        }
        k.dirty.remove(rel);
        let Some(g) = k.gens.remove(rel) else { return };
        match self.gcs.delete(&self.bucket, &self.object(rel), Some(g)) {
            Ok(()) => {}
            Err(e) if e.not_found() => {}
            Err(e) => {
                k.dirty.insert(rel.to_string());
                if e.conflict() {
                    k.lost = Some(self.url(rel));
                }
                drop(k);
                panic!("state: cannot delete {}: {e}", self.url(rel));
            }
        }
    }

    // ------------------------------------------------------------ lease

    /// Take the lease: create run.lock with ifGenerationMatch=0 and `holder` (which
    /// carries expires_at) as its body. Ok(Err(holder text)) when another process
    /// holds it. A lease past its expires_at (or, without one, past timeCreated +
    /// `ttl_secs`) is deleted at its generation and the create tried once more.
    pub fn acquire(&self, holder: &Value, now: DateTime<Utc>, ttl_secs: i64) -> Result<Result<(), String>, GcsError> {
        let name = self.object(state::LOCK_FILE);
        let body = format!("{holder}\n");
        for attempt in 0..2 {
            match self.gcs.upload(&self.bucket, &name, body.as_bytes(), 0) {
                Ok(g) => {
                    let mut k = lock(&self.known);
                    k.lease = Some(g);
                    k.lost = None;
                    return Ok(Ok(()));
                }
                Err(e) if e.conflict() => {}
                Err(e) => return Err(e),
            }
            let read = self.gcs.metadata(&self.bucket, &name)
                .and_then(|m| Ok((m.clone(), self.gcs.download(&self.bucket, &name)?)));
            let (meta, raw) = match read {
                Ok(x) => x,
                Err(e) if e.not_found() => continue, // released meanwhile
                Err(e) => return Err(e),
            };
            let text = String::from_utf8_lossy(&raw).trim().to_string();
            let expires = serde_json::from_str::<Value>(&text).ok()
                .and_then(|v| parse_iso(v["expires_at"].as_str()?))
                .or_else(|| parse_iso(meta["timeCreated"].as_str()?).map(|t| t + chrono::Duration::seconds(ttl_secs)));
            if attempt == 0 && let Some(t) = expires.filter(|t| *t <= now) {
                eprintln!("state: {} expired at {} ({text}); taking it over", self.url(state::LOCK_FILE),
                          super::common::iso_utc(t));
                match self.gcs.delete(&self.bucket, &name, int_of(&meta["generation"])) {
                    Ok(()) => continue,
                    Err(e) if e.not_found() || e.conflict() => continue,
                    Err(e) => return Err(e),
                }
            }
            return Ok(Err(if text.is_empty() { "holder unknown".into() } else { text }));
        }
        Ok(Err("holder unknown (the lock changed while it was read)".into()))
    }

    /// Release the lease (RunLock drop): delete run.lock at our generation.
    pub fn release(&self) {
        let Some(g) = lock(&self.known).lease.take() else { return };
        let name = self.object(state::LOCK_FILE);
        match self.gcs.delete(&self.bucket, &name, Some(g)) {
            Ok(()) => {}
            Err(e) if e.not_found() || e.conflict() => {
                eprintln!("state: {} was no longer ours at release ({e})", self.url(state::LOCK_FILE));
            }
            Err(e) => eprintln!("state: cannot release {}: {e}", self.url(state::LOCK_FILE)),
        }
    }
}

// ---------------------------------------------------------------- process-wide mirror

enum Slot {
    /// Not looked at STATE_BUCKET yet.
    Unset,
    Off,
    On(Arc<Mirror>),
}

static SLOT: RwLock<Slot> = RwLock::new(Slot::Unset);

/// The state mirror of this process; None without STATE_BUCKET. The first call
/// reads the environment and syncs (init()); a failed sync panics here.
pub fn active() -> Option<Arc<Mirror>> {
    match &*SLOT.read().unwrap_or_else(|e| e.into_inner()) {
        Slot::Off => return None,
        Slot::On(m) => return Some(m.clone()),
        Slot::Unset => {}
    }
    init().unwrap_or_else(|e| panic!("{e}"))
}

/// Read STATE_BUCKET once and, when set, sync the mirror. Err when that sync fails
/// (the next call tries again).
pub fn init() -> Result<Option<Arc<Mirror>>, String> {
    let mut slot = SLOT.write().unwrap_or_else(|e| e.into_inner());
    match &*slot {
        Slot::Off => return Ok(None),
        Slot::On(m) => return Ok(Some(m.clone())),
        Slot::Unset => {}
    }
    let var = |k: &str| std::env::var(k).ok();
    let Some(m) = Mirror::from_var(&var) else {
        *slot = Slot::Off;
        return Ok(None);
    };
    let dir = state::local_dir();
    let st = m.sync(&dir).map_err(|e| format!("cannot sync state from {} into {}: {e}", m.url(""), dir.display()))?;
    println!("state: mirror of {} in {}: {} objects, {} downloaded", m.url(""), dir.display(), st.objects, st.downloaded);
    let m = Arc::new(m);
    *slot = Slot::On(m.clone());
    Ok(Some(m))
}

/// Tests: state mode on with this mirror, or off (also what temp_state sets).
#[cfg(test)]
pub fn set_active(m: Option<Mirror>) {
    *SLOT.write().unwrap_or_else(|e| e.into_inner()) = match m {
        Some(m) => Slot::On(Arc::new(m)),
        None => Slot::Off,
    };
}

#[cfg(test)]
mod tests;
