//! CVE.org cvelistV5: the primary CVE feed (CNA-published records, minutes after
//! publication).
//!
//! Steady state reads only the head of cves/deltaLog.json (36 MB, newest first)
//! with a byte Range, takes the entries newer than the saved cursor, and fetches
//! those records' raw JSON (~45 per 30 minutes). Every in-window record lives
//! in a local store, so each run returns the full window and the renderer filters.
//!
//! First run, or a cursor too old for the 4 MB deltaLog cap: rebuild the store
//! from the GitHub release zips (one ~2 MB end-of-day delta per window day, plus
//! today's latest hourly delta, which is cumulative since midnight), then catch up
//! from the deltaLog, which is also read back to the window start so the commit
//! just after each midnight (missing from both adjacent zips) can be replayed.
//! Release downloads go to github.com, not api.github.com, so they do not spend
//! the 60 req/h API budget. Never touch *_all_CVEs_at_midnight (650 MB).
//!
//! State:
//!   cursors/cvelist.json          {fetch_time, run_at, retry: {cveId: [url, tries]}, stats}
//!   cursors/cvelist_records.json  {cveId: Item as JSON} for every in-window record

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Timelike, Utc};
use serde_json::{Map, Value, json};

use super::common::{self, FetchOutput, GetOpts, Item, Response, SourceError, iso_utc, parse_iso, severity_for};
use super::state;

pub const NAME: &str = "CVE.org cvelistV5";
pub const CADENCE: u64 = 0;

pub const DELTA_URL: &str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json";
const RELEASE_BASE: &str = "https://github.com/CVEProject/cvelistV5/releases/download";
pub const CHUNK: usize = 128 * 1024; // ~2-4 h of deltaLog at 2026-11 volume
pub const MAX_DELTA: usize = 4 * 1024 * 1024; // ~3 days; past that, backfill is cheaper
const MAX_CURSOR_AGE_DAYS: i64 = 3;
const OVERLAP_MIN: i64 = 15; // re-read a little before a release snapshot; refetching is harmless
pub const BACKFILL_CHUNK: usize = 1024 * 1024; // backfill reads the log back to the window start (~1.3 MB/day)
pub const BACKFILL_DELTA: usize = 16 * 1024 * 1024;
// The first commit after 00:00 UTC is in neither the day's end-of-day zip nor the next
// day's "since midnight" zips (2026-11-03: fetchTime 00:06:24, 5 records). Backfill
// replays deltaLog entries in this slot around every midnight.
const MIDNIGHT_GAP_MIN: (i64, i64) = (-15, 45);
pub const WORKERS: usize = 8;
pub const MAX_RETRY: u64 = 3; // runs a 404 record is retried before it is dropped
pub const DESC_MAX: usize = 400;

pub const CURSOR: &str = "cursors/cvelist.json";
pub const STORE: &str = "cursors/cvelist_records.json";

fn overlap() -> Duration {
    Duration::minutes(OVERLAP_MIN)
}

fn severity_word(w: &str) -> Option<&'static str> {
    Some(match w {
        "critical" => "CRITICAL",
        "high" | "important" => "HIGH",
        "medium" | "moderate" => "MEDIUM",
        "low" => "LOW",
        _ => return None,
    })
}

// ---------------------------------------------------------------- record parsing

fn arr(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// (av, pr) from a CVSS 3.x or 4.0 vector, same buckets as Mark's NVD table.
pub fn vector_bits(vec: &str) -> (&'static str, &'static str) {
    let av = if vec.contains("AV:N") { "network" } else if vec.contains("AV:L") { "local" } else { "" };
    let pr = if vec.contains("PR:N") {
        "none"
    } else if vec.contains("PR:L") {
        "low"
    } else if vec.contains("PR:H") {
        "high"
    } else {
        ""
    };
    (av, pr)
}

/// A number or numeric string as f64; None for anything else.
fn as_score(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// (score, severity, vector) from a CVE 5 metrics[] list, newest CVSS version first; None if unscored.
pub fn cvss(metrics: &[Value]) -> Option<(f64, String, String)> {
    for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0"] {
        for m in metrics {
            let Some(d) = m.get(key).filter(|d| d.as_object().is_some_and(|o| !o.is_empty())) else { continue };
            let Some(bs) = d.get("baseScore").filter(|b| !b.is_null()) else { continue };
            let score = as_score(bs).unwrap_or(0.0);
            let mut sev = s(d, "baseSeverity").to_uppercase();
            if !matches!(sev.as_str(), "CRITICAL" | "HIGH" | "MEDIUM" | "LOW") {
                sev = severity_for(score).to_string(); // also maps v4 "NONE" to ""
            }
            return Some((score, sev, s(d, "vectorString").to_string()));
        }
    }
    None
}

/// Some CNAs rate in words only (metrics[].other, e.g. Red Hat "Important").
pub fn other_severity(metrics: &[Value]) -> &'static str {
    for m in metrics {
        let mut c = m.get("other").and_then(|o| o.get("content"));
        if let Some(Value::Object(o)) = c {
            c = ["text", "value", "baseSeverity"].iter().filter_map(|k| o.get(*k)).find(|x| truthy(x));
        }
        if let Some(Value::String(w)) = c {
            if let Some(sev) = severity_word(&w.trim().to_lowercase()) {
                return sev;
            }
        }
    }
    ""
}

/// False for null, false, 0, "", [] and {}; true otherwise.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

pub fn ssvc_exploitation(metrics: &[Value]) -> String {
    for m in metrics {
        let Some(o) = m.get("other") else { continue };
        if s(o, "type") == "ssvc" {
            for opt in arr(o.get("content").and_then(|c| c.get("options"))) {
                if let Some(x) = opt.get("Exploitation") {
                    return match x {
                        Value::String(t) => t.to_lowercase(),
                        other => other.to_string().to_lowercase(),
                    };
                }
            }
        }
    }
    String::new()
}

fn truncate_desc(desc: &str) -> String {
    let desc = desc.split_whitespace().collect::<Vec<_>>().join(" ");
    if desc.chars().count() > DESC_MAX {
        let mut t: String = desc.chars().take(DESC_MAX - 1).collect();
        t.push('…');
        return t;
    }
    desc
}

fn bad(what: &str, cid: &str, val: &str) -> SourceError {
    SourceError::new(format!("{NAME} {cid}: bad {what} {val:?}"))
}

/// CVE JSON 5 record -> Item, or None when it is not a published record.
/// Err when a published record has an unparseable date.
pub fn parse_record(rec: &Value) -> Result<Option<Item>, SourceError> {
    let empty = Value::Null;
    let meta = rec.get("cveMetadata").unwrap_or(&empty);
    if s(meta, "state") != "PUBLISHED" || s(meta, "datePublished").is_empty() {
        return Ok(None);
    }
    let cid = s(meta, "cveId");
    if cid.is_empty() {
        return Err(SourceError::new(format!("{NAME}: published record without cveId")));
    }
    let containers = rec.get("containers").unwrap_or(&empty);
    let cna = containers.get("cna").unwrap_or(&empty);
    let adp = arr(containers.get("adp")).iter()
        .find(|a| a.get("providerMetadata").map(|p| s(p, "shortName")) == Some("CISA-ADP"))
        .unwrap_or(&empty);
    let cna_metrics = arr(cna.get("metrics"));
    let adp_metrics = arr(adp.get("metrics"));

    // The CNA's own score wins; CISA-ADP (Vulnrichment) fills in when the CNA gave none.
    let (score, sev, vec, src) = if let Some((a, b, c)) = cvss(cna_metrics) {
        (a, b, c, "CNA")
    } else if let Some((a, b, c)) = cvss(adp_metrics) {
        (a, b, c, "CISA-ADP")
    } else {
        let sev = other_severity(cna_metrics);
        (0.0, sev.to_string(), String::new(), if sev.is_empty() { "" } else { "CNA" })
    };

    let desc = arr(cna.get("descriptions")).iter()
        .find(|d| s(d, "lang").to_lowercase().starts_with("en"))
        .map(|d| s(d, "value"))
        .unwrap_or("");
    let desc = truncate_desc(desc);
    let mut vendors: Vec<String> = Vec::new();
    for a in arr(cna.get("affected")) {
        let v = s(a, "vendor").trim();
        if !v.is_empty() && v.to_lowercase() != "n/a" && !vendors.iter().any(|x| x == v) {
            vendors.push(v.to_string());
        }
    }
    let (av, pr) = vector_bits(&vec);
    let dp = s(meta, "datePublished");
    let published = iso_utc(parse_iso(dp).ok_or_else(|| bad("datePublished", cid, dp))?);
    let du = s(meta, "dateUpdated");
    let updated = if du.is_empty() { String::new() } else { iso_utc(parse_iso(du).ok_or_else(|| bad("dateUpdated", cid, du))?) };

    let title = if desc.is_empty() { s(cna, "title").to_string() } else { desc };
    let mut it = Item::new(NAME, cid, &format!("https://www.cve.org/CVERecord?id={cid}"), &title, &published);
    it.updated = updated;
    it.cves = vec![cid.to_string()];
    it.score = score;
    it.severity = sev;
    vendors.truncate(3);
    it.extra = match json!({
        "score_source": src, "vector": vec, "av": av, "pr": pr, "vendors": vendors,
        "ssvc_exploitation": ssvc_exploitation(adp_metrics),
        "assigner": s(meta, "assignerShortName"), "nvd_score": "",
    }) {
        Value::Object(m) => m,
        _ => unreachable!(),
    };
    Ok(Some(it))
}

pub type Store = Map<String, Value>;

/// Upsert one record into the store; drop it if rejected or published before the window.
pub fn apply(store: &mut Store, rec: &Value, start: DateTime<Utc>) -> Result<(), SourceError> {
    let Some(cid) = rec.get("cveMetadata").and_then(|m| m.get("cveId")).and_then(Value::as_str).filter(|c| !c.is_empty()) else {
        return Ok(());
    };
    match parse_record(rec)? {
        Some(item) if parse_iso(&item.published).is_some_and(|p| p >= start) => {
            store.insert(cid.to_string(), serde_json::to_value(&item).expect("item is JSON"));
        }
        _ => {
            store.remove(cid);
        }
    }
    Ok(())
}

/// Store entries published in the window. An entry without a readable "published" is dropped.
pub fn prune(store: Store, start: DateTime<Utc>) -> Store {
    store.into_iter()
        .filter(|(_, v)| v.get("published").and_then(Value::as_str).and_then(parse_iso).is_some_and(|p| p >= start))
        .collect()
}

// ---------------------------------------------------------------- http with cost accounting

/// Request cost of one fetch(); goes into stats as "requests" / "bytes".
#[derive(Default)]
struct Cost {
    requests: u64,
    bytes: u64,
}

impl Cost {
    fn add(&mut self, r: &Response) {
        self.requests += 1;
        self.bytes += r.content.len() as u64;
    }
}

fn is_404(e: &SourceError) -> bool {
    e.status == Some(404)
}

// ---------------------------------------------------------------- deltaLog

/// Complete entries from the head of a JSON array cut off at an arbitrary byte.
pub fn parse_delta_prefix(buf: &[u8]) -> Result<Vec<Value>, SourceError> {
    let text = String::from_utf8_lossy(buf); // a cut multibyte char can only be in the dropped tail
    let b = text.as_bytes();
    let Some(i0) = b.iter().position(|&c| c == b'[') else {
        return Err(SourceError::new(format!("{NAME}: deltaLog does not start with a JSON array")));
    };
    let (mut i, n, mut out) = (i0 + 1, b.len(), Vec::new());
    loop {
        while i < n && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n' | b',') {
            i += 1;
        }
        if i >= n || b[i] == b']' {
            return Ok(out);
        }
        let mut it = serde_json::Deserializer::from_slice(&b[i..]).into_iter::<Value>();
        match it.next() {
            Some(Ok(v)) => {
                i += it.byte_offset();
                out.push(v);
            }
            _ => return Ok(out), // truncated last entry
        }
    }
}

fn fetch_time(e: &Value) -> Result<DateTime<Utc>, SourceError> {
    let ft = s(e, "fetchTime");
    parse_iso(ft).ok_or_else(|| SourceError::new(format!("{NAME}: deltaLog entry with bad fetchTime {ft:?}")))
}

fn newer_than(entries: &[Value], since: DateTime<Utc>) -> Result<Vec<Value>, SourceError> {
    let mut out = Vec::new();
    for e in entries {
        if fetch_time(e)? > since {
            out.push(e.clone());
        }
    }
    Ok(out)
}

/// Entries with fetchTime > since, newest first, and whether the read got back to since.
/// Reads the head in chunk steps up to cap bytes. Accept-Encoding: identity is required:
/// with gzip the Range applies to the compressed bytes.
fn read_delta<G>(get: &G, cost: &mut Cost, since: DateTime<Utc>, chunk: usize, cap: usize) -> Result<(Vec<Value>, bool), SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let label = format!("{NAME} deltaLog");
    for _attempt in 0..3 {
        let mut buf: Vec<u8> = Vec::new();
        let mut etag: Option<String> = None;
        let mut entries: Vec<Value> = Vec::new();
        let mut rewritten = false;
        while buf.len() < cap {
            let first = buf.len() as u64;
            let r = get(DELTA_URL, &label, GetOpts {
                conditional: false,
                byte_range: Some((first, first + chunk as u64 - 1)),
                headers: &[("Accept-Encoding", "identity")],
                ..Default::default()
            })?;
            cost.add(&r);
            let tag = Some(r.header("etag").to_string()).filter(|t| !t.is_empty());
            if etag.is_some() && tag != etag {
                rewritten = true; // file was rewritten between chunks; offsets moved
                break;
            }
            etag = tag;
            let whole = r.status == 200; // server ignored Range and sent everything
            let got = r.content.len();
            if whole {
                buf = r.content;
            } else {
                buf.extend_from_slice(&r.content);
            }
            entries = parse_delta_prefix(&buf)?;
            let newer = newer_than(&entries, since)?;
            if newer.len() < entries.len() {
                return Ok((newer, true));
            }
            if whole || got < chunk {
                return Ok((newer, false)); // end of file, cursor older than the log
            }
        }
        if !rewritten {
            return Ok((newer_than(&entries, since)?, false));
        }
    }
    Err(SourceError::new(format!("{NAME}: deltaLog kept changing between range requests")))
}

/// cveId -> raw record URL for every new/updated entry (errors are not records).
pub fn changed_links(entries: &[Value]) -> BTreeMap<String, String> {
    let mut links = BTreeMap::new();
    for e in entries {
        for c in arr(e.get("new")).iter().chain(arr(e.get("updated"))) {
            let (cid, link) = (s(c, "cveId"), s(c, "githubLink"));
            if !cid.is_empty() && !link.is_empty() {
                links.entry(cid.to_string()).or_insert_with(|| link.to_string());
            }
        }
    }
    links
}

/// Fetch raw records with WORKERS threads. Returns ({cveId: record}, [cveIds that were 404]).
fn fetch_records<G>(get: &G, cost: &mut Cost, links: &BTreeMap<String, String>) -> Result<(BTreeMap<String, Value>, Vec<String>), SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError> + Sync,
{
    let work: Vec<(&String, &String)> = links.iter().collect(); // sorted by cveId
    let next = AtomicUsize::new(0);
    let mut results: Vec<(usize, Result<Response, SourceError>)> = Vec::with_capacity(work.len());
    if !work.is_empty() {
        std::thread::scope(|sc| {
            let handles: Vec<_> = (0..WORKERS.min(work.len())).map(|_| {
                sc.spawn(|| {
                    let mut got = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some((cid, url)) = work.get(i) else { break };
                        got.push((i, get(url, &format!("{NAME} {cid}"), GetOpts { conditional: false, ..Default::default() })));
                    }
                    got
                })
            }).collect();
            for h in handles {
                results.extend(h.join().expect("record worker panicked"));
            }
        });
    }
    results.sort_by_key(|(i, _)| *i);

    let (mut recs, mut missing) = (BTreeMap::new(), Vec::new());
    for (i, res) in results {
        let cid = work[i].0;
        match res {
            // A 404 is usually CDN lag or a moved file: retry next run instead of
            // failing a core feed forever. Anything else fails the feed.
            Err(e) if is_404(&e) => missing.push(cid.clone()),
            Err(e) => return Err(e),
            Ok(r) => {
                cost.add(&r);
                let v: Value = r.json().map_err(|_| SourceError::new(format!("{NAME} {cid}: record is not JSON")))?;
                recs.insert(cid.clone(), v);
            }
        }
    }
    Ok((recs, missing))
}

// ---------------------------------------------------------------- backfill from release zips

/// CVE records from a release zip (layout deltaCves/CVE-*.json, checked 2026-11-03).
pub fn zip_records(content: &[u8]) -> Result<Vec<Value>, SourceError> {
    let not_zip = || SourceError::new(format!("{NAME}: release asset is not a zip"));
    let mut z = zip::ZipArchive::new(Cursor::new(content)).map_err(|_| not_zip())?;
    let mut out = Vec::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i).map_err(|e| SourceError::new(format!("{NAME}: release zip entry {i}: {e}")))?;
        // zip 9: name() is fallible (non-UTF-8 name); such an entry cannot be a CVE-*.json record
        let name = f.name().map(|n| n.into_owned()).unwrap_or_default();
        let base = name.rsplit('/').next().unwrap_or("");
        if base.starts_with("CVE-") && base.ends_with(".json") {
            let mut raw = Vec::new();
            f.read_to_end(&mut raw).map_err(|e| SourceError::new(format!("{NAME}: release zip {name}: {e}")))?;
            out.push(serde_json::from_slice(&raw).map_err(|e| SourceError::new(format!("{NAME}: release zip {name}: {e}")))?);
        }
    }
    Ok(out)
}

fn release_zip<G>(get: &G, cost: &mut Cost, tag: &str, asset: &str) -> Result<Option<Vec<u8>>, SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    if asset.contains("_all_CVEs_") {
        return Err(SourceError::new(format!("{NAME}: refusing to download {asset} (650 MB)")));
    }
    match get(&format!("{RELEASE_BASE}/{tag}/{asset}"), &format!("{NAME} {asset}"), GetOpts { conditional: false, ..Default::default() }) {
        Ok(r) => {
            cost.add(&r);
            Ok(Some(r.content))
        }
        Err(e) if is_404(&e) => Ok(None), // release not published yet
        Err(e) => Err(e),
    }
}

fn midnight(day: NaiveDate) -> DateTime<Utc> {
    Utc.from_utc_datetime(&day.and_hms_opt(0, 0, 0).unwrap())
}

/// (zip bytes, time covered up to) for one UTC day: the end-of-day delta when it
/// exists, else the latest hourly delta (cumulative since midnight).
fn day_snapshot<G>(get: &G, cost: &mut Cost, day: NaiveDate, last_hour: u32) -> Result<Option<(Vec<u8>, DateTime<Utc>)>, SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let ds = day.to_string();
    let m = midnight(day);
    if last_hour == 23 {
        if let Some(z) = release_zip(get, cost, &format!("cve_{ds}_at_end_of_day"), &format!("{ds}_delta_CVEs_at_end_of_day.zip"))? {
            return Ok(Some((z, m + Duration::days(1))));
        }
    }
    for h in (0..=last_hour).rev() {
        if let Some(z) = release_zip(get, cost, &format!("cve_{ds}_{h:02}00Z"), &format!("{ds}_delta_CVEs_at_{h:02}00Z.zip"))? {
            return Ok(Some((z, m + Duration::hours(h as i64))));
        }
    }
    Ok(None)
}

/// Rebuild the store from release zips. Returns (store, snapshot time the zips cover up to).
fn backfill<G>(get: &G, cost: &mut Cost, start: DateTime<Utc>, now: DateTime<Utc>) -> Result<(Store, Option<DateTime<Utc>>), SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let (mut store, mut snap, today) = (Store::new(), None, now.date_naive());
    let mut day = start.date_naive();
    while day <= today {
        let last_hour = if day < today { 23 } else { now.hour() };
        let Some((z, covered)) = day_snapshot(get, cost, day, last_hour)? else {
            if day < today {
                return Err(SourceError::new(format!("{NAME}: no release zip found for {day}")));
            }
            break; // just after midnight: the deltaLog covers today
        };
        for rec in zip_records(&z)? {
            apply(&mut store, &rec, start)?;
        }
        snap = Some(covered);
        day = day.succ_opt().expect("date in range");
    }
    Ok((store, snap))
}

pub fn near_midnight(t: DateTime<Utc>) -> bool {
    let day = midnight(t.date_naive());
    let (lo, hi) = (Duration::minutes(MIDNIGHT_GAP_MIN.0), Duration::minutes(MIDNIGHT_GAP_MIN.1));
    t - day <= hi || (day + Duration::days(1)) - t <= -lo
}

/// deltaLog entries to replay after a zip backfill: everything after the snapshot,
/// plus the midnight slots the zips miss. Fails if the log does not reach the snapshot.
/// Returns (newer, gap, log reaches start).
fn backfill_catch_up<G>(get: &G, cost: &mut Cost, start: DateTime<Utc>, snap: Option<DateTime<Utc>>) -> Result<(Vec<Value>, Vec<Value>, bool), SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let since = snap.unwrap_or(start) - overlap();
    let (entries, reached) = read_delta(get, cost, start, BACKFILL_CHUNK, BACKFILL_DELTA)?;
    let (mut newer, mut gap, mut reaches_snapshot) = (Vec::new(), Vec::new(), false);
    for e in entries {
        let t = fetch_time(&e)?;
        if t > since {
            newer.push(e);
        } else {
            reaches_snapshot = true;
            if near_midnight(t) {
                gap.push(e);
            }
        }
    }
    if !reaches_snapshot {
        return Err(SourceError::new(format!(
            "{NAME}: deltaLog head ({BACKFILL_DELTA} bytes) does not reach back to the backfill snapshot {}",
            iso_utc(since)
        )));
    }
    Ok((newer, gap, reached))
}

// ---------------------------------------------------------------- fetch

fn fetch_with<G>(start: DateTime<Utc>, end: DateTime<Utc>, get: &G) -> Result<FetchOutput, SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError> + Sync,
{
    let t0 = Instant::now();
    let mut cost = Cost::default();
    let mut stats = Map::new();
    let mut mode = "delta";
    let cur: Map<String, Value> = state::load_json(CURSOR).unwrap_or_default();
    let mut store: Option<Store> = state::load_json(STORE);
    let cur_ft = cur.get("fetch_time").and_then(Value::as_str).filter(|s| !s.is_empty());
    let mut since = match cur_ft {
        Some(ft) => Some(parse_iso(ft).ok_or_else(|| SourceError::new(format!("{NAME}: bad cursor fetch_time {ft:?}")))?),
        None => None,
    };

    let mut newer: Option<Vec<Value>> = None;
    let mut gap = Vec::new();
    if let Some(sn) = since {
        if store.is_some() && sn > start.max(end - Duration::days(MAX_CURSOR_AGE_DAYS)) {
            let (n, reached) = read_delta(get, &mut cost, sn, CHUNK, MAX_DELTA)?;
            if reached {
                newer = Some(n);
            }
        }
    }
    let newer = match newer {
        Some(n) => n,
        None => {
            mode = "backfill";
            let (st, snap) = backfill(get, &mut cost, start, end)?;
            stats.insert("backfill_records".into(), st.len().into());
            store = Some(st);
            since = Some(snap.unwrap_or(start) - overlap());
            let (n, g, reached) = backfill_catch_up(get, &mut cost, start, snap)?;
            stats.insert("log_reaches_start".into(), reached.into()); // false: older midnights are not replayed
            stats.insert("midnight_entries".into(), g.len().into());
            gap = g;
            n
        }
    };
    let mut store = store.expect("store is set in both modes");

    // retry: {cveId: [url, tries]}; drop entries that already used up MAX_RETRY runs
    let mut retry: BTreeMap<String, (String, u64)> = BTreeMap::new();
    if let Some(Value::Object(r)) = cur.get("retry") {
        for (cid, v) in r {
            let url = v.get(0).and_then(Value::as_str).unwrap_or("").to_string();
            let tries = v.get(1).and_then(Value::as_u64).unwrap_or(0);
            if tries < MAX_RETRY {
                retry.insert(cid.clone(), (url, tries));
            }
        }
    }
    let mut links: BTreeMap<String, String> = retry.iter().map(|(c, (u, _))| (c.clone(), u.clone())).collect();
    let mut replay = gap;
    replay.extend(newer.iter().cloned());
    links.extend(changed_links(&replay));
    let (recs, missing) = fetch_records(get, &mut cost, &links)?;
    for rec in recs.values() {
        apply(&mut store, rec, start)?;
    }
    let store = prune(store, start);

    stats.insert("requests".into(), cost.requests.into());
    stats.insert("bytes".into(), cost.bytes.into());
    stats.insert("mode".into(), mode.into());
    stats.insert("changed".into(), links.len().into());
    stats.insert("missing".into(), missing.len().into());
    stats.insert("items".into(), store.len().into());
    stats.insert("seconds".into(), json!((t0.elapsed().as_secs_f64() * 10.0).round() / 10.0));

    // Store before cursor: a crash between the two re-reads the same deltas next run.
    state::save_json(STORE, &store);
    // Keep the raw fetchTime (ms precision) so the boundary entry is not re-read.
    let fetch_time = match newer.first() {
        Some(e) => s(e, "fetchTime").to_string(),
        None if mode == "delta" => cur_ft.unwrap_or("").to_string(),
        None => iso_utc(since.expect("since is set in backfill mode")),
    };
    let retry_out: Map<String, Value> = missing.iter()
        .map(|cid| (cid.clone(), json!([links[cid], retry.get(cid).map(|r| r.1).unwrap_or(0) + 1])))
        .collect();
    state::save_json(CURSOR, &json!({
        "fetch_time": fetch_time,
        "run_at": iso_utc(end),
        "retry": retry_out,
        "stats": stats,
    }));

    let mut items = Vec::with_capacity(store.len());
    for (k, v) in store {
        items.push(serde_json::from_value::<Item>(v).map_err(|e| SourceError::new(format!("{NAME}: bad store entry {k}: {e}")))?);
    }
    items.sort_by(|a, b| (&b.published, &b.id).cmp(&(&a.published, &a.id)));
    Ok(FetchOutput { items, stats })
}

pub fn fetch(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    fetch_with(start, end, &common::get)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::Mutex;

    use super::super::kev::testutil::*;
    use super::*;

    fn make_record(cid: &str, published: &str, state_: &str, cna_metrics: Value) -> Value {
        json!({"cveMetadata": {"cveId": cid, "state": state_, "datePublished": published,
                               "dateUpdated": published, "assignerShortName": "test"},
               "containers": {"cna": {"descriptions": [{"lang": "en", "value": format!("{cid} desc")}],
                                      "affected": [{"vendor": "n/a"}, {"vendor": "Acme"}],
                                      "metrics": cna_metrics}}})
    }

    fn rec(cid: &str, published: &str) -> Value {
        make_record(cid, published, "PUBLISHED", json!([]))
    }

    fn rejected(cid: &str, published: &str) -> Value {
        make_record(cid, published, "REJECTED", json!([]))
    }

    fn make_zip(records: &[Value]) -> Vec<u8> {
        let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for r in records {
            z.start_file(format!("deltaCves/{}.json", r["cveMetadata"]["cveId"].as_str().unwrap()), opts).unwrap();
            z.write_all(&serde_json::to_vec(r).unwrap()).unwrap();
        }
        z.start_file("deltaCves/README.txt", opts).unwrap();
        z.write_all(b"not a record").unwrap();
        z.finish().unwrap().into_inner()
    }

    fn delta_log(entries: &[Value]) -> Vec<u8> {
        // indent=2, like the real file
        let mut buf = Vec::new();
        let fmt = serde_json::ser::PrettyFormatter::with_indent(b"  ");
        serde::Serialize::serialize(&entries, &mut serde_json::Serializer::with_formatter(&mut buf, fmt)).unwrap();
        buf
    }

    fn entry(fetch_time: &str, cves: &[&str], kind: &str) -> Value {
        let rows: Vec<Value> = cves.iter()
            .map(|c| json!({"cveId": c, "githubLink": format!("https://raw.test/{c}.json"), "dateUpdated": fetch_time}))
            .collect();
        json!({"fetchTime": fetch_time, "numberOfChanges": rows.len(),
               "new": if kind == "new" { rows.clone() } else { vec![] },
               "updated": if kind == "updated" { rows } else { vec![] }, "error": []})
    }

    /// Serves a deltaLog with Range support, raw records and release zips.
    struct FakeRaw {
        log: Vec<u8>,
        records: Mutex<HashMap<String, Value>>,
        zips: HashMap<String, Vec<u8>>,
        etag: String,
        calls: Mutex<Vec<String>>,
    }

    impl FakeRaw {
        fn new(log: Vec<u8>, records: Vec<(&str, Value)>, zips: HashMap<String, Vec<u8>>) -> Self {
            Self {
                log,
                records: Mutex::new(records.into_iter().map(|(k, v)| (k.to_string(), v)).collect()),
                zips,
                etag: "\"v1\"".into(),
                calls: Mutex::new(vec![]),
            }
        }

        fn get(&self, url: &str, label: &str, o: GetOpts) -> Result<Response, SourceError> {
            self.calls.lock().unwrap().push(url.to_string());
            let not_found = || Err(SourceError { message: format!("{label}: HTTP 404"), status: Some(404) });
            if url == DELTA_URL {
                assert_eq!(o.headers, &[("Accept-Encoding", "identity")]);
                let (a, b) = o.byte_range.unwrap();
                let (a, b) = ((a as usize).min(self.log.len()), ((b + 1) as usize).min(self.log.len()));
                return Ok(resp(&self.log[a..b], 206, &[("ETag", &self.etag)], url, false));
            }
            if let Some(rest) = url.strip_prefix("https://raw.test/") {
                let cid = &rest[..rest.len() - 5];
                return match self.records.lock().unwrap().get(cid) {
                    Some(r) => Ok(ok_json(r)),
                    None => not_found(),
                };
            }
            match self.zips.get(url) {
                Some(z) => Ok(resp(z.clone(), 200, &[], url, false)),
                None => not_found(),
            }
        }

        fn called(&self, url: &str) -> usize {
            self.calls.lock().unwrap().iter().filter(|u| *u == url).count()
        }
    }

    fn ids(items: &[Item]) -> Vec<&str> {
        items.iter().map(|i| i.id.as_str()).collect()
    }

    fn utc(s: &str) -> DateTime<Utc> {
        parse_iso(s).unwrap()
    }

    // ------------------------------------------------------------ parsing

    #[test]
    fn delta_prefix_truncated() {
        let entries = parse_delta_prefix(&fixture("cvelist_delta_prefix.bin")).unwrap();
        assert!(entries.len() >= 3);
        assert_eq!(entries[0]["fetchTime"], "2026-11-03T02:36:31.191Z");
        assert_eq!(entries[0]["new"][0]["cveId"], "CVE-2026-111464");
        let links = changed_links(&entries);
        assert!(links.contains_key("CVE-2026-6324")); // from updated[]
    }

    #[test]
    fn cna_record() {
        let i = parse_record(&fixture_json("cve_record_cna.json")).unwrap().unwrap();
        assert_eq!(i.id, "CVE-2026-105770");
        assert_eq!(i.published, "2026-11-03T00:41:24Z");
        assert_eq!((i.score, i.severity.as_str()), (5.3, "MEDIUM"));
        assert_eq!(i.x("score_source"), "CNA");
        assert_eq!((i.x("av"), i.x("pr")), ("network", "none"));
        assert_eq!(i.x("assigner"), "chainguard");
        assert_eq!(i.extra["vendors"], json!(["octo-sts"]));
        assert_eq!(i.url, "https://www.cve.org/CVERecord?id=CVE-2026-105770");
        assert!(i.title.chars().count() <= DESC_MAX);
    }

    #[test]
    fn adp_record() {
        let i = parse_record(&fixture_json("cve_record_adp.json")).unwrap().unwrap();
        assert_eq!((i.score, i.severity.as_str()), (8.1, "HIGH"));
        assert_eq!(i.x("score_source"), "CISA-ADP");
        assert_eq!(i.x("ssvc_exploitation"), "poc");
        assert_eq!(i.x("pr"), "low");
    }

    #[test]
    fn cvss_preference_and_words() {
        let m = json!([{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/PR:N"}},
                       {"cvssV4_0": {"baseScore": 9.3, "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/AV:L/PR:H"}}]);
        assert_eq!(cvss(m.as_array().unwrap()), Some((9.3, "CRITICAL".into(), "CVSS:4.0/AV:L/PR:H".into())));
        let none = json!([{"cvssV4_0": {"baseScore": 0.0, "baseSeverity": "NONE"}}]);
        assert_eq!(cvss(none.as_array().unwrap()).unwrap().1, "");
        let i = parse_record(&make_record("CVE-2026-1", "2026-11-01T00:00:00.000Z", "PUBLISHED",
            json!([{"other": {"type": "Red Hat severity rating", "content": {"value": "Important"}}}]))).unwrap().unwrap();
        assert_eq!((i.score, i.severity.as_str(), i.x("score_source")), (0.0, "HIGH", "CNA"));
        assert_eq!(i.extra["vendors"], json!(["Acme"])); // "n/a" dropped
        assert_eq!(vector_bits("CVSS:4.0/AV:N/AC:L/AT:N/PR:L"), ("network", "low"));
    }

    #[test]
    fn rejected_and_window() {
        let mut store: Store = json!({"CVE-2026-2": {"published": "2026-11-01T00:00:00Z"}}).as_object().unwrap().clone();
        apply(&mut store, &rejected("CVE-2026-2", "2026-11-01T00:00:00Z"), start()).unwrap();
        assert!(!store.contains_key("CVE-2026-2"));
        apply(&mut store, &rec("CVE-2025-9", "2025-01-01T00:00:00Z"), start()).unwrap();
        assert!(!store.contains_key("CVE-2025-9"));
        apply(&mut store, &rec("CVE-2026-3", "2026-11-02T10:00:00.123Z"), start()).unwrap();
        assert_eq!(store["CVE-2026-3"]["published"], "2026-11-02T10:00:00Z");
    }

    #[test]
    fn near_midnight_slots() {
        assert!(near_midnight(utc("2026-11-03T00:06:24")));
        assert!(near_midnight(utc("2026-11-02T23:50:00")));
        assert!(!near_midnight(utc("2026-11-03T00:50:00")));
        assert!(!near_midnight(utc("2026-11-02T23:40:00")));
    }

    #[test]
    fn zip_records_and_refusal() {
        let z = make_zip(&[rec("CVE-2026-4", "2026-11-01T00:00:00Z")]);
        let got = zip_records(&z).unwrap();
        assert_eq!(got.iter().map(|r| r["cveMetadata"]["cveId"].as_str().unwrap()).collect::<Vec<_>>(), ["CVE-2026-4"]);
        assert!(zip_records(b"not a zip").is_err());
        let never = |_: &str, _: &str, _: GetOpts| -> Result<Response, SourceError> { panic!("must not download") };
        let e = release_zip(&never, &mut Cost::default(), "cve_2026-11-03_0200Z", "2026-11-03_all_CVEs_at_midnight.zip.zip").unwrap_err();
        assert!(e.message.contains("refusing to download"), "{e}");
    }

    // ------------------------------------------------------------ fetch

    #[test]
    fn read_delta_needs_several_chunks() {
        let _t = state::testing::temp_state("cvelist-chunks");
        let log = delta_log(&(1..=59).rev()
            .map(|m| entry(&format!("2026-11-03T02:{m:02}:00.000Z"), &[&format!("CVE-2026-{m}")], "new"))
            .collect::<Vec<_>>());
        let fake = FakeRaw::new(log, vec![], HashMap::new());
        let get = |u: &str, l: &str, o: GetOpts| fake.get(u, l, o);
        let (newer, reached) = read_delta(&get, &mut Cost::default(), utc("2026-11-03T02:10:00Z"), 1024, MAX_DELTA).unwrap();
        assert!(reached);
        assert_eq!(newer.len(), 49);
        assert_eq!(newer.last().unwrap()["fetchTime"], "2026-11-03T02:11:00.000Z");
        assert!(fake.called(DELTA_URL) > 1);
    }

    #[test]
    fn steady_state_delta() {
        let _t = state::testing::temp_state("cvelist-delta");
        state::save_json(CURSOR, &json!({"fetch_time": "2026-11-03T02:00:00.000Z"}));
        let r10 = parse_record(&rec("CVE-2026-10", "2026-10-30T00:00:00Z")).unwrap().unwrap();
        state::save_json(STORE, &json!({
            "CVE-2026-10": r10,
            "CVE-2026-11": {"published": "2026-10-20T00:00:00Z"},     // fell out of the window
        }));
        let log = delta_log(&[
            entry("2026-11-03T02:40:00.000Z", &["CVE-2026-12", "CVE-2026-13"], "new"),
            entry("2026-11-03T02:20:00.000Z", &["CVE-2026-10"], "updated"),
            entry("2026-11-03T02:00:00.000Z", &["CVE-2026-99"], "new"), // already processed
        ]);
        let fake = FakeRaw::new(log, vec![
            ("CVE-2026-12", rec("CVE-2026-12", "2026-11-03T02:35:00Z")),
            ("CVE-2026-10", rejected("CVE-2026-10", "2026-10-30T00:00:00Z")),
        ], HashMap::new()); // CVE-2026-13 -> 404
        let get = |u: &str, l: &str, o: GetOpts| fake.get(u, l, o);
        let out = fetch_with(start(), end(), &get).unwrap();
        assert_eq!(ids(&out.items), ["CVE-2026-12"]);
        assert_eq!(fake.called("https://raw.test/CVE-2026-99.json"), 0);
        let cur: Value = state::load_json(CURSOR).unwrap();
        assert_eq!(cur["fetch_time"], "2026-11-03T02:40:00.000Z");
        assert_eq!(cur["retry"], json!({"CVE-2026-13": ["https://raw.test/CVE-2026-13.json", 1]}));
        assert_eq!(out.stats["mode"], "delta");
        assert_eq!(cur["stats"]["mode"], "delta");

        // Next run: nothing new in the log, the 404 record is retried and now exists.
        fake.records.lock().unwrap().insert("CVE-2026-13".into(), rec("CVE-2026-13", "2026-11-03T02:39:00Z"));
        let out = fetch_with(start(), end(), &get).unwrap();
        assert_eq!(ids(&out.items), ["CVE-2026-13", "CVE-2026-12"]);
        let cur: Value = state::load_json(CURSOR).unwrap();
        assert_eq!(cur["fetch_time"], "2026-11-03T02:40:00.000Z");
        assert_eq!(cur["retry"], json!({}));
    }

    #[test]
    fn backfill_first_run() {
        let _t = state::testing::temp_state("cvelist-backfill");
        let base = "https://github.com/CVEProject/cvelistV5/releases/download/";
        let mut zips = HashMap::new();
        for d in 27..32 {
            let ds = format!("2026-10-{d}");
            zips.insert(format!("{base}cve_{ds}_at_end_of_day/{ds}_delta_CVEs_at_end_of_day.zip"),
                        make_zip(&[rec(&format!("CVE-2026-{d}"), &format!("{ds}T12:00:00Z"))]));
        }
        zips.insert(format!("{base}cve_2026-11-01_at_end_of_day/2026-11-01_delta_CVEs_at_end_of_day.zip"),
                    make_zip(&[rejected("CVE-2026-27", "2026-10-27T12:00:00Z")]));
        // 2026-11-02: end-of-day zip not published yet, fall back to its 2300Z hourly
        zips.insert(format!("{base}cve_2026-11-02_2300Z/2026-11-02_delta_CVEs_at_2300Z.zip"),
                    make_zip(&[rec("CVE-2026-102", "2026-11-02T22:00:00Z")]));
        // today 03:00 -> 0300Z missing, 0200Z exists
        zips.insert(format!("{base}cve_2026-11-03_0200Z/2026-11-03_delta_CVEs_at_0200Z.zip"),
                    make_zip(&[rec("CVE-2026-103", "2026-11-03T01:00:00Z"), rec("CVE-2025-1", "2025-01-01T00:00:00Z")]));
        let log = delta_log(&[
            entry("2026-11-03T02:50:00.000Z", &["CVE-2026-104"], "new"),
            entry("2026-11-03T01:30:00.000Z", &["CVE-2026-103"], "updated"),
            entry("2026-11-01T12:00:00.000Z", &["CVE-2026-29"], "updated"),
            entry("2026-11-01T00:06:24.148Z", &["CVE-2026-900"], "new"), // in neither zip
            entry("2026-10-26T12:00:00.000Z", &["CVE-2026-1"], "new"),
        ]);
        let fake = FakeRaw::new(log, vec![
            ("CVE-2026-104", rec("CVE-2026-104", "2026-11-03T02:45:00Z")),
            ("CVE-2026-103", rec("CVE-2026-103", "2026-11-03T01:00:00Z")),
            ("CVE-2026-900", rec("CVE-2026-900", "2026-10-31T23:58:00Z")),
        ], zips);
        let get = |u: &str, l: &str, o: GetOpts| fake.get(u, l, o);
        let out = fetch_with(start(), end(), &get).unwrap();
        assert_eq!(ids(&out.items), ["CVE-2026-104", "CVE-2026-103", "CVE-2026-102", "CVE-2026-900", "CVE-2026-31",
                                     "CVE-2026-30", "CVE-2026-29", "CVE-2026-28"]); // 27 rejected later, 2025-1 outside
        assert_eq!(out.stats["mode"], "backfill");
        assert_eq!(out.stats["midnight_entries"], 1);
        assert_eq!(out.stats["log_reaches_start"], true);
        // Catch-up starts 15 min before the 0200Z snapshot, so the 01:30 entry is not re-read,
        // and a midday entry covered by a zip is not replayed either.
        assert_eq!(fake.called("https://raw.test/CVE-2026-103.json"), 0);
        assert_eq!(fake.called("https://raw.test/CVE-2026-29.json"), 0);
        assert!(!fake.calls.lock().unwrap().iter().any(|u| u.contains("_all_CVEs_")));
        let cur: Value = state::load_json(CURSOR).unwrap();
        assert_eq!(cur["fetch_time"], "2026-11-03T02:50:00.000Z");
    }

    /// Live, against a copy of state/: EW_STATE_COPY=<dir> cargo test -- --ignored live_state_copy --nocapture
    #[test]
    #[ignore]
    fn live_state_copy_cvelist() {
        let _g = state::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        state::set_dir(std::env::var("EW_STATE_COPY").expect("EW_STATE_COPY"));
        let end = Utc::now();
        let out = fetch(end - Duration::days(7), end).unwrap();
        println!("LIVE cvelist items={} stats={}", out.items.len(), Value::Object(out.stats));
    }
}
