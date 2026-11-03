//! CERT-EU security advisories.
//!
//! The RSS lists the latest 10 advisories, ordered by latest revision. Its pubDate
//! carries a zone *label* ("CEST", "CET") that an RFC 2822 parser does not know, so
//! the exact time comes from the per-advisory JSON, whose publish_date is UTC
//! without a marker (checked 2026-11-03: RSS 16:36:26 CEST == JSON 14:36:26 on all
//! 10 items). The JSON is fetched only when a serial is new or its pubDate changed;
//! the result is kept in cursors/certeu.json (shape: see Rec).
//!
//! The RSS sends no ETag/Last-Modified and answers If-Modified-Since with 200, so
//! it is fetched unconditionally (~10 KB). The site sits behind an Azure
//! Application Gateway that answers 403 to a request without our User-Agent;
//! common::get() always sends it.

use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::common::{self, FetchOutput, GetOpts, Item, Response, SourceError, iso_utc};
use super::state;

pub const NAME: &str = "CERT-EU";
pub const CADENCE: u64 = 0;

pub const RSS: &str = "https://cert.europa.eu/publications/security-advisories-rss";
const PAGE_BASE: &str = "https://cert.europa.eu/publications/security-advisories/";
pub const CURSOR: &str = "cursors/certeu.json";

/// Zone labels seen in the feed. Only used to pre-filter and as a fallback when
/// the JSON is unavailable; GMT/UT/UTC/Z and +hhmm are handled by the parser.
const ZONES: &[(&str, &str)] = &[("CEST", "+0200"), ("CET", "+0100")];

static SERIAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)^(\d{4}-\d{3,})\s*:\s*(.*)$").unwrap());
static CVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"CVE-\d{4}-\d{4,}").unwrap());
static FRONT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)\A\s*---[ \t]*\n(.*?)\n---").unwrap());
static V1: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d{2})/(\d{2})/(\d{4})\s*-+\s*v1\.0\b").unwrap());
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").unwrap());

/// Advisory page, e.g. https://cert.europa.eu/publications/security-advisories/2026-018/
pub fn page(serial: &str) -> String {
    format!("{PAGE_BASE}{serial}/")
}

/// Per-advisory JSON (page URL + "json").
pub fn json_url(serial: &str) -> String {
    format!("{PAGE_BASE}{serial}/json")
}

/// The pluggable GET, so tests can serve fixtures. Production passes common::get.
pub type Getter<'a> = dyn FnMut(&str, &str, GetOpts) -> Result<Response, SourceError> + 'a;

// ---------------------------------------------------------------- text helpers

/// Whitespace: Unicode White_Space plus the ASCII separators \x1c..\x1f.
fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// Runs of whitespace collapsed to one space, trimmed at both ends.
fn squash(s: &str) -> String {
    s.split(is_space).filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ")
}

/// s without leading and trailing whitespace (see is_space).
fn strip_space(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// Lines of s split at any line boundary (\n, \r\n, \r, \x0b, \x0c, \x1c-\x1e, NEL, LS, PS), without the breaks.
fn split_lines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}') {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' && it.peek().map(|&(_, n)| n) == Some('\n') {
                it.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// s in single quotes with backslash escapes (double quotes when s holds only a single quote), for error messages.
fn quoted(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::from(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || (0x7f..=0xa0).contains(&(c as u32)) => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

// ---------------------------------------------------------------- parsing

/// One RSS entry: the first (latest) item per serial.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    pub serial: String,
    pub title: String,
    pub url: String,
    pub pubdate: String,
}

/// One advisory as kept in cursors/certeu.json. Field order and names are part of
/// the stored format: id, url, title, published, updated, cves, extra, [fallback], pubdate.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Rec {
    pub id: String,
    pub url: String,
    pub title: String,
    pub published: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub extra: Map<String, Value>,
    /// Built from the RSS because the JSON failed; never trusted as a cache hit.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fallback: bool,
    /// RSS pubDate the record was built for (set by fetch, absent from parse output).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubdate: Option<String>,
}

impl Rec {
    fn to_item(&self) -> Item {
        let mut i = Item::new(NAME, &self.id, &self.url, &self.title, &self.published);
        i.updated = self.updated.clone();
        i.cves = self.cves.clone();
        i.extra = self.extra.clone();
        i
    }
}

/// RFC 2822 date with numeric or GMT/UT/UTC/Z zone
/// (a leading day name is dropped and not checked; "-0000" means "no zone" and gives None).
fn parse_rfc2822(s: &str) -> Option<DateTime<Utc>> {
    let mut words: Vec<&str> = s.split_whitespace().collect();
    let first = words.first()?;
    let days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    if first.ends_with(',') || days.contains(&first.to_lowercase().as_str()) {
        words.remove(0);
    }
    let zone = *words.last()?;
    if zone == "-0000" {
        return None;
    }
    if ["GMT", "UT", "UTC", "Z"].contains(&zone.to_uppercase().as_str()) {
        *words.last_mut()? = "+0000";
    }
    DateTime::parse_from_rfc2822(&words.join(" ")).ok().map(|d| d.with_timezone(&Utc))
}

/// "Fri, 23 Oct 2026 16:36:26 CEST" -> UTC time. None if the zone label is unknown.
pub fn parse_pubdate(s: &str) -> Option<DateTime<Utc>> {
    let s = strip_space(s);
    let (head, zone) = match s.rfind(' ') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => ("", s),
    };
    if let Some((_, off)) = ZONES.iter().find(|(z, _)| *z == zone) {
        return parse_rfc2822(&format!("{head} {off}"));
    }
    if !zone.is_empty() && zone.chars().all(char::is_alphabetic) && !["GMT", "UT", "UTC", "Z"].contains(&zone) {
        return None;
    }
    parse_rfc2822(s)
}

/// Text of the first direct child `name` (no namespace),
/// up to its first child element. None when there is no such child.
fn findtext(node: roxmltree::Node, name: &str) -> Option<String> {
    let child = node.children().find(|c| c.is_element() && c.tag_name().name() == name && c.tag_name().namespace().is_none())?;
    let mut out = String::new();
    for n in child.children() {
        if n.is_element() {
            break;
        }
        if let Some(t) = n.text().filter(|_| n.is_text()) {
            out.push_str(t);
        }
    }
    Some(out)
}

/// RSS bytes -> entries in feed order, one per serial.
pub fn parse_rss(content: &[u8]) -> Result<Vec<Entry>, SourceError> {
    let bad = |e: &dyn std::fmt::Display| SourceError::new(format!("{NAME}: RSS is not valid XML: {e}"));
    let text = std::str::from_utf8(content).map_err(|e| bad(&e))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let opts = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(text, opts).map_err(|e| bad(&e))?;
    let mut out: Vec<Entry> = Vec::new();
    let mut seen = BTreeSet::new();
    for it in doc.descendants().filter(|n| n.is_element() && n.tag_name().name() == "item" && n.tag_name().namespace().is_none()) {
        let title = findtext(it, "title").unwrap_or_default();
        let Some(m) = SERIAL.captures(strip_space(&title)) else {
            continue; // not an advisory title like "2026-018: …"
        };
        let serial = m[1].to_string();
        if !seen.insert(serial.clone()) {
            continue; // feed is ordered by latest revision: the first entry wins
        }
        let link = findtext(it, "link").unwrap_or_default();
        let link = strip_space(&link);
        out.push(Entry {
            title: squash(&m[2]),
            url: if link.is_empty() { page(&serial) } else { link.to_string() },
            pubdate: strip_space(&findtext(it, "pubDate").unwrap_or_default()).to_string(),
            serial,
        });
    }
    Ok(out)
}

/// YAML-ish header of content_markdown -> map. Values may or may not be quoted.
pub fn front_matter(md: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(m) = FRONT.captures(md) {
        for line in split_lines(&m[1]) {
            if let Some((k, v)) = line.split_once(':') {
                out.insert(strip_space(k).to_string(), strip_space(v).trim_matches(['\'', '"']).to_string());
            }
        }
    }
    out
}

/// Date of v1.0 from the History list ("* _20/10/2026 --- v1.0 -- …", underscores optional).
pub fn first_release_date(md: &str, fm: &HashMap<String, String>) -> String {
    if let Some(m) = V1.captures(md) {
        return format!("{}-{}-{}", &m[3], &m[2], &m[1]);
    }
    // front-matter `date` matched v1.0 on 9 of 10 advisories checked; original_date
    // is the vendor's disclosure date, not CERT-EU's, so it is not used.
    fm.get("date").cloned().unwrap_or_default()
}

/// j[key] as a string; Err is the quoted key ("'serial_number'") when it is missing.
fn key_str(j: &Value, key: &str) -> Result<String, String> {
    match j.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        Some(other) => Err(format!("{key} is not a string: {other}")),
        None => Err(quoted(key)),
    }
}

/// Advisory JSON -> record. prev is the cached record for the same serial: when it
/// holds an exact v1.0 time, that stays the published time after revisions.
/// Err is a one-line reason (missing key, bad date).
pub fn parse_advisory(j: &Value, prev: Option<&Rec>) -> Result<Rec, String> {
    let serial = key_str(j, "serial_number")?;
    let md = j.get("content_markdown").and_then(Value::as_str).unwrap_or("");
    let fm = front_matter(md);
    let version = fm.get("version").cloned().unwrap_or_default();
    let pd = key_str(j, "publish_date")?;
    let latest = NaiveDateTime::parse_from_str(&pd, "%d-%m-%Y %H:%M:%S")
        .map_err(|_| format!("time data {} does not match format '%d-%m-%Y %H:%M:%S'", quoted(&pd)))?;
    let latest = iso_utc(latest.and_utc());
    let (published, updated) = if ["", "1", "1.0"].contains(&version.as_str()) {
        (latest, String::new())
    } else {
        let exact_v1 = prev.is_some_and(|p| !p.fallback && p.updated.is_empty() && p.published.contains('T'));
        let published = if exact_v1 { prev.unwrap().published.clone() } else { first_release_date(md, &fm) };
        (published, latest)
    };
    let summary = TAG.replace_all(j.get("description").and_then(Value::as_str).unwrap_or(""), " ");
    let cves: BTreeSet<&str> = CVE.find_iter(md).map(|m| m.as_str()).collect();
    let mut extra = Map::new();
    extra.insert("version".into(), Value::String(version));
    extra.insert("summary".into(), Value::String(squash(&summary)));
    Ok(Rec {
        url: page(&serial),
        id: serial,
        title: squash(j.get("title").and_then(Value::as_str).unwrap_or("")),
        published,
        updated,
        cves: cves.into_iter().map(String::from).collect(),
        extra,
        fallback: false,
        pubdate: None,
    })
}

/// Fallback record when the JSON is unavailable: RSS time via the zone map, no CVEs.
pub fn from_rss(e: &Entry) -> Result<Rec, SourceError> {
    let dt = parse_pubdate(&e.pubdate).ok_or_else(|| {
        SourceError::new(format!(
            "{NAME}: {} JSON unavailable and pubDate {} has an unknown zone; add it to ZONES",
            e.serial,
            quoted(&e.pubdate)
        ))
    })?;
    let mut extra = Map::new();
    extra.insert("version".into(), Value::String(String::new()));
    extra.insert("summary".into(), Value::String(String::new()));
    Ok(Rec {
        id: e.serial.clone(),
        url: page(&e.serial),
        title: e.title.clone(),
        published: iso_utc(dt),
        updated: String::new(),
        cves: vec![],
        extra,
        fallback: true,
        pubdate: None,
    })
}

/// ts is ISO UTC or a bare date; a bare date counts if the day overlaps the window.
pub fn in_window(ts: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
    if ts.is_empty() {
        return false;
    }
    if !ts.contains('T') {
        let (d0, d1) = (start.date_naive().to_string(), end.date_naive().to_string());
        return d0.as_str() <= ts && ts <= d1.as_str();
    }
    iso_utc(start).as_str() <= ts && ts <= iso_utc(end).as_str()
}

// ---------------------------------------------------------------- fetch

pub fn fetch(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    fetch_with(start, end, &mut common::get)
}

pub fn fetch_with(start: DateTime<Utc>, end: DateTime<Utc>, get: &mut Getter) -> Result<FetchOutput, SourceError> {
    let rss = get(RSS, &format!("{NAME} RSS"), GetOpts { conditional: false, ..Default::default() })?;
    let entries = parse_rss(&rss.content)?;
    if entries.is_empty() {
        return Err(SourceError::new(format!("{NAME}: RSS has no advisory items; the feed format may have changed")));
    }

    let cache: Map<String, Value> = state::load_json(CURSOR).unwrap_or_default();
    let mut keep = Map::new();
    let mut items = Vec::new();
    for e in &entries {
        // An unreadable cached record counts as a miss.
        let cached: Option<Rec> = cache.get(&e.serial).and_then(|v| serde_json::from_value(v.clone()).ok());
        let rec = match cached {
            Some(r) if r.pubdate.as_deref() == Some(e.pubdate.as_str()) && !r.fallback => r,
            prev => {
                // pubDate is the latest revision time, so an advisory last touched more
                // than a day (zone slack) before the window cannot be in it: skip the JSON.
                if parse_pubdate(&e.pubdate).is_some_and(|approx| approx < start - Duration::days(1)) {
                    continue;
                }
                let label = format!("{NAME} {} JSON", e.serial);
                let parsed = get(&json_url(&e.serial), &label, GetOpts { conditional: false, ..Default::default() })
                    .map_err(|err| err.message)
                    .and_then(|r| {
                        let body = r.content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&r.content);
                        serde_json::from_slice::<Value>(body).map_err(|err| err.to_string())
                    })
                    .and_then(|j| parse_advisory(&j, prev.as_ref()));
                let mut rec = match parsed {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!("  note: {NAME} {}: JSON failed ({err}); using RSS pubDate", e.serial);
                        from_rss(e)?
                    }
                };
                rec.pubdate = Some(e.pubdate.clone());
                rec
            }
        };
        keep.insert(e.serial.clone(), serde_json::to_value(&rec).expect("record serialises"));
        if in_window(&rec.published, start, end) || in_window(&rec.updated, start, end) {
            items.push(rec.to_item());
        }
    }

    // Only serials still in the RSS are kept, so the cursor stays at ~10 entries.
    state::save_json(CURSOR, &keep);
    sort_newest_first(&mut items);
    Ok(items.into())
}

/// Newest first by updated-or-published; stable, so ties keep their order.
fn sort_newest_first(items: &mut [Item]) {
    let key = |i: &Item| if i.updated.is_empty() { i.published.clone() } else { i.updated.clone() };
    items.sort_by(|a, b| key(b).cmp(&key(a)));
}

// ---------------------------------------------------------------- tests

/// Test seam shared by the certeu and ncscnl tests: a fake GET that serves
/// fixtures by URL and records the calls.
#[cfg(test)]
pub(crate) mod fake {
    use std::collections::HashMap;
    use std::path::Path;

    use chrono::{DateTime, TimeZone, Utc};
    use reqwest::header::HeaderMap;

    use crate::feeds::common::{GetOpts, Response, SourceError};

    pub fn fixture(name: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    pub fn utc(y: i32, mo: u32, d: u32, h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, 0, 0).unwrap()
    }

    /// url -> body, or the error to return. Unknown URLs answer "<label>: HTTP 404".
    #[derive(Default)]
    pub struct FakeGet {
        pub routes: HashMap<String, Result<Vec<u8>, SourceError>>,
        pub calls: Vec<String>,
        /// conditional flag of each call, in call order
        pub conditional: Vec<bool>,
    }

    impl FakeGet {
        pub fn new<I: IntoIterator<Item = (String, Result<Vec<u8>, SourceError>)>>(routes: I) -> Self {
            Self { routes: routes.into_iter().collect(), ..Default::default() }
        }

        pub fn route(&mut self, url: &str, body: Result<Vec<u8>, SourceError>) {
            self.routes.insert(url.to_string(), body);
        }

        pub fn call(&mut self, url: &str, label: &str, opts: GetOpts) -> Result<Response, SourceError> {
            self.calls.push(url.to_string());
            self.conditional.push(opts.conditional);
            match self.routes.get(url) {
                None => Err(SourceError::new(format!("{label}: HTTP 404"))),
                Some(Err(e)) => Err(e.clone()),
                Some(Ok(body)) => Ok(Response {
                    status: 200,
                    content: body.clone(),
                    headers: HeaderMap::new(),
                    url: url.to_string(),
                    from_cache: false,
                }),
            }
        }

        pub fn clear(&mut self) {
            self.calls.clear();
            self.conditional.clear();
        }
    }

    type FetchWith = fn(
        DateTime<Utc>,
        DateTime<Utc>,
        &mut dyn FnMut(&str, &str, GetOpts) -> Result<Response, SourceError>,
    ) -> Result<crate::feeds::common::FetchOutput, SourceError>;

    /// Live run against a COPY of state/ ($EW_STATE_COPY), twice, with the real
    /// common::get; window = $EW_END (default now) minus 7 days. Each request is
    /// logged (status, from_cache, bytes) and the result is written to
    /// $EW_STATE_COPY/../live_<tag>.json. No-op when EW_STATE_COPY is unset.
    pub fn live_twice(tag: &str, f: FetchWith) {
        use crate::feeds::{common, state};
        use serde_json::json;
        let Some(dir) = std::env::var_os("EW_STATE_COPY") else {
            eprintln!("EW_STATE_COPY not set; skipped");
            return;
        };
        let _g = state::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        state::set_dir(&dir);
        let end = std::env::var("EW_END").ok().and_then(|s| common::parse_iso(&s)).unwrap_or_else(Utc::now);
        let start = end - chrono::Duration::days(7);
        let mut runs = Vec::new();
        for n in 1..=2 {
            let mut log = Vec::new();
            let t0 = std::time::Instant::now();
            let res = f(start, end, &mut |u: &str, l: &str, o: GetOpts| {
                let r = common::get(u, l, o);
                log.push(match &r {
                    Ok(r) => json!({"url": u, "status": r.status, "from_cache": r.from_cache, "bytes": r.content.len()}),
                    Err(e) => json!({"url": u, "error": e.message}),
                });
                r
            });
            let secs = t0.elapsed().as_secs_f64();
            let (items, err) = match res {
                Ok(o) => (json!(o.items), None),
                Err(e) => (json!(null), Some(e.message)),
            };
            eprintln!("{tag} run {n}: {:.2}s, {} requests, items={}, error={:?}", secs, log.len(),
                      items.as_array().map_or(0, |a| a.len()), err);
            runs.push(json!({"run": n, "secs": secs, "requests": log, "items": items, "error": err}));
        }
        let out = Path::new(&dir).parent().unwrap().join(format!("live_{tag}.json"));
        let v = json!({"start": crate::feeds::common::iso_utc(start), "end": crate::feeds::common::iso_utc(end), "runs": runs});
        std::fs::write(&out, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        eprintln!("wrote {}", out.display());
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{FakeGet, fixture, utc};
    use super::*;
    use chrono::TimeZone;

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    fn advisory(name: &str) -> Value {
        serde_json::from_slice(&fixture(name)).unwrap()
    }

    // ------------------------------------------------ parse

    #[test]
    fn pubdate_zone_labels() {
        // "CEST" is unknown to an RFC 2822 parser, which would read it as UTC (2 h off).
        assert_eq!(parse_pubdate("Fri, 23 Oct 2026 16:36:26 CEST"), Some(at(2026, 10, 23, 14, 36, 26)));
        assert_eq!(parse_pubdate("Mon, 02 Mar 2026 18:00:00 CET"), Some(at(2026, 3, 2, 17, 0, 0)));
        assert_eq!(parse_pubdate("Mon, 02 Nov 2026 09:17:50 +0000"), Some(at(2026, 11, 2, 9, 17, 50)));
        assert_eq!(parse_pubdate("Mon, 02 Nov 2026 09:17:50 GMT"), Some(at(2026, 11, 2, 9, 17, 50)));
        assert_eq!(parse_pubdate("Mon, 02 Nov 2026 09:17:50 EEST"), None);
        assert_eq!(parse_pubdate(""), None);
    }

    #[test]
    fn rss() {
        let e = parse_rss(&fixture("certeu_rss.xml")).unwrap();
        assert_eq!(e.iter().map(|x| x.serial.as_str()).collect::<Vec<_>>(), ["2026-018", "2026-019", "2026-017"]);
        assert_eq!(e[0].title, "Critical Vulnerabilities in PHP");
        assert_eq!(e[0].url, "https://cert.europa.eu/publications/security-advisories/2026-018/");
        assert_eq!(e[0].pubdate, "Fri, 23 Oct 2026 16:36:26 CEST");
    }

    #[test]
    fn rss_dedup_keeps_first() {
        let xml = br#"<rss><channel>
          <item><title>2026-018: New title</title><pubDate>Fri, 23 Oct 2026 16:36:26 CEST</pubDate></item>
          <item><title>2026-018: Old title</title><pubDate>Tue, 20 Oct 2026 10:00:00 CEST</pubDate></item>
          <item><title>Not an advisory</title></item>
        </channel></rss>"#;
        let e = parse_rss(xml).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].title, "New title");
    }

    #[test]
    fn rss_bad_xml() {
        let err = parse_rss(b"<html>maintenance").unwrap_err();
        assert!(err.message.starts_with("CERT-EU: RSS is not valid XML"), "{err}");
    }

    #[test]
    fn front_matter_quoted_and_bare() {
        let fm = front_matter("---    \ntitle: 'A: B'\nversion: '1.2'\ndate: 2026-09-09\n---\nbody");
        let want: HashMap<String, String> =
            [("title", "A: B"), ("version", "1.2"), ("date", "2026-09-09")].map(|(k, v)| (k.into(), v.into())).into();
        assert_eq!(fm, want);
        let none = HashMap::new();
        assert_eq!(first_release_date("* 09/09/2026 --- v1.0 -- Initial publication.", &none), "2026-09-09");
        assert_eq!(first_release_date("* _20/10/2026 --- v1.0 -- Initial_", &none), "2026-10-20");
        let fm = HashMap::from([("date".to_string(), "2026-10-21".to_string())]);
        assert_eq!(first_release_date("no history", &fm), "2026-10-21");
    }

    #[test]
    fn advisory_revised() {
        let r = parse_advisory(&advisory("certeu_2026-018.json"), None).unwrap();
        assert_eq!(r.id, "2026-018");
        assert_eq!(r.url, "https://cert.europa.eu/publications/security-advisories/2026-018/");
        assert_eq!(r.published, "2026-10-20"); // v1.0 date from History
        assert_eq!(r.updated, "2026-10-23T14:36:26Z"); // publish_date is UTC
        assert_eq!(r.extra["version"], "1.2");
        assert_eq!(r.cves, ["CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"]);
        assert!(!r.extra["summary"].as_str().unwrap().contains("<br>"));
    }

    #[test]
    fn advisory_first_version() {
        let r = parse_advisory(&advisory("certeu_2026-019.json"), None).unwrap();
        assert_eq!((r.published.as_str(), r.updated.as_str()), ("2026-10-22T09:14:22Z", ""));
        assert_eq!(r.cves, ["CVE-2026-110264"]);
    }

    #[test]
    fn revision_keeps_exact_v1_time() {
        let prev = Rec { published: "2026-10-20T08:00:00Z".into(), ..Default::default() };
        let r = parse_advisory(&advisory("certeu_2026-018.json"), Some(&prev)).unwrap();
        assert_eq!(r.published, "2026-10-20T08:00:00Z");
    }

    // ------------------------------------------------ fetch

    fn window() -> (DateTime<Utc>, DateTime<Utc>) {
        (utc(2026, 10, 21, 0), utc(2026, 10, 28, 0))
    }

    fn routes() -> FakeGet {
        FakeGet::new([
            (RSS.to_string(), Ok(fixture("certeu_rss.xml"))),
            (json_url("2026-018"), Ok(fixture("certeu_2026-018.json"))),
            (json_url("2026-019"), Ok(fixture("certeu_2026-019.json"))),
        ])
    }

    fn run(fake: &mut FakeGet) -> Result<Vec<Item>, SourceError> {
        let (s, e) = window();
        fetch_with(s, e, &mut |u: &str, l: &str, o: GetOpts| fake.call(u, l, o)).map(|o| o.items)
    }

    #[test]
    fn window_and_cache() {
        let _t = state::testing::temp_state("certeu-cache");
        let mut fake = routes();
        let items = run(&mut fake).unwrap();
        assert_eq!(items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["2026-018", "2026-019"]);
        assert!(items.iter().all(|i| i.source == "CERT-EU"));
        // 2026-017 (15 Oct) is older than the window: its JSON is never requested.
        assert_eq!(fake.calls.len(), 3);
        assert!(fake.conditional.iter().all(|c| !c), "RSS and JSON are fetched unconditionally");
        fake.clear();
        let again = run(&mut fake).unwrap();
        assert_eq!(again, items);
        assert_eq!(fake.calls, [RSS]); // run 2: cache hits only
    }

    #[test]
    fn json_failure_falls_back_to_rss_time() {
        let _t = state::testing::temp_state("certeu-fallback");
        let url = json_url("2026-019");
        let mut fake = routes();
        fake.route(&url, Err(SourceError::new("CERT-EU 2026-019 JSON: HTTP 503")));
        let items = run(&mut fake).unwrap();
        let i = items.iter().find(|i| i.id == "2026-019").unwrap();
        assert_eq!(i.published, "2026-10-22T09:14:22Z");
        assert!(i.cves.is_empty());
        // A fallback record is not trusted as cached: the next run asks for the JSON again.
        fake.route(&url, Ok(fixture("certeu_2026-019.json")));
        fake.clear();
        let items = run(&mut fake).unwrap();
        assert!(fake.calls.contains(&url));
        assert_eq!(items.iter().find(|i| i.id == "2026-019").unwrap().cves, ["CVE-2026-110264"]);
    }

    #[test]
    fn rss_failure_raises() {
        let _t = state::testing::temp_state("certeu-rssfail");
        let mut fake = routes();
        fake.route(RSS, Err(SourceError::new("CERT-EU RSS: HTTP 403 (blocked or rate limited)")));
        let err = run(&mut fake).unwrap_err();
        assert!(err.message.contains("CERT-EU RSS: HTTP 403"), "{err}");
    }

    #[test]
    fn empty_rss_raises() {
        let _t = state::testing::temp_state("certeu-empty");
        let mut fake = routes();
        fake.route(RSS, Ok(b"<rss><channel></channel></rss>".to_vec()));
        let err = run(&mut fake).unwrap_err();
        assert!(err.message.contains("RSS has no advisory items"), "{err}");
    }

    /// The cursor record keeps its stored shape: these keys, pubdate as received, no fallback.
    #[test]
    fn cursor_record_shape() {
        let _t = state::testing::temp_state("certeu-record");
        let mut fake = routes();
        run(&mut fake).unwrap();
        let cur: Value = state::load_json(CURSOR).unwrap();
        let r = &cur["2026-018"];
        assert_eq!(r["pubdate"], "Fri, 23 Oct 2026 16:36:26 CEST");
        assert!(r.get("fallback").is_none());
        let keys: BTreeSet<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, BTreeSet::from(["id", "url", "title", "published", "updated", "cves", "extra", "pubdate"]));
    }

    // ------------------------------------------------ live (manual)

    /// EW_STATE_COPY=<copy of state/> cargo test -- --ignored certeu::tests::live_state_copy --nocapture
    #[test]
    #[ignore]
    fn live_state_copy() {
        super::fake::live_twice("certeu", fetch_with);
    }
}
