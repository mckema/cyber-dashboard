//! ENISA EU Vulnerability Database, exploited-vulnerability view. Port of feeds/euvd.py.
//!
//! /api/vulnerabilities is 404; /api/search with fromKEVDate/toKEVDate is the
//! documented query (2026-11-03). The API sends Cache-Control: no-store and no
//! ETag, so every run is a full (small) fetch. Dates come as "Nov 3, 2026,
//! 12:41:24 AM" with no zone; ENISA serves them in UTC.

use std::sync::OnceLock;

use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::{Map, Value};

use super::common::{self, FetchOutput, GetOpts, Item, Response, SourceError, iso_utc, severity_for};

pub const NAME: &str = "ENISA EUVD";
pub const TABLE: &str = "kev";
pub const CADENCE: u64 = 0;

pub const URL: &str = "https://euvdservices.enisa.europa.eu/api/search";
pub const PAGE_SIZE: usize = 100; // API maximum
pub const MAX_PAGES: usize = 10;

const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// "Nov 3, 2026, 12:41:24 AM" -> UTC datetime. Own parser so %b never depends on locale.
pub fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^(\w{3}) (\d{1,2}), (\d{4}), (\d{1,2}):(\d{2}):(\d{2}) ([AP]M)$").unwrap());
    let c = re.captures(s.trim())?;
    let n = |i: usize| c[i].parse::<u32>().ok();
    let mon = MON.iter().position(|m| *m == &c[1])? as u32 + 1;
    let hh = n(4)? % 12 + if &c[7] == "PM" { 12 } else { 0 };
    Utc.with_ymd_and_hms(c[3].parse().ok()?, mon, n(2)?, hh, n(5)?, n(6)?).single()
}

fn uniq<'a>(xs: impl IntoIterator<Item = Option<&'a str>>) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for x in xs.into_iter().flatten() {
        if !x.is_empty() && !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

fn date_of(v: &Value, k: &str) -> Option<DateTime<Utc>> {
    v.get(k).and_then(Value::as_str).and_then(parse_date)
}

/// Python float(x or 0) for a number or a numeric string.
pub(crate) fn num(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) if !s.is_empty() => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Python (v.get(k) or ""), for string fields.
pub(crate) fn str_or_empty<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// Python " ".join(s.split()).
pub(crate) fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

const LINE_BREAKS: &[char] = &['\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}'];

pub fn to_item(v: &Value) -> Result<Item, SourceError> {
    // Python str.splitlines(); empty pieces are dropped, so "\r\n" splitting in two is harmless.
    let aliases: Vec<&str> = str_or_empty(v, "aliases").split(LINE_BREAKS).map(str::trim).filter(|a| !a.is_empty()).collect();
    let cves: Vec<String> = aliases.iter().filter(|a| a.starts_with("CVE-")).map(|a| a.to_string()).collect();
    let euvd_id = v.get("id").and_then(Value::as_str).ok_or_else(|| SourceError::new(format!("{NAME}: item without id")))?;
    let exploited = date_of(v, "exploitedSince");
    let published = date_of(v, "datePublished");
    let updated = date_of(v, "dateUpdated");
    let list = |k: &str, inner: &str| -> Vec<String> {
        let xs = v.get(k).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
        uniq(xs.iter().map(|x| x.get(inner).and_then(|o| o.get("name")).and_then(Value::as_str)))
            .into_iter().map(String::from).collect()
    };
    let vendors = list("enisaIdVendor", "vendor");
    let products = list("enisaIdProduct", "product");
    let score = num(v.get("baseScore"));
    let exploited_day = exploited.map(|d| d.date_naive().to_string()).unwrap_or_default();
    let published_iso = published.map(iso_utc).unwrap_or_default();

    let id = cves.first().cloned().unwrap_or_else(|| euvd_id.to_string());
    let mut it = Item::new(
        NAME, &id, &format!("https://euvd.enisa.europa.eu/vulnerability/{euvd_id}"),
        &squash(str_or_empty(v, "description")),
        // The KEV table is "newly known exploited", so the row date is exploitedSince
        // (always midnight, so a date). The vulnerability's own publication is in extra.
        if exploited.is_some() { &exploited_day } else { &published_iso },
    );
    it.updated = updated.map(iso_utc).unwrap_or_default();
    it.cves = cves;
    it.score = score;
    it.severity = severity_for(score).to_string();
    let mut extra = Map::new();
    extra.insert("euvd_id".into(), euvd_id.into());
    extra.insert("exploited_since".into(), exploited_day.into());
    extra.insert("euvd_published".into(), published_iso.into());
    extra.insert("vendor".into(), vendors.iter().take(3).cloned().collect::<Vec<_>>().join(", ").into());
    extra.insert("product".into(), products.iter().take(3).cloned().collect::<Vec<_>>().join(", ").into());
    // percent (27.3 = 27.3 %), not a 0-1 fraction
    extra.insert("epss".into(), v.get("epss").cloned().unwrap_or(Value::Null));
    extra.insert("vector".into(), str_or_empty(v, "baseScoreVector").into());
    extra.insert("assigner".into(), str_or_empty(v, "assigner").into());
    it.extra = extra;
    Ok(it)
}

fn fetch_with<G>(start: DateTime<Utc>, end: DateTime<Utc>, get: &G) -> Result<FetchOutput, SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let from = start.date_naive().to_string();
    let to = end.date_naive().to_string();
    let size = PAGE_SIZE.to_string();
    let mut rows: Vec<Value> = Vec::new();
    let mut done = false;
    for page in 0..MAX_PAGES {
        let p = page.to_string();
        let params = [("fromKEVDate", from.as_str()), ("toKEVDate", to.as_str()), ("size", size.as_str()), ("page", p.as_str())];
        let r = get(URL, &format!("{NAME} page {page}"), GetOpts { conditional: false, params: &params, ..Default::default() })?;
        let j: Value = r.json().map_err(|_| SourceError::new(format!("{NAME}: response is not JSON")))?;
        let total = j.get("total").and_then(Value::as_u64).unwrap_or(0) as usize;
        let batch = j.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
        let empty = batch.is_empty();
        rows.extend(batch);
        if empty || rows.len() >= total {
            done = true;
            break;
        }
    }
    if !done {
        return Err(SourceError::new(format!("{NAME}: more than {} results; page cap hit", MAX_PAGES * PAGE_SIZE)));
    }
    let mut out = rows.iter().map(to_item).collect::<Result<Vec<_>, _>>()?;
    out.sort_by(|a, b| (&b.published, &b.id).cmp(&(&a.published, &a.id)));
    Ok(out.into())
}

pub fn fetch(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    fetch_with(start, end, &common::get)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::Timelike;
    use serde_json::json;

    use super::super::kev::testutil::*;
    use super::*;

    #[test]
    fn parse_date_variants() {
        assert_eq!(parse_date("Nov 3, 2026, 12:41:24 AM"), Some(Utc.with_ymd_and_hms(2026, 11, 3, 0, 41, 24).unwrap()));
        assert_eq!(parse_date("Oct 15, 2026, 8:56:58 PM").unwrap().hour(), 20);
        assert_eq!(parse_date("Oct 15, 2026, 12:05:00 PM").unwrap().hour(), 12);
        assert_eq!(parse_date(""), None);
    }

    #[test]
    fn item() {
        let j = fixture_json("euvd_search.json");
        let rows = j["items"].as_array().unwrap();
        let i = to_item(&rows[0]).unwrap();
        assert_eq!(i.id, "CVE-2026-111357"); // first CVE alias, though GHSA is listed first
        assert_eq!(i.cves, ["CVE-2026-111357"]);
        assert_eq!(i.published, "2026-10-30"); // exploitedSince
        assert_eq!(i.updated, "2026-10-31T03:56:17Z");
        assert_eq!(i.x("euvd_id"), "EUVD-2026-102437");
        assert_eq!(i.x("euvd_published"), "2026-10-15T20:56:58Z");
        assert_eq!(i.x("vendor"), "Ivanti");
        assert_eq!(i.x("product"), "Connect Secure");
        assert_eq!(i.severity, "HIGH");
        assert_eq!(i.url, "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-102437");
        let cisco = to_item(&rows[1]).unwrap();
        assert_eq!(cisco.x("product").matches("Adaptive Security Appliance").count(), 1); // de-duplicated
    }

    #[test]
    fn paging() {
        let j = fixture_json("euvd_search.json");
        let rows = j["items"].as_array().unwrap().clone();
        let calls: Mutex<Vec<Vec<(String, String)>>> = Mutex::new(vec![]);
        let fake = |_url: &str, _label: &str, o: GetOpts| {
            assert!(!o.conditional);
            let params: Vec<(String, String)> = o.params.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
            let page: usize = params.iter().find(|(k, _)| k == "page").unwrap().1.parse().unwrap();
            calls.lock().unwrap().push(params);
            Ok(ok_json(&json!({"items": rows[page..page + 1], "total": 2})))
        };
        let items = fetch_with(start(), end(), &fake).unwrap().items;
        assert_eq!(items.len(), 2);
        let calls = calls.into_inner().unwrap();
        let p = |c: &Vec<(String, String)>, k: &str| c.iter().find(|(a, _)| a == k).unwrap().1.clone();
        assert_eq!(calls.iter().map(|c| p(c, "page")).collect::<Vec<_>>(), ["0", "1"]);
        assert_eq!(p(&calls[0], "fromKEVDate"), "2026-10-27");
        assert_eq!(p(&calls[0], "toKEVDate"), "2026-11-03");
    }

    /// Live, against a copy of state/: EW_STATE_COPY=<dir> cargo test -- --ignored live_state_copy --nocapture
    #[test]
    #[ignore]
    fn live_state_copy_euvd() {
        let _g = crate::feeds::state::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::feeds::state::set_dir(std::env::var("EW_STATE_COPY").expect("EW_STATE_COPY"));
        let end = Utc::now();
        let out = fetch(end - chrono::Duration::days(7), end).unwrap();
        println!("LIVE euvd items={}", out.items.len());
    }
}
