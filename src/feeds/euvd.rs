//! ENISA EU Vulnerability Database, exploited-vulnerability view.
//!
//! /api/vulnerabilities is 404; /api/search with fromKEVDate/toKEVDate is the
//! query the EUVD site uses (2026-11-03); fromKEVDate is in no published API
//! documentation (checked 2026-11-06). The API sends Cache-Control: no-store and
//! no ETag, so every run is a full (small) fetch. Dates come as "Nov 3, 2026,
//! 12:41:24 AM" with no zone; ENISA serves them in UTC.
//!
//! Fallback (2026-11-06): when the fromKEVDate query fails (HTTP error, not JSON,
//! no items/total, page cap, a bad item), the job reads every exploited entry with
//! /api/search?exploited=true (1,786 entries, 18 pages of 100 on 2026-11-06) and
//! keeps those whose exploitedSince falls in the window. Paging stops at `total`,
//! not at a date: the list is sorted by dateUpdated, and exploitedSince can be
//! later than dateUpdated (3 of 300 entries checked). /api/exploitedvulnerabilities
//! is not used: it ignores page/size, returned a fixed list of 4 entries, and
//! missed one of the 5 entries the fromKEVDate query returned for the same 7 days.
//! stats["primary_error"] tells run.rs to say so in the health note.

use std::sync::OnceLock;

use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::{Map, Value};

use super::common::{self, FetchOutput, GetOpts, Item, Response, SourceError, iso_utc, severity_for};

pub const NAME: &str = "ENISA EUVD";
pub const CADENCE: u64 = 0;

pub const URL: &str = "https://euvdservices.enisa.europa.eu/api/search";
pub const PAGE_SIZE: usize = 100; // API maximum (size=200 returns 100)
pub const MAX_PAGES: usize = 10;
/// Fallback reads all exploited entries: 1,786 on 2026-11-06, so 30 pages leave room for growth.
pub const FALLBACK_MAX_PAGES: usize = 30;

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

/// A number or numeric string as f64; 0 when missing, empty or not numeric.
pub(crate) fn num(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) if !s.is_empty() => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// v[k] as a string ("" when missing or not a string).
pub(crate) fn str_or_empty<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// Runs of whitespace collapsed to one space, trimmed at both ends.
pub(crate) fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

const LINE_BREAKS: &[char] = &['\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}'];

pub fn to_item(v: &Value) -> Result<Item, SourceError> {
    // Split at any line boundary; empty pieces are dropped, so "\r\n" splitting in two is harmless.
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

/// Every row of one /api/search query, paging until `total` rows are read.
/// Returns (rows, requests). Err on a non-JSON page, a page without `items` and
/// `total`, the page cap, or ids that do not add up to `total` (the list changed
/// while paging).
fn search_all<G>(get: &G, query: &[(&str, &str)], what: &str, max_pages: usize) -> Result<(Vec<Value>, usize), SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let size = PAGE_SIZE.to_string();
    let mut rows: Vec<Value> = Vec::new();
    for page in 0..max_pages {
        let p = page.to_string();
        let mut params = query.to_vec();
        params.extend([("size", size.as_str()), ("page", p.as_str())]);
        let r = get(URL, &format!("{NAME} ({what}) page {page}"), GetOpts { conditional: false, params: &params, ..Default::default() })?;
        let j: Value = r.json().map_err(|_| SourceError::new(format!("{NAME} ({what}): response is not JSON")))?;
        let (Some(total), Some(batch)) = (j.get("total").and_then(Value::as_u64), j.get("items").and_then(Value::as_array)) else {
            return Err(SourceError::new(format!("{NAME} ({what}): response has no 'items' list and 'total'")));
        };
        let total = total as usize;
        rows.extend(batch.iter().cloned());
        if batch.is_empty() || rows.len() >= total {
            let mut ids = rows.iter().map(|v| v.get("id").and_then(Value::as_str)).collect::<Option<Vec<&str>>>()
                .ok_or_else(|| SourceError::new(format!("{NAME} ({what}): item without id")))?;
            ids.sort_unstable();
            ids.dedup();
            if ids.len() != total {
                return Err(SourceError::new(format!("{NAME} ({what}): {} distinct ids for a total of {total}; the list changed while paging", ids.len())));
            }
            return Ok((rows, page + 1));
        }
    }
    Err(SourceError::new(format!("{NAME} ({what}): more than {} results; page cap hit", max_pages * PAGE_SIZE)))
}

fn newest_first(mut out: Vec<Item>) -> Vec<Item> {
    out.sort_by(|a, b| (&b.published, &b.id).cmp(&(&a.published, &a.id)));
    out
}

/// Primary: entries whose KEV date (exploitedSince) is in the window. Returns (items, requests).
fn by_kev_date<G>(start: DateTime<Utc>, end: DateTime<Utc>, get: &G) -> Result<(Vec<Item>, usize), SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let from = start.date_naive().to_string();
    let to = end.date_naive().to_string();
    let (rows, requests) = search_all(get, &[("fromKEVDate", from.as_str()), ("toKEVDate", to.as_str())], "fromKEVDate", MAX_PAGES)?;
    let items = rows.iter().map(to_item).collect::<Result<Vec<_>, _>>()?;
    Ok((newest_first(items), requests))
}

/// Fallback: every exploited entry, filtered here to exploitedSince within the
/// window's dates (both ends included, as fromKEVDate/toKEVDate). Entries without
/// exploitedSince cannot be placed in the window and are left out.
/// Returns (items, requests, entries read).
fn by_exploited_flag<G>(start: DateTime<Utc>, end: DateTime<Utc>, get: &G) -> Result<(Vec<Item>, usize, usize), SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let (first, last) = (start.date_naive(), end.date_naive());
    let (rows, requests) = search_all(get, &[("exploited", "true")], "exploited=true", FALLBACK_MAX_PAGES)?;
    let items = rows.iter()
        .filter(|v| date_of(v, "exploitedSince").is_some_and(|d| (first..=last).contains(&d.date_naive())))
        .map(to_item)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((newest_first(items), requests, rows.len()))
}

fn fetch_with<G>(start: DateTime<Utc>, end: DateTime<Utc>, get: &G) -> Result<FetchOutput, SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let mut stats = Map::new();
    let items = match by_kev_date(start, end, get) {
        Ok((items, requests)) => {
            stats.insert("via".into(), "fromKEVDate".into());
            stats.insert("requests".into(), requests.into());
            items
        }
        // Rate limited: the fallback would send up to 18 more requests to the same host.
        Err(primary) if primary.status == Some(429) => return Err(primary),
        Err(primary) => {
            eprintln!("  {}; trying exploited=true", primary.message);
            let (items, requests, read) = by_exploited_flag(start, end, get)
                .map_err(|e| SourceError::new(format!("{}; fallback: {}", primary.message, e.message)))?;
            stats.insert("via".into(), "exploited=true".into());
            stats.insert("requests".into(), requests.into());
            stats.insert("scanned".into(), read.into());
            stats.insert("primary_error".into(), primary.message.into());
            items
        }
    };
    Ok(FetchOutput { items, stats })
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

    fn param(o: &GetOpts, k: &str) -> Option<String> {
        o.params.iter().find(|(a, _)| *a == k).map(|(_, b)| b.to_string())
    }

    /// Page `page` of euvd_search_exploited.json (6 real entries from
    /// /api/search?exploited=true, 2026-11-06) served 3 per page.
    fn exploited_page(page: usize) -> Response {
        let j = fixture_json("euvd_search_exploited.json");
        let rows = j["items"].as_array().unwrap();
        let a = (page * 3).min(rows.len());
        ok_json(&json!({"items": rows[a..(a + 3).min(rows.len())], "total": j["total"]}))
    }

    fn http(status: u16, label: &str) -> SourceError {
        SourceError { message: format!("{label}: HTTP {status}"), status: Some(status) }
    }

    fn euvd_ids(items: &[Item]) -> Vec<&str> {
        items.iter().map(|i| i.x("euvd_id")).collect()
    }

    #[test]
    fn primary_ok_no_fallback() {
        let j = fixture_json("euvd_search.json");
        let fake = |_url: &str, _label: &str, o: GetOpts| {
            assert!(param(&o, "exploited").is_none(), "fallback must not run");
            Ok(ok_json(&j))
        };
        let out = fetch_with(start(), end(), &fake).unwrap();
        assert_eq!(euvd_ids(&out.items), ["EUVD-2026-102437", "EUVD-2026-112462"]);
        assert_eq!(out.stats["via"], "fromKEVDate");
        assert_eq!(out.stats["requests"], 1);
        assert!(!out.stats.contains_key("primary_error"));
    }

    #[test]
    fn fallback_when_primary_fails() {
        let cases: Vec<(&str, Box<dyn Fn() -> Result<Response, SourceError>>)> = vec![
            ("HTTP 404", Box::new(|| Err(http(404, "ENISA EUVD (fromKEVDate) page 0")))),
            ("HTTP 403", Box::new(|| Err(http(403, "ENISA EUVD (fromKEVDate) page 0")))),
            // a proxy block page
            ("not JSON", Box::new(|| Ok(resp("<html>blocked</html>", 200, &[], "https://example.test/", false)))),
            ("no 'items' list", Box::new(|| Ok(ok_json(&json!({"content": [], "totalElements": 0}))))),
            // fromKEVDate ignored: every exploited entry comes back, more than the page cap
            ("page cap hit", Box::new(|| Ok(ok_json(&json!({"items": [{"id": "EUVD-1"}], "total": 1786}))))),
            ("without id", Box::new(|| Ok(ok_json(&json!({"items": [{"aliases": "CVE-1"}], "total": 1}))))),
        ];
        for (want, primary) in cases {
            let pages: Mutex<Vec<String>> = Mutex::new(vec![]);
            let fake = |_url: &str, _label: &str, o: GetOpts| {
                if param(&o, "fromKEVDate").is_some() {
                    return primary();
                }
                assert_eq!(param(&o, "exploited").as_deref(), Some("true"));
                assert!(param(&o, "toKEVDate").is_none());
                let page = param(&o, "page").unwrap();
                pages.lock().unwrap().push(page.clone());
                Ok(exploited_page(page.parse().unwrap()))
            };
            let out = fetch_with(start(), end(), &fake).unwrap_or_else(|e| panic!("{want}: {e}"));
            // Window 2026-10-27..2026-11-03, both ends included: Oct 26 and Nov 4 are out,
            // and so is an entry whose exploitedSince (Oct 10) is later than its dateUpdated.
            assert_eq!(euvd_ids(&out.items), ["EUVD-2026-114575", "EUVD-2026-115872", "EUVD-2026-108169"], "{want}");
            assert_eq!(out.items[0].published, "2026-11-03");
            assert_eq!(out.items[2].published, "2026-10-27");
            assert_eq!(pages.into_inner().unwrap(), ["0", "1"]);
            assert_eq!(out.stats["via"], "exploited=true");
            assert_eq!(out.stats["requests"], 2);
            assert_eq!(out.stats["scanned"], 6);
            let err = out.stats["primary_error"].as_str().unwrap();
            assert!(err.contains(want), "{want}: {err}");
        }
    }

    #[test]
    fn rate_limited_primary_skips_fallback() {
        let fake = |_url: &str, _label: &str, o: GetOpts| {
            assert!(param(&o, "exploited").is_none(), "fallback must not run after a 429");
            Err(http(429, "ENISA EUVD (fromKEVDate) page 0"))
        };
        let e = fetch_with(start(), end(), &fake).unwrap_err();
        assert_eq!(e.message, "ENISA EUVD (fromKEVDate) page 0: HTTP 429");
    }

    #[test]
    fn both_fail() {
        let fake = |_url: &str, _label: &str, o: GetOpts| {
            if param(&o, "fromKEVDate").is_some() {
                Err(http(404, "ENISA EUVD (fromKEVDate) page 0"))
            } else {
                Err(http(429, "ENISA EUVD (exploited=true) page 0"))
            }
        };
        let e = fetch_with(start(), end(), &fake).unwrap_err();
        assert_eq!(e.message, "ENISA EUVD (fromKEVDate) page 0: HTTP 404; fallback: ENISA EUVD (exploited=true) page 0: HTTP 429");
    }

    #[test]
    fn list_changed_while_paging() {
        // Page 1 repeats page 0 (an update moved entries down): fewer distinct ids than total.
        let fake = |_url: &str, _label: &str, o: GetOpts| {
            if param(&o, "fromKEVDate").is_some() {
                return Err(http(404, "primary"));
            }
            Ok(exploited_page(0))
        };
        let e = fetch_with(start(), end(), &fake).unwrap_err();
        assert!(e.message.contains("3 distinct ids for a total of 6; the list changed while paging"), "{}", e.message);
    }

    /// Live: the fallback query finds the same entries as fromKEVDate for the last 7 days.
    /// cargo test -- --ignored live_fallback_matches --nocapture
    #[test]
    #[ignore]
    fn live_fallback_matches_primary_euvd() {
        let end = Utc::now();
        let start = end - chrono::Duration::days(7);
        let (a, ra) = by_kev_date(start, end, &common::get).unwrap();
        let (b, rb, read) = by_exploited_flag(start, end, &common::get).unwrap();
        println!("LIVE euvd fromKEVDate: {} items, {ra} requests; exploited=true: {} of {read} entries, {rb} requests",
                 a.len(), b.len());
        let ids = |v: &[Item]| { let mut x: Vec<String> = v.iter().map(|i| i.x("euvd_id").to_string()).collect(); x.sort(); x };
        assert_eq!(ids(&a), ids(&b));
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
