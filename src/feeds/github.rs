//! GitHub Advisory Database: reviewed critical and high advisories. Port of feeds/github.py.
//!
//! The original fetch_gh read one page per severity and silently dropped the rest
//! (125 high advisories in the 7 days to 2026-11-03 = 2 pages). This follows
//! Link: rel="next" until the end, capped at MAX_PAGES.
//!
//! The query uses whole UTC dates (start date .. today) so the URL stays the same
//! all day and conditional GETs can return 304; the exact window is applied here.
//! A 304 may come back without a Link header, so the next-page URL seen on the
//! last 200 is remembered per page URL (cursors/github_next.json, {page URL: next URL | null}).
//!
//! Rate limit: 60 req/h per IP unauthenticated (shared by everyone behind the
//! proxy), 1,000/h for an Actions GITHUB_TOKEN; 304s are free only when authenticated.

use std::collections::HashMap;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{self, FetchOutput, GetOpts, Item, Response, SourceError, iso_utc, parse_iso};
use super::state;

pub const NAME: &str = "GitHub Advisory";
pub const TABLE: &str = "dep";
pub const CADENCE: u64 = 0;

pub const URL: &str = "https://api.github.com/advisories";
pub const SEVERITIES: [&str; 2] = ["critical", "high"];
pub const PER_PAGE: usize = 100;
pub const MAX_PAGES: usize = 10;
pub const NEXT: &str = "cursors/github_next.json"; // page URL -> next page URL from its last 200

fn headers() -> Vec<(&'static str, String)> {
    let mut h = vec![("Accept", "application/vnd.github+json".to_string()), ("X-GitHub-Api-Version", "2022-11-28".to_string())];
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            h.push(("Authorization", format!("Bearer {token}")));
        }
    }
    h
}

/// URL of rel="next" in a Link header, or None.
pub fn next_link(link: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"<([^>]+)>\s*;\s*rel="next""#).unwrap());
    link.split(',').find_map(|part| re.captures(part).map(|c| c[1].to_string()))
}

fn uniq<'a>(xs: impl IntoIterator<Item = Option<&'a str>>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for x in xs.into_iter().flatten() {
        if !x.is_empty() && !out.iter().any(|o| o == x) {
            out.push(x.to_string());
        }
    }
    out
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn num(v: Option<&Value>) -> f64 {
    super::euvd::num(v)
}

pub fn score_and_vector(a: &Value) -> (f64, String) {
    let null = Value::Null;
    let cs = a.get("cvss_severities").unwrap_or(&null);
    for k in ["cvss_v4", "cvss_v3"] {
        let d = cs.get(k).unwrap_or(&null);
        let score = num(d.get("score"));
        if score != 0.0 {
            return (score, s(d, "vector_string").to_string());
        }
    }
    let d = a.get("cvss").unwrap_or(&null); // deprecated field, still filled on older advisories
    (num(d.get("score")), s(d, "vector_string").to_string())
}

pub fn to_item(a: &Value) -> Result<Item, SourceError> {
    let vulns = a.get("vulnerabilities").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let mut pkgs = uniq(vulns.iter().map(|v| v.get("package").and_then(|p| p.get("name")).and_then(Value::as_str)));
    let mut ecos = uniq(vulns.iter().map(|v| v.get("package").and_then(|p| p.get("ecosystem")).and_then(Value::as_str)));
    let mut fixed = uniq(vulns.iter().map(|v| v.get("first_patched_version").and_then(Value::as_str)));
    let (score, vec) = score_and_vector(a);
    let ghsa = s(a, "ghsa_id");
    if ghsa.is_empty() {
        return Err(SourceError::new(format!("{NAME}: advisory without ghsa_id")));
    }
    let bad = |what: &str, val: &str| SourceError::new(format!("{NAME} {ghsa}: bad {what} {val:?}"));
    let cve = s(a, "cve_id");
    let pa = s(a, "published_at");
    let published = iso_utc(parse_iso(pa).ok_or_else(|| bad("published_at", pa))?);
    let ua = s(a, "updated_at");
    let updated = if ua.is_empty() { String::new() } else { iso_utc(parse_iso(ua).ok_or_else(|| bad("updated_at", ua))?) };
    let npkg = pkgs.len();
    pkgs.sort();
    ecos.sort();
    fixed.sort();
    fixed.truncate(3);

    let id = if cve.is_empty() { ghsa } else { cve };
    let mut it = Item::new(NAME, id, s(a, "html_url"), &s(a, "summary").split_whitespace().collect::<Vec<_>>().join(" "), &published);
    it.updated = updated;
    it.cves = if cve.is_empty() { vec![] } else { vec![cve.to_string()] };
    it.score = score;
    it.severity = s(a, "severity").to_uppercase();
    if let Value::Object(m) = json!({"ghsa": ghsa, "ecosystems": ecos, "packages": pkgs, "fixed": fixed, "npkg": npkg, "vector": vec}) {
        it.extra = m;
    }
    Ok(it)
}

#[derive(Default)]
struct Counts {
    requests: u64,
    not_modified: u64,
}

fn fetch_severity<G>(get: &G, n: &mut Counts, sev: &str, start: DateTime<Utc>, end: DateTime<Utc>, nexts: &mut Map<String, Value>) -> Result<Vec<Value>, SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let hdr = headers();
    let hdr: Vec<(&str, &str)> = hdr.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let per_page = PER_PAGE.to_string();
    let published = format!("{}..{}", start.date_naive(), end.date_naive());
    let first_params = [("type", "reviewed"), ("severity", sev), ("per_page", per_page.as_str()), ("published", published.as_str())];
    let mut url = URL.to_string();
    let mut params: &[(&str, &str)] = &first_params;
    let mut rows = Vec::new();
    for page in 0..MAX_PAGES {
        let r = get(&url, &format!("{NAME} {sev} page {}", page + 1), GetOpts { headers: &hdr, params, ..Default::default() })?;
        n.requests += 1;
        n.not_modified += r.from_cache as u64;
        match r.json::<Value>() {
            Ok(Value::Array(a)) => rows.extend(a),
            _ => return Err(SourceError::new(format!("{NAME} {sev}: response is not JSON"))),
        }
        let link = next_link(r.header("link"));
        let nxt = if r.from_cache {
            link.or_else(|| nexts.get(&r.url).and_then(Value::as_str).map(String::from))
        } else {
            nexts.insert(r.url.clone(), link.clone().map_or(Value::Null, Value::String));
            link
        };
        let Some(nxt) = nxt else { return Ok(rows) };
        url = nxt;
        params = &[];
    }
    Err(SourceError::new(format!(
        "{NAME} {sev}: more than {MAX_PAGES} pages ({} advisories); page cap hit",
        MAX_PAGES * PER_PAGE
    )))
}

fn fetch_with<G>(start: DateTime<Utc>, end: DateTime<Utc>, get: &G) -> Result<FetchOutput, SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let mut n = Counts::default();
    let mut nexts: Map<String, Value> = state::load_json(NEXT).unwrap_or_default();
    // keyed by GHSA id, first-insertion order kept like a Python dict
    let (mut items, mut pos): (Vec<Item>, HashMap<String, usize>) = (Vec::new(), HashMap::new());
    for sev in SEVERITIES {
        for a in fetch_severity(get, &mut n, sev, start, end, &mut nexts)? {
            if a.get("withdrawn_at").is_some_and(|w| !w.is_null() && w != "") {
                continue;
            }
            let it = to_item(&a)?;
            if parse_iso(&it.published).is_some_and(|p| start <= p && p <= end) {
                let ghsa = it.x("ghsa").to_string();
                match pos.get(&ghsa) {
                    Some(&i) => items[i] = it,
                    None => {
                        pos.insert(ghsa, items.len());
                        items.push(it);
                    }
                }
            }
        }
    }
    // Keep only today's page URLs; yesterday's never come back.
    let today = end.date_naive().to_string();
    let kept: Map<String, Value> = nexts.into_iter().filter(|(k, _)| k.contains(&today)).collect();
    state::save_json(NEXT, &kept);
    let mut stats = Map::new();
    stats.insert("requests".into(), n.requests.into());
    stats.insert("not_modified".into(), n.not_modified.into());
    stats.insert("items".into(), items.len().into());
    items.sort_by(|a, b| {
        (a.severity != "CRITICAL").cmp(&(b.severity != "CRITICAL"))
            .then(b.score.total_cmp(&a.score))
            .then(a.id.cmp(&b.id))
    });
    Ok(FetchOutput { items, stats })
}

pub fn fetch(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    fetch_with(start, end, &common::get)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::super::kev::testutil::*;
    use super::*;

    #[test]
    fn next_link_parsing() {
        let link = "<https://api.github.com/advisories?per_page=100&after=Y3Vy>; rel=\"next\", \
                    <https://api.github.com/advisories?per_page=100&before=Y3V>; rel=\"prev\"";
        assert_eq!(next_link(link).as_deref(), Some("https://api.github.com/advisories?per_page=100&after=Y3Vy"));
        assert_eq!(next_link(""), None);
    }

    #[test]
    fn item() {
        let _t = state::testing::temp_state("github-item");
        let i = to_item(&fixture_json("github_advisories.json")[0]).unwrap();
        assert_eq!(i.id, "CVE-2026-111497");
        assert_eq!(i.url, "https://github.com/advisories/GHSA-9v8h-qqgm-4m35");
        assert_eq!((i.score, i.severity.as_str()), (9.2, "CRITICAL"));
        assert_eq!(i.published, "2026-10-30T18:22:05Z");
        assert_eq!(i.extra["packages"], json!(["brotli", "brotli-wasm"]));
        assert_eq!(i.extra["ecosystems"], json!(["npm", "pip"]));
        assert_eq!(i.extra["fixed"], json!(["1.2.1", "1.3.1", "3.0.2"]));
        assert_eq!(i.extra["npkg"], 2);
        assert_eq!(i.title, "Brotli decoder heap overflow");
    }

    #[test]
    fn follows_pages_and_filters_window() {
        let _t = state::testing::temp_state("github-pages");
        let adv = fixture_json("github_advisories.json");
        let page2 = "https://api.github.com/advisories?severity=high&after=abc&published=2026-10-27..2026-11-03";
        let first: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
        let param = |o: &GetOpts, k: &str| o.params.iter().find(|(a, _)| *a == k).map(|x| x.1.to_string());

        let fake = |url: &str, _l: &str, o: GetOpts| -> Result<Response, SourceError> {
            if let Some(sev) = param(&o, "severity") {
                let full = format!("{url}?severity={sev}&published={}", param(&o, "published").unwrap());
                first.lock().unwrap().insert(sev.clone(), full.clone());
                if sev == "critical" {
                    return Ok(resp(serde_json::to_vec(&json!([adv[0]])).unwrap(), 200, &[], &full, false));
                }
                let link = format!("<{page2}>; rel=\"next\"");
                return Ok(resp(serde_json::to_vec(&json!([adv[1]])).unwrap(), 200, &[("Link", &link)], &full, false));
            }
            assert_eq!(url, page2);
            let mut hi = adv[0].clone();
            hi["ghsa_id"] = json!("GHSA-xxxx-yyyy-zzzz");
            hi["cve_id"] = Value::Null;
            hi["severity"] = json!("high");
            hi["html_url"] = json!("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz");
            Ok(resp(serde_json::to_vec(&json!([hi])).unwrap(), 200, &[], page2, false))
        };
        let out = fetch_with(start(), end(), &fake).unwrap();
        let ids: Vec<&str> = out.items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["CVE-2026-111497", "GHSA-xxxx-yyyy-zzzz"]); // page 2 kept, old one dropped
        assert_eq!(out.stats["requests"], 3);

        // Second run: every page is a 304 without a Link header; page 2 is still found.
        let cached = |url: &str, l: &str, o: GetOpts| -> Result<Response, SourceError> {
            let full = match param(&o, "severity") {
                Some(sev) => first.lock().unwrap()[&sev].clone(),
                None => url.to_string(),
            };
            let body = fake(url, l, GetOpts { params: o.params, ..Default::default() })?.content;
            Ok(resp(body, 304, &[], &full, true))
        };
        let out = fetch_with(start(), end(), &cached).unwrap();
        assert_eq!(out.items.len(), 2);
        assert_eq!(out.stats["not_modified"], 3);
    }

    #[test]
    fn page_cap() {
        let _t = state::testing::temp_state("github-cap");
        let endless = |url: &str, _l: &str, _o: GetOpts| {
            Ok(resp("[]", 200, &[("Link", "<https://api.github.com/advisories?after=x&published=2026-11-03>; rel=\"next\"")], url, false))
        };
        let e = fetch_with(start(), end(), &endless).unwrap_err();
        assert!(e.message.contains("page cap hit"), "{e}");
    }

    /// Live, against a copy of state/: EW_STATE_COPY=<dir> cargo test -- --ignored live_state_copy --nocapture
    /// Costs 3 requests of the shared 60/h unauthenticated quota.
    #[test]
    #[ignore]
    fn live_state_copy_github() {
        let _g = state::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        state::set_dir(std::env::var("EW_STATE_COPY").expect("EW_STATE_COPY"));
        let end = Utc::now();
        let out = fetch(end - chrono::Duration::days(7), end).unwrap();
        println!("LIVE github items={} stats={}", out.items.len(), Value::Object(out.stats));
    }
}
