//! CISA Known Exploited Vulnerabilities catalog. Port of feeds/kev.py.
//!
//! cisa.gov answers 403 to some egress proxies (ours, 2026-11-03), so the cisagov
//! GitHub mirror is the fallback. The mirror carries the same file and a weak ETag,
//! so a repeat run costs a 304. dateAdded is a date only; the catalog-level
//! dateReleased is the only precise timestamp CISA publishes.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use super::common::{self, FetchOutput, GetOpts, Item, Response, SourceError, iso_utc, parse_iso};

pub const NAME: &str = "CISA KEV";
pub const TABLE: &str = "kev";
pub const CADENCE: u64 = 0;

pub const SOURCES: &[(&str, &str)] = &[
    ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "cisa.gov"),
    ("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json", "github mirror"),
];

pub fn cve_link(cve: &str) -> String {
    format!("https://www.cve.org/CVERecord?id={cve}")
}

/// Return (catalog json, via). Tries each source in order; fails only if all fail.
fn load_catalog<G>(get: &G) -> Result<(Value, &'static str), SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let mut errors = Vec::new();
    for &(url, via) in SOURCES {
        let r = match get(url, &format!("{NAME} ({via})"), GetOpts::default()) {
            Ok(r) => r,
            Err(e) => {
                errors.push(e.message);
                continue;
            }
        };
        let j: Value = match r.json() {
            Ok(j) => j,
            Err(_) => {
                // A proxy block page comes back as 200 HTML; treat it like a failure.
                errors.push(format!("{NAME} ({via}): response is not JSON"));
                continue;
            }
        };
        if !j.as_object().is_some_and(|o| o.contains_key("vulnerabilities")) {
            errors.push(format!("{NAME} ({via}): no 'vulnerabilities' key"));
            continue;
        }
        return Ok((j, via));
    }
    Err(SourceError::new(errors.join("; ")))
}

/// v[k] as-is, or "" when the key is missing (Python: v.get(k, "")).
fn get_or_empty(v: &Value, k: &str) -> Value {
    v.get(k).cloned().unwrap_or_else(|| Value::String(String::new()))
}

pub fn parse(j: &Value, via: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Item>, SourceError> {
    let first = start.date_naive().to_string();
    let last = end.date_naive().to_string();
    let mut released = j.get("dateReleased").and_then(Value::as_str).unwrap_or("").to_string();
    if !released.is_empty() {
        released = iso_utc(parse_iso(&released)
            .ok_or_else(|| SourceError::new(format!("{NAME}: bad dateReleased {released:?}")))?);
    }
    let mut out = Vec::new();
    for v in j.get("vulnerabilities").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        let added = v.get("dateAdded").and_then(Value::as_str).unwrap_or("");
        if !(first.as_str() <= added && added <= last.as_str()) {
            continue;
        }
        let cve = v.get("cveID").and_then(Value::as_str)
            .ok_or_else(|| SourceError::new(format!("{NAME}: entry dated {added} has no cveID")))?;
        let desc = v.get("shortDescription").and_then(Value::as_str).unwrap_or("");
        let mut it = Item::new(NAME, cve, &cve_link(cve), &desc.split_whitespace().collect::<Vec<_>>().join(" "), added);
        it.cves = vec![cve.to_string()];
        let mut extra = Map::new();
        extra.insert("vendor".into(), get_or_empty(v, "vendorProject"));
        extra.insert("product".into(), get_or_empty(v, "product"));
        extra.insert("due".into(), get_or_empty(v, "dueDate"));
        extra.insert("catalog_released".into(), Value::String(released.clone()));
        extra.insert("catalog_version".into(), get_or_empty(j, "catalogVersion"));
        extra.insert("via".into(), Value::String(via.to_string()));
        it.extra = extra;
        out.push(it);
    }
    out.sort_by(|a, b| (&b.published, &b.id).cmp(&(&a.published, &a.id)));
    Ok(out)
}

fn fetch_with<G>(start: DateTime<Utc>, end: DateTime<Utc>, get: &G) -> Result<FetchOutput, SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let (j, via) = load_catalog(get)?;
    Ok(parse(&j, via, start, end)?.into())
}

pub fn fetch(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    fetch_with(start, end, &common::get)
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Shared by the CVE-side feed tests: fixtures, window and a fake Response.
    use chrono::{DateTime, TimeZone, Utc};
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    use crate::feeds::common::Response;

    pub fn start() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 27, 3, 0, 0).unwrap()
    }

    pub fn end() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 3, 3, 0, 0).unwrap()
    }

    pub fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    pub fn fixture_json(name: &str) -> serde_json::Value {
        serde_json::from_slice(&fixture(name)).unwrap()
    }

    pub fn resp(body: impl Into<Vec<u8>>, status: u16, headers: &[(&str, &str)], url: &str, from_cache: bool) -> Response {
        let mut h = HeaderMap::new();
        for (k, v) in headers {
            h.insert(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        Response { status, content: body.into(), headers: h, url: url.to_string(), from_cache }
    }

    pub fn ok_json(v: &serde_json::Value) -> Response {
        resp(serde_json::to_vec(v).unwrap(), 200, &[], "https://example.test/", false)
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn window_and_fields() {
        let items = parse(&fixture_json("kev_catalog.json"), "github mirror", start(), end()).unwrap();
        assert_eq!(items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["CVE-2026-76418", "CVE-2026-97229"]);
        let i = &items[0];
        assert_eq!(i.source, "CISA KEV");
        assert_eq!(i.published, "2026-10-29");
        assert_eq!(i.url, "https://www.cve.org/CVERecord?id=CVE-2026-76418");
        assert_eq!(i.x("due"), "2026-11-01");
        assert_eq!(i.x("vendor"), "Cisco");
        assert_eq!(i.x("catalog_released"), "2026-10-30T17:02:45Z");
        assert_eq!(i.x("via"), "github mirror");
    }

    #[test]
    fn falls_back_to_mirror() {
        let cat = fixture_json("kev_catalog.json");
        let fake = |url: &str, label: &str, _o: GetOpts| {
            if url.contains("cisa.gov") {
                return Err(SourceError { message: format!("{label}: HTTP 403 (blocked or rate limited)"), status: Some(403) });
            }
            Ok(ok_json(&cat))
        };
        let items = fetch_with(start(), end(), &fake).unwrap().items;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].x("via"), "github mirror");
    }

    #[test]
    fn both_fail() {
        let fake = |url: &str, label: &str, _o: GetOpts| {
            if url.contains("cisa.gov") {
                return Err(SourceError { message: format!("{label}: HTTP 403 (blocked or rate limited)"), status: Some(403) });
            }
            Ok(resp("<html>proxy says no</html>", 200, &[], url, false))
        };
        let e = fetch_with(start(), end(), &fake).unwrap_err();
        assert!(e.message.contains("CISA KEV (cisa.gov): HTTP 403"), "{e}");
        assert!(e.message.contains("CISA KEV (github mirror): response is not JSON"), "{e}");
    }

    /// Live, against a copy of state/: EW_STATE_COPY=<dir> cargo test -- --ignored live_state_copy --nocapture
    #[test]
    #[ignore]
    fn live_state_copy_kev() {
        let _g = crate::feeds::state::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::feeds::state::set_dir(std::env::var("EW_STATE_COPY").expect("EW_STATE_COPY"));
        let end = Utc::now();
        let out = fetch(end - chrono::Duration::days(7), end).unwrap();
        println!("LIVE kev items={} via={}", out.items.len(), out.items.first().map(|i| i.x("via")).unwrap_or(""));
    }
}
