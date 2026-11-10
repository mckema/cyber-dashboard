//! NVD CVE API 2.0: enrichment only (NVD score and CPE vendors merged into the "cve"
//! table).
//!
//! NVD asks clients to poll incrementally no more often than every 2 hours with
//! lastModStartDate/lastModEndDate, so CADENCE is 7200 and each fetch asks only
//! for what changed since the last one, kept in a local store. No severity filter:
//! on 2026-11-03 cvssV3Severity matched 156 of 3,371 window CVEs, because most new
//! CVEs are not analysed yet. No ETag, so no conditional GET.
//!
//! Rate limit: 5 requests / 30 s without a key, 50 with NVD_API_KEY.
//!
//! State:
//!   cursors/nvd.json          {last_mod_end, stats}
//!   cursors/nvd_records.json  {cveId: Item as JSON} for every CVE published in the window

use std::time::Instant;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value, json};

use super::common::{self, FetchOutput, GetOpts, Item, Response, SourceError, iso_utc, parse_iso, severity_for};
use super::cvelist::vector_bits;
use super::state;

pub const NAME: &str = "NVD";
pub const CADENCE: u64 = 7200;

pub const URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const PAGE_SIZE: usize = 2000; // API maximum
pub const MAX_PAGES: usize = 20;
/// Cap on one page of PAGE_SIZE CVEs: a few KB a CVE with its CPE configurations,
/// so a full page is ~5-8 MB.
pub const MAX_PAGE_BYTES: u64 = 32 * 1024 * 1024;
const OVERLAP_MIN: i64 = 15; // NVD indexes lastModified a little late; re-reading is harmless
pub const DESC_MAX: usize = 400;

pub const CURSOR: &str = "cursors/nvd.json";
pub const STORE: &str = "cursors/nvd_records.json";

fn api_key() -> String {
    std::env::var("NVD_API_KEY").unwrap_or_default()
}

/// NVD wants an explicit offset; the query encoder turns the '+' into %2B.
pub fn nvd_time(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S.000+00:00").to_string()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn arr(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// (score, severity, vector), NVD's own (Primary) row first, newest CVSS version first.
pub fn cvss(metrics: &Value) -> (f64, String, String) {
    for k in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"] {
        let rows = arr(metrics.get(k));
        if let Some(first) = rows.first() {
            let row = rows.iter().find(|r| s(r, "type") == "Primary").unwrap_or(first);
            let null = Value::Null;
            let d = row.get("cvssData").unwrap_or(&null);
            let score = super::euvd::num(d.get("baseScore"));
            let mut sev = s(d, "baseSeverity").to_uppercase();
            if !matches!(sev.as_str(), "CRITICAL" | "HIGH" | "MEDIUM" | "LOW") {
                sev = severity_for(score).to_string();
            }
            return (score, sev, s(d, "vectorString").to_string());
        }
    }
    (0.0, String::new(), String::new())
}

pub fn cpe_vendors(c: &Value) -> Vec<String> {
    let mut vendors: Vec<String> = Vec::new();
    for cfg in arr(c.get("configurations")) {
        for n in arr(cfg.get("nodes")) {
            for cm in arr(n.get("cpeMatch")) {
                let parts: Vec<&str> = s(cm, "criteria").split(':').collect();
                if parts.len() > 4 && !vendors.iter().any(|v| v == parts[3]) {
                    vendors.push(parts[3].to_string());
                }
            }
        }
    }
    vendors
}

/// NVD "cve" object -> Item, or None for rejected CVEs.
pub fn to_item(c: &Value) -> Result<Option<Item>, SourceError> {
    if s(c, "vulnStatus").to_lowercase() == "rejected" || s(c, "published").is_empty() {
        return Ok(None);
    }
    let id = s(c, "id");
    if id.is_empty() {
        return Err(SourceError::new(format!("{NAME}: CVE object without id")));
    }
    let bad = |what: &str, val: &str| SourceError::new(format!("{NAME} {id}: bad {what} {val:?}"));
    let (score, sev, vec) = cvss(c.get("metrics").unwrap_or(&Value::Null));
    let desc = arr(c.get("descriptions")).iter().find(|d| s(d, "lang") == "en").map(|d| s(d, "value")).unwrap_or("");
    let mut desc = desc.split_whitespace().collect::<Vec<_>>().join(" ");
    if desc.chars().count() > DESC_MAX {
        desc = desc.chars().take(DESC_MAX - 1).collect::<String>() + "…";
    }
    let (av, pr) = vector_bits(&vec);
    let p = s(c, "published");
    // NVD sends no zone; it is UTC
    let published = iso_utc(parse_iso(p).ok_or_else(|| bad("published", p))?);
    let lm = s(c, "lastModified");
    let updated = if lm.is_empty() { String::new() } else { iso_utc(parse_iso(lm).ok_or_else(|| bad("lastModified", lm))?) };
    let mut vendors = cpe_vendors(c);
    vendors.truncate(3);

    let mut it = Item::new(NAME, id, &format!("https://nvd.nist.gov/vuln/detail/{id}"), &desc, &published);
    it.updated = updated;
    it.cves = vec![id.to_string()];
    it.score = score;
    it.severity = sev;
    if let Value::Object(m) = json!({"vector": vec, "vendors": vendors, "av": av, "pr": pr, "status": s(c, "vulnStatus")}) {
        it.extra = m;
    }
    Ok(Some(it))
}

pub type Store = Map<String, Value>;

pub fn apply(store: &mut Store, c: &Value, start: DateTime<Utc>) -> Result<(), SourceError> {
    let id = s(c, "id");
    match to_item(c)? {
        Some(item) if parse_iso(&item.published).is_some_and(|p| p >= start) => {
            store.insert(id.to_string(), serde_json::to_value(&item).expect("item is JSON"));
        }
        _ => {
            store.remove(id);
        }
    }
    Ok(())
}

fn fetch_with<G>(start: DateTime<Utc>, end: DateTime<Utc>, get: &G, pause: std::time::Duration) -> Result<FetchOutput, SourceError>
where
    G: Fn(&str, &str, GetOpts) -> Result<Response, SourceError>,
{
    let t0 = Instant::now();
    let (mut requests, mut bytes) = (0u64, 0u64);
    let cur: Map<String, Value> = state::load_json(CURSOR).unwrap_or_default();
    let store: Option<Store> = state::load_json(STORE);
    let key = api_key();
    let headers_kv = [("apiKey", key.as_str())];
    let headers: &[(&str, &str)] = if key.is_empty() { &[] } else { &headers_kv };

    let last_mod_end = cur.get("last_mod_end").and_then(Value::as_str).filter(|s| !s.is_empty());
    let (lo, mut store, mut params, mode) = match (store, last_mod_end) {
        (Some(store), Some(lme)) => {
            // Anything modified before the window start was also published before it, so
            // the lastMod range never reaches further back than start (<< 120-day cap).
            let prev = parse_iso(lme).ok_or_else(|| SourceError::new(format!("{NAME}: bad cursor last_mod_end {lme:?}")))?;
            let lo = start.max(prev - Duration::minutes(OVERLAP_MIN));
            (lo, store, vec![("lastModStartDate", nvd_time(lo)), ("lastModEndDate", nvd_time(end))], "lastMod")
        }
        // First run: the store only keeps CVEs published in the window, and pub* returns
        // exactly those (3.4k rows on 2026-11-03), where lastMod over 7 days returns 8.9k.
        _ => (start, Store::new(), vec![("pubStartDate", nvd_time(start)), ("pubEndDate", nvd_time(end))], "pub"),
    };
    params.push(("resultsPerPage", PAGE_SIZE.to_string()));

    let mut seen = 0usize;
    let mut done = false;
    for page in 0..MAX_PAGES {
        if page > 0 {
            std::thread::sleep(pause); // stay under 5 req / 30 s without a key
        }
        let idx = seen.to_string();
        let mut q: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        q.push(("startIndex", &idx));
        let r = get(URL, &format!("{NAME} page {page}"), GetOpts { headers, conditional: false, params: &q, max_bytes: MAX_PAGE_BYTES, ..Default::default() })?;
        requests += 1;
        bytes += r.content.len() as u64;
        let j: Value = r.json().map_err(|_| SourceError::new(format!("{NAME}: response is not JSON")))?;
        let vulns = arr(j.get("vulnerabilities"));
        for v in vulns {
            apply(&mut store, v.get("cve").unwrap_or(&Value::Null), start)?;
        }
        seen += vulns.len();
        if vulns.is_empty() || seen as u64 >= j.get("totalResults").and_then(Value::as_u64).unwrap_or(0) {
            done = true;
            break;
        }
    }
    if !done {
        return Err(SourceError::new(format!("{NAME}: more than {MAX_PAGES} pages of changes; page cap hit")));
    }

    let store: Store = store.into_iter()
        .filter(|(_, v)| v.get("published").and_then(Value::as_str).and_then(parse_iso).is_some_and(|p| p >= start))
        .collect();
    let mut stats = Map::new();
    stats.insert("requests".into(), requests.into());
    stats.insert("bytes".into(), bytes.into());
    stats.insert("mode".into(), mode.into());
    stats.insert("changed".into(), seen.into());
    stats.insert("items".into(), store.len().into());
    stats.insert("since".into(), iso_utc(lo).into());
    stats.insert("seconds".into(), json!((t0.elapsed().as_secs_f64() * 10.0).round() / 10.0));
    state::save_json(STORE, &store);
    state::save_json(CURSOR, &json!({"last_mod_end": iso_utc(end), "stats": stats}));

    let mut items = Vec::with_capacity(store.len());
    for (k, v) in store {
        items.push(serde_json::from_value::<Item>(v).map_err(|e| SourceError::new(format!("{NAME}: bad store entry {k}: {e}")))?);
    }
    items.sort_by(|a, b| (&b.published, &b.id).cmp(&(&a.published, &a.id)));
    Ok(FetchOutput { items, stats })
}

pub fn fetch(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    let pause = std::time::Duration::from_millis(if api_key().is_empty() { 6000 } else { 600 });
    fetch_with(start, end, &common::get, pause)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::TimeZone;

    use super::super::kev::testutil::*;
    use super::*;

    #[test]
    fn item() {
        let _t = state::testing::temp_state("nvd-item");
        let page = fixture_json("nvd_page.json");
        let i = to_item(&page["vulnerabilities"][0]["cve"]).unwrap().unwrap();
        assert_eq!((i.score, i.severity.as_str()), (7.5, "HIGH")); // NVD Primary row wins
        assert_eq!(i.published, "2026-10-28T16:15:42Z");
        assert_eq!(i.extra["vendors"], json!(["cisco"]));
        assert_eq!(i.title, "A vulnerability in Cisco Secure Firewall ASA could allow an unauthenticated, \
                             remote attacker to cause a reload.");
        assert!(to_item(&page["vulnerabilities"][2]["cve"]).unwrap().is_none());
        assert_eq!(nvd_time(start()), "2026-10-27T03:00:00.000+00:00");
    }

    #[test]
    fn incremental() {
        let _t = state::testing::temp_state("nvd-incremental");
        let page = fixture_json("nvd_page.json");
        let calls: Mutex<Vec<Vec<(String, String)>>> = Mutex::new(vec![]);
        let record = |o: &GetOpts| calls.lock().unwrap().push(o.params.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect());
        let fake = |_u: &str, _l: &str, o: GetOpts| {
            record(&o);
            Ok(ok_json(&page))
        };
        let items = fetch_with(start(), end(), &fake, std::time::Duration::ZERO).unwrap().items;
        assert_eq!(items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["CVE-2026-111464", "CVE-2026-76418"]);
        let p = |i: usize, k: &str| calls.lock().unwrap()[i].iter().find(|(a, _)| a == k).map(|x| x.1.clone());
        assert_eq!(p(0, "pubStartDate").as_deref(), Some("2026-10-27T03:00:00.000+00:00")); // first run
        assert_eq!(p(0, "lastModStartDate"), None);
        assert_eq!(p(0, "startIndex").as_deref(), Some("0"));

        let later = Utc.with_ymd_and_hms(2026, 11, 3, 5, 0, 0).unwrap();
        let empty = json!({"totalResults": 0, "vulnerabilities": []});
        let fake = |_u: &str, _l: &str, o: GetOpts| {
            record(&o);
            Ok(ok_json(&empty))
        };
        let items = fetch_with(start(), later, &fake, std::time::Duration::ZERO).unwrap().items;
        assert_eq!(items.len(), 2); // kept from the store
        assert_eq!(p(1, "lastModStartDate").as_deref(), Some("2026-11-03T02:45:00.000+00:00"));
    }

    /// Live, against a copy of state/: EW_STATE_COPY=<dir> cargo test -- --ignored live_state_copy --nocapture
    #[test]
    #[ignore]
    fn live_state_copy_nvd() {
        let _g = state::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        state::set_dir(std::env::var("EW_STATE_COPY").expect("EW_STATE_COPY"));
        let end = Utc::now();
        let out = fetch(end - Duration::days(7), end).unwrap();
        println!("LIVE nvd items={} stats={}", out.items.len(), Value::Object(out.stats));
    }
}
