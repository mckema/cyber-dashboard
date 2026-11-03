//! NCSC-NL security advisories, read as CSAF 2.0. Port of feeds/ncscnl.py.
//!
//! provider-metadata.json (/.well-known/csaf/) points at the directory
//! https://advisories.ncsc.nl/csaf/v2/. Its changes.csv (~71 KB, newest first)
//! lists every document once with the time of its latest revision, and supports
//! ETag, so most runs cost one 304. Each document is fetched once per
//! (path, timestamp); the parsed result is kept in cursors/ncscnl.json
//! ({path: {"ts": <changes.csv time>, "item": <Item>}}, same as the Python job).
//!
//! The RSS (https://advisories.ncsc.nl/rss/advisories, 25 items, titles like
//! "NCSC-2026-0464 [1.00] [M/H] …") carries the same data in a lossy form and is
//! not used.

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{self, FetchOutput, GetOpts, Item, Response, SourceError, iso_utc, severity_for};
use super::state;

pub const NAME: &str = "NCSC-NL";
pub const TABLE: &str = "adv";
pub const CADENCE: u64 = 0;

pub const BASE: &str = "https://advisories.ncsc.nl/csaf/v2/";
pub const CHANGES: &str = "https://advisories.ncsc.nl/csaf/v2/changes.csv";
pub const CURSOR: &str = "cursors/ncscnl.json";

static PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{4}/ncsc-\d{4}-\d{4,}\.json$").unwrap());

/// The RSS link (advisory?id=…) is a JavaScript redirect to this page; link it directly.
fn page(year: &str, id: &str) -> String {
    format!("https://advisories.ncsc.nl/{year}/{id}.html")
}

/// "Kans" / "Schade" note text -> H/M/L.
fn level(s: &str) -> Option<&'static str> {
    match s {
        "high" => Some("H"),
        "medium" => Some("M"),
        "low" => Some("L"),
        _ => None,
    }
}

/// The pluggable GET, so tests can serve fixtures. Production passes common::get.
pub type Getter<'a> = dyn FnMut(&str, &str, GetOpts) -> Result<Response, SourceError> + 'a;

// ---------------------------------------------------------------- python-compatible helpers
// (same as in certeu.rs; kept local so each module reads on its own)

fn is_py_ws(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// Python " ".join(s.split()).
fn squash(s: &str) -> String {
    s.split(is_py_ws).filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ")
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_ws)
}

/// Python repr() of a str.
fn py_repr(s: &str) -> String {
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

/// Python truthiness of a JSON value.
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

fn py_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// v[k] with the error repr Python's `except … as e: {e!r}` would print.
fn key<'a>(v: &'a Value, k: &str) -> Result<&'a Value, String> {
    match v {
        Value::Object(o) => o.get(k).ok_or_else(|| format!("KeyError({})", py_repr(k))),
        other => Err(format!("TypeError({})", py_repr(&format!("'{}' object is not subscriptable", py_type(other))))),
    }
}

fn key_str<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    let x = key(v, k)?;
    x.as_str().ok_or_else(|| format!("TypeError({})", py_repr(&format!("{k}: expected str, got {}", py_type(x)))))
}

/// `(v.get(k) or default)` for a dict-like value.
fn get_or<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.get(k).filter(|x| truthy(x))
}

// ---------------------------------------------------------------- parsing

/// changes.csv -> [(path, timestamp)]. Rows that are not CSAF document paths are skipped.
pub fn parse_changes(text: &str) -> Vec<(String, String)> {
    let mut rdr = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(text.as_bytes());
    let mut out = Vec::new();
    for row in rdr.records().flatten() {
        if row.len() >= 2 && PATH.is_match(py_strip(&row[0])) {
            out.push((py_strip(&row[0]).to_string(), py_strip(&row[1]).to_string()));
        }
    }
    out
}

/// product_tree.branches vendor -> product_name as "Vendor Product", without repeating the vendor.
pub fn products(tree: Option<&Value>) -> Vec<String> {
    fn walk(branches: Option<&Value>, vendor: &str, out: &mut Vec<String>) {
        for b in branches.and_then(Value::as_array).into_iter().flatten() {
            let cat = b.get("category").and_then(Value::as_str);
            let name = py_strip(b.get("name").and_then(Value::as_str).unwrap_or("")).to_string();
            match cat {
                Some("vendor") => walk(b.get("branches"), &name, out),
                Some("product_name") => {
                    let label = if vendor.is_empty() || name.to_lowercase().starts_with(&vendor.to_lowercase()) {
                        name
                    } else {
                        format!("{vendor} {name}")
                    };
                    if !out.contains(&label) {
                        out.push(label);
                    }
                }
                _ => walk(b.get("branches"), vendor, out),
            }
        }
    }
    let mut out = Vec::new();
    walk(tree.and_then(|t| t.get("branches")), "", &mut out);
    out
}

/// Python float() of a JSON value.
fn py_float(v: &Value) -> Result<f64, String> {
    match v {
        Value::Number(n) => Ok(n.as_f64().unwrap_or(0.0)),
        Value::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
        Value::String(s) => py_strip(s)
            .parse::<f64>()
            .map_err(|_| format!("ValueError({})", py_repr(&format!("could not convert string to float: {}", py_repr(s))))),
        other => Err(format!(
            "TypeError({})",
            py_repr(&format!("float() argument must be a string or a real number, not '{}'", py_type(other)))
        )),
    }
}

/// Highest CVSS base score in vulnerabilities[].scores. Documents that only carry a
/// CVSS 4.0 vector (as a note titled "CVSSV4") have no score here and yield 0.
pub fn max_score(vulns: &[Value]) -> Result<f64, String> {
    let mut best = 0.0_f64;
    for v in vulns {
        for s in get_or(v, "scores").and_then(Value::as_array).into_iter().flatten() {
            for k in ["cvss_v4", "cvss_v3", "cvss_v2"] {
                let x = match get_or(s, k).and_then(|c| get_or(c, "baseScore")) {
                    Some(b) => py_float(b)?,
                    None => 0.0,
                };
                if x > best {
                    best = x;
                }
            }
        }
    }
    Ok(best)
}

fn parse_time(tr: &Value, k: &str) -> Result<DateTime<Utc>, String> {
    let s = key_str(tr, k)?;
    common::parse_iso(s).ok_or_else(|| format!("ValueError({})", py_repr(&format!("Invalid isoformat string: {}", py_repr(s)))))
}

/// CSAF document -> Item. Err is the repr of the exception Python would raise.
pub fn parse_csaf(doc: &Value) -> Result<Item, String> {
    let d = key(doc, "document")?;
    let tr = key(d, "tracking")?;
    let tid = key_str(tr, "id")?;
    let mut notes: HashMap<String, String> = HashMap::new();
    for n in get_or(d, "notes").and_then(Value::as_array).into_iter().flatten() {
        let title = n.get("title").and_then(Value::as_str).unwrap_or("");
        let text = n.get("text").and_then(Value::as_str).unwrap_or("");
        notes.insert(title.to_string(), py_strip(text).to_string());
    }
    let empty = vec![];
    let vulns = get_or(doc, "vulnerabilities").and_then(Value::as_array).unwrap_or(&empty);
    let first = parse_time(tr, "initial_release_date")?;
    let latest = parse_time(tr, "current_release_date")?;
    let score = max_score(vulns)?;
    let mut cves: Vec<String> = Vec::new();
    for v in vulns {
        if let Some(c) = get_or(v, "cve").and_then(Value::as_str) {
            if !cves.iter().any(|x| x == c) {
                cves.push(c.to_string());
            }
        }
    }
    let year = tid.split('-').nth(1).ok_or_else(|| "IndexError('list index out of range')".to_string())?;
    let note = |k: &str| notes.get(k).cloned().unwrap_or_default();
    let lvl = |k: &str| {
        let t = note(k);
        level(&t.to_lowercase()).map(String::from).unwrap_or(t)
    };

    let mut extra = Map::new();
    extra.insert("version".into(), tr.get("version").cloned().unwrap_or_else(|| json!("")));
    extra.insert("products".into(), json!(products(doc.get("product_tree").filter(|t| truthy(t)))));
    extra.insert("probability".into(), json!(lvl("Kans")));
    extra.insert("impact".into(), json!(lvl("Schade")));
    extra.insert("summary".into(), json!(note("Feiten"))); // Dutch, one or two sentences

    let mut item = Item::new(
        NAME,
        tid,
        &page(year, &tid.to_lowercase()),
        &squash(get_or(d, "title").and_then(Value::as_str).unwrap_or("")),
        &iso_utc(first),
    );
    item.updated = if latest > first { iso_utc(latest) } else { String::new() };
    item.cves = cves;
    item.score = score;
    item.severity = severity_for(score).to_string();
    item.extra = extra;
    Ok(item)
}

// ---------------------------------------------------------------- fetch

pub fn fetch(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    fetch_with(start, end, &mut common::get)
}

pub fn fetch_with(start: DateTime<Utc>, end: DateTime<Utc>, get: &mut Getter) -> Result<FetchOutput, SourceError> {
    let rows = parse_changes(&get(CHANGES, &format!("{NAME} changes.csv"), GetOpts::default())?.text());
    if rows.is_empty() {
        return Err(SourceError::new(format!("{NAME}: changes.csv has no document rows; the CSAF layout may have changed")));
    }

    let cache: Map<String, Value> = state::load_json(CURSOR).unwrap_or_default();
    let mut keep = Map::new();
    let mut items = Vec::new();
    let result = (|| -> Result<(), SourceError> {
        for (path, ts) in &rows {
            let t = common::parse_iso(ts).ok_or_else(|| {
                SourceError::new(format!("{NAME}: changes.csv row {path} has a bad timestamp {}", py_repr(ts)))
            })?;
            if !(start <= t && t <= end) {
                continue; // the row time is the latest revision, so older rows cannot be in the window
            }
            // A cached record is used when its ts matches; one that does not read as an Item counts as a miss.
            let hit = cache
                .get(path)
                .filter(|rec| rec.get("ts").and_then(Value::as_str) == Some(ts.as_str()))
                .and_then(|rec| Some((rec.clone(), serde_json::from_value::<Item>(rec.get("item")?.clone()).ok()?)));
            let (rec, item) = match hit {
                Some(x) => x,
                None => {
                    // Our cursor is the cache, so no HTTP body cache (the Apple ones are ~300 KB).
                    let r = get(&format!("{BASE}{path}"), &format!("{NAME} {path}"), GetOpts { conditional: false, ..Default::default() })?;
                    let body = r.content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&r.content);
                    let item = serde_json::from_slice::<Value>(body)
                        .map_err(|e| format!("JSONDecodeError({})", py_repr(&e.to_string())))
                        .and_then(|doc| parse_csaf(&doc))
                        .map_err(|e| SourceError::new(format!("{NAME}: {path} is not a readable CSAF document: {e}")))?;
                    (json!({"ts": ts, "item": item}), item)
                }
            };
            keep.insert(path.clone(), rec);
            items.push(item);
        }
        Ok(())
    })();

    // On success keep only rows in the window; on failure keep everything, so
    // documents already fetched are not fetched again on the next run.
    if result.is_ok() {
        state::save_json(CURSOR, &keep);
    } else {
        let mut all = cache;
        all.extend(keep);
        state::save_json(CURSOR, &all);
    }
    result?;

    let k = |i: &Item| if i.updated.is_empty() { i.published.clone() } else { i.updated.clone() };
    items.sort_by(|a, b| k(b).cmp(&k(a)));
    Ok(items.into())
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::super::certeu::fake::{FakeGet, fixture, utc};
    use super::*;

    fn doc(name: &str) -> Value {
        serde_json::from_slice(&fixture(name)).unwrap()
    }

    // ------------------------------------------------ parse

    #[test]
    fn changes() {
        let text = String::from_utf8(fixture("ncscnl_changes.csv")).unwrap() + "\"index.txt\",\"x\"\n\n";
        let rows = parse_changes(&text);
        assert_eq!(rows.len(), 12);
        assert_eq!(rows[0], ("2026/ncsc-2026-0464.json".into(), "2026-11-02T09:17:50.006979+00:00".into()));
    }

    #[test]
    fn cvss4_only_document() {
        let i = parse_csaf(&doc("ncscnl_2026-0464.json")).unwrap();
        assert_eq!(i.id, "NCSC-2026-0464");
        assert_eq!(i.url, "https://advisories.ncsc.nl/2026/ncsc-2026-0464.html");
        assert_eq!(i.published, "2026-11-02T09:17:50Z");
        assert_eq!(i.updated, "");
        assert_eq!(i.cves, ["CVE-2026-112816"]);
        assert_eq!((i.score, i.severity.as_str()), (0.0, "")); // only a CVSS 4.0 vector note
        assert_eq!(i.x("probability"), "M");
        assert_eq!(i.x("impact"), "H");
        assert_eq!(i.extra["products"], json!(["Canonical LXD", "Debian lxd"]));
        assert_eq!(i.x("version"), "1.0.0");
        assert!(i.title.starts_with("Kwetsbaarheid verholpen in LXD"));
    }

    #[test]
    fn cvss3_and_vendor_not_repeated() {
        let i = parse_csaf(&doc("ncscnl_2026-0463.json")).unwrap();
        assert_eq!((i.score, i.severity.as_str()), (8.6, "HIGH"));
        let p = i.extra["products"].as_array().unwrap();
        assert!(!p.is_empty());
        assert!(!p.iter().any(|p| p.as_str().unwrap().starts_with("Cisco Cisco")));
    }

    #[test]
    fn revision() {
        let i = parse_csaf(&doc("ncscnl_2026-0455.json")).unwrap();
        assert_eq!(i.x("version"), "1.0.1");
        assert_eq!(i.published, "2026-10-27T08:05:01Z");
        assert_eq!(i.updated, "2026-10-28T14:17:59Z");
    }

    // ------------------------------------------------ fetch

    fn routes() -> FakeGet {
        FakeGet::new([
            (CHANGES.to_string(), Ok(fixture("ncscnl_changes.csv"))),
            (format!("{BASE}2026/ncsc-2026-0464.json"), Ok(fixture("ncscnl_2026-0464.json"))),
        ])
    }

    fn run(fake: &mut FakeGet, start: DateTime<Utc>) -> Result<Vec<Item>, SourceError> {
        fetch_with(start, utc(2026, 11, 3, 0), &mut |u: &str, l: &str, o: GetOpts| fake.call(u, l, o)).map(|o| o.items)
    }

    #[test]
    fn window_cache_and_revision() {
        let _t = state::testing::temp_state("ncscnl-cache");
        let start = utc(2026, 11, 1, 0);
        let mut fake = routes();
        let items = run(&mut fake, start).unwrap();
        assert_eq!(items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["NCSC-2026-0464"]);
        assert_eq!(fake.calls.len(), 2);
        assert_eq!(fake.conditional, [true, false]); // changes.csv conditional, document not
        fake.clear();
        let again = run(&mut fake, start).unwrap();
        assert_eq!(again, items);
        assert_eq!(fake.calls, [CHANGES]); // run 2: cursor hit
        // A new revision time in changes.csv makes the document be fetched again.
        let csv = String::from_utf8(fixture("ncscnl_changes.csv")).unwrap().replace("2026-11-02T09:17:50.006979", "2026-11-02T15:00:00.000000");
        fake.route(CHANGES, Ok(csv.into_bytes()));
        fake.clear();
        run(&mut fake, start).unwrap();
        assert_eq!(fake.calls.len(), 2);
    }

    #[test]
    fn document_failure_raises_and_keeps_progress() {
        let _t = state::testing::temp_state("ncscnl-fail");
        let mut fake = routes();
        fake.route(&format!("{BASE}2026/ncsc-2026-0463.json"), Err(SourceError::new("NCSC-NL 2026/ncsc-2026-0463.json: HTTP 503")));
        let err = run(&mut fake, utc(2026, 10, 30, 14)).unwrap_err();
        assert!(err.message.contains("HTTP 503"), "{err}");
        let cur: Map<String, Value> = state::load_json(CURSOR).unwrap();
        assert!(cur.contains_key("2026/ncsc-2026-0464.json"));
    }

    #[test]
    fn broken_document() {
        let _t = state::testing::temp_state("ncscnl-broken");
        let mut fake = routes();
        fake.route(&format!("{BASE}2026/ncsc-2026-0464.json"), Ok(br#"{"document": {}}"#.to_vec()));
        let err = run(&mut fake, utc(2026, 11, 1, 0)).unwrap_err();
        assert_eq!(err.message, "NCSC-NL: 2026/ncsc-2026-0464.json is not a readable CSAF document: KeyError('tracking')");
    }

    /// A cursor written by the Python job is a cache hit for the Rust job.
    #[test]
    fn python_cursor_is_a_hit() {
        let _t = state::testing::temp_state("ncscnl-pycursor");
        let item = parse_csaf(&doc("ncscnl_2026-0464.json")).unwrap();
        // Python writes score as 0.0 and keys in dataclass order; both read the same.
        let py = format!(
            r#"{{"2026/ncsc-2026-0464.json": {{"ts": "2026-11-02T09:17:50.006979+00:00", "item": {}}}}}"#,
            serde_json::to_string(&item).unwrap()
        );
        state::save_bytes(CURSOR, py.as_bytes());
        let mut fake = routes();
        let items = run(&mut fake, utc(2026, 11, 1, 0)).unwrap();
        assert_eq!(fake.calls, [CHANGES]);
        assert_eq!(items, [item]);
    }

    // ------------------------------------------------ parity / live (manual)

    /// PARITY_OUT=<dir> cargo test -- --ignored ncscnl::tests::parity_dump
    #[test]
    #[ignore]
    fn parity_dump() {
        let csv = String::from_utf8(fixture("ncscnl_changes.csv")).unwrap() + "\"index.txt\",\"x\"\n\n";
        let fetch_case = || {
            let _t = state::testing::temp_state("ncscnl-parity");
            let mut fake = routes();
            fake.route(&format!("{BASE}2026/ncsc-2026-0463.json"), Ok(fixture("ncscnl_2026-0463.json")));
            let items = run(&mut fake, utc(2026, 10, 30, 14)).unwrap();
            json!({"items": items, "cursor": state::load_json::<Value>(CURSOR), "calls": fake.calls})
        };
        super::super::certeu::fake::dump("ncscnl", &json!({
            "changes": parse_changes(&csv),
            "csaf": {
                "0455": parse_csaf(&doc("ncscnl_2026-0455.json")).unwrap(),
                "0463": parse_csaf(&doc("ncscnl_2026-0463.json")).unwrap(),
                "0464": parse_csaf(&doc("ncscnl_2026-0464.json")).unwrap(),
            },
            "fetch": fetch_case(),
        }));
    }

    /// EW_STATE_COPY=<copy of state/> cargo test -- --ignored ncscnl::tests::live_state_copy --nocapture
    #[test]
    #[ignore]
    fn live_state_copy() {
        super::super::certeu::fake::live_twice("ncscnl", fetch_with);
    }
}
