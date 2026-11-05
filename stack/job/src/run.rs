//! One rebuild of the Cyber Threat Exploit Watch page.
//!
//! Pulls seven public feeds (see feeds/mod.rs), runs the triage step (see
//! triage/step.rs), rebuilds the table bodies and the counters on the page, and
//! writes the result back through the Wiki.js GraphQL API. Only the anchored
//! regions are replaced; prose, callouts and source cards stay hand-editable.
//! One run at a time per STATE_DIR: a run holds state/run.lock (see main below).
//!
//! Environment:
//!   WIKI_BASE         https://wiki2.internal.ediphy.io   (compose: http://wiki:3000)
//!   WIKI_PAGE_ID      51                                  (local bootstrap: 1)
//!   WIKIJS_API_KEY    Wiki.js API key          -> Authorization header
//!   IAP_ID_TOKEN      Google OIDC ID token     -> Proxy-Authorization header (only behind IAP)
//!   STATE_DIR         ./state                  caches, cursors, seen.json, runs.jsonl
//!   CVE_ROW_CAP       300                      rows shown in the CVE table
//!   HEARTBEAT_HOURS   24                       rewrite even without data changes after this long
//!   GITHUB_TOKEN      optional, raises the GitHub rate limit
//!   NVD_API_KEY       optional, raises the NVD rate limit
//!   COMPONENTS_FILE   stack/job/components.sample.toml   component list for the matcher
//!   LINEAR_MODE       off                      off | live
//!   LINEAR_API_KEY    live mode only: personal API key (lin_api_…, sent bare) or OAuth access token (sent as Bearer)
//!   LINEAR_TEAM_ID    live mode only: team whose Triage inbox receives issues
//!   LINEAR_API_URL    https://api.linear.app/graphql   live mode endpoint (compose lab: the linear-mock service)

use std::collections::HashMap;
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::time::Instant;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::feeds::common::{Fatal, Item, iso_utc, parse_iso};
use crate::feeds::{self, Feed, state};
use crate::render::{self, HealthRow, Regions, thousands};
use crate::{triage, wiki};

const WINDOW_DAYS: i64 = 7;

// Regions that change on every run without the data changing. They are left out
// of the "did anything change" fingerprint, otherwise every run writes a new
// page version (Wiki.js keeps them all).
const VOLATILE: &[&str] = &["t-health", "n-health", "winlabel"];

#[derive(clap::Args)]
pub struct Args {
    /// Build and diff, write nothing
    #[arg(long)]
    pub dry_run: bool,
    /// Render into stack/wiki/page/skeleton.html and save to FILE; no wiki
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Loop forever, one run every SECONDS
    #[arg(long, value_name = "SECONDS")]
    pub every: Option<u64>,
}

fn env_num<T: std::str::FromStr>(k: &str, default: T) -> T {
    std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

fn heartbeat() -> Duration {
    Duration::seconds((env_num("HEARTBEAT_HOURS", 24.0_f64) * 3600.0) as i64)
}

/// Whole-second duration as H:MM:SS, e.g. "6:00:00".
fn td_str(d: Duration) -> String {
    let s = d.num_seconds();
    format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

// ---------------------------------------------------------------- feeds

#[derive(Serialize, Deserialize)]
struct Cached {
    last_success: String,
    items: Vec<Item>,
}

fn load_cached(key: &str) -> Option<Cached> {
    state::load_json(&format!("items/{key}.json"))
}

fn newest(items: &[Item]) -> String {
    items.iter().map(|i| if i.updated.is_empty() { &i.published } else { &i.updated }).max().cloned().unwrap_or_default()
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<&str>().map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panic".into())
}

/// Fetch one feed module, honouring CADENCE and the failure policy.
/// Err only when a CORE feed fails.
fn fetch_one(feed: &Feed, start: DateTime<Utc>, end: DateTime<Utc>, now: DateTime<Utc>)
    -> Result<(Vec<Item>, HealthRow), Fatal> {
    let cached = load_cached(feed.key);
    let mut h = HealthRow {
        source: feed.name.into(),
        last_success: cached.as_ref().map(|c| c.last_success.clone()).unwrap_or_default(),
        ..Default::default()
    };
    let not_due = match (&cached, cached.as_ref().and_then(|c| parse_iso(&c.last_success))) {
        (Some(c), Some(last)) if feed.cadence > 0 && (now - last).num_seconds() < feed.cadence as i64 => Some((c, last)),
        _ => None,
    };
    let items;

    if let Some((c, last)) = not_due {
        items = c.items.clone();
        h.status = "cached".into();
        h.note = format!("Polled every {} h; next fetch after {}.", feed.cadence / 3600,
                         render::ftime(&iso_utc(last + Duration::seconds(feed.cadence as i64)), false));
    } else {
        // A bug in one feed must not blank the page: a panic counts as a failure of that feed.
        let res = catch_unwind(AssertUnwindSafe(|| (feed.fetch)(start, end)))
            .unwrap_or_else(|p| Err(crate::feeds::common::SourceError::new(
                format!("internal error: panic: {}", panic_text(p)))));
        match res {
            Ok(out) => {
                state::save_json(&format!("items/{}.json", feed.key),
                                 &Cached { last_success: iso_utc(now), items: out.items.clone() });
                h.status = "ok".into();
                h.last_success = iso_utc(now);
                h.note = feed_note(feed.key, &out.items, &out.stats);
                items = out.items;
            }
            Err(e) => {
                if feeds::CORE.contains(&feed.key) {
                    return Err(Fatal(format!("{}: {}", feed.name, e.message)));
                }
                eprintln!("  {}: {}", feed.name, e.message);
                h.status = if cached.is_some() { "stale" } else { "error" }.into();
                h.note = match &cached {
                    Some(c) => format!("Stale since {}: {}", render::ftime(&c.last_success, false), clip(&e.message, 200)),
                    None => clip(&e.message, 200),
                };
                items = cached.map(|c| c.items).unwrap_or_default();
            }
        }
    }
    h.items = items.len();
    h.newest = newest(&items);
    Ok((items, h))
}

/// One line for the health table: how this run got its data.
fn feed_note(key: &str, items: &[Item], st: &Map<String, Value>) -> String {
    let n = |k: &str| st.get(k).map(|v| match v { Value::String(s) => s.clone(), v => v.to_string() })
        .unwrap_or_else(|| "0".into());
    match key {
        "kev" if !items.is_empty() => {
            let via = items[0].x("via");
            format!("Read from {via}.{}", if via != "cisa.gov" { " cisa.gov refused the request." } else { "" })
        }
        "cvelist" => format!("{}: {} changed records, {} requests.",
                             st.get("mode").and_then(Value::as_str).unwrap_or(""), n("changed"), n("requests")),
        "nvd" => "Enrichment only: adds NVD scores to CVE.org records; polled every 2 h.".into(),
        "github" => format!("{} requests.", n("requests")),
        _ => String::new(),
    }
}

/// KEV + EUVD on one row per CVE. CISA rows win (they carry the due date).
fn merge_exploited(kev: &[Item], euvd: &[Item]) -> Vec<Item> {
    let mut rows: Vec<Item> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for it in kev {
        let mut it = it.clone();
        it.extra.insert("sources".into(), json!([it.source]));
        at.insert(it.id.clone(), rows.len());
        rows.push(it);
    }
    for it in euvd {
        if let Some(&i) = at.get(&it.id) {
            let k = &mut rows[i];
            if let Some(Value::Array(s)) = k.extra.get_mut("sources") {
                s.push(json!(it.source));
            }
            for f in ["euvd_id", "exploited_since"] {
                if !k.extra.contains_key(f) {
                    k.extra.insert(f.into(), it.extra.get(f).cloned().unwrap_or(json!("")));
                }
            }
        } else {
            let mut it = it.clone();
            it.extra.insert("sources".into(), json!([it.source]));
            at.insert(it.id.clone(), rows.len());
            rows.push(it);
        }
    }
    rows
}

/// Add NVD's score to CVE.org records; fill the score where the CNA and CISA ADP gave none.
fn enrich_cves(cves: &[Item], nvd: &[Item]) -> Vec<Item> {
    let by_id: HashMap<&str, &Item> = nvd.iter().map(|i| (i.id.as_str(), i)).collect();
    cves.iter().map(|it| {
        let mut it = it.clone();
        if let Some(n) = by_id.get(it.id.as_str()).filter(|n| n.score != 0.0) {
            it.extra.insert("nvd_score".into(), json!(n.score));
            if it.score == 0.0 {
                it.score = n.score;
                it.severity = n.severity.clone();
                it.extra.insert("score_source".into(), json!("NVD"));
                if !it.extra.contains_key("vector") {
                    it.extra.insert("vector".into(), n.extra.get("vector").cloned().unwrap_or(json!("")));
                }
                if !n.x_list("vendors").is_empty() && it.x_list("vendors").is_empty() {
                    it.extra.insert("vendors".into(), n.extra["vendors"].clone());
                }
            }
        }
        it
    }).collect()
}

/// Minutes from first publication to `now` for each item new on this run. Only
/// `published` counts, never `updated`: a revision is not a new publication.
/// Date-only values (KEV dateAdded) give no sample. A feed's first run is its
/// baseline: everything is "new" but was published days ago, so it gives none either.
fn lags(items: &[Item], is_new: impl Fn(&Item) -> bool, baseline: bool, now: DateTime<Utc>) -> Vec<f64> {
    if baseline {
        return Vec::new();
    }
    items.iter()
        .filter(|i| is_new(i) && i.published.trim().len() > 10)
        .filter_map(|i| parse_iso(&i.published))
        .map(|t| (now - t).num_milliseconds() as f64 / 60_000.0)
        .collect()
}

/// (max, median) of the lags, one decimal; (None, None) when there are none.
fn lag_summary(lags: &[f64]) -> (Option<f64>, Option<f64>) {
    let mut v = lags.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n == 0 {
        return (None, None);
    }
    let median = if n.is_multiple_of(2) { (v[n / 2 - 1] + v[n / 2]) / 2.0 } else { v[n / 2] };
    let r1 = |x: f64| (x * 10.0).round() / 10.0;
    (Some(r1(v[n - 1])), Some(r1(median)))
}

/// Record first_seen for every item the page carries; per feed, how late new items
/// were (a metric, not a pass/fail rule). NVD only enriches CVE.org rows and has
/// no rows of its own.
fn lag_stats(fs: &[Feed], tables: &[Vec<Item>], health: &[HealthRow], now: DateTime<Utc>) -> Map<String, Value> {
    let seen_before = state::seen();
    let mut out = Map::new();
    for ((feed, items), h) in fs.iter().zip(tables).zip(health) {
        let src = &h.source;
        if feed.key == "nvd" {
            out.insert(src.clone(), json!({"status": h.status, "items": items.len(), "lag": "n/a (enrichment only)"}));
            continue;
        }
        let prefix = format!("{src}:");
        let baseline = !seen_before.keys().any(|k| k.starts_with(&prefix));
        let new = state::mark_seen(items.iter().map(Item::key), now, 30);
        let (max, median) = lag_summary(&lags(items, |i| new.contains_key(&i.key()), baseline, now));
        out.insert(src.clone(), json!({
            "status": h.status, "items": items.len(), "new": new.len(), "baseline": baseline,
            "lag_max_min": max, "lag_median_min": median,
        }));
    }
    out
}

// ---------------------------------------------------------------- fingerprint

/// The page with the regions that change on every run (VOLATILE and the stamp)
/// emptied, so two pages compare equal when they carry the same data.
fn without_volatile(html: &str) -> Result<String, Fatal> {
    let blank = |ids: &[String]| -> Vec<(String, String)> {
        ids.iter().filter(|id| VOLATILE.contains(&id.as_str())).map(|id| (id.clone(), String::new())).collect()
    };
    let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let r = Regions {
        tbody: blank(&ids(&render::TBODY_IDS)),
        text: blank(&ids(&render::TEXT_IDS)),
        stamp: String::new(),
    };
    render::apply_regions(html, &r)
}

/// sha256 hex of the regions that carry data, plus each feed's status. Stored in
/// state/wiki.json; an equal fingerprint means there is nothing new to write.
fn fingerprint(regions: &Regions, health: &[HealthRow]) -> String {
    let pick = |v: &[(String, String)]| -> Map<String, Value> {
        v.iter().filter(|(k, _)| !VOLATILE.contains(&k.as_str())).map(|(k, x)| (k.clone(), json!(x))).collect()
    };
    let stable = json!({
        "tbody": pick(&regions.tbody),
        "text": pick(&regions.text),
        // Health statuses count (a feed going stale is news); their timestamps don't.
        "health": health.iter().map(|h| json!([h.source, h.status])).collect::<Vec<_>>(),
    });
    // serde_json::Map is a BTreeMap (no preserve_order feature), so object keys are serialised sorted.
    let s = serde_json::to_string(&stable).expect("JSON value");
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ---------------------------------------------------------------- wiki

const READ_PAGE: &str = r#"
query ($id: Int!) {
  pages { single(id: $id) { content title description tags { tag } } }
}
"#;

// Note: do NOT request `page { ... }` in the mutation response. Page.editor is
// non-nullable and serialises to null here, which surfaces as a GraphQL error
// even though the write succeeded. scriptCss is not sent: the job's key has no
// write:styles, so Wiki.js keeps the hand-written CSS.
const WRITE_PAGE: &str = r#"
mutation ($id: Int!, $content: String!, $tags: [String]!, $title: String!, $desc: String!) {
  pages {
    update(id: $id, content: $content, tags: $tags, title: $title,
           description: $desc, isPublished: true) {
      responseResult { succeeded errorCode message }
    }
  }
}
"#;

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

// ---------------------------------------------------------------- main

fn run(args: &Args) -> Result<(), Fatal> {
    let t0 = Instant::now();
    let now = state::utcnow();
    let (end, start) = (now, now - Duration::days(WINDOW_DAYS));
    println!("window {} -> {}", iso_utc(start), iso_utc(end));

    let fs = feeds::all();
    let mut got: HashMap<&str, Vec<Item>> = HashMap::new();
    let mut health = Vec::new();
    for f in &fs {
        let (items, h) = fetch_one(f, start, end, now)?;
        println!("  {:<18} {:<8} {:>5}  {}", h.source, h.status, h.items, clip(&h.note, 90));
        got.insert(f.key, items);
        health.push(h);
    }
    if got.values().all(Vec::is_empty) {
        return Err(Fatal("every feed came back empty — refusing to publish an empty brief".into()));
    }

    let g = |k: &str| got.get(k).cloned().unwrap_or_default();
    let exploited = merge_exploited(&g("kev"), &g("euvd"));
    let cves = enrich_cves(&g("cvelist"), &g("nvd"));
    let adv: Vec<Item> = g("certeu").into_iter().chain(g("ncscnl")).collect();
    let catalog = g("kev").first().map(|i| i.x("catalog_version").to_string()).unwrap_or_default();

    // FR-A2/A3: every item the page lists goes through the matcher. NVD only adds
    // scores, so it is left out; KEV and EUVD are triaged as published, unmerged.
    let to_triage: Vec<Item> = [g("kev"), g("euvd"), cves.clone(), g("github"), adv.clone()].concat();
    let writing = !args.dry_run && args.out.is_none();
    let triage = triage::step::step(&to_triage, &cves, now, writing);

    let regions = render::build_regions(&exploited, &adv, &g("github"), &cves, &health,
                                        &triage.view, start, end, now, &catalog, env_num("CVE_ROW_CAP", 300usize));
    let fp = fingerprint(&regions, &health);

    let mut record = Map::new();
    record.insert("run_at".into(), json!(iso_utc(now)));
    record.insert("mode".into(), json!(mode(args)));
    let last: Value = state::load_json("wiki.json").unwrap_or(json!({}));
    let result;

    if let Some(out) = &args.out {
        let skel = std::fs::read_to_string(render::SKELETON_PATH)
            .map_err(|e| Fatal(format!("cannot read {}: {e}", render::SKELETON_PATH)))?;
        let doc = render::apply_regions(&skel, &regions)?;
        std::fs::write(out, &doc).map_err(|e| Fatal(format!("cannot write {}: {e}", out.display())))?;
        println!("wrote {} ({} bytes)", out.display(), thousands(doc.chars().count()));
        result = "out";
    } else {
        let page_id: i64 = env_num("WIKI_PAGE_ID", 51);
        let data = wiki::gql_bot(READ_PAGE, json!({"id": page_id}))?;
        let page = &data["pages"]["single"];
        let content = s(page, "content");
        let doc = render::apply_regions(content, &regions)?;
        let written_at = s(&last, "written_at");
        let due = parse_iso(written_at).is_none_or(|w| now - w >= heartbeat());
        // The page may no longer carry the last written data: `bootstrap --reseed`
        // empties every table, and anyone can edit the page by hand. Compare what is
        // on the page with what would be written, ignoring the per-run regions.
        let page_stale = without_volatile(content)? != without_volatile(&doc)?;
        if fp == s(&last, "fingerprint") && !due && !page_stale {
            println!("no data change since {written_at} — skipping write");
            result = "unchanged";
        } else if doc == content {
            println!("page already identical — skipping write");
            result = "unchanged";
        } else {
            let reason = if fp != s(&last, "fingerprint") { "data changed".to_string() }
                         else if page_stale { "page does not carry the current data (reseeded or edited)".to_string() }
                         else { format!("heartbeat ({})", td_str(heartbeat())) };
            println!("content {} -> {} bytes ({reason})", thousands(content.chars().count()), thousands(doc.chars().count()));
            if args.dry_run {
                println!("dry run: not writing");
                result = "would-write";
            } else {
                let tags: Vec<Value> = page["tags"].as_array().map(|a| a.iter().map(|t| t["tag"].clone()).collect())
                    .unwrap_or_default(); // required: the resolver maps over it
                let res = wiki::gql_bot(WRITE_PAGE, json!({
                    "id": page_id, "content": doc, "tags": tags,
                    "title": s(page, "title"), "desc": s(page, "description"),
                }))?;
                let rr = &res["pages"]["update"]["responseResult"];
                if rr["succeeded"] != json!(true) {
                    return Err(Fatal(format!("Wiki.js refused the write: {}", s(rr, "message"))));
                }
                println!("written: {}", s(rr, "message"));
                state::save_json("wiki.json", &json!({"fingerprint": fp, "written_at": iso_utc(now),
                                                      "bytes": doc.chars().count()}));
                result = "written";
            }
        }
        record.insert("bytes".into(), json!(doc.chars().count()));
    }
    record.insert("result".into(), json!(result));

    // first_seen is only recorded once the page carries the item (or already did).
    let feeds_rec = if result == "written" || result == "unchanged" {
        let tables: Vec<Vec<Item>> = fs.iter().map(|f| g(f.key)).collect();
        lag_stats(&fs, &tables, &health, now)
    } else {
        health.iter().map(|h| (h.source.clone(), json!({"status": h.status, "items": h.items}))).collect()
    };
    record.insert("feeds".into(), Value::Object(feeds_rec));
    record.insert("triage".into(), triage.record);
    record.insert("seconds".into(), json!((t0.elapsed().as_secs_f64() * 10.0).round() / 10.0));
    state::append_run(&Value::Object(record));
    Ok(())
}

/// Exit code of a single run that found another run in progress (sysexits
/// EX_TEMPFAIL): nothing was done, try again later. A failed run exits 1.
pub const EXIT_LOCKED: i32 = 75;

fn mode(args: &Args) -> &'static str {
    if args.dry_run { "dry-run" } else if args.out.is_some() { "out" } else { "write" }
}

/// Take the state lock for one run. When another run holds it, print who,
/// append a `locked` line to runs.jsonl (the only write) and return None.
fn lock_or_skip(args: &Args) -> Result<Option<state::RunLock>, Fatal> {
    let now = state::utcnow();
    match state::lock_run(now)? {
        Ok(lock) => Ok(Some(lock)),
        Err(holder) => {
            let msg = format!("another run holds {}/run.lock ({holder}); this run did nothing",
                              state::dir().display());
            eprintln!("LOCKED: {msg}");
            state::append_run(&json!({"run_at": iso_utc(now), "mode": mode(args), "result": "locked", "error": clip(&msg, 300)}));
            Ok(None)
        }
    }
}

/// Every run, with or without --dry-run or --out, writes state (feed caches,
/// cursors, runs.jsonl), so each one holds the lock; each --every iteration
/// takes it afresh, so a manual run can slot in between two loop runs.
pub fn main(args: Args) -> Result<i32, Fatal> {
    let Some(every) = args.every else {
        let Some(_lock) = lock_or_skip(&args)? else {
            return Ok(EXIT_LOCKED);
        };
        run(&args)?;
        return Ok(0);
    };
    let fatal = |e: Fatal| {
        eprintln!("FATAL: {e}");
        state::append_run(&json!({"run_at": iso_utc(state::utcnow()), "result": "fatal", "error": e.0}));
    };
    loop {
        let started = Instant::now();
        match lock_or_skip(&args) {
            Ok(None) => {} // logged and recorded; try again next interval
            Err(e) => fatal(e),
            // The guard lives to the end of this arm, so a fatal or crash line is
            // also written under the lock. Unwinding from a panic drops it as well.
            Ok(Some(_lock)) => match catch_unwind(AssertUnwindSafe(|| run(&args))) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => fatal(e),
                Err(p) => {
                    // Keep the loop alive; the log shows what happened.
                    let msg = panic_text(p);
                    eprintln!("CRASH: {msg}");
                    state::append_run(&json!({"run_at": iso_utc(state::utcnow()), "result": "crash", "error": clip(&msg, 300)}));
                }
            },
        }
        let _ = std::io::stdout().flush();
        let left = every.saturating_sub(started.elapsed().as_secs());
        std::thread::sleep(std::time::Duration::from_secs(left));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(src: &str, id: &str) -> Item {
        Item::new(src, id, "u", "t", "2026-11-03")
    }

    #[test]
    fn fingerprint_follows_data_not_volatile_regions() {
        let regions = |kev: &str, win: &str| Regions {
            tbody: vec![("t-health".into(), win.into()), ("t-kev".into(), kev.into())],
            text: vec![("winlabel".into(), win.into()), ("s-kev".into(), "1".into())],
            stamp: win.into(),
        };
        let health = |status: &str| vec![HealthRow { source: "CISA KEV".into(), status: status.into(), ..Default::default() }];
        let a = fingerprint(&regions("<tr>CVE-1</tr>", "06:03"), &health("ok"));
        assert_eq!(a.len(), 64);
        assert_eq!(a, fingerprint(&regions("<tr>CVE-1</tr>", "06:33"), &health("ok")));
        assert_ne!(a, fingerprint(&regions("<tr>CVE-2</tr>", "06:03"), &health("ok")));
        assert_ne!(a, fingerprint(&regions("<tr>CVE-1</tr>", "06:03"), &health("stale")));
        // Keys are serialised in sorted order, whatever order the map was built in.
        assert_eq!(serde_json::to_string(&json!({"b": 1, "a": {"z": 0, "y": 0}})).unwrap(), r#"{"a":{"y":0,"z":0},"b":1}"#);
    }

    #[test]
    fn merge_keeps_cisa_row_and_adds_sources() {
        let mut e = item("ENISA EUVD", "CVE-1");
        e.extra.insert("euvd_id".into(), json!("EUVD-1"));
        let rows = merge_exploited(&[item("CISA KEV", "CVE-1")], &[e, item("ENISA EUVD", "CVE-2")]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].source, "CISA KEV");
        assert_eq!(rows[0].extra["sources"], json!(["CISA KEV", "ENISA EUVD"]));
        assert_eq!(rows[0].extra["euvd_id"], json!("EUVD-1"));
        assert_eq!(rows[0].extra["exploited_since"], json!(""));
        assert_eq!(rows[1].extra["sources"], json!(["ENISA EUVD"]));
    }

    #[test]
    fn enrich_fills_unscored_only() {
        let mut scored = item("CVE.org cvelistV5", "CVE-1");
        scored.score = 9.8;
        let unscored = item("CVE.org cvelistV5", "CVE-2");
        let mut n1 = item("NVD", "CVE-1");
        n1.score = 7.5;
        let mut n2 = item("NVD", "CVE-2");
        n2.score = 8.1;
        n2.severity = "HIGH".into();
        n2.extra.insert("vendors".into(), json!(["acme"]));
        let out = enrich_cves(&[scored, unscored], &[n1, n2]);
        assert_eq!((out[0].score, out[0].extra["nvd_score"].clone()), (9.8, json!(7.5)));
        assert_eq!((out[1].score, out[1].severity.as_str()), (8.1, "HIGH"));
        assert_eq!(out[1].extra["score_source"], json!("NVD"));
        assert_eq!(out[1].extra["vendors"], json!(["acme"]));
    }

    #[test]
    fn without_volatile_ignores_per_run_regions_only() {
        let page = |health: &str, kev: &str, win: &str, stamp: &str| format!(
            r#"<tbody id="t-health">{health}</tbody><tbody id="t-kev">{kev}</tbody><b id="winlabel">{win}</b><span id="n-health">x</span><div class="rstat" id="rstat">{stamp}</div>"#);
        let a = without_volatile(&page("<tr>ok 06:03</tr>", "<tr>CVE-1</tr>", "06:03", "Generated <b>06:03</b>")).unwrap();
        let b = without_volatile(&page("<tr>ok 06:33</tr>", "<tr>CVE-1</tr>", "06:33", "Generated <b>06:33</b>")).unwrap();
        let reseeded = without_volatile(&page("", "", "", "")).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, reseeded);
    }

    fn published(id: &str, published: &str, updated: &str) -> Item {
        let mut it = Item::new("CERT-EU", id, "u", "t", published);
        it.updated = updated.into();
        it
    }

    const NOW: &str = "2026-11-03T06:00:00Z";

    #[test]
    fn lag_uses_published_not_updated() {
        let now = parse_iso(NOW).unwrap();
        let revised = published("a", "2026-11-03T04:00:00Z", "2026-11-03T05:30:00Z");
        assert_eq!(lags(&[revised], |_| true, false, now), vec![120.0]);
    }

    #[test]
    fn lag_skips_date_only_and_seen_items() {
        let now = parse_iso(NOW).unwrap();
        let items = [
            published("date-only", "2026-11-03", ""),
            published("new", "2026-11-03T05:00:00Z", ""),
            published("seen", "2026-11-03T04:00:00Z", ""),
        ];
        assert_eq!(lags(&items, |i| i.id != "seen", false, now), vec![60.0]);
    }

    #[test]
    fn lag_skips_baseline() {
        let now = parse_iso(NOW).unwrap();
        assert!(lags(&[published("a", "2026-11-03T05:00:00Z", "")], |_| true, true, now).is_empty());
    }

    #[test]
    fn lag_summary_max_and_median() {
        assert_eq!(lag_summary(&[]), (None, None));
        assert_eq!(lag_summary(&[30.0, 5.0, 12.34]), (Some(30.0), Some(12.3)));
        assert_eq!(lag_summary(&[40.0, 10.0, 20.0, 35.0]), (Some(40.0), Some(27.5)));
        let rec = json!({"lag_max_min": lag_summary(&[]).0});
        assert_eq!(rec.to_string(), r#"{"lag_max_min":null}"#);
    }

    #[test]
    fn busy_lock_records_locked_and_writes_nothing_else() {
        let t = state::testing::temp_state("run-locked");
        let _held = state::lock_run(state::utcnow()).unwrap().ok().unwrap();
        let args = Args { dry_run: true, out: None, every: None };
        assert_eq!(main(args).unwrap(), EXIT_LOCKED);
        let runs = std::fs::read_to_string(t.dir.join("runs.jsonl")).unwrap();
        let rec: Value = serde_json::from_str(runs.trim()).unwrap();
        assert_eq!((rec["result"].as_str(), rec["mode"].as_str()), (Some("locked"), Some("dry-run")));
        assert!(s(&rec, "error").contains("\"pid\":"), "{rec}");
        let mut names: Vec<String> = std::fs::read_dir(&t.dir).unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, ["run.lock", "runs.jsonl"]);
    }

    #[test]
    fn helpers() {
        assert_eq!(td_str(Duration::hours(6)), "6:00:00");
        let mut a = item("A", "1");
        a.updated = "2026-11-03T04:00:00Z".into();
        assert_eq!(newest(&[a, item("A", "2")]), "2026-11-03T04:00:00Z");
    }
}
