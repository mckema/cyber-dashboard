//! Monthly close (FR-A4, since 2026-11-06): freeze the final report of a month that
//! is over, upload its PDF to the wiki, draw the quality-check sample of
//! automatically ruled-out items and file a review reminder in Linear.
//!
//! One path, close_month(), shared by
//!   - `run` (writing runs, right after the month-to-date report): catch-up for the
//!     previous Amsterdam month, so the first writing run of a new month closes the
//!     last one; errors go to runs.jsonl (`close_month`) and never fail the run;
//!   - `report --close-month [--month YYYY-MM] [--now RFC3339]` (default: the month
//!     before now), which takes the run lock; production: a Cloud Scheduler trigger
//!     on the 1st at 06:00 Europe/Amsterdam runs it as a Cloud Run Job (not built).
//!
//! Steps, each done once and resumed on the next call when it failed:
//!   1. skip, with a reason, when the month is not over at `now`, when there is no
//!      event log or it starts after the month ends (generate()'s rule); when
//!      reports/<M>/frozen.json exists, go on with the steps still pending
//!   2. draw the sample (draw_sample) and generate Period::Month with it in the
//!      appendix ("Final monthly"); append report_frozen and sample_drawn to the
//!      event log, write review.json (the sample), then frozen.json {frozen_at,
//!      data_sha, pdf_sha, content_sha, marking, …}. From then on `report --month M`
//!      refuses to overwrite the folder (generate())
//!   3. upload report.pdf as the wiki asset report-YYYY-MM.pdf (upload.json records
//!      path, pdf_sha, time); retried while upload.json does not name this pdf_sha
//!   4. file the review reminder (TaskSpec, state type unstarted = Todo) with a
//!      UUID v4 saved in review.json before the first attempt; a lost answer is
//!      recovered by that id (Tracker::create_task); review.json then holds the
//!      issue and review_issue_created is logged. LINEAR_MODE=off: skipped
//!
//! The reminder is only a reminder: the job never reads it back and records no
//! approval; the PDF carries no review stamp. Nothing goes into triage.json.
//!
//! Quality-check sample (control for the automatic rule-out by name only): N
//! (REVIEW_SAMPLE_SIZE, default 10) of the month's `decided` events with decision
//! not-relevant-by-rule. Seed = sha256(month + "\n" + the sorted candidate keys
//! joined by "\n"), not data_sha (the report contains the sample); each key is
//! ranked by sha256(seed + "\n" + key) and the N lowest are taken, so a rerun or an
//! auditor gets the same list. Each item is enriched from triage.json while its
//! record is there (title, vendor / product, source link), else from its `decided`
//! event, else a link is built from the key.
//!
//! Environment (read through CloseOpts::var):
//!   EW_ENVIRONMENT             lab | test | production (default lab): data marking
//!   REVIEW_SAMPLE_SIZE         10
//!   WIKI_PUBLIC_URL            the page as the browser sees it: dashboard link; its
//!                              origin makes the PDF link absolute
//!   REPORT_REVIEW_ASSIGNEE_ID  Linear user id of the reviewer (default: none)
//!   REPORT_REVIEW_DUE_DAYS     due date: business days (Mon-Fri, Amsterdam) after the
//!                              month's last day (default: none)

use chrono::{DateTime, Datelike, NaiveDate, Utc, Weekday};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::model::{self, Ev, Log, REPORT_KEY_PREFIX};
use super::{Opts, Period, Renderer, build, environment_from, generate, sha_hex};
use crate::feeds::common::{Fatal, Item, iso_utc, parse_iso};
use crate::feeds::state;
use crate::triage::store::{EVENTS_FILE, event, to_amsterdam};
use crate::triage::tracker::{self, IssueRef, TaskSpec, Tracker, TrackerError, new_issue_id};

pub const FROZEN: &str = "frozen.json";
pub const REVIEW: &str = "review.json";
pub const UPLOAD: &str = "upload.json";
pub const DEFAULT_SAMPLE_SIZE: usize = 10;
/// Linear workflow state type of the reminder: Todo, not Triage.
pub const REVIEW_STATE_TYPE: &str = "unstarted";

fn rel(month: &str, file: &str) -> String {
    format!("reports/{month}/{file}")
}

/// Wiki asset name of a month's final PDF.
pub fn asset_name(month: &str) -> String {
    format!("cyber-threat-report-{month}.pdf")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// "2026-11" -> "November 2026" (the input as it is when it is not YYYY-MM).
pub fn month_title(month: &str) -> String {
    NaiveDate::parse_from_str(&format!("{month}-01"), "%Y-%m-%d").map(|d| d.format("%B %Y").to_string())
        .unwrap_or_else(|_| month.to_string())
}

/// The calendar month before the Amsterdam month `now` lies in.
pub fn previous_month(now: DateTime<Utc>) -> Period {
    let l = to_amsterdam(now).date();
    let (year, month) = if l.month() == 1 { (l.year() - 1, 12) } else { (l.year(), l.month() - 1) };
    Period::Month { year, month }
}

// ---------------------------------------------------------------- what the card reads

/// The review reminder of a closed month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewRef {
    pub identifier: String,
    pub url: String,
}

/// The newest closed month whose PDF is on the wiki (for the report card).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MonthlyUpload {
    /// "2026-10"
    pub month: String,
    /// "October 2026"
    pub title: String,
    /// Wiki asset path, "/exploit-watch/report-2026-10.pdf".
    pub path: String,
    pub pdf_sha: String,
    /// UTC RFC 3339.
    pub frozen_at: String,
    pub review: Option<ReviewRef>,
}

/// The newest month under state/reports/ with frozen.json and an upload.json for
/// the same pdf_sha. None before the first monthly close has uploaded its PDF.
pub fn latest_monthly() -> Option<MonthlyUpload> {
    let mut months: Vec<String> = std::fs::read_dir(state::dir().join("reports")).ok()?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| Period::parse_month(n).is_ok())
        .collect();
    months.sort();
    months.into_iter().rev().find_map(|m| {
        let frozen: Value = state::load_json(&rel(&m, FROZEN))?;
        let up: Value = state::load_json(&rel(&m, UPLOAD))?;
        let pdf_sha = s(&frozen, "pdf_sha");
        if s(&up, "path").is_empty() || pdf_sha.is_empty() || s(&up, "pdf_sha") != pdf_sha {
            return None;
        }
        let review = state::load_json::<Value>(&rel(&m, REVIEW))
            .and_then(|r| r.get("issue").filter(|i| i.is_object()).cloned())
            .map(|i| ReviewRef { identifier: s(&i, "identifier").into(), url: s(&i, "url").into() });
        Some(MonthlyUpload {
            title: month_title(&m), path: s(&up, "path").into(), pdf_sha: pdf_sha.into(),
            frozen_at: s(&frozen, "frozen_at").into(), review, month: m,
        })
    })
}

// ---------------------------------------------------------------- sample

/// Link to an item's public page, built from its key ("" when unknown).
pub fn key_link(key: &str) -> String {
    let Some((src, id)) = key.split_once(':') else { return String::new() };
    if id.starts_with("CVE-") {
        format!("https://www.cve.org/CVERecord?id={id}")
    } else if id.starts_with("EUVD-") {
        format!("https://euvd.enisa.europa.eu/vulnerability/{id}")
    } else if id.starts_with("GHSA-") || src.starts_with("GitHub") {
        format!("https://github.com/advisories/{id}")
    } else if src == "NCSC-NL" {
        let year = id.split('-').nth(1).unwrap_or("");
        format!("https://advisories.ncsc.nl/{year}/{}.html", id.to_lowercase())
    } else if src == "CERT-EU" {
        format!("https://cert.europa.eu/publications/security-advisories/{id}/")
    } else {
        String::new()
    }
}

/// "vendor / product" of an item: `vendor`/`product` (KEV, EUVD), else the first
/// three `vendors`/`products` (CVE.org, NCSC-NL) or ecosystem packages (GitHub).
fn vendor_product(it: &Item) -> String {
    let first3 = |k: &str| it.x_list(k).into_iter().take(3).collect::<Vec<_>>().join(", ");
    let vendor = if it.x("vendor").is_empty() { first3("vendors") } else { it.x("vendor").to_string() };
    let mut product = if it.x("product").is_empty() { first3("products") } else { it.x("product").to_string() };
    if product.is_empty() {
        product = first3("eco_packages");
    }
    [vendor, product].into_iter().filter(|x| !x.trim().is_empty()).collect::<Vec<_>>().join(" / ")
}

fn clip(s: &str, n: usize) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= n { s } else { s.chars().take(n - 1).collect::<String>().trim_end().to_string() + "…" }
}

fn sample_item(e: &Ev, triage: &Value) -> Value {
    let record = triage.get(&e.key).and_then(|r| r.get("item"))
        .and_then(|v| serde_json::from_value::<Item>(v.clone()).ok());
    let (title, vp, url, from) = match &record {
        Some(it) => (it.title.clone(), vendor_product(it), it.url.clone(), "triage.json"),
        None if !e.s("title").is_empty() => (e.s("title").to_string(), String::new(), e.s("url").to_string(), "event log"),
        None => (String::new(), String::new(), String::new(), "key"),
    };
    let url = if url.trim().is_empty() { key_link(&e.key) } else { url };
    let source = if e.s("item_source").is_empty() { e.key.split_once(':').map_or("", |(s, _)| s) } else { e.s("item_source") };
    json!({"key": e.key, "source": source, "first_seen": build::local(e.at), "title": clip(&title, 140),
           "vendor_product": vp, "url": url, "from": from})
}

/// The quality-check sample of a month (module doc): {size, candidates, seed,
/// method, note, items [{key, source, first_seen, title, vendor_product, url, from}]}.
pub fn draw_sample(log: &Log, month: &str, start: DateTime<Utc>, end: DateTime<Utc>, size: usize, triage: &Value) -> Value {
    let mut cands: Vec<&Ev> = log.events.iter()
        .filter(|e| e.kind == "decided" && e.s("decision") == "not-relevant-by-rule" && start <= e.at && e.at < end)
        .collect();
    let mut keys: Vec<&str> = cands.iter().map(|e| e.key.as_str()).collect();
    keys.sort_unstable();
    keys.dedup();
    let seed = sha_hex(format!("{month}\n{}", keys.join("\n")).as_bytes());
    let rank = |k: &str| sha_hex(format!("{seed}\n{k}").as_bytes());
    cands.sort_by_cached_key(|e| (rank(&e.key), e.key.clone()));
    cands.dedup_by(|a, b| a.key == b.key);
    cands.truncate(size);
    cands.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.key.cmp(&b.key)));
    let note = if keys.is_empty() {
        "No automatically ruled-out items in the period."
    } else if size == 0 {
        "Sampling is turned off (REVIEW_SAMPLE_SIZE=0)."
    } else {
        ""
    };
    json!({
        "size": size,
        "candidates": keys.len(),
        "seed": seed,
        "method": "sha256 of the month and the sorted candidate keys; the keys with the lowest sha256(seed + key) are drawn",
        "note": note,
        "items": cands.iter().map(|e| sample_item(e, triage)).collect::<Vec<_>>(),
    })
}

fn sample_size(var: &dyn Fn(&str) -> Option<String>) -> usize {
    var("REVIEW_SAMPLE_SIZE").and_then(|v| v.trim().parse().ok()).unwrap_or(DEFAULT_SAMPLE_SIZE)
}

// ---------------------------------------------------------------- review reminder

/// `n` Monday-to-Friday days after `d` (no holiday calendar); `d` itself for 0.
pub fn business_days_after(d: NaiveDate, n: u32) -> NaiveDate {
    let mut d = d;
    let mut left = n;
    while left > 0 {
        d = d.succ_opt().expect("date in range");
        if !matches!(d.weekday(), Weekday::Sat | Weekday::Sun) {
            left -= 1;
        }
    }
    d
}

/// "http://host:3000" of "http://host:3000/en/page"; None without a scheme.
fn origin(url: &str) -> Option<&str> {
    let i = url.find("://")? + 3;
    let host_end = url[i..].find('/').map_or(url.len(), |j| i + j);
    Some(&url[..host_end]).filter(|o| o.len() > i)
}

/// Markdown link text: no brackets (they would end the link).
fn md_text(s: &str) -> String {
    s.replace(['[', ']'], "").replace('\n', " ")
}

struct ReminderInput<'a> {
    month: &'a str,
    frozen: &'a Value,
    sample: &'a Value,
    asset_path: &'a str,
    test_run: bool,
}

/// The reminder issue (module doc): title, Markdown description, Todo, optional
/// assignee and due date.
fn reminder_spec(r: &ReminderInput, var: &dyn Fn(&str) -> Option<String>) -> TaskSpec {
    let title_month = month_title(r.month);
    let title = format!("{}Review monthly cyber threat report — {title_month}", if r.test_run { "[TEST] " } else { "" });
    let public = var("WIKI_PUBLIC_URL").map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    let path = if r.asset_path.is_empty() {
        format!("/{}/{}", crate::wiki::assets::ASSET_FOLDER, asset_name(r.month))
    } else {
        r.asset_path.to_string()
    };
    let pdf = match public.as_deref().and_then(origin) {
        Some(o) => format!("[{}]({o}{path})", asset_name(r.month)),
        None => format!("`{path}` on the wiki"),
    };
    let dashboard = match &public {
        Some(u) => format!("[Cyber Threat Dashboard]({u})"),
        None => "the Cyber Threat Dashboard page on the wiki".to_string(),
    };
    let mut d = String::new();
    if r.test_run {
        d += "**Test run** (`report --close-month --now`): not the real monthly close.\n\n";
    }
    d += &format!(
        "The final monthly cyber threat report for **{title_month}** has been generated and frozen \
         (document {}, data sha256 `{}`). This issue is a reminder only: the dashboard job does not read it back \
         and does not record who reviewed the report.\n\n",
        s(r.frozen, "document_id"), &s(r.frozen, "data_sha")[..s(r.frozen, "data_sha").len().min(12)]);
    d += &format!("- Dashboard: {dashboard}\n- Report PDF: {pdf}\n\n");
    d += "**Steps**\n\n\
          - [ ] Check the figures and the exceptions in the PDF against the dashboard\n\
          - [ ] Download the PDF\n\
          - [ ] Send it to the fairCT COO via the Shared Drive\n\
          - [ ] Close this issue\n\n";
    let items = r.sample["items"].as_array().cloned().unwrap_or_default();
    let candidates = r.sample["candidates"].as_u64().unwrap_or(0);
    d += "**Quality check sample — really not relevant?**\n\n";
    if items.is_empty() {
        let note = s(r.sample, "note");
        d += &format!("{}\n", if note.is_empty() { "No sample was drawn." } else { note });
    } else {
        d += &format!(
            "The dashboard job ruled out {candidates} items automatically in {title_month} because no component on the \
             list matched them (by name only; affected versions are not checked). {} of them were drawn at random \
             for a check; the PDF lists the same items in its appendix. Tick each item once checked. If one is \
             relevant to fairCT after all, add a comment on this issue naming it, so that the component list can \
             be completed.\n\n",
            items.len());
        for i in &items {
            let key = md_text(s(i, "key"));
            let link = if s(i, "url").is_empty() { key.clone() } else { format!("[{key}]({})", s(i, "url")) };
            let mut line = format!("- [ ] {link}");
            if !s(i, "title").is_empty() {
                line += &format!(" — {}", md_text(&clip(s(i, "title"), 100)));
            }
            if !s(i, "vendor_product").is_empty() {
                line += &format!(" · {}", md_text(s(i, "vendor_product")));
            }
            d += &line;
            d += "\n";
        }
    }
    let due_date = var("REPORT_REVIEW_DUE_DAYS").and_then(|v| v.trim().parse::<u32>().ok()).and_then(|n| {
        let first = NaiveDate::parse_from_str(&format!("{}-01", r.month), "%Y-%m-%d").ok()?;
        let next = if first.month() == 12 {
            NaiveDate::from_ymd_opt(first.year() + 1, 1, 1)?
        } else {
            NaiveDate::from_ymd_opt(first.year(), first.month() + 1, 1)?
        };
        Some(business_days_after(next.pred_opt()?, n))
    });
    TaskSpec {
        title,
        description: d,
        state_type: REVIEW_STATE_TYPE.into(),
        assignee_id: var("REPORT_REVIEW_ASSIGNEE_ID").map(|v| v.trim().to_string()).filter(|v| !v.is_empty()),
        due_date,
    }
}

// ---------------------------------------------------------------- close

/// What close_month needs from outside, so tests can stand in for each.
pub struct CloseOpts<'a> {
    /// Render the PDF (typst); off in tests unless `render` stands in.
    pub pdf: bool,
    pub render: Option<Renderer>,
    /// `--now` was given: marking at least TEST DATA, "[TEST] " title prefix.
    pub test_run: bool,
    /// Wiki asset upload: (file name, bytes) -> asset path (wiki::assets::upload_asset).
    pub upload: &'a mut dyn FnMut(&str, &[u8]) -> Result<String, Fatal>,
    /// The tracker (tracker::from_env): Ok(None) for LINEAR_MODE=off, Err for bad settings.
    pub tracker: Result<Option<Box<dyn Tracker>>, String>,
    /// Environment lookup (module doc).
    pub var: &'a dyn Fn(&str) -> Option<String>,
}

/// What one close_month call did (runs.jsonl `close_month`, stdout).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Closed {
    pub month: String,
    /// Why this call did not freeze the month: not over, no history, already frozen.
    pub skipped: String,
    /// This call froze the month.
    pub frozen: bool,
    pub frozen_at: String,
    pub marking: String,
    pub data_sha: String,
    pub pdf_sha: String,
    pub asset_path: String,
    /// This call uploaded the PDF.
    pub uploaded: bool,
    pub upload_error: Option<String>,
    pub sample: usize,
    pub candidates: usize,
    pub review: Option<IssueRef>,
    /// This call filed (or recovered) the reminder.
    pub review_created: bool,
    /// Why no reminder is filed (LINEAR_MODE=off).
    pub review_skipped: String,
    pub review_error: Option<String>,
    /// Events this call appended.
    pub events: Vec<String>,
}

impl Closed {
    pub fn has_error(&self) -> bool {
        self.upload_error.is_some() || self.review_error.is_some()
    }

    /// Done and nothing left to do: frozen earlier, PDF on the wiki, reminder filed or off.
    fn idle(&self) -> bool {
        self.skipped.starts_with("already frozen") && !self.uploaded && !self.review_created && !self.has_error()
    }

    /// The runs.jsonl entry: empty fields left out.
    pub fn record(&self) -> Value {
        fn put(m: &mut Map<String, Value>, k: &str, v: Value) {
            if !(v.is_null() || v == json!("") || v == json!(false) || v == json!([])) {
                m.insert(k.into(), v);
            }
        }
        let mut m = Map::new();
        put(&mut m, "month", json!(self.month));
        put(&mut m, "skipped", json!(self.skipped));
        if self.idle() || (!self.frozen && self.frozen_at.is_empty()) {
            return Value::Object(m);
        }
        put(&mut m, "frozen", json!(self.frozen));
        put(&mut m, "frozen_at", json!(self.frozen_at));
        put(&mut m, "marking", json!(self.marking));
        put(&mut m, "data_sha", json!(self.data_sha));
        put(&mut m, "pdf_sha", json!(self.pdf_sha));
        put(&mut m, "asset", json!(self.asset_path));
        put(&mut m, "uploaded", json!(self.uploaded));
        put(&mut m, "upload_error", json!(self.upload_error.as_deref().map(|e| clip(e, 300))));
        if self.frozen {
            m.insert("sample".into(), json!(self.sample));
            m.insert("candidates".into(), json!(self.candidates));
        }
        put(&mut m, "review", json!(self.review.as_ref().map(|r| &r.identifier)));
        put(&mut m, "review_created", json!(self.review_created));
        put(&mut m, "review_skipped", json!(self.review_skipped));
        put(&mut m, "review_error", json!(self.review_error.as_deref().map(|e| clip(e, 300))));
        put(&mut m, "events", json!(self.events));
        Value::Object(m)
    }

    /// One line per fact, for stdout.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!("close {}: {}", self.month,
                                   if self.skipped.is_empty() { "frozen now".to_string() } else { self.skipped.clone() })];
        if self.frozen {
            out.push(format!("  frozen at {}, marking {:?}, data_sha {}", self.frozen_at, self.marking, self.data_sha));
            out.push(format!("  sample: {} of {} automatically ruled-out items", self.sample, self.candidates));
        }
        if self.uploaded {
            out.push(format!("  uploaded {}", self.asset_path));
        }
        if let Some(e) = &self.upload_error {
            out.push(format!("  upload failed: {e}"));
        }
        if let (Some(r), true) = (&self.review, self.review_created) {
            out.push(format!("  review reminder {} {}", r.identifier, r.url));
        }
        if !self.review_skipped.is_empty() {
            out.push(format!("  review reminder: {}", self.review_skipped));
        }
        if let Some(e) = &self.review_error {
            out.push(format!("  review reminder failed: {e}"));
        }
        out
    }
}

fn report_event(kind: &str, month: &str, at: &str, part: &str, fields: Value) -> Value {
    event(kind, &format!("{REPORT_KEY_PREFIX}{month}"), at, &[part], state::utcnow(), "live", fields)
}

/// Close `period` (a calendar month) as of `now` (module doc). Err only for a
/// broken event log, a report that cannot be generated (e.g. no typst) or a month
/// that is not a calendar month; upload and tracker problems are in Closed.
pub fn close_month(period: &Period, now: DateTime<Utc>, o: &mut CloseOpts) -> Result<Closed, Fatal> {
    let Period::Month { .. } = period else {
        return Err(Fatal("close_month: needs a calendar month".into()));
    };
    let name = period.month_name(now);
    let mut out = Closed { month: name.clone(), ..Default::default() };

    let frozen = match state::load_json::<Value>(&rel(&name, FROZEN)) {
        Some(f) => {
            out.skipped = format!("already frozen at {}", s(&f, "frozen_at"));
            f
        }
        None => match freeze(period, &name, now, o, &mut out)? {
            Some(f) => f,
            None => return Ok(out),
        },
    };
    out.frozen_at = s(&frozen, "frozen_at").into();
    out.marking = s(&frozen, "marking").into();
    out.data_sha = s(&frozen, "data_sha").into();
    out.pdf_sha = s(&frozen, "pdf_sha").into();

    upload(&name, &frozen, now, o, &mut out);
    review(&name, &frozen, now, o, &mut out);
    Ok(out)
}

/// Step 2: Some(frozen.json) once frozen; None (out.skipped set) when the month
/// cannot be closed yet.
fn freeze(period: &Period, name: &str, now: DateTime<Utc>, o: &mut CloseOpts, out: &mut Closed)
    -> Result<Option<Value>, Fatal> {
    let (start, end) = period.bounds(now);
    if now < end {
        out.skipped = format!("{name} is not over (it ends {})", build::local(end));
        return Ok(None);
    }
    let Some(raw) = state::load_bytes(EVENTS_FILE) else {
        out.skipped = format!("no event log ({EVENTS_FILE}) yet");
        return Ok(None);
    };
    let log = model::read_events(&String::from_utf8_lossy(&raw))
        .map_err(|e| Fatal(format!("close {name}: {}/{EVENTS_FILE}: {e}", state::dir().display())))?;
    if end <= log.coverage_from {
        out.skipped = format!("the event log covers from {} only; no report for {name}", build::local(log.coverage_from));
        return Ok(None);
    }

    let triage: Value = state::load_json(crate::triage::store::FILE).unwrap_or(Value::Null);
    let sample = draw_sample(&log, name, start, end, sample_size(o.var), &triage);
    let g = generate(period, now, &Opts {
        pdf: o.pdf, tickets_as_of: None, environment: Some(environment_from(o.var)), test_run: o.test_run,
        sample: Some(sample.clone()), render: o.render,
    })?;
    let frozen_at = iso_utc(now);
    let marking = g.json["marking"]["label"].as_str().unwrap_or("").to_string();
    let frozen = json!({
        "month": name, "frozen_at": frozen_at, "status": g.json["document"]["status"],
        "document_id": g.json["document"]["id"], "data_sha": g.data_sha, "pdf_sha": g.pdf_sha,
        "content_sha": g.content_sha, "marking": marking, "test_run": o.test_run, "tickets_as_of": g.as_of,
    });
    let keys: Vec<&str> = sample["items"].as_array().into_iter().flatten().map(|i| s(i, "key")).collect();
    // Events first: a crash before frozen.json repeats them with equal ids (the data
    // and the sample do not change), and the report drops repeats.
    let events = [
        report_event("report_frozen", name, &frozen_at, &g.data_sha, json!({
            "data_sha": g.data_sha, "pdf_sha": g.pdf_sha, "content_sha": g.content_sha, "marking": marking,
            "document_id": g.json["document"]["id"], "test_run": o.test_run})),
        report_event("sample_drawn", name, &frozen_at, s(&sample, "seed"), json!({
            "size": sample["size"], "candidates": sample["candidates"], "seed": sample["seed"], "keys": keys})),
    ];
    state::append_jsonl(EVENTS_FILE, &events);
    out.events.extend(["report_frozen".to_string(), "sample_drawn".to_string()]);
    // review.json: the sample; an id or issue from an earlier freeze of this month is kept.
    let mut review: Value = state::load_json(&rel(name, REVIEW)).unwrap_or_else(|| json!({}));
    review["month"] = json!(name);
    review["sample"] = sample.clone();
    state::save_json(&rel(name, REVIEW), &review);
    state::save_json(&rel(name, FROZEN), &frozen);
    out.frozen = true;
    out.sample = sample["items"].as_array().map_or(0, Vec::len);
    out.candidates = sample["candidates"].as_u64().unwrap_or(0) as usize;
    Ok(Some(frozen))
}

/// Step 3: upload report.pdf unless upload.json already names this pdf_sha.
fn upload(name: &str, frozen: &Value, now: DateTime<Utc>, o: &mut CloseOpts, out: &mut Closed) {
    let pdf_sha = s(frozen, "pdf_sha");
    if pdf_sha.is_empty() {
        return; // frozen without a PDF (tests)
    }
    let last: Value = state::load_json(&rel(name, UPLOAD)).unwrap_or(Value::Null);
    if s(&last, "pdf_sha") == pdf_sha && !s(&last, "path").is_empty() {
        out.asset_path = s(&last, "path").into();
        return;
    }
    let bytes = match state::load_bytes(&rel(name, "report.pdf")) {
        Some(b) if sha_hex(&b) == pdf_sha => b,
        _ => {
            out.upload_error = Some(format!("{}/{} is missing or does not match {FROZEN}",
                                            state::dir().display(), rel(name, "report.pdf")));
            return;
        }
    };
    match (o.upload)(&asset_name(name), &bytes) {
        Ok(path) => {
            state::save_json(&rel(name, UPLOAD), &json!({"path": path, "pdf_sha": pdf_sha, "uploaded_at": iso_utc(now)}));
            out.asset_path = path;
            out.uploaded = true;
        }
        Err(e) => out.upload_error = Some(e.0),
    }
}

/// Step 4: the review reminder, once (module doc).
fn review(name: &str, frozen: &Value, now: DateTime<Utc>, o: &mut CloseOpts, out: &mut Closed) {
    let path = rel(name, REVIEW);
    let mut review: Value = state::load_json(&path).unwrap_or_else(|| json!({"month": name}));
    if !out.frozen {
        out.sample = review["sample"]["items"].as_array().map_or(0, Vec::len);
        out.candidates = review["sample"]["candidates"].as_u64().unwrap_or(0) as usize;
    }
    if let Some(i) = review.get("issue").filter(|i| i.is_object()) {
        out.review = Some(IssueRef { id: s(i, "id").into(), identifier: s(i, "identifier").into(), url: s(i, "url").into() });
        return;
    }
    let tracker = match &mut o.tracker {
        Err(e) => {
            out.review_error = Some(format!("tracker settings: {e}"));
            return;
        }
        Ok(None) => {
            out.review_skipped = "LINEAR_MODE=off: no review reminder filed".into();
            return;
        }
        Ok(Some(t)) => t,
    };
    let test_run = frozen.get("test_run").and_then(Value::as_bool).unwrap_or(false) || o.test_run;
    let sample = review.get("sample").cloned().unwrap_or(Value::Null);
    let spec = reminder_spec(&ReminderInput { month: name, frozen, sample: &sample, asset_path: &out.asset_path, test_run },
                             o.var);
    // The id is saved before the first attempt, so a lost answer is recovered by it.
    let mut retried = false;
    loop {
        let id = match review.get("create_id").and_then(Value::as_str).filter(|i| !i.is_empty()) {
            Some(id) => id.to_string(),
            None => {
                let id = new_issue_id();
                review["create_id"] = json!(id);
                state::save_json(&path, &review);
                id
            }
        };
        match tracker.create_task(&spec, &id) {
            Ok(r) => {
                review["issue"] = json!({"id": r.id, "identifier": r.identifier, "url": r.url});
                review["title"] = json!(spec.title);
                review["created_at"] = json!(iso_utc(now));
                state::save_json(&path, &review);
                state::append_jsonl(EVENTS_FILE, &[report_event("review_issue_created", name, &iso_utc(now), &r.id, json!({
                    "issue_id": r.id, "identifier": r.identifier, "url": r.url, "title": spec.title}))]);
                out.events.push("review_issue_created".into());
                out.review = Some(r);
                out.review_created = true;
                return;
            }
            // The id is taken by an issue Linear no longer returns (deleted): once more with a new id.
            Err(TrackerError::IdTaken(_)) if !retried => {
                retried = true;
                review["create_id"] = Value::Null;
            }
            Err(e) => {
                out.review_error = Some(e.to_string());
                return;
            }
        }
    }
}

// ---------------------------------------------------------------- live

/// close_month with the wiki upload, the tracker of LINEAR_MODE and the process
/// environment (run.rs and the CLI).
pub fn close_month_live(period: &Period, now: DateTime<Utc>, test_run: bool) -> Result<Closed, Fatal> {
    let mut upload = |name: &str, bytes: &[u8]| crate::wiki::assets::upload_asset(name, bytes);
    let var = |k: &str| std::env::var(k).ok();
    let mut o = CloseOpts {
        pdf: true, render: None, test_run, upload: &mut upload,
        tracker: tracker::from_env().map_err(|e| e.to_string()), var: &var,
    };
    close_month(period, now, &mut o)
}

/// Seconds between two lock attempts of `report --close-month`.
const LOCK_POLL_SECS: u64 = 10;

/// `report --close-month [--month M] [--now T]`: takes the run lock (waiting up to
/// LOCK_WAIT_SECONDS, default 900), closes the month, prints what it did and adds a
/// `mode: "close-month"` line to runs.jsonl. Exit 1 when the upload or the reminder
/// failed (a rerun resumes), 75 when the lock stayed busy.
pub fn main(month: Option<&str>, now: Option<&str>) -> Result<i32, Fatal> {
    let test_run = now.is_some();
    let now = match now {
        Some(t) => parse_iso(t).filter(|_| t.trim().len() > 10)
            .ok_or_else(|| Fatal(format!("report: --now must be an RFC 3339 time such as 2026-12-01T06:00:00Z, got {t:?}")))?,
        None => state::utcnow(),
    };
    let period = match month {
        Some(m) => Period::parse_month(m)?,
        None => previous_month(now),
    };
    let wait = std::env::var("LOCK_WAIT_SECONDS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(900u64);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait);
    let _lock = loop {
        match state::lock_run(state::utcnow())? {
            Ok(l) => break l,
            Err(holder) if std::time::Instant::now() < deadline => {
                println!("lock held ({holder}); trying again in {LOCK_POLL_SECS} s");
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                std::thread::sleep(left.min(std::time::Duration::from_secs(LOCK_POLL_SECS)));
            }
            Err(holder) => {
                eprintln!("LOCKED: another run holds {}/run.lock ({holder}); the month was not closed",
                          state::dir().display());
                return Ok(crate::run::EXIT_LOCKED);
            }
        }
    };
    let started = state::utcnow();
    let res = close_month_live(&period, now, test_run);
    let (result, rec) = match &res {
        Ok(c) => (if c.has_error() { "error" } else if c.frozen { "closed" } else { "skipped" }, c.record()),
        Err(e) => ("fatal", json!({"error": clip(&e.0, 300)})),
    };
    let mut line = json!({"run_at": iso_utc(started), "mode": "close-month", "result": result, "close_month": rec});
    if test_run {
        line["now"] = json!(iso_utc(now));
    }
    state::append_run(&line);
    let c = res?;
    for l in c.lines() {
        println!("{l}");
    }
    Ok(if c.has_error() { 1 } else { 0 })
}

#[cfg(test)]
mod tests;
