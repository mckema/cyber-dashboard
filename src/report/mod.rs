//! Internal resolution report (items triaged, actions taken, actions open), for a
//! calendar month or month to date, in Europe/Amsterdam time. Built from
//! state/triage-events.jsonl and state/runs.jsonl; written to
//! state/reports/<YYYY-MM | month-to-date>/ as report.json, report.pdf and SHA256SUMS.
//!
//! Interface fixed on 2026-11-05 so `run` (month-to-date PDF every writing run),
//! `serve` (refresh on click) and the `report` subcommand share one engine.
//!
//! Layout (one template and one build path for the monthly report and the month to
//! date, each fact once): page 1 summary for management (overall status
//! with a two-sentence bottom line, key figures with the previous month and a trend,
//! decisions and attention grouped by kind); page 2 the month in review (intake,
//! assessment, action backlog reconciliation, open actions, closed in the month,
//! waiting); appendix (quality-check sample of a closed month, feed health, tracker
//! errors, definitions, provenance and document control in one table).
//!
//!   model.rs    read the event log (tolerant) and runs.jsonl, replay per key; fill
//!               score/severity/exploited of older `decided` lines from triage.json
//!   build.rs    the report sections, KPIs, RAG status and their definitions
//!   pdf.rs      report.typ + data.json -> PDF/A-2b through the typst CLI
//!   close.rs    monthly close: freeze a finished month (frozen.json), upload its PDF,
//!               the quality-check sample and the review reminder in Linear
//!
//! Data marking (build::marking): EW_ENVIRONMENT = lab | test | production (default
//! lab). lab: "LAB DATA"; production: none; anything else: "TEST DATA". A test run of
//! the close (`--now`) in production is marked TEST DATA.
//!
//! Audience (audience()): REPORT_ORG names the organisation in the PDF header and
//! document control (default: none), REPORT_AUDIENCE is the distribution line
//! (default "Internal"), REPORT_TLP the TLP label on every page (default "TLP:AMBER").
//!
//! The report takes no lock: it only reads the event log (and triage.json for the
//! backfill), and a last line still being written is skipped (model::read_events). data_sha is the sha256 of
//! report.json without `generated_at`, serialised compact with sorted keys, so two
//! reports of equal data have equal data_sha.

mod build;
pub mod close;
mod model;
mod pdf;

#[allow(unused_imports)] // MonthlyUpload and ReviewRef: for the page's report card
pub use close::{MonthlyUpload, ReviewRef, latest_monthly};

use std::path::PathBuf;

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::feeds::common::{Fatal, iso_utc, parse_iso};
use crate::feeds::state;
use crate::triage::store::{EVENTS_FILE, from_amsterdam, to_amsterdam};

/// The period a report covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Period {
    /// A whole calendar month in Amsterdam time, e.g. 2026-11.
    Month { year: i32, month: u32 },
    /// From the first of the current Amsterdam month to `now`.
    MonthToDate,
}

impl Period {
    /// "2026-11" -> Month.
    pub fn parse_month(s: &str) -> Result<Self, Fatal> {
        let bad = || Fatal(format!("report: --month must be YYYY-MM, got {s:?}"));
        let (y, m) = s.trim().split_once('-').ok_or_else(bad)?;
        let (year, month) = (y.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
        if y.len() != 4 || m.len() != 2 || NaiveDate::from_ymd_opt(year, month, 1).is_none() {
            return Err(bad());
        }
        Ok(Self::Month { year, month })
    }

    /// [start, end) in UTC: Amsterdam midnight of the 1st to that of the next 1st,
    /// or to `now` for MonthToDate.
    pub fn bounds(&self, now: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
        let first = |y: i32, m: u32| from_amsterdam(NaiveDate::from_ymd_opt(y, m, 1).unwrap().and_hms_opt(0, 0, 0).unwrap());
        match *self {
            Self::Month { year, month } => {
                let (ny, nm) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
                (first(year, month), first(ny, nm))
            }
            Self::MonthToDate => {
                let l = to_amsterdam(now);
                (first(l.year(), l.month()), now)
            }
        }
    }

    /// YYYY-MM of the month the period lies in.
    pub fn month_name(&self, now: DateTime<Utc>) -> String {
        match *self {
            Self::Month { year, month } => format!("{year:04}-{month:02}"),
            Self::MonthToDate => to_amsterdam(now).format("%Y-%m").to_string(),
        }
    }

    /// Folder under state/reports/: YYYY-MM, or month-to-date (overwritten each time).
    pub fn dir_name(&self, now: DateTime<Utc>) -> String {
        match self {
            Self::Month { .. } => self.month_name(now),
            Self::MonthToDate => "month-to-date".into(),
        }
    }

    pub fn label(&self, now: DateTime<Utc>) -> String {
        match self {
            Self::Month { .. } => format!("Monthly report {}", self.month_name(now)),
            Self::MonthToDate => format!("On-demand snapshot {} (to {}) – not the official monthly report",
                                         self.month_name(now), to_amsterdam(now).format("%Y-%m-%d")),
        }
    }
}

/// Renders report.json (+ data_sha, tickets as of) to PDF bytes: pdf::render, or a
/// stand-in in tests (no typst there).
pub type Renderer = fn(&Value, &str, DateTime<Utc>) -> Result<Vec<u8>, Fatal>;

#[derive(Debug, Clone, Default)]
pub struct Opts {
    /// Render the PDF (needs the typst CLI). Off in unit tests.
    pub pdf: bool,
    /// "Tickets as of": when the tracker was last read back. None: the last writing
    /// run in runs.jsonl that got that far (run_at), up to the end of the period.
    pub tickets_as_of: Option<DateTime<Utc>>,
    /// EW_ENVIRONMENT (lab | test | production) for the data marking; None: read it
    /// from the environment (environment()).
    pub environment: Option<String>,
    /// REPORT_ORG / REPORT_AUDIENCE / REPORT_TLP; None: read them from the environment
    /// (audience()).
    pub audience: Option<Audience>,
    /// A test run with a set clock (`--close-month --now`): marked at least TEST DATA.
    pub test_run: bool,
    /// The quality-check sample (close.rs), printed in the appendix of a monthly report.
    pub sample: Option<Value>,
    /// None: pdf::render (the typst CLI).
    pub render: Option<Renderer>,
}

/// EW_ENVIRONMENT, trimmed and lowercased; unset or empty: "lab".
pub fn environment_from(var: &dyn Fn(&str) -> Option<String>) -> String {
    var("EW_ENVIRONMENT").map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty()).unwrap_or_else(|| "lab".into())
}

pub fn environment() -> String {
    environment_from(&|k| std::env::var(k).ok())
}

/// Who the report is for, printed in the PDF header, the TLP label and document control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audience {
    /// REPORT_ORG: organisation named in the report; "" (default): not named.
    pub org: String,
    /// REPORT_AUDIENCE: the distribution line (default "Internal").
    pub audience: String,
    /// REPORT_TLP: the TLP marking (default "TLP:AMBER").
    pub tlp: String,
}

impl Default for Audience {
    fn default() -> Self {
        Self { org: String::new(), audience: "Internal".into(), tlp: "TLP:AMBER".into() }
    }
}

/// REPORT_ORG, REPORT_AUDIENCE and REPORT_TLP, trimmed; unset or empty: the defaults.
pub fn audience_from(var: &dyn Fn(&str) -> Option<String>) -> Audience {
    let d = Audience::default();
    let get = |k: &str, default: String| var(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).unwrap_or(default);
    Audience { org: get("REPORT_ORG", d.org), audience: get("REPORT_AUDIENCE", d.audience), tlp: get("REPORT_TLP", d.tlp) }
}

pub fn audience() -> Audience {
    audience_from(&|k| std::env::var(k).ok())
}

/// What generate() produced.
#[derive(Debug, Clone, Default)]
pub struct Generated {
    /// The report data (report.json).
    pub json: Value,
    /// report.pdf when Opts::pdf.
    pub pdf: Option<Vec<u8>>,
    /// sha256 hex of report.json without its generated_at: equal data, equal sha.
    pub data_sha: String,
    /// sha256 hex of report.pdf ("" without a PDF).
    pub pdf_sha: String,
    /// "Tickets as of": the last tracker read-back the data includes (UTC ISO).
    pub as_of: String,
    /// "Monthly report 2026-11" or "On-demand snapshot 2026-11 (to <date>)".
    pub label: String,
    /// First moment the event log covers (its baseline); earlier periods are refused.
    pub coverage_from: String,
    /// Folder the files were written to (state/reports/<period>/).
    pub dir: PathBuf,
    /// sha256 of the report's content sections only (CONTENT_KEYS): unlike data_sha
    /// it does not move with the cut-off time or the run counts.
    pub content_sha: String,
    /// publish_month_to_date: the wiki asset path of the PDF the page links to ("" if
    /// none was ever uploaded), whether this call uploaded it, and the upload error.
    pub asset_path: String,
    pub asset_sha: String,
    pub uploaded: bool,
    pub upload_error: Option<String>,
}

/// The sections whose change makes a new month-to-date upload worth it. They do not
/// move with the hour (no run counts, no cut-off time, no durations); ages in whole
/// days and "over 1 business day" flags change at most once a day.
const CONTENT_KEYS: [&str; 12] = ["components", "status", "bottom_line", "attention", "kpis", "open_actions",
                                  "resolved", "outcomes", "funnel", "backlog", "waiting_items", "exceptions"];

/// sha256 of the content sections of report.json (CONTENT_KEYS).
pub fn content_sha(report: &Value) -> String {
    let picked: serde_json::Map<String, Value> =
        CONTENT_KEYS.iter().map(|k| (k.to_string(), report.get(*k).cloned().unwrap_or(Value::Null))).collect();
    sha_hex(&serde_json::to_vec(&picked).expect("json"))
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// sha256 of the report data without generated_at (compact, keys sorted: serde_json's
/// Map is a BTreeMap here).
pub fn data_sha(report: &Value) -> String {
    let mut v = report.clone();
    if let Value::Object(o) = &mut v {
        o.remove("generated_at");
    }
    sha_hex(&serde_json::to_vec(&v).expect("json"))
}

/// Build the report for `period` as of `now`, write it under state/reports/ and
/// return it. Err when the event log is missing or the period ends before its
/// coverage; a period that starts before it carries a coverage note.
pub fn generate(period: &Period, now: DateTime<Utc>, opts: &Opts) -> Result<Generated, Fatal> {
    if let Period::Month { .. } = period {
        let name = period.month_name(now);
        if let Some(f) = state::load_json::<Value>(&format!("reports/{name}/{}", close::FROZEN)) {
            return Err(Fatal(format!(
                "report: {}/reports/{name} is frozen ({} at {}); the final monthly report is not overwritten",
                state::dir().display(), close::FROZEN, f["frozen_at"].as_str().unwrap_or("?"))));
        }
    }
    let raw = state::load_bytes(EVENTS_FILE).ok_or_else(|| Fatal(format!(
        "report: {}/{EVENTS_FILE} not found; the event log is started by the first writing `run` (since 2026-11-05)",
        state::dir().display())))?;
    let mut log = model::read_events(&String::from_utf8_lossy(&raw))
        .map_err(|e| Fatal(format!("report: {}/{EVENTS_FILE}: {e}", state::dir().display())))?;
    let (start, end) = period.bounds(now);
    if end <= log.coverage_from {
        return Err(Fatal(format!(
            "report: {} ends at {} but the event log covers from {} only; no report for this period",
            period.month_name(now), build::local(end), build::local(log.coverage_from))));
    }
    let runs = model::read_runs(&String::from_utf8_lossy(&state::load_bytes("runs.jsonl").unwrap_or_default()));
    // Older `decided` lines lack score, severity and exploited: take them from triage.json.
    model::backfill(&mut log, &state::load_json::<Value>(crate::triage::store::FILE).unwrap_or(Value::Null));
    let list = crate::triage::components::load().ok().map(|c| (c.sha256.clone(), c.components.len()));
    let cut = end.min(now);
    let as_of = opts.tickets_as_of
        .or_else(|| runs.iter().filter(|r| r.read_back() && r.at <= cut).map(|r| r.at).max())
        .or_else(|| log.events.iter().filter_map(|e| parse_iso(e.s("ts"))).filter(|t| *t <= cut).max())
        .unwrap_or(log.coverage_from)
        .min(cut);

    let label = period.label(now);
    let environment = opts.environment.clone().unwrap_or_else(environment);
    let audience = opts.audience.clone().unwrap_or_else(audience);
    let mut data = build::build(&log, &runs, &build::Frame {
        start, end, cut, as_of, mtd: *period == Period::MonthToDate, list, environment, test_run: opts.test_run,
        audience,
    });
    data["label"] = json!(label);
    // UTC twin of tickets_as_of (local), read by `serve` to label the last PDF.
    data["as_of"] = json!(iso_utc(as_of));
    data["period"]["kind"] = json!(if *period == Period::MonthToDate { "month-to-date" } else { "month" });
    data["period"]["name"] = json!(period.month_name(now));
    if let (Some(s), Period::Month { .. }) = (&opts.sample, period) {
        data["review_sample"] = s.clone();
    }
    // The review reminder of a closed month, when review.json already names its issue
    // (the close files it after the freeze, so a first freeze does not have it yet).
    if let Period::Month { .. } = period {
        let review = state::load_json::<Value>(&format!("reports/{}/{}", period.month_name(now), close::REVIEW));
        if let Some(id) = review.as_ref().and_then(|r| r.pointer("/issue/identifier")).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            data["review_issue"] = json!(id);
        }
    }
    let data_sha = data_sha(&data);
    data["generated_at"] = json!(build::local(now));

    let render = opts.render.unwrap_or(pdf::render);
    let pdf = if opts.pdf { Some(render(&data, &data_sha, as_of)?) } else { None };
    let pdf_sha = pdf.as_deref().map(sha_hex).unwrap_or_default();

    let name = period.dir_name(now);
    let rel = |f: &str| format!("reports/{name}/{f}");
    let mut sums = String::new();
    if let Some(p) = &pdf {
        state::save_bytes(&rel("report.pdf"), p);
    } else {
        // A PDF from an earlier call would no longer match report.json.
        state::remove(&rel("report.pdf"));
    }
    state::save_json(&rel("report.json"), &data);
    let json_bytes = state::load_bytes(&rel("report.json")).unwrap_or_default();
    sums += &format!("{}  report.json\n", sha_hex(&json_bytes));
    if !pdf_sha.is_empty() {
        sums += &format!("{pdf_sha}  report.pdf\n");
    }
    state::save_bytes(&rel("SHA256SUMS"), sums.as_bytes());

    let content_sha = content_sha(&data);
    Ok(Generated {
        json: data, pdf, data_sha, pdf_sha, as_of: iso_utc(as_of), label,
        coverage_from: iso_utc(log.coverage_from),
        dir: state::dir().join("reports").join(name),
        content_sha,
        ..Default::default()
    })
}

/// Last upload of the month-to-date PDF (state/reports/month-to-date/upload.json).
const UPLOAD_FILE: &str = "reports/month-to-date/upload.json";
/// Upload again after this long even when the content did not change (ages, "as of").
const REUPLOAD_HOURS: i64 = 24;

/// The month-to-date report as linked from the dashboard: generate it with a PDF
/// (tickets as of `now`: callers have just read the tracker back) and upload the
/// PDF as a wiki asset when its content changed since the last upload, or that
/// upload is older than 24 h (state/reports/month-to-date/upload.json). An upload
/// error is returned in `upload_error`, not as Err: the PDF on disk is still good.
/// Shared by `run` and `serve`.
pub fn publish_month_to_date(now: DateTime<Utc>) -> Result<Generated, Fatal> {
    let mut g = generate(&Period::MonthToDate, now, &Opts { pdf: true, tickets_as_of: Some(now), ..Default::default() })?;
    let last: Value = state::load_json(UPLOAD_FILE).unwrap_or(Value::Null);
    let last_sha = last["content_sha"].as_str().unwrap_or("");
    let last_at = last["uploaded_at"].as_str().and_then(parse_iso);
    let stale = last_at.is_none_or(|t| now - t >= chrono::Duration::hours(REUPLOAD_HOURS));
    g.asset_path = last["path"].as_str().unwrap_or("").to_string();
    g.asset_sha = last_sha.to_string();
    if last_sha == g.content_sha && !stale && !g.asset_path.is_empty() {
        return Ok(g);
    }
    let pdf = g.pdf.clone().unwrap_or_default();
    match crate::wiki::assets::upload_asset(crate::wiki::assets::MTD_REPORT_NAME, &pdf) {
        Ok(path) => {
            state::save_json(UPLOAD_FILE, &json!({
                "path": path, "content_sha": g.content_sha, "pdf_sha": g.pdf_sha,
                "uploaded_at": iso_utc(now), "tickets_as_of": g.as_of,
            }));
            g.asset_path = path;
            g.asset_sha = g.content_sha.clone();
            g.uploaded = true;
        }
        Err(e) => g.upload_error = Some(e.0),
    }
    Ok(g)
}

/// The month-to-date PDF the wiki holds, from upload.json: (asset path, content
/// sha, tickets as of). None before the first upload.
pub fn uploaded() -> Option<(String, String, String)> {
    let v: Value = state::load_json(UPLOAD_FILE)?;
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    Some((s("path"), s("content_sha"), s("tickets_as_of"))).filter(|(p, _, _)| !p.is_empty())
}

#[derive(clap::Args)]
pub struct Args {
    /// Calendar month to report, YYYY-MM (Amsterdam time). With --close-month: the
    /// month to close (default: the month before --now).
    #[arg(long, conflicts_with = "month_to_date", required_unless_present_any = ["month_to_date", "close_month"])]
    pub month: Option<String>,
    /// From the first of this month to now.
    #[arg(long)]
    pub month_to_date: bool,
    /// Write report.json only, no PDF.
    #[arg(long)]
    pub no_pdf: bool,
    /// Close a finished month: freeze its final report, upload the PDF to the wiki and
    /// file the review reminder in Linear (see close.rs). Takes the run lock.
    #[arg(long, conflicts_with_all = ["month_to_date", "no_pdf"])]
    pub close_month: bool,
    /// --close-month only, for tests: act as if it were this moment (RFC 3339). The
    /// report is marked at least TEST DATA and the reminder title starts with "[TEST] ".
    #[arg(long, requires = "close_month", value_name = "RFC3339")]
    pub now: Option<String>,
}

pub fn main(args: Args) -> Result<i32, Fatal> {
    if args.close_month {
        return close::main(args.month.as_deref(), args.now.as_deref());
    }
    let period = match &args.month {
        Some(m) => Period::parse_month(m)?,
        None => Period::MonthToDate,
    };
    let g = generate(&period, state::utcnow(), &Opts { pdf: !args.no_pdf, ..Default::default() })?;
    println!("{}", g.label);
    println!("  tickets as of {}, history from {}", g.as_of, g.coverage_from);
    if g.json["coverage"]["partial"] == json!(true) {
        println!("  note: the period starts before the event log; counts cover {} on", g.coverage_from);
    }
    println!("  {}", g.dir.join("report.json").display());
    if g.pdf.is_some() {
        println!("  {}", g.dir.join("report.pdf").display());
    }
    println!("  data_sha {}", g.data_sha);
    if !g.pdf_sha.is_empty() {
        println!("  pdf_sha  {}", g.pdf_sha);
    }
    Ok(0)
}

#[cfg(test)]
mod tests;
