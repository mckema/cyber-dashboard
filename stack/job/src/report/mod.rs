//! FR-A4: internal resolution report to the fairCT COO (items triaged, actions
//! taken, actions open), for a calendar month or month to date, in Europe/Amsterdam
//! time. Built from state/triage-events.jsonl and state/runs.jsonl; written to
//! state/reports/<YYYY-MM | month-to-date>/ as report.json, report.pdf and SHA256SUMS.
//!
//! Interface fixed on 2026-11-05 so `run` (month-to-date PDF every writing run),
//! `serve` (refresh on click) and the `report` subcommand share one engine.
//!
//! Layout approved by Henry on 2026-11-05: page 1 for the COO (overall status with a
//! bottom line, attention list, KPIs against target and the previous month, open
//! actions, resolved items, coverage), then detail and an audit appendix.
//!
//!   model.rs    read the event log (tolerant) and runs.jsonl, replay per key; fill
//!               score/severity/exploited of older `decided` lines from triage.json
//!   build.rs    the report sections, KPIs, RAG status and their definitions
//!   pdf.rs      report.typ + data.json -> PDF/A-2b through the typst CLI
//!
//! The report takes no lock: it only reads the event log (and triage.json for the
//! backfill), and a last line still being written is skipped (model::read_events). data_sha is the sha256 of
//! report.json without `generated_at`, serialised compact with sorted keys, so two
//! reports of equal data have equal data_sha.

mod build;
mod model;
mod pdf;

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

#[derive(Debug, Clone, Default)]
pub struct Opts {
    /// Render the PDF (needs the typst CLI). Off in unit tests.
    pub pdf: bool,
    /// "Tickets as of": when the tracker was last read back. None: the last writing
    /// run in runs.jsonl that got that far (run_at), up to the end of the period.
    pub tickets_as_of: Option<DateTime<Utc>>,
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
/// move with the clock alone (no ages, no run counts, no cut-off time).
const CONTENT_KEYS: [&str; 10] = ["components", "status", "bottom_line", "attention", "kpis", "open_actions",
                                  "resolved", "outcomes", "funnel", "exceptions"];

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
    let mut data = build::build(&log, &runs, &build::Frame {
        start, end, cut, as_of, mtd: *period == Period::MonthToDate, list,
    });
    data["label"] = json!(label);
    // UTC twin of tickets_as_of (local), read by `serve` to label the last PDF.
    data["as_of"] = json!(iso_utc(as_of));
    data["period"]["kind"] = json!(if *period == Period::MonthToDate { "month-to-date" } else { "month" });
    data["period"]["name"] = json!(period.month_name(now));
    let data_sha = data_sha(&data);
    data["generated_at"] = json!(build::local(now));

    let pdf = if opts.pdf { Some(pdf::render(&data, &data_sha, as_of)?) } else { None };
    let pdf_sha = pdf.as_deref().map(sha_hex).unwrap_or_default();

    let name = period.dir_name(now);
    let rel = |f: &str| format!("reports/{name}/{f}");
    let mut sums = String::new();
    if let Some(p) = &pdf {
        state::save_bytes(&rel("report.pdf"), p);
    } else {
        // A PDF from an earlier call would no longer match report.json.
        let _ = std::fs::remove_file(state::dir().join(rel("report.pdf")));
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
    let mut g = generate(&Period::MonthToDate, now, &Opts { pdf: true, tickets_as_of: Some(now) })?;
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
    /// Calendar month to report, YYYY-MM (Amsterdam time).
    #[arg(long, conflicts_with = "month_to_date", required_unless_present = "month_to_date")]
    pub month: Option<String>,
    /// From the first of this month to now.
    #[arg(long)]
    pub month_to_date: bool,
    /// Write report.json only, no PDF.
    #[arg(long)]
    pub no_pdf: bool,
}

pub fn main(args: Args) -> Result<i32, Fatal> {
    let period = match &args.month {
        Some(m) => Period::parse_month(m)?,
        None => Period::MonthToDate,
    };
    let g = generate(&period, state::utcnow(), &Opts { pdf: !args.no_pdf, tickets_as_of: None })?;
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
