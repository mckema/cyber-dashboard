//! The report data (report.json without generated_at) from the event log and
//! runs.jsonl. Pure: the period, the cut-off and "tickets as of" are parameters.
//!
//! Definitions (design approved on 2026-11-05, as implemented). JSON keys stay
//! technical; the PDF uses the words in brackets.
//!   notices          `decided` events in the period ("new public vulnerability notices")
//!   relevant         matched among them ("relevant to fairCT"); the rest is
//!                    not-relevant-by-rule ("automatically ruled out")
//!   assessed         a relevant item of the period whose first `triaged` event exists
//!                    by the cut-off ("assessed"): accepted ("action planned") or
//!                    declined ("ruled out by a person"); time to assess =
//!                    business_time(first_seen, triaged.at), Amsterdam Mon-Fri
//!   waiting          matched, not pruned, still in Triage or never read back at the
//!                    cut-off, whatever month it was first seen ("not assessed yet")
//!   open actions     replayed state at the cut-off = accepted (not pruned);
//!                    overdue = due < Amsterdam date of the cut-off
//!   resolved         `state_changed` to done ("fixed") / canceled ("closed without
//!                    fix") / declined ("ruled out by a person") in the period, last
//!                    one per key; on time = Amsterdam close date <= due
//!   exploited        the `decided` event's flag (triage::store::exploited_source),
//!                    or one of the item's CVEs was logged from CISA KEV or ENISA EUVD
//!                    by the cut-off
//!   sources          the feeds of the last writing run of the period that reported
//!                    feeds; healthy = ok or cached; a fatal run counts as a failure of
//!                    the core feed its error names
//! KPI and RAG rules: kpis() (printed under Definitions in the PDF). The previous
//! calendar month is measured with the same code when the log covers it.
//! The cut-off is the end of the period, or now for a period not over yet.
//! All times are written as Europe/Amsterdam local time with offset.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use serde_json::{Value, json};

use super::model::{Item, Log, Run, replay};
use crate::triage::store::{amsterdam_offset, business_time, from_amsterdam, to_amsterdam};

/// Everything build() needs besides the data.
pub struct Frame {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// min(end, now): the moment states, ages and SLA are measured at.
    pub cut: DateTime<Utc>,
    pub as_of: DateTime<Utc>,
    /// Month to date (title, wording, document id); false: a calendar month.
    pub mtd: bool,
    /// The component list the job can load now: (sha256, number of components). The
    /// count is printed only when the sha is that of the list the period used.
    pub list: Option<(String, usize)>,
    /// EW_ENVIRONMENT: lab | test | production (marking()).
    pub environment: String,
    /// A test run with a set clock (`report --close-month --now`): marked at least TEST DATA.
    pub test_run: bool,
}

/// Target share of fixes by due date: a team proposal, not agreed yet (printed with the KPI).
const FIX_TARGET_NOTE: &str = "team proposal, pending agreement";

/// The data marking on every page of the PDF ("" = none), and its one-line notice.
/// production: none (unless a test run); otherwise "LAB DATA" when the tracker is
/// linear-mock, else "TEST DATA". A test run is marked at least TEST DATA. Any
/// value other than "production" counts as a test environment.
pub fn marking(environment: &str, endpoint: &str, test_run: bool) -> (&'static str, String) {
    let production = environment.trim().eq_ignore_ascii_case("production");
    let label = if production && !test_run {
        ""
    } else if endpoint.contains("linear-mock") {
        "LAB DATA"
    } else {
        "TEST DATA"
    };
    let mut notice = match label {
        "" => String::new(),
        "LAB DATA" => "tickets, owners and dates come from a simulated tracker (linear-mock), not from fairCT's.".into(),
        _ => "built in a test environment: tickets, owners and dates are not fairCT's.".into(),
    };
    if test_run {
        notice = format!("{} A test run with a set clock; not a report to send.", notice.trim_end());
    }
    (label, notice)
}

/// Feeds whose failure for more than two days turns the report red (and aborts a run).
const CORE_FEEDS: [&str; 2] = ["CISA KEV", "CVE.org cvelistV5"];
/// Every item of these feeds is known exploited.
const EXPLOITED_FEEDS: [&str; 2] = ["CISA KEV", "ENISA EUVD"];
/// Target share of fixes closed by their due date.
const FIX_TARGET: f64 = 0.95;

/// Amsterdam local time with its offset, e.g. 2026-11-05T08:31:08+01:00.
pub fn local(t: DateTime<Utc>) -> String {
    let off = if amsterdam_offset(t) == Duration::hours(2) { "+02:00" } else { "+01:00" };
    format!("{}{off}", to_amsterdam(t).format("%Y-%m-%dT%H:%M:%S"))
}

fn local_opt(t: Option<DateTime<Utc>>) -> Value {
    t.map_or(Value::Null, |t| json!(local(t)))
}

fn local_date(t: DateTime<Utc>) -> NaiveDate {
    to_amsterdam(t).date()
}

/// "20 Nov".
fn day_mon(d: NaiveDate) -> String {
    d.format("%-d %b").to_string()
}

/// "2026-11-20" -> "20 Nov"; anything else as it is.
fn due_label(due: &str) -> String {
    NaiveDate::parse_from_str(due.trim(), "%Y-%m-%d").map(day_mon).unwrap_or_else(|_| due.trim().to_string())
}

/// One decimal.
fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn hours(d: Duration) -> f64 {
    round1(d.num_seconds() as f64 / 3600.0)
}

fn median(mut v: Vec<Duration>) -> Option<Duration> {
    if v.is_empty() {
        return None;
    }
    v.sort();
    let n = v.len();
    Some(if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2 })
}

/// 3852 -> "3,852".
fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn pct(x: usize, y: usize) -> String {
    format!("{x} of {y} ({}%)", (x as f64 * 100.0 / y as f64).round())
}

fn clip(s: &str, n: usize) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= n { s } else { s.chars().take(n - 1).collect::<String>().trim_end().to_string() + "…" }
}

/// Feed name as readers know it.
fn source_label(feed: &str) -> &str {
    if feed == "CVE.org cvelistV5" { "CVE.org" } else { feed }
}

fn healthy(status: &str) -> bool {
    matches!(status, "ok" | "cached")
}

/// The vulnerability an item is about: its first CVE, else the source's own id.
fn vuln(it: &Item) -> String {
    it.cves.first().cloned()
        .or_else(|| Some(it.item_id.clone()).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| it.key.split_once(':').map_or(it.key.clone(), |(_, id)| id.to_string()))
}

/// Ticket id, or the item key when no ticket was filed.
fn ticket(it: &Item) -> String {
    if it.identifier.is_empty() { vuln(it) } else { it.identifier.clone() }
}

fn row(it: &Item) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("key".into(), json!(it.key));
    m.insert("identifier".into(), json!(it.identifier));
    m.insert("vulnerability".into(), json!(vuln(it)));
    m.insert("title".into(), json!(clip(&it.title, 60)));
    m.insert("component".into(), json!(it.component));
    m.insert("url".into(), json!(if it.issue_url.is_empty() { &it.url } else { &it.issue_url }));
    m
}

fn with(mut m: serde_json::Map<String, Value>, extra: Value) -> Value {
    if let Value::Object(e) = extra {
        m.extend(e);
    }
    Value::Object(m)
}

/// RAG tiers, ordered so the worst is the max.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rag {
    Green,
    Amber,
    Red,
}

impl Rag {
    fn upper(self) -> &'static str {
        match self { Rag::Green => "GREEN", Rag::Amber => "AMBER", Rag::Red => "RED" }
    }

    fn title(self) -> &'static str {
        match self { Rag::Green => "Green", Rag::Amber => "Amber", Rag::Red => "Red" }
    }
}

/// Why a KPI (or the tracker check) is not green.
#[derive(Debug, Clone)]
struct Reason {
    rag: Rag,
    text: String,
    /// Listed under "Attention / decisions needed" on page 1.
    attention: bool,
    /// A monitoring problem (sources, tracker) rather than a ticket.
    monitoring: bool,
}

fn reason(rag: Rag, text: String, attention: bool) -> Reason {
    Reason { rag, text, attention, monitoring: false }
}

/// What the log and runs say about one period, measured at its cut-off.
struct Facts<'a> {
    start: DateTime<Utc>,
    cut: DateTime<Utc>,
    /// Every key replayed to the cut-off, `exploited` widened by CVE.
    items: BTreeMap<String, Item>,
    notices: usize,
    /// Keys first seen in the period and matched.
    relevant: Vec<String>,
    /// Relevant keys of the period with a first triage by the cut-off, and the time it took.
    assessed: Vec<(String, Duration)>,
    /// Matched keys (any month) not assessed at the cut-off, with the time waited.
    waiting: Vec<(String, Duration)>,
    open: Vec<String>,
    overdue: BTreeSet<String>,
    fixed: Vec<(String, DateTime<Utc>)>,
    canceled: Vec<(String, DateTime<Utc>)>,
    declined: Vec<(String, DateTime<Utc>)>,
    /// Ruled out by a person without a reason, at the cut-off (any month).
    no_reason: Vec<String>,
    writing: Vec<&'a Run>,
    /// Feeds of the last writing run that reported feeds, with their last status.
    sources: Vec<(String, String)>,
    /// Feeds reported earlier in the period but not by that run.
    removed: Vec<String>,
    /// Core feeds failing for more than two days at the cut-off, and since when.
    core_down: Vec<(String, DateTime<Utc>)>,
    tracker_errors: Vec<(DateTime<Utc>, String)>,
}

impl Facts<'_> {
    fn it(&self, k: &str) -> &Item {
        &self.items[k]
    }

    fn in_period(&self, t: DateTime<Utc>) -> bool {
        self.start <= t && t < self.cut
    }

    fn on_time(&self, k: &str, at: DateTime<Utc>) -> Option<bool> {
        NaiveDate::parse_from_str(self.it(k).due.trim(), "%Y-%m-%d").ok().map(|d| local_date(at) <= d)
    }
}

/// Status of every feed in a writing run: its feeds map, or for a fatal run the
/// core feed its error names.
fn run_feeds(r: &Run) -> Vec<(String, String)> {
    if let Some(Value::Object(fs)) = r.v.get("feeds") {
        return fs.iter()
            .map(|(n, v)| (n.clone(), v.get("status").and_then(Value::as_str).unwrap_or("unknown").to_string()))
            .collect();
    }
    let err = r.s("error");
    CORE_FEEDS.iter().filter(|f| err.starts_with(&format!("{f}:"))).map(|f| (f.to_string(), "error".to_string())).collect()
}

fn facts<'a>(log: &Log, runs: &'a [Run], start: DateTime<Utc>, cut: DateTime<Utc>) -> Facts<'a> {
    let mut items = replay(&log.events, cut);
    // Exploited by CVE: a CVE logged from KEV or EUVD by the cut-off marks every item naming it.
    let mut kev_cves: BTreeMap<String, String> = BTreeMap::new();
    for e in log.events.iter().take_while(|e| e.at < cut)
        .filter(|e| e.kind == "decided" && EXPLOITED_FEEDS.contains(&e.s("item_source"))) {
        for c in e.v.get("cves").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            let src = e.s("item_source").to_string();
            kev_cves.entry(c.to_string()).and_modify(|s| if src == EXPLOITED_FEEDS[0] { s.clone_from(&src) }).or_insert(src);
        }
    }
    for it in items.values_mut().filter(|i| !i.exploited) {
        if let Some(src) = it.cves.iter().find_map(|c| kev_cves.get(c)) {
            it.exploited = true;
            it.exploited_source = src.clone();
        }
    }

    let in_period = |t: DateTime<Utc>| start <= t && t < cut;
    let decided: Vec<&Item> = items.values().filter(|i| i.first_seen.is_some_and(in_period)).collect();
    let relevant: Vec<String> = decided.iter().filter(|i| i.matched).map(|i| i.key.clone()).collect();
    let assessed: Vec<(String, Duration)> = relevant.iter().filter_map(|k| {
        let i = &items[k];
        Some((k.clone(), business_time(i.first_seen?, i.first_triaged.as_ref()?.at)))
    }).collect();
    let waiting: Vec<(String, Duration)> = items.values()
        .filter(|i| i.matched && !i.pruned && (i.state == "triage" || (i.state == "none" && i.first_triaged.is_none())))
        .filter_map(|i| Some((i.key.clone(), business_time(i.first_seen?, cut))))
        .collect();

    let today = local_date(cut);
    let mut open: Vec<&Item> = items.values().filter(|i| i.state == "accepted" && !i.pruned).collect();
    open.sort_by(|a, b| a.due.is_empty().cmp(&b.due.is_empty()).then(a.due.cmp(&b.due)).then(a.key.cmp(&b.key)));
    let overdue = open.iter()
        .filter(|i| NaiveDate::parse_from_str(i.due.trim(), "%Y-%m-%d").is_ok_and(|d| d < today))
        .map(|i| i.key.clone()).collect();
    let open = open.into_iter().map(|i| i.key.clone()).collect();

    // Closed in the period and still closed that way at the cut-off (a reopened ticket is open).
    let mut closed: BTreeMap<&str, BTreeMap<String, DateTime<Utc>>> = BTreeMap::new();
    for e in log.events.iter().filter(|e| e.kind == "state_changed" && in_period(e.at)) {
        let to = e.s("to");
        if matches!(to, "done" | "canceled" | "declined") && items.get(&e.key).is_some_and(|i| i.state == to) {
            closed.entry(to).or_default().insert(e.key.clone(), e.at);
        }
    }
    let list = |to: &str| -> Vec<(String, DateTime<Utc>)> {
        let mut v: Vec<_> = closed.get(to).into_iter().flatten().map(|(k, at)| (k.clone(), *at)).collect();
        v.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        v
    };
    let no_reason = items.values()
        .filter(|i| i.matched && i.state == "declined" && i.reason.trim().is_empty())
        .map(|i| i.key.clone()).collect();

    // ------------------------------------------------------------- runs and feeds
    let mut writing: Vec<&Run> = runs.iter().filter(|r| r.is_writing() && in_period(r.at)).collect();
    writing.sort_by_key(|r| r.at);
    let last_feeds = writing.iter().rev().find(|r| r.v.get("feeds").is_some_and(Value::is_object));
    let mut sources: Vec<(String, String)> = last_feeds.map(|r| run_feeds(r)).unwrap_or_default();
    // A later fatal run blames a core feed: that is its latest status.
    for r in writing.iter().filter(|r| last_feeds.is_none_or(|l| r.at > l.at)) {
        for (f, st) in run_feeds(r) {
            if let Some(s) = sources.iter_mut().find(|(n, _)| *n == f) {
                s.1 = st;
            }
        }
    }
    let seen: BTreeSet<String> = writing.iter().flat_map(|r| run_feeds(r)).map(|(f, _)| f).collect();
    let removed = seen.into_iter().filter(|f| !sources.iter().any(|(n, _)| n == f)).collect();
    // Core feed failing since: the first failing run after its last healthy one (all runs to the cut-off).
    let mut all: Vec<&Run> = runs.iter().filter(|r| r.is_writing() && r.at < cut).collect();
    all.sort_by_key(|r| r.at);
    let core_down = CORE_FEEDS.iter().filter_map(|core| {
        let mut since = None;
        for r in &all {
            if let Some((_, st)) = run_feeds(r).into_iter().find(|(f, _)| f.as_str() == *core) {
                if healthy(&st) { since = None } else if since.is_none() { since = Some(r.at) }
            }
        }
        since.filter(|s| cut - *s > Duration::days(2)).map(|s| (core.to_string(), s))
    }).collect();
    let tracker_errors = runs.iter().filter(|r| in_period(r.at)).flat_map(|r| {
        r.v.pointer("/triage/errors").and_then(Value::as_array).into_iter().flatten()
            .map(|e| (r.at, clip(e.as_str().unwrap_or(""), 300)))
    }).collect();

    Facts {
        start, cut, notices: decided.len(), relevant, assessed, waiting, open, overdue,
        fixed: list("done"), canceled: list("canceled"), declined: list("declined"), no_reason,
        writing, sources, removed, core_down, tracker_errors, items,
    }
}

/// One KPI row.
struct Kpi {
    key: &'static str,
    label: &'static str,
    value: String,
    target: &'static str,
    /// None: not rated ("—").
    status: Option<Rag>,
    /// Printed under the target (e.g. that the target is not agreed yet).
    target_note: Option<&'static str>,
}

/// The KPI rows and every reason a rule fired (RAG rules, printed in the PDF):
///   GREEN  none of the below
///   AMBER  an assessment took > 1 business day (or an item waits > 1); an open action
///          lacks owner or due date; ruled out by a person without a reason; a source
///          stale or failing in the last run (or no run in the period); a tracker
///          error in the period; an overdue action on a non-exploited item; fewer than
///          95% of the fixes in the period by their due date
///   RED    an overdue action on a known-exploited item; a relevant item unassessed
///          for > 3 business days at the cut-off; CISA KEV or CVE.org failing > 2 days
fn kpis(f: &Facts) -> (Vec<Kpi>, Vec<Reason>) {
    let one = Duration::days(1);
    let mut all = Vec::new();
    let worst = |rs: &[Reason]| rs.iter().map(|r| r.rag).max().unwrap_or(Rag::Green);

    // assessed within 1 business day
    let mut rs = Vec::new();
    for (k, d) in f.assessed.iter().filter(|(_, d)| *d > one) {
        rs.push(reason(Rag::Amber, format!("{}: assessment took {:.1} business days", ticket(f.it(k)),
                                            d.num_seconds() as f64 / 86400.0), false));
    }
    for (k, d) in f.waiting.iter().filter(|(_, d)| *d > one) {
        let i = f.it(k);
        let (rag, n) = if *d > Duration::days(3) { (Rag::Red, 3) } else { (Rag::Amber, 1) };
        rs.push(reason(rag, format!("{} ({}): relevant item not assessed after more than {} first seen {}",
                                    ticket(i), vuln(i), plural(n, "business day,", "business days,"),
                                    i.first_seen.map(|t| day_mon(local_date(t))).unwrap_or_default()), true));
    }
    for k in &f.no_reason {
        rs.push(reason(Rag::Amber, format!("{} ({}): ruled out by a person without a reason", ticket(f.it(k)), vuln(f.it(k))), true));
    }
    let late_waiting = f.waiting.iter()
        .filter(|(k, d)| *d > one && f.it(k).first_seen.is_some_and(|t| f.in_period(t))).count();
    let ok = f.assessed.iter().filter(|(_, d)| *d <= one).count();
    let y = f.assessed.len() + late_waiting;
    let assessed = Kpi { key: "assessed", label: "Assessed within 1 business day",
                         value: match (y, f.no_reason.len()) {
                             (0, 0) => "—".into(),
                             (0, n) => format!("—; {n} without a reason"),
                             (y, 0) => pct(ok, y),
                             (y, n) => format!("{}; {n} without a reason", pct(ok, y)),
                         }, target: "100%", target_note: None, status: Some(worst(&rs)) };
    all.append(&mut rs);

    // open actions
    for k in &f.open {
        let i = f.it(k);
        if f.overdue.contains(k) {
            let owner = if i.assignee.is_empty() { "no owner".to_string() } else { format!("owner {}", i.assignee) };
            if i.exploited {
                rs.push(reason(Rag::Red, format!("{} ({}, known exploited): action overdue since {} ({owner})",
                                                 ticket(i), vuln(i), due_label(&i.due)), true));
            } else {
                rs.push(reason(Rag::Amber, format!("{} ({}): action overdue since {} ({owner})",
                                                   ticket(i), vuln(i), due_label(&i.due)), true));
            }
        }
        let missing: Vec<&str> = [(i.assignee.trim().is_empty(), "an owner"), (i.due.trim().is_empty(), "a due date")]
            .into_iter().filter(|(m, _)| *m).map(|(_, w)| w).collect();
        if !missing.is_empty() {
            rs.push(reason(Rag::Amber, format!("{} ({}): open action without {}", ticket(i), vuln(i), missing.join(" or ")), true));
        }
    }
    let open = Kpi { key: "open", label: "Open actions (of which overdue)",
                     value: format!("{} ({} overdue)", f.open.len(), f.overdue.len()), target: "0 overdue", target_note: None,
                     status: Some(worst(&rs)) };
    all.append(&mut rs);

    // fixed by due date
    let on_time = f.fixed.iter().filter(|(k, at)| f.on_time(k, *at) == Some(true)).count();
    let n = f.fixed.len();
    let fixed_status = if n == 0 {
        None
    } else if on_time as f64 >= FIX_TARGET * n as f64 {
        Some(Rag::Green)
    } else {
        all.push(reason(Rag::Amber, format!("fixes by due date: {}, below the proposed 95% target", pct(on_time, n)), false));
        Some(Rag::Amber)
    };
    let fixed = Kpi { key: "fixed", label: "Fixed by due date", value: if n == 0 { "—".into() } else { pct(on_time, n) },
                      target: "≥ 95%", target_note: Some(FIX_TARGET_NOTE), status: fixed_status };

    // known exploited still open (its red reason is listed under open actions)
    let expl: Vec<&String> = f.open.iter().filter(|k| f.it(k).exploited).collect();
    let expl_overdue = expl.iter().any(|k| f.overdue.contains(*k));
    let exploited = Kpi { key: "exploited", label: "Known-exploited items still open", value: expl.len().to_string(),
                          target: "0 overdue", target_note: None, status: Some(if expl_overdue { Rag::Red } else { Rag::Green }) };

    // sources
    for (core, since) in &f.core_down {
        rs.push(Reason { rag: Rag::Red, text: format!("{} failing since {} (more than 2 days)", source_label(core),
                                                       day_mon(local_date(*since))), attention: true, monitoring: true });
    }
    for (feed, st) in f.sources.iter().filter(|(_, s)| !healthy(s)) {
        if !f.core_down.iter().any(|(c, _)| c == feed) {
            rs.push(Reason { rag: Rag::Amber, text: format!("{} {} in the last run", source_label(feed),
                                                             if st == "stale" { "stale (fetch failed, older data used)" } else { "failing" }),
                             attention: true, monitoring: true });
        }
    }
    if f.writing.is_empty() {
        rs.push(Reason { rag: Rag::Amber, text: "no scheduled run recorded in the period".into(), attention: true, monitoring: true });
    }
    let good = f.sources.iter().filter(|(_, s)| healthy(s)).count();
    let sources = Kpi { key: "sources", label: "Sources healthy",
                        value: if f.sources.is_empty() { "no data".into() } else { format!("{good}/{}", f.sources.len()) },
                        target: "all", target_note: None, status: Some(worst(&rs)) };
    all.append(&mut rs);

    // tracker (not a KPI row; counts for the report status)
    if let Some((last, _)) = f.tracker_errors.last() {
        all.push(Reason { rag: Rag::Amber, text: format!("Ticket tracker errors in {}, the last on {}",
                                                         plural(f.tracker_errors.len(), "run", "runs"), day_mon(local_date(*last))),
                          attention: true, monitoring: true });
    }

    let relevant = Kpi { key: "relevant", label: "Relevant to fairCT", value: f.relevant.len().to_string(), target: "—", target_note: None, status: None };
    (vec![relevant, assessed, open, fixed, exploited, sources], all)
}

/// The 2–3 sentence summary on page 1.
fn bottom_line(f: &Facts, reasons: &[Reason], month: &str, mtd: bool) -> Vec<String> {
    let when = if mtd { format!("So far in {month}") } else { format!("In {month}") };
    let n = thousands(f.notices);
    let r = f.relevant.len();
    let mut out = Vec::new();
    if r == 0 {
        out.push(format!("{when}, fairCT's monitoring recorded {n} new public vulnerability {}. No new public vulnerability notice concerned a component on fairCT's list.",
                         if f.notices == 1 { "notice" } else { "notices" }));
    } else {
        out.push(format!("{when}, {r} of {n} new public vulnerability {} fairCT components.",
                         if f.notices == 1 { "notice concerned" } else { "notices concerned" }));
    }

    let mut parts = Vec::new();
    if r > 0 {
        let ok = f.assessed.iter().filter(|(_, d)| *d <= Duration::days(1)).count();
        let waiting = f.relevant.iter().filter(|k| f.waiting.iter().any(|(w, _)| w == *k)).count();
        parts.push(if ok == r {
            match r { 1 => "It was assessed within 1 business day".to_string(),
                      2 => "Both were assessed within 1 business day".to_string(),
                      _ => format!("All {r} were assessed within 1 business day") }
        } else {
            let mut s = format!("{ok} of {r} {} assessed within 1 business day", if ok == 1 { "was" } else { "were" });
            if waiting > 0 {
                s += &format!(", {waiting} {} still waiting for assessment", if waiting == 1 { "is" } else { "are" });
            }
            s
        });
    }
    let open: Vec<&Item> = f.open.iter().map(|k| f.it(k)).collect();
    match open.as_slice() {
        [] if r > 0 => parts.push("no fix is pending".into()),
        [] => {}
        [i] => {
            let due = if i.due.trim().is_empty() { ", without a due date".to_string() } else { format!(" by {}", due_label(&i.due)) };
            let owner = if i.assignee.trim().is_empty() { "no owner".to_string() } else { format!("owner {}", i.assignee) };
            parts.push(format!("1 fix is planned{due} ({owner})"));
        }
        many => {
            let next = many.iter().find(|i| !i.due.trim().is_empty()).map(|i| format!(", the next by {}", due_label(&i.due)));
            parts.push(format!("{} fixes are planned{}", many.len(), next.unwrap_or_default()));
        }
    }
    if !open.is_empty() {
        let m = f.overdue.len();
        let expl = f.overdue.iter().filter(|k| f.it(k).exploited).count();
        parts.push(match (m, expl) {
            (0, _) => "none is overdue".into(),
            (m, 0) => format!("{m} {} overdue", if m == 1 { "is" } else { "are" }),
            (m, e) => format!("{m} {} overdue, {e} of them on a known-exploited vulnerability", if m == 1 { "is" } else { "are" }),
        });
    }
    if !parts.is_empty() {
        let mut s = parts.join("; ");
        s[..1].make_ascii_uppercase();
        out.push(s + ".");
    }

    let att: Vec<&Reason> = reasons.iter().filter(|r| r.attention).collect();
    let mon = att.iter().filter(|r| r.monitoring).count();
    if att.is_empty() {
        out.push("No decision is needed from you.".into());
    } else if mon == att.len() {
        out.push("Monitoring needs attention (listed below); no ticket needs a decision from you.".into());
    } else {
        let k = att.len();
        let mut s = format!("{} your attention (listed below)", plural(k, "point needs", "points need"));
        if mon > 0 {
            s += &format!(", {} of them about monitoring", mon);
        }
        out.push(s + ".");
    }
    out
}

/// Bounds of the calendar month before the one `start` lies in.
fn previous_month(start: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>, String, String) {
    let l = to_amsterdam(start).date();
    let (y, m) = if l.month() == 1 { (l.year() - 1, 12) } else { (l.year(), l.month() - 1) };
    let first = NaiveDate::from_ymd_opt(y, m, 1).unwrap();
    let this = NaiveDate::from_ymd_opt(l.year(), l.month(), 1).unwrap();
    (from_amsterdam(first.and_hms_opt(0, 0, 0).unwrap()), from_amsterdam(this.and_hms_opt(0, 0, 0).unwrap()),
     first.format("%Y-%m").to_string(), first.format("%B %Y").to_string())
}

/// The report sections (header data included, generated_at excluded).
pub fn build(log: &Log, runs: &[Run], f: &Frame) -> Value {
    let fa = facts(log, runs, f.start, f.cut);
    let (kpi_rows, reasons) = kpis(&fa);

    // ---------------------------------------------------------- previous month
    let (pstart, pend, pname, plabel) = previous_month(f.start);
    let covered = log.coverage_from < pend;
    let prev = covered.then(|| kpis(&facts(log, runs, pstart, pend)).0);
    let kpis_json: Vec<Value> = kpi_rows.iter().map(|k| {
        let previous = match &prev {
            None => "first period".to_string(),
            Some(p) => p.iter().find(|q| q.key == k.key).map(|q| q.value.clone()).unwrap_or_else(|| "no data".into()),
        };
        json!({"key": k.key, "label": k.label, "value": k.value, "target": k.target,
               "status": k.status.map_or("—", Rag::title), "previous": previous, "target_note": k.target_note})
    }).collect();
    let mut sorted = reasons.clone();
    sorted.sort_by(|a, b| b.rag.cmp(&a.rag));
    let rag = reasons.iter().map(|r| r.rag).max().unwrap_or(Rag::Green);
    let status = json!({"rag": rag.upper(),
                        "reasons": sorted.iter().map(|r| json!({"rag": r.rag.upper(), "text": r.text})).collect::<Vec<_>>()});
    let attention: Vec<Value> = sorted.iter().filter(|r| r.attention).map(|r| json!({"rag": r.rag.upper(), "text": r.text})).collect();

    // ---------------------------------------------------------- title
    let lstart = to_amsterdam(f.start).date();
    let month = lstart.format("%B %Y").to_string();
    let month_only = lstart.format("%B").to_string();
    let last_day = local_date(f.cut - Duration::seconds(1)).max(lstart);
    let title = if f.mtd {
        format!("Cyber threat report — {month}, month to date (1–{} {})", last_day.day(), lstart.format("%b"))
    } else {
        format!("Cyber threat report — {month}")
    };
    let subtitle = if f.mtd { "Month-to-date snapshot – not the official monthly report" } else { "Monthly report" };
    let bottom = bottom_line(&fa, &reasons, &month_only, f.mtd);

    // ---------------------------------------------------------- open actions
    let risk = |i: &Item| json!({"exploited": i.exploited, "exploited_source": i.exploited_source,
                                 "severity": i.severity, "score": i.score});
    let open_rows: Vec<Value> = fa.open.iter().map(|k| {
        let i = fa.it(k);
        with(with(row(i), risk(i)).as_object().cloned().unwrap_or_default(),
             json!({"owner": i.assignee, "due": i.due, "state_name": i.state_name, "overdue": fa.overdue.contains(k)}))
    }).collect();
    let open_actions = json!({"count": open_rows.len(), "overdue": fa.overdue.len(), "items": open_rows});

    // ---------------------------------------------------------- resolved
    let mut resolved: Vec<(DateTime<Utc>, Value)> = Vec::new();
    let mut fixed_rows = Vec::new();
    let (mut on_time, mut late, mut no_due, mut ttr) = (0, 0, 0, Vec::new());
    for (k, at) in &fa.fixed {
        let i = fa.it(k);
        let ok = fa.on_time(k, *at);
        match ok { Some(true) => on_time += 1, Some(false) => late += 1, None => no_due += 1 }
        if let Some(seen) = i.first_seen {
            ttr.push(*at - seen);
        }
        let when = match ok { Some(true) => "on time", Some(false) => "late", None => "no due date" };
        resolved.push((*at, with(row(i), json!({"outcome": format!("fixed on {} ({when})", day_mon(local_date(*at))),
                                                 "warn": ok != Some(true)}))));
        fixed_rows.push(with(row(i), json!({"owner": i.assignee, "due": i.due, "closed_at": local(*at), "on_time": ok,
                                            "first_seen": local_opt(i.first_seen)})));
    }
    let mut canceled_rows = Vec::new();
    for (k, at) in &fa.canceled {
        let i = fa.it(k);
        resolved.push((*at, with(row(i), json!({"outcome": format!("closed without fix on {}", day_mon(local_date(*at))),
                                                 "warn": false}))));
        canceled_rows.push(with(row(i), json!({"owner": i.assignee, "due": i.due, "closed_at": local(*at)})));
    }
    let mut declined_rows = Vec::new();
    for (k, at) in &fa.declined {
        let i = fa.it(k);
        let actor = i.first_triaged.as_ref().map(|t| t.actor.clone()).unwrap_or_default();
        let who = if actor.trim().is_empty() { "a person (not recorded)".to_string() } else { actor.clone() };
        let no_reason = i.reason.trim().is_empty();
        let what = if no_reason { "no reason given".to_string() } else { clip(&i.reason, 80) };
        resolved.push((*at, with(row(i), json!({"outcome": format!("ruled out by {who}: {what}"), "warn": no_reason}))));
        declined_rows.push(with(row(i), json!({"reason": i.reason, "actor": actor, "declined_at": local(*at)})));
    }
    resolved.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1["key"].as_str().cmp(&b.1["key"].as_str())));
    let outcomes = json!({
        "fixed": fixed_rows, "fixed_count": fa.fixed.len(), "on_time": on_time, "late": late, "no_due": no_due,
        "mttr_median_days": median(ttr).map(|d| round1(d.num_seconds() as f64 / 86400.0)),
        "closed_without_fix": canceled_rows, "ruled_out": declined_rows,
    });

    // ---------------------------------------------------------- funnel
    let mut by_source: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for i in fa.items.values().filter(|i| i.first_seen.is_some_and(|t| fa.in_period(t))) {
        let e = by_source.entry(i.source.as_str()).or_default();
        if i.matched { e.0 += 1 } else { e.1 += 1 }
    }
    let first_state = |k: &str| fa.it(k).first_triaged.as_ref().map(|t| t.state.clone()).unwrap_or_default();
    let planned = fa.assessed.iter().filter(|(k, _)| first_state(k) != "declined").count();
    let times: Vec<Duration> = fa.assessed.iter().map(|(_, d)| *d).collect();
    let mut over: Vec<(DateTime<Utc>, Value)> = Vec::new();
    for (k, d) in fa.assessed.iter().filter(|(_, d)| *d > Duration::days(1)) {
        let i = fa.it(k);
        let (Some(seen), Some(t)) = (i.first_seen, &i.first_triaged) else { continue };
        over.push((seen, with(row(i), json!({"first_seen": local(seen), "assessed_at": local(t.at), "business_hours": hours(*d)}))));
    }
    for (k, _) in fa.waiting.iter().filter(|(_, d)| *d > Duration::days(1)) {
        let i = fa.it(k);
        let Some(seen) = i.first_seen else { continue };
        // No duration for a waiting item: it would move with the clock.
        over.push((seen, with(row(i), json!({"first_seen": local(seen), "assessed_at": null, "business_hours": null}))));
    }
    over.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1["key"].as_str().cmp(&b.1["key"].as_str())));
    let relevant_waiting = fa.relevant.iter().filter(|k| fa.waiting.iter().any(|(w, _)| w == *k)).count();
    let funnel = json!({
        "notices": fa.notices,
        "auto_ruled_out": fa.notices - fa.relevant.len(),
        "relevant": fa.relevant.len(),
        "assessed": fa.assessed.len(),
        "action_planned": planned,
        "ruled_out_by_person": fa.assessed.len() - planned,
        "waiting": relevant_waiting,
        "time_to_assess": {"count": times.len(), "median_business_hours": median(times.clone()).map(hours),
                           "max_business_hours": times.iter().max().copied().map(hours)},
        "over_one_day": over.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
        "by_source": by_source.iter().map(|(s, (m, n))| json!({"source": s, "total": m + n, "relevant": m, "auto_ruled_out": n}))
            .collect::<Vec<_>>(),
    });

    // ---------------------------------------------------------- exceptions
    let ids = |keys: Vec<&String>| -> Vec<Value> {
        keys.into_iter().map(|k| { let i = fa.it(k); json!({"identifier": i.identifier, "title": clip(&i.title, 100), "key": i.key}) }).collect()
    };
    let assessed_keys: BTreeSet<&String> = fa.assessed.iter().map(|(k, _)| k).collect();
    let exceptions = json!({
        "overdue": ids(fa.open.iter().filter(|k| fa.overdue.contains(*k)).collect()),
        "open_without_owner": ids(fa.open.iter().filter(|k| fa.it(k).assignee.trim().is_empty()).collect()),
        "open_without_due": ids(fa.open.iter().filter(|k| fa.it(k).due.trim().is_empty()).collect()),
        "unassessed_over_one_day": ids(fa.waiting.iter().filter(|(_, d)| *d > Duration::days(1)).map(|(k, _)| k).collect()),
        "declined_without_reason": ids(fa.no_reason.iter().collect()),
        "triaged_without_actor": ids(assessed_keys.into_iter()
            .filter(|k| fa.it(k).first_triaged.as_ref().is_some_and(|t| t.actor.trim().is_empty())).collect()),
        "sources_unhealthy": fa.sources.iter().filter(|(_, s)| !healthy(s))
            .map(|(n, s)| json!({"feed": n, "status": s})).collect::<Vec<_>>(),
        "tracker_errors": fa.tracker_errors.iter().map(|(at, e)| json!({"run_at": local(*at), "error": e})).collect::<Vec<_>>(),
        "log_lines_skipped": log.skipped_lines,
    });

    // ---------------------------------------------------------- provenance
    let in_period = |t: DateTime<Utc>| f.start <= t && t < f.cut;
    let mut components: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut last_list = (String::new(), String::new(), None::<DateTime<Utc>>);
    for e in log.events.iter().filter(|e| e.kind == "decided" && in_period(e.at)) {
        let vs = (e.s("components_version").to_string(), e.s("components_sha256").to_string());
        if last_list.2.is_none_or(|t| e.at >= t) {
            last_list = (vs.0.clone(), vs.1.clone(), Some(e.at));
        }
        *components.entry(vs).or_default() += 1;
    }
    // The list of the last writing run wins over that of the last decision.
    if let Some(r) = fa.writing.iter().rev().find(|r| !r.v.pointer("/triage/components").and_then(Value::as_str).unwrap_or("").is_empty()) {
        let s = |p: &str| r.v.pointer(p).and_then(Value::as_str).unwrap_or("").to_string();
        last_list = (s("/triage/components"), s("/triage/components_sha256"), Some(r.at));
    }
    let count = f.list.as_ref().filter(|(sha, _)| !sha.is_empty() && *sha == last_list.1).map(|(_, n)| *n);
    let component_list = json!({"version": last_list.0, "sha256": last_list.1, "count": count});

    let mut by_result: BTreeMap<String, u64> = BTreeMap::new();
    let mut feed_runs: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for r in &fa.writing {
        *by_result.entry(r.s("result").to_string()).or_default() += 1;
        if let Some(Value::Object(fs)) = r.v.get("feeds") {
            for (name, fv) in fs {
                let st = fv.get("status").and_then(Value::as_str).unwrap_or("unknown").to_string();
                *feed_runs.entry(name.clone()).or_default().entry(st).or_default() += 1;
            }
        }
    }
    let feeds: Vec<Value> = fa.sources.iter().map(|(name, last)| {
        let st = feed_runs.get(name).cloned().unwrap_or_default();
        json!({"feed": name, "runs": st.values().sum::<u64>(), "ok": st.get("ok").copied().unwrap_or(0),
               "by_status": st, "last_status": last, "healthy": healthy(last)})
    }).collect();
    let endpoint_of = |r: &&Run| r.v.pointer("/triage/endpoint").and_then(Value::as_str).map(String::from);
    let endpoint = runs.iter().filter(|r| r.at < f.cut).rev().find_map(|r| endpoint_of(&r))
        .or_else(|| runs.iter().rev().find_map(|r| endpoint_of(&r)))
        .unwrap_or_default();
    let mark = marking(&f.environment, &endpoint, f.test_run);

    // ---------------------------------------------------------- coverage sentence
    let names: Vec<&str> = fa.sources.iter().map(|(n, _)| n.as_str()).collect();
    let order = ["CISA KEV", "ENISA EUVD", "CVE.org cvelistV5", "GitHub Advisory", "CERT-EU", "NCSC-NL"];
    let mut listed: Vec<&str> = order.iter().copied().filter(|n| names.contains(n)).collect();
    listed.extend(names.iter().copied().filter(|n| !order.contains(n) && *n != "NVD"));
    let mut srcs = listed.iter().map(|n| source_label(n)).collect::<Vec<_>>().join(", ");
    if names.contains(&"NVD") {
        srcs += "; NVD for scores";
    }
    let list_text = match (&last_list.0, count) {
        (v, _) if v.is_empty() => "the component list".to_string(),
        (v, Some(m)) => format!("component list {v} ({})", plural(m, "component", "components")),
        (v, None) => format!("component list {v}"),
    };
    let sentence = if names.is_empty() {
        "No scheduled run checked the public sources in this period. Limits: components not on the list are not checked; affected versions are not checked.".to_string()
    } else {
        format!("{} ({srcs}) checked in {} (every 6 h) against {list_text}. Limits: components not on the list are not checked; affected versions are not checked.",
                plural(names.len(), "public source", "public sources"), plural(fa.writing.len(), "scheduled run", "scheduled runs"))
    };

    // ---------------------------------------------------------- document control
    let ym = lstart.format("%Y-%m").to_string();
    let complete = f.cut >= f.end;
    let stamp = |t: DateTime<Utc>| to_amsterdam(t).format("%-d %b %Y %H:%M").to_string();
    let period_text = if complete && !f.mtd {
        format!("1–{} {month} (Europe/Amsterdam)", last_day.day())
    } else {
        format!("{} to {} (Europe/Amsterdam){}", stamp(f.start), stamp(f.cut), if f.mtd { "" } else { ", period not over" })
    };
    let document = json!({
        "id": if f.mtd { format!("EW-CTR-{ym}-MTD-{}", to_amsterdam(f.cut).format("%Y%m%d-%H%M")) } else { format!("EW-CTR-{ym}") },
        "version": "1.0",
        "status": if f.mtd { "Snapshot" } else if complete { "Final monthly" } else { "Interim (period not over)" },
        "prepared_by": "Exploit Watch job, operated by the ISB Vietnam team",
        "distribution": "fairCT COO; others on a need-to-know basis (TLP:AMBER+STRICT)",
        "retention": "to be agreed with fairCT",
    });

    json!({
        "title": title,
        "subtitle": subtitle,
        "period": {"start": local(f.start), "end": local(f.end), "complete": complete, "data_to": local(f.cut),
                   "month": month, "text": period_text},
        "tickets_as_of": local(f.as_of),
        "coverage": {"from": local(log.coverage_from), "partial": f.start < log.coverage_from,
                     "duplicates_dropped": log.duplicates, "half_written_tail": log.half_written_tail,
                     "backfilled": log.events.iter().filter(|e| e.v.get("backfilled").is_some()).count()},
        "tracker": {"endpoint": endpoint},
        "marking": {"label": mark.0, "notice": mark.1, "environment": f.environment, "test_run": f.test_run},
        "components": components.into_iter()
            .map(|((v, s), n)| json!({"version": v, "sha256": s, "decisions": n})).collect::<Vec<_>>(),
        "component_list": component_list,
        "runs": {"writing": fa.writing.len(), "by_result": by_result},
        "feeds": feeds,
        "feeds_removed": fa.removed,
        "status": status,
        "bottom_line": bottom,
        "attention": attention,
        "kpis": kpis_json,
        "previous": {"month": pname, "label": plabel, "covered": covered, "partial": covered && pstart < log.coverage_from},
        "open_actions": open_actions,
        "resolved": resolved.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
        "outcomes": outcomes,
        "funnel": funnel,
        "exceptions": exceptions,
        "monitoring": {"sources": listed.iter().map(|n| source_label(n)).collect::<Vec<_>>(),
                       "scheduled_runs": fa.writing.len(), "sentence": sentence},
        "document": document,
    })
}
