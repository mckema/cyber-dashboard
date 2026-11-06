//! HTML builders for the Cyber Threat Exploit Watch page.
//!
//! Pure functions: slices of Item in, HTML strings out. No network and no file
//! I/O, except demo().
//!
//! Every builder emits only the class names styled by stack/wiki/page/style.css (the page's
//! scriptCss) and no inline style attributes, because the Wiki.js sanitiser
//! mangles long ones (README.md, Known limitations). The row vocabulary (td.id, sv sv-*, tgt, sub,
//! desc, due/due past, pkg, eco, fix, score, vecbits, empty) is the one of the
//! original page's row builders; feed, hs-*, ssrc, ssvc-* and pi-* are the
//! additions for the tables the original did not have, and item, pend and
//! tr.overdue those of the triage tables (FR-A2/A3).
//!
//! Times: every timestamp on the page is UTC and carries the "UTC" label.
//! Date-only source values (e.g. CISA dueDate) are shown as a date with no time.
//!
//! Anchors filled on the page (see stack/wiki/page/skeleton.html):
//!   tbody  t-health t-kev t-adv t-dep t-nvd t-untriaged t-tickets
//!   text   s-kev s-crit s-high s-dep s-adv s-untriaged s-auto
//!          n-health n-kev n-adv n-dep n-nvd n-cvecap n-untriaged n-tickets winlabel
//!   stamp  rstat   (inner HTML, contains <b>; must never contain a <div>)
//!   html   l-kpis l-refresh   (inner HTML of a <div>, spans and links only, never a <div>)
//!
//! The Linear section (first on the page, above the "Threat feeds — last 7 days"
//! group) has the "Refresh tickets" link with the tickets' "as of" time in its heading
//! (`l-refresh`, changes every run) and opens with four tiles (`l-kpis`, since
//! 2026-11-06): two "now" tiles counted from the triage view, so they always equal
//! the two tables below them, and two "this month" tiles from the month-to-date
//! report (report.json), so they equal the PDF. One number per concept, each label
//! with its scope (now / this month / last 7 days).
//!
//! The triage tables take a TriageView, built by the caller from the triage
//! store and the tracker; render does not depend on the triage module's types.
//!
//! Item.extra values are read through Item::x / x_list / x_num, so a value of
//! another type than the one feeds/common.rs lists for its key counts as missing.
//!
//! Modules: fmt (dates, escaping, small HTML helpers), tables (one builder per
//! table body), demo (the standalone preview page).
//!
//! Preview:
//!   exploit-watch demo state/preview.html [--dark]

mod demo;
mod fmt;
mod tables;

use std::sync::LazyLock;

use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::feeds::common::{Fatal, Item, parse_iso};

pub use demo::{DemoArgs, demo};
pub use fmt::{esc, ftime, plural, thousands};
use fmt::{day, hm};
use tables::{
    build_adv_rows, build_cve_rows, build_dep_rows, build_health_rows, build_kev_rows, build_ticket_rows,
    build_untriaged_rows, cve_keep, feed_status, health_summary, kev_overdue, sev, tickets_missing, tickets_past_due,
};

pub const TBODY_IDS: [&str; 7] = ["t-health", "t-kev", "t-adv", "t-dep", "t-nvd", "t-untriaged", "t-tickets"];
pub const TEXT_IDS: [&str; 16] = [
    "s-kev", "s-crit", "s-high", "s-dep", "s-adv", "s-untriaged", "s-auto",
    "n-health", "n-kev", "n-adv", "n-dep", "n-nvd", "n-cvecap", "n-untriaged", "n-tickets", "winlabel",
];
pub const STAMP_ID: &str = "rstat";
/// <div> regions with inline markup (spans, b, a), never a nested <div>.
pub const HTML_IDS: [&str; 2] = ["l-kpis", "l-refresh"];

/// Page content and scriptCss, relative to the repo root (the job and demo run from there).
pub const SKELETON_PATH: &str = "stack/wiki/page/skeleton.html";
pub const STYLE_PATH: &str = "stack/wiki/page/style.css";

/// One row of the feed health table, built by run.rs (the "Linear" row: by triage/step.rs).
/// status: "ok" | "not-modified" | "cached" | "stale" | "error", or "off" for the Linear row
/// (anything else renders as stale)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthRow {
    pub source: String,
    pub status: String,
    pub items: usize,
    pub newest: String,
    pub last_success: String,
    pub note: String,
}

/// One row of the untriaged table: a matched item whose triage is not complete (the issue is
/// neither accepted nor declined, or was declined without a reason).
/// first_seen: ISO 8601 UTC. issue_identifier "" means the issue is not created yet ("pending").
/// overdue: set by the caller when the item has waited more than one business day.
/// note: shown under the issue, e.g. "declined in Linear without a reason"; "" for none.
/// no_reason: the issue was declined without a reason (counted as "need a reason").
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TriageRow {
    pub item_id: String,
    pub item_url: String,
    pub title: String,
    pub component: String,
    pub rule: String,
    pub first_seen: String,
    pub issue_identifier: String,
    pub issue_url: String,
    pub overdue: bool,
    pub note: String,
    pub no_reason: bool,
}

/// One row of the open tickets table: an accepted issue that is not closed.
/// due: YYYY-MM-DD or "" (no due date set). An empty assignee or due date is shown
/// in red as "no owner" / "no due date" (FR-A3 asks for both; Linear does not).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TicketRow {
    pub issue_identifier: String,
    pub issue_url: String,
    pub item_id: String,
    pub title: String,
    pub component: String,
    pub assignee: String,
    pub due: String,
    pub state_name: String,
}

/// What the triage tables show, built by the caller. auto_not_relevant: items in the
/// window marked not relevant by rule. mode_note: replaces the empty-row message of
/// both tables (e.g. when Linear sync is off); rows, when present, are shown as usual.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TriageView {
    pub untriaged: Vec<TriageRow>,
    pub tickets: Vec<TicketRow>,
    pub auto_not_relevant: usize,
    pub mode_note: Option<String>,
}

/// Everything the job writes, in a fixed order (tbody ids, then text ids, then html
/// ids, then rstat). An html region left out is not touched by apply_regions.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Regions {
    pub tbody: Vec<(String, String)>,
    pub text: Vec<(String, String)>,
    pub stamp: String,
    pub html: Vec<(String, String)>,
}

impl Regions {
    /// The value of a tbody, text or html region by anchor id ("" when absent).
    pub fn get(&self, id: &str) -> &str {
        if id == STAMP_ID {
            return &self.stamp;
        }
        self.tbody.iter().chain(self.text.iter()).chain(self.html.iter()).find(|(k, _)| k == id)
            .map(|(_, v)| v.as_str()).unwrap_or("")
    }
}

// ---------------------------------------------------------------- whole page

/// One labelled value of the status strip: small caps label, value, optional note.
fn status_item(label: &str, value: &str, note: &str, extra_class: &str) -> String {
    let note = if note.is_empty() { String::new() } else { format!("<span class=\"rsub\">{note}</span>") };
    format!("<span class=\"rkv{extra_class}\"><span class=\"rk\">{label}</span><span class=\"rv\">{value}</span>{note}</span>")
}

/// Inner HTML of <div id="rstat">: a status strip of labelled values (feeds with a
/// coloured dot, last update, KEV catalog) in <span class="rmeta">; report_links()
/// may append the report card after it. Spans only, never a <div>.
pub fn build_stamp(now: DateTime<Utc>, kev_catalog: &str, health: &[HealthRow]) -> String {
    let mut s = String::from("<span class=\"rmeta\">");
    if !health.is_empty() {
        let (cls, head) = feed_status(health);
        let summary = health_summary(health);
        let detail = summary.split_once(" &middot; ").map_or("", |(_, rest)| rest);
        s.push_str(&status_item("Feeds", &format!("<span class=\"rdot\"></span>{head}"), detail,
                                &format!(" rst-{cls}")));
    }
    s.push_str(&status_item("Updated", &format!("{}, {} UTC", day(&now, true), hm(&now)), "by the scheduled job", ""));
    if !kev_catalog.is_empty() {
        s.push_str(&status_item("CISA KEV catalog", &esc(kev_catalog), "", ""));
    }
    s.push_str("</span>");
    s
}

/// Display name of the FR-A4 report (MS-30 is the "Cyber threat dashboard").
pub const REPORT_NAME: &str = "Cyber threat report";

/// The latest frozen monthly report, as the card links it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MonthlyLink {
    /// "October 2026".
    pub title: String,
    /// Wiki asset path with ?v=<first 12 hex of the PDF sha>.
    pub href: String,
    /// "1 Nov 2026" (Amsterdam date of the freeze).
    pub frozen_on: String,
    /// The review reminder issue: (identifier such as TRI-31, URL).
    pub review: Option<(String, String)>,
}

impl MonthlyLink {
    /// From the fields of report::latest_monthly(): month "YYYY-MM", asset path, PDF
    /// sha256, frozen_at (RFC 3339) and the review issue. None when the month or the
    /// path is unusable.
    pub fn new(month: &str, path: &str, pdf_sha: &str, frozen_at: &str, review: Option<(String, String)>) -> Option<Self> {
        let first = NaiveDate::parse_from_str(&format!("{}-01", month.trim()), "%Y-%m-%d").ok()?;
        if path.trim().is_empty() {
            return None;
        }
        let v = &pdf_sha[..pdf_sha.len().min(12)];
        let href = if v.is_empty() { path.to_string() } else { format!("{path}?v={v}") };
        let frozen_on = parse_iso(frozen_at)
            .map(|t| crate::triage::store::to_amsterdam(t).format("%-d %b %Y").to_string())
            .unwrap_or_default();
        Some(MonthlyLink { title: first.format("%B %Y").to_string(), href, frozen_on, review })
    }
}

/// "1 Dec 2026": the first of the month after `now`'s Amsterdam month, when the
/// first monthly report is due.
fn next_first(now: DateTime<Utc>) -> String {
    let l = crate::triage::store::to_amsterdam(now).date();
    let (y, m) = if l.month() == 12 { (l.year() + 1, 1) } else { (l.year(), l.month() + 1) };
    NaiveDate::from_ymd_opt(y, m, 1).map(|d| d.format("%-d %b %Y").to_string()).unwrap_or_default()
}

/// `serve_url` trimmed of spaces and a trailing slash; None when empty.
fn serve_base(serve_url: Option<&str>) -> Option<&str> {
    serve_url.map(|u| u.trim().trim_end_matches('/')).filter(|u| !u.is_empty())
}

/// The FR-A4 report card, appended to the stamp: name, what it covers (FR-A4's own
/// words) and two buttons, plain links styled as buttons (the wiki strips scripts):
///   "Monthly report · <Month YYYY>": the latest frozen monthly PDF (`monthly`), with
///     the review issue as a small link; without one, "First monthly report: 1 <Mon YYYY>".
///   "Export snapshot": a month-to-date PDF, fresh from Linear through `serve`
///     (SERVE_PUBLIC_URL) or else the one the last run uploaded (`mtd_href`, with its
///     "as of" time `tickets_as_of`).
/// The word "official" is not used: the monthly report is final (frozen), not approved.
/// "" when there is no button at all.
pub fn report_links(monthly: Option<&MonthlyLink>, mtd_href: Option<&str>, tickets_as_of: &str,
                    serve_url: Option<&str>, now: DateTime<Utc>) -> String {
    let mut buttons = Vec::new();
    let mut notes = Vec::new();
    match monthly {
        Some(m) => {
            let tip = if m.frozen_on.is_empty() { "Final, frozen".to_string() } else { format!("Final, frozen on {}", esc(&m.frozen_on)) };
            buttons.push(format!("<a class=\"rbtn\" href=\"{}\" title=\"{tip}\">&darr;&nbsp; Monthly report &middot; {}</a>",
                                 esc(&m.href), esc(&m.title)));
            if let Some((id, url)) = m.review.as_ref().filter(|(id, _)| !id.trim().is_empty()) {
                let link = if url.starts_with("https://") || url.starts_with("http://") {
                    format!("<a class=\"rrev\" href=\"{}\">{}</a>", esc(url), esc(id))
                } else {
                    esc(id)
                };
                notes.push(format!("<span class=\"rreport-a\">Review: {link}</span>"));
            }
        }
        None => notes.push(format!("<span class=\"rreport-a\">First monthly report: {}</span>", next_first(now))),
    }
    if let Some(u) = serve_base(serve_url) {
        buttons.push(format!(
            "<a class=\"rbtn rbtn-2\" href=\"{}/report/month-to-date.pdf\" \
             title=\"Month to date, fresh from Linear. Not the monthly report.\">&darr;&nbsp; Export snapshot</a>",
            esc(u)
        ));
    } else if let Some(h) = mtd_href.filter(|h| !h.is_empty()) {
        buttons.push(format!(
            "<a class=\"rbtn rbtn-2\" href=\"{}\" title=\"Month to date, as of the last scheduled run. \
             Not the monthly report.\">&darr;&nbsp; Export snapshot</a>",
            esc(h)
        ));
        if let Some(t) = parse_iso(tickets_as_of) {
            notes.push(format!("<span class=\"rreport-a\">Snapshot data as of <b>{} {} UTC</b></span>", day(&t, false), hm(&t)));
        }
    }
    if buttons.is_empty() {
        return String::new();
    }
    format!(
        "<span class=\"rreport\"><span class=\"rreport-txt\">\
         <span class=\"rreport-t\"><b>{REPORT_NAME}</b></span>\
         <span class=\"rreport-d\">Items triaged, actions taken and actions open, with owner and due date. \
         Internal to fairCT.</span>{}</span><span class=\"rbtns\">{}</span></span>",
        notes.join(""),
        buttons.join("")
    )
}

// ---------------------------------------------------------------- Linear tiles

/// One tile of the Linear section: label, scope, number, detail line. With `href` the
/// whole tile links to the table it counts, else it is a plain span. `state` (class
/// kpi-<state>): "bad" overdue or missing items (red), "ok" nothing pending (green),
/// "open" pending but nothing late, "info" a month figure, "none" no figures yet.
fn kpi_tile(label: &str, scope: &str, n: &str, detail: &str, state: &str, href: Option<&str>) -> String {
    let inner = format!(
        "<span class=\"kpi-h\"><span class=\"kpi-l\">{label}</span><span class=\"kpi-sc\">{scope}</span></span>\
         <span class=\"kpi-n\">{n}</span><span class=\"kpi-d\">{detail}</span>"
    );
    match href {
        Some(h) => format!("<a class=\"kpi kpi-{state}\" href=\"{h}\">{inner}</a>"),
        None => format!("<span class=\"kpi kpi-{state}\">{inner}</span>"),
    }
}

/// The non-zero parts as "2 overdue &middot; 1 needs a reason", each in red, and
/// whether there was one; `none` when every part is zero. Parts: (n, singular, plural).
fn kpi_detail(parts: &[(usize, &str, &str)], none: &str) -> (String, bool) {
    let bad: Vec<String> = parts.iter().filter(|(n, ..)| *n > 0)
        .map(|(n, one, many)| format!("<span class=\"kpi-late\">{} {}</span>", thousands(*n), if *n == 1 { one } else { many }))
        .collect();
    if bad.is_empty() { (none.to_string(), false) } else { (bad.join(" &middot; "), true) }
}

/// The scope of the month tiles: the Amsterdam month of the report's tickets-as-of
/// time ("November"); "month to date" without a usable as_of. Not the day: l-kpis is
/// part of the page fingerprint, and a daily change would write a page version a day.
fn month_scope(r: &Value) -> String {
    r.get("as_of").and_then(Value::as_str).and_then(parse_iso)
        .map(|t| crate::triage::store::to_amsterdam(t).format("%B").to_string())
        .unwrap_or_else(|| "month to date".into())
}

/// "4 of 6 (67%)…", the value of the report's "assessed" KPI (assessed within 1 business day).
static KPI_WITHIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(\d+) of \d+").unwrap());

/// The four tiles of the Linear section (`l-kpis`), one number per concept:
///   Waiting for triage  now: the rows of the untriaged table (store view: no decision
///                       in Linear yet, or declined without a reason); overdue = waiting
///                       more than 1 business day; need a reason = declined without one
///   Open tickets        now: the rows of the open-tickets table; overdue = due date
///                       before `today`; no owner; no due date
///   Triaged this month  report funnel.assessed (the PDF's "assessed"); the detail is the
///                       x of the "assessed" KPI ("x of y (z%)", within 1 business day)
///   Closed this month   report outcomes.fixed_count + closed_without_fix
/// The "now" tiles use the same view and `today` as the tables, so they always agree
/// with them. Without a report (no `funnel`), the month tiles show "&mdash;".
pub fn linear_kpis(view: &TriageView, today: &str, report: Option<&Value>) -> String {
    let state = |n: usize, bad: bool| if bad { "bad" } else if n == 0 { "ok" } else { "open" };
    let u = &view.untriaged;
    let late = u.iter().filter(|r| r.overdue).count();
    let reason = u.iter().filter(|r| r.no_reason).count();
    let (d, bad) = kpi_detail(&[(late, "overdue", "overdue"), (reason, "needs a reason", "need a reason")],
                              if u.is_empty() { "none waiting" } else { "none overdue" });
    let mut s = kpi_tile("Waiting for triage", "now", &thousands(u.len()), &d, state(u.len(), bad), Some("#untriaged"));
    let t = &view.tickets;
    let (no_owner, no_due) = tickets_missing(t);
    let (d, bad) = kpi_detail(
        &[(tickets_past_due(t, today), "overdue", "overdue"), (no_owner, "no owner", "no owner"),
          (no_due, "no due date", "no due date")],
        if t.is_empty() { "none open" } else { "none overdue" },
    );
    s.push_str(&kpi_tile("Open tickets", "now", &thousands(t.len()), &d, state(t.len(), bad), Some("#tickets")));
    let Some(r) = report.filter(|r| r.get("funnel").is_some()) else {
        for label in ["Triaged this month", "Closed this month"] {
            s.push_str(&kpi_tile(label, "month to date", "&mdash;", "no month-to-date report yet", "none", None));
        }
        return s;
    };
    let n = |p: &str| r.pointer(p).and_then(Value::as_u64).unwrap_or(0) as usize;
    let len = |p: &str| r.pointer(p).and_then(Value::as_array).map_or(0, Vec::len);
    let scope = month_scope(r);
    let assessed = n("/funnel/assessed");
    let within = r.get("kpis").and_then(Value::as_array)
        .and_then(|ks| ks.iter().find(|k| k.get("key").and_then(Value::as_str) == Some("assessed")))
        .and_then(|k| k.get("value")).and_then(Value::as_str)
        .and_then(|v| KPI_WITHIN.captures(v)).and_then(|c| c[1].parse::<usize>().ok());
    let d = match (assessed, within) {
        (0, _) => "none yet".to_string(),
        (_, Some(x)) => format!("{} within 1 business day", thousands(x)),
        (_, None) => String::new(),
    };
    s.push_str(&kpi_tile("Triaged this month", &scope, &thousands(assessed), &d, "info", None));
    let (fixed, without) = (n("/outcomes/fixed_count"), len("/outcomes/closed_without_fix"));
    let d = if fixed + without == 0 {
        "none yet".to_string()
    } else {
        format!("{} fixed &middot; {} without fix", thousands(fixed), thousands(without))
    };
    s.push_str(&kpi_tile("Closed this month", &scope, &thousands(fixed + without), &d, "info", None));
    s
}

/// The "Refresh tickets" link to `serve` (none without SERVE_PUBLIC_URL) and "as of
/// HH:MM <CET|CEST>", the report's tickets-as-of time in Amsterdam time.
pub fn linear_refresh(report: Option<&Value>, serve_url: Option<&str>) -> String {
    let mut s = String::new();
    if let Some(u) = serve_base(serve_url) {
        s.push_str(&format!(
            "<a class=\"rbtn rbtn-2\" href=\"{}/refresh\" title=\"Reads the tickets back from Linear (a few seconds) \
             and updates this section. Feeds are not fetched again.\">&#8635;&nbsp; Refresh tickets</a>",
            esc(u)
        ));
    }
    if let Some(t) = report.and_then(|r| r.get("as_of")).and_then(Value::as_str).and_then(parse_iso) {
        let zone = if crate::triage::store::amsterdam_offset(t) == Duration::hours(2) { "CEST" } else { "CET" };
        s.push_str(&format!("<span class=\"lasof\">as of {} {zone}</span>",
                            crate::triage::store::to_amsterdam(t).format("%H:%M")));
    }
    s
}

/// The html regions (HTML_IDS order): the tiles for the triage view and a month-to-date
/// report's data, and the refresh link. `now`: the time the tables are rendered for
/// (its UTC date decides "overdue" for tickets, as in the tables).
pub fn linear_regions(view: &TriageView, now: DateTime<Utc>, report: Option<&Value>, serve_url: Option<&str>)
                      -> Vec<(String, String)> {
    let today = now.format("%Y-%m-%d").to_string();
    HTML_IDS.iter().map(|s| s.to_string())
        .zip([linear_kpis(view, &today, report), linear_refresh(report, serve_url)]).collect()
}

/// Everything the job writes. start/end/now are UTC. cap 0 means no CVE row cap.
/// The triage view comes from the caller (TriageView::default() shows empty tables).
/// `tracker` is the "Linear" row of the health table (None: no row). It is kept out
/// of `health`, which also feeds the health count, the stamp and the run record.
#[allow(clippy::too_many_arguments)]
pub fn build_regions(
    kev: &[Item], adv: &[Item], dep: &[Item], cve: &[Item], health: &[HealthRow], tracker: Option<&HealthRow>,
    triage: &TriageView, start: DateTime<Utc>, end: DateTime<Utc>, now: DateTime<Utc>, kev_catalog: &str,
    cap: usize,
) -> Regions {
    let today = end.format("%Y-%m-%d").to_string();
    let (cve_html, shown, total) = build_cve_rows(cve, cap);
    let kept = cve_keep(cve);
    let n_crit = kept.iter().filter(|it| sev(it) == "CRITICAL").count();
    let n_high = kept.iter().filter(|it| sev(it) == "HIGH").count();
    let overdue = kev_overdue(kev, &today);
    let note = triage.mode_note.as_deref();

    let tbody = [
        build_health_rows(health, tracker),
        build_kev_rows(kev, &today),
        build_adv_rows(adv),
        build_dep_rows(dep),
        cve_html,
        build_untriaged_rows(&triage.untriaged, note),
        build_ticket_rows(&triage.tickets, &today, note),
    ];
    let mut n_kev = plural(kev.len(), "entry", Some("entries"));
    if overdue > 0 {
        n_kev.push_str(&format!(" &middot; {overdue} past deadline"));
    }
    let text = [
        thousands(kev.len()),
        thousands(n_crit),
        thousands(n_high),
        thousands(dep.len()),
        thousands(adv.len()),
        untriaged_summary(triage),
        thousands(triage.auto_not_relevant),
        health_summary(health),
        n_kev,
        plural(adv.len(), "advisory", Some("advisories")),
        plural(dep.len(), "advisory", Some("advisories")),
        plural(total, "CVE", None),
        if shown < total {
            format!("Showing {} of {}, highest score first.", thousands(shown), thousands(total))
        } else {
            format!("All {} shown.", thousands(total))
        },
        plural(triage.untriaged.len(), "item", None),
        tickets_summary(triage, &today),
        format!("{} {} &rarr; {} {} UTC", day(&start, false), hm(&start), day(&end, false), hm(&end)),
    ];
    Regions {
        tbody: TBODY_IDS.iter().map(|s| s.to_string()).zip(tbody).collect(),
        text: TEXT_IDS.iter().map(|s| s.to_string()).zip(text).collect(),
        stamp: build_stamp(now, kev_catalog, health),
        // Without a report: the caller puts the month-to-date report in (linear_regions).
        html: linear_regions(triage, end, None, None),
    }
}

/// s-untriaged: "3", or "3 &middot; 1 overdue &middot; 1 need a reason" (the words of the tile).
fn untriaged_summary(triage: &TriageView) -> String {
    let mut s = thousands(triage.untriaged.len());
    let late = triage.untriaged.iter().filter(|r| r.overdue).count();
    let reason = triage.untriaged.iter().filter(|r| r.no_reason).count();
    if late > 0 {
        s.push_str(&format!(" &middot; {} overdue", thousands(late)));
    }
    if reason > 0 {
        s.push_str(&format!(" &middot; {} {}", thousands(reason), if reason == 1 { "needs a reason" } else { "need a reason" }));
    }
    s
}

/// n-tickets: "2 tickets", plus overdue / no owner / no due date counts when non-zero.
fn tickets_summary(triage: &TriageView, today: &str) -> String {
    let (no_owner, no_due) = tickets_missing(&triage.tickets);
    let mut s = plural(triage.tickets.len(), "ticket", None);
    for (n, what) in [(tickets_past_due(&triage.tickets, today), "overdue"), (no_owner, "no owner"), (no_due, "no due date")] {
        if n > 0 {
            s.push_str(&format!(" &middot; {} {what}", thousands(n)));
        }
    }
    s
}

/// Ticket-table ids that `ticket_regions` fills (s-auto is not one: it counts the
/// items of a run's window, which a partial refresh does not have).
pub const TICKET_TBODY_IDS: [&str; 2] = ["t-untriaged", "t-tickets"];
pub const TICKET_TEXT_IDS: [&str; 3] = ["s-untriaged", "n-untriaged", "n-tickets"];

/// The Linear section only: the two triage tables, their counters and the html
/// regions (tiles, refresh link), exactly as build_regions plus linear_regions render
/// them for the same view, `now` (end of the window), report and serve URL, for
/// `serve`'s partial re-splice. `stamp` is left empty: the caller puts back the page's
/// own stamp (stamp_of), since apply_regions always writes it.
pub fn ticket_regions(view: &TriageView, now: DateTime<Utc>, report: Option<&Value>, serve_url: Option<&str>) -> Regions {
    let today = now.format("%Y-%m-%d").to_string();
    let note = view.mode_note.as_deref();
    let tbody = [build_untriaged_rows(&view.untriaged, note), build_ticket_rows(&view.tickets, &today, note)];
    let text = [untriaged_summary(view), plural(view.untriaged.len(), "item", None), tickets_summary(view, &today)];
    Regions {
        tbody: TICKET_TBODY_IDS.iter().map(|s| s.to_string()).zip(tbody).collect(),
        text: TICKET_TEXT_IDS.iter().map(|s| s.to_string()).zip(text).collect(),
        stamp: String::new(),
        html: linear_regions(view, now, report, serve_url),
    }
}

static TAG_OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^<([a-zA-Z0-9]+)[^>]*>").unwrap());

/// The first element whose opening tag carries id="EID", up to the first closing
/// tag of the same name. TAG is "div" when div_only, else any `[a-zA-Z0-9]+`.
/// Same match as `(<(TAG)[^>]*\bid="EID"[^>]*>)(.*?)(</\2>)` (dot matches newline);
/// the regex crate has no backreference, so this walks that search order by hand:
/// leftmost '<', then the longest tag name first.
/// -> (start, end of the opening tag, start of the closing tag, end of the match).
fn find_element(doc: &str, eid: &str, div_only: bool) -> Option<(usize, usize, usize, usize)> {
    let id_attr = format!("id=\"{eid}\"");
    for (p, _) in doc.match_indices('<') {
        let Some(m) = TAG_OPEN.captures(&doc[p..]) else { continue };
        let open = m.get(0).unwrap();
        let name = m.get(1).unwrap().as_str();
        let tag_text = open.as_str();
        // \bid="EID" somewhere after the name, inside this tag.
        let has_id = tag_text.match_indices(&id_attr).any(|(i, _)| {
            i > name.len() && !tag_text[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_')
        });
        if !has_id {
            continue;
        }
        let open_end = p + open.end();
        let names: Vec<&str> = if div_only {
            if name.starts_with("div") { vec!["div"] } else { vec![] }
        } else {
            (1..=name.len()).rev().map(|l| &name[..l]).collect()
        };
        for tag in names {
            let close = format!("</{tag}>");
            if let Some(i) = doc[open_end..].find(&close) {
                let cs = open_end + i;
                return Some((p, open_end, cs, cs + close.len()));
            }
        }
    }
    None
}

/// The inner HTML of the page's stamp (`rstat`), as last written. A partial
/// re-splice (serve) passes it back unchanged, since apply_regions always writes
/// the stamp. None when the page has no stamp anchor.
pub fn stamp_of(doc: &str) -> Option<String> {
    find_element(doc, STAMP_ID, true).map(|(_, open_end, close_start, _)| doc[open_end..close_start].to_string())
}

/// Splice regions into the page HTML. Err names the first missing anchor. Idempotent.
pub fn apply_regions(doc: &str, regions: &Regions) -> Result<String, Fatal> {
    let mut doc = doc.to_string();
    for (tid, rows) in &regions.tbody {
        let open = format!("<tbody id=\"{tid}\">");
        let found = doc.find(&open).and_then(|s| {
            let body = s + open.len();
            doc[body..].find("</tbody>").map(|i| (body, body + i))
        });
        let Some((a, b)) = found else {
            return Err(Fatal(format!("page anchor <tbody id=\"{tid}\"> not found — re-seed the page skeleton")));
        };
        doc.replace_range(a..b, rows);
    }
    let stamp = (STAMP_ID.to_string(), regions.stamp.clone());
    for (eid, text) in regions.text.iter().chain(regions.html.iter()).chain(std::iter::once(&stamp)) {
        let div = eid == STAMP_ID || HTML_IDS.contains(&eid.as_str());
        let Some((_, open_end, close_start, _)) = find_element(&doc, eid, div) else {
            return Err(Fatal(format!("page anchor id=\"{eid}\" not found — re-seed the page skeleton")));
        };
        doc.replace_range(open_end..close_start, text);
    }
    Ok(doc)
}

// ---------------------------------------------------------------- tests

/// Inputs shared by the tests of the render modules.
#[cfg(test)]
mod test_support {
    use std::path::{Path, PathBuf};

    use regex::Regex;
    use serde_json::json;

    use super::{TicketRow, TriageRow, TriageView};
    use crate::feeds::common::Item;
    pub use crate::feeds::kev::testutil::repo_root;

    pub const EVIL: &str = r#"<script>alert(1)</script>"><img src=x onerror=alert(2)>"#;

    /// A file by its path relative to the repo root, such as SKELETON_PATH.
    pub fn read(rel: &str) -> String {
        super::demo::read_text(&repo_root().join(rel)).unwrap()
    }

    pub fn fixture_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/render_items.json")
    }

    pub fn re(p: &str) -> Regex {
        Regex::new(p).unwrap()
    }

    pub fn evil_item() -> Item {
        let mut it = Item::new(EVIL, &format!("CVE-2026-0001{EVIL}"), "javascript:alert(3)", EVIL, "2026-11-03T02:31:19Z");
        it.updated = "2026-11-03T03:00:00Z".into();
        it.cves = vec![format!("CVE-2026-0002{EVIL}")];
        it.score = 9.8;
        it.severity = "CRITICAL".into();
        it.extra = json!({"vendor": EVIL, "product": EVIL, "due": "2026-11-01", "euvd_id": EVIL,
            "sources": [EVIL], "version": EVIL, "products": [EVIL],
            "probability": EVIL, "impact": "H", "ghsa": EVIL, "ecosystems": [EVIL],
            "packages": [EVIL], "fixed": [EVIL], "npkg": 1, "score_source": EVIL,
            "vector": EVIL, "vendors": [EVIL], "ssvc_exploitation": "active",
            "assigner": EVIL, "nvd_score": 7.0})
        .as_object()
        .unwrap()
        .clone();
        it
    }

    /// Hostile text in every string field of both triage rows; URLs are javascript:.
    pub fn evil_triage() -> TriageView {
        TriageView {
            untriaged: vec![TriageRow {
                item_id: EVIL.into(), item_url: "javascript:alert(3)".into(), title: EVIL.into(),
                component: EVIL.into(), rule: EVIL.into(), first_seen: EVIL.into(),
                issue_identifier: EVIL.into(), issue_url: "javascript:alert(4)".into(), overdue: true, note: EVIL.into(),
                no_reason: true,
            }],
            tickets: vec![TicketRow {
                issue_identifier: EVIL.into(), issue_url: "javascript:alert(5)".into(), item_id: EVIL.into(),
                title: EVIL.into(), component: EVIL.into(), assignee: EVIL.into(), due: EVIL.into(),
                state_name: EVIL.into(),
            }],
            auto_not_relevant: 1,
            mode_note: Some(EVIL.into()),
        }
    }

    pub fn assert_clean(out: &str) {
        assert!(!out.contains("<script"), "{out}");
        assert!(!out.contains("<img"), "{out}");
        assert!(!out.contains("javascript:"), "{out}");
        assert!(out.contains("&lt;script&gt;"), "{out}");
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{evil_item, evil_triage, fixture_path, re, read};
    use super::*;

    fn skel() -> String {
        read(SKELETON_PATH)
    }

    fn first_row_cells(rows: &str) -> usize {
        let first = re(r"(?s)^<tr\b[^>]*>(.*?)</tr>").captures(rows).unwrap()[1].to_string();
        let tds: Vec<String> = re(r"<td\b([^>]*)>").captures_iter(&first).map(|c| c[1].to_string()).collect();
        if tds.len() == 1 {
            return re(r#"colspan="(\d+)""#).captures(&tds[0]).map_or(1, |m| m[1].parse().unwrap());
        }
        tds.len()
    }

    /// Number of <th> in the <thead> right before <tbody id="tid">.
    fn thead_cols(tid: &str) -> usize {
        let s = skel();
        let t = s.find(&format!("<tbody id=\"{tid}\">")).unwrap();
        let before = s[..t].trim_end();
        let close = before.strip_suffix("</thead>").map(str::len).unwrap();
        let open = before[..close].rfind("<thead>").unwrap() + "<thead>".len();
        re(r"<th\b").find_iter(&before[open..close]).count()
    }

    /// Regions of the demo fixture.
    fn load() -> Regions {
        demo::load_fixture(&fixture_path()).unwrap().regions()
    }

    fn all_anchors() -> Vec<&'static str> {
        TBODY_IDS.iter().chain(TEXT_IDS.iter()).chain(HTML_IDS.iter()).copied().chain([STAMP_ID]).collect()
    }

    // ------------------------------------------------ skeleton

    #[test]
    fn every_anchor_exactly_once() {
        let s = skel();
        for a in all_anchors() {
            assert_eq!(s.matches(&format!("id=\"{a}\"")).count(), 1, "{a}");
        }
        for t in TBODY_IDS {
            assert_eq!(s.matches(&format!("<tbody id=\"{t}\">")).count(), 1, "{t}");
        }
    }

    #[test]
    fn plain_text_anchors_have_no_child_tags() {
        let s = skel();
        for a in TEXT_IDS {
            let (_, open_end, close_start, _) = find_element(&s, a, false).unwrap_or_else(|| panic!("{a}"));
            assert!(!s[open_end..close_start].contains('<'), "{a}");
        }
    }

    #[test]
    fn refresh_bar_exact() {
        let s = skel();
        assert!(s.contains(r#"<div class="refresh"><div class="wrap"><div class="rstat" id="rstat">"#));
        let m = re(r#"(?s)id="rstat">(.*?)</div></div></div>"#).captures(&s).expect("rstat");
        assert!(!m[1].contains("<div"));
    }

    #[test]
    fn no_stripped_or_document_tags() {
        let s = skel().to_lowercase();
        // \b so that the page's own <header> is not taken for <head>.
        for bad in [r"<style\b", r"<script\b", r"<link\b", r"<html\b", r"<head\b", r"<body\b", r"\bstyle="] {
            assert!(!re(bad).is_match(&s), "{bad}");
        }
    }

    #[test]
    fn wrapper_and_balanced_divs() {
        let s = skel();
        assert!(s.trim_start().starts_with(r#"<div id="ew">"#));
        assert_eq!(s.matches("<div").count(), s.matches("</div>").count());
        assert_eq!(s.matches("<table").count(), s.matches("</table>").count());
    }

    #[test]
    fn css_is_scoped() {
        let css = read(STYLE_PATH);
        let body = re(r"(?s)/\*.*?\*/").replace_all(&css, "").to_string();
        let body = re(r"@import[^;]*;").replace_all(&body, "").to_string();
        let body = re(r"@media[^{]*\{").replace_all(&body, "").to_string();
        for m in re(r"([^{}]+)\{").captures_iter(&body) {
            for part in m[1].split(',') {
                let part = part.trim();
                if !part.is_empty() {
                    assert!(part.contains("#ew"), "{part}");
                }
            }
        }
        assert!(!css.to_lowercase().contains("</style"));
        // Only the font import may sit outside a rule, and it must come first.
        assert_eq!(css.matches("@import").count(), 1);
        assert!(css.starts_with("@import url(https://fonts.googleapis.com/"));
    }

    // ------------------------------------------------ whole page

    #[test]
    fn column_counts_match_thead() {
        let r = load();
        for (tid, rows) in &r.tbody {
            assert_eq!(first_row_cells(rows), thead_cols(tid), "{tid}");
        }
        let empties = [
            ("t-health", build_health_rows(&[], None)), ("t-kev", build_kev_rows(&[], "")),
            ("t-adv", build_adv_rows(&[])), ("t-dep", build_dep_rows(&[])),
            ("t-nvd", build_cve_rows(&[], 300).0),
            ("t-untriaged", build_untriaged_rows(&[], None)), ("t-tickets", build_ticket_rows(&[], "", None)),
            ("t-untriaged", build_untriaged_rows(&[], Some("Linear sync is off."))),
            ("t-tickets", build_ticket_rows(&[], "", Some("Linear sync is off."))),
        ];
        for (tid, rows) in empties {
            assert_eq!(first_row_cells(&rows), thead_cols(tid), "empty {tid}");
        }
    }

    fn t_now() -> DateTime<Utc> {
        parse_iso("2026-11-06T09:00:00Z").unwrap()
    }

    fn monthly() -> MonthlyLink {
        MonthlyLink::new("2026-10", "/exploit-watch/report-2026-10.pdf", "0123456789abcdef", "2026-11-01T05:00:12Z",
                         Some(("TRI-31".into(), "https://linear.app/x/issue/TRI-31".into()))).unwrap()
    }

    /// The parts of a month-to-date report.json the tiles read (and some they must not:
    /// funnel.waiting and open_actions count other sets than the tables).
    fn report_fixture() -> Value {
        serde_json::json!({
            "as_of": "2026-11-06T13:05:00Z",
            "period": {"start": "2026-11-01T00:00:00+01:00", "month": "November 2026"},
            "funnel": {"assessed": 5, "waiting": 9, "over_one_day": [
                {"key": "a", "first_seen": "2026-11-02T10:00:00+01:00", "assessed_at": null, "business_hours": null},
                {"key": "c", "first_seen": "2026-11-03T10:00:00+01:00", "assessed_at": "2026-11-05T10:00:00+01:00",
                 "business_hours": 48.0}]},
            "kpis": [{"key": "relevant", "value": "7"},
                     {"key": "assessed", "value": "4 of 6 (67%); 1 without a reason"}],
            "open_actions": {"count": 8, "overdue": 7, "items": []},
            "outcomes": {"fixed_count": 2, "closed_without_fix": [{"key": "d"}]},
        })
    }

    /// The tile with this label: (class, scope, number, detail), from a tiles region.
    fn tile(html: &str, label: &str) -> (String, String, String, String) {
        let p = format!(
            r#"<(?:a|span) class="kpi ([a-z-]+)"(?: href="[^"]*")?><span class="kpi-h"><span class="kpi-l">{}</span><span class="kpi-sc">([^<]*)</span></span><span class="kpi-n">([^<]*)</span><span class="kpi-d">((?:[^<]|<span class="kpi-late">[^<]*</span>)*)</span></(?:a|span)>"#,
            regex::escape(label));
        let c = re(&p).captures(html).unwrap_or_else(|| panic!("{label}: {html}"));
        (c[1].to_string(), c[2].to_string(), c[3].to_string(), c[4].to_string())
    }

    #[test]
    fn monthly_link_from_latest_monthly() {
        let m = monthly();
        assert_eq!((m.title.as_str(), m.frozen_on.as_str()), ("October 2026", "1 Nov 2026"));
        assert_eq!(m.href, "/exploit-watch/report-2026-10.pdf?v=0123456789ab");
        assert!(MonthlyLink::new("2026-13", "/x.pdf", "", "", None).is_none());
        assert!(MonthlyLink::new("2026-10", " ", "", "", None).is_none());
        assert_eq!(MonthlyLink::new("2026-10", "/x.pdf", "", "", None).unwrap().href, "/x.pdf");
    }

    #[test]
    fn report_card_buttons() {
        assert_eq!(report_links(None, None, "", None, t_now()), "");
        assert_eq!(report_links(None, Some(""), "", Some("  "), t_now()), "");
        // Lab: a frozen month and serve.
        let lab = report_links(Some(&monthly()), Some("/exploit-watch/report-month-to-date.pdf?v=abc"),
                               "2026-11-05T07:31:00Z", Some("http://localhost:8090/"), t_now());
        assert!(lab.starts_with(r#"<span class="rreport">"#), "{lab}");
        assert!(lab.contains(r#"<a class="rbtn" href="/exploit-watch/report-2026-10.pdf?v=0123456789ab" title="Final, frozen on 1 Nov 2026">&darr;&nbsp; Monthly report &middot; October 2026</a>"#), "{lab}");
        assert!(lab.contains(r#"<span class="rreport-a">Review: <a class="rrev" href="https://linear.app/x/issue/TRI-31">TRI-31</a></span>"#), "{lab}");
        assert!(lab.contains(r#"<a class="rbtn rbtn-2" href="http://localhost:8090/report/month-to-date.pdf" title="Month to date, fresh from Linear. Not the monthly report.">&darr;&nbsp; Export snapshot</a>"#), "{lab}");
        assert!(!lab.contains("report-month-to-date.pdf"), "serve wins over the uploaded asset: {lab}");
        assert!(!lab.contains("First monthly report") && !lab.contains("Snapshot data as of"), "{lab}");
        assert!(!lab.contains("Download report") && !lab.to_lowercase().contains("official"), "{lab}");
        assert!(!lab.contains("<div"), "the stamp may not hold a div");
        // No monthly report yet, no serve: the uploaded asset with its time (option B).
        let b = report_links(None, Some("/exploit-watch/report-month-to-date.pdf?v=abc"), "2026-11-05T07:31:00Z", None, t_now());
        assert!(b.contains(r#"<span class="rreport-a">First monthly report: 1 Dec 2026</span>"#), "{b}");
        assert!(b.contains(r#"<a class="rbtn rbtn-2" href="/exploit-watch/report-month-to-date.pdf?v=abc""#), "{b}");
        assert!(b.contains("Snapshot data as of <b>5 Nov 07:31 UTC</b>") && !b.contains("Monthly report &middot;"), "{b}");
        // December rolls over to January; Amsterdam time decides the month.
        let dec = report_links(None, None, "", Some("http://x"), parse_iso("2026-12-31T23:30:00Z").unwrap());
        assert!(dec.contains("First monthly report: 1 Feb 2027"), "{dec}");
        // A review without a usable URL is shown as text; hostile values are escaped.
        let mut m = monthly();
        m.review = Some((r#"<script>"#.into(), "javascript:alert(1)".into()));
        m.href = r#"/x?v="><script>"#.into();
        let evil = report_links(Some(&m), None, "", None, t_now());
        assert!(!evil.contains("<script>") && !evil.contains("javascript:"), "{evil}");
        assert!(evil.contains("Review: &lt;script&gt;</span>"), "{evil}");
    }

    fn t4(a: &str, b: &str, c: &str, d: &str) -> (String, String, String, String) {
        (a.into(), b.into(), c.into(), d.into())
    }

    #[test]
    fn month_tiles_from_the_report() {
        let r = report_fixture();
        let s = linear_kpis(&TriageView::default(), "2026-11-06", Some(&r));
        assert_eq!(tile(&s, "Triaged this month"), t4("kpi-info", "November", "5", "4 within 1 business day"));
        assert_eq!(tile(&s, "Closed this month"), t4("kpi-info", "November", "3", "2 fixed &middot; 1 without fix"));
        // funnel.waiting (9) and open_actions (8, 7 overdue) count other sets than the tables: not shown.
        assert!(!s.contains('9') && !s.contains('8') && !s.contains('7'), "{s}");
        // An empty view: both "now" tiles green, and links to their tables; the month tiles are not links.
        assert_eq!(tile(&s, "Waiting for triage"), t4("kpi-ok", "now", "0", "none waiting"));
        assert_eq!(tile(&s, "Open tickets"), t4("kpi-ok", "now", "0", "none open"));
        assert!(s.starts_with(r##"<a class="kpi kpi-ok" href="#untriaged">"##), "{s}");
        assert!(s.contains(r##"<a class="kpi kpi-ok" href="#tickets">"##), "{s}");
        assert_eq!(s.matches(r#"<span class="kpi kpi-info">"#).count(), 2, "{s}");
        assert!(!s.contains("<div"), "an html region holds no div: {s}");
        // Nothing triaged or closed yet.
        let mut calm = r.clone();
        calm["funnel"]["assessed"] = serde_json::json!(0);
        calm["outcomes"] = serde_json::json!({"fixed_count": 0, "closed_without_fix": []});
        let s = linear_kpis(&TriageView::default(), "2026-11-06", Some(&calm));
        assert_eq!(tile(&s, "Triaged this month"), t4("kpi-info", "November", "0", "none yet"));
        assert_eq!(tile(&s, "Closed this month"), t4("kpi-info", "November", "0", "none yet"));
        // A KPI value without "x of y": the number stays, the detail is left out.
        let mut odd = r.clone();
        odd["kpis"] = serde_json::json!([{"key": "assessed", "value": "—; 1 without a reason"}]);
        assert_eq!(tile(&linear_kpis(&TriageView::default(), "2026-11-06", Some(&odd)), "Triaged this month").3, "");
        // Scope: the Amsterdam month of as_of (00:30 on 1 Nov there); no as_of.
        let mut first = r.clone();
        first["as_of"] = serde_json::json!("2026-10-31T23:30:00Z");
        assert_eq!(tile(&linear_kpis(&TriageView::default(), "2026-11-01", Some(&first)), "Closed this month").1, "November");
        first.as_object_mut().unwrap().remove("as_of");
        assert_eq!(tile(&linear_kpis(&TriageView::default(), "2026-11-01", Some(&first)), "Closed this month").1, "month to date");
    }

    #[test]
    fn month_tiles_without_a_report() {
        for rep in [None, Some(serde_json::json!({"error": "x"}))] {
            let s = linear_kpis(&TriageView::default(), "2026-11-06", rep.as_ref());
            for label in ["Triaged this month", "Closed this month"] {
                assert_eq!(tile(&s, label), t4("kpi-none", "month to date", "&mdash;", "no month-to-date report yet"));
            }
            assert_eq!(tile(&s, "Waiting for triage").2, "0");
        }
        // A run without a report (dry run with none on disk) renders the same tiles.
        let t = parse_iso("2026-11-03T02:45:00Z").unwrap();
        let r = build_regions(&[], &[], &[], &[], &[], None, &TriageView::default(), t, t, t, "", 300);
        assert_eq!(r.get("l-kpis"), linear_kpis(&TriageView::default(), "2026-11-03", None));
        assert_eq!(r.get("l-refresh"), "");
    }

    /// The "now" tiles count exactly the rows of the two tables, in the words of
    /// their counters; the month tiles come from the fixture's report part.
    #[test]
    fn now_tiles_equal_the_tables() {
        let r = load();
        let k = r.get("l-kpis");
        let rows = |id: &str| r.get(id).matches("<tr").count().to_string();
        let (cls, scope, n, d) = tile(k, "Waiting for triage");
        assert_eq!((cls.as_str(), scope.as_str(), n.as_str()), ("kpi-bad", "now", rows("t-untriaged").as_str()));
        assert_eq!(format!("{n} items"), r.get("n-untriaged"));
        assert_eq!(r.get("t-untriaged").matches(r#"<tr class="overdue">"#).count(), 2);
        assert_eq!(r.get("t-untriaged").matches("declined in Linear without a reason").count(), 1);
        assert_eq!(d, r#"<span class="kpi-late">2 overdue</span> &middot; <span class="kpi-late">1 needs a reason</span>"#);
        assert_eq!(r.get("s-untriaged"), "4 &middot; 2 overdue &middot; 1 needs a reason");
        let (cls, scope, n, d) = tile(k, "Open tickets");
        assert_eq!((cls.as_str(), scope.as_str(), n.as_str()), ("kpi-bad", "now", rows("t-tickets").as_str()));
        assert_eq!(d, concat!(r#"<span class="kpi-late">1 overdue</span> &middot; <span class="kpi-late">1 no owner</span>"#,
                              r#" &middot; <span class="kpi-late">1 no due date</span>"#));
        assert_eq!(r.get("n-tickets"), "3 tickets &middot; 1 overdue &middot; 1 no owner &middot; 1 no due date");
        assert_eq!(tile(k, "Triaged this month"), t4("kpi-info", "November", "13", "11 within 1 business day"));
        assert_eq!(tile(k, "Closed this month"), t4("kpi-info", "November", "2", "1 fixed &middot; 1 without fix"));
        // Pending but nothing late or missing: neutral.
        let calm = TriageView {
            untriaged: vec![TriageRow { item_id: "A".into(), ..Default::default() }],
            tickets: vec![TicketRow { issue_identifier: "T-1".into(), assignee: "Ann".into(), due: "2026-12-01".into(),
                                      ..Default::default() }],
            ..Default::default()
        };
        let s = linear_kpis(&calm, "2026-11-06", None);
        assert_eq!(tile(&s, "Waiting for triage"), t4("kpi-open", "now", "1", "none overdue"));
        assert_eq!(tile(&s, "Open tickets"), t4("kpi-open", "now", "1", "none overdue"));
        // Hostile text in the view and the report never reaches the tiles unescaped.
        let evil = linear_regions(&evil_triage(), t_now(),
                                  Some(&serde_json::json!({"funnel": {}, "as_of": super::test_support::EVIL,
                                                           "kpis": [{"key": "assessed", "value": super::test_support::EVIL}]})),
                                  Some(super::test_support::EVIL));
        assert!(!evil.iter().any(|(_, v)| v.contains("<script") || v.contains("<div")), "{evil:?}");
    }

    /// "Refresh tickets" (lab only) and the tickets' "as of" time in Amsterdam time.
    #[test]
    fn refresh_link_and_as_of() {
        let r = report_fixture();
        // 13:05 UTC is 14:05 in Amsterdam in November (CET), 15:05 in summer (CEST).
        let f = linear_refresh(Some(&r), Some("http://localhost:8090/"));
        assert!(f.starts_with(r#"<a class="rbtn rbtn-2" href="http://localhost:8090/refresh" title="Reads the tickets back from Linear (a few seconds) and updates this section. Feeds are not fetched again.">"#), "{f}");
        assert!(f.contains("Refresh tickets</a>") && f.ends_with(r#"<span class="lasof">as of 14:05 CET</span>"#), "{f}");
        let mut summer = r.clone();
        summer["as_of"] = serde_json::json!("2026-07-01T13:05:00Z");
        assert!(linear_refresh(Some(&summer), None).ends_with("as of 15:05 CEST</span>"));
        assert_eq!(linear_refresh(Some(&r), None), r#"<span class="lasof">as of 14:05 CET</span>"#);
        assert_eq!(linear_refresh(None, None), "");
        let regions = linear_regions(&TriageView::default(), t_now(), Some(&r), None);
        assert_eq!(regions.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), HTML_IDS);
    }

    /// Spliced into the page: the tiles under the Linear heading, the refresh link on
    /// the heading's right; a partial refresh (ticket_regions) leaves the rest alone.
    #[test]
    fn html_regions_splice() {
        let r = load();
        let page = apply_regions(&skel(), &r).unwrap();
        assert_eq!(apply_regions(&page, &r).unwrap(), page, "idempotent");
        assert!(page.contains(r##"<div class="kpis" id="l-kpis"><a class="kpi kpi-bad" href="#untriaged">"##), "tiles spliced");
        let mut part = ticket_regions(&TriageView::default(), t_now(), Some(&report_fixture()), Some("http://localhost:8090"));
        part.stamp = stamp_of(&page).unwrap();
        let out = apply_regions(&page, &part).unwrap();
        assert!(out.contains(concat!(
            r#"<div class="shead"><h2>Triage and actions (Linear)</h2><div class="lact" id="l-refresh">"#,
            r#"<a class="rbtn rbtn-2" href="http://localhost:8090/refresh" "#)), "refresh link in the heading");
        assert!(out.contains(r#"<span class="lasof">as of 14:05 CET</span></div></div>"#));
        assert!(out.contains(r##"<div class="kpis" id="l-kpis"><a class="kpi kpi-ok" href="#untriaged">"##), "now tiles refreshed");
        let inner = |d: &str, id: &str| find_element(d, id, false).map(|(_, a, b, _)| d[a..b].to_string()).unwrap();
        for id in ["s-auto", "s-kev", "n-health", "t-kev", "rstat"] {
            assert_eq!(inner(&out, id), inner(&page, id), "{id}");
        }
        assert!(apply_regions(&skel().replace(r#"id="l-refresh""#, ""), &r).is_err());
        assert!(apply_regions(&skel().replace(r#"id="l-kpis""#, ""), &r).is_err());
    }

    /// The Linear section (tiles, untriaged, open tickets) comes first, then the group
    /// "Threat feeds — last 7 days" (five tiles, feed health, KEV, advisories, deps,
    /// CVEs as h3 subsections), then sources and terminal; long tables scroll.
    #[test]
    fn page_order_and_scrolling_tables() {
        let s = skel();
        let at = |needle: &str| s.find(needle).unwrap_or_else(|| panic!("{needle}"));
        let order = [r#"id="rstat""#, r#"<section class="block" id="linear">"#,
                     "Triage and actions (Linear)", r#"id="l-refresh""#, r#"id="l-kpis""#,
                     r#"<section class="block" id="untriaged">"#, r#"<section class="block" id="tickets">"#,
                     r#"<section class="block" id="feeds">"#, "<h2>Threat feeds &mdash; last 7 days</h2>",
                     r#"<div class="triage">"#, r#"id="s-kev""#, r#"id="s-adv""#,
                     r#"<section class="block" id="health">"#, r#"id="kev""#, r#"id="adv""#, r#"id="deps""#,
                     r#"id="nvd""#, r#"<section class="block" id="sources">"#, r#"<section class="block" id="terminal">"#];
        for w in order.windows(2) {
            assert!(at(w[0]) < at(w[1]), "{} before {}", w[0], w[1]);
        }
        assert!(s.contains(r#"<div class="shead"><h2>Triage and actions (Linear)</h2><div class="lact" id="l-refresh"></div></div>"#));
        assert!(!s.contains("lbar") && !s.contains("l-summary"), "no separate summary bar");
        // Each group closes right after its last table.
        let squash = |a: &str, b: &str| re(r"\s+").replace_all(s[at(a)..at(b)].split_once("</tbody>").unwrap().1, "").to_string();
        assert_eq!(squash(r#"<tbody id="t-tickets">"#, r#"<section class="block" id="feeds">"#),
                   "</table></div></div></section></section>");
        assert_eq!(squash(r#"<tbody id="t-nvd">"#, r#"<section class="block" id="sources">"#),
                   "</table></div></div></section></section>");
        // The feed tables are h3 subsections of the group, like the Linear tables.
        for id in ["health", "kev", "adv", "deps", "nvd", "untriaged", "tickets"] {
            let open = format!("<section class=\"block\" id=\"{id}\">\n<div class=\"shead\"><h3>");
            assert!(s.contains(&open), "{id}");
        }
        assert_eq!(s.matches("<h2>").count(), 4, "Linear, threat feeds, sources, terminal");
        for t in ["t-kev", "t-adv", "t-dep", "t-nvd", "t-untriaged", "t-tickets"] {
            let before = &s[..at(&format!("<tbody id=\"{t}\">"))];
            let open = before.rfind("<div class=\"tscroll\"><div class=\"scroller\"><table>").unwrap_or(0);
            assert!(open > before.rfind("</table>").unwrap_or(0), "{t} not in a tscroll");
        }
        assert!(!s[at(r#"<section class="block" id="health">"#)..at(r#"<tbody id="t-health">"#)].contains("tscroll"),
                "feed health does not scroll");
        assert_eq!(s.matches("<section").count(), s.matches("</section>").count());
    }

    /// Every tooltip has the same text in its title and in its tiptext (tags aside),
    /// and holds no block element.
    #[test]
    fn tooltips_are_complete() {
        let s = skel();
        let tips: Vec<_> = re(r#"<span class="tip" tabindex="0" title="([^"]*)">&#9432;<span class="tiptext">(.*?)</span></span>"#)
            .captures_iter(&s).map(|c| (c[1].to_string(), c[2].to_string())).collect();
        assert_eq!(tips.len(), s.matches(r#"class="tip""#).count(), "every tip in the expected form");
        assert!(tips.len() >= 9, "{}", tips.len());
        let plain = |x: &str| re(r"<[^>]+>").replace_all(x, "").replace("&mdash;", ":").replace(" :", ":");
        for (title, text) in &tips {
            assert!(!title.contains('<'), "{title}");
            assert!(!re(r"<(div|p|ul|table)\b").is_match(text), "{text}");
            assert_eq!(plain(title), plain(text));
        }
    }

    #[test]
    fn stamp_status_strip() {
        let row = |status: &str| HealthRow { source: "X".into(), status: status.into(), ..Default::default() };
        let now = parse_iso("2026-11-05T08:23:00Z").unwrap();
        let ok = build_stamp(now, "2026.11.04", &[row("ok"), row("cached"), row("not-modified")]);
        assert!(ok.contains(r#"<span class="rkv rst-ok"><span class="rk">Feeds</span><span class="rv"><span class="rdot"></span>All 3 feeds current</span><span class="rsub">2 ok &middot; 1 cached</span>"#), "{ok}");
        assert!(ok.contains(r#"<span class="rk">Updated</span><span class="rv">5 Nov 2026, 08:23 UTC</span>"#), "{ok}");
        assert!(ok.contains(r#"<span class="rk">CISA KEV catalog</span><span class="rv">2026.11.04</span>"#), "{ok}");
        assert!(!ok.contains("<div"));
        assert!(build_stamp(now, "", &[row("ok"), row("stale")]).contains("rst-warn\"><span class=\"rk\">Feeds</span><span class=\"rv\"><span class=\"rdot\"></span>1 feed stale"));
        assert!(build_stamp(now, "", &[row("error"), row("error"), row("stale")]).contains("2 feeds failing"));
    }

    #[test]
    fn text_regions_have_no_tags() {
        let r = load();
        for (k, v) in &r.text {
            assert!(!v.contains('<'), "{k}");
        }
        assert!(!r.stamp.contains("<div"));
        assert!(r.stamp.contains(r#"<span class="rv">"#), "the stamp carries inline markup");
    }

    #[test]
    fn triage_view_default_and_mode_note() {
        let t = crate::feeds::common::parse_iso("2026-11-03T02:45:00Z").unwrap();
        let r = |v: &TriageView| build_regions(&[], &[], &[], &[], &[], None, v, t, t, t, "", 300);
        let off = r(&TriageView::default());
        assert!(off.get("t-untriaged").contains("No matched item is waiting for triage."));
        assert!(off.get("t-tickets").contains("No open tickets."));
        assert_eq!((off.get("s-untriaged"), off.get("s-auto")), ("0", "0"));
        assert_eq!((off.get("n-untriaged"), off.get("n-tickets")), ("0 items", "0 tickets"));
        let note = TriageView { mode_note: Some("Linear sync is off: no issues are filed.".into()), ..Default::default() };
        let off = r(&note);
        assert!(off.get("t-untriaged").contains(r#"class="empty">Linear sync is off: no issues are filed."#));
        assert!(off.get("t-tickets").contains(r#"class="empty">Linear sync is off: no issues are filed."#));
        let evil = r(&evil_triage());
        for id in ["t-untriaged", "t-tickets"] {
            super::test_support::assert_clean(evil.get(id));
        }
    }

    /// serve's partial refresh renders the Linear section exactly as a full run does
    /// (tables, counters, tiles, refresh link), and nothing else (no s-auto, no stamp).
    #[test]
    fn ticket_regions_match_build_regions() {
        let t = crate::feeds::common::parse_iso("2026-11-03T02:45:00Z").unwrap();
        let row = |id: &str, overdue: bool| TriageRow { item_id: id.into(), title: id.into(), overdue, ..Default::default() };
        let ticket = |id: &str, assignee: &str, due: &str| TicketRow {
            issue_identifier: id.into(), assignee: assignee.into(), due: due.into(), ..Default::default()
        };
        let views = [
            TriageView::default(),
            TriageView { mode_note: Some("Linear sync is off.".into()), ..Default::default() },
            TriageView {
                untriaged: vec![row("A", true), row("B", false)],
                tickets: vec![ticket("T-1", "", "2026-11-01"), ticket("T-2", "Ann", ""), ticket("T-3", "Bo", "2026-12-01")],
                auto_not_relevant: 7,
                mode_note: None,
            },
            evil_triage(),
        ];
        for v in &views {
            let full = build_regions(&[], &[], &[], &[], &[], None, v, t, t, t, "", 300);
            let part = ticket_regions(v, t, None, None);
            let ids: Vec<&str> =
                part.tbody.iter().chain(part.text.iter()).chain(part.html.iter()).map(|(k, _)| k.as_str()).collect();
            assert_eq!(ids, ["t-untriaged", "t-tickets", "s-untriaged", "n-untriaged", "n-tickets", "l-kpis", "l-refresh"]);
            for id in &ids {
                assert_eq!(part.get(id), full.get(id), "{id}");
            }
            assert_eq!(part.stamp, "");
            // With a report: the tiles and link that run.rs puts in (linear_regions).
            let rep = report_fixture();
            assert_eq!(ticket_regions(v, t, Some(&rep), Some("http://x")).html,
                       linear_regions(v, t, Some(&rep), Some("http://x")));
        }
        let busy = ticket_regions(&views[2], t, None, None);
        assert_eq!(busy.get("s-untriaged"), "2 &middot; 1 overdue");
        assert_eq!(busy.get("n-tickets"), "3 tickets &middot; 1 overdue &middot; 1 no owner &middot; 1 no due date");
        // Spliced into the skeleton with the page's stamp put back, the rest of the page is untouched.
        let page = apply_regions(&skel(), &load()).unwrap();
        let mut r = busy.clone();
        r.stamp = stamp_of(&page).unwrap();
        let out = apply_regions(&page, &r).unwrap();
        assert_eq!(stamp_of(&out), stamp_of(&page));
        assert_ne!(out, page);
        let inner = |d: &str, id: &str| find_element(d, id, false).map(|(_, a, b, _)| d[a..b].to_string()).unwrap();
        assert_eq!(inner(&out, "s-auto"), inner(&page, "s-auto"));
        assert_eq!(inner(&out, "s-auto"), "412");
        assert_eq!(inner(&out, "n-tickets"), busy.get("n-tickets"));
    }

    /// The Linear row goes into the health table only: the health count and the
    /// stamp stay per feed, and its error text is escaped.
    #[test]
    fn tracker_row_in_health_table_only() {
        use super::test_support::{EVIL, assert_clean};
        let t = crate::feeds::common::parse_iso("2026-11-03T02:45:00Z").unwrap();
        let feeds = [HealthRow { source: "CISA KEV".into(), status: "ok".into(), ..Default::default() }];
        let linear = HealthRow { source: "Linear".into(), status: "error".into(),
                                 note: format!("create issue for NCSC-NL:{EVIL}"), ..Default::default() };
        let tv = TriageView::default();
        let with = build_regions(&[], &[], &[], &[], &feeds, Some(&linear), &tv, t, t, t, "", 300);
        let without = build_regions(&[], &[], &[], &[], &feeds, None, &tv, t, t, t, "", 300);
        let rows = with.get("t-health");
        assert!(rows.contains(r#"<span class="feed">Linear</span></td><td><span class="hs hs-error">Error</span>"#));
        assert_clean(rows);
        assert_eq!(with.get("n-health"), "1 feed &middot; 1 ok");
        assert_eq!(with.get("n-health"), without.get("n-health"));
        assert_eq!(with.stamp, without.stamp);
        assert_eq!(first_row_cells(&rows[rows.rfind("<tr>").unwrap()..]), thead_cols("t-health"));
    }

    #[test]
    fn counts() {
        let r = load();
        assert_eq!(r.get("s-kev"), "3");
        assert_eq!(r.get("s-crit"), "2");
        assert_eq!(r.get("s-high"), "1");
        assert_eq!(r.get("n-nvd"), "4 CVEs");
        assert_eq!(r.get("n-cvecap"), "All 4 shown.");
        assert_eq!(r.get("n-kev"), "3 entries &middot; 1 past deadline");
        assert_eq!(r.get("winlabel"), "27 Oct 02:45 &rarr; 3 Nov 02:45 UTC");
        assert_eq!(r.get("s-untriaged"), "4 &middot; 2 overdue &middot; 1 needs a reason");
        assert_eq!(r.get("s-auto"), "412");
        assert_eq!(r.get("n-untriaged"), "4 items");
        assert_eq!(r.get("n-tickets"), "3 tickets &middot; 1 overdue &middot; 1 no owner &middot; 1 no due date");
    }

    #[test]
    fn apply_is_idempotent_and_fills() {
        let r = load();
        let once = apply_regions(&skel(), &r).unwrap();
        let twice = apply_regions(&once, &r).unwrap();
        assert_eq!(once, twice);
        assert!(!once.contains("Not generated yet."));
        assert!(once.contains("CVE-2026-111464"));
        assert!(once.contains("NCSC-2026-0464"));
        assert!(once.contains("FAKE-3"));
        assert!(once.contains(r#"<tr class="overdue">"#));
        assert!(once.contains(r#"<span class="sub">declined in Linear without a reason</span>"#));
        assert!(once.contains(r#"<td class="due past">no owner</td>"#));
        assert!(once.contains(r#"<td class="due past">no due date</td>"#));
        assert_eq!(once.matches("<div").count(), once.matches("</div>").count());
        assert!(!once.contains("style="));
    }

    /// Every class on the filled page has a rule in style.css, except modifiers
    /// that deliberately fall back to their base class's look.
    #[test]
    fn every_class_is_styled() {
        let r = load();
        let page = apply_regions(&skel(), &r).unwrap();
        let mut evil = String::new();
        evil.push_str(&build_cve_rows(&[evil_item()], 300).0);
        let t = evil_triage();
        evil.push_str(&build_untriaged_rows(&t.untriaged, None));
        evil.push_str(&build_ticket_rows(&t.tickets, "2026-11-03", None));
        evil.push_str(&report_links(Some(&monthly()), Some("/x.pdf?v=1"), "2026-11-05T07:57:00Z", None, t_now()));
        evil.push_str(&report_links(None, None, "", Some("http://localhost:8090"), t_now()));
        for h in linear_regions(&t, t_now(), Some(&report_fixture()), Some("http://localhost:8090")) {
            evil.push_str(&h.1);
        }
        // Every tile state: ok and none (empty view, no report), open (pending, nothing late).
        evil.push_str(&linear_kpis(&TriageView::default(), "2026-11-06", None));
        let open = TriageView { untriaged: vec![TriageRow::default()], ..Default::default() };
        evil.push_str(&linear_kpis(&open, "2026-11-06", None));
        for state in ["bad", "ok", "open", "info", "none"] {
            let c = format!("kpi kpi-{state}");
            assert!(evil.contains(&c) || page.contains(&c), "{state}");
        }
        let css = read(STYLE_PATH);
        let fallback = ["sm", "score-other", "pi-L", "pi-X", "sv-MEDIUM", "sv-LOW"];
        for c in re(r#"class="([^"]*)""#).captures_iter(&(page + &evil)) {
            for cls in c[1].split_whitespace() {
                if fallback.contains(&cls) || c[1].contains('&') {
                    continue;
                }
                // The name followed by anything but a name character (.kpi is not .kpi-n).
                assert!(re(&format!(r"\.{}([^\w-]|$)", regex::escape(cls))).is_match(&css), "no rule for .{cls}");
            }
        }
    }

    #[test]
    fn missing_anchor_is_fatal() {
        let r = load();
        assert!(apply_regions(&skel().replace(r#"id="t-nvd""#, r#"id="t-gone""#), &r).is_err());
        assert!(apply_regions(&skel().replace(r#"id="n-cvecap""#, ""), &r).is_err());
        assert!(apply_regions(&skel().replace(r#"id="t-tickets""#, r#"id="t-gone""#), &r).is_err());
        assert!(apply_regions(&skel().replace(r#"id="s-auto""#, ""), &r).is_err());
        assert!(apply_regions(&skel().replace(r#"id="l-kpis""#, ""), &r).is_err());
    }
}
