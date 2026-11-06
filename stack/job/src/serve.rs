//! Local lab only: a small HTTP service behind two links on the dashboard. "Generate current
//! report" (GET /report/month-to-date.pdf) and "Sync with Linear" (GET /refresh)
//! both read the tracker back, rebuild the month-to-date report (FR-A4 on demand) and
//! re-splice the Linear section of the wiki page (two ticket tables, their counters,
//! the four tiles, the "as of" time); the first returns the PDF, the second sends the browser back
//! to the page. Production design (Cloud Run behind IAP) is in README §Deployment.
//!
//! Routes:
//!   GET /healthz                   200 "ok" (compose healthcheck: `serve --healthcheck`)
//!   GET /report/month-to-date.pdf  the refresh flow below, answered with the PDF
//!   GET /refresh                   the refresh flow below, answered with 303 to
//!                                  WIKI_PUBLIC_URL (200 "Refreshed. Go back to the page."
//!                                  when it is not set)
//!   other methods on these paths   405; anything else 404
//!
//! Refresh flow, one request at a time (tiny_http, single thread: /healthz waits
//! while a refresh runs):
//!   1. Within SERVE_COOLDOWN_SECONDS of the last successful refresh (either route):
//!      no refresh; the last PDF, or the redirect to the page.
//!   2. Take state/run.lock, trying every 2 s for up to SERVE_LOCK_WAIT_SECONDS. Still
//!      held by a run: the last PDF (`X-Report-Refreshed: false`), or 503 with
//!      `Retry-After` when there is none yet; /refresh always answers 503.
//!   3. Under the lock: tracker read-back into state/triage.json (no read-back when
//!      LINEAR_MODE=off), report::publish_month_to_date, then rebuild t-untriaged,
//!      t-tickets, n-untriaged, n-tickets and s-untriaged (not s-auto, which counts a
//!      run's window), the tiles l-kpis (the "now" tiles from the same view, the month
//!      tiles from the report) and l-refresh; splice them into the page with its stamp
//!      kept and write the page when it changed. On a report error the month tiles
//!      and "as of" come from the last report.json on disk (the tables and "now"
//!      tiles are still spliced). Any error: the last PDF, else 500 (/refresh: 500).
//!   4. One runs.jsonl line per request on either route: mode "serve", route, result
//!      refreshed | cooldown | locked | error, seconds, error, updated, page_written.
//!
//! Environment (besides the ones `run` reads, see run.rs):
//!   SERVE_COOLDOWN_SECONDS   60   no new refresh this soon after the last one
//!   SERVE_LOCK_WAIT_SECONDS  90   how long a request waits for a run to finish
//!   WIKI_PUBLIC_URL          —    the page as the browser sees it (WIKI_BASE is the
//!                                 container-internal wiki URL); /refresh redirects there

use std::any::Any;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

use crate::feeds::common::{Fatal, iso_utc};
use crate::feeds::state;
use crate::render::{self, Regions};
use crate::report::{self, Generated};
use crate::triage::store::Store;
use crate::triage::{step, tracker};
use crate::wiki;

#[derive(clap::Args)]
pub struct Args {
    /// Port to listen on.
    #[arg(long, default_value_t = 8090)]
    pub port: u16,
    /// Check that a running service answers /healthz and exit (compose healthcheck).
    #[arg(long)]
    pub healthcheck: bool,
}

pub const HEALTH_PATH: &str = "/healthz";
pub const REPORT_PATH: &str = "/report/month-to-date.pdf";
pub const REFRESH_PATH: &str = "/refresh";
/// File name the browser saves the PDF as: "cyber-threat-report-<YYYY-MM-DD-HHMM>.pdf",
/// the tickets' "as of" time in Amsterdam time, so each export names when its data is
/// from (Henry, 2026-11-06); the monthly report is "cyber-threat-report-<YYYY-MM>.pdf".
/// "cyber-threat-report-to-date.pdf" when that time is unknown.
pub fn download_name(as_of: &str) -> String {
    match crate::feeds::common::parse_iso(as_of) {
        Some(t) => format!("cyber-threat-report-{}.pdf", crate::triage::store::to_amsterdam(t).format("%Y-%m-%d-%H%M")),
        None => "cyber-threat-report-to-date.pdf".into(),
    }
}
/// Retry-After (seconds) on a 503 while a run holds the lock and no PDF exists yet.
pub const RETRY_AFTER_SECS: u64 = 120;
/// Seconds between two attempts at the run lock.
const LOCK_POLL_SECS: u64 = 2;
/// Where report::publish_month_to_date leaves its files (state/reports/month-to-date/).
const MTD_DIR: &str = "reports/month-to-date";

// ---------------------------------------------------------------- reply

/// One HTTP answer. `log`: a few words for the service's log line.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
    pub log: String,
}

impl Reply {
    fn text(status: u16, body: impl Into<String>) -> Self {
        let body: String = body.into();
        Reply {
            status,
            headers: vec![("Content-Type", "text/plain; charset=utf-8".into()), ("Cache-Control", "no-store".into())],
            log: body.clone(),
            body: body.into_bytes(),
        }
    }

    /// The report PDF. `stale`: why it is the last PDF rather than a fresh one
    /// (cooldown | locked | error), None when it was just refreshed.
    fn pdf(bytes: Vec<u8>, as_of: &str, stale: Option<&str>) -> Self {
        let mut headers = vec![
            ("Content-Type", "application/pdf".to_string()),
            ("Content-Disposition", format!("attachment; filename=\"{}\"", download_name(as_of))),
            ("Cache-Control", "no-store".into()),
            ("X-Report-Refreshed", stale.is_none().to_string()),
        ];
        if let Some(why) = stale {
            headers.push(("X-Report-Reason", why.into()));
        }
        if !as_of.is_empty() {
            headers.push(("X-Report-As-Of", as_of.into()));
        }
        let log = format!("pdf {} bytes, {}", bytes.len(), stale.map_or("refreshed".into(), |w| format!("last PDF ({w})")));
        Reply { status: 200, headers, body: bytes, log }
    }

    /// /refresh done (or skipped: `stale` = cooldown): 303 to the page when its public
    /// URL is known, else a line of text.
    fn back(page_url: Option<&str>, stale: Option<&str>, cooldown_secs: i64) -> Self {
        let mut r = match page_url {
            Some(u) => {
                let mut r = Reply::text(303, format!("Refreshed. Back to {u}"));
                r.headers.push(("Location", u.to_string()));
                r
            }
            None if stale.is_some() => Reply::text(200, format!(
                "Already refreshed in the last {cooldown_secs} s. Go back to the page.")),
            None => Reply::text(200, "Refreshed. Go back to the page."),
        };
        r.headers.push(("X-Report-Refreshed", stale.is_none().to_string()));
        if let Some(why) = stale {
            r.headers.push(("X-Report-Reason", why.into()));
        }
        r
    }

    /// Value of the first header called `name` (ASCII case-insensitive).
    #[cfg(test)]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

// ---------------------------------------------------------------- backend

/// What a refresh produced: the report, how many triage records the tracker
/// read-back changed, and whether the page was written.
#[derive(Debug, Clone, Default)]
pub struct Refreshed {
    pub report: Generated,
    pub updated: usize,
    pub page_written: bool,
}

/// Held run lock; dropping it releases the lock.
pub type Guard = Box<dyn Any>;

/// Everything handle() needs from the outside world, so tests can fake it.
pub trait Backend {
    /// One attempt at the state lock: Ok(Ok(guard)) when held, Ok(Err(holder)) when
    /// a run holds it, Err when the lock file cannot be used.
    fn try_lock(&mut self) -> Result<Result<Guard, String>, Fatal>;
    /// Wait between two lock attempts.
    fn sleep(&mut self, secs: u64);
    /// Tracker read-back, ticket tables on the page, month-to-date report (lock held).
    fn refresh(&mut self, now: DateTime<Utc>) -> Result<Refreshed, Fatal>;
    /// The last month-to-date PDF on disk and its "tickets as of" time ("" if unknown).
    fn last_pdf(&self) -> Option<(Vec<u8>, String)>;
    /// Append one runs.jsonl line.
    fn record(&mut self, rec: &Value);
}

/// Settings and what the service remembers between requests.
#[derive(Debug, Clone)]
pub struct State {
    pub cooldown_secs: i64,
    pub lock_wait_secs: u64,
    /// Time of the last successful refresh since the service started.
    pub last_refresh: Option<DateTime<Utc>>,
    /// WIKI_PUBLIC_URL: where /refresh sends the browser back to.
    pub page_url: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        State { cooldown_secs: 60, lock_wait_secs: 90, last_refresh: None, page_url: None }
    }
}

impl State {
    pub fn from_env() -> Self {
        let d = State::default();
        State {
            cooldown_secs: env_num("SERVE_COOLDOWN_SECONDS", d.cooldown_secs),
            lock_wait_secs: env_num("SERVE_LOCK_WAIT_SECONDS", d.lock_wait_secs),
            last_refresh: None,
            page_url: std::env::var("WIKI_PUBLIC_URL").ok().map(|u| u.trim().to_string()).filter(|u| !u.is_empty()),
        }
    }

    fn cooling(&self, now: DateTime<Utc>) -> bool {
        self.last_refresh.is_some_and(|t| now - t < Duration::seconds(self.cooldown_secs))
    }
}

fn env_num<T: std::str::FromStr>(k: &str, default: T) -> T {
    std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

// ---------------------------------------------------------------- handler

/// One HTTP request -> reply. `url` may carry a query string; `now` is the request time.
pub fn handle(method: &str, url: &str, now: DateTime<Utc>, st: &mut State, be: &mut dyn Backend) -> Reply {
    let path = url.split('?').next().unwrap_or("");
    if ![HEALTH_PATH, REPORT_PATH, REFRESH_PATH].contains(&path) {
        return Reply::text(404, "not found");
    }
    if method != "GET" {
        let mut r = Reply::text(405, "method not allowed");
        r.headers.push(("Allow", "GET".into()));
        return r;
    }
    if path == HEALTH_PATH {
        return Reply::text(200, "ok");
    }
    let t0 = Instant::now();
    let (reply, mut rec) = if path == REFRESH_PATH { page_flow(now, st, be) } else { refresh_flow(now, st, be) };
    rec["run_at"] = json!(iso_utc(now));
    rec["mode"] = json!("serve");
    rec["route"] = json!(path);
    rec["seconds"] = json!((t0.elapsed().as_secs_f64() * 10.0).round() / 10.0);
    be.record(&rec);
    reply
}

/// Outcome of trying to take the run lock for one request.
enum Locked {
    /// Held, after waiting this many seconds.
    Held(Guard, u64),
    /// Still held by a run after the wait: runs.jsonl error text.
    Busy(String),
    /// The lock file cannot be used.
    Failed(String),
}

/// Take state/run.lock, trying every LOCK_POLL_SECS for up to SERVE_LOCK_WAIT_SECONDS.
fn take_lock(st: &State, be: &mut dyn Backend) -> Locked {
    let attempts = st.lock_wait_secs / LOCK_POLL_SECS + 1;
    let mut waited = 0;
    let mut holder = String::new();
    for i in 0..attempts {
        if i > 0 {
            be.sleep(LOCK_POLL_SECS);
            waited += LOCK_POLL_SECS;
        }
        match be.try_lock() {
            Ok(Ok(g)) => return Locked::Held(g, waited),
            Ok(Err(h)) => holder = h,
            Err(e) => return Locked::Failed(e.0),
        }
    }
    let msg = format!("another run holds {}/run.lock ({holder}); waited {waited} s", state::dir().display());
    Locked::Busy(clip(&msg, 300))
}

/// GET /refresh (module doc): refresh, then back to the page.
fn page_flow(now: DateTime<Utc>, st: &mut State, be: &mut dyn Backend) -> (Reply, Value) {
    if st.cooling(now) {
        return (Reply::back(st.page_url.as_deref(), Some("cooldown"), st.cooldown_secs), json!({"result": "cooldown"}));
    }
    let fail = |err: &str| {
        eprintln!("serve: error: {err}");
        (Reply::text(500, format!("Refresh failed: {}", clip(err, 300))), json!({"result": "error", "error": clip(err, 300)}))
    };
    match take_lock(st, be) {
        Locked::Failed(e) => fail(&e),
        Locked::Busy(msg) => {
            let mut r = Reply::text(503, "A scheduled run is updating the data; the page shows it when the run ends. \
                                          Go back to the page and try again in a few minutes.");
            r.headers.push(("Retry-After", RETRY_AFTER_SECS.to_string()));
            (r, json!({"result": "locked", "error": msg}))
        }
        Locked::Held(guard, waited) => {
            let at = now + Duration::seconds(waited as i64);
            let res = be.refresh(at);
            drop(guard);
            match res {
                Ok(Refreshed { updated, page_written, .. }) => {
                    st.last_refresh = Some(at);
                    (Reply::back(st.page_url.as_deref(), None, st.cooldown_secs),
                     json!({"result": "refreshed", "updated": updated, "page_written": page_written}))
                }
                Err(e) => fail(&e.0),
            }
        }
    }
}

/// The refresh flow (module doc). Returns the reply and the runs.jsonl fields
/// result, error and updated.
fn refresh_flow(now: DateTime<Utc>, st: &mut State, be: &mut dyn Backend) -> (Reply, Value) {
    if st.cooling(now) {
        // Without a PDF on disk (deleted by hand) the cooldown does not apply.
        if let Some((pdf, as_of)) = be.last_pdf() {
            return (Reply::pdf(pdf, &as_of, Some("cooldown")), json!({"result": "cooldown"}));
        }
    }

    let (guard, waited) = match take_lock(st, be) {
        Locked::Held(g, w) => (g, w),
        Locked::Failed(e) => return failed(be, "error", &e),
        Locked::Busy(msg) => {
            return match be.last_pdf() {
                Some((pdf, as_of)) => (Reply::pdf(pdf, &as_of, Some("locked")), json!({"result": "locked", "error": msg})),
                None => {
                    let mut r = Reply::text(503, "A run is updating the data and there is no earlier report yet; try again in a few minutes.");
                    r.headers.push(("Retry-After", RETRY_AFTER_SECS.to_string()));
                    (r, json!({"result": "locked", "error": msg}))
                }
            };
        }
    };

    let at = now + Duration::seconds(waited as i64);
    let res = be.refresh(at);
    drop(guard);
    match res {
        Ok(Refreshed { report: Generated { pdf: Some(pdf), as_of, .. }, updated, page_written }) => {
            st.last_refresh = Some(at);
            (Reply::pdf(pdf, &as_of, None), json!({"result": "refreshed", "updated": updated, "page_written": page_written}))
        }
        Ok(_) => failed(be, "error", "the report was generated without a PDF"),
        Err(e) => failed(be, "error", &e.0),
    }
}

/// The last PDF (`X-Report-Reason: <why>`) when there is one, else 500.
fn failed(be: &mut dyn Backend, why: &str, err: &str) -> (Reply, Value) {
    eprintln!("serve: {why}: {err}");
    let rec = json!({"result": why, "error": clip(err, 300)});
    match be.last_pdf() {
        Some((pdf, as_of)) => (Reply::pdf(pdf, &as_of, Some(why)), rec),
        None => (Reply::text(500, format!("Report refresh failed: {}", clip(err, 300))), rec),
    }
}

// ---------------------------------------------------------------- live backend

/// The backend on the real state directory, tracker, wiki and report engine.
struct Live;

impl Backend for Live {
    fn try_lock(&mut self) -> Result<Result<Guard, String>, Fatal> {
        Ok(state::lock_run(state::utcnow())?.map(|l| Box::new(l) as Guard))
    }

    fn sleep(&mut self, secs: u64) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }

    fn refresh(&mut self, now: DateTime<Utc>) -> Result<Refreshed, Fatal> {
        let (view, updated) = read_back(now)?;
        let report = report::publish_month_to_date(now);
        // The month tiles and "as of": this report, else the last one on disk (as run.rs).
        let disk = report.is_err().then(|| state::load_json::<Value>(&format!("{MTD_DIR}/report.json"))).flatten();
        let json = report.as_ref().ok().map(|g| &g.json).or(disk.as_ref());
        let regions = render::ticket_regions(&view, now, json, std::env::var("SERVE_PUBLIC_URL").ok().as_deref());
        let page_written = splice_page(regions)?;
        Ok(Refreshed { report: report?, updated, page_written })
    }

    fn last_pdf(&self) -> Option<(Vec<u8>, String)> {
        let pdf = state::load_bytes(&format!("{MTD_DIR}/report.pdf"))?;
        let meta: Value = state::load_json(&format!("{MTD_DIR}/report.json")).unwrap_or(Value::Null);
        let as_of = meta.get("as_of").and_then(Value::as_str).unwrap_or("").to_string();
        Some((pdf, as_of))
    }

    fn record(&mut self, rec: &Value) {
        state::append_run(rec);
    }
}

/// Empty-table messages of the triage tables, as triage::step::step words them,
/// so a refresh does not change what the page says between two runs.
fn mode_note(t: &Result<Option<Box<dyn tracker::Tracker>>, tracker::TrackerError>) -> Option<String> {
    match t {
        Ok(None) => Some("Linear sync is off (LINEAR_MODE=off): matched items are recorded but no issue is filed.".into()),
        Ok(Some(_)) => None,
        Err(e) => Some(format!("Linear sync is not configured: {e}.")),
    }
}

/// Read the tracker back into state/triage.json. Returns the triage tables' view
/// and the number of records changed.
fn read_back(now: DateTime<Utc>) -> Result<(render::TriageView, usize), Fatal> {
    let mut store = Store::load()?;
    let mut t = tracker::from_env();
    let note = mode_note(&t);
    let mut updated = 0;
    if let Ok(Some(tr)) = &mut t {
        let issues = store.issues();
        if !issues.is_empty() {
            let statuses = tr.fetch_states(&issues).map_err(|e| Fatal(format!("tracker read-back: {e}")))?;
            updated = store.apply_statuses(&statuses, now);
        }
    }
    store.save();
    Ok((step::view(&store, &[], now, note), updated))
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// Put `regions` into the page, keeping its stamp, and write it when it changed
/// (same page variables as run.rs). Returns whether a new page version was written.
fn splice_page(mut regions: Regions) -> Result<bool, Fatal> {
    let page_id: i64 = env_num("WIKI_PAGE_ID", 51);
    let data = wiki::gql_bot(wiki::READ_PAGE, json!({"id": page_id}))?;
    let page = &data["pages"]["single"];
    let content = s(page, "content");
    regions.stamp = render::stamp_of(content).ok_or_else(|| {
        Fatal(format!("page {page_id} has no id=\"{}\" stamp — re-seed the page skeleton", render::STAMP_ID))
    })?;
    let doc = render::apply_regions(content, &regions)?;
    if doc == content {
        return Ok(false);
    }
    let tags: Vec<Value> = page["tags"].as_array().map(|a| a.iter().map(|t| t["tag"].clone()).collect())
        .unwrap_or_default(); // required: the resolver maps over it
    let res = wiki::gql_bot(wiki::WRITE_PAGE, json!({
        "id": page_id, "content": doc, "tags": tags,
        "title": s(page, "title"), "desc": s(page, "description"),
    }))?;
    let rr = &res["pages"]["update"]["responseResult"];
    if rr["succeeded"] != json!(true) {
        return Err(Fatal(format!("Wiki.js refused the write: {}", s(rr, "message"))));
    }
    Ok(true)
}

// ---------------------------------------------------------------- server

fn respond(req: tiny_http::Request, reply: Reply) -> std::io::Result<()> {
    let mut response = tiny_http::Response::from_data(reply.body).with_status_code(reply.status);
    for (k, v) in &reply.headers {
        if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            response.add_header(h);
        }
    }
    req.respond(response)
}

fn serve_one(req: tiny_http::Request, st: &mut State, be: &mut dyn Backend) {
    let method = req.method().to_string();
    let url = req.url().to_string();
    let now = state::utcnow();
    // A panic (e.g. a state file that cannot be written) answers 500 and keeps the
    // service up; unwinding drops the run lock.
    let reply = catch_unwind(AssertUnwindSafe(|| handle(&method, &url, now, st, be))).unwrap_or_else(|p| {
        let msg = p.downcast_ref::<&str>().map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_else(|| "panic".into());
        Reply::text(500, format!("internal error: {}", clip(&msg, 300)))
    });
    let path = url.split('?').next().unwrap_or("");
    println!("{} {method} {path} -> {} {}", iso_utc(now), reply.status, clip(&reply.log, 200));
    if let Err(e) = respond(req, reply) {
        eprintln!("{} {method} {path} could not send the reply: {e}", iso_utc(now));
    }
}

/// `serve --healthcheck`: 0 when GET /healthz on this container answers 200.
fn healthcheck(port: u16) -> i32 {
    let check = || -> std::io::Result<bool> {
        let mut s = TcpStream::connect(("127.0.0.1", port))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
        s.write_all(format!("GET {HEALTH_PATH} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes())?;
        let mut out = String::new();
        s.read_to_string(&mut out)?;
        Ok(out.starts_with("HTTP/1.0 200") || out.starts_with("HTTP/1.1 200"))
    };
    match check() {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("serve healthcheck: {HEALTH_PATH} did not answer 200");
            1
        }
        Err(e) => {
            eprintln!("serve healthcheck: {e}");
            1
        }
    }
}

pub fn main(args: Args) -> Result<i32, Fatal> {
    if args.healthcheck {
        return Ok(healthcheck(args.port));
    }
    let mut st = State::from_env();
    let server = tiny_http::Server::http(("0.0.0.0", args.port))
        .map_err(|e| Fatal(format!("serve: cannot listen on 0.0.0.0:{}: {e}", args.port)))?;
    println!("{} serve listening on 0.0.0.0:{}, state {}, cooldown {} s, lock wait {} s, page {}",
             iso_utc(state::utcnow()), args.port, state::dir().display(), st.cooldown_secs, st.lock_wait_secs,
             st.page_url.as_deref().unwrap_or("(WIKI_PUBLIC_URL not set)"));
    let mut be = Live;
    for req in server.incoming_requests() {
        serve_one(req, &mut st, &mut be);
    }
    Ok(0)
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::feeds::common::parse_iso;

    const NOW: &str = "2026-11-05T10:00:00Z";

    fn now() -> DateTime<Utc> {
        parse_iso(NOW).unwrap()
    }

    /// Drop flag for the fake lock guard.
    struct Held(Rc<Cell<bool>>);

    impl Drop for Held {
        fn drop(&mut self) {
            self.0.set(false);
        }
    }

    #[derive(Default)]
    struct Fake {
        /// try_lock answers "busy" this many times before it succeeds (u32::MAX: never).
        busy: u32,
        lock_error: bool,
        fail: Option<String>,
        no_pdf: bool,
        last: Option<(Vec<u8>, String)>,
        held: Rc<Cell<bool>>,
        lock_calls: u32,
        slept: u64,
        refreshes: Vec<DateTime<Utc>>,
        records: Vec<Value>,
    }

    impl Backend for Fake {
        fn try_lock(&mut self) -> Result<Result<Guard, String>, Fatal> {
            self.lock_calls += 1;
            if self.lock_error {
                return Err(Fatal("cannot lock state/run.lock: read-only".into()));
            }
            if self.lock_calls <= self.busy {
                return Ok(Err(r#"{"pid":7,"host":"job","started":"2026-11-05T09:59:00Z"}"#.into()));
            }
            self.held.set(true);
            Ok(Ok(Box::new(Held(self.held.clone()))))
        }
        fn sleep(&mut self, secs: u64) {
            self.slept += secs;
        }
        fn refresh(&mut self, now: DateTime<Utc>) -> Result<Refreshed, Fatal> {
            assert!(self.held.get(), "refresh must run under the lock");
            self.refreshes.push(now);
            if let Some(e) = &self.fail {
                return Err(Fatal(e.clone()));
            }
            let pdf = (!self.no_pdf).then(|| b"%PDF-new".to_vec());
            self.last = pdf.clone().map(|p| (p, iso_utc(now)));
            Ok(Refreshed {
                report: Generated { pdf, as_of: iso_utc(now), ..Default::default() },
                updated: 2,
                page_written: true,
            })
        }
        fn last_pdf(&self) -> Option<(Vec<u8>, String)> {
            self.last.clone()
        }
        fn record(&mut self, rec: &Value) {
            self.records.push(rec.clone());
        }
    }

    fn old_pdf() -> Option<(Vec<u8>, String)> {
        Some((b"%PDF-old".to_vec(), "2026-11-05T06:00:00Z".into()))
    }

    fn get(st: &mut State, be: &mut Fake) -> Reply {
        handle("GET", REPORT_PATH, now(), st, be)
    }

    #[test]
    fn health_404_and_405() {
        let (mut st, mut be) = (State::default(), Fake::default());
        let r = handle("GET", "/healthz", now(), &mut st, &mut be);
        assert_eq!((r.status, r.body.as_slice()), (200, b"ok".as_slice()));
        assert_eq!(handle("GET", "/", now(), &mut st, &mut be).status, 404);
        assert_eq!(handle("GET", "/report/month-to-date.pdfx", now(), &mut st, &mut be).status, 404);
        assert_eq!(handle("POST", "/nope", now(), &mut st, &mut be).status, 404);
        let r = handle("POST", REPORT_PATH, now(), &mut st, &mut be);
        assert_eq!((r.status, r.header("allow")), (405, Some("GET")));
        assert_eq!(handle("HEAD", "/healthz", now(), &mut st, &mut be).status, 405);
        // No report request, no runs.jsonl line, no lock taken.
        assert!(be.records.is_empty());
        assert_eq!(be.lock_calls, 0);
    }

    #[test]
    fn refreshed_pdf_with_headers_and_record() {
        let (mut st, mut be) = (State::default(), Fake { last: old_pdf(), ..Default::default() });
        let r = handle("GET", "/report/month-to-date.pdf?x=1", now(), &mut st, &mut be);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"%PDF-new");
        assert_eq!(r.header("content-type"), Some("application/pdf"));
        assert_eq!(r.header("Content-Disposition"),
                   Some(r#"attachment; filename="cyber-threat-report-2026-11-05-1100.pdf""#));
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        assert_eq!(r.header("X-Report-Refreshed"), Some("true"));
        assert_eq!(r.header("X-Report-Reason"), None);
        assert_eq!(r.header("X-Report-As-Of"), Some(NOW));
        assert!(!be.held.get(), "lock released after the refresh");
        assert_eq!(st.last_refresh, Some(now()));
        let rec = &be.records[0];
        assert_eq!((rec["mode"].as_str(), rec["result"].as_str()), (Some("serve"), Some("refreshed")));
        assert_eq!((rec["run_at"].as_str(), rec["updated"].as_u64()), (Some(NOW), Some(2)));
        assert!(rec["seconds"].is_number() && rec.get("error").is_none(), "{rec}");
    }

    #[test]
    fn cooldown_serves_last_pdf_without_refresh() {
        let (mut st, mut be) = (State::default(), Fake::default());
        assert_eq!(get(&mut st, &mut be).header("X-Report-Refreshed"), Some("true"));
        let soon = now() + Duration::seconds(59);
        let r = handle("GET", REPORT_PATH, soon, &mut st, &mut be);
        assert_eq!((r.status, r.body.as_slice()), (200, b"%PDF-new".as_slice()));
        assert_eq!((r.header("X-Report-Refreshed"), r.header("X-Report-Reason")), (Some("false"), Some("cooldown")));
        assert_eq!(be.refreshes.len(), 1);
        assert_eq!(be.lock_calls, 1, "no lock attempt during the cooldown");
        assert_eq!(be.records[1]["result"], "cooldown");
        // Once the cooldown is over, a new refresh.
        let later = now() + Duration::seconds(60);
        assert_eq!(handle("GET", REPORT_PATH, later, &mut st, &mut be).header("X-Report-Refreshed"), Some("true"));
        assert_eq!(be.refreshes, [now(), later]);
    }

    #[test]
    fn waits_for_lock_then_refreshes() {
        let (mut st, mut be) = (State::default(), Fake { busy: 3, ..Default::default() });
        let r = get(&mut st, &mut be);
        assert_eq!(r.header("X-Report-Refreshed"), Some("true"));
        assert_eq!((be.lock_calls, be.slept), (4, 6));
        // The report is as of when the lock was taken, not when the request came in.
        assert_eq!(be.refreshes, [now() + Duration::seconds(6)]);
    }

    #[test]
    fn locked_with_previous_pdf() {
        let (mut st, mut be) = (State::default(), Fake { busy: u32::MAX, last: old_pdf(), ..Default::default() });
        let r = get(&mut st, &mut be);
        assert_eq!((r.status, r.body.as_slice()), (200, b"%PDF-old".as_slice()));
        assert_eq!((r.header("X-Report-Refreshed"), r.header("X-Report-Reason")), (Some("false"), Some("locked")));
        assert_eq!(r.header("X-Report-As-Of"), Some("2026-11-05T06:00:00Z"));
        // 90 s in 2 s steps: 46 attempts, 45 waits.
        assert_eq!((be.lock_calls, be.slept), (46, 90));
        assert!(be.refreshes.is_empty());
        assert_eq!(st.last_refresh, None);
        let rec = &be.records[0];
        assert_eq!(rec["result"], "locked");
        assert!(rec["error"].as_str().unwrap().contains("\"pid\":7"), "{rec}");
    }

    #[test]
    fn locked_without_pdf_is_503() {
        let mut st = State { lock_wait_secs: 4, ..Default::default() };
        let mut be = Fake { busy: u32::MAX, ..Default::default() };
        let r = get(&mut st, &mut be);
        assert_eq!((r.status, r.header("Retry-After")), (503, Some("120")));
        assert_eq!(r.header("Content-Type"), Some("text/plain; charset=utf-8"));
        assert_eq!((be.lock_calls, be.slept), (3, 4));
        assert_eq!(be.records[0]["result"], "locked");
    }

    #[test]
    fn error_with_previous_pdf() {
        let mut st = State::default();
        let mut be = Fake { fail: Some("GraphQL HTTP 500: boom".into()), last: old_pdf(), ..Default::default() };
        let r = get(&mut st, &mut be);
        assert_eq!((r.status, r.body.as_slice()), (200, b"%PDF-old".as_slice()));
        assert_eq!((r.header("X-Report-Refreshed"), r.header("X-Report-Reason")), (Some("false"), Some("error")));
        assert!(!be.held.get());
        assert_eq!(st.last_refresh, None, "a failed refresh starts no cooldown");
        assert_eq!((be.records[0]["result"].as_str(), be.records[0]["error"].as_str()),
                   (Some("error"), Some("GraphQL HTTP 500: boom")));
    }

    #[test]
    fn error_without_pdf_is_500() {
        let mut st = State::default();
        let mut be = Fake { fail: Some("tracker read-back: Linear: network error".into()), ..Default::default() };
        let r = get(&mut st, &mut be);
        assert_eq!(r.status, 500);
        assert!(String::from_utf8_lossy(&r.body).contains("tracker read-back"));
        assert_eq!(be.records[0]["result"], "error");
        // A report without a PDF and a lock file that cannot be used are errors too.
        let mut be = Fake { no_pdf: true, ..Default::default() };
        assert_eq!(get(&mut st, &mut be).status, 500);
        let mut be = Fake { lock_error: true, last: old_pdf(), ..Default::default() };
        let r = get(&mut st, &mut be);
        assert_eq!((r.status, r.header("X-Report-Reason")), (200, Some("error")));
        assert!(be.refreshes.is_empty());
    }

    const PAGE: &str = "http://localhost:3000/en/CTP/run-books/Cyber-Threat-Dashboard";

    fn page_state() -> State {
        State { page_url: Some(PAGE.into()), ..Default::default() }
    }

    #[test]
    fn refresh_redirects_to_the_page() {
        let (mut st, mut be) = (page_state(), Fake::default());
        let r = handle("GET", "/refresh?from=page", now(), &mut st, &mut be);
        assert_eq!((r.status, r.header("Location")), (303, Some(PAGE)));
        assert_eq!((r.header("X-Report-Refreshed"), r.header("Cache-Control")), (Some("true"), Some("no-store")));
        assert_eq!(be.refreshes, [now()]);
        assert!(!be.held.get(), "lock released after the refresh");
        assert_eq!(st.last_refresh, Some(now()));
        let rec = &be.records[0];
        assert_eq!((rec["mode"].as_str(), rec["route"].as_str(), rec["result"].as_str()),
                   (Some("serve"), Some("/refresh"), Some("refreshed")));
        assert_eq!((rec["updated"].as_u64(), rec["page_written"].as_bool()), (Some(2), Some(true)));
        assert_eq!(handle("POST", REFRESH_PATH, now(), &mut st, &mut be).status, 405);
        assert_eq!(be.records.len(), 1, "a refused method is not recorded");
    }

    #[test]
    fn refresh_without_page_url_says_go_back() {
        let (mut st, mut be) = (State::default(), Fake::default());
        let r = handle("GET", REFRESH_PATH, now(), &mut st, &mut be);
        assert_eq!((r.status, r.header("Location")), (200, None));
        assert_eq!(r.body, b"Refreshed. Go back to the page.");
        let r = handle("GET", REFRESH_PATH, now() + Duration::seconds(5), &mut st, &mut be);
        assert_eq!((r.status, r.header("X-Report-Reason")), (200, Some("cooldown")));
        assert!(String::from_utf8_lossy(&r.body).starts_with("Already refreshed in the last 60 s."));
    }

    /// One cooldown for both routes: a refresh of either kind starts it.
    #[test]
    fn refresh_cooldown() {
        let (mut st, mut be) = (page_state(), Fake::default());
        assert_eq!(handle("GET", REFRESH_PATH, now(), &mut st, &mut be).status, 303);
        let soon = now() + Duration::seconds(59);
        let r = handle("GET", REFRESH_PATH, soon, &mut st, &mut be);
        assert_eq!((r.status, r.header("Location")), (303, Some(PAGE)));
        assert_eq!((r.header("X-Report-Refreshed"), r.header("X-Report-Reason")), (Some("false"), Some("cooldown")));
        assert_eq!((be.refreshes.len(), be.lock_calls), (1, 1), "no refresh and no lock attempt during the cooldown");
        assert_eq!(be.records[1]["result"], "cooldown");
        // The PDF built by /refresh is served without a new refresh.
        let r = handle("GET", REPORT_PATH, soon, &mut st, &mut be);
        assert_eq!((r.status, r.header("X-Report-Reason")), (200, Some("cooldown")));
        assert_eq!(be.records[2]["route"], REPORT_PATH);
        let later = now() + Duration::seconds(60);
        assert_eq!(handle("GET", REFRESH_PATH, later, &mut st, &mut be).header("X-Report-Refreshed"), Some("true"));
        assert_eq!(be.refreshes, [now(), later]);
        // And a PDF click starts it for /refresh.
        let (mut st, mut be) = (page_state(), Fake::default());
        assert_eq!(get(&mut st, &mut be).header("X-Report-Refreshed"), Some("true"));
        let r = handle("GET", REFRESH_PATH, now() + Duration::seconds(1), &mut st, &mut be);
        assert_eq!((r.status, r.header("X-Report-Reason")), (303, Some("cooldown")));
    }

    #[test]
    fn refresh_locked_or_failed() {
        let mut st = State { lock_wait_secs: 4, ..page_state() };
        let mut be = Fake { busy: u32::MAX, last: old_pdf(), ..Default::default() };
        let r = handle("GET", REFRESH_PATH, now(), &mut st, &mut be);
        assert_eq!((r.status, r.header("Retry-After"), r.header("Location")), (503, Some("120"), None));
        assert_eq!((be.lock_calls, be.slept), (3, 4));
        assert_eq!(be.records[0]["result"], "locked");
        assert!(be.refreshes.is_empty() && st.last_refresh.is_none());
        let mut be = Fake { fail: Some("tracker read-back: Linear: network error".into()), ..Default::default() };
        let r = handle("GET", REFRESH_PATH, now(), &mut st, &mut be);
        assert_eq!(r.status, 500);
        assert!(String::from_utf8_lossy(&r.body).contains("tracker read-back"));
        assert_eq!((be.records[0]["result"].as_str(), st.last_refresh), (Some("error"), None));
        assert!(!be.held.get());
        let mut be = Fake { lock_error: true, ..Default::default() };
        assert_eq!(handle("GET", REFRESH_PATH, now(), &mut st, &mut be).status, 500);
        // A report without a PDF is no error for the page.
        let mut be = Fake { no_pdf: true, ..Default::default() };
        assert_eq!(handle("GET", REFRESH_PATH, now(), &mut st, &mut be).status, 303);
    }

    #[test]
    fn mode_note_matches_step() {
        assert!(mode_note(&Ok(None)).unwrap().contains("LINEAR_MODE=off"));
        let bad = tracker::from_vars(&|k| (k == "LINEAR_MODE").then(|| "sideways".to_string()));
        assert!(mode_note(&bad).unwrap().starts_with("Linear sync is not configured: LINEAR_MODE=sideways"));
    }

    /// The real server and `--healthcheck` against it, on a free port.
    #[test]
    fn healthcheck_against_server() {
        let server = tiny_http::Server::http(("127.0.0.1", 0)).unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let t = std::thread::spawn(move || {
            let mut st = State::default();
            let mut be = Fake::default();
            let req = server.recv().unwrap();
            serve_one(req, &mut st, &mut be);
        });
        assert_eq!(healthcheck(port), 0);
        t.join().unwrap();
        assert_eq!(healthcheck(port), 1, "nothing listens any more");
    }
}
