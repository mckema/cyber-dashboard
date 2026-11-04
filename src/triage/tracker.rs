//! Where the triage tickets live (FR-A2 triage inbox, FR-A3 ticket; for now
//! the same ticket also serves FR-A9).
//!
//! One issue per matched item, created in the team's Triage inbox. A later
//! change to the item becomes a comment on that issue, never a new issue (the
//! store remembers item key -> issue). People Accept (the issue becomes the
//! ticket: owner, due date, status) or Decline (not relevant, reason as a
//! comment) in the tracker; each run reads the states back with fetch_states().
//!
//! LINEAR_MODE selects the tracker (from_env):
//!
//!   off    (default, also when unset or empty) no tracker; matched items stay
//!          untriaged on the page
//!   fake   FakeTracker: issues in STATE_DIR/fake-linear.json
//!   live   LinearTracker: Linear GraphQL API, needs LINEAR_API_KEY + LINEAR_TEAM_ID
//!
//! TrackerError's Display is one line (whitespace collapsed, bodies cut), so the
//! run can put it in the health note; tracker errors never fail the run (sync.rs).
//!
//! FakeTracker file (state/fake-linear.json). The job appends issues; a person
//! simulates triage by editing the five fields marked "edit" and saving:
//!
//!   {
//!    "next": 3,                                   next FAKE-n number
//!    "issues": [
//!     {
//!      "identifier": "FAKE-1",
//!      "url": "https://linear.invalid/fake/issue/FAKE-1",
//!      "title": "[CVE-2026-1234] ...",
//!      "description": "...",                      Markdown, as Linear would get it
//!      "item_key": "CISA KEV:CVE-2026-1234",
//!      "created": "2026-11-03T08:00:00Z",
//!      "state": "triage",        edit: triage | accepted | done | declined
//!      "assignee": "",           edit: owner name, e.g. "Henry"
//!      "due": "",                edit: YYYY-MM-DD
//!      "reason": "",             edit: why it was declined
//!      "actor": "",              edit: who accepted/declined it
//!      "changed": "",            optional: when (UTC ISO), "" = unknown
//!      "comments": [{"at": "2026-11-04T08:00:00Z", "body": "..."}]
//!     }
//!    ]
//!   }
//!
//! A file that does not parse is an error, never silently replaced: losing it
//! would lose the triage state.
//!
//! Linear API (https://linear.app/developers/graphql, schema
//! github.com/linear/linear packages/sdk/src/schema.graphql, read 2026-11-03):
//! endpoint https://api.linear.app/graphql, personal API key in
//! `Authorization: <key>` (no "Bearer"), errors in a GraphQL `errors` array even
//! with HTTP 200, rate limit = HTTP 429 + extensions.code "RATELIMITED" with
//! X-RateLimit-* headers (https://linear.app/developers/rate-limiting).
//! Workflow state types: triage, backlog, unstarted, started, completed,
//! canceled, duplicate. Linear has no "decline reason" field; the reason is the
//! latest comment that the job did not write itself.

use chrono::{DateTime, Utc};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::types::Match;
use crate::feeds::common::{self, Item, iso_utc, parse_iso};
use crate::feeds::state;

pub const ENDPOINT: &str = "https://api.linear.app/graphql";
pub const FAKE_FILE: &str = "fake-linear.json";
/// Comments the job writes start with this, so they are never read back as a decline reason.
pub const BOT_PREFIX: &str = "**exploit-watch**";
/// Issue titles longer than this are cut with "…".
pub const TITLE_MAX: usize = 120;
/// Issues per fetch_states() request. Each issue also asks for NESTED_N history and
/// NESTED_N comment nodes, which count toward Linear's complexity budget.
const FETCH_BATCH: usize = 25;
const NESTED_N: usize = 20;

// ---------------------------------------------------------------- types

/// A tracker issue. `id` is the tracker's own id (Linear: UUID), `identifier`
/// the short human one ("CTP-123", "FAKE-1").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRef {
    pub id: String,
    pub identifier: String,
    pub url: String,
}

/// Where an issue is in the triage flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssueState {
    /// Still in the Triage inbox: nobody has looked yet.
    Triage,
    /// Accepted: relevant, now an open ticket (Linear: backlog / unstarted / started).
    Accepted,
    /// Ticket closed as done (Linear: completed).
    Done,
    /// Not relevant (Linear: canceled, or duplicate).
    Declined,
}

impl IssueState {
    /// Linear WorkflowState.type -> IssueState. None for a type this code does not know.
    pub fn from_linear(t: &str) -> Option<Self> {
        match t {
            "triage" => Some(Self::Triage),
            "backlog" | "unstarted" | "started" => Some(Self::Accepted),
            "completed" => Some(Self::Done),
            "canceled" | "duplicate" => Some(Self::Declined),
            _ => None,
        }
    }

    pub fn is_closed(self) -> bool {
        matches!(self, Self::Done | Self::Declined)
    }
}

/// What the tracker says about an issue. Strings are "" when unknown or unset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueStatus {
    pub state: IssueState,
    #[serde(default)]
    pub state_name: String, // the tracker's own name: "Triage", "In Progress", "Canceled"
    #[serde(default)]
    pub assignee: String,
    #[serde(default)]
    pub due: String,        // YYYY-MM-DD
    #[serde(default)]
    pub reason: String,     // decline reason; only filled when state is Declined
    #[serde(default)]
    pub actor: String,      // who moved the issue to its current state
    #[serde(default)]
    pub changed: String,    // when that happened (UTC ISO)
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TrackerError {
    /// Missing or bad settings (LINEAR_MODE, LINEAR_API_KEY, LINEAR_TEAM_ID, team without triage).
    #[error("{0}")]
    Config(String),
    /// No HTTP answer at all.
    #[error("Linear: network error: {0}")]
    Network(String),
    /// HTTP error without a GraphQL error body.
    #[error("Linear: HTTP {status}: {body}")]
    Http { status: u16, body: String },
    /// HTTP 429 or extensions.code RATELIMITED. `limits` is the X-RateLimit-* summary.
    #[error("Linear: rate limited ({message}); {limits}")]
    RateLimited { message: String, limits: String },
    /// GraphQL `errors`. `codes` are the extensions.code values, e.g. AUTHENTICATION_ERROR.
    #[error("Linear: GraphQL errors: {message}")]
    GraphQl { message: String, codes: Vec<String> },
    /// The answer does not have the expected shape.
    #[error("Linear: unexpected reply to {0}")]
    Reply(String),
    /// state/fake-linear.json problems.
    #[error("fake tracker: {0}")]
    Fake(String),
}

pub trait Tracker {
    /// Create one issue for a matched item in the triage inbox.
    fn create_issue(&mut self, item: &Item, m: &Match) -> Result<IssueRef, TrackerError>;
    /// Add a comment (Markdown) to an existing issue.
    fn comment(&mut self, issue: &IssueRef, body: &str) -> Result<(), TrackerError>;
    /// Current state of each issue. An issue the tracker no longer returns
    /// (deleted) is left out; the caller keeps its last known status.
    fn fetch_states(&mut self, issues: &[IssueRef]) -> Result<Vec<(IssueRef, IssueStatus)>, TrackerError>;
}

/// LINEAR_MODE -> tracker. Ok(None) for "off" or unset. Nothing is contacted here: the
/// live tracker looks up the triage state on its first create_issue().
pub fn from_env() -> Result<Option<Box<dyn Tracker>>, TrackerError> {
    from_vars(&|k| std::env::var(k).ok())
}

/// from_env with an explicit variable lookup (tests: no process-wide env changes).
pub fn from_vars(var: &dyn Fn(&str) -> Option<String>) -> Result<Option<Box<dyn Tracker>>, TrackerError> {
    let mode = var("LINEAR_MODE").unwrap_or_default();
    match mode.trim().to_ascii_lowercase().as_str() {
        "" | "off" => Ok(None),
        "fake" => Ok(Some(Box::new(FakeTracker::new()))),
        "live" => Ok(Some(Box::new(LinearTracker::from_vars(var)?))),
        other => Err(TrackerError::Config(format!("LINEAR_MODE={other}: expected off, fake or live"))),
    }
}

// ---------------------------------------------------------------- issue content

/// First `n` characters of `s` (never splits a UTF-8 sequence).
fn head(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// `s` on one line (whitespace runs collapsed), at most `n` characters ("…" when cut).
/// For error texts that end up in the one-line health note.
fn one_line(s: &str, n: usize) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= n { s } else { format!("{}…", head(&s, n - 1)) }
}

/// "[CVE-2026-1234] <title>", "[CVE-A +2] ..." for several CVEs, "[GHSA-…] ..." without one.
/// A title that already starts with the label does not repeat it.
pub fn issue_title(item: &Item) -> String {
    let label = match item.cves.as_slice() {
        [] => item.id.clone(),
        [one] => one.clone(),
        [first, rest @ ..] => format!("{first} +{}", rest.len()),
    };
    let base = item.cves.first().unwrap_or(&item.id);
    let mut title = item.title.trim();
    if let Some(rest) = title.strip_prefix(base.as_str()) {
        title = rest.trim_start_matches([':', '-', ' ', '\u{2013}', '\u{2014}']);
    }
    if title.is_empty() {
        title = item.x("summary").trim();
    }
    let full = if title.is_empty() { format!("[{label}] {}", item.source) } else { format!("[{label}] {title}") };
    let full = full.split_whitespace().collect::<Vec<_>>().join(" ");
    if full.chars().count() <= TITLE_MAX {
        full
    } else {
        format!("{}…", head(&full, TITLE_MAX - 1).trim_end())
    }
}

/// Table cell text: no newlines, no bare pipes.
fn cell(s: &str) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ").replace('|', "\\|");
    if s.is_empty() { "—".into() } else { s }
}

/// UTC ISO when the value parses with a time, the value as-is otherwise (date-only stays a date).
fn utc(s: &str) -> String {
    if s.len() > 10 && let Some(dt) = parse_iso(s) {
        return iso_utc(dt);
    }
    s.to_string()
}

fn score_text(item: &Item) -> String {
    match (item.score > 0.0, item.severity.is_empty()) {
        (true, false) => format!("{:.1} {}", item.score, item.severity),
        (true, true) => format!("{:.1}", item.score),
        (false, false) => item.severity.clone(),
        (false, true) => String::new(),
    }
}

/// Issue description (Markdown). The item key on the last line is the dedup key.
pub fn issue_description(item: &Item, m: &Match) -> String {
    let link = if item.url.is_empty() { cell(&item.id) } else { format!("[{}]({})", cell(&item.id), item.url) };
    let mut out = String::new();
    out.push_str(&format!("New item from **{}** matched component **{}**.\n\n", cell(&item.source), cell(&m.component)));
    out.push_str("| Field | Value |\n|---|---|\n");
    for (k, v) in [
        ("Source", cell(&item.source)),
        ("Publisher link", link),
        ("CVEs", cell(&item.cves.join(", "))),
        ("Published (UTC)", cell(&utc(&item.published))),
        ("Updated (UTC)", cell(&utc(&item.updated))),
        ("Score / severity", cell(&score_text(item))),
        ("Matched component", format!("`{}`", m.component.replace('`', "'"))),
        ("Rule", cell(&m.rule)),
        ("Evidence", format!("`{}`", m.evidence.replace('`', "'"))),
    ] {
        out.push_str(&format!("| {k} | {v} |\n"));
    }
    let summary = item.x("summary").trim();
    if !summary.is_empty() {
        out.push_str(&format!("\n> {}\n", summary.lines().collect::<Vec<_>>().join("\n> ")));
    }
    out.push_str("\nAccept if the component is affected (set an owner and a due date). \
                  Decline if it is not relevant, with the reason as a comment.\n\n");
    out.push_str(&format!("Item key: `{}`\n", item.key()));
    out
}

/// Comment for an item that changed after its issue was created.
pub fn update_comment(item: &Item) -> String {
    format!(
        "{BOT_PREFIX}: the feed item changed.\n\n| Field | Value |\n|---|---|\n\
         | Updated (UTC) | {} |\n| Title | {} |\n| CVEs | {} |\n| Score / severity | {} |\n\nItem key: `{}`\n",
        cell(&utc(&item.updated)), cell(&item.title), cell(&item.cves.join(", ")), cell(&score_text(item)), item.key()
    )
}

// ---------------------------------------------------------------- fake

/// One issue in state/fake-linear.json (see the module doc).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FakeIssue {
    pub identifier: String,
    pub url: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub item_key: String,
    #[serde(default)]
    pub created: String,
    #[serde(default = "fake_state_default")]
    pub state: FakeState,
    #[serde(default)]
    pub assignee: String,
    #[serde(default)]
    pub due: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub changed: String,
    #[serde(default)]
    pub comments: Vec<FakeComment>,
}

/// The four states a person can type in the file ("canceled"/"completed" are accepted too).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FakeState {
    Triage,
    Accepted,
    #[serde(alias = "completed")]
    Done,
    #[serde(alias = "canceled")]
    Declined,
}

fn fake_state_default() -> FakeState {
    FakeState::Triage
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FakeComment {
    pub at: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FakeFile {
    pub next: u64,
    pub issues: Vec<FakeIssue>,
}

impl Default for FakeFile {
    fn default() -> Self {
        Self { next: 1, issues: vec![] }
    }
}

/// Local stand-in for Linear. Reads and writes the file on every call, so edits
/// made between runs (or between calls) are picked up.
pub struct FakeTracker {
    clock: fn() -> DateTime<Utc>,
}

impl Default for FakeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeTracker {
    pub fn new() -> Self {
        Self { clock: state::utcnow }
    }

    #[cfg(test)]
    pub fn with_clock(clock: fn() -> DateTime<Utc>) -> Self {
        Self { clock }
    }

    /// The file, or an empty one when it does not exist. Err when it does not parse.
    pub fn load() -> Result<FakeFile, TrackerError> {
        let Some(raw) = state::load_bytes(FAKE_FILE) else {
            return Ok(FakeFile::default());
        };
        serde_json::from_slice(&raw).map_err(|e| {
            TrackerError::Fake(format!("{}/{FAKE_FILE} is not valid ({e}); fix it by hand, it holds the triage state",
                                       state::dir().display()))
        })
    }

    fn save(f: &FakeFile) {
        state::save_json(FAKE_FILE, f);
    }
}

impl Tracker for FakeTracker {
    fn create_issue(&mut self, item: &Item, m: &Match) -> Result<IssueRef, TrackerError> {
        let mut f = Self::load()?;
        let identifier = format!("FAKE-{}", f.next);
        let url = format!("https://linear.invalid/fake/issue/{identifier}");
        f.next += 1;
        f.issues.push(FakeIssue {
            identifier: identifier.clone(), url: url.clone(), title: issue_title(item),
            description: issue_description(item, m), item_key: item.key(), created: iso_utc((self.clock)()),
            state: FakeState::Triage, assignee: String::new(), due: String::new(), reason: String::new(),
            actor: String::new(), changed: String::new(), comments: vec![],
        });
        Self::save(&f);
        Ok(IssueRef { id: identifier.clone(), identifier, url })
    }

    fn comment(&mut self, issue: &IssueRef, body: &str) -> Result<(), TrackerError> {
        let mut f = Self::load()?;
        let Some(i) = f.issues.iter_mut().find(|i| i.identifier == issue.id) else {
            return Err(TrackerError::Fake(format!("no issue {} in {FAKE_FILE}", issue.identifier)));
        };
        i.comments.push(FakeComment { at: iso_utc((self.clock)()), body: body.into() });
        Self::save(&f);
        Ok(())
    }

    fn fetch_states(&mut self, issues: &[IssueRef]) -> Result<Vec<(IssueRef, IssueStatus)>, TrackerError> {
        let f = Self::load()?;
        Ok(issues
            .iter()
            .filter_map(|r| f.issues.iter().find(|i| i.identifier == r.id))
            .map(|i| {
                let (state, name) = match i.state {
                    FakeState::Triage => (IssueState::Triage, "Triage"),
                    FakeState::Accepted => (IssueState::Accepted, "Accepted"),
                    FakeState::Done => (IssueState::Done, "Done"),
                    FakeState::Declined => (IssueState::Declined, "Declined"),
                };
                let r = IssueRef { id: i.identifier.clone(), identifier: i.identifier.clone(), url: i.url.clone() };
                (r, IssueStatus {
                    state, state_name: name.into(), assignee: i.assignee.trim().into(), due: i.due.trim().into(),
                    reason: if state == IssueState::Declined { i.reason.trim().into() } else { String::new() },
                    actor: i.actor.trim().into(), changed: utc(i.changed.trim()),
                })
            })
            .collect())
    }
}

// ---------------------------------------------------------------- Linear

/// Raw HTTP answer. Header names are lowercase.
#[derive(Debug, Clone)]
pub struct HttpReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpReply {
    pub fn header(&self, name: &str) -> &str {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).unwrap_or("")
    }
}

/// The HTTP layer: POST one JSON body to the GraphQL endpoint. Tests swap it for canned replies.
pub trait Transport {
    fn post(&mut self, body: &Value) -> Result<HttpReply, String>;
}

/// The real transport: shared client (proxy from HTTP(S)_PROXY), personal API key.
pub struct HttpTransport {
    pub endpoint: String,
    key: String,
}

impl HttpTransport {
    pub fn new(endpoint: &str, key: &str) -> Self {
        Self { endpoint: endpoint.into(), key: key.into() }
    }
}

impl Transport for HttpTransport {
    fn post(&mut self, body: &Value) -> Result<HttpReply, String> {
        let r = common::client()
            .post(&self.endpoint)
            .header(CONTENT_TYPE, "application/json")
            // Personal API key: the bare key, no "Bearer" (that is for OAuth tokens).
            .header(AUTHORIZATION, &self.key)
            .header(USER_AGENT, common::user_agent())
            .body(serde_json::to_vec(body).expect("JSON body"))
            .send()
            .map_err(|e| err_chain(&e))?;
        let status = r.status().as_u16();
        let headers = r
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = r.bytes().map_err(|e| err_chain(&e))?.to_vec();
        Ok(HttpReply { status, headers, body })
    }
}

/// Error text with its source chain, so "error sending request" also says why.
fn err_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let t = s.to_string();
        if !out.contains(&t) {
            out.push_str(": ");
            out.push_str(&t);
        }
        src = s.source();
    }
    out
}

/// X-RateLimit-* headers of the last answer ("" when absent). Reset values are UTC ISO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimit {
    pub requests_limit: String,
    pub requests_remaining: String,
    pub requests_reset: String,
    pub complexity: String, // X-Complexity: cost of the last query
    pub complexity_limit: String,
    pub complexity_remaining: String,
    pub complexity_reset: String,
    pub retry_after: String, // seconds, on 429
}

impl RateLimit {
    pub fn from_reply(r: &HttpReply) -> Self {
        // Reset headers are UTC epoch milliseconds (rate-limiting doc).
        let reset = |h: &str| {
            let v = r.header(h);
            v.parse::<i64>().ok().and_then(DateTime::<Utc>::from_timestamp_millis).map(iso_utc).unwrap_or_else(|| v.into())
        };
        Self {
            requests_limit: r.header("x-ratelimit-requests-limit").into(),
            requests_remaining: r.header("x-ratelimit-requests-remaining").into(),
            requests_reset: reset("x-ratelimit-requests-reset"),
            complexity: r.header("x-complexity").into(),
            complexity_limit: r.header("x-ratelimit-complexity-limit").into(),
            complexity_remaining: r.header("x-ratelimit-complexity-remaining").into(),
            complexity_reset: reset("x-ratelimit-complexity-reset"),
            retry_after: r.header("retry-after").into(),
        }
    }

    /// "requests 2499/2500 (reset …), complexity 2999000/3000000 (reset …), retry after 30 s"
    pub fn note(&self) -> String {
        let mut parts = vec![];
        if !self.requests_remaining.is_empty() {
            parts.push(format!("requests {}/{} (reset {})", self.requests_remaining, self.requests_limit, self.requests_reset));
        }
        if !self.complexity_remaining.is_empty() {
            parts.push(format!("complexity {}/{} (reset {})", self.complexity_remaining, self.complexity_limit, self.complexity_reset));
        }
        if !self.retry_after.is_empty() {
            parts.push(format!("retry after {} s", self.retry_after));
        }
        if parts.is_empty() { "no rate-limit headers".into() } else { parts.join(", ") }
    }
}

const Q_TRIAGE_STATE: &str = "query TriageState($team: ID!) {
  workflowStates(filter: { team: { id: { eq: $team } }, type: { eq: \"triage\" } }) {
    nodes { id name type }
  }
}";

const M_ISSUE_CREATE: &str = "mutation IssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { id identifier url }
  }
}";

const M_COMMENT_CREATE: &str = "mutation CommentCreate($input: CommentCreateInput!) {
  commentCreate(input: $input) {
    success
    comment { id }
  }
}";

const Q_ISSUE_STATES: &str = "query IssueStates($ids: [ID!]!, $first: Int!, $nested: Int!) {
  issues(filter: { id: { in: $ids } }, first: $first, includeArchived: true) {
    nodes {
      id
      identifier
      url
      state { type name }
      assignee { name }
      dueDate
      history(first: $nested) { nodes { createdAt actor { name } botActor { name } toState { type name } } }
      comments(first: $nested) { nodes { body createdAt user { name } } }
    }
  }
}";

pub struct LinearTracker {
    transport: Box<dyn Transport>,
    pub team_id: String,
    triage_state: Option<String>,
    /// Rate-limit headers of the last answer, for the health note.
    pub rate: RateLimit,
}

impl LinearTracker {
    pub fn new(transport: Box<dyn Transport>, team_id: &str) -> Self {
        Self { transport, team_id: team_id.into(), triage_state: None, rate: RateLimit::default() }
    }

    /// LINEAR_API_KEY + LINEAR_TEAM_ID from the environment (used by the live test).
    #[cfg(test)]
    pub fn from_env() -> Result<Self, TrackerError> {
        Self::from_vars(&|k| std::env::var(k).ok())
    }

    pub fn from_vars(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, TrackerError> {
        let var = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let key = var("LINEAR_API_KEY").ok_or_else(|| TrackerError::Config("LINEAR_MODE=live needs LINEAR_API_KEY".into()))?;
        let team = var("LINEAR_TEAM_ID").ok_or_else(|| TrackerError::Config("LINEAR_MODE=live needs LINEAR_TEAM_ID".into()))?;
        Ok(Self::new(Box::new(HttpTransport::new(ENDPOINT, &key)), &team))
    }

    /// One GraphQL call; returns `data`. `label` names the operation in errors.
    pub fn gql(&mut self, query: &str, variables: Value, label: &str) -> Result<Value, TrackerError> {
        let r = self
            .transport
            .post(&json!({"query": query, "variables": variables}))
            .map_err(|e| TrackerError::Network(format!("{label}: {}", one_line(&e, 240))))?;
        self.rate = RateLimit::from_reply(&r);
        let text = String::from_utf8_lossy(&r.body);
        let j: Option<Value> = serde_json::from_slice(&r.body).ok();
        let errs = j.as_ref().and_then(|j| j.get("errors")).and_then(Value::as_array).filter(|a| !a.is_empty());
        let codes: Vec<String> = errs
            .map(|a| a.iter().filter_map(|e| e.pointer("/extensions/code").and_then(Value::as_str)).map(String::from).collect())
            .unwrap_or_default();
        let message = errs.map(|a| {
            let m = a.iter().map(|e| e.get("message").and_then(Value::as_str).unwrap_or("?")).collect::<Vec<_>>();
            one_line(&m.join("; "), 240)
        });

        if r.status == 429 || codes.iter().any(|c| c == "RATELIMITED") {
            let m = message.unwrap_or_else(|| format!("HTTP {}", r.status));
            return Err(TrackerError::RateLimited { message: format!("{label}: {m}"), limits: self.rate.note() });
        }
        if let Some(mut m) = message {
            if codes.iter().any(|c| c.contains("AUTHENTICATION")) || r.status == 401 {
                m.push_str(" (LINEAR_API_KEY missing, wrong or revoked)");
            } else if codes.iter().any(|c| c == "FORBIDDEN") || r.status == 403 {
                m.push_str(" (the key's user cannot access LINEAR_TEAM_ID)");
            }
            return Err(TrackerError::GraphQl { message: format!("{label}: {m}"), codes });
        }
        if !(200..300).contains(&r.status) {
            return Err(TrackerError::Http { status: r.status, body: format!("{label}: {}", one_line(&text, 200)) });
        }
        let Some(j) = j else {
            return Err(TrackerError::Reply(format!("{label}: non-JSON body: {}", one_line(&text, 120))));
        };
        Ok(j.get("data").cloned().unwrap_or(Value::Null))
    }

    /// Id of the team's triage workflow state (looked up once, then cached).
    pub fn triage_state_id(&mut self) -> Result<String, TrackerError> {
        if let Some(s) = &self.triage_state {
            return Ok(s.clone());
        }
        let team = self.team_id.clone();
        let d = self.gql(Q_TRIAGE_STATE, json!({"team": team}), "workflowStates")?;
        let nodes = d.pointer("/workflowStates/nodes").and_then(Value::as_array)
            .ok_or_else(|| TrackerError::Reply("workflowStates: no nodes".into()))?;
        let id = nodes.first().and_then(|n| n.get("id")).and_then(Value::as_str).ok_or_else(|| {
            TrackerError::Config(format!("Linear team {team} has no triage state: turn on Triage in the team settings, \
                                          or check LINEAR_TEAM_ID"))
        })?;
        self.triage_state = Some(id.to_string());
        Ok(id.to_string())
    }
}

fn s(v: &Value, ptr: &str) -> String {
    v.pointer(ptr).and_then(Value::as_str).unwrap_or("").to_string()
}

fn issue_ref(v: &Value, label: &str) -> Result<IssueRef, TrackerError> {
    let r = IssueRef { id: s(v, "/id"), identifier: s(v, "/identifier"), url: s(v, "/url") };
    if r.id.is_empty() {
        return Err(TrackerError::Reply(format!("{label}: issue without id: {}", head(&v.to_string(), 200))));
    }
    Ok(r)
}

/// Node with the latest `createdAt` among `nodes` that pass `keep` (order of the API not assumed).
fn latest(nodes: Option<&Value>, keep: impl Fn(&Value) -> bool) -> Option<&Value> {
    nodes?.as_array()?.iter().filter(|n| keep(n)).max_by_key(|n| parse_iso(&s(n, "/createdAt")))
}

/// One node of the IssueStates query -> (IssueRef, IssueStatus).
pub fn parse_issue_node(n: &Value) -> Result<(IssueRef, IssueStatus), TrackerError> {
    let r = issue_ref(n, "issues")?;
    let t = s(n, "/state/type");
    let state = IssueState::from_linear(&t)
        .ok_or_else(|| TrackerError::Reply(format!("issues: {} has unknown state type {t:?}", r.identifier)))?;
    let change = latest(n.pointer("/history/nodes"), |h| h.pointer("/toState").is_some_and(|v| !v.is_null()));
    let actor = change.map(|h| {
        let a = s(h, "/actor/name");
        if a.is_empty() { s(h, "/botActor/name") } else { a }
    });
    let reason = if state == IssueState::Declined {
        latest(n.pointer("/comments/nodes"), |c| !s(c, "/body").trim_start().starts_with(BOT_PREFIX))
            .map(|c| s(c, "/body").trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok((r, IssueStatus {
        state,
        state_name: s(n, "/state/name"),
        assignee: s(n, "/assignee/name"),
        due: s(n, "/dueDate"),
        reason,
        actor: actor.unwrap_or_default(),
        changed: change.map(|h| utc(&s(h, "/createdAt"))).unwrap_or_default(),
    }))
}

impl Tracker for LinearTracker {
    fn create_issue(&mut self, item: &Item, m: &Match) -> Result<IssueRef, TrackerError> {
        let state = self.triage_state_id()?;
        let input = json!({"teamId": self.team_id, "title": issue_title(item),
                           "description": issue_description(item, m), "stateId": state});
        let d = self.gql(M_ISSUE_CREATE, json!({"input": input}), "issueCreate")?;
        if d.pointer("/issueCreate/success") != Some(&Value::Bool(true)) {
            return Err(TrackerError::Reply(format!("issueCreate: success is not true: {}", head(&d.to_string(), 200))));
        }
        issue_ref(d.pointer("/issueCreate/issue").unwrap_or(&Value::Null), "issueCreate")
    }

    fn comment(&mut self, issue: &IssueRef, body: &str) -> Result<(), TrackerError> {
        let d = self.gql(M_COMMENT_CREATE, json!({"input": {"issueId": issue.id, "body": body}}), "commentCreate")?;
        if d.pointer("/commentCreate/success") != Some(&Value::Bool(true)) {
            return Err(TrackerError::Reply(format!("commentCreate on {}: success is not true", issue.identifier)));
        }
        Ok(())
    }

    fn fetch_states(&mut self, issues: &[IssueRef]) -> Result<Vec<(IssueRef, IssueStatus)>, TrackerError> {
        let mut out = vec![];
        for chunk in issues.chunks(FETCH_BATCH) {
            let ids: Vec<&str> = chunk.iter().map(|r| r.id.as_str()).collect();
            let d = self.gql(Q_ISSUE_STATES, json!({"ids": ids, "first": chunk.len(), "nested": NESTED_N}),
                             "issues")?;
            let nodes = d.pointer("/issues/nodes").and_then(Value::as_array)
                .ok_or_else(|| TrackerError::Reply("issues: no nodes".into()))?;
            for n in nodes {
                out.push(parse_issue_node(n)?);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use chrono::TimeZone;

    use super::*;

    fn fixture(name: &str) -> String {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn item() -> Item {
        let mut it = Item::new("CISA KEV", "CVE-2026-1234", "https://www.cve.org/CVERecord?id=CVE-2026-1234",
                               "CVE-2026-1234: Tokio | runtime use-after-free", "2026-11-03T02:31:19.933Z");
        it.cves = vec!["CVE-2026-1234".into()];
        it.score = 9.8;
        it.severity = "CRITICAL".into();
        it
    }

    fn m() -> Match {
        Match { component: "fairct-scorer".into(), rule: "package".into(), evidence: "rust:tokio".into() }
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 3, 8, 0, 0).unwrap()
    }

    // ------------------------------------------------ content

    #[test]
    fn title_label_and_truncation() {
        assert_eq!(issue_title(&item()), "[CVE-2026-1234] Tokio | runtime use-after-free");
        let mut it = item();
        it.cves = vec!["CVE-2026-1".into(), "CVE-2026-2".into(), "CVE-2026-3".into()];
        it.title = "Multiple flaws in nginx".into();
        assert_eq!(issue_title(&it), "[CVE-2026-1 +2] Multiple flaws in nginx");
        let mut g = Item::new("GitHub", "GHSA-abcd-efgh-ijkl", "u", &format!("tokio: {}", "é".repeat(200)), "2026-11-03");
        g.cves.clear();
        let t = issue_title(&g);
        assert!(t.starts_with("[GHSA-abcd-efgh-ijkl] tokio: éé"), "{t}");
        assert_eq!(t.chars().count(), TITLE_MAX);
        assert!(t.ends_with('…'));
        let empty = Item::new("NCSC-NL", "NCSC-2026-0464", "u", "  ", "2026-11-03");
        assert_eq!(issue_title(&empty), "[NCSC-2026-0464] NCSC-NL");
    }

    #[test]
    fn description_has_fields_and_key() {
        let mut it = item();
        it.updated = "2026-11-03T05:00:00+02:00".into();
        it.extra.insert("summary".into(), json!("Line one\nline two"));
        let d = issue_description(&it, &m());
        for want in [
            "| Source | CISA KEV |",
            "| Publisher link | [CVE-2026-1234](https://www.cve.org/CVERecord?id=CVE-2026-1234) |",
            "| Published (UTC) | 2026-11-03T02:31:19Z |",
            "| Updated (UTC) | 2026-11-03T03:00:00Z |",
            "| Score / severity | 9.8 CRITICAL |",
            "| Matched component | `fairct-scorer` |",
            "| Rule | package |",
            "| Evidence | `rust:tokio` |",
            "> Line one\n> line two",
            "Item key: `CISA KEV:CVE-2026-1234`",
        ] {
            assert!(d.contains(want), "missing {want:?} in\n{d}");
        }
        let mut bare = Item::new("NCSC-NL", "NCSC-2026-0464", "", "x", "2026-11-03");
        bare.cves.clear();
        let d = issue_description(&bare, &m());
        assert!(d.contains("| Publisher link | NCSC-2026-0464 |") && d.contains("| Updated (UTC) | — |")
                && d.contains("| Published (UTC) | 2026-11-03 |"), "{d}");
        assert!(update_comment(&it).starts_with(BOT_PREFIX));
    }

    // ------------------------------------------------ fake

    #[test]
    fn fake_round_trip_with_hand_edit() {
        let t = state::testing::temp_state("fake-linear");
        let mut f = FakeTracker::with_clock(fixed_now);
        let a = f.create_issue(&item(), &m()).unwrap();
        let mut other = item();
        other.id = "CVE-2026-9".into();
        let b = f.create_issue(&other, &m()).unwrap();
        assert_eq!((a.identifier.as_str(), b.identifier.as_str()), ("FAKE-1", "FAKE-2"));
        f.comment(&a, &update_comment(&item())).unwrap();

        let st = f.fetch_states(&[a.clone(), b.clone()]).unwrap();
        assert_eq!(st.len(), 2);
        assert_eq!(st[0].1.state, IssueState::Triage);

        // A person triages by editing the file.
        let p = t.dir.join(FAKE_FILE);
        let mut j: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(j["next"], 3);
        assert_eq!(j["issues"][0]["item_key"], "CISA KEV:CVE-2026-1234");
        assert_eq!(j["issues"][0]["created"], "2026-11-03T08:00:00Z");
        assert_eq!(j["issues"][0]["comments"].as_array().unwrap().len(), 1);
        j["issues"][0]["state"] = json!("accepted");
        j["issues"][0]["assignee"] = json!("Henry");
        j["issues"][0]["due"] = json!("2026-11-10");
        j["issues"][0]["actor"] = json!("James");
        j["issues"][0]["reason"] = json!("ignored unless declined");
        j["issues"][1]["state"] = json!("canceled");
        j["issues"][1]["reason"] = json!("we do not ship nginx");
        j["issues"][1]["changed"] = json!("2026-11-04T09:00:00+07:00");
        std::fs::write(&p, serde_json::to_vec_pretty(&j).unwrap()).unwrap();

        let gone = IssueRef { id: "FAKE-99".into(), identifier: "FAKE-99".into(), url: String::new() };
        let st = f.fetch_states(&[a.clone(), b.clone(), gone]).unwrap();
        assert_eq!(st.len(), 2, "unknown issues are left out");
        assert_eq!(st[0].0, a);
        assert_eq!(st[0].1, IssueStatus {
            state: IssueState::Accepted, state_name: "Accepted".into(), assignee: "Henry".into(),
            due: "2026-11-10".into(), reason: String::new(), actor: "James".into(), changed: String::new(),
        });
        assert_eq!(st[1].1.state, IssueState::Declined);
        assert_eq!(st[1].1.reason, "we do not ship nginx");
        assert_eq!(st[1].1.changed, "2026-11-04T02:00:00Z");
    }

    #[test]
    fn fake_bad_file_is_an_error_and_kept() {
        let t = state::testing::temp_state("fake-linear-bad");
        let p = t.dir.join(FAKE_FILE);
        std::fs::write(&p, r#"{"next": 2, "issues": [{"identifier": "FAKE-1", "url": "u", "title": "t", "state": "maybe"}]}"#).unwrap();
        let mut f = FakeTracker::new();
        let e = f.create_issue(&item(), &m()).unwrap_err();
        assert!(matches!(&e, TrackerError::Fake(msg) if msg.contains("is not valid")), "{e}");
        assert!(std::fs::read_to_string(&p).unwrap().contains("maybe"), "file must not be overwritten");
        let r = IssueRef { id: "FAKE-7".into(), identifier: "FAKE-7".into(), url: String::new() };
        std::fs::remove_file(&p).unwrap();
        assert!(matches!(f.comment(&r, "x").unwrap_err(), TrackerError::Fake(_)));
    }

    #[test]
    fn mode_selection() {
        let pick = |vars: &[(&str, &str)]| {
            let vars: Vec<(String, String)> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            from_vars(&move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
        };
        assert!(pick(&[("LINEAR_MODE", "off")]).unwrap().is_none());
        assert!(pick(&[]).unwrap().is_none(), "default is off");
        assert!(pick(&[("LINEAR_MODE", " ")]).unwrap().is_none());
        assert!(pick(&[("LINEAR_MODE", " Fake ")]).unwrap().is_some());
        assert_eq!(pick(&[("LINEAR_MODE", "live"), ("LINEAR_API_KEY", " ")]).err().unwrap(),
                   TrackerError::Config("LINEAR_MODE=live needs LINEAR_API_KEY".into()));
        assert_eq!(pick(&[("LINEAR_MODE", "live"), ("LINEAR_API_KEY", "lin_api_x")]).err().unwrap(),
                   TrackerError::Config("LINEAR_MODE=live needs LINEAR_TEAM_ID".into()));
        assert!(pick(&[("LINEAR_MODE", "live"), ("LINEAR_API_KEY", "lin_api_x"), ("LINEAR_TEAM_ID", "t")]).unwrap().is_some());
        assert!(matches!(pick(&[("LINEAR_MODE", "jira")]).err().unwrap(), TrackerError::Config(m) if m.contains("LINEAR_MODE=jira")));
    }

    // ------------------------------------------------ Linear (canned replies)

    /// Serves canned replies in order and records the request bodies.
    struct Canned {
        replies: VecDeque<Result<HttpReply, String>>,
        seen: Arc<Mutex<Vec<Value>>>,
    }

    impl Transport for Canned {
        fn post(&mut self, body: &Value) -> Result<HttpReply, String> {
            self.seen.lock().unwrap().push(body.clone());
            self.replies.pop_front().expect("no canned reply left")
        }
    }

    fn reply(status: u16, body: &str, headers: &[(&str, &str)]) -> Result<HttpReply, String> {
        Ok(HttpReply {
            status,
            headers: headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.to_string())).collect(),
            body: body.as_bytes().to_vec(),
        })
    }

    fn linear(replies: Vec<Result<HttpReply, String>>) -> (LinearTracker, Arc<Mutex<Vec<Value>>>) {
        let seen = Arc::new(Mutex::new(vec![]));
        let t = Canned { replies: replies.into(), seen: seen.clone() };
        (LinearTracker::new(Box::new(t), "team-uuid"), seen)
    }

    #[test]
    fn linear_create_comment_requests() {
        let (mut l, seen) = linear(vec![
            reply(200, &fixture("linear_workflow_states.json"), &[]),
            reply(200, &fixture("linear_issue_create.json"), &[("X-RateLimit-Requests-Remaining", "2498"),
                  ("X-RateLimit-Requests-Limit", "2500"), ("X-RateLimit-Requests-Reset", "1793692800000")]),
            reply(200, &fixture("linear_issue_create.json"), &[]),
            reply(200, &fixture("linear_comment_create.json"), &[]),
        ]);
        let r = l.create_issue(&item(), &m()).unwrap();
        assert_eq!(r, IssueRef {
            id: "a1b2c3d4-0000-4000-8000-000000000123".into(), identifier: "CTP-123".into(),
            url: "https://linear.app/ediphy/issue/CTP-123/cve-2026-1234-tokio-runtime-use-after-free".into(),
        });
        assert_eq!(l.rate.note(), "requests 2498/2500 (reset 2026-11-03T08:00:00Z)");
        l.create_issue(&item(), &m()).unwrap(); // triage state id is cached: no second lookup
        l.comment(&r, "**exploit-watch**: x").unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 4);
        assert!(seen[0]["query"].as_str().unwrap().contains("type: { eq: \"triage\" }"));
        assert_eq!(seen[0]["variables"], json!({"team": "team-uuid"}));
        let input = &seen[1]["variables"]["input"];
        assert_eq!(input["teamId"], "team-uuid");
        assert_eq!(input["stateId"], "6f1e2d3c-0000-4000-8000-00000000000a");
        assert_eq!(input["title"], "[CVE-2026-1234] Tokio | runtime use-after-free");
        assert!(input["description"].as_str().unwrap().contains("Item key: `CISA KEV:CVE-2026-1234`"));
        assert!(seen[2]["query"].as_str().unwrap().starts_with("mutation IssueCreate"));
        assert_eq!(seen[3]["variables"]["input"], json!({"issueId": r.id, "body": "**exploit-watch**: x"}));
    }

    #[test]
    fn linear_fetch_states_parsing() {
        let (mut l, seen) = linear(vec![reply(200, &fixture("linear_issues_states.json"), &[])]);
        let refs: Vec<IssueRef> = ["CTP-123", "CTP-124", "CTP-125", "CTP-126"]
            .iter()
            .map(|i| IssueRef { id: format!("id-{i}"), identifier: i.to_string(), url: String::new() })
            .collect();
        let st = l.fetch_states(&refs).unwrap();
        let v = &seen.lock().unwrap()[0]["variables"];
        assert_eq!(v["ids"], json!(["id-CTP-123", "id-CTP-124", "id-CTP-125", "id-CTP-126"]));
        assert_eq!(v["first"], 4);

        assert_eq!(st.len(), 4);
        let by = |i: &str| st.iter().find(|(r, _)| r.identifier == i).unwrap().1.clone();
        assert_eq!(by("CTP-123"), IssueStatus {
            state: IssueState::Triage, state_name: "Triage".into(), assignee: String::new(), due: String::new(),
            reason: String::new(), actor: String::new(), changed: String::new(),
        });
        assert_eq!(by("CTP-124"), IssueStatus {
            state: IssueState::Accepted, state_name: "In Progress".into(), assignee: "Tran Trung Hau".into(),
            due: "2026-11-10".into(), reason: String::new(), actor: "Vu Huy Hoang".into(),
            changed: "2026-11-03T09:15:00Z".into(),
        });
        let declined = by("CTP-125");
        assert_eq!(declined.state, IssueState::Declined);
        assert_eq!(declined.reason, "Not relevant: we only use tokio in the test harness.");
        assert_eq!((declined.actor.as_str(), declined.changed.as_str()), ("Tran Trung Hau", "2026-11-03T10:00:00Z"));
        let dup = by("CTP-126");
        assert_eq!(IssueState::from_linear("duplicate"), Some(IssueState::Declined));
        assert_eq!((dup.state, dup.actor.as_str()), (IssueState::Declined, "Triage Intelligence"));
        assert_eq!(dup.reason, "", "the job's own comments are never a reason");
        assert_eq!(st[0].0.url, "https://linear.app/ediphy/issue/CTP-123/x");
    }

    #[test]
    fn linear_fetch_batches() {
        let empty = r#"{"data":{"issues":{"nodes":[]}}}"#;
        let (mut l, seen) = linear(vec![reply(200, empty, &[]), reply(200, empty, &[])]);
        let refs: Vec<IssueRef> = (0..FETCH_BATCH + 3)
            .map(|i| IssueRef { id: format!("id{i}"), identifier: format!("CTP-{i}"), url: String::new() })
            .collect();
        assert!(l.fetch_states(&refs).unwrap().is_empty());
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1]["variables"]["ids"].as_array().unwrap().len(), 3);
        assert!(l.fetch_states(&[]).unwrap().is_empty());
    }

    #[test]
    fn linear_error_mapping() {
        let rl_headers = [("X-RateLimit-Requests-Remaining", "0"), ("X-RateLimit-Requests-Limit", "2500"),
                          ("X-RateLimit-Requests-Reset", "1793692800000"), ("Retry-After", "30")];
        let (mut l, _) = linear(vec![
            Err("error sending request: connection refused".into()),
            reply(429, &fixture("linear_error_ratelimited.json"), &rl_headers),
            reply(400, &fixture("linear_error_auth.json"), &[]),
            reply(200, r#"{"errors":[{"message":"Entity not found: Issue","extensions":{"code":"INVALID_INPUT"}}],"data":null}"#, &[]),
            reply(502, "<html>Bad Gateway</html>", &[]),
            reply(200, "not json", &[]),
            reply(200, r#"{"data":{"issueCreate":{"success":false,"issue":null}}}"#, &[]),
            reply(200, r#"{"data":{"workflowStates":{"nodes":[]}}}"#, &[]),
            reply(200, r#"{"data":{"issues":{"nodes":[{"id":"x","identifier":"CTP-1","url":"u","state":{"type":"paused","name":"P"}}]}}}"#, &[]),
        ]);
        let q = |l: &mut LinearTracker| l.gql("{ viewer { id } }", json!({}), "viewer").unwrap_err();
        assert_eq!(q(&mut l), TrackerError::Network("viewer: error sending request: connection refused".into()));
        let e = q(&mut l);
        assert_eq!(e.to_string(), "Linear: rate limited (viewer: Rate limit exceeded); \
                                   requests 0/2500 (reset 2026-11-03T08:00:00Z), retry after 30 s");
        let e = q(&mut l);
        assert!(matches!(&e, TrackerError::GraphQl { codes, .. } if codes == &["AUTHENTICATION_ERROR"]), "{e:?}");
        assert!(e.to_string().ends_with("(LINEAR_API_KEY missing, wrong or revoked)"), "{e}");
        assert_eq!(q(&mut l).to_string(), "Linear: GraphQL errors: viewer: Entity not found: Issue");
        assert_eq!(q(&mut l), TrackerError::Http { status: 502, body: "viewer: <html>Bad Gateway</html>".into() });
        assert_eq!(q(&mut l), TrackerError::Reply("viewer: non-JSON body: not json".into()));

        l.triage_state = Some("s".into());
        assert!(matches!(l.create_issue(&item(), &m()).unwrap_err(), TrackerError::Reply(m) if m.starts_with("issueCreate: success")));
        l.triage_state = None;
        let e = l.create_issue(&item(), &m()).unwrap_err();
        assert!(matches!(&e, TrackerError::Config(m) if m.contains("has no triage state")), "{e}");
        let r = IssueRef { id: "x".into(), identifier: "CTP-1".into(), url: String::new() };
        assert!(matches!(l.fetch_states(&[r]).unwrap_err(), TrackerError::Reply(m) if m.contains("\"paused\"")));
    }

    /// Error texts go into a one-line health note: no newlines, bounded length.
    #[test]
    fn linear_errors_are_one_line() {
        let page = format!("<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n{}\n</body></html>", "x ".repeat(500));
        let many = (0..30).map(|i| format!(r#"{{"message":"Field 'f{i}' is\nnot defined"}}"#)).collect::<Vec<_>>().join(",");
        let (mut l, _) = linear(vec![
            Err(format!("error sending request\n{}", "for url ".repeat(100))),
            reply(502, &page, &[]),
            reply(200, &page, &[]),
            reply(200, &format!(r#"{{"errors":[{many}],"data":null}}"#), &[]),
        ]);
        for _ in 0..4 {
            let e = l.gql("{ viewer { id } }", json!({}), "viewer").unwrap_err().to_string();
            assert!(!e.contains('\n') && e.chars().count() <= 320, "{} chars: {e}", e.chars().count());
        }
        assert_eq!(one_line(" a \n b ", 10), "a b");
        assert_eq!(one_line("abcdef", 4), "abc…");
    }

    /// Live, against a THROWAWAY Linear team with Triage turned on: creates one
    /// issue, comments on it and reads its state back.
    ///   LINEAR_API_KEY=… LINEAR_TEAM_ID=… cargo test -- --ignored live_linear_round_trip --nocapture
    #[test]
    #[ignore]
    fn live_linear_round_trip() {
        let mut l = LinearTracker::from_env().unwrap();
        let mut it = item();
        it.title = format!("exploit-watch live test {}", iso_utc(Utc::now()));
        let r = l.create_issue(&it, &m()).unwrap();
        eprintln!("created {} {}", r.identifier, r.url);
        l.comment(&r, &update_comment(&it)).unwrap();
        let st = l.fetch_states(std::slice::from_ref(&r)).unwrap();
        eprintln!("state: {:?}\nrate: {}", st, l.rate.note());
        assert_eq!(st[0].1.state, IssueState::Triage);
    }
}
