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
//!   live   LinearTracker: Linear GraphQL API, needs LINEAR_API_KEY + LINEAR_TEAM_ID
//!
//! Any other value (also the former "fake") is a Config error. LINEAR_API_URL
//! sets the live tracker's GraphQL endpoint (unset or empty: ENDPOINT, the real
//! Linear API); the local compose lab points it at the `linear-mock` service,
//! which serves the same GraphQL API.
//!
//! TrackerError's Display is one line (whitespace collapsed, bodies cut), so the
//! run can put it in the health note; tracker errors never fail the run (sync.rs).
//!
//! FakeTracker exists in test builds only: a file-based test double for the
//! store and sync tests (file format on FakeTracker). The binary has no
//! file-based tracker.
//!
//! Linear API (https://linear.app/developers/graphql, schema
//! github.com/linear/linear packages/sdk/src/schema.graphql, read 2026-11-03):
//! endpoint https://api.linear.app/graphql, personal API key in
//! `Authorization: <key>` (no "Bearer"), OAuth access token in
//! `Authorization: Bearer <token>`, errors in a GraphQL `errors` array even
//! with HTTP 200, rate limit = HTTP 429 + extensions.code "RATELIMITED" with
//! X-RateLimit-* headers (https://linear.app/developers/rate-limiting).
//! Workflow state types: triage, backlog, unstarted, started, completed,
//! canceled, duplicate. Linear has no "decline reason" field; the reason is the
//! latest comment that the job did not write itself.
//!
//! Reading triage back (parse_issue_node), as observed on a real Linear
//! workspace on 2026-11-04/05:
//!   - Any move out of Triage (Accept, Decline, a status change, Mark as
//!     duplicate) sets Issue.triagedAt and writes one history entry, by the
//!     person, within ~50 ms of triagedAt. Accept, Decline and a status change
//!     give that entry fromState.type "triage"; Mark as duplicate gives an
//!     entry with fromState and toState null (the relation only) and the state
//!     type "duplicate", not "canceled". Snooze leaves the issue in Triage
//!     (snoozedUntilAt set, triagedAt null, no history entry): still untriaged.
//!   - A decline reason is a separate comment, at the same time as the state
//!     change or some seconds later.
//!   - history and comments come back newest first; first: N keeps the N
//!     newest. The code does not rely on the order (it compares createdAt).
//!   - An OAuth app shows as a user in actor / creator ("Exploit Watch");
//!     botActor stayed null.
//!
//! Credential: LINEAR_API_KEY holds either a personal API key or an OAuth access
//! token (e.g. from an OAuth app's client_credentials grant, actor=app). The
//! prefix picks the header (auth_value): a value starting with
//! PERSONAL_KEY_PREFIX ("lin_api_") is sent bare, anything else as
//! "Bearer <value>". The job does not obtain or refresh OAuth tokens: when one
//! expires, calls fail with AUTHENTICATION_ERROR until LINEAR_API_KEY is replaced.
//! The credential never appears in errors, logs or the health note; the header
//! value is marked sensitive.
//!
//! Idempotent issue creation (real Linear, 2026-11-05): every create sends the
//! job's own id in IssueCreateInput.id, a random UUID v4 (new_issue_id) that the
//! store saves in the record before the first attempt (sync.rs), so every retry
//! for the same item sends the same id. Linear stores that id as the issue id
//! (T15). A second issueCreate with an id that exists answers HTTP 200,
//! `data: null`, extensions.code INPUT_ERROR, message "conflict on insert of
//! Issue", and creates nothing (T15). So when the answer to a create is lost
//! (timeout, proxy reset), the next run's create conflicts and create_issue()
//! reads the issue with `issue(id:)` and returns it as if just created
//! (counted in recovered()). Any other INPUT_ERROR stays an error. If the id
//! conflicts but `issue(id:)` finds nothing (the issue was deleted and Linear
//! still holds its id; not verified), create_issue() returns IdTaken and sync
//! retries once with a fresh id, so a deleted issue never blocks later runs.
//! Linear accepts only version 4: a name-based v5 id was refused with
//! INVALID_INPUT "id must be a UUID" (2026-11-05), so the id cannot be derived
//! from the item key. Attachment URLs are no dedup key either: Linear upserts
//! them per (issue, url) only, the same url on another issue is a new
//! attachment (T16).

use chrono::{DateTime, Utc};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::types::Match;
use crate::feeds::common::{self, Item, iso_utc, parse_iso};
#[cfg(test)]
use crate::feeds::state;

/// Default GraphQL endpoint of the live tracker; LINEAR_API_URL overrides it.
pub const ENDPOINT: &str = "https://api.linear.app/graphql";
/// Linear personal API keys start with this; they go in Authorization without "Bearer".
pub const PERSONAL_KEY_PREFIX: &str = "lin_api_";
#[cfg(test)]
pub const FAKE_FILE: &str = "fake-linear.json";
/// Comments the job writes start with this, so they are never read back as a decline reason.
pub const BOT_PREFIX: &str = "**exploit-watch**";
/// Issue titles longer than this are cut with "…".
pub const TITLE_MAX: usize = 120;
/// Issues per fetch_states() request. Each issue also asks for NESTED_N history and
/// NESTED_N comment nodes, which count toward Linear's complexity budget: measured
/// 2026-11-05, x-complexity of IssueStates was 99 with 20 and 234 with 50, the same
/// for 1 or 19 ids (limit 10,000 per query).
const FETCH_BATCH: usize = 25;
/// Newest history entries and comments read per issue. 50, not 20: Linear keeps the
/// newest, so the entry that left Triage and the decline comment drop out of the
/// window once an issue has that many later changes or comments.
const NESTED_N: usize = 50;
/// A history entry this close to triagedAt is the triage action (measured: under 50 ms).
const TRIAGE_MATCH_MS: i64 = 5_000;
/// `reason` of an issue marked as duplicate when nobody left a comment.
pub const DUPLICATE_REASON: &str = "Marked as duplicate";

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
    /// Not relevant (Linear: canceled, or duplicate = Mark as duplicate).
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
    /// Decline reason; only filled when state is Declined: the latest comment the job did
    /// not write, else DUPLICATE_REASON for a duplicate.
    #[serde(default)]
    pub reason: String,
    /// Who triaged the issue, i.e. moved it out of Triage (Accept, Decline, a status
    /// change, Mark as duplicate); later moves do not change it. "" while in Triage.
    #[serde(default)]
    pub actor: String,
    /// When the issue left Triage (UTC ISO; Linear triagedAt). "" while in Triage.
    #[serde(default)]
    pub changed: String,
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
    /// issueCreate: an issue with this id exists, but Linear does not return it
    /// (deleted). The caller retries with a new id.
    #[error("Linear: issue id {0} is taken by an issue Linear does not return (deleted?)")]
    IdTaken(String),
    /// state/fake-linear.json problems (FakeTracker, test builds only).
    #[cfg(test)]
    #[error("fake tracker: {0}")]
    Fake(String),
}

pub trait Tracker {
    /// Create one issue for a matched item in the triage inbox, with `id` (a UUID
    /// v4 the store keeps for the item) as its tracker id. Called again with the
    /// same id after an answer was lost, it returns the issue that exists.
    fn create_issue(&mut self, item: &Item, m: &Match, id: &str) -> Result<IssueRef, TrackerError>;
    /// How many create_issue() calls so far found their issue already created
    /// (an earlier answer was lost) instead of creating it.
    fn recovered(&self) -> usize {
        0
    }
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
        "live" => Ok(Some(Box::new(LinearTracker::from_vars(var)?))),
        other => Err(TrackerError::Config(format!("LINEAR_MODE={other}: expected off or live"))),
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

// ---------------------------------------------------------------- issue ids

/// `b` as a UUID version 4 (RFC 9562 §5.4): version and variant bits set,
/// lowercase and hyphenated.
pub fn uuid_v4(mut b: [u8; 16]) -> String {
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// A new random UUID v4 for IssueCreateInput.id (Linear accepts version 4 only).
/// 16 bytes from /dev/urandom (the job runs on Linux); where that cannot be read,
/// SHA-256 of OS-seeded hasher keys, the time, the process id and a counter.
/// Uniqueness is what matters here, not secrecy.
pub fn new_issue_id() -> String {
    use std::hash::{BuildHasher, Hasher, RandomState};
    use std::io::Read;
    use std::sync::atomic::{AtomicU64, Ordering};

    use sha2::{Digest, Sha256};

    let mut b = [0u8; 16];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_err() {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let mut h = Sha256::new();
        for _ in 0..2 {
            let mut s = RandomState::new().build_hasher();
            s.write_u64(n);
            h.update(s.finish().to_le_bytes());
        }
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        h.update(nanos.to_le_bytes());
        h.update(std::process::id().to_le_bytes());
        b.copy_from_slice(&h.finalize()[..16]);
    }
    uuid_v4(b)
}

// ---------------------------------------------------------------- fake (test builds only)

/// One issue in state/fake-linear.json (format on FakeTracker).
#[cfg(test)]
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

/// The four states a test can write in the file ("canceled"/"completed" are accepted too).
#[cfg(test)]
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

#[cfg(test)]
fn fake_state_default() -> FakeState {
    FakeState::Triage
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FakeComment {
    pub at: String,
    pub body: String,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FakeFile {
    pub next: u64,
    pub issues: Vec<FakeIssue>,
}

#[cfg(test)]
impl Default for FakeFile {
    fn default() -> Self {
        Self { next: 1, issues: vec![] }
    }
}

/// Test double for Linear (test builds only), used by the store and sync tests.
/// Reads and writes STATE_DIR/fake-linear.json on every call, so edits a test
/// makes between calls are picked up. A test simulates triage by editing the
/// fields marked "edit":
///
///   {
///    "next": 3,                                   next FAKE-n number
///    "issues": [
///     {
///      "identifier": "FAKE-1",
///      "url": "https://linear.invalid/fake/issue/FAKE-1",
///      "title": "[CVE-2026-1234] ...",
///      "description": "...",                      Markdown, as Linear would get it
///      "item_key": "CISA KEV:CVE-2026-1234",
///      "created": "2026-11-03T08:00:00Z",
///      "state": "triage",        edit: triage | accepted | done | declined
///      "assignee": "",           edit: owner name, e.g. "Henry"
///      "due": "",                edit: YYYY-MM-DD
///      "reason": "",             edit: why it was declined
///      "actor": "",              edit: who accepted/declined it
///      "changed": "",            optional: when (UTC ISO), "" = unknown
///      "comments": [{"at": "2026-11-04T08:00:00Z", "body": "..."}]
///     }
///    ]
///   }
///
/// A file that does not parse is an error, never silently replaced.
#[cfg(test)]
pub struct FakeTracker {
    clock: fn() -> DateTime<Utc>,
}

#[cfg(test)]
impl Default for FakeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
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

#[cfg(test)]
impl Tracker for FakeTracker {
    /// `id` is ignored: the fake's issue id is its identifier (FAKE-n).
    fn create_issue(&mut self, item: &Item, m: &Match, _id: &str) -> Result<IssueRef, TrackerError> {
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
/// `Any` lets tests downcast a LinearTracker's transport to check its endpoint.
pub trait Transport: std::any::Any {
    fn post(&mut self, body: &Value) -> Result<HttpReply, String>;
}

/// Authorization header value for the LINEAR_API_KEY credential: a personal API
/// key (starts with PERSONAL_KEY_PREFIX) bare, as Linear requires; anything else
/// is taken as an OAuth access token and sent as "Bearer <token>".
pub fn auth_value(credential: &str) -> String {
    if credential.starts_with(PERSONAL_KEY_PREFIX) {
        credential.to_string()
    } else {
        format!("Bearer {credential}")
    }
}

/// The real transport: shared client (proxy from HTTP(S)_PROXY), Authorization
/// from auth_value(). No Debug: it holds the credential.
pub struct HttpTransport {
    pub endpoint: String,
    auth: HeaderValue,
}

impl HttpTransport {
    /// Config error (without the value) when the credential cannot go in an HTTP header.
    pub fn new(endpoint: &str, credential: &str) -> Result<Self, TrackerError> {
        let mut auth = HeaderValue::from_str(&auth_value(credential)).map_err(|_| {
            TrackerError::Config("LINEAR_API_KEY has characters that are not allowed in an HTTP header".into())
        })?;
        auth.set_sensitive(true);
        Ok(Self { endpoint: endpoint.into(), auth })
    }

    /// The request post() sends (tests build it without sending).
    fn request(&self, body: &Value) -> reqwest::blocking::RequestBuilder {
        common::client()
            .post(&self.endpoint)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, self.auth.clone())
            .header(USER_AGENT, common::user_agent())
            .body(serde_json::to_vec(body).expect("JSON body"))
    }
}

impl Transport for HttpTransport {
    fn post(&mut self, body: &Value) -> Result<HttpReply, String> {
        let r = self.request(body).send().map_err(|e| err_chain(&e))?;
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

/// The issue an issueCreate conflict refers to. `id` takes the UUID (or an identifier such as "TRI-7").
const Q_ISSUE_BY_ID: &str = "query IssueById($id: String!) {
  issue(id: $id) { id identifier url }
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
      triagedAt
      history(first: $nested) { nodes { createdAt actor { name } botActor { name } fromState { type } toState { type name } } }
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
    /// create_issue() calls that found their issue already created (Tracker::recovered).
    recovered: usize,
}

impl LinearTracker {
    pub fn new(transport: Box<dyn Transport>, team_id: &str) -> Self {
        Self { transport, team_id: team_id.into(), triage_state: None, rate: RateLimit::default(), recovered: 0 }
    }

    /// LINEAR_API_KEY + LINEAR_TEAM_ID from the environment (used by the live test).
    #[cfg(test)]
    pub fn from_env() -> Result<Self, TrackerError> {
        Self::from_vars(&|k| std::env::var(k).ok())
    }

    /// LINEAR_API_KEY (personal API key or OAuth access token, see auth_value),
    /// LINEAR_TEAM_ID (both required) and LINEAR_API_URL (optional, default
    /// ENDPOINT; the compose lab sets it to the linear-mock service).
    pub fn from_vars(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, TrackerError> {
        let var = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let key = var("LINEAR_API_KEY").ok_or_else(|| TrackerError::Config("LINEAR_MODE=live needs LINEAR_API_KEY".into()))?;
        let team = var("LINEAR_TEAM_ID").ok_or_else(|| TrackerError::Config("LINEAR_MODE=live needs LINEAR_TEAM_ID".into()))?;
        let url = var("LINEAR_API_URL").unwrap_or_else(|| ENDPOINT.to_string());
        Ok(Self::new(Box::new(HttpTransport::new(&url, &key)?), &team))
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
                m.push_str(" (LINEAR_API_KEY missing, wrong, revoked or an expired OAuth token)");
            } else if codes.iter().any(|c| c == "FORBIDDEN") || r.status == 403 {
                m.push_str(" (the key's user or OAuth app cannot access LINEAR_TEAM_ID, or lacks a scope)");
            } else if codes.iter().any(|c| c == "INPUT_ERROR") && m.contains("Entity not found: Team") {
                // Real Linear (T13, 2026-11-05): a wrong LINEAR_TEAM_ID, and a key scoped to other
                // teams, both get this INPUT_ERROR (HTTP 200), not FORBIDDEN.
                m.push_str(" (wrong LINEAR_TEAM_ID, or the key or OAuth app is not scoped to that team)");
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

    /// The issue with this id, None when Linear does not return it (`issue: null`
    /// or "Entity not found: Issue"; the exact not-found answer is not verified).
    pub fn issue_by_id(&mut self, id: &str) -> Result<Option<IssueRef>, TrackerError> {
        match self.gql(Q_ISSUE_BY_ID, json!({"id": id}), "issue") {
            Ok(d) => match d.get("issue") {
                None | Some(Value::Null) => Ok(None),
                Some(v) => issue_ref(v, "issue").map(Some),
            },
            Err(TrackerError::GraphQl { message, .. }) if message.contains("Entity not found: Issue") => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// issueCreate refused because an issue with the input's id exists (real Linear,
/// 2026-11-05: HTTP 200, extensions.code INPUT_ERROR, "conflict on insert of Issue").
fn is_id_conflict(e: &TrackerError) -> bool {
    matches!(e, TrackerError::GraphQl { message, codes }
             if codes.iter().any(|c| c == "INPUT_ERROR") && message.contains("conflict on insert of Issue"))
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

/// Node with the latest `createdAt` among `nodes` that pass `keep`. Linear returns
/// nodes newest first, but this does not rely on it.
fn latest(nodes: Option<&Value>, keep: impl Fn(&Value) -> bool) -> Option<&Value> {
    nodes?.as_array()?.iter().filter(|n| keep(n)).max_by_key(|n| parse_iso(&s(n, "/createdAt")))
}

/// Name on a history entry: actor (people, and an OAuth app acting as itself), else botActor.
fn entry_actor(h: &Value) -> String {
    let a = s(h, "/actor/name");
    if a.is_empty() { s(h, "/botActor/name") } else { a }
}

/// A history entry that moved the issue out of Triage (Accept, Decline, status change).
fn left_triage(h: &Value) -> bool {
    s(h, "/fromState/type") == "triage"
}

/// (actor, changed) of the triage: who moved the issue out of Triage and when (UTC ISO).
///
/// `changed` is triagedAt. `actor` is the name on the history entry closest to
/// triagedAt, within TRIAGE_MATCH_MS, preferring an entry that left Triage: Mark as
/// duplicate writes an entry without states, so only its time ties it to the triage.
/// Without such an entry (it fell out of the NESTED_N window): the newest entry that
/// left Triage, else "". Without triagedAt (not set by older data): that entry's name
/// and time. ("", "") when neither is there.
fn triaged_by(n: &Value) -> (String, String) {
    let history = n.pointer("/history/nodes").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let at = |h: &Value| parse_iso(&s(h, "/createdAt"));
    let left = history.iter().filter(|h| left_triage(h)).max_by_key(|h| at(h));
    match parse_iso(&s(n, "/triagedAt")) {
        Some(t) => {
            let near = history
                .iter()
                .filter_map(|h| Some((h, (at(h)? - t).num_milliseconds().abs())))
                .filter(|(_, ms)| *ms <= TRIAGE_MATCH_MS)
                .min_by_key(|(h, ms)| (!left_triage(h), *ms))
                .map(|(h, _)| h);
            (near.or(left).map(entry_actor).unwrap_or_default(), iso_utc(t))
        }
        None => left.map(|h| (entry_actor(h), utc(&s(h, "/createdAt")))).unwrap_or_default(),
    }
}

/// One node of the IssueStates query -> (IssueRef, IssueStatus).
pub fn parse_issue_node(n: &Value) -> Result<(IssueRef, IssueStatus), TrackerError> {
    let r = issue_ref(n, "issues")?;
    let t = s(n, "/state/type");
    let state = IssueState::from_linear(&t)
        .ok_or_else(|| TrackerError::Reply(format!("issues: {} has unknown state type {t:?}", r.identifier)))?;
    // In Triage (also snoozed): not triaged, whatever an earlier triage left behind.
    let (actor, changed) = if state == IssueState::Triage { Default::default() } else { triaged_by(n) };
    let reason = if state == IssueState::Declined {
        let comment = latest(n.pointer("/comments/nodes"), |c| !s(c, "/body").trim_start().starts_with(BOT_PREFIX))
            .map(|c| s(c, "/body").trim().to_string())
            .unwrap_or_default();
        if comment.is_empty() && t == "duplicate" { DUPLICATE_REASON.to_string() } else { comment }
    } else {
        String::new()
    };
    Ok((r, IssueStatus {
        state,
        state_name: s(n, "/state/name"),
        assignee: s(n, "/assignee/name"),
        due: s(n, "/dueDate"),
        reason,
        actor,
        changed,
    }))
}

impl Tracker for LinearTracker {
    /// issueCreate with `id` as IssueCreateInput.id. On an id conflict the
    /// existing issue is returned; IdTaken when Linear does not return it (module doc).
    fn create_issue(&mut self, item: &Item, m: &Match, id: &str) -> Result<IssueRef, TrackerError> {
        let state = self.triage_state_id()?;
        let input = json!({"id": id, "teamId": self.team_id, "title": issue_title(item),
                           "description": issue_description(item, m), "stateId": state});
        let d = match self.gql(M_ISSUE_CREATE, json!({"input": input}), "issueCreate") {
            Ok(d) => d,
            Err(e) if is_id_conflict(&e) => {
                // Created by an earlier attempt whose answer was lost.
                let r = self.issue_by_id(id)?.ok_or_else(|| TrackerError::IdTaken(id.into()))?;
                self.recovered += 1;
                return Ok(r);
            }
            Err(e) => return Err(e),
        };
        if d.pointer("/issueCreate/success") != Some(&Value::Bool(true)) {
            return Err(TrackerError::Reply(format!("issueCreate: success is not true: {}", head(&d.to_string(), 200))));
        }
        issue_ref(d.pointer("/issueCreate/issue").unwrap_or(&Value::Null), "issueCreate")
    }

    fn recovered(&self) -> usize {
        self.recovered
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

    /// The issue id the tests send; the conflict and lookup fixtures name it too.
    const ID: &str = "3d4f6a2e-8b1c-4e7a-9f20-5c6b7a8d9e01";

    /// Linear's IsUUID("4") check, as observed on 2026-11-05 (v5 refused).
    fn is_uuid_v4(s: &str) -> bool {
        let b = s.as_bytes();
        s.len() == 36
            && s.char_indices().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() })
            && b[14] == b'4'
            && matches!(b[19], b'8' | b'9' | b'a' | b'b')
    }

    // ------------------------------------------------ issue ids

    #[test]
    fn issue_ids_are_random_uuid_v4() {
        assert_eq!(uuid_v4([0; 16]), "00000000-0000-4000-8000-000000000000");
        assert_eq!(uuid_v4([0xff; 16]), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert!(is_uuid_v4(ID));
        assert!(!is_uuid_v4("e8caf09b-8627-59c1-8257-e4112feff854"), "the v5 id Linear refused");
        let ids: std::collections::BTreeSet<String> = (0..1000).map(|_| new_issue_id()).collect();
        assert_eq!(ids.len(), 1000, "no repeats");
        assert!(ids.iter().all(|i| is_uuid_v4(i)), "{ids:?}");
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
        let a = f.create_issue(&item(), &m(), ID).unwrap();
        let mut other = item();
        other.id = "CVE-2026-9".into();
        let b = f.create_issue(&other, &m(), ID).unwrap();
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
        let e = f.create_issue(&item(), &m(), ID).unwrap_err();
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
        assert_eq!(pick(&[("LINEAR_MODE", " Fake ")]).err().unwrap(),
                   TrackerError::Config("LINEAR_MODE=fake: expected off or live".into()), "fake mode is gone");
        assert_eq!(pick(&[("LINEAR_MODE", "live"), ("LINEAR_API_KEY", " ")]).err().unwrap(),
                   TrackerError::Config("LINEAR_MODE=live needs LINEAR_API_KEY".into()));
        assert_eq!(pick(&[("LINEAR_MODE", "live"), ("LINEAR_API_KEY", "lin_api_x")]).err().unwrap(),
                   TrackerError::Config("LINEAR_MODE=live needs LINEAR_TEAM_ID".into()));
        assert!(pick(&[("LINEAR_MODE", "live"), ("LINEAR_API_KEY", "lin_api_x"), ("LINEAR_TEAM_ID", "t")]).unwrap().is_some());
        assert!(matches!(pick(&[("LINEAR_MODE", "jira")]).err().unwrap(), TrackerError::Config(m) if m.contains("LINEAR_MODE=jira")));
    }

    #[test]
    fn live_endpoint_from_linear_api_url() {
        let endpoint = |url: Option<&str>| {
            let l = LinearTracker::from_vars(&|k| match k {
                "LINEAR_API_KEY" => Some("lin_api_x".into()),
                "LINEAR_TEAM_ID" => Some("t".into()),
                "LINEAR_API_URL" => url.map(String::from),
                _ => None,
            })
            .unwrap();
            let any: &dyn std::any::Any = &*l.transport;
            any.downcast_ref::<HttpTransport>().expect("HttpTransport").endpoint.clone()
        };
        assert_eq!(endpoint(None), ENDPOINT);
        assert_eq!(endpoint(Some("  ")), ENDPOINT);
        assert_eq!(endpoint(Some(" http://linear-mock:8080/graphql ")), "http://linear-mock:8080/graphql");
    }

    #[test]
    fn auth_header_from_credential_prefix() {
        assert_eq!(auth_value("lin_api_abc123"), "lin_api_abc123", "personal API key: bare");
        assert_eq!(auth_value("lin_oauth_abc123"), "Bearer lin_oauth_abc123", "OAuth access token: Bearer");
        assert_eq!(auth_value("abc123"), "Bearer abc123", "unknown prefix: treated as an OAuth token");
        assert_eq!(auth_value("LIN_API_abc"), "Bearer LIN_API_abc", "the prefix is case-sensitive");
    }

    /// The header the real transport would send, built from the environment as the job does.
    #[test]
    fn auth_header_sent_by_http_transport() {
        let header = |key: &str| {
            let l = LinearTracker::from_vars(&|k| match k {
                "LINEAR_API_KEY" => Some(key.into()),
                "LINEAR_TEAM_ID" => Some("t".into()),
                "LINEAR_API_URL" => Some("http://linear-mock:8080/graphql".into()),
                _ => None,
            })
            .unwrap();
            let any: &dyn std::any::Any = &*l.transport;
            let t = any.downcast_ref::<HttpTransport>().expect("HttpTransport");
            let req = t.request(&json!({"query": "q"})).build().unwrap();
            let v = req.headers().get(AUTHORIZATION).expect("Authorization header").clone();
            assert!(v.is_sensitive(), "the credential must be marked sensitive");
            assert_eq!(format!("{v:?}"), "Sensitive", "Debug output must not show the credential");
            v.to_str().unwrap().to_string()
        };
        assert_eq!(header(" lin_api_mock "), "lin_api_mock");
        assert_eq!(header("lin_oauth_mock"), "Bearer lin_oauth_mock");
    }

    #[test]
    fn credential_that_cannot_be_a_header_is_a_config_error_without_the_value() {
        let e = LinearTracker::from_vars(&|k| match k {
            "LINEAR_API_KEY" => Some("lin_oauth_se\u{7}cret".into()),
            "LINEAR_TEAM_ID" => Some("t".into()),
            _ => None,
        })
        .err()
        .unwrap();
        assert!(matches!(&e, TrackerError::Config(m) if m.contains("LINEAR_API_KEY")), "{e:?}");
        assert!(!e.to_string().contains("lin_oauth") && !e.to_string().contains("cret"), "{e}");
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
        let r = l.create_issue(&item(), &m(), ID).unwrap();
        assert_eq!(r, IssueRef {
            id: "a1b2c3d4-0000-4000-8000-000000000123".into(), identifier: "CTP-123".into(),
            url: "https://linear.app/ediphy/issue/CTP-123/cve-2026-1234-tokio-runtime-use-after-free".into(),
        });
        assert_eq!(l.rate.note(), "requests 2498/2500 (reset 2026-11-03T08:00:00Z)");
        l.create_issue(&item(), &m(), ID).unwrap(); // triage state id is cached: no second lookup
        l.comment(&r, "**exploit-watch**: x").unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 4);
        assert!(seen[0]["query"].as_str().unwrap().contains("type: { eq: \"triage\" }"));
        assert_eq!(seen[0]["variables"], json!({"team": "team-uuid"}));
        let input = &seen[1]["variables"]["input"];
        assert_eq!(input["id"], ID, "the job's own issue id");
        assert_eq!(input["teamId"], "team-uuid");
        assert_eq!(input["stateId"], "6f1e2d3c-0000-4000-8000-00000000000a");
        assert_eq!(input["title"], "[CVE-2026-1234] Tokio | runtime use-after-free");
        assert!(input["description"].as_str().unwrap().contains("Item key: `CISA KEV:CVE-2026-1234`"));
        assert!(seen[2]["query"].as_str().unwrap().starts_with("mutation IssueCreate"));
        assert_eq!(seen[3]["variables"]["input"], json!({"issueId": r.id, "body": "**exploit-watch**: x"}));
    }

    /// The answer to an earlier create was lost: Linear refuses the same id
    /// (T15 body), and the issue is read back by id instead.
    #[test]
    fn linear_create_conflict_is_recovered_by_lookup() {
        let (mut l, seen) = linear(vec![
            reply(200, &fixture("linear_workflow_states.json"), &[]),
            reply(200, &fixture("linear_error_issue_conflict.json"), &[]),
            reply(200, &fixture("linear_issue_by_id.json"), &[]),
        ]);
        assert_eq!(l.recovered(), 0);
        let r = l.create_issue(&item(), &m(), ID).unwrap();
        assert_eq!(r, IssueRef {
            id: ID.into(), identifier: "CTP-120".into(),
            url: "https://linear.app/ediphy/issue/CTP-120/cve-2026-1234-tokio-runtime-use-after-free".into(),
        });
        assert_eq!(l.recovered(), 1);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[1]["variables"]["input"]["id"], ID);
        assert!(seen[2]["query"].as_str().unwrap().starts_with("query IssueById"));
        assert!(seen[2]["query"].as_str().unwrap().contains("issue(id: $id)"));
        assert_eq!(seen[2]["variables"], json!({"id": ID}));
    }

    /// The id is taken but its issue is gone: IdTaken, so sync can retry with a new id.
    #[test]
    fn linear_create_conflict_without_issue_is_id_taken() {
        let not_found = r#"{"errors":[{"message":"Entity not found: Issue","path":["issue"],
                            "extensions":{"type":"invalid input","code":"INPUT_ERROR","statusCode":400}}],"data":null}"#;
        let (mut l, _) = linear(vec![
            reply(200, &fixture("linear_error_issue_conflict.json"), &[]),
            reply(200, r#"{"data":{"issue":null}}"#, &[]),
            reply(200, &fixture("linear_error_issue_conflict.json"), &[]),
            reply(200, not_found, &[]),
            reply(200, &fixture("linear_error_issue_conflict.json"), &[]),
            Err("operation timed out".into()),
        ]);
        l.triage_state = Some("s".into());
        assert_eq!(l.create_issue(&item(), &m(), ID).unwrap_err(), TrackerError::IdTaken(ID.into()));
        let e = l.create_issue(&item(), &m(), ID).unwrap_err();
        assert_eq!(e, TrackerError::IdTaken(ID.into()));
        assert_eq!(e.to_string(), format!("Linear: issue id {ID} is taken by an issue Linear does not return (deleted?)"));
        // The lookup itself fails: that error, not IdTaken (the next run tries again).
        assert_eq!(l.create_issue(&item(), &m(), ID).unwrap_err(),
                   TrackerError::Network("issue: operation timed out".into()));
        assert_eq!(l.recovered(), 0);
    }

    /// Only "conflict on insert of Issue" is recovered; every other INPUT_ERROR or
    /// INVALID_INPUT stays an error, with no lookup.
    #[test]
    fn linear_other_input_errors_stay_errors() {
        let other = r#"{"errors":[{"message":"conflict on insert of Comment",
                        "extensions":{"code":"INPUT_ERROR"}}],"data":null}"#;
        let (mut l, seen) = linear(vec![
            reply(200, &fixture("linear_error_team_not_found.json"), &[]),
            reply(200, &fixture("linear_error_id_not_uuid.json"), &[]),
            reply(200, other, &[]),
        ]);
        l.triage_state = Some("s".into());
        // T13 (2026-11-05): wrong LINEAR_TEAM_ID or a key scoped to other teams.
        let e = l.create_issue(&item(), &m(), ID).unwrap_err();
        assert!(matches!(&e, TrackerError::GraphQl { codes, .. } if codes == &["INPUT_ERROR"]), "{e:?}");
        assert_eq!(e.to_string(), "Linear: GraphQL errors: issueCreate: Entity not found: Team \
                                   (wrong LINEAR_TEAM_ID, or the key or OAuth app is not scoped to that team)");
        // 2026-11-05: Linear accepts only UUID v4 as IssueCreateInput.id.
        let e = l.create_issue(&item(), &m(), "e8caf09b-8627-59c1-8257-e4112feff854").unwrap_err();
        assert!(matches!(&e, TrackerError::GraphQl { codes, .. } if codes == &["INVALID_INPUT"]), "{e:?}");
        assert_eq!(e.to_string(), "Linear: GraphQL errors: issueCreate: Argument Validation Error");
        let e = l.create_issue(&item(), &m(), ID).unwrap_err();
        assert!(matches!(&e, TrackerError::GraphQl { message, .. } if message.contains("Comment")), "{e:?}");
        assert_eq!(seen.lock().unwrap().len(), 3, "no issue lookup after these errors");
        assert_eq!(l.recovered(), 0);
    }

    #[test]
    fn linear_fetch_states_parsing() {
        let (mut l, seen) = linear(vec![reply(200, &fixture("linear_issues_states.json"), &[])]);
        let refs: Vec<IssueRef> = ["CTP-123", "CTP-124", "CTP-125", "CTP-126"]
            .iter()
            .map(|i| IssueRef { id: format!("id-{i}"), identifier: i.to_string(), url: String::new() })
            .collect();
        let st = l.fetch_states(&refs).unwrap();
        let req = &seen.lock().unwrap()[0];
        let v = &req["variables"];
        assert_eq!(v["ids"], json!(["id-CTP-123", "id-CTP-124", "id-CTP-125", "id-CTP-126"]));
        assert_eq!(v["first"], 4);
        assert_eq!(v["nested"], NESTED_N);
        let q = req["query"].as_str().unwrap();
        assert!(q.contains("triagedAt") && q.contains("fromState { type }"), "{q}");

        assert_eq!(st.len(), 4);
        let by = |i: &str| st.iter().find(|(r, _)| r.identifier == i).unwrap().1.clone();
        assert_eq!(by("CTP-123"), IssueStatus {
            state: IssueState::Triage, state_name: "Triage".into(), assignee: String::new(), due: String::new(),
            reason: String::new(), actor: String::new(), changed: String::new(),
        });
        // Triaged by Vu Huy Hoang (triage -> Todo), later moved on by someone else: the triage counts.
        assert_eq!(by("CTP-124"), IssueStatus {
            state: IssueState::Accepted, state_name: "In Progress".into(), assignee: "Tran Trung Hau".into(),
            due: "2026-11-10".into(), reason: String::new(), actor: "Vu Huy Hoang".into(),
            changed: "2026-11-03T09:00:00Z".into(),
        });
        let declined = by("CTP-125");
        assert_eq!(declined.state, IssueState::Declined);
        assert_eq!(declined.reason, "Not relevant: we only use tokio in the test harness.");
        assert_eq!((declined.actor.as_str(), declined.changed.as_str()), ("Tran Trung Hau", "2026-11-03T10:00:00Z"));
        let dup = by("CTP-126");
        assert_eq!(IssueState::from_linear("duplicate"), Some(IssueState::Declined));
        assert_eq!((dup.state, dup.actor.as_str()), (IssueState::Declined, "Triage Intelligence"), "botActor name");
        assert_eq!(dup.reason, DUPLICATE_REASON, "the job's own comments are never a reason");
        assert_eq!(st[0].0.url, "https://linear.app/ediphy/issue/CTP-123/x");
    }

    /// Replies shaped like the real Linear workspace on 2026-11-04 (results T06-T11): nested
    /// nodes newest first, Mark as duplicate with a state-less history entry, a decline
    /// comment 10 s after the state change, a snoozed issue, and TRI-7 accepted by a person
    /// and then moved on by the OAuth app.
    #[test]
    fn linear_triage_read_back_like_real_linear() {
        let (mut l, _) = linear(vec![reply(200, &fixture("linear_issues_states_triage.json"), &[])]);
        let refs: Vec<IssueRef> = ["TRI-1", "TRI-15", "TRI-3", "TRI-4", "TRI-6", "TRI-7", "TRI-17"]
            .iter()
            .map(|i| IssueRef { id: format!("id-{i}"), identifier: i.to_string(), url: String::new() })
            .collect();
        let st = l.fetch_states(&refs).unwrap();
        assert_eq!(st.len(), 7);
        let by = |i: &str| st.iter().find(|(r, _)| r.identifier == i).unwrap().1.clone();
        let henry = "Tran Trung Hau";
        let who = |i: &str| {
            let s = by(i);
            (s.state, s.actor, s.changed, s.reason)
        };
        let t = |state, actor: &str, changed: &str, reason: &str| (state, actor.to_string(), changed.to_string(), reason.to_string());

        // T06: Accept; status menu straight to In Progress.
        assert_eq!(who("TRI-1"), t(IssueState::Accepted, henry, "2026-11-04T10:34:02Z", ""));
        assert_eq!((by("TRI-1").assignee.as_str(), by("TRI-1").due.as_str()), (henry, "2026-11-06"));
        assert_eq!(who("TRI-17"), t(IssueState::Accepted, henry, "2026-11-04T10:27:06Z", ""));
        // T07: Decline with the reason as a later comment; Decline without a comment.
        assert_eq!(who("TRI-15"), t(IssueState::Declined, henry, "2026-11-04T10:33:41Z",
                                    "Not relevant: fairCT does not ship this component."));
        assert_eq!(who("TRI-3"), t(IssueState::Declined, henry, "2026-11-04T10:33:58Z", ""));
        // T08: Mark as duplicate. The entry has no states; triagedAt ties it to the person.
        assert_eq!(who("TRI-4"), t(IssueState::Declined, henry, "2026-11-04T10:34:47Z", DUPLICATE_REASON));
        assert_eq!(by("TRI-4").state_name, "Duplicate");
        // T09: Snooze leaves the issue untriaged.
        assert_eq!(who("TRI-6"), t(IssueState::Triage, "", "", ""));
        // T11: accepted by Henry, then moved by the OAuth app: Henry triaged it.
        assert_eq!(who("TRI-7"), t(IssueState::Accepted, henry, "2026-11-04T10:35:20Z", ""));
    }

    /// The triage actor rule on the real T10 body (TRI-18: 20 newest of 26 history entries,
    /// newest first, all priority/label changes) and on small hand-made nodes.
    #[test]
    fn triage_actor_rule() {
        let real: Value = serde_json::from_str(&fixture("linear_issue_detail_t10.json")).unwrap();
        let real = real.pointer("/data/issue").unwrap().clone();
        let first = |n: &Value| n["history"]["nodes"][0]["createdAt"].as_str().unwrap().to_string();
        let last = |n: &Value| n["history"]["nodes"][19]["createdAt"].as_str().unwrap().to_string();
        assert!(first(&real) > last(&real), "Linear returns history newest first");
        let read = |n: &Value| {
            let (_, st) = parse_issue_node(n).unwrap();
            (st.actor, st.changed)
        };
        let pair = |a: &str, c: &str| (a.to_string(), c.to_string());

        // Still in Triage: nothing, although history has 20 entries.
        assert_eq!(read(&real), pair("", ""));
        let mut n = real.clone();
        n["state"] = json!({"type": "backlog", "name": "Backlog"});
        // Triaged before the window: when is known, who is not.
        n["triagedAt"] = json!("2026-11-04T10:30:00.000Z");
        assert_eq!(read(&n), pair("", "2026-11-04T10:30:00Z"));
        // The closest entry wins, although its neighbours (3.3 s away) are within the tolerance too.
        n["history"]["nodes"][9]["actor"] = json!({"name": "Vu Huy Hoang"});
        n["triagedAt"] = json!("2026-11-05T02:14:30.278Z");
        assert_eq!(n["history"]["nodes"][9]["createdAt"], "2026-11-05T02:14:30.248Z");
        assert_eq!(read(&n), pair("Vu Huy Hoang", "2026-11-05T02:14:30Z"));
        // No triagedAt and no entry that left Triage: unknown.
        n["triagedAt"] = Value::Null;
        assert_eq!(read(&n), pair("", ""));

        let node = |triaged: Value, history: Value| {
            json!({"id": "x", "identifier": "CTP-9", "url": "u", "state": {"type": "started", "name": "In Progress"},
                   "triagedAt": triaged, "history": {"nodes": history}, "comments": {"nodes": []}})
        };
        let entry = |at: &str, who: &str, from: Option<&str>| {
            json!({"createdAt": at, "actor": {"name": who}, "botActor": null,
                   "fromState": from.map(|f| json!({"type": f})), "toState": from.map(|_| json!({"type": "started", "name": "x"}))})
        };
        // Within the tolerance an entry that left Triage beats a closer one that did not.
        let n = node(json!("2026-11-04T10:00:00.000Z"), json!([
            entry("2026-11-04T10:00:00.010Z", "Exploit Watch", None),
            entry("2026-11-04T10:00:02.000Z", "Henry", Some("triage")),
        ]));
        assert_eq!(read(&n), pair("Henry", "2026-11-04T10:00:00Z"));
        // Nothing near triagedAt: the newest entry that left Triage.
        let n = node(json!("2026-11-04T09:00:00Z"), json!([
            entry("2026-11-04T11:00:00Z", "Exploit Watch", Some("backlog")),
            entry("2026-11-04T10:00:00Z", "James", Some("triage")),
            entry("2026-11-04T08:00:00Z", "Henry", Some("triage")),
        ]));
        assert_eq!(read(&n), pair("James", "2026-11-04T09:00:00Z"));
        // No triagedAt (older data): that entry's name and time.
        let n = node(Value::Null, json!([
            entry("2026-11-04T11:00:00Z", "Exploit Watch", Some("backlog")),
            entry("2026-11-04T10:00:00Z", "James", Some("triage")),
        ]));
        assert_eq!(read(&n), pair("James", "2026-11-04T10:00:00Z"));
        // Fields missing altogether (no history, no triagedAt): unknown, not an error.
        let bare = json!({"id": "x", "identifier": "CTP-9", "url": "u", "state": {"type": "duplicate", "name": "Duplicate"}});
        let (_, st) = parse_issue_node(&bare).unwrap();
        assert_eq!((st.actor.as_str(), st.changed.as_str(), st.reason.as_str()), ("", "", DUPLICATE_REASON));
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
        assert!(e.to_string().ends_with("(LINEAR_API_KEY missing, wrong, revoked or an expired OAuth token)"), "{e}");
        assert_eq!(q(&mut l).to_string(), "Linear: GraphQL errors: viewer: Entity not found: Issue");
        assert_eq!(q(&mut l), TrackerError::Http { status: 502, body: "viewer: <html>Bad Gateway</html>".into() });
        assert_eq!(q(&mut l), TrackerError::Reply("viewer: non-JSON body: not json".into()));

        l.triage_state = Some("s".into());
        assert!(matches!(l.create_issue(&item(), &m(), ID).unwrap_err(), TrackerError::Reply(m) if m.starts_with("issueCreate: success")));
        l.triage_state = None;
        let e = l.create_issue(&item(), &m(), ID).unwrap_err();
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
        let r = l.create_issue(&it, &m(), &new_issue_id()).unwrap();
        eprintln!("created {} {}", r.identifier, r.url);
        l.comment(&r, &update_comment(&it)).unwrap();
        let st = l.fetch_states(std::slice::from_ref(&r)).unwrap();
        eprintln!("state: {:?}\nrate: {}", st, l.rate.note());
        assert_eq!(st[0].1.state, IssueState::Triage);
    }
}
