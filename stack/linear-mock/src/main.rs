//! linear-mock: a local stand-in for the Linear GraphQL API, for the Docker
//! Compose lab only. It answers the four GraphQL documents that the
//! exploit-watch job's live Linear client sends (triage/tracker.rs,
//! `LinearTracker`), so that client can be exercised end to end over real HTTP
//! without a Linear workspace. It is not a Linear emulator: it does not parse
//! GraphQL, it recognises each document by the operation name at its start.
//!
//! HTTP
//!
//!   GET  /health    200 "ok" (no auth)
//!   POST /graphql   JSON {"query": "...", "variables": {...}}
//!   anything else   404
//!
//! Auth: the `Authorization` header must equal MOCK_API_KEY exactly (the bare
//! key, as Linear expects for personal API keys; "Bearer <key>" is rejected).
//! Otherwise HTTP 401 with Linear's error body (extensions.code
//! AUTHENTICATION_ERROR).
//!
//! Operations (dispatch on the trimmed start of `query`):
//!
//!   query TriageState      variables.team == MOCK_TEAM_ID -> one workflow state
//!                          {id "state-triage", name "Triage", type "triage"};
//!                          any other team -> no nodes
//!   mutation IssueCreate   input {teamId, title, description, stateId}; appends
//!                          issue mock-<n> / MOCK-<n> in state triage
//!   mutation CommentCreate input {issueId, body}; appends a comment written by
//!                          the job to that issue
//!   query IssueStates      variables.ids -> the issues that exist, in file
//!                          order (unknown ids are left out, as Linear does)
//!
//! Errors are GraphQL errors (HTTP 200, `data: null`, one entry in `errors`
//! with extensions.code), except auth (401) and a body that is not JSON (400):
//!
//!   GRAPHQL_VALIDATION_FAILED  unknown operation, or variables missing or of the
//!                              wrong type
//!   INVALID_INPUT              IssueCreate with a teamId other than MOCK_TEAM_ID,
//!                              a stateId other than "state-triage", or an empty
//!                              title; CommentCreate on an id not in the file
//!   MOCK_DATA_INVALID          issues.json cannot be read or does not parse
//!                              (mock-specific code, not a Linear one)
//!   MOCK_IO_ERROR              issues.json cannot be written (mock-specific)
//!
//! Data file: $MOCK_DATA_DIR/issues.json, pretty JSON, read on every request so
//! hand edits take effect on the next call. A missing or empty file means no
//! issues. Writes go to issues.json.tmp, then rename, so mount the directory,
//! not the single file (a rename onto a single-file bind mount fails). A file
//! that does not parse is never overwritten: every operation that needs it
//! answers MOCK_DATA_INVALID until it is fixed by hand.
//!
//!   {
//!    "next": 3,                                       next MOCK-n number
//!    "issues": [
//!     {
//!      "id": "mock-20261104080000-1",                  creation time digits + number
//!      "identifier": "MOCK-1",
//!      "url": "http://linear-mock.invalid/issue/MOCK-1",
//!      "title": "[CVE-2026-1234] ...",
//!      "description": "...",
//!      "created": "2026-11-04T08:00:00Z",
//!      "state": "triage",      edit: triage | accepted | done | declined
//!                                    (completed, canceled, cancelled also read)
//!      "assignee": "",         edit: owner name, "" = unassigned
//!      "due": "",              edit: YYYY-MM-DD, "" = none
//!      "reason": "",           edit: why it was declined
//!      "actor": "",            edit: who moved it to its state ("" = "mock user")
//!      "changed": "",          edit: when (UTC ISO), "" = use `created`
//!      "comments": [{"at": "2026-11-04T09:00:00Z", "body": "..."}]   job-only
//!     }
//!    ]
//!   }
//!
//! The editable fields match the job's test double FakeTracker. Other fields a
//! person adds to an issue are kept when the mock rewrites the file. `comments`
//! holds the job's comments only (shown as written by "exploit-watch bot"); a
//! decline reason goes in `reason`, not in `comments`. A leading UTF-8 BOM is
//! ignored. Reset the mock together with the job's state/triage.json.
//!
//! How IssueStates maps an issue to Linear's shape:
//!
//!   state     triage -> triage "Triage", accepted -> unstarted "Todo",
//!             done -> completed "Done", declined -> canceled "Canceled"
//!   assignee  "" -> null, else {name}; due "" -> dueDate null
//!   history   state triage: no nodes; otherwise one node {createdAt: changed
//!             or created, actor {name: actor or "mock user"}, botActor null,
//!             toState {type, name}}
//!   comments  the job's comments with user "exploit-watch bot", plus, when
//!             `reason` is set, a comment {body: reason, createdAt: changed or
//!             created, user {name: actor or "mock user"}}
//!
//! Timestamps are passed through as written in the file.
//!
//! Environment:
//!
//!   MOCK_API_KEY   required; the value clients must send in Authorization
//!   MOCK_TEAM_ID   required; the only team id that exists
//!   MOCK_DATA_DIR  default /data
//!   PORT           default 8080; the server listens on 0.0.0.0
//!
//! `linear-mock healthcheck` GETs http://127.0.0.1:$PORT/health and exits 0 when
//! it answers 200, 1 otherwise (the runtime image has no curl or wget).
//!
//! Logging: one line per request on stdout (time, method, path, operation,
//! result, HTTP status). The API key is never logged.
//!
//! Not simulated: rate limits (HTTP 429 / RATELIMITED, X-RateLimit-* headers),
//! pagination (`first` and nested `first` are ignored, all matches are
//! returned), archived issues, any other query or mutation, other workflow
//! states or teams, comment authors other than the two above, OAuth tokens.
//! Requests are served one at a time.

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

const DATA_FILE: &str = "issues.json";
const TRIAGE_STATE_ID: &str = "state-triage";
const BOT_USER: &str = "exploit-watch bot";
const DEFAULT_ACTOR: &str = "mock user";
const URL_BASE: &str = "http://linear-mock.invalid/issue/";
/// Larger request bodies get 413.
const MAX_BODY: u64 = 1 << 20;

// ---------------------------------------------------------------- config

#[derive(Debug, Clone)]
pub struct Config {
    pub api_key: String,
    pub team_id: String,
    pub data_dir: PathBuf,
}

impl Config {
    fn from_vars(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let required = |k: &str| get(k).filter(|v| !v.is_empty()).ok_or_else(|| format!("{k} is required"));
        Ok(Self {
            api_key: required("MOCK_API_KEY")?,
            team_id: required("MOCK_TEAM_ID")?,
            data_dir: get("MOCK_DATA_DIR").filter(|v| !v.is_empty()).unwrap_or_else(|| "/data".into()).into(),
        })
    }
}

fn port_from(get: &dyn Fn(&str) -> Option<String>) -> Result<u16, String> {
    match get("PORT").filter(|v| !v.is_empty()) {
        None => Ok(8080),
        Some(p) => p.parse().map_err(|_| format!("PORT={p:?} is not a port number")),
    }
}

// ---------------------------------------------------------------- data file

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MockFile {
    #[serde(default = "one")]
    next: u64,
    #[serde(default)]
    issues: Vec<Issue>,
}

fn one() -> u64 {
    1
}

impl Default for MockFile {
    fn default() -> Self {
        Self { next: 1, issues: vec![] }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Issue {
    id: String,
    identifier: String,
    url: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    created: String,
    #[serde(default)]
    state: MockState,
    #[serde(default)]
    assignee: String,
    #[serde(default)]
    due: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    actor: String,
    #[serde(default)]
    changed: String,
    #[serde(default)]
    comments: Vec<Comment>,
    /// Fields a person added by hand; written back unchanged.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Comment {
    #[serde(default)]
    at: String,
    #[serde(default)]
    body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MockState {
    #[default]
    Triage,
    Accepted,
    #[serde(alias = "completed")]
    Done,
    #[serde(alias = "canceled", alias = "cancelled")]
    Declined,
}

impl MockState {
    /// Linear WorkflowState (type, name).
    fn linear(self) -> (&'static str, &'static str) {
        match self {
            Self::Triage => ("triage", "Triage"),
            Self::Accepted => ("unstarted", "Todo"),
            Self::Done => ("completed", "Done"),
            Self::Declined => ("canceled", "Canceled"),
        }
    }
}

/// The file, or an empty one when it is missing or blank. Err when it cannot be read or parsed.
fn load(dir: &Path) -> Result<MockFile, GqlError> {
    let path = dir.join(DATA_FILE);
    let raw = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(MockFile::default()),
        Err(e) => return Err(GqlError::new("MOCK_DATA_INVALID", format!("cannot read {}: {e}", path.display()))),
    };
    // Some Windows editors (PowerShell 5.1 `Set-Content -Encoding utf8`) prepend a UTF-8 BOM.
    let raw = raw.strip_prefix(b"\xEF\xBB\xBF".as_slice()).unwrap_or(&raw);
    if raw.iter().all(u8::is_ascii_whitespace) {
        return Ok(MockFile::default());
    }
    serde_json::from_slice(raw).map_err(|e| {
        GqlError::new("MOCK_DATA_INVALID",
                      format!("{} is not valid ({e}); fix it by hand, linear-mock will not overwrite it", path.display()))
    })
}

/// Atomic write: issues.json.tmp, then rename onto issues.json.
fn save(dir: &Path, f: &MockFile) -> Result<(), GqlError> {
    let path = dir.join(DATA_FILE);
    let tmp = dir.join(format!("{DATA_FILE}.tmp"));
    let mut text = serde_json::to_string_pretty(f).expect("issues serialise to JSON");
    text.push('\n');
    let write = || -> io::Result<()> {
        fs::create_dir_all(dir)?;
        let mut fh = fs::File::create(&tmp)?;
        fh.write_all(text.as_bytes())?;
        fh.sync_all()?;
        fs::rename(&tmp, &path)
    };
    write().map_err(|e| GqlError::new("MOCK_IO_ERROR", format!("cannot write {}: {e}", path.display())))
}

// ---------------------------------------------------------------- request handling

/// What handle() answers. `log` describes the outcome for stdout and never holds the key.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub json: bool,
    pub log: String,
}

impl Reply {
    fn text(status: u16, body: &str, log: impl Into<String>) -> Self {
        Self { status, body: body.into(), json: false, log: log.into() }
    }
}

#[derive(Debug)]
struct GqlError {
    code: &'static str,
    message: String,
}

impl GqlError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

fn error_body(code: &str, message: &str) -> String {
    json!({"errors": [{"message": message, "extensions": {"code": code}}], "data": null}).to_string()
}

/// Linear's answer to a missing or wrong key (tests/fixtures/linear_error_auth.json in the job repo).
fn auth_error_body() -> String {
    json!({
        "errors": [{
            "message": "Authentication required, not authenticated",
            "extensions": {
                "type": "authentication error",
                "code": "AUTHENTICATION_ERROR",
                "statusCode": 401,
                "userError": true,
                "userPresentableMessage": "You need to authenticate to access this operation."
            }
        }],
        "data": null
    })
    .to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    TriageState,
    IssueCreate,
    CommentCreate,
    IssueStates,
}

impl Op {
    const ALL: [(Op, &'static str); 4] = [
        (Op::TriageState, "query TriageState"),
        (Op::IssueCreate, "mutation IssueCreate"),
        (Op::CommentCreate, "mutation CommentCreate"),
        (Op::IssueStates, "query IssueStates"),
    ];

    /// The operation named at the start of `query`; the name must end there ("query TriageStateX" is unknown).
    fn detect(query: &str) -> Option<Op> {
        let q = query.trim_start();
        Self::ALL
            .iter()
            .find(|(_, prefix)| {
                q.strip_prefix(prefix).is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
            })
            .map(|(op, _)| *op)
    }

    fn name(self) -> &'static str {
        match self {
            Op::TriageState => "TriageState",
            Op::IssueCreate => "IssueCreate",
            Op::CommentCreate => "CommentCreate",
            Op::IssueStates => "IssueStates",
        }
    }
}

/// One HTTP request -> reply. `url` may carry a query string; `now` is the UTC ISO time stamped on new records.
pub fn handle(method: &str, url: &str, auth: Option<&str>, body: &[u8], cfg: &Config, now: &str) -> Reply {
    let path = url.split('?').next().unwrap_or("");
    match (method, path) {
        ("GET", "/health") => Reply::text(200, "ok", "health"),
        ("POST", "/graphql") => graphql(auth, body, cfg, now),
        _ => Reply::text(404, "not found", "not found"),
    }
}

fn graphql(auth: Option<&str>, body: &[u8], cfg: &Config, now: &str) -> Reply {
    if auth != Some(cfg.api_key.as_str()) {
        let why = if auth.is_some() { "wrong Authorization" } else { "no Authorization" };
        return Reply { status: 401, body: auth_error_body(), json: true, log: format!("rejected: {why}") };
    }
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return Reply {
                status: 400,
                body: error_body("BAD_REQUEST", &format!("request body is not JSON: {e}")),
                json: true,
                log: "body is not JSON".into(),
            };
        }
    };
    let query = req.get("query").and_then(Value::as_str).unwrap_or("");
    let null = Value::Null;
    let vars = req.get("variables").unwrap_or(&null);
    let Some(op) = Op::detect(query) else {
        let head: String = query.trim().lines().next().unwrap_or("").chars().take(60).collect();
        let message = format!("linear-mock only answers TriageState, IssueCreate, CommentCreate and IssueStates; got {head:?}");
        return Reply {
            status: 200,
            body: error_body("GRAPHQL_VALIDATION_FAILED", &message),
            json: true,
            log: format!("unknown operation {head:?}"),
        };
    };
    let result = match op {
        Op::TriageState => triage_state(vars, cfg),
        Op::IssueCreate => issue_create(vars, cfg, now),
        Op::CommentCreate => comment_create(vars, cfg, now),
        Op::IssueStates => issue_states(vars, cfg),
    };
    match result {
        Ok((data, detail)) => Reply {
            status: 200,
            body: json!({"data": data}).to_string(),
            json: true,
            log: format!("{} ok: {detail}", op.name()),
        },
        Err(e) => Reply {
            status: 200,
            body: error_body(e.code, &e.message),
            json: true,
            log: format!("{} error {}: {}", op.name(), e.code, e.message),
        },
    }
}

type OpResult = Result<(Value, String), GqlError>;

fn input<'a>(vars: &'a Value, op: &str) -> Result<&'a Value, GqlError> {
    vars.get("input")
        .filter(|v| v.is_object())
        .ok_or_else(|| GqlError::new("GRAPHQL_VALIDATION_FAILED", format!("{op} needs variables.input (an object)")))
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Some(trimmed) when `s` has non-blank content.
fn nonempty(s: &str) -> Option<&str> {
    Some(s.trim()).filter(|t| !t.is_empty())
}

fn triage_state(vars: &Value, cfg: &Config) -> OpResult {
    let team = str_field(vars, "team");
    let nodes = if team == cfg.team_id {
        vec![json!({"id": TRIAGE_STATE_ID, "name": "Triage", "type": "triage"})]
    } else {
        vec![]
    };
    let detail = format!("team {team:?}, {} state(s)", nodes.len());
    Ok((json!({"workflowStates": {"nodes": nodes}}), detail))
}

/// Issue id: "mock-<creation time digits>-<n>". The time part keeps ids unique when
/// issues.json is deleted or an older copy is saved over it and numbering restarts,
/// so a job that still holds an old id never gets another item's issue.
fn issue_id(now: &str, n: u64) -> String {
    let stamp: String = now.chars().filter(char::is_ascii_digit).collect();
    format!("mock-{stamp}-{n}")
}

fn issue_create(vars: &Value, cfg: &Config, now: &str) -> OpResult {
    let input = input(vars, "issueCreate")?;
    let team = str_field(input, "teamId");
    if team != cfg.team_id {
        return Err(GqlError::new("INVALID_INPUT", format!("teamId {team:?} does not exist (the mock team is MOCK_TEAM_ID)")));
    }
    if let Some(state) = input.get("stateId").filter(|v| !v.is_null())
        && state.as_str() != Some(TRIAGE_STATE_ID)
    {
        return Err(GqlError::new("INVALID_INPUT",
                                 format!("stateId {state} does not exist (the only state is {TRIAGE_STATE_ID:?}, from TriageState)")));
    }
    let title = str_field(input, "title");
    if title.trim().is_empty() {
        return Err(GqlError::new("INVALID_INPUT", "issueCreate needs a non-empty title"));
    }
    let mut f = load(&cfg.data_dir)?;
    let mut n = f.next.max(1);
    while f.issues.iter().any(|i| i.id == issue_id(now, n) || i.identifier == format!("MOCK-{n}")) {
        n += 1;
    }
    let identifier = format!("MOCK-{n}");
    let issue = Issue {
        id: issue_id(now, n),
        identifier: identifier.clone(),
        url: format!("{URL_BASE}{identifier}"),
        title: title.into(),
        description: str_field(input, "description").into(),
        created: now.into(),
        state: MockState::Triage,
        assignee: String::new(),
        due: String::new(),
        reason: String::new(),
        actor: String::new(),
        changed: String::new(),
        comments: vec![],
        extra: Map::new(),
    };
    let reply = json!({"id": issue.id, "identifier": issue.identifier, "url": issue.url});
    f.next = n + 1;
    f.issues.push(issue);
    save(&cfg.data_dir, &f)?;
    Ok((json!({"issueCreate": {"success": true, "issue": reply}}), identifier))
}

fn comment_create(vars: &Value, cfg: &Config, now: &str) -> OpResult {
    let input = input(vars, "commentCreate")?;
    let issue_id = str_field(input, "issueId");
    let mut f = load(&cfg.data_dir)?;
    let Some(issue) = f.issues.iter_mut().find(|i| i.id == issue_id) else {
        return Err(GqlError::new("INVALID_INPUT", format!("Entity not found: Issue {issue_id:?} (not in {DATA_FILE})")));
    };
    issue.comments.push(Comment { at: now.into(), body: str_field(input, "body").into() });
    let id = format!("{}-comment-{}", issue.id, issue.comments.len());
    let detail = format!("{} on {}", id, issue.identifier);
    save(&cfg.data_dir, &f)?;
    Ok((json!({"commentCreate": {"success": true, "comment": {"id": id}}}), detail))
}

fn issue_states(vars: &Value, cfg: &Config) -> OpResult {
    let ids: Vec<&str> = vars
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| GqlError::new("GRAPHQL_VALIDATION_FAILED", "issues needs variables.ids (a list of ids)"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let f = load(&cfg.data_dir)?;
    let nodes: Vec<Value> = f.issues.iter().filter(|i| ids.contains(&i.id.as_str())).map(issue_node).collect();
    let detail = format!("{} of {} id(s) found", nodes.len(), ids.len());
    Ok((json!({"issues": {"nodes": nodes}}), detail))
}

/// One issue in the shape of Linear's IssueStates node (see the module doc for the mapping).
fn issue_node(i: &Issue) -> Value {
    let (state_type, state_name) = i.state.linear();
    let when = nonempty(&i.changed).unwrap_or(i.created.trim());
    let who = nonempty(&i.actor).unwrap_or(DEFAULT_ACTOR);
    let history: Vec<Value> = if i.state == MockState::Triage {
        vec![]
    } else {
        vec![json!({"createdAt": when, "actor": {"name": who}, "botActor": null,
                    "toState": {"type": state_type, "name": state_name}})]
    };
    let mut comments: Vec<Value> = i
        .comments
        .iter()
        .map(|c| json!({"body": c.body, "createdAt": c.at, "user": {"name": BOT_USER}}))
        .collect();
    if let Some(reason) = nonempty(&i.reason) {
        comments.push(json!({"body": reason, "createdAt": when, "user": {"name": who}}));
    }
    json!({
        "id": i.id,
        "identifier": i.identifier,
        "url": i.url,
        "state": {"type": state_type, "name": state_name},
        "assignee": nonempty(&i.assignee).map(|a| json!({"name": a})),
        "dueDate": nonempty(&i.due),
        "history": {"nodes": history},
        "comments": {"nodes": comments},
    })
}

// ---------------------------------------------------------------- server

fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn serve_one(mut req: tiny_http::Request, cfg: &Config) {
    let method = req.method().to_string();
    let url = req.url().to_string();
    let auth = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .map(|h| h.value.as_str().to_string());
    let now = now_iso();
    let mut body = vec![];
    let reply = match req.as_reader().take(MAX_BODY + 1).read_to_end(&mut body) {
        Ok(_) if body.len() as u64 > MAX_BODY => Reply::text(413, "request body too large", "body too large"),
        Ok(_) => handle(&method, &url, auth.as_deref(), &body, cfg, &now),
        Err(e) => Reply::text(400, "cannot read request body", format!("cannot read body: {e}")),
    };
    let path = url.split('?').next().unwrap_or("");
    println!("{now} {method} {path} {} -> {}", reply.log, reply.status);
    let content_type = if reply.json { "application/json" } else { "text/plain; charset=utf-8" };
    let response = tiny_http::Response::from_string(reply.body)
        .with_status_code(reply.status)
        .with_header(tiny_http::Header::from_bytes("Content-Type", content_type).expect("static header"));
    if let Err(e) = req.respond(response) {
        eprintln!("{now} {method} {path} could not send the reply: {e}");
    }
}

/// `linear-mock healthcheck`: 0 when GET /health on this container answers 200.
fn healthcheck(port: u16) -> i32 {
    let check = || -> io::Result<bool> {
        let mut s = TcpStream::connect(("127.0.0.1", port))?;
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        s.write_all(b"GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
        let mut out = String::new();
        s.read_to_string(&mut out)?;
        Ok(out.starts_with("HTTP/1.0 200") || out.starts_with("HTTP/1.1 200"))
    };
    match check() {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("linear-mock healthcheck: /health did not answer 200");
            1
        }
        Err(e) => {
            eprintln!("linear-mock healthcheck: {e}");
            1
        }
    }
}

fn main() {
    let get = |k: &str| std::env::var(k).ok();
    let port = port_from(&get).unwrap_or_else(|e| {
        eprintln!("linear-mock: {e}");
        exit(2)
    });
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("healthcheck") => exit(healthcheck(port)),
        Some(_) => {
            eprintln!("usage: linear-mock [healthcheck]   (settings come from the environment, see the source)");
            exit(2)
        }
    }
    let cfg = Config::from_vars(&get).unwrap_or_else(|e| {
        eprintln!("linear-mock: {e}");
        exit(2)
    });
    let server = tiny_http::Server::http(("0.0.0.0", port)).unwrap_or_else(|e| {
        eprintln!("linear-mock: cannot listen on 0.0.0.0:{port}: {e}");
        exit(1)
    });
    println!("{} linear-mock listening on 0.0.0.0:{port}, team {:?}, data {}",
             now_iso(), cfg.team_id, cfg.data_dir.join(DATA_FILE).display());
    for req in server.incoming_requests() {
        serve_one(req, &cfg);
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    const NOW: &str = "2026-11-04T08:00:00Z";
    const KEY: &str = "lin_api_test";
    const TEAM: &str = "team-1";

    // The four documents exactly as the job sends them (src/triage/tracker.rs, 2026-11-04).
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

    /// A fresh directory under the system temp dir, removed on drop.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir()
                .join(format!("linear-mock-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn cfg(&self) -> Config {
            Config { api_key: KEY.into(), team_id: TEAM.into(), data_dir: self.0.clone() }
        }
        fn file(&self) -> PathBuf {
            self.0.join(DATA_FILE)
        }
        fn read(&self) -> Value {
            serde_json::from_slice(&fs::read(self.file()).unwrap()).unwrap()
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn post(cfg: &Config, auth: Option<&str>, query: &str, vars: Value) -> (u16, Value) {
        let body = json!({"query": query, "variables": vars}).to_string();
        let r = handle("POST", "/graphql", auth, body.as_bytes(), cfg, NOW);
        assert!(r.json);
        assert!(!r.log.contains(KEY), "log must not hold the key: {}", r.log);
        (r.status, serde_json::from_str(&r.body).unwrap())
    }

    fn gql(cfg: &Config, query: &str, vars: Value) -> Value {
        let (status, v) = post(cfg, Some(KEY), query, vars);
        assert_eq!(status, 200);
        v
    }

    fn error_code(v: &Value) -> &str {
        assert_eq!(v["data"], Value::Null, "{v}");
        v.pointer("/errors/0/extensions/code").and_then(Value::as_str).unwrap_or("")
    }

    fn create(cfg: &Config, title: &str) -> Value {
        let input = json!({"teamId": TEAM, "title": title, "description": "d", "stateId": TRIAGE_STATE_ID});
        gql(cfg, M_ISSUE_CREATE, json!({"input": input}))
    }

    fn states(cfg: &Config, ids: &[&str]) -> Vec<Value> {
        let v = gql(cfg, Q_ISSUE_STATES, json!({"ids": ids, "first": ids.len(), "nested": 20}));
        v.pointer("/data/issues/nodes").and_then(Value::as_array).cloned().unwrap_or_else(|| panic!("{v}"))
    }

    #[test]
    fn health_and_unknown_paths() {
        let d = TestDir::new();
        let cfg = d.cfg();
        let r = handle("GET", "/health", None, b"", &cfg, NOW);
        assert_eq!((r.status, r.body.as_str(), r.json), (200, "ok", false));
        assert_eq!(handle("GET", "/health?probe=1", None, b"", &cfg, NOW).status, 200);
        assert_eq!(handle("GET", "/graphql", Some(KEY), b"", &cfg, NOW).status, 404);
        assert_eq!(handle("POST", "/other", Some(KEY), b"{}", &cfg, NOW).status, 404);
        assert_eq!(handle("POST", "/health", None, b"", &cfg, NOW).status, 404);
    }

    #[test]
    fn auth_failure_is_401_with_linear_body() {
        let d = TestDir::new();
        let cfg = d.cfg();
        let fixture: Value = serde_json::from_str(r#"{
          "errors": [{"message": "Authentication required, not authenticated",
                      "extensions": {"type": "authentication error", "code": "AUTHENTICATION_ERROR", "statusCode": 401,
                                     "userError": true,
                                     "userPresentableMessage": "You need to authenticate to access this operation."}}],
          "data": null}"#).unwrap();
        let bearer = format!("Bearer {KEY}");
        for auth in [None, Some("wrong"), Some(bearer.as_str()), Some("")] {
            let (status, v) = post(&cfg, auth, M_ISSUE_CREATE,
                                   json!({"input": {"teamId": TEAM, "title": "t", "stateId": TRIAGE_STATE_ID}}));
            assert_eq!(status, 401, "{auth:?}");
            assert_eq!(v, fixture);
        }
        assert!(!d.file().exists(), "a rejected call must not write");
    }

    #[test]
    fn unknown_operation_and_bad_body() {
        let d = TestDir::new();
        let cfg = d.cfg();
        for q in ["query Viewer { viewer { id } }", "query TriageStateX { x }", "{ viewer { id } }", ""] {
            assert_eq!(error_code(&gql(&cfg, q, json!({}))), "GRAPHQL_VALIDATION_FAILED", "{q:?}");
        }
        let r = handle("POST", "/graphql", Some(KEY), b"not json", &cfg, NOW);
        assert_eq!(r.status, 400);
        assert_eq!(error_code(&serde_json::from_str(&r.body).unwrap()), "BAD_REQUEST");
        // Leading whitespace before the operation is fine.
        let v = gql(&cfg, &format!("\n  {Q_TRIAGE_STATE}"), json!({"team": TEAM}));
        assert_eq!(v.pointer("/data/workflowStates/nodes/0/id"), Some(&json!(TRIAGE_STATE_ID)));
    }

    #[test]
    fn triage_state_only_for_the_mock_team() {
        let d = TestDir::new();
        let cfg = d.cfg();
        assert_eq!(gql(&cfg, Q_TRIAGE_STATE, json!({"team": TEAM})),
                   json!({"data": {"workflowStates": {"nodes": [{"id": "state-triage", "name": "Triage", "type": "triage"}]}}}));
        assert_eq!(gql(&cfg, Q_TRIAGE_STATE, json!({"team": "other"})),
                   json!({"data": {"workflowStates": {"nodes": []}}}));
    }

    #[test]
    fn issue_create_appends_and_numbers() {
        let d = TestDir::new();
        let cfg = d.cfg();
        assert_eq!(create(&cfg, "first"), json!({"data": {"issueCreate": {"success": true, "issue": {
            "id": issue_id(NOW, 1), "identifier": "MOCK-1", "url": "http://linear-mock.invalid/issue/MOCK-1"}}}}));
        // No stateId is allowed too (Linear would pick the default state; here it is triage).
        let v = gql(&cfg, M_ISSUE_CREATE, json!({"input": {"teamId": TEAM, "title": "second"}}));
        assert_eq!(v.pointer("/data/issueCreate/issue/identifier"), Some(&json!("MOCK-2")));

        let f = d.read();
        assert_eq!(f["next"], json!(3));
        let i = &f["issues"][0];
        assert_eq!(i["id"], json!(issue_id(NOW, 1)));
        assert_eq!(i["title"], "first");
        assert_eq!(i["description"], "d");
        assert_eq!(i["created"], NOW);
        assert_eq!(i["state"], "triage");
        assert_eq!(i["comments"], json!([]));
        for k in ["assignee", "due", "reason", "actor", "changed"] {
            assert_eq!(i[k], "", "{k}");
        }
        assert!(fs::read_to_string(d.file()).unwrap().contains("\n  \"issues\""), "pretty JSON");
        assert!(!d.0.join("issues.json.tmp").exists());
    }

    #[test]
    fn issue_create_skips_numbers_already_used() {
        let d = TestDir::new();
        let cfg = d.cfg();
        create(&cfg, "a");
        // A person reset "next" by hand: the mock must not reuse MOCK-1.
        let mut f = d.read();
        f["next"] = json!(1);
        fs::write(d.file(), f.to_string()).unwrap();
        assert_eq!(create(&cfg, "b").pointer("/data/issueCreate/issue/id"), Some(&json!(issue_id(NOW, 2))));
    }

    #[test]
    fn ids_stay_unique_after_the_file_is_reset() {
        let d = TestDir::new();
        let cfg = d.cfg();
        let first = create(&cfg, "a").pointer("/data/issueCreate/issue/id").cloned().unwrap();
        // A person deletes issues.json; numbering restarts at MOCK-1 but the id must differ.
        fs::remove_file(d.file()).unwrap();
        let input = json!({"teamId": TEAM, "title": "b", "stateId": TRIAGE_STATE_ID});
        let body = json!({"query": M_ISSUE_CREATE, "variables": {"input": input}}).to_string();
        let r = handle("POST", "/graphql", Some(KEY), body.as_bytes(), &cfg, "2026-11-05T09:30:00Z");
        let v: Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v.pointer("/data/issueCreate/issue/identifier"), Some(&json!("MOCK-1")));
        assert_eq!(v.pointer("/data/issueCreate/issue/id"), Some(&json!("mock-20261105093000-1")));
        assert_ne!(v.pointer("/data/issueCreate/issue/id"), Some(&first));
    }

    #[test]
    fn utf8_bom_is_ignored() {
        let d = TestDir::new();
        let cfg = d.cfg();
        create(&cfg, "a");
        let mut raw = b"\xEF\xBB\xBF".to_vec();
        raw.extend(fs::read(d.file()).unwrap());
        fs::write(d.file(), raw).unwrap();
        assert_eq!(states(&cfg, &[&issue_id(NOW, 1)]).len(), 1);
    }

    #[test]
    fn issue_create_rejects_unknown_team_state_and_empty_title() {
        let d = TestDir::new();
        let cfg = d.cfg();
        for input in [json!({"teamId": "other", "title": "t", "stateId": TRIAGE_STATE_ID}),
                      json!({"teamId": TEAM, "title": "t", "stateId": "state-done"}),
                      json!({"teamId": TEAM, "title": "  ", "stateId": TRIAGE_STATE_ID})] {
            assert_eq!(error_code(&gql(&cfg, M_ISSUE_CREATE, json!({"input": input}))), "INVALID_INPUT", "{input}");
        }
        assert_eq!(error_code(&gql(&cfg, M_ISSUE_CREATE, json!({}))), "GRAPHQL_VALIDATION_FAILED");
        assert!(!d.file().exists());
    }

    #[test]
    fn comment_create_appends_and_rejects_unknown_issue() {
        let d = TestDir::new();
        let cfg = d.cfg();
        create(&cfg, "a");
        let id1 = issue_id(NOW, 1);
        let v = gql(&cfg, M_COMMENT_CREATE, json!({"input": {"issueId": id1, "body": "**exploit-watch**: changed"}}));
        assert_eq!(v, json!({"data": {"commentCreate": {"success": true, "comment": {"id": format!("{id1}-comment-1")}}}}));
        assert_eq!(d.read()["issues"][0]["comments"], json!([{"at": NOW, "body": "**exploit-watch**: changed"}]));

        let before = fs::read(d.file()).unwrap();
        let v = gql(&cfg, M_COMMENT_CREATE, json!({"input": {"issueId": "mock-9", "body": "x"}}));
        assert_eq!(error_code(&v), "INVALID_INPUT");
        assert_eq!(fs::read(d.file()).unwrap(), before);
    }

    #[test]
    fn issue_states_fresh_issue_and_unknown_ids() {
        let d = TestDir::new();
        let cfg = d.cfg();
        create(&cfg, "a");
        let id1 = issue_id(NOW, 1);
        gql(&cfg, M_COMMENT_CREATE, json!({"input": {"issueId": id1, "body": "**exploit-watch**: c"}}));
        let nodes = states(&cfg, &[id1.as_str(), "mock-404"]);
        assert_eq!(nodes, vec![json!({
            "id": id1, "identifier": "MOCK-1", "url": "http://linear-mock.invalid/issue/MOCK-1",
            "state": {"type": "triage", "name": "Triage"}, "assignee": null, "dueDate": null,
            "history": {"nodes": []},
            "comments": {"nodes": [{"body": "**exploit-watch**: c", "createdAt": NOW, "user": {"name": "exploit-watch bot"}}]}
        })]);
        assert!(states(&cfg, &[]).is_empty());
        // Missing file: no issues, not an error.
        let empty = TestDir::new();
        assert!(states(&empty.cfg(), &["mock-1"]).is_empty());
        assert_eq!(error_code(&gql(&cfg, Q_ISSUE_STATES, json!({"first": 1}))), "GRAPHQL_VALIDATION_FAILED");
    }

    /// A file as a person would leave it after triaging four issues by hand.
    fn hand_edited(d: &TestDir) {
        let issue = |n: u32, state: &str, extra: Value| {
            let mut i = json!({"id": format!("mock-{n}"), "identifier": format!("MOCK-{n}"),
                               "url": format!("{URL_BASE}MOCK-{n}"), "title": "t", "description": "",
                               "created": "2026-11-04T08:00:00Z", "state": state, "assignee": "", "due": "",
                               "reason": "", "actor": "", "changed": "",
                               "comments": [{"at": "2026-11-04T08:30:00Z", "body": "**exploit-watch**: changed"}]});
            for (k, v) in extra.as_object().unwrap() {
                i[k] = v.clone();
            }
            i
        };
        let f = json!({"next": 5, "issues": [
            issue(1, "triage", json!({})),
            issue(2, "accepted", json!({"assignee": "Henry", "due": "2026-11-10", "actor": "James",
                                        "changed": "2026-11-04T09:00:00Z"})),
            issue(3, "completed", json!({"assignee": "Henry"})),
            issue(4, "canceled", json!({"reason": "  Not relevant: test harness only.\n", "actor": "Henry",
                                        "changed": "2026-11-04T10:00:00Z", "item_key": "CISA KEV:CVE-2026-1234"})),
        ]});
        fs::write(d.file(), serde_json::to_string_pretty(&f).unwrap()).unwrap();
    }

    #[test]
    fn state_mapping_history_and_reason_comment() {
        let d = TestDir::new();
        let cfg = d.cfg();
        hand_edited(&d);
        let nodes = states(&cfg, &["mock-1", "mock-2", "mock-3", "mock-4"]);
        let st: Vec<(&str, &str)> = nodes
            .iter()
            .map(|n| (n["state"]["type"].as_str().unwrap(), n["state"]["name"].as_str().unwrap()))
            .collect();
        assert_eq!(st, [("triage", "Triage"), ("unstarted", "Todo"), ("completed", "Done"), ("canceled", "Canceled")]);

        assert_eq!(nodes[0]["history"]["nodes"], json!([]));
        assert_eq!(nodes[1]["assignee"], json!({"name": "Henry"}));
        assert_eq!(nodes[1]["dueDate"], json!("2026-11-10"));
        assert_eq!(nodes[1]["history"]["nodes"], json!([{"createdAt": "2026-11-04T09:00:00Z", "actor": {"name": "James"},
            "botActor": null, "toState": {"type": "unstarted", "name": "Todo"}}]));
        // No actor / changed: "mock user" at the creation time.
        assert_eq!(nodes[2]["history"]["nodes"][0]["actor"], json!({"name": "mock user"}));
        assert_eq!(nodes[2]["history"]["nodes"][0]["createdAt"], json!("2026-11-04T08:00:00Z"));
        assert_eq!(nodes[2]["comments"]["nodes"].as_array().unwrap().len(), 1);

        assert_eq!(nodes[3]["comments"]["nodes"], json!([
            {"body": "**exploit-watch**: changed", "createdAt": "2026-11-04T08:30:00Z", "user": {"name": "exploit-watch bot"}},
            {"body": "Not relevant: test harness only.", "createdAt": "2026-11-04T10:00:00Z", "user": {"name": "Henry"}},
        ]));
    }

    /// Recursive check that `ours` has the same keys as Linear's node at every level.
    fn same_keys(ours: &Value, linear: &Value, path: &str) {
        match (ours, linear) {
            (Value::Object(a), Value::Object(b)) => {
                let mut ka: Vec<_> = a.keys().collect();
                let mut kb: Vec<_> = b.keys().collect();
                ka.sort();
                kb.sort();
                assert_eq!(ka, kb, "keys at {path}");
                for (k, v) in a {
                    same_keys(v, &b[k], &format!("{path}/{k}"));
                }
            }
            (Value::Array(a), Value::Array(b)) if !b.is_empty() => {
                for v in a {
                    same_keys(v, &b[0], &format!("{path}[]"));
                }
            }
            _ => {}
        }
    }

    #[test]
    fn node_shape_matches_linear_fixture() {
        // Node id-CTP-125 of tests/fixtures/linear_issues_states.json in the job repo (comments trimmed to one).
        let linear: Value = serde_json::from_str(r#"{
          "id": "id-CTP-125", "identifier": "CTP-125", "url": "https://linear.app/ediphy/issue/CTP-125/z",
          "state": { "type": "canceled", "name": "Canceled" }, "assignee": { "name": "x" }, "dueDate": null,
          "history": { "nodes": [ { "createdAt": "2026-11-03T10:00:00.000Z", "actor": { "name": "Tran Trung Hau" },
                                    "botActor": null, "toState": { "type": "canceled", "name": "Canceled" } } ] },
          "comments": { "nodes": [ { "body": "Not relevant.", "createdAt": "2026-11-03T10:00:00.000Z",
                                     "user": { "name": "Tran Trung Hau" } } ] } }"#).unwrap();
        let d = TestDir::new();
        let cfg = d.cfg();
        hand_edited(&d);
        for n in states(&cfg, &["mock-1", "mock-2", "mock-3", "mock-4"]) {
            same_keys(&n, &linear, "");
        }
    }

    /// The job's parse_issue_node (src/triage/tracker.rs) reduced to the fields it derives:
    /// state type, actor and time of the latest node with a toState, reason = latest comment
    /// not starting with "**exploit-watch**" when the state is declined (canceled/duplicate).
    fn job_view(n: &Value) -> (String, String, String, String, String, String) {
        let s = |v: &Value, p: &str| v.pointer(p).and_then(Value::as_str).unwrap_or("").to_string();
        let empty = vec![];
        let change = n["history"]["nodes"].as_array().unwrap_or(&empty).iter()
            .filter(|h| h.get("toState").is_some_and(|v| !v.is_null()))
            .max_by_key(|h| s(h, "/createdAt"));
        let declined = matches!(s(n, "/state/type").as_str(), "canceled" | "duplicate");
        let reason = if declined {
            n["comments"]["nodes"].as_array().unwrap_or(&empty).iter()
                .filter(|c| !s(c, "/body").trim_start().starts_with("**exploit-watch**"))
                .max_by_key(|c| s(c, "/createdAt"))
                .map(|c| s(c, "/body").trim().to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        (s(n, "/state/type"), s(n, "/assignee/name"), s(n, "/dueDate"), reason,
         change.map(|h| s(h, "/actor/name")).unwrap_or_default(), change.map(|h| s(h, "/createdAt")).unwrap_or_default())
    }

    #[test]
    fn job_reads_what_the_person_typed() {
        let d = TestDir::new();
        let cfg = d.cfg();
        hand_edited(&d);
        let views: Vec<_> = states(&cfg, &["mock-1", "mock-2", "mock-4"]).iter().map(job_view).collect();
        let v = |a: &str, b: &str, c: &str, e: &str, f: &str, g: &str| {
            (a.to_string(), b.to_string(), c.to_string(), e.to_string(), f.to_string(), g.to_string())
        };
        assert_eq!(views, vec![
            v("triage", "", "", "", "", ""),
            v("unstarted", "Henry", "2026-11-10", "", "James", "2026-11-04T09:00:00Z"),
            v("canceled", "", "", "Not relevant: test harness only.", "Henry", "2026-11-04T10:00:00Z"),
        ]);
    }

    #[test]
    fn hand_added_fields_survive_a_write() {
        let d = TestDir::new();
        let cfg = d.cfg();
        hand_edited(&d);
        gql(&cfg, M_COMMENT_CREATE, json!({"input": {"issueId": "mock-4", "body": "**exploit-watch**: again"}}));
        let f = d.read();
        assert_eq!(f["issues"][3]["item_key"], "CISA KEV:CVE-2026-1234");
        assert_eq!(f["issues"][2]["state"], "done", "aliases are written back in their canonical form");
        assert_eq!(f["issues"][3]["comments"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn corrupt_file_is_reported_and_never_overwritten() {
        let d = TestDir::new();
        let cfg = d.cfg();
        let corrupt = b"{\"next\": 2, \"issues\": [ {\"id\": \"mock-1\", oops";
        fs::write(d.file(), corrupt).unwrap();
        let calls = [
            (M_ISSUE_CREATE, json!({"input": {"teamId": TEAM, "title": "t", "stateId": TRIAGE_STATE_ID}})),
            (M_COMMENT_CREATE, json!({"input": {"issueId": "mock-1", "body": "x"}})),
            (Q_ISSUE_STATES, json!({"ids": ["mock-1"], "first": 1, "nested": 20})),
        ];
        for (q, vars) in calls {
            let v = gql(&cfg, q, vars);
            assert_eq!(error_code(&v), "MOCK_DATA_INVALID");
            assert!(v["errors"][0]["message"].as_str().unwrap().contains("will not overwrite"));
            assert_eq!(fs::read(d.file()).unwrap(), corrupt);
        }
        // An unknown state word is a parse error too.
        fs::write(d.file(), r#"{"next":2,"issues":[{"id":"mock-1","identifier":"MOCK-1","url":"u","state":"Accepted"}]}"#)
            .unwrap();
        assert_eq!(error_code(&gql(&cfg, Q_ISSUE_STATES, json!({"ids": ["mock-1"]}))), "MOCK_DATA_INVALID");
        // A blank file counts as empty.
        fs::write(d.file(), "\n").unwrap();
        assert_eq!(create(&cfg, "t").pointer("/data/issueCreate/issue/id"), Some(&json!(issue_id(NOW, 1))));
    }

    #[test]
    fn config_from_env() {
        let vars = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
        };
        let c = Config::from_vars(&vars(&[("MOCK_API_KEY", "k"), ("MOCK_TEAM_ID", "t")])).unwrap();
        assert_eq!((c.api_key.as_str(), c.team_id.as_str(), c.data_dir), ("k", "t", PathBuf::from("/data")));
        assert!(Config::from_vars(&vars(&[("MOCK_TEAM_ID", "t")])).unwrap_err().contains("MOCK_API_KEY"));
        assert!(Config::from_vars(&vars(&[("MOCK_API_KEY", "k"), ("MOCK_TEAM_ID", "")])).is_err());
        assert_eq!(port_from(&vars(&[])), Ok(8080));
        assert_eq!(port_from(&vars(&[("PORT", "9000")])), Ok(9000));
        assert!(port_from(&vars(&[("PORT", "x")])).is_err());
    }

    /// Raw HTTP/1.0 exchange; returns the whole response text.
    fn raw(port: u16, request: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn real_http_round_trip() {
        let d = TestDir::new();
        let cfg = d.cfg();
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let worker = std::thread::spawn(move || {
            for _ in 0..3 {
                serve_one(server.recv().unwrap(), &cfg);
            }
        });
        assert_eq!(healthcheck(port), 0);

        let body = json!({"query": M_ISSUE_CREATE,
                          "variables": {"input": {"teamId": TEAM, "title": "t", "stateId": TRIAGE_STATE_ID}}}).to_string();
        let ok = raw(port, &format!("POST /graphql HTTP/1.0\r\nAuthorization: {KEY}\r\nContent-Type: application/json\r\n\
                                     Content-Length: {}\r\n\r\n{body}", body.len()));
        assert!(ok.starts_with("HTTP/1.0 200") || ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.to_ascii_lowercase().contains("content-type: application/json"), "{ok}");
        assert!(ok.contains(r#""identifier":"MOCK-1""#), "{ok}");

        let denied = raw(port, &format!("POST /graphql HTTP/1.0\r\nAuthorization: Bearer {KEY}\r\n\
                                         Content-Length: {}\r\n\r\n{body}", body.len()));
        assert!(denied.contains(" 401 "), "{denied}");
        assert!(denied.contains("AUTHENTICATION_ERROR"), "{denied}");
        worker.join().unwrap();
        assert_eq!(d.read()["issues"].as_array().unwrap().len(), 1);
    }
}
