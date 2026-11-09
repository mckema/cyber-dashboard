//! linear-mock: a local stand-in for the Linear GraphQL API, for the Docker
//! Compose lab only. It answers the six GraphQL documents that the
//! exploit-watch job's live Linear client sends (triage/tracker.rs,
//! `LinearTracker`), so that client can be exercised end to end over real HTTP
//! without a Linear workspace. It is not a Linear emulator: it does not parse
//! GraphQL, it recognises each document by the operation name at its start.
//!
//! HTTP
//!
//!   GET  /health        200 "ok" (no auth)
//!   POST /graphql       JSON {"query": "...", "variables": {...}}
//!   POST /oauth/token   client_credentials grant (form body, see OAuth token below)
//!   anything else   404
//!
//! Auth: two credentials, mirroring Linear's two header forms.
//!
//!   personal API key  `Authorization: <MOCK_API_KEY>`, the bare key (as Linear
//!                     expects for personal API keys); "Bearer <key>" is rejected
//!   OAuth app token   `Authorization: Bearer <MOCK_APP_TOKEN>` (scheme word in
//!                     any case, one space), only when MOCK_APP_TOKEN is set; the
//!                     bare token is rejected
//!
//! Anything else is HTTP 401 with Linear's error body (extensions.code
//! AUTHENTICATION_ERROR). Both credentials can do everything; the log line says
//! which one a request used ("as user" / "as app"). Token expiry, revocation and
//! scopes are not simulated (POST /oauth/token always hands out the same token),
//! and the data is the same whichever credential wrote it: comments still show as written by "exploit-watch bot",
//! and no history node or botActor is produced for what the app created.
//!
//! Operations (dispatch on the trimmed start of `query`):
//!
//!   query TriageState      variables.team == MOCK_TEAM_ID -> one workflow state
//!                          {id "state-triage", name "Triage", type "triage"};
//!                          any other team -> no nodes
//!   query StateByType      variables {team, type} (since 2026-11-06, the job's
//!                          create_task): type "triage" -> the triage state,
//!                          "unstarted" -> {id "state-todo", name "Todo", type
//!                          "unstarted", position 1}; other types or teams -> no nodes
//!   mutation IssueCreate   input {id, teamId, title, description, stateId,
//!                          assigneeId, dueDate}; appends issue MOCK-<n>, in state
//!                          triage (stateId "state-triage" or none) or todo
//!                          (stateId "state-todo": a task such as the monthly review
//!                          reminder; assigneeId is kept as `assignee`, dueDate as
//!                          `due`, both only when given). `id` (optional, as in
//!                          Linear) becomes the issue id; it must be a UUID v4
//!                          and not taken. Without it the id is mock-<time>-<n>
//!   query IssueById        variables.id = an issue id or identifier (MOCK-1) ->
//!                          issue {id identifier url}
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
//!                              a stateId other than "state-triage" or "state-todo", or an empty
//!                              title; CommentCreate on an id not in the file.
//!                              IssueCreate with an `id` that is not a UUID v4:
//!                              Linear's answer of 2026-11-05 ("Argument
//!                              Validation Error", userPresentableMessage
//!                              "id must be a UUID."; Linear refused a v5 UUID)
//!   INPUT_ERROR                IssueCreate with an `id` an issue already has:
//!                              Linear's answer of 2026-11-05 (message "conflict on
//!                              insert of Issue", extensions type "invalid input",
//!                              statusCode 400, userError, userPresentableMessage
//!                              "Entity Issue with id <id> already exists.",
//!                              without `locations`); nothing is written.
//!                              IssueCreate whose title contains FAIL_CREATE
//!                              ("FAIL-CREATE"): a failure switch for tests of the
//!                              job's error handling; same shape, message "linear-mock:
//!                              create refused (title contains FAIL-CREATE)", nothing
//!                              is written (mock-specific, not a Linear answer).
//!                              IssueById on an unknown id: "Entity not found:
//!                              Issue" (shape of Linear's "Entity not found: Team"
//!                              answer; the Issue case is not verified)
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
//!      "id": "mock-20261104080000-1",                  IssueCreate input.id (UUID v4), or
//!                                                      creation time digits + number
//!      "identifier": "MOCK-1",
//!      "url": "http://linear-mock.invalid/issue/MOCK-1",
//!      "title": "[CVE-2026-1234] ...",
//!      "description": "...",
//!      "created": "2026-11-04T08:00:00Z",
//!      "state": "triage",      edit: triage | accepted | done | declined | duplicate
//!                                    | accepted-canceled (accepted, later canceled)
//!                                    | todo (created into Todo by a task, never triaged)
//!                                    (completed, canceled, cancelled also read;
//!                                    canceled = declined, a Decline from Triage)
//!      "assignee": "",         edit: owner name, "" = unassigned
//!      "due": "",              edit: YYYY-MM-DD, "" = none
//!      "reason": "",           edit: why it was declined
//!      "actor": "",            edit: who triaged it, i.e. moved it out of Triage
//!                                    ("" = "mock user")
//!      "changed": "",          edit: when it left Triage (UTC ISO), "" = use `created`
//!      "completed": "",        optional: completedAt of a done issue, "" = `changed`
//!      "canceled": "",         optional: canceledAt of an accepted-canceled issue,
//!                                    "" = 1 hour after `changed`; of a declined or
//!                                    duplicate issue, "" = `changed`
//!      "comments": [{"at": "2026-11-04T09:00:00Z", "body": "..."}]   job-only
//!     }
//!    ]
//!   }
//!
//! The editable fields match the job's test double FakeTracker (which has no
//! `duplicate` state and no `completed` / `canceled` times). Other fields a
//! person adds to an issue are kept when the mock rewrites the file. `comments`
//! holds the job's comments only (shown as written by "exploit-watch bot"); a
//! decline reason goes in `reason`, not in `comments`. A leading UTF-8 BOM is
//! ignored. Reset the mock together with the job's state/triage.json.
//!
//! How IssueStates maps an issue to Linear's shape, following what a real
//! Linear workspace returned on 2026-11-04/05:
//!
//!   state      triage -> triage "Triage", accepted and todo -> unstarted "Todo",
//!              done -> completed "Done", declined -> canceled "Canceled",
//!              accepted-canceled -> canceled "Canceled", duplicate ->
//!              duplicate "Duplicate" (Linear's own state type for Mark as
//!              duplicate, not canceled)
//!   assignee   "" -> null, else {name}; due "" -> dueDate null
//!   triagedAt  state triage or todo: null; otherwise changed or created (Linear
//!              sets it on any move out of Triage; a task never was in Triage)
//!   createdAt  created ("" -> null)
//!   startedAt  always null (the mock has no started state)
//!   completedAt  done: completed or triagedAt; otherwise null
//!   canceledAt declined, duplicate: canceled or triagedAt (real Linear: within
//!              3-4 ms of triagedAt on a Decline, 2026-11-05); accepted-canceled:
//!              canceled or 1 hour after triagedAt (real Linear: ~20 h later on
//!              TRI-1); otherwise null
//!   history    state triage or todo: no nodes; otherwise the entry that left Triage,
//!              {createdAt: changed or created, actor {name: actor or
//!              "mock user"}, botActor null, fromState {type "triage"},
//!              toState {type, name}}; for duplicate fromState and toState
//!              are null (Linear records only the relation); accepted-canceled
//!              has two entries, triage -> backlog "Backlog" at triagedAt and
//!              backlog -> canceled "Canceled" at canceledAt, both by the actor
//!   comments   the job's comments with user "exploit-watch bot", plus, when
//!              `reason` is set, a separate comment {body: reason, createdAt:
//!              changed or created (accepted-canceled: canceledAt), user
//!              {name: actor or "mock user"}}
//!
//! history and comments are newest first, as Linear returns them (times that
//! do not parse as RFC 3339 sort last). Timestamps are passed through as
//! written in the file, except the computed default canceledAt of
//! accepted-canceled (null when triagedAt does not parse).
//!
//! Environment:
//!
//!   MOCK_API_KEY    required; the personal API key clients send bare in Authorization
//!   MOCK_APP_TOKEN  optional; an OAuth access token clients send as "Bearer <token>".
//!                   Must differ from MOCK_API_KEY and must not start with
//!                   "lin_api_" (the job sends such values bare, as personal keys)
//!   MOCK_CLIENT_ID, MOCK_CLIENT_SECRET   optional, both or neither, and only
//!                   with MOCK_APP_TOKEN: the OAuth app credentials POST /oauth/token accepts
//!   MOCK_TOKEN_EXPIRES_IN  default 2592000 (30 days, as Linear): expires_in of the token
//!   MOCK_TEAM_ID    required; the only team id that exists
//!   MOCK_DATA_DIR   default /data
//!   PORT            default 8080; the server listens on 0.0.0.0
//!
//! OAuth token: POST /oauth/token with an application/x-www-form-urlencoded body
//! grant_type=client_credentials, client_id, client_secret, scope (optional), as
//! Linear's token endpoint takes it. The right MOCK_CLIENT_ID/MOCK_CLIENT_SECRET
//! pair gets 200 {"access_token": MOCK_APP_TOKEN, "token_type": "Bearer",
//! "expires_in": MOCK_TOKEN_EXPIRES_IN, "scope": <as asked, default "read">}.
//! Errors are OAuth error bodies {"error", "error_description"}: HTTP 400
//! unsupported_grant_type (any other grant) or invalid_request (a field missing),
//! HTTP 401 invalid_client (wrong pair, or the mock has no client configured).
//!
//! `linear-mock healthcheck` GETs http://127.0.0.1:$PORT/health and exits 0 when
//! it answers 200, 1 otherwise (the runtime image has no curl or wget).
//!
//! Logging: one line per request on stdout (time, method, path, operation,
//! credential kind, result, HTTP status). The API key, the app token and the
//! client secret are never logged.
//!
//! Not simulated: rate limits (HTTP 429 / RATELIMITED, X-RateLimit-* headers),
//! pagination (`first` and nested `first` are ignored, all matches are
//! returned), archived issues, any other query or mutation, other workflow
//! states or teams, comment authors other than the two above, the OAuth flow
//! beyond the client_credentials token (authorization code, expiry, refresh,
//! revocation, scopes, app attribution), moves
//! after the triage other than accepted-canceled (one history entry per issue,
//! two for accepted-canceled), startedAt, Snooze (snoozedUntilAt) and the
//! duplicate relation to the canonical issue.
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
/// The team's unstarted state (Todo), for tasks such as the monthly review reminder.
const TODO_STATE_ID: &str = "state-todo";
const BOT_USER: &str = "exploit-watch bot";
const DEFAULT_ACTOR: &str = "mock user";
const URL_BASE: &str = "http://linear-mock.invalid/issue/";
/// Prefix of Linear personal API keys; the job sends values with it bare.
const PERSONAL_KEY_PREFIX: &str = "lin_api_";
/// Larger request bodies get 413.
const MAX_BODY: u64 = 1 << 20;
/// An IssueCreate whose title contains this is refused with INPUT_ERROR (failure switch).
const FAIL_CREATE: &str = "FAIL-CREATE";
/// Default canceledAt of an accepted-canceled issue: this long after triagedAt.
const CANCEL_AFTER_SECS: i64 = 3600;

// ---------------------------------------------------------------- config

#[derive(Debug, Clone)]
pub struct Config {
    pub api_key: String,
    /// MOCK_APP_TOKEN: OAuth access token accepted as "Bearer <token>"; None = only the API key.
    pub app_token: Option<String>,
    pub team_id: String,
    pub data_dir: PathBuf,
    /// MOCK_CLIENT_ID + MOCK_CLIENT_SECRET: what POST /oauth/token accepts; None = no client.
    pub oauth_client: Option<(String, String)>,
    /// MOCK_TOKEN_EXPIRES_IN: `expires_in` of the issued token.
    pub token_expires_in: u64,
}

/// Default MOCK_TOKEN_EXPIRES_IN: 30 days, the life of a Linear client_credentials token.
const DEFAULT_TOKEN_EXPIRES_IN: u64 = 30 * 86_400;

impl Config {
    /// Errors name the variable, never its value.
    fn from_vars(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let required = |k: &str| get(k).filter(|v| !v.is_empty()).ok_or_else(|| format!("{k} is required"));
        let api_key = required("MOCK_API_KEY")?;
        let app_token = get("MOCK_APP_TOKEN").filter(|v| !v.is_empty());
        if let Some(t) = &app_token {
            if *t == api_key {
                return Err("MOCK_APP_TOKEN must differ from MOCK_API_KEY".into());
            }
            if t.starts_with(PERSONAL_KEY_PREFIX) {
                return Err(format!("MOCK_APP_TOKEN must not start with {PERSONAL_KEY_PREFIX:?}: the job sends such \
                                    values bare, as personal API keys, never as \"Bearer <token>\""));
            }
        }
        let optional = |k: &str| get(k).filter(|v| !v.is_empty());
        let oauth_client = match (optional("MOCK_CLIENT_ID"), optional("MOCK_CLIENT_SECRET")) {
            (None, None) => None,
            (Some(id), Some(secret)) if app_token.is_some() => Some((id, secret)),
            (Some(_), Some(_)) => return Err("MOCK_CLIENT_ID needs MOCK_APP_TOKEN: it is the token /oauth/token issues".into()),
            _ => return Err("MOCK_CLIENT_ID and MOCK_CLIENT_SECRET go together: set both or neither".into()),
        };
        let token_expires_in = match optional("MOCK_TOKEN_EXPIRES_IN") {
            None => DEFAULT_TOKEN_EXPIRES_IN,
            Some(v) => v.parse().map_err(|_| format!("MOCK_TOKEN_EXPIRES_IN={v:?} is not a number of seconds"))?,
        };
        Ok(Self {
            api_key,
            app_token,
            team_id: required("MOCK_TEAM_ID")?,
            data_dir: get("MOCK_DATA_DIR").filter(|v| !v.is_empty()).unwrap_or_else(|| "/data".into()).into(),
            oauth_client,
            token_expires_in,
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
    /// completedAt of a done issue; "" = changed (module doc).
    #[serde(default)]
    completed: String,
    /// canceledAt of a declined, duplicate or accepted-canceled issue; "" = derived (module doc).
    #[serde(default)]
    canceled: String,
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
    /// Decline from Triage.
    #[serde(alias = "canceled", alias = "cancelled")]
    Declined,
    /// Mark as duplicate.
    Duplicate,
    /// Accepted (to Backlog), later canceled.
    #[serde(rename = "accepted-canceled")]
    AcceptedCanceled,
    /// Created straight into Todo (StateByType "unstarted"), never in Triage: a task such as the
    /// monthly review reminder. Not triaged, so no triagedAt and no history.
    Todo,
}

impl MockState {
    /// Linear WorkflowState (type, name).
    fn linear(self) -> (&'static str, &'static str) {
        match self {
            Self::Triage => ("triage", "Triage"),
            Self::Todo => ("unstarted", "Todo"),
            Self::Accepted => ("unstarted", "Todo"),
            Self::Done => ("completed", "Done"),
            Self::Declined | Self::AcceptedCanceled => ("canceled", "Canceled"),
            Self::Duplicate => ("duplicate", "Duplicate"),
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
    /// `path` of Linear's error entry ("issueCreate"); None = no path.
    path: Option<&'static str>,
    /// More extensions besides `code` (Linear's user errors carry type, statusCode, …).
    ext: Map<String, Value>,
}

impl GqlError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), path: None, ext: Map::new() }
    }

    /// A Linear user error: path, extensions {type "invalid input", code, statusCode 400,
    /// userError true, userPresentableMessage}.
    fn user(code: &'static str, message: impl Into<String>, path: &'static str, user_message: String) -> Self {
        let ext = json!({"type": "invalid input", "statusCode": 400, "userError": true,
                         "userPresentableMessage": user_message});
        Self { code, message: message.into(), path: Some(path), ext: ext.as_object().cloned().unwrap_or_default() }
    }

    fn body(&self) -> String {
        let mut ext = Map::new();
        ext.insert("code".into(), json!(self.code));
        ext.extend(self.ext.clone());
        let mut e = json!({"message": self.message, "extensions": ext});
        if let Some(p) = self.path {
            e["path"] = json!([p]);
        }
        json!({"errors": [e], "data": null}).to_string()
    }
}

fn error_body(code: &str, message: &str) -> String {
    json!({"errors": [{"message": message, "extensions": {"code": code}}], "data": null}).to_string()
}

/// Linear's IsUUID("4") check on IssueCreateInput.id (a v5 UUID was refused on 2026-11-05).
fn is_uuid_v4(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 36
        && s.char_indices().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() })
        && b[14] == b'4'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
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
    StateByType,
    IssueCreate,
    IssueById,
    CommentCreate,
    IssueStates,
}

impl Op {
    const ALL: [(Op, &'static str); 6] = [
        (Op::TriageState, "query TriageState"),
        (Op::StateByType, "query StateByType"),
        (Op::IssueCreate, "mutation IssueCreate"),
        (Op::IssueById, "query IssueById"),
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
            Op::StateByType => "StateByType",
            Op::IssueCreate => "IssueCreate",
            Op::IssueById => "IssueById",
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
        ("POST", "/oauth/token") => oauth_token(body, cfg),
        _ => Reply::text(404, "not found", "not found"),
    }
}

/// Value of one application/x-www-form-urlencoded field ("+" is a space, %XX a byte).
fn form_decode(s: &str) -> String {
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let escaped = (b[i] == b'%' && i + 2 < b.len()).then(|| Some(hex(b[i + 1])? << 4 | hex(b[i + 2])?)).flatten();
        match (b[i], escaped) {
            (_, Some(v)) => {
                out.push(v);
                i += 2;
            }
            (b'+', None) => out.push(b' '),
            (c, None) => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The fields of a form body (the last of a repeated name wins).
fn form_fields(body: &[u8]) -> Map<String, Value> {
    let text = String::from_utf8_lossy(body);
    let mut m = Map::new();
    for pair in text.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        m.insert(form_decode(k), Value::String(form_decode(v)));
    }
    m
}

/// POST /oauth/token: the client_credentials grant (module doc). Logs never hold the secret or the token.
fn oauth_token(body: &[u8], cfg: &Config) -> Reply {
    let f = form_fields(body);
    let field = |k: &str| f.get(k).and_then(Value::as_str).unwrap_or("");
    let error = |status: u16, code: &str, description: &str, log: String| Reply {
        status,
        body: json!({"error": code, "error_description": description}).to_string(),
        json: true,
        log: format!("oauth token refused: {log}"),
    };
    let grant = field("grant_type");
    if grant != "client_credentials" {
        return error(400, "unsupported_grant_type", "linear-mock only supports grant_type=client_credentials",
                     format!("grant_type {:?}", grant.chars().take(40).collect::<String>()));
    }
    if field("client_id").is_empty() || field("client_secret").is_empty() {
        return error(400, "invalid_request", "client_id and client_secret are required", "client_id or client_secret missing".into());
    }
    let (Some((id, secret)), Some(token)) = (&cfg.oauth_client, &cfg.app_token) else {
        return error(401, "invalid_client", "Client authentication failed", "MOCK_CLIENT_ID is not set".into());
    };
    if field("client_id") != id || field("client_secret") != secret {
        return error(401, "invalid_client", "Client authentication failed", "wrong client credentials".into());
    }
    let scope = match field("scope") {
        "" => "read",
        s => s,
    };
    Reply {
        status: 200,
        body: json!({"access_token": token, "token_type": "Bearer", "expires_in": cfg.token_expires_in, "scope": scope})
            .to_string(),
        json: true,
        log: format!("oauth token issued (client_credentials, scope {:?})", scope.chars().take(80).collect::<String>()),
    }
}

/// Which credential a request used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Caller {
    /// The bare personal API key (MOCK_API_KEY).
    User,
    /// "Bearer <MOCK_APP_TOKEN>" (OAuth app, actor=app).
    App,
}

impl Caller {
    fn name(self) -> &'static str {
        match self {
            Caller::User => "user",
            Caller::App => "app",
        }
    }
}

/// The Authorization header -> Caller, or why it is rejected (a log text that never holds a credential).
fn authenticate(auth: Option<&str>, cfg: &Config) -> Result<Caller, &'static str> {
    let Some(auth) = auth else {
        return Err("no Authorization");
    };
    let bearer = auth.split_once(' ').filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer")).map(|(_, rest)| rest);
    let app = cfg.app_token.as_deref();
    match (bearer, app) {
        _ if auth == cfg.api_key => Ok(Caller::User),
        (Some(t), Some(app)) if t == app => Ok(Caller::App),
        (Some(t), _) if t == cfg.api_key => Err("personal API key sent as Bearer"),
        (None, Some(app)) if auth == app => Err("app token sent without Bearer"),
        (Some(_), None) => Err("Bearer token, but MOCK_APP_TOKEN is not set"),
        _ => Err("wrong Authorization"),
    }
}

fn graphql(auth: Option<&str>, body: &[u8], cfg: &Config, now: &str) -> Reply {
    let caller = match authenticate(auth, cfg) {
        Ok(c) => c,
        Err(why) => return Reply { status: 401, body: auth_error_body(), json: true, log: format!("rejected: {why}") },
    };
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
        let message =
            format!("linear-mock only answers TriageState, StateByType, IssueCreate, IssueById, CommentCreate and IssueStates; got {head:?}");
        return Reply {
            status: 200,
            body: error_body("GRAPHQL_VALIDATION_FAILED", &message),
            json: true,
            log: format!("unknown operation {head:?}"),
        };
    };
    let result = match op {
        Op::TriageState => triage_state(vars, cfg),
        Op::StateByType => state_by_type(vars, cfg),
        Op::IssueCreate => issue_create(vars, cfg, now),
        Op::IssueById => issue_by_id(vars, cfg),
        Op::CommentCreate => comment_create(vars, cfg, now),
        Op::IssueStates => issue_states(vars, cfg),
    };
    match result {
        Ok((data, detail)) => Reply {
            status: 200,
            body: json!({"data": data}).to_string(),
            json: true,
            log: format!("{} as {} ok: {detail}", op.name(), caller.name()),
        },
        Err(e) => Reply {
            status: 200,
            body: e.body(),
            json: true,
            log: format!("{} as {} error {}: {}", op.name(), caller.name(), e.code, e.message),
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

/// `workflowStates` filtered by team and type (the job's create_task lookup): the
/// triage state for "triage", Todo ("state-todo", position 1) for "unstarted";
/// any other type or team -> no nodes.
fn state_by_type(vars: &Value, cfg: &Config) -> OpResult {
    let team = str_field(vars, "team");
    let Some(kind) = vars.get("type").and_then(Value::as_str) else {
        return Err(GqlError::new("GRAPHQL_VALIDATION_FAILED", "StateByType needs variables.type (a string)"));
    };
    let nodes = match kind {
        _ if team != cfg.team_id => vec![],
        "triage" => vec![json!({"id": TRIAGE_STATE_ID, "name": "Triage", "type": "triage", "position": 0})],
        "unstarted" => vec![json!({"id": TODO_STATE_ID, "name": "Todo", "type": "unstarted", "position": 1})],
        _ => vec![],
    };
    let detail = format!("team {team:?}, type {kind:?}, {} state(s)", nodes.len());
    Ok((json!({"workflowStates": {"nodes": nodes}}), detail))
}

/// Issue id: "mock-<creation time digits>-<n>". The time part keeps ids unique when
/// issues.json is deleted or an older copy is saved over it and numbering restarts,
/// so a job that still holds an old id never gets another item's issue.
fn issue_id(now: &str, n: u64) -> String {
    let stamp: String = now.chars().filter(char::is_ascii_digit).collect();
    format!("mock-{stamp}-{n}")
}

/// Linear's answer to an IssueCreateInput.id that is not a UUID v4 (2026-11-05).
fn id_not_uuid(id: &Value) -> GqlError {
    let ext = json!({
        "validationErrors": [{"value": id, "property": "id", "children": [],
                              "constraints": {"isUuid": "id must be a UUID"}}],
        "type": "invalid input", "userError": true, "userPresentableMessage": "id must be a UUID.",
    });
    GqlError { code: "INVALID_INPUT", message: "Argument Validation Error".into(), path: Some("issueCreate"),
               ext: ext.as_object().cloned().unwrap_or_default() }
}

fn issue_create(vars: &Value, cfg: &Config, now: &str) -> OpResult {
    let input = input(vars, "issueCreate")?;
    // input.id: optional, as in Linear; a UUID v4 that becomes the issue id.
    let own_id = match input.get("id").filter(|v| !v.is_null()) {
        None => None,
        Some(v) => match v.as_str().filter(|s| is_uuid_v4(s)) {
            Some(s) => Some(s.to_string()),
            None => return Err(id_not_uuid(v)),
        },
    };
    let team = str_field(input, "teamId");
    if team != cfg.team_id {
        return Err(GqlError::new("INVALID_INPUT", format!("teamId {team:?} does not exist (the mock team is MOCK_TEAM_ID)")));
    }
    // No stateId: Triage (Linear would pick the team's default state). state-todo: a task, straight into Todo.
    let state = match input.get("stateId").filter(|v| !v.is_null()) {
        None => MockState::Triage,
        Some(s) if s.as_str() == Some(TRIAGE_STATE_ID) => MockState::Triage,
        Some(s) if s.as_str() == Some(TODO_STATE_ID) => MockState::Todo,
        Some(s) => {
            return Err(GqlError::new("INVALID_INPUT", format!(
                "stateId {s} does not exist (the states are {TRIAGE_STATE_ID:?} and {TODO_STATE_ID:?}, from TriageState or StateByType)")));
        }
    };
    // assigneeId (a Linear user id; the mock has no users and keeps it as the assignee) and dueDate, when given.
    let assignee = nonempty(str_field(input, "assigneeId")).unwrap_or("").to_string();
    let due = nonempty(str_field(input, "dueDate")).unwrap_or("").to_string();
    let title = str_field(input, "title");
    if title.trim().is_empty() {
        return Err(GqlError::new("INVALID_INPUT", "issueCreate needs a non-empty title"));
    }
    if title.contains(FAIL_CREATE) {
        // Failure switch (module doc): a refused create, shaped like Linear's user errors.
        return Err(GqlError::user("INPUT_ERROR", format!("linear-mock: create refused (title contains {FAIL_CREATE})"),
                                  "issueCreate", format!("Issue creation refused: the title contains {FAIL_CREATE}.")));
    }
    let mut f = load(&cfg.data_dir)?;
    if let Some(id) = &own_id
        && f.issues.iter().any(|i| i.id.eq_ignore_ascii_case(id))
    {
        // Linear, 2026-11-05 (T15): HTTP 200, data null, nothing created, no issue in the answer.
        return Err(GqlError::user("INPUT_ERROR", "conflict on insert of Issue", "issueCreate",
                                  format!("Entity Issue with id {id} already exists.")));
    }
    let mut n = f.next.max(1);
    while f.issues.iter().any(|i| i.id == issue_id(now, n) || i.identifier == format!("MOCK-{n}")) {
        n += 1;
    }
    let identifier = format!("MOCK-{n}");
    let issue = Issue {
        id: own_id.unwrap_or_else(|| issue_id(now, n)),
        identifier: identifier.clone(),
        url: format!("{URL_BASE}{identifier}"),
        title: title.into(),
        description: str_field(input, "description").into(),
        created: now.into(),
        state,
        assignee,
        due,
        reason: String::new(),
        actor: String::new(),
        changed: String::new(),
        completed: String::new(),
        canceled: String::new(),
        comments: vec![],
        extra: Map::new(),
    };
    let reply = json!({"id": issue.id, "identifier": issue.identifier, "url": issue.url});
    f.next = n + 1;
    f.issues.push(issue);
    save(&cfg.data_dir, &f)?;
    Ok((json!({"issueCreate": {"success": true, "issue": reply}}), identifier))
}

/// `issue(id:)`: by id or identifier, as Linear accepts both.
fn issue_by_id(vars: &Value, cfg: &Config) -> OpResult {
    let id = vars
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| GqlError::new("GRAPHQL_VALIDATION_FAILED", "issue needs variables.id (a string)"))?;
    let f = load(&cfg.data_dir)?;
    let Some(i) = f.issues.iter().find(|i| i.id.eq_ignore_ascii_case(id) || i.identifier == id) else {
        return Err(GqlError::user("INPUT_ERROR", "Entity not found: Issue", "issue",
                                  "Could not find referenced Issue.".into()));
    };
    Ok((json!({"issue": {"id": i.id, "identifier": i.identifier, "url": i.url}}), i.identifier.clone()))
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

/// Sort nodes newest first by createdAt, as Linear returns history and comments.
/// Times that do not parse go last; equal times keep their order.
fn newest_first(nodes: &mut [Value]) {
    let at = |v: &Value| chrono::DateTime::parse_from_rfc3339(v["createdAt"].as_str().unwrap_or("")).ok();
    nodes.sort_by(|a, b| at(b).cmp(&at(a)));
}

/// `t` (RFC 3339) plus `secs`, as UTC "YYYY-MM-DDTHH:MM:SSZ"; None when `t` does not parse.
fn plus_secs(t: &str, secs: i64) -> Option<String> {
    let dt = chrono::DateTime::parse_from_rfc3339(t).ok()? + chrono::Duration::seconds(secs);
    Some(dt.with_timezone(&chrono::Utc).format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// One issue in the shape of Linear's IssueStates node (see the module doc for the mapping).
fn issue_node(i: &Issue) -> Value {
    let (state_type, state_name) = i.state.linear();
    let when = nonempty(&i.changed).unwrap_or(i.created.trim());
    let who = nonempty(&i.actor).unwrap_or(DEFAULT_ACTOR);
    let completed = (i.state == MockState::Done).then(|| nonempty(&i.completed).unwrap_or(when).to_string());
    let canceled = match i.state {
        MockState::Declined | MockState::Duplicate => Some(nonempty(&i.canceled).unwrap_or(when).to_string()),
        MockState::AcceptedCanceled => nonempty(&i.canceled).map(String::from).or_else(|| plus_secs(when, CANCEL_AFTER_SECS)),
        _ => None,
    };
    let entry = |at: &str, from: Value, to: Value| {
        json!({"createdAt": at, "actor": {"name": who}, "botActor": null, "fromState": from, "toState": to})
    };
    let mut history: Vec<Value> = match i.state {
        MockState::Triage | MockState::Todo => vec![],
        // Mark as duplicate: Linear's entry holds the relation only, no states.
        MockState::Duplicate => vec![entry(when, Value::Null, Value::Null)],
        // Accept to Backlog, later Cancel: two entries, like TRI-1 on real Linear (2026-11-05).
        MockState::AcceptedCanceled => vec![
            entry(when, json!({"type": "triage"}), json!({"type": "backlog", "name": "Backlog"})),
            entry(canceled.as_deref().unwrap_or(when), json!({"type": "backlog"}),
                  json!({"type": state_type, "name": state_name})),
        ],
        _ => vec![entry(when, json!({"type": "triage"}), json!({"type": state_type, "name": state_name}))],
    };
    let mut comments: Vec<Value> = i
        .comments
        .iter()
        .map(|c| json!({"body": c.body, "createdAt": c.at, "user": {"name": BOT_USER}}))
        .collect();
    if let Some(reason) = nonempty(&i.reason) {
        let at = if i.state == MockState::AcceptedCanceled { canceled.as_deref().unwrap_or(when) } else { when };
        comments.push(json!({"body": reason, "createdAt": at, "user": {"name": who}}));
    }
    newest_first(&mut history);
    newest_first(&mut comments);
    json!({
        "id": i.id,
        "identifier": i.identifier,
        "url": i.url,
        "state": {"type": state_type, "name": state_name},
        "assignee": nonempty(&i.assignee).map(|a| json!({"name": a})),
        "dueDate": nonempty(&i.due),
        "triagedAt": (!matches!(i.state, MockState::Triage | MockState::Todo)).then_some(when),
        "createdAt": nonempty(&i.created),
        "startedAt": null,
        "completedAt": completed,
        "canceledAt": canceled,
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
    const APP: &str = "lin_oauth_test";
    const TEAM: &str = "team-1";
    const CLIENT_ID: &str = "mock-client";
    const CLIENT_SECRET: &str = "mock-secret+/=";

    // The documents exactly as the job sends them (src/triage/tracker.rs, 2026-11-04;
    // IssueById 2026-11-05; IssueStates with the four timestamps 2026-11-05).
    const Q_ISSUE_BY_ID: &str = "query IssueById($id: String!) {
  issue(id: $id) { id identifier url }
}";
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
      triagedAt
      createdAt
      startedAt
      completedAt
      canceledAt
      history(first: $nested) { nodes { createdAt actor { name } botActor { name } fromState { type } toState { type name } } }
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
            Config { api_key: KEY.into(), app_token: Some(APP.into()), team_id: TEAM.into(), data_dir: self.0.clone(),
                     oauth_client: Some((CLIENT_ID.into(), CLIENT_SECRET.into())), token_expires_in: DEFAULT_TOKEN_EXPIRES_IN }
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
        assert!(!r.log.contains(KEY) && !r.log.contains(APP), "log must not hold a credential: {}", r.log);
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
        let bearer_key = format!("Bearer {KEY}");
        let bearer_two_spaces = format!("Bearer  {APP}");
        let bearer_other = "Bearer lin_oauth_other".to_string();
        let rejected = [None, Some("wrong"), Some(bearer_key.as_str()), Some(""), Some(APP),
                        Some(bearer_two_spaces.as_str()), Some(bearer_other.as_str()), Some("Bearer ")];
        for auth in rejected {
            let (status, v) = post(&cfg, auth, M_ISSUE_CREATE,
                                   json!({"input": {"teamId": TEAM, "title": "t", "stateId": TRIAGE_STATE_ID}}));
            assert_eq!(status, 401, "{auth:?}");
            assert_eq!(v, fixture);
        }
        // Without MOCK_APP_TOKEN no Bearer value is accepted.
        let no_app = Config { app_token: None, ..cfg.clone() };
        assert_eq!(post(&no_app, Some(&format!("Bearer {APP}")), Q_TRIAGE_STATE, json!({"team": TEAM})).0, 401);
        assert!(!d.file().exists(), "a rejected call must not write");
    }

    #[test]
    fn auth_rejection_reasons_never_hold_a_credential() {
        let cfg = TestDir::new().cfg();
        let why = |auth: Option<&str>| authenticate(auth, &cfg).unwrap_err();
        assert_eq!(why(None), "no Authorization");
        assert_eq!(why(Some(&format!("Bearer {KEY}"))), "personal API key sent as Bearer");
        assert_eq!(why(Some(APP)), "app token sent without Bearer");
        assert_eq!(why(Some("lin_api_other")), "wrong Authorization");
        let no_app = Config { app_token: None, ..cfg.clone() };
        assert_eq!(authenticate(Some(&format!("Bearer {APP}")), &no_app), Err("Bearer token, but MOCK_APP_TOKEN is not set"));
    }

    #[test]
    fn app_token_as_bearer_is_accepted() {
        let d = TestDir::new();
        let cfg = d.cfg();
        assert_eq!(authenticate(Some(KEY), &cfg), Ok(Caller::User));
        for auth in [format!("Bearer {APP}"), format!("bearer {APP}"), format!("BEARER {APP}")] {
            assert_eq!(authenticate(Some(&auth), &cfg), Ok(Caller::App), "{auth}");
        }
        let bearer = format!("Bearer {APP}");
        let (status, v) = post(&cfg, Some(&bearer), M_ISSUE_CREATE,
                               json!({"input": {"teamId": TEAM, "title": "by app", "stateId": TRIAGE_STATE_ID}}));
        assert_eq!(status, 200);
        assert_eq!(v.pointer("/data/issueCreate/issue/identifier"), Some(&json!("MOCK-1")));
        let id1 = issue_id(NOW, 1);
        let (status, _) = post(&cfg, Some(&bearer), M_COMMENT_CREATE,
                               json!({"input": {"issueId": id1, "body": "**exploit-watch**: c"}}));
        assert_eq!(status, 200);
        // The API key reads what the app wrote: one store, whichever credential wrote it.
        let nodes = states(&cfg, &[id1.as_str()]);
        assert_eq!(nodes[0]["comments"]["nodes"][0]["user"], json!({"name": "exploit-watch bot"}));
        let body = json!({"query": Q_TRIAGE_STATE, "variables": {"team": TEAM}}).to_string();
        let r = handle("POST", "/graphql", Some(&bearer), body.as_bytes(), &cfg, NOW);
        assert!(r.log.starts_with("TriageState as app ok"), "{}", r.log);
        let r = handle("POST", "/graphql", Some(KEY), body.as_bytes(), &cfg, NOW);
        assert!(r.log.starts_with("TriageState as user ok"), "{}", r.log);
    }

    // ------------------------------------------------ POST /oauth/token (client_credentials)

    /// The form the job sends (triage/linear_oauth.rs), with the mock's client pair.
    fn token_form(id: &str, secret: &str) -> String {
        format!("grant_type=client_credentials&client_id={id}&client_secret={}&scope=read%2Cwrite%2Cissues%3Acreate%2Ccomments%3Acreate",
                secret.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D"))
    }

    fn token(cfg: &Config, body: &str) -> (u16, Value, String) {
        let r = handle("POST", "/oauth/token", None, body.as_bytes(), cfg, NOW);
        assert!(r.json);
        assert!(!r.log.contains(CLIENT_SECRET) && !r.log.contains("mock-secret") && !r.log.contains(APP),
                "log must not hold a secret: {}", r.log);
        (r.status, serde_json::from_str(&r.body).unwrap(), r.log)
    }

    #[test]
    fn oauth_token_issues_the_app_token() {
        let d = TestDir::new();
        let cfg = d.cfg();
        let (status, v, log) = token(&cfg, &token_form(CLIENT_ID, CLIENT_SECRET));
        assert_eq!(status, 200);
        assert_eq!(v, json!({"access_token": APP, "token_type": "Bearer", "expires_in": 2_592_000,
                             "scope": "read,write,issues:create,comments:create"}));
        assert_eq!(log, "oauth token issued (client_credentials, scope \"read,write,issues:create,comments:create\")");
        // The issued token works on /graphql as the app.
        let bearer = format!("Bearer {}", v["access_token"].as_str().unwrap());
        assert_eq!(authenticate(Some(&bearer), &cfg), Ok(Caller::App));
        // No scope asked: "read"; MOCK_TOKEN_EXPIRES_IN is passed through.
        let short = Config { token_expires_in: 90, ..cfg.clone() };
        let (_, v, _) = token(&short, &format!("grant_type=client_credentials&client_id={CLIENT_ID}&client_secret={}",
                                                CLIENT_SECRET.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")));
        assert_eq!((v["scope"].clone(), v["expires_in"].clone()), (json!("read"), json!(90)));
        assert!(!d.file().exists(), "issuing a token writes nothing");
    }

    #[test]
    fn oauth_token_errors_are_oauth_bodies() {
        let cfg = TestDir::new().cfg();
        let err = |body: &str| {
            let (status, v, log) = token(&cfg, body);
            (status, v["error"].as_str().unwrap_or("").to_string(), log)
        };
        assert_eq!(err(&token_form(CLIENT_ID, "wrong")), (401, "invalid_client".into(), "oauth token refused: wrong client credentials".into()));
        assert_eq!(err(&token_form("other", CLIENT_SECRET)).0, 401);
        assert_eq!(err(&token_form(CLIENT_ID, CLIENT_SECRET).replace("client_credentials", "authorization_code")).1,
                   "unsupported_grant_type");
        assert_eq!(err("").1, "unsupported_grant_type");
        assert_eq!(err("grant_type=client_credentials&client_id=x").1, "invalid_request");
        // Unescaped "+" in the secret is a space, so it does not match.
        assert_eq!(err(&format!("grant_type=client_credentials&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}")).0, 401);
        let no_client = Config { oauth_client: None, ..cfg.clone() };
        let (status, v, log) = token(&no_client, &token_form(CLIENT_ID, CLIENT_SECRET));
        assert_eq!((status, v["error"].as_str()), (401, Some("invalid_client")));
        assert_eq!(log, "oauth token refused: MOCK_CLIENT_ID is not set");
        assert_eq!(handle("GET", "/oauth/token", None, b"", &cfg, NOW).status, 404);
    }

    #[test]
    fn form_decoding() {
        assert_eq!(form_decode("a+b%2B%2f%3D%zz%4"), "a b+/=%zz%4");
        let f = form_fields(b"x=1&y=&z&x=2&k%20e=v%26");
        assert_eq!(Value::Object(f), json!({"x": "2", "y": "", "z": "", "k e": "v&"}));
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
        for k in ["assignee", "due", "reason", "actor", "changed", "completed", "canceled"] {
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

    const UUID: &str = "3d4f6a2e-8b1c-4e7a-9f20-5c6b7a8d9e01";

    fn create_with_id(cfg: &Config, id: Value, title: &str) -> Value {
        let input = json!({"id": id, "teamId": TEAM, "title": title, "description": "d", "stateId": TRIAGE_STATE_ID});
        gql(cfg, M_ISSUE_CREATE, json!({"input": input}))
    }

    #[test]
    fn issue_create_with_id_stores_it_and_refuses_a_second() {
        let d = TestDir::new();
        let cfg = d.cfg();
        assert_eq!(create_with_id(&cfg, json!(UUID), "first"), json!({"data": {"issueCreate": {"success": true,
            "issue": {"id": UUID, "identifier": "MOCK-1", "url": "http://linear-mock.invalid/issue/MOCK-1"}}}}));
        let before = fs::read(d.file()).unwrap();

        // Same id again (a retry after a lost answer): Linear's T15 answer, nothing written.
        let (status, v) = post(&cfg, Some(KEY), M_ISSUE_CREATE,
                               json!({"input": {"id": UUID, "teamId": TEAM, "title": "retry", "stateId": TRIAGE_STATE_ID}}));
        assert_eq!(status, 200);
        let t15: Value = serde_json::from_str(&format!(r#"{{"errors":[{{"message":"conflict on insert of Issue",
            "path":["issueCreate"],"extensions":{{"type":"invalid input","code":"INPUT_ERROR","statusCode":400,
            "userError":true,"userPresentableMessage":"Entity Issue with id {UUID} already exists."}}}}],"data":null}}"#))
            .unwrap();
        assert_eq!(v, t15, "T15 body without `locations`");
        assert_eq!(fs::read(d.file()).unwrap(), before, "no second issue");
        let upper = create_with_id(&cfg, json!(UUID.to_ascii_uppercase()), "upper");
        assert_eq!(error_code(&upper), "INPUT_ERROR", "ids compare case-insensitively");

        // Without an id the mock still makes one up; null counts as no id.
        let v = create_with_id(&cfg, Value::Null, "second");
        assert_eq!(v.pointer("/data/issueCreate/issue/id"), Some(&json!(issue_id(NOW, 2))));
        let f = d.read();
        assert_eq!((f["issues"][0]["id"].as_str(), f["issues"][0]["title"].as_str()), (Some(UUID), Some("first")));
        assert_eq!(f["issues"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn issue_create_refuses_an_id_that_is_not_uuid_v4() {
        let d = TestDir::new();
        let cfg = d.cfg();
        // The v5 id Linear refused on 2026-11-05, other versions, junk.
        for id in [json!("e8caf09b-8627-59c1-8257-e4112feff854"), json!("3d4f6a2e-8b1c-1e7a-9f20-5c6b7a8d9e01"),
                   json!("3d4f6a2e-8b1c-4e7a-7f20-5c6b7a8d9e01"), json!("3d4f6a2e8b1c4e7a9f205c6b7a8d9e01"),
                   json!("not-a-uuid"), json!(""), json!(42)] {
            let v = create_with_id(&cfg, id.clone(), "t");
            assert_eq!(error_code(&v), "INVALID_INPUT", "{id}");
            assert_eq!(v["errors"][0]["message"], "Argument Validation Error");
            assert_eq!(v["errors"][0]["path"], json!(["issueCreate"]));
            assert_eq!(v["errors"][0]["extensions"]["userPresentableMessage"], "id must be a UUID.");
            assert_eq!(v["errors"][0]["extensions"]["validationErrors"][0]["value"], id);
        }
        assert!(!d.file().exists());
        assert!(is_uuid_v4(UUID) && is_uuid_v4(&UUID.to_ascii_uppercase()));
    }

    #[test]
    fn issue_by_id_finds_by_id_or_identifier() {
        let d = TestDir::new();
        let cfg = d.cfg();
        create_with_id(&cfg, json!(UUID), "a");
        let want = json!({"data": {"issue": {"id": UUID, "identifier": "MOCK-1",
                                             "url": "http://linear-mock.invalid/issue/MOCK-1"}}});
        assert_eq!(gql(&cfg, Q_ISSUE_BY_ID, json!({"id": UUID})), want);
        assert_eq!(gql(&cfg, Q_ISSUE_BY_ID, json!({"id": "MOCK-1"})), want);
        let v = gql(&cfg, Q_ISSUE_BY_ID, json!({"id": "0f0e0d0c-0b0a-4908-8706-050403020100"}));
        assert_eq!(error_code(&v), "INPUT_ERROR");
        assert_eq!(v["errors"][0]["message"], "Entity not found: Issue");
        assert_eq!(v["errors"][0]["path"], json!(["issue"]));
        assert_eq!(error_code(&gql(&cfg, Q_ISSUE_BY_ID, json!({}))), "GRAPHQL_VALIDATION_FAILED");
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
            "state": {"type": "triage", "name": "Triage"}, "assignee": null, "dueDate": null, "triagedAt": null,
            "createdAt": NOW, "startedAt": null, "completedAt": null, "canceledAt": null,
            "createdAt": NOW, "startedAt": null, "completedAt": null, "canceledAt": null,
            "history": {"nodes": []},
            "comments": {"nodes": [{"body": "**exploit-watch**: c", "createdAt": NOW, "user": {"name": "exploit-watch bot"}}]}
        })]);
        assert!(states(&cfg, &[]).is_empty());
        // Missing file: no issues, not an error.
        let empty = TestDir::new();
        assert!(states(&empty.cfg(), &["mock-1"]).is_empty());
        assert_eq!(error_code(&gql(&cfg, Q_ISSUE_STATES, json!({"first": 1}))), "GRAPHQL_VALIDATION_FAILED");
    }

    /// A file as a person would leave it after triaging four issues by hand, marking one as
    /// duplicate, and accepting one and canceling it later.
    fn hand_edited(d: &TestDir) {
        let issue = |n: u32, state: &str, extra: Value| {
            let mut i = json!({"id": format!("mock-{n}"), "identifier": format!("MOCK-{n}"),
                               "url": format!("{URL_BASE}MOCK-{n}"), "title": "t", "description": "",
                               "created": "2026-11-04T08:00:00Z", "state": state, "assignee": "", "due": "",
                               "reason": "", "actor": "", "changed": "", "completed": "", "canceled": "",
                               "comments": [{"at": "2026-11-04T08:30:00Z", "body": "**exploit-watch**: changed"}]});
            for (k, v) in extra.as_object().unwrap() {
                i[k] = v.clone();
            }
            i
        };
        let f = json!({"next": 7, "issues": [
            issue(1, "triage", json!({})),
            issue(2, "accepted", json!({"assignee": "Henry", "due": "2026-11-10", "actor": "James",
                                        "changed": "2026-11-04T09:00:00Z"})),
            issue(3, "completed", json!({"assignee": "Henry"})),
            issue(4, "canceled", json!({"reason": "  Not relevant: test harness only.\n", "actor": "Henry",
                                        "changed": "2026-11-04T10:00:00Z", "item_key": "CISA KEV:CVE-2026-1234"})),
            issue(5, "duplicate", json!({"actor": "James", "changed": "2026-11-04T11:00:00Z"})),
            issue(6, "accepted-canceled", json!({"assignee": "Henry", "due": "2026-11-12", "actor": "Henry",
                                                 "changed": "2026-11-04T09:30:00Z"})),
        ]});
        fs::write(d.file(), serde_json::to_string_pretty(&f).unwrap()).unwrap();
    }

    #[test]
    fn state_mapping_history_and_reason_comment() {
        let d = TestDir::new();
        let cfg = d.cfg();
        hand_edited(&d);
        let nodes = states(&cfg, &["mock-1", "mock-2", "mock-3", "mock-4", "mock-5", "mock-6"]);
        let st: Vec<(&str, &str)> = nodes
            .iter()
            .map(|n| (n["state"]["type"].as_str().unwrap(), n["state"]["name"].as_str().unwrap()))
            .collect();
        assert_eq!(st, [("triage", "Triage"), ("unstarted", "Todo"), ("completed", "Done"), ("canceled", "Canceled"),
                        ("duplicate", "Duplicate"), ("canceled", "Canceled")]);
        // createdAt, completedAt (done), canceledAt (declined, duplicate: at triagedAt, as Linear does).
        let times: Vec<[Value; 4]> = nodes
            .iter()
            .map(|n| [n["createdAt"].clone(), n["startedAt"].clone(), n["completedAt"].clone(), n["canceledAt"].clone()])
            .collect();
        let c = json!("2026-11-04T08:00:00Z");
        assert_eq!(times[..5], [
            [c.clone(), Value::Null, Value::Null, Value::Null],
            [c.clone(), Value::Null, Value::Null, Value::Null],
            [c.clone(), Value::Null, c.clone(), Value::Null],
            [c.clone(), Value::Null, Value::Null, json!("2026-11-04T10:00:00Z")],
            [c.clone(), Value::Null, Value::Null, json!("2026-11-04T11:00:00Z")],
        ]);
        // Accepted, then canceled: canceledAt 1 h after triagedAt, two history entries newest first.
        assert_eq!(nodes[5]["triagedAt"], json!("2026-11-04T09:30:00Z"));
        assert_eq!(nodes[5]["canceledAt"], json!("2026-11-04T10:30:00Z"));
        assert_eq!(nodes[5]["history"]["nodes"], json!([
            {"createdAt": "2026-11-04T10:30:00Z", "actor": {"name": "Henry"}, "botActor": null,
             "fromState": {"type": "backlog"}, "toState": {"type": "canceled", "name": "Canceled"}},
            {"createdAt": "2026-11-04T09:30:00Z", "actor": {"name": "Henry"}, "botActor": null,
             "fromState": {"type": "triage"}, "toState": {"type": "backlog", "name": "Backlog"}},
        ]));

        assert_eq!(nodes[0]["history"]["nodes"], json!([]));
        assert_eq!(nodes[0]["triagedAt"], Value::Null);
        assert_eq!(nodes[1]["assignee"], json!({"name": "Henry"}));
        assert_eq!(nodes[1]["dueDate"], json!("2026-11-10"));
        assert_eq!(nodes[1]["triagedAt"], json!("2026-11-04T09:00:00Z"));
        assert_eq!(nodes[1]["history"]["nodes"], json!([{"createdAt": "2026-11-04T09:00:00Z", "actor": {"name": "James"},
            "botActor": null, "fromState": {"type": "triage"}, "toState": {"type": "unstarted", "name": "Todo"}}]));
        // No actor / changed: "mock user" at the creation time.
        assert_eq!(nodes[2]["history"]["nodes"][0]["actor"], json!({"name": "mock user"}));
        assert_eq!(nodes[2]["history"]["nodes"][0]["createdAt"], json!("2026-11-04T08:00:00Z"));
        assert_eq!(nodes[2]["triagedAt"], json!("2026-11-04T08:00:00Z"));
        assert_eq!(nodes[2]["comments"]["nodes"].as_array().unwrap().len(), 1);

        // The reason is a separate comment; comments come newest first.
        assert_eq!(nodes[3]["comments"]["nodes"], json!([
            {"body": "Not relevant: test harness only.", "createdAt": "2026-11-04T10:00:00Z", "user": {"name": "Henry"}},
            {"body": "**exploit-watch**: changed", "createdAt": "2026-11-04T08:30:00Z", "user": {"name": "exploit-watch bot"}},
        ]));
        // Mark as duplicate: an entry without states, by the person, at triagedAt.
        assert_eq!(nodes[4]["triagedAt"], json!("2026-11-04T11:00:00Z"));
        assert_eq!(nodes[4]["history"]["nodes"], json!([{"createdAt": "2026-11-04T11:00:00Z", "actor": {"name": "James"},
            "botActor": null, "fromState": null, "toState": null}]));
    }

    #[test]
    fn nested_nodes_newest_first() {
        let mut v = vec![json!({"createdAt": "2026-11-04T08:00:00Z", "n": 1}), json!({"createdAt": "bad", "n": 2}),
                         json!({"createdAt": "2026-11-04T10:00:00+02:00", "n": 3}), json!({"createdAt": "2026-11-04T09:00:00Z", "n": 4})];
        newest_first(&mut v);
        let order: Vec<i64> = v.iter().map(|n| n["n"].as_i64().unwrap()).collect();
        assert_eq!(order, [4, 1, 3, 2], "10:00+02:00 is 08:00Z; equal times keep their order; unparsable last");
        // Several job comments plus a reason written later: newest first.
        let d = TestDir::new();
        let cfg = d.cfg();
        hand_edited(&d);
        let mut f = d.read();
        f["issues"][3]["comments"]
            .as_array_mut()
            .unwrap()
            .push(json!({"at": "2026-11-04T12:00:00Z", "body": "**exploit-watch**: again"}));
        fs::write(d.file(), f.to_string()).unwrap();
        let n = &states(&cfg, &["mock-4"])[0];
        let times: Vec<&str> = n["comments"]["nodes"].as_array().unwrap().iter().map(|c| c["createdAt"].as_str().unwrap()).collect();
        assert_eq!(times, ["2026-11-04T12:00:00Z", "2026-11-04T10:00:00Z", "2026-11-04T08:30:00Z"]);
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
        // Node id-TRI-15 of tests/fixtures/linear_issues_states_triage.json in the job repo (shaped like
        // real Linear on 2026-11-04; comments trimmed to one), plus the four timestamps the query asks
        // for since 2026-11-05 (keys as in linear_issues_states_timestamps.json; only keys are compared).
        let linear: Value = serde_json::from_str(r#"{
          "id": "id-TRI-15", "identifier": "TRI-15", "url": "https://linear.app/<workspace>/issue/TRI-15/x",
          "state": { "type": "canceled", "name": "Canceled" }, "assignee": { "name": "x" }, "dueDate": null,
          "triagedAt": "2026-11-04T10:33:41.207Z",
          "createdAt": null, "startedAt": null, "completedAt": null, "canceledAt": null,
          "history": { "nodes": [ { "createdAt": "2026-11-04T10:33:41.180Z", "actor": { "name": "Tran Trung Hau" },
                                    "botActor": null, "fromState": { "type": "triage" },
                                    "toState": { "type": "canceled", "name": "Canceled" } } ] },
          "comments": { "nodes": [ { "body": "Not relevant.", "createdAt": "2026-11-04T10:33:51.522Z",
                                     "user": { "name": "Tran Trung Hau" } } ] } }"#).unwrap();
        let d = TestDir::new();
        let cfg = d.cfg();
        hand_edited(&d);
        for n in states(&cfg, &["mock-1", "mock-2", "mock-3", "mock-4", "mock-5", "mock-6"]) {
            same_keys(&n, &linear, "");
        }
    }

    /// The job's parse_issue_node (src/triage/tracker.rs, 2026-11-05) reduced to the fields it
    /// derives: state (the job's IssueState: canceled is "canceled" when canceledAt is more than
    /// 5 s after triagedAt, else "declined"; without canceledAt the entry that left Triage
    /// decides); outside triage, changed = triagedAt and actor = the history entry at it (one
    /// that left Triage first), else the newest entry that left Triage; reason (declined only) =
    /// latest comment not starting with "**exploit-watch**" written from triagedAt - 5 s on,
    /// "Marked as duplicate" for a duplicate without one. Entry times are compared as text
    /// here (the mock writes one format).
    fn job_view(n: &Value) -> (String, String, String, String, String, String) {
        let s = |v: &Value, p: &str| v.pointer(p).and_then(Value::as_str).unwrap_or("").to_string();
        let t = |v: &str| chrono::DateTime::parse_from_rfc3339(v).ok();
        let empty = vec![];
        let history = n["history"]["nodes"].as_array().unwrap_or(&empty);
        let kind = s(n, "/state/type");
        let triaged_at = s(n, "/triagedAt");
        let exit = history.iter().filter(|h| s(h, "/fromState/type") == "triage").max_by_key(|h| s(h, "/createdAt"))
            .map(|h| s(h, "/toState/type")).unwrap_or_default();
        let after_accept = match (t(&triaged_at), t(&s(n, "/canceledAt"))) {
            (Some(a), Some(c)) => (c - a).num_milliseconds() > 5_000,
            _ => matches!(exit.as_str(), "backlog" | "unstarted" | "started" | "completed"),
        };
        let state = match kind.as_str() {
            "triage" => "triage",
            "backlog" | "unstarted" | "started" => "accepted",
            "completed" => "done",
            "canceled" if after_accept => "canceled",
            _ => "declined",
        }
        .to_string();
        let left = |h: &&Value| s(h, "/fromState/type") == "triage";
        let entry = history.iter().find(|h| left(h) && s(h, "/createdAt") == triaged_at)
            .or_else(|| history.iter().find(|h| s(h, "/createdAt") == triaged_at))
            .or_else(|| history.iter().filter(left).max_by_key(|h| s(h, "/createdAt")));
        let (actor, changed) = match (state.as_str(), entry) {
            ("triage", _) => (String::new(), String::new()),
            (_, e) => (e.map(|h| s(h, "/actor/name")).unwrap_or_default(),
                       if triaged_at.is_empty() { e.map(|h| s(h, "/createdAt")).unwrap_or_default() } else { triaged_at.clone() }),
        };
        let reason = if state == "declined" {
            let from = t(&changed).map(|c| c - chrono::Duration::seconds(5));
            let c = n["comments"]["nodes"].as_array().unwrap_or(&empty).iter()
                .filter(|c| !s(c, "/body").trim_start().starts_with("**exploit-watch**"))
                .filter(|c| from.is_none_or(|f| t(&s(c, "/createdAt")).is_some_and(|at| at >= f)))
                .max_by_key(|c| s(c, "/createdAt"))
                .map(|c| s(c, "/body").trim().to_string())
                .unwrap_or_default();
            if c.is_empty() && kind == "duplicate" { "Marked as duplicate".to_string() } else { c }
        } else {
            String::new()
        };
        (state, s(n, "/assignee/name"), s(n, "/dueDate"), reason, actor, changed)
    }

    #[test]
    fn job_reads_what_the_person_typed() {
        let d = TestDir::new();
        let cfg = d.cfg();
        hand_edited(&d);
        let views: Vec<_> =
            states(&cfg, &["mock-1", "mock-2", "mock-4", "mock-5", "mock-6"]).iter().map(job_view).collect();
        let v = |a: &str, b: &str, c: &str, e: &str, f: &str, g: &str| {
            (a.to_string(), b.to_string(), c.to_string(), e.to_string(), f.to_string(), g.to_string())
        };
        assert_eq!(views, vec![
            v("triage", "", "", "", "", ""),
            v("accepted", "Henry", "2026-11-10", "", "James", "2026-11-04T09:00:00Z"),
            v("declined", "", "", "Not relevant: test harness only.", "Henry", "2026-11-04T10:00:00Z"),
            v("declined", "", "", "Marked as duplicate", "James", "2026-11-04T11:00:00Z"),
            v("canceled", "Henry", "2026-11-12", "", "Henry", "2026-11-04T09:30:00Z"),
        ]);
    }

    /// accepted-canceled with hand-set times: canceledAt and the second entry follow
    /// `canceled`, a reason comment goes with the cancel; `completed` sets completedAt of done.
    #[test]
    fn accepted_canceled_and_hand_set_times() {
        let d = TestDir::new();
        let cfg = d.cfg();
        hand_edited(&d);
        let mut f = d.read();
        f["issues"][5]["canceled"] = json!("2026-11-05T07:04:43Z");
        f["issues"][5]["reason"] = json!("No longer needed.");
        f["issues"][2]["changed"] = json!("2026-11-04T09:00:00Z");
        f["issues"][2]["completed"] = json!("2026-11-04T09:00:05Z");
        fs::write(d.file(), f.to_string()).unwrap();
        let nodes = states(&cfg, &["mock-3", "mock-6"]);
        assert_eq!((&nodes[0]["triagedAt"], &nodes[0]["completedAt"]),
                   (&json!("2026-11-04T09:00:00Z"), &json!("2026-11-04T09:00:05Z")));
        let n = &nodes[1];
        assert_eq!(n["canceledAt"], json!("2026-11-05T07:04:43Z"));
        let entries: Vec<(&str, &str, &str)> = n["history"]["nodes"].as_array().unwrap().iter()
            .map(|h| (h["createdAt"].as_str().unwrap(), h["fromState"]["type"].as_str().unwrap(),
                      h["toState"]["type"].as_str().unwrap()))
            .collect();
        assert_eq!(entries, [("2026-11-05T07:04:43Z", "backlog", "canceled"), ("2026-11-04T09:30:00Z", "triage", "backlog")]);
        assert_eq!(n["comments"]["nodes"][0], json!({"body": "No longer needed.", "createdAt": "2026-11-05T07:04:43Z",
                                                     "user": {"name": "Henry"}}));
        assert_eq!(job_view(n).0, "canceled");
        // Without canceledAt the entry that left Triage (to backlog) still says canceled after Accept.
        let mut bare = n.clone();
        bare["canceledAt"] = Value::Null;
        assert_eq!(job_view(&bare).0, "canceled");
        assert_eq!(d.read()["issues"][5]["state"], "accepted-canceled", "written back as typed");
        // triagedAt that does not parse: no computed canceledAt.
        let mut f = d.read();
        f["issues"][5]["canceled"] = json!("");
        f["issues"][5]["changed"] = json!("yesterday");
        fs::write(d.file(), f.to_string()).unwrap();
        assert_eq!(states(&cfg, &["mock-6"])[0]["canceledAt"], Value::Null);
    }

    /// Failure switch: a title with FAIL-CREATE is refused like a Linear user error, nothing is
    /// written, and the next create still works.
    #[test]
    fn fail_create_switch() {
        let d = TestDir::new();
        let cfg = d.cfg();
        create(&cfg, "a");
        let before = fs::read(d.file()).unwrap();
        let v = create_with_id(&cfg, json!(UUID), "[CVE-2026-1] FAIL-CREATE test");
        assert_eq!(v, json!({"errors": [{"message": "linear-mock: create refused (title contains FAIL-CREATE)",
            "path": ["issueCreate"], "extensions": {"code": "INPUT_ERROR", "type": "invalid input", "statusCode": 400,
            "userError": true, "userPresentableMessage": "Issue creation refused: the title contains FAIL-CREATE."}}],
            "data": null}));
        assert_eq!(fs::read(d.file()).unwrap(), before, "nothing created");
        let body = json!({"query": M_ISSUE_CREATE, "variables": {"input": {"teamId": TEAM, "title": "FAIL-CREATE"}}});
        let r = handle("POST", "/graphql", Some(KEY), body.to_string().as_bytes(), &cfg, NOW);
        assert!(r.log.starts_with("IssueCreate as user error INPUT_ERROR: linear-mock: create refused"), "{}", r.log);
        assert_eq!(create(&cfg, "b").pointer("/data/issueCreate/issue/identifier"), Some(&json!("MOCK-2")));
        // The same UUID was never stored, so it can be used now.
        let v = create_with_id(&cfg, json!(UUID), "fail-create in lower case is no switch");
        assert_eq!(v.pointer("/data/issueCreate/issue/id"), Some(&json!(UUID)));
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
        assert_eq!(c.app_token, None, "MOCK_APP_TOKEN is optional");
        let app = |token: &str| {
            Config::from_vars(&|k: &str| match k {
                "MOCK_API_KEY" => Some("lin_api_k".into()),
                "MOCK_TEAM_ID" => Some("t".into()),
                "MOCK_APP_TOKEN" => Some(token.into()),
                _ => None,
            })
        };
        assert_eq!(app("").unwrap().app_token, None, "empty means unset");
        assert_eq!(app("lin_oauth_a").unwrap().app_token.as_deref(), Some("lin_oauth_a"));
        let same = app("lin_api_k").unwrap_err();
        assert!(same.contains("must differ") && !same.contains("lin_api_k"), "{same}");
        let personal = app("lin_api_other").unwrap_err();
        assert!(personal.contains("must not start with") && !personal.contains("other"), "{personal}");
        assert_eq!((c.oauth_client.clone(), c.token_expires_in), (None, 2_592_000), "no OAuth client by default");
        let oauth = |pairs: &[(&str, &str)]| {
            let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            Config::from_vars(&move |k: &str| match k {
                "MOCK_API_KEY" => Some("lin_api_k".into()),
                "MOCK_TEAM_ID" => Some("t".into()),
                _ => pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()),
            })
        };
        let c = oauth(&[("MOCK_APP_TOKEN", "lin_oauth_a"), ("MOCK_CLIENT_ID", "id"), ("MOCK_CLIENT_SECRET", "sec"),
                        ("MOCK_TOKEN_EXPIRES_IN", "120")]).unwrap();
        assert_eq!((c.oauth_client, c.token_expires_in), (Some(("id".into(), "sec".into())), 120));
        let e = oauth(&[("MOCK_CLIENT_ID", "id"), ("MOCK_CLIENT_SECRET", "sec")]).unwrap_err();
        assert!(e.contains("needs MOCK_APP_TOKEN") && !e.contains("sec\""), "{e}");
        let e = oauth(&[("MOCK_APP_TOKEN", "lin_oauth_a"), ("MOCK_CLIENT_ID", "id")]).unwrap_err();
        assert!(e.contains("set both or neither"), "{e}");
        assert!(oauth(&[("MOCK_TOKEN_EXPIRES_IN", "soon")]).unwrap_err().contains("MOCK_TOKEN_EXPIRES_IN"));
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
            for _ in 0..5 {
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

        let app = raw(port, &format!("POST /graphql HTTP/1.0\r\nAuthorization: Bearer {APP}\r\n\
                                      Content-Length: {}\r\n\r\n{body}", body.len()));
        assert!(app.starts_with("HTTP/1.0 200") || app.starts_with("HTTP/1.1 200"), "{app}");
        assert!(app.contains(r#""identifier":"MOCK-2""#), "{app}");
        let bare_app = raw(port, &format!("POST /graphql HTTP/1.0\r\nAuthorization: {APP}\r\n\
                                           Content-Length: {}\r\n\r\n{body}", body.len()));
        assert!(bare_app.contains(" 401 "), "{bare_app}");
        worker.join().unwrap();
        assert_eq!(d.read()["issues"].as_array().unwrap().len(), 2);
    }

    // ------------------------------------------------ tasks (create_task, 2026-11-06)

    /// The document exactly as the job's create_task sends it (src/triage/tracker.rs, 2026-11-06).
    const Q_STATE_BY_TYPE: &str = "query StateByType($team: ID!, $type: String!) {
  workflowStates(filter: { team: { id: { eq: $team } }, type: { eq: $type } }) {
    nodes { id name type position }
  }
}";

    #[test]
    fn state_by_type_lookup() {
        let d = TestDir::new();
        let cfg = d.cfg();
        let nodes = |team: &str, t: &str| gql(&cfg, Q_STATE_BY_TYPE, json!({"team": team, "type": t}));
        assert_eq!(nodes(TEAM, "unstarted"), json!({"data": {"workflowStates": {"nodes": [
            {"id": "state-todo", "name": "Todo", "type": "unstarted", "position": 1}]}}}));
        assert_eq!(nodes(TEAM, "triage").pointer("/data/workflowStates/nodes/0/id"), Some(&json!(TRIAGE_STATE_ID)));
        for (team, t) in [(TEAM, "completed"), ("other", "unstarted")] {
            assert_eq!(nodes(team, t), json!({"data": {"workflowStates": {"nodes": []}}}), "{team} {t}");
        }
        assert_eq!(error_code(&gql(&cfg, Q_STATE_BY_TYPE, json!({"team": TEAM}))), "GRAPHQL_VALIDATION_FAILED");
        // TriageState is still its own operation
        assert_eq!(gql(&cfg, Q_TRIAGE_STATE, json!({"team": TEAM})).pointer("/data/workflowStates/nodes/0/id"),
                   Some(&json!(TRIAGE_STATE_ID)));
    }

    /// The review reminder: created straight into Todo with an id, assignee and due date;
    /// a plain Todo, not triaged; a second create with the same id conflicts and
    /// IssueById returns it (the job's recovery path).
    #[test]
    fn task_create_into_todo_with_id() {
        let d = TestDir::new();
        let cfg = d.cfg();
        let input = json!({"id": UUID, "teamId": TEAM, "title": "Review monthly cyber threat report — November 2026",
                           "description": "- [ ] check", "stateId": TODO_STATE_ID, "assigneeId": "user-1",
                           "dueDate": "2026-12-03"});
        let v = gql(&cfg, M_ISSUE_CREATE, json!({"input": input}));
        assert_eq!(v.pointer("/data/issueCreate/issue/id"), Some(&json!(UUID)));
        let f = d.read();
        let i = &f["issues"][0];
        assert_eq!((i["state"].as_str(), i["assignee"].as_str(), i["due"].as_str()), (Some("todo"), Some("user-1"), Some("2026-12-03")));
        let n = &states(&cfg, &[UUID])[0];
        assert_eq!(n["state"], json!({"type": "unstarted", "name": "Todo"}));
        assert_eq!((n["triagedAt"].clone(), n["history"].clone()), (Value::Null, json!({"nodes": []})), "never in Triage");
        assert_eq!((n["assignee"].clone(), n["dueDate"].clone()), (json!({"name": "user-1"}), json!("2026-12-03")));

        let before = fs::read(d.file()).unwrap();
        assert_eq!(error_code(&gql(&cfg, M_ISSUE_CREATE, json!({"input": input}))), "INPUT_ERROR");
        assert_eq!(fs::read(d.file()).unwrap(), before, "no second reminder");
        assert_eq!(gql(&cfg, Q_ISSUE_BY_ID, json!({"id": UUID})).pointer("/data/issue/identifier"), Some(&json!("MOCK-1")));

        // without assignee and due date: both stay empty; an unknown state is refused
        let v = gql(&cfg, M_ISSUE_CREATE, json!({"input": {"teamId": TEAM, "title": "t", "stateId": TODO_STATE_ID}}));
        assert_eq!(v.pointer("/data/issueCreate/issue/identifier"), Some(&json!("MOCK-2")));
        let i = &d.read()["issues"][1];
        assert_eq!((i["state"].as_str(), i["assignee"].as_str(), i["due"].as_str()), (Some("todo"), Some(""), Some("")));
        let bad = gql(&cfg, M_ISSUE_CREATE, json!({"input": {"teamId": TEAM, "title": "t", "stateId": "state-done"}}));
        assert_eq!(error_code(&bad), "INVALID_INPUT");
        // a hand edit may still triage-like move it: "accepted" then reads as a triaged Todo
        let mut f = d.read();
        f["issues"][1]["state"] = json!("accepted");
        fs::write(d.file(), f.to_string()).unwrap();
        let ids = d.read()["issues"][1]["id"].as_str().unwrap().to_string();
        assert!(states(&cfg, &[&ids])[0]["triagedAt"].is_string());
    }
}
