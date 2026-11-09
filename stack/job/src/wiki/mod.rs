//! Wiki.js 2.5 GraphQL client shared by `run` (bot API key, optional IAP token, iap.rs)
//! and `bootstrap` (admin JWT; the setup steps themselves are in bootstrap.rs).
//!
//! Wiki.js 2.5 never answers 401 for a bad key: an unknown key is treated as a
//! guest (HTTP 200 + "not authorized" in errors), a revoked key or a disabled API
//! is HTTP 500 with a message. Proxy settings come from HTTP(S)_PROXY / NO_PROXY
//! (inside compose the wiki is http://wiki:3000 and NO_PROXY lists `wiki`).

pub mod assets;
pub mod bootstrap;
pub mod iap;

use std::thread::sleep;
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, PROXY_AUTHORIZATION};
use serde_json::{Value, json};

use crate::feeds::common::{self, Fatal};

pub const DEFAULT_BASE: &str = "https://wiki2.internal.ediphy.io";

/// Read the page the job owns (bot key). Used by `run` and `serve`.
pub(crate) const READ_PAGE: &str = r#"
query ($id: Int!) {
  pages { single(id: $id) { content title description tags { tag } } }
}
"#;

// Note: do NOT request `page { ... }` in the mutation response. Page.editor is
// non-nullable and serialises to null here, which surfaces as a GraphQL error
// even though the write succeeded. scriptCss is not sent: the job's key has no
// write:styles, so Wiki.js keeps the hand-written CSS.
pub(crate) const WRITE_PAGE: &str = r#"
mutation ($id: Int!, $content: String!, $tags: [String]!, $title: String!, $desc: String!) {
  pages {
    update(id: $id, content: $content, tags: $tags, title: $title,
           description: $desc, isPublished: true) {
      responseResult { succeeded errorCode message }
    }
  }
}
"#;
/// Per-request timeout of the bootstrap client.
pub const ADMIN_TIMEOUT_SECS: u64 = 30;

/// First `n` characters of `s` (never splits a UTF-8 sequence).
pub fn head(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Error text with its source chain, so "error sending request" also says why.
pub fn err_chain(e: &dyn std::error::Error) -> String {
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

/// "; "-joined messages of a GraphQL `errors` array, or None when there are none.
fn error_messages(j: &Value) -> Option<String> {
    let errs = j.get("errors")?.as_array()?;
    if errs.is_empty() {
        return None;
    }
    Some(errs.iter().map(|e| e.get("message").and_then(Value::as_str).unwrap_or("?")).collect::<Vec<_>>().join("; "))
}

// ---------------------------------------------------------------- bot (job)

/// WIKI_BASE without the trailing `/` (default https://wiki2.internal.ediphy.io).
pub fn bot_base() -> String {
    let b = std::env::var("WIKI_BASE").unwrap_or_else(|_| DEFAULT_BASE.into());
    b.trim_end_matches('/').to_string()
}

/// GraphQL call as the job: WIKI_BASE + WIKIJS_API_KEY (+ the IAP token from
/// iap::token() as Proxy-Authorization when IAP is configured). Returns `data`,
/// or Fatal naming what went wrong (no IAP token, unreachable, IAP sign-in
/// redirect, HTTP status, GraphQL errors).
pub fn gql_bot(query: &str, variables: Value) -> Result<Value, Fatal> {
    let key = std::env::var("WIKIJS_API_KEY").unwrap_or_default();
    let iap = iap::token()?;
    gql_bot_with(common::client(), &bot_base(), &key, &iap, query, variables)
}

/// The job's auth on any Wiki.js request (GraphQL, asset upload and read-back):
/// `Authorization: Bearer <key>`, plus the IAP token (iap::token()) as
/// Proxy-Authorization when it is not empty.
pub(crate) fn bot_auth(req: RequestBuilder, key: &str, iap: &str) -> RequestBuilder {
    let req = req.header(AUTHORIZATION, format!("Bearer {key}"));
    if iap.is_empty() {
        return req;
    }
    // IAP consumes Authorization and never forwards it, so the IAP token rides
    // on Proxy-Authorization and Authorization is left for Wiki.js.
    req.header(PROXY_AUTHORIZATION, format!("Bearer {iap}"))
}

pub(crate) const SIGNIN: &str = "redirected to Google sign-in: the IAP token is missing, expired, \
                                 or the service account lacks roles/iap.httpsResourceAccessor";

/// True when the reply is IAP's Google sign-in (redirect, or its HTML page) instead of Wiki.js.
pub(crate) fn is_signin(status: u16, final_url: &str, text: &str) -> bool {
    status == 301 || status == 302 || final_url.contains("accounts.google.com")
        || head(text, 600).contains("accounts.google.com")
}

/// gql_bot with explicit inputs (tests, or callers with their own client).
pub fn gql_bot_with(client: &Client, base: &str, key: &str, iap: &str, query: &str, variables: Value)
    -> Result<Value, Fatal> {
    if key.is_empty() {
        return Err(Fatal("WIKIJS_API_KEY is empty".into()));
    }
    let base = base.trim_end_matches('/');
    let vars = if variables.is_null() { json!({}) } else { variables };
    let body = serde_json::to_vec(&json!({"query": query, "variables": vars})).expect("JSON body");
    let req = bot_auth(client.post(format!("{base}/graphql")).header(CONTENT_TYPE, "application/json"), key, iap);
    let r = req.body(body).send().map_err(|e| Fatal(format!("cannot reach Wiki.js at {base}: {}", err_chain(&e))))?;
    let status = r.status().as_u16();
    let final_url = r.url().to_string();
    let bytes = r.bytes().map_err(|e| Fatal(format!("cannot reach Wiki.js at {base}: {}", err_chain(&e))))?;
    let text = String::from_utf8_lossy(&bytes);

    if is_signin(status, &final_url, &text) {
        return Err(Fatal(SIGNIN.into()));
    }
    if !(200..400).contains(&status) {
        return Err(Fatal(format!("GraphQL HTTP {status}: {}", head(&text, 300))));
    }
    let j: Value = serde_json::from_slice(&bytes)
        .map_err(|e| Fatal(format!("GraphQL HTTP {status}: non-JSON reply ({e}): {}", head(&text, 300))))?;
    if let Some(mut msg) = error_messages(&j) {
        if msg.contains("not authorized") {
            msg.push_str(" (WIKIJS_API_KEY unknown to this wiki, or its group lacks manage:pages on the page)");
        }
        return Err(Fatal(format!("GraphQL errors: {msg}")));
    }
    Ok(j.get("data").cloned().unwrap_or(Value::Null))
}

// ---------------------------------------------------------------- admin (bootstrap)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Ready,
    Setup,
}

impl Mode {
    pub fn name(m: Option<Mode>) -> &'static str {
        match m {
            Some(Mode::Ready) => "ready",
            Some(Mode::Setup) => "setup",
            None => "no answer",
        }
    }
}

/// What a probe `POST /graphql {"query":"{ __typename }"}` says about the wiki.
///
/// The first-run setup app only serves `GET *` and `POST /finalize`, so a POST to
/// /graphql is 404 there. A ready wiki answers `{"data":{"__typename":"Query"}}`.
/// Anything else (starting up, proxy error page, ...) is "not answering".
pub fn classify_mode(status: u16, body: &[u8]) -> Option<Mode> {
    if status == 404 {
        return Some(Mode::Setup);
    }
    if (200..400).contains(&status) {
        if let Ok(j) = serde_json::from_slice::<Value>(body) {
            let t = j.get("data").and_then(|d| d.get("__typename"));
            if t.is_some_and(|t| !t.is_null() && t != "" && t != false) {
                return Some(Mode::Ready);
            }
        }
    }
    None
}

/// Plain HTTP answer: status, body text, and the body as JSON when it parses.
pub struct Reply {
    pub status: u16,
    pub text: String,
    pub json: Option<Value>,
}

/// Admin-side client used by bootstrap.
pub struct Wiki {
    pub base: String,
    client: Client,
}

impl Wiki {
    pub fn new(base: &str) -> Result<Self, Fatal> {
        // No keep-alive reuse: in setup mode the 404 handler of Wiki.js 2.5 throws
        // (`sendError` of undefined) and the socket dies, and POST /finalize restarts
        // the server. A pooled connection then fails with "connection reset" on the
        // next request (seen 2026-11-03 on POST /finalize). A fresh connection per
        // request costs nothing at ~20 requests per run.
        let client = Client::builder()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(ADMIN_TIMEOUT_SECS))
            .build()
            .map_err(|e| Fatal(format!("HTTP client: {}", err_chain(&e))))?;
        Ok(Self::with_client(base, client))
    }

    pub fn with_client(base: &str, client: Client) -> Self {
        Self { base: base.trim_end_matches('/').to_string(), client }
    }

    /// POST JSON to `path`, with `Authorization: Bearer <token>` when given.
    pub fn post(&self, path: &str, payload: &Value, token: Option<&str>) -> Result<Reply, reqwest::Error> {
        let mut req = self
            .client
            .post(format!("{}{path}", self.base))
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(payload).expect("JSON body"));
        if let Some(t) = token.filter(|t| !t.is_empty()) {
            req = req.header(AUTHORIZATION, format!("Bearer {t}"));
        }
        let r = req.send()?;
        let status = r.status().as_u16();
        let bytes = r.bytes()?;
        Ok(Reply { status, text: String::from_utf8_lossy(&bytes).into_owned(), json: serde_json::from_slice(&bytes).ok() })
    }

    /// GraphQL call; returns `data` or Fatal prefixed with `label`.
    pub fn gql(&self, query: &str, variables: Value, token: Option<&str>, label: &str) -> Result<Value, Fatal> {
        let vars = if variables.is_null() { json!({}) } else { variables };
        let r = self
            .post("/graphql", &json!({"query": query, "variables": vars}), token)
            .map_err(|e| Fatal(format!("{label}: cannot reach {}: {}", self.base, err_chain(&e))))?;
        if r.status == 401 {
            return Err(Fatal(format!("{label}: HTTP 401 from Wiki.js: API disabled, or the token is wrong/revoked")));
        }
        if !(200..400).contains(&r.status) {
            return Err(Fatal(format!("{label}: HTTP {}: {}", r.status, head(&r.text, 300))));
        }
        let Some(j) = r.json else {
            return Err(Fatal(format!("{label}: non-JSON reply (is the wiki still in setup mode?): {}", head(&r.text, 200))));
        };
        if let Some(msg) = error_messages(&j) {
            return Err(Fatal(format!("{label}: GraphQL errors: {msg}")));
        }
        Ok(j.get("data").cloned().unwrap_or(Value::Null))
    }

    /// Ready, Setup, or None (not answering).
    pub fn mode(&self) -> Option<Mode> {
        match self.post("/graphql", &json!({"query": "{ __typename }"}), None) {
            Ok(r) => classify_mode(r.status, r.text.as_bytes()),
            Err(_) => None,
        }
    }

    /// Poll mode() every 2 s until it is one of `want`, or Fatal after `seconds`.
    pub fn wait(&self, want: &[Mode], seconds: u64, what: &str) -> Result<Mode, Fatal> {
        self.wait_every(want, seconds, Duration::from_secs(2), what)
    }

    pub fn wait_every(&self, want: &[Mode], seconds: u64, every: Duration, what: &str) -> Result<Mode, Fatal> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut last = None;
        while Instant::now() < deadline {
            last = self.mode();
            if let Some(m) = last.filter(|m| want.contains(m)) {
                return Ok(m);
            }
            sleep(every);
        }
        let names: Vec<&str> = want.iter().map(|m| Mode::name(Some(*m))).collect();
        Err(Fatal(format!(
            "{what}: Wiki.js at {} not {} after {seconds}s (last state: {}). Check `docker compose logs wiki`.",
            self.base, names.join("/"), Mode::name(last)
        )))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Tiny one-shot HTTP server on 127.0.0.1 for client tests (no extra crates).

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use reqwest::blocking::Client;

    pub struct Canned {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    pub fn canned(status: u16, body: &str) -> Canned {
        Canned { status, headers: vec![], body: body.into() }
    }

    /// Serve `replies` in order, one per connection. Returns the base URL and a
    /// receiver of the raw requests (head + body) the server saw.
    pub fn serve(replies: Vec<Canned>) -> (String, mpsc::Receiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for c in replies {
                let Ok((mut s, _)) = l.accept() else { return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(end) = find(&buf, b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
                let mut out = format!("HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n", c.status, c.body.len());
                for (k, v) in &c.headers {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                out.push_str(&c.body);
                let _ = s.write_all(out.as_bytes());
            }
        });
        (base, rx)
    }

    fn find(h: &[u8], n: &[u8]) -> Option<usize> {
        h.windows(n.len()).position(|w| w == n)
    }

    /// Client that ignores HTTP(S)_PROXY, so tests work inside the proxied build container.
    pub fn client() -> Client {
        Client::builder().no_proxy().build().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{canned, client, serve};
    use super::*;

    fn bot(replies: Vec<testing::Canned>, key: &str, iap: &str) -> (Result<Value, Fatal>, Vec<String>) {
        let n = replies.len();
        let (base, rx) = serve(replies);
        let r = gql_bot_with(&client(), &format!("{base}/"), key, iap, "{ x }", json!({"id": 1}));
        let seen: Vec<String> = rx.try_iter().take(n).collect();
        (r, seen)
    }

    #[test]
    fn head_is_char_safe() {
        assert_eq!(head("aé—b", 2), "aé");
        assert_eq!(head("ab", 5), "ab");
    }

    #[test]
    fn bot_empty_key() {
        let e = gql_bot_with(&client(), "http://127.0.0.1:9", "", "", "{ x }", Value::Null).unwrap_err();
        assert_eq!(e.0, "WIKIJS_API_KEY is empty");
    }

    #[test]
    fn bot_ok_sends_headers_and_returns_data() {
        let (r, seen) = bot(vec![canned(200, r#"{"data":{"pages":{"single":{"id":1}}}}"#)], "KEY", "IAPTOK");
        assert_eq!(r.unwrap()["pages"]["single"]["id"], 1);
        let req = seen[0].to_lowercase();
        assert!(req.starts_with("post /graphql "), "{req}");
        assert!(req.contains("authorization: bearer key\r\n"));
        assert!(req.contains("proxy-authorization: bearer iaptok\r\n"));
        assert!(req.contains("content-type: application/json"));
        assert!(req.contains(r#""variables":{"id":1}"#));
    }

    #[test]
    fn bot_no_iap_header_when_unset() {
        let (_, seen) = bot(vec![canned(200, r#"{"data":{}}"#)], "KEY", "");
        assert!(!seen[0].to_lowercase().contains("proxy-authorization"));
    }

    #[test]
    fn bot_not_authorized_hint() {
        let (r, _) = bot(vec![canned(200, r#"{"errors":[{"message":"You are not authorized to view this page."},{"x":1}],"data":null}"#)], "K", "");
        assert_eq!(r.unwrap_err().0, "GraphQL errors: You are not authorized to view this page.; ? \
            (WIKIJS_API_KEY unknown to this wiki, or its group lacks manage:pages on the page)");
    }

    #[test]
    fn bot_http_500_revoked() {
        let body = format!(r#"{{"errors":[{{"message":"API Key is invalid or was revoked."}}]}}{}"#, "x".repeat(400));
        let (r, _) = bot(vec![canned(500, &body)], "K", "");
        let e = r.unwrap_err().0;
        assert!(e.starts_with("GraphQL HTTP 500: {\"errors\":[{\"message\":\"API Key is invalid or was revoked.\"}]}x"), "{e}");
        assert_eq!(e.chars().count(), "GraphQL HTTP 500: ".len() + 300);
    }

    #[test]
    fn bot_google_signin() {
        let (r, _) = bot(vec![canned(200, "<html><a href=\"https://accounts.google.com/o/oauth2\">")], "K", "");
        assert!(r.unwrap_err().0.starts_with("redirected to Google sign-in: the IAP token is missing"));
        let mut c = canned(302, "");
        c.headers.push(("Location".into(), "https://accounts.google.com/".into()));
        // The redirect target is unreachable from the test, so stop following redirects.
        let (base, _rx) = serve(vec![c]);
        let cl = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap();
        let e = gql_bot_with(&cl, &base, "K", "", "{ x }", Value::Null).unwrap_err();
        assert!(e.0.starts_with("redirected to Google sign-in"), "{}", e.0);
    }

    #[test]
    fn bot_unreachable() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let e = gql_bot_with(&client(), &base, "K", "", "{ x }", Value::Null).unwrap_err().0;
        assert!(e.starts_with(&format!("cannot reach Wiki.js at {base}: ")), "{e}");
    }

    #[test]
    fn mode_classification() {
        assert_eq!(classify_mode(404, b"Cannot POST /graphql"), Some(Mode::Setup));
        assert_eq!(classify_mode(200, br#"{"data":{"__typename":"Query"}}"#), Some(Mode::Ready));
        assert_eq!(classify_mode(200, br#"{"data":{"__typename":""}}"#), None);
        assert_eq!(classify_mode(200, br#"{"data":null}"#), None);
        assert_eq!(classify_mode(200, b"<html>setup</html>"), None);
        assert_eq!(classify_mode(502, b"Bad Gateway"), None);
    }

    #[test]
    fn admin_gql_errors() {
        let (base, rx) = serve(vec![
            canned(401, "nope"),
            canned(500, "boom"),
            canned(200, "<html>"),
            canned(200, r#"{"errors":[{"message":"Too many requests, please try again in 42 seconds."}]}"#),
            canned(200, r#"{"data":{"a":1}}"#),
        ]);
        let w = Wiki::with_client(&base, client());
        let q = |t: Option<&str>| w.gql("{ a }", Value::Null, t, "L");
        assert_eq!(q(None).unwrap_err().0, "L: HTTP 401 from Wiki.js: API disabled, or the token is wrong/revoked");
        assert_eq!(q(None).unwrap_err().0, "L: HTTP 500: boom");
        assert_eq!(q(None).unwrap_err().0, "L: non-JSON reply (is the wiki still in setup mode?): <html>");
        assert_eq!(q(None).unwrap_err().0, "L: GraphQL errors: Too many requests, please try again in 42 seconds.");
        assert_eq!(q(Some("JWT")).unwrap()["a"], 1);
        let reqs: Vec<String> = rx.try_iter().collect();
        assert!(!reqs[0].to_lowercase().contains("authorization"));
        assert!(reqs[4].to_lowercase().contains("authorization: bearer jwt\r\n"));
    }

    /// Live, against a THROWAWAY wiki after `bootstrap`: the bot key reads and
    /// updates its page (the job's queries), and is refused anywhere else.
    ///   WIKI_BASE=… WIKIJS_API_KEY=… WIKI_PAGE_ID=… WIKI_ADMIN_EMAIL=… WIKI_ADMIN_PASSWORD=…
    ///   cargo test -- --ignored live_bot_least_privilege --nocapture
    #[test]
    #[ignore]
    fn live_bot_least_privilege() {
        let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
        let pid: i64 = env("WIKI_PAGE_ID").parse().unwrap();
        let ok = |r: &Value| r["responseResult"]["succeeded"] == true;

        let page = gql_bot("query ($id: Int!) { pages { single(id: $id) { content title description tags { tag } } } }",
                           json!({"id": pid})).unwrap()["pages"]["single"].clone();
        let content = page["content"].as_str().unwrap().to_string();
        eprintln!("bot read page {pid}: {} B", content.len());
        let tags: Vec<Value> = page["tags"].as_array().unwrap().iter().map(|t| t["tag"].clone()).collect();
        let write = "mutation ($id: Int!, $content: String!, $tags: [String]!, $title: String!, $desc: String!) {
          pages { update(id: $id, content: $content, tags: $tags, title: $title, description: $desc, isPublished: true) {
            responseResult { succeeded errorCode message } } } }";
        let r = gql_bot(write, json!({"id": pid, "content": format!("{content}\n"), "tags": tags,
                                      "title": page["title"], "desc": page["description"]})).unwrap();
        eprintln!("bot update own page: {}", r["pages"]["update"]["responseResult"]);
        assert!(ok(&r["pages"]["update"]));

        // A page outside CTP/run-books/, made by the admin.
        let w = Wiki::new(&bot_base()).unwrap();
        let jwt = w.gql(r#"mutation ($u: String!, $p: String!) { authentication { login(username: $u, password: $p, strategy: "local") { jwt } } }"#,
                        json!({"u": env("WIKI_ADMIN_EMAIL"), "p": env("WIKI_ADMIN_PASSWORD")}), None, "login").unwrap()
            ["authentication"]["login"]["jwt"].as_str().unwrap().to_string();
        let find = |path: &str| -> Option<i64> {
            w.gql("{ pages { list(limit: 100000) { id path } } }", Value::Null, Some(&jwt), "list").unwrap()["pages"]["list"]
                .as_array().unwrap().iter().find(|p| p["path"] == path).and_then(|p| p["id"].as_i64())
        };
        let create = "mutation ($path: String!) { pages { create(content: \"<p>x</p>\", description: \"\", editor: \"code\",
            isPublished: true, isPrivate: false, locale: \"en\", path: $path, tags: [], title: \"probe\") {
            responseResult { succeeded errorCode message } } } }";
        if find("Other/ew-secret").is_none() {
            let r = w.gql(create, json!({"path": "Other/ew-secret"}), Some(&jwt), "admin create").unwrap();
            assert!(ok(&r["pages"]["create"]));
        }
        let other = find("Other/ew-secret").unwrap();

        let e = gql_bot("query ($id: Int!) { pages { single(id: $id) { content } } }", json!({"id": other})).unwrap_err();
        eprintln!("bot read Other/ew-secret (id {other}): {e}");
        assert!(e.0.contains("not authorized") && e.0.contains("(WIKIJS_API_KEY unknown"));

        let r = gql_bot(write, json!({"id": other, "content": "<p>pwned</p>", "tags": [], "title": "x", "desc": ""}));
        eprintln!("bot update Other/ew-secret: {r:?}");
        assert!(r.map_or(true, |d| !ok(&d["pages"]["update"])));

        for path in ["Other/ew-bot-probe", "CTP/ew-bot-probe"] {
            let r = gql_bot(create, json!({"path": path}));
            eprintln!("bot create {path}: {r:?}");
            assert!(r.map_or(true, |d| !ok(&d["pages"]["create"])));
        }
        let r = gql_bot(create, json!({"path": "CTP/run-books/ew-bot-probe"}));
        eprintln!("bot create CTP/run-books/ew-bot-probe (inside write scope): {r:?}");

        let r = gql_bot("mutation { pages { purgeHistory(olderThan: \"P1D\") { responseResult { succeeded message } } } }", Value::Null);
        eprintln!("bot purgeHistory: {r:?}");
        assert!(r.map_or(true, |d| !ok(&d["pages"]["purgeHistory"])));

        let e = gql_bot_with(common::client(), &bot_base(), "not-a-key", "", "query ($id: Int!) { pages { single(id: $id) { id } } }",
                             json!({"id": pid})).unwrap_err();
        eprintln!("unknown key: {e}");
    }

    #[test]
    fn admin_mode_and_wait() {
        let (base, _rx) = serve(vec![
            canned(404, "Cannot POST /graphql"),
            canned(200, r#"{"data":{"__typename":"Query"}}"#),
        ]);
        let w = Wiki::with_client(&base, client());
        assert_eq!(w.mode(), Some(Mode::Setup));
        assert_eq!(w.wait_every(&[Mode::Ready], 5, Duration::from_millis(10), "t").unwrap(), Mode::Ready);
        // Server gone: not answering, then a timeout message naming the last state.
        let e = w.wait_every(&[Mode::Ready], 0, Duration::from_millis(1), "restart after setup").unwrap_err().0;
        assert_eq!(e, format!("restart after setup: Wiki.js at {base} not ready after 0s (last state: no answer). \
                               Check `docker compose logs wiki`."));
    }
}
