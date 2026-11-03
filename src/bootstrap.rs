//! Wiki.js setup for the job. Port of bootstrap_wiki.py: same steps, order,
//! idempotency and printed lines.
//!
//! Steps, each skipped when already done:
//!   1. Finish the first-run setup wizard (POST /finalize) and wait for the restart.
//!   2. Log in as the local admin.
//!   3. Turn the GraphQL API on (it is off by default).
//!   4. Create/refresh group "exploit-watch": read+write pages under CTP/run-books/,
//!      plus manage:pages on the one page (needed to read it; see step_group).
//!   5. Create the page CTP/run-books/Cyber-Exploit-Watch from stack/wiki/page/skeleton.html
//!      with stack/wiki/page/style.css as scriptCss. Done as admin, because the bot key
//!      deliberately lacks write:styles.
//!   6. Create API key "exploit-watch" bound to that group, unless .env already holds
//!      a working one (revoking older "exploit-watch" keys). The key is shown once,
//!      so it goes straight into .env.
//!   7. Smoke test: the bot key reads the page with pages.single, as the job does.
//!
//! .env (--env-file) gets WIKIJS_API_KEY, WIKI_PAGE_ID and, if generated,
//! WIKI_ADMIN_PASSWORD (written as soon as each is known; every other line is kept).
//!
//! --update-css re-pushes scriptCss from the CSS file and keeps the content;
//! --reseed overwrites the content from the skeleton and keeps the current
//! scriptCss (combine both to replace both). --purge-history only deletes page
//! versions older than an ISO 8601 duration and skips every other step.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread::sleep;
use std::time::Duration;

use regex::Regex;
use serde_json::{Value, json};

use crate::feeds::common::Fatal;
use crate::wiki::{Mode, Wiki};

pub const PAGE_PATH: &str = "CTP/run-books/Cyber-Exploit-Watch";
pub const PAGE_LOCALE: &str = "en";
const PAGE_TITLE: &str = "Cyber Threat Exploit Watch";
const PAGE_DESC: &str = "Exploited-in-the-wild vulnerabilities, critical CVEs and dependency advisories from public feeds. Rebuilt on a schedule.";
const PAGE_TAGS: [&str; 2] = ["runbook", "threat-intel"];
pub const RULE_PATH: &str = "CTP/run-books/";
pub const GROUP_NAME: &str = "exploit-watch";
pub const KEY_NAME: &str = "exploit-watch";
const KEY_EXPIRATION: &str = "1y";

#[derive(clap::Args)]
pub struct Args {
    /// Page content used on create / --reseed
    #[arg(long, default_value = crate::render::SKELETON_PATH)]
    pub skeleton: PathBuf,
    /// scriptCss used on create / --update-css
    #[arg(long, default_value = crate::render::STYLE_PATH)]
    pub css: PathBuf,
    /// Overwrite page content from --skeleton (as admin)
    #[arg(long)]
    pub reseed: bool,
    /// Re-push scriptCss from --css (as admin)
    #[arg(long)]
    pub update_css: bool,
    /// Only delete page versions older than an ISO 8601 duration, e.g. P7D (as admin; all pages)
    #[arg(long, value_name = "DURATION")]
    pub purge_history: Option<String>,
    /// .env file read and updated by bootstrap
    #[arg(long, default_value = ".env")]
    pub env_file: PathBuf,
}

// ---------------------------------------------------------------- .env

fn key_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$").unwrap())
}

/// KEY=value pairs of a .env text; later lines win, quotes around values are dropped.
pub fn parse_env(text: &str) -> HashMap<String, String> {
    let mut vals = HashMap::new();
    for line in text.lines() {
        if let Some(c) = key_re().captures(line) {
            let v = c[2].trim().trim_matches('"').trim_matches('\'');
            vals.insert(c[1].to_string(), v.to_string());
        }
    }
    vals
}

pub fn read_env_file(path: &Path) -> Result<HashMap<String, String>, Fatal> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let text = fs::read_to_string(path).map_err(|e| Fatal(format!("cannot read {}: {e}", path.display())))?;
    Ok(parse_env(&text))
}

/// Set KEY=value for each update on its first line, in place; append keys that are
/// missing. Every other line (comments, blanks, other keys) is kept. LF line ends.
pub fn render_env(existing: &str, updates: &[(&str, &str)]) -> String {
    let mut lines: Vec<String> = existing.lines().map(str::to_string).collect();
    let mut done: Vec<&str> = Vec::new();
    for line in lines.iter_mut() {
        let Some(c) = key_re().captures(line) else { continue };
        let k = c[1].to_string();
        if let Some(&(uk, uv)) = updates.iter().find(|(uk, _)| *uk == k) {
            if !done.contains(&uk) {
                *line = format!("{uk}={uv}");
                done.push(uk);
            }
        }
    }
    for &(k, v) in updates {
        if !done.contains(&k) {
            lines.push(format!("{k}={v}"));
            done.push(k);
        }
    }
    lines.join("\n") + "\n"
}

pub fn write_env_file(path: &Path, updates: &[(&str, &str)]) -> Result<(), Fatal> {
    let existing = if path.exists() {
        fs::read_to_string(path).map_err(|e| Fatal(format!("cannot read {}: {e}", path.display())))?
    } else {
        String::new()
    };
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp, render_env(&existing, updates)).map_err(|e| Fatal(format!("cannot write {}: {e}", tmp.display())))?;
    fs::rename(&tmp, path).map_err(|e| Fatal(format!("cannot replace {}: {e}", path.display())))
}

pub fn mask(v: &str) -> String {
    if v.is_empty() {
        return "(empty)".into();
    }
    let n = v.chars().count();
    let tail: String = v.chars().skip(n.saturating_sub(4)).collect();
    format!("****{tail} ({n} chars)")
}

// ---------------------------------------------------------------- small helpers

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding (Python secrets.token_urlsafe alphabet).
pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(B64URL[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// base64url (or standard) decode; padding optional. None on a bad character.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Claims of a JWT (the API key is one), or an empty map when unreadable.
pub fn jwt_claims(token: &str) -> serde_json::Map<String, Value> {
    token
        .split('.')
        .nth(1)
        .and_then(b64url_decode)
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

/// secrets.token_urlsafe(n): n random bytes as base64url ([A-Za-z0-9_-], safe in compose .env).
fn token_urlsafe(n: usize) -> Result<String, Fatal> {
    let mut buf = vec![0u8; n];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| Fatal(format!("cannot read /dev/urandom to generate WIKI_ADMIN_PASSWORD ({e}); set it in .env")))?;
    Ok(b64url_encode(&buf))
}

/// Python repr() of a JSON value, for messages that print a dict as the Python script did.
pub fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True".into() } else { "False".into() },
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
        Value::Array(a) => format!("[{}]", a.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter().map(|(k, v)| format!("'{k}': {}", py_repr(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// Python str() of a JSON value (strings bare, the rest as repr).
fn py_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(v) => py_repr(v),
        None => "None".into(),
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// res.responseResult.succeeded, else Fatal "<what> refused: <message or the whole result>".
fn check(res: &Value, what: &str) -> Result<(), Fatal> {
    let rr = res.get("responseResult").filter(|v| truthy(Some(v))).cloned().unwrap_or_else(|| json!({}));
    if !truthy(rr.get("succeeded")) {
        let why = if truthy(rr.get("message")) { py_str(rr.get("message")) } else { py_repr(&rr) };
        return Err(Fatal(format!("{what} refused: {why}")));
    }
    Ok(())
}

fn text_len(v: &Value) -> usize {
    v.as_str().map_or(0, |s| s.chars().count())
}

fn as_id(v: &Value) -> Option<i64> {
    v.as_i64()
}

// ---------------------------------------------------------------- steps

fn step_setup(w: &Wiki, email: &str, password: &str, site_url: &str) -> Result<bool, Fatal> {
    let state = w.wait(&[Mode::Ready, Mode::Setup], 180, "startup")?;
    if state == Mode::Ready {
        println!("setup      already finalized");
        return Ok(false);
    }
    println!("setup      finalizing (admin {email}, siteUrl {site_url})");
    let r = w
        .post("/finalize", &json!({"adminEmail": email, "adminPassword": password, "siteUrl": site_url, "telemetry": false}), None)
        .map_err(|e| Fatal(format!("POST /finalize failed: {}", crate::wiki::err_chain(&e))))?;
    let Some(j) = r.json else {
        return Err(Fatal(format!("POST /finalize failed: HTTP {}, non-JSON reply: {}", r.status, crate::wiki::head(&r.text, 200))));
    };
    if !truthy(j.get("ok")) {
        let why = if truthy(j.get("error")) { py_str(j.get("error")) } else { py_repr(&j) };
        return Err(Fatal(format!("POST /finalize refused: {why}")));
    }
    sleep(Duration::from_secs(3)); // server tears down the setup app and reboots ~1 s after replying
    w.wait(&[Mode::Ready], 180, "restart after setup")?;
    println!("setup      done, wiki restarted");
    Ok(true)
}

fn step_login(w: &Wiki, email: &str, password: &str) -> Result<String, Fatal> {
    let d = w
        .gql(
            r#"
          mutation ($u: String!, $p: String!) {
            authentication { login(username: $u, password: $p, strategy: "local") {
              jwt responseResult { succeeded message } } }
          }"#,
            json!({"u": email, "p": password}),
            None,
            "admin login",
        )
        .map_err(|e| {
            if e.0.contains("Too many requests") {
                Fatal(format!("{} Wiki.js allows 5 login calls per 60 s (good or bad); wait and rerun", e.0))
            } else {
                e
            }
        })?;
    let res = &d["authentication"]["login"];
    let rr = &res["responseResult"];
    let jwt = res["jwt"].as_str().unwrap_or("");
    if !truthy(rr.get("succeeded")) || jwt.is_empty() {
        let msg = if truthy(rr.get("message")) { py_str(rr.get("message")) } else { "no message".into() };
        return Err(Fatal(format!(
            "admin login failed: {}. WIKI_ADMIN_EMAIL / WIKI_ADMIN_PASSWORD in .env do not match this wiki's admin \
             (the wiki-data volume keeps the account from its first setup)",
            msg.trim_end_matches('.')
        )));
    }
    println!("login      ok as {email}");
    Ok(jwt.to_string())
}

fn step_api_on(w: &Wiki, jwt: &str) -> Result<(), Fatal> {
    let d = w.gql("{ authentication { apiState } }", Value::Null, Some(jwt), "apiState")?;
    if truthy(d["authentication"].get("apiState")) {
        println!("api        already enabled");
        return Ok(());
    }
    let d = w.gql(
        "mutation { authentication { setApiState(enabled: true) { responseResult { succeeded message } } } }",
        Value::Null,
        Some(jwt),
        "setApiState",
    )?;
    check(&d["authentication"]["setApiState"], "setApiState")?;
    println!("api        enabled");
    Ok(())
}

fn find_group(w: &Wiki, jwt: &str) -> Result<Option<i64>, Fatal> {
    let d = w.gql("{ groups { list { id name } } }", Value::Null, Some(jwt), "groups.list")?;
    let mut hits: Vec<i64> = d["groups"]["list"]
        .as_array()
        .map(|a| a.iter().filter(|g| g["name"] == GROUP_NAME).filter_map(|g| as_id(&g["id"])).collect())
        .unwrap_or_default();
    hits.sort_unstable();
    if hits.len() > 1 {
        let ids: Vec<String> = hits.iter().map(i64::to_string).collect();
        println!("  warning: {} groups named '{GROUP_NAME}' (ids [{}]); using {}", hits.len(), ids.join(", "), hits[0]);
    }
    Ok(hits.first().copied())
}

fn step_group(w: &Wiki, jwt: &str) -> Result<i64, Fatal> {
    let gid = match find_group(w, jwt)? {
        Some(gid) => {
            println!("group      reusing '{GROUP_NAME}' id {gid}");
            gid
        }
        None => {
            let d = w.gql(
                "mutation ($n: String!) { groups { create(name: $n) { responseResult { succeeded message } } } }",
                json!({"n": GROUP_NAME}),
                Some(jwt),
                "groups.create",
            )?;
            check(&d["groups"]["create"], "groups.create")?;
            let gid = find_group(w, jwt)?
                .ok_or_else(|| Fatal(format!("group '{GROUP_NAME}' was created but does not appear in groups.list")))?;
            println!("group      created '{GROUP_NAME}' id {gid}");
            gid
        }
    };

    // Always re-apply, so a hand-edited group is put back to least privilege.
    //
    // Why manage:pages: in 2.5.x `pages.single` / `pages.singleByPath` (the only
    // GraphQL reads that return page content) check manage:pages OR delete:pages on
    // the page, NOT read:pages. Without it the job's READ_PAGE fails with "You are
    // not authorized to view this page." manage:pages is the lesser of the two
    // (delete:pages would let the key delete the page), and it is pinned by an
    // EXACT rule to the one page. What it adds there: move (destination still needs
    // write:pages, so only inside CTP/run-books/), convert, restore a version.
    let d = w.gql(
        r#"
      mutation ($id: Int!, $n: String!, $perm: [String]!, $rules: [PageRuleInput]!) {
        groups { update(id: $id, name: $n, redirectOnLogin: "/", permissions: $perm, pageRules: $rules) {
          responseResult { succeeded message } } }
      }"#,
        json!({
            "id": gid, "n": GROUP_NAME,
            "perm": ["read:pages", "write:pages", "manage:pages"],
            "rules": [
                {"id": "rb", "deny": false, "match": "START",
                 "roles": ["read:pages", "write:pages"], "path": RULE_PATH, "locales": [PAGE_LOCALE]},
                {"id": "ew", "deny": false, "match": "EXACT",
                 "roles": ["manage:pages"], "path": PAGE_PATH, "locales": [PAGE_LOCALE]},
            ],
        }),
        Some(jwt),
        "groups.update",
    )?;
    check(&d["groups"]["update"], "groups.update")?;
    println!(
        "group      read:pages+write:pages START '{RULE_PATH}'; manage:pages EXACT '{PAGE_PATH}'; locale {PAGE_LOCALE}"
    );
    Ok(gid)
}

/// True only if `key` can do what the job does: pages.single on the page.
///
/// A cheaper check is not enough: Wiki.js treats a malformed or foreign-signed
/// key as a guest (HTTP 200), and guests may run pages.list. pages.single needs
/// manage:pages on the page, which only our group has.
fn key_works(w: &Wiki, key: &str, pid: i64) -> bool {
    if key.is_empty() {
        return false;
    }
    match w.gql("query ($id: Int!) { pages { single(id: $id) { id } } }", json!({"id": pid}), Some(key), "key check") {
        Ok(_) => true,
        Err(e) => {
            println!("  key rejected: {e}");
            false
        }
    }
}

fn step_key(w: &Wiki, jwt: &str, gid: i64, current: &str, pid: i64) -> Result<String, Fatal> {
    let d = w.gql("{ authentication { apiKeys { id name isRevoked } } }", Value::Null, Some(jwt), "apiKeys")?;
    let keys: Vec<Value> = d["authentication"]["apiKeys"].as_array().cloned().unwrap_or_default();
    let live = |k: &Value| k["name"] == KEY_NAME && !truthy(k.get("isRevoked"));
    if !current.is_empty() {
        let c = jwt_claims(current);
        let api = c.get("api").and_then(Value::as_i64);
        let ours = keys.iter().any(|k| api.is_some() && as_id(&k["id"]) == api && live(k));
        if !ours {
            let shown = if c.is_empty() { "unreadable".to_string() } else { py_repr(&Value::Object(c.clone())) };
            println!("  .env key is not a live '{KEY_NAME}' key of this wiki (claims {shown})");
        } else if c.get("grp").and_then(Value::as_i64) != Some(gid) {
            println!("  .env key is bound to group {}, not {gid}", py_str(c.get("grp")));
        } else if key_works(w, current, pid) {
            println!("apikey     .env key works, keeping it ({})", mask(current));
            return Ok(current.to_string());
        }
    }
    for k in keys.iter().filter(|k| live(k)) {
        let id = as_id(&k["id"]).unwrap_or_default();
        let d = w.gql(
            "mutation ($id: Int!) { authentication { revokeApiKey(id: $id) { responseResult { succeeded message } } } }",
            json!({"id": id}),
            Some(jwt),
            "revokeApiKey",
        )?;
        check(&d["authentication"]["revokeApiKey"], &format!("revokeApiKey {id}"))?;
        println!("apikey     revoked old key id {id}");
    }
    let d = w.gql(
        r#"
      mutation ($n: String!, $exp: String!, $g: Int!) {
        authentication { createApiKey(name: $n, expiration: $exp, fullAccess: false, group: $g) {
          key responseResult { succeeded message } } }
      }"#,
        json!({"n": KEY_NAME, "exp": KEY_EXPIRATION, "g": gid}),
        Some(jwt),
        "createApiKey",
    )?;
    let res = &d["authentication"]["createApiKey"];
    check(res, "createApiKey")?;
    let key = res["key"].as_str().unwrap_or("").to_string();
    // The new key must be usable right away; fail here rather than in the job.
    let mut ok = false;
    for _ in 0..5 {
        if key_works(w, &key, pid) {
            ok = true;
            break;
        }
        sleep(Duration::from_secs(2));
    }
    if !ok {
        return Err(Fatal("createApiKey returned a key that Wiki.js then rejects".into()));
    }
    println!("apikey     created '{KEY_NAME}' for group {gid}, expires in {KEY_EXPIRATION} ({})", mask(&key));
    Ok(key)
}

fn find_page(w: &Wiki, jwt: &str) -> Result<Option<i64>, Fatal> {
    let d = w.gql("{ pages { list(limit: 100000) { id path locale } } }", Value::Null, Some(jwt), "pages.list")?;
    let mut hits: Vec<i64> = d["pages"]["list"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|p| p["path"] == PAGE_PATH && p["locale"] == PAGE_LOCALE)
                .filter_map(|p| as_id(&p["id"]))
                .collect()
        })
        .unwrap_or_default();
    hits.sort_unstable();
    Ok(hits.first().copied())
}

/// File as UTF-8 text without a BOM (a BOM must not land in the page); Fatal if missing or blank.
pub fn read_file(path: &Path, what: &str, flag: &str) -> Result<String, Fatal> {
    if !path.is_file() {
        return Err(Fatal(format!("{what} not found: {} (pass {flag} <path>)", path.display())));
    }
    let raw = fs::read(path).map_err(|e| Fatal(format!("cannot read {what} {}: {e}", path.display())))?;
    let data = String::from_utf8(raw).map_err(|_| Fatal(format!("{what} is not UTF-8: {}", path.display())))?;
    let data = data.strip_prefix('\u{feff}').map(str::to_string).unwrap_or(data);
    if data.trim().is_empty() {
        return Err(Fatal(format!("{what} is empty: {}", path.display())));
    }
    Ok(data)
}

fn step_page(w: &Wiki, jwt: &str, args: &Args) -> Result<i64, Fatal> {
    let Some(pid) = find_page(w, jwt)? else {
        let content = read_file(&args.skeleton, "page skeleton", "--skeleton")?;
        let css = read_file(&args.css, "page CSS", "--css")?;
        // Do NOT request `page { ... }` in the response: Page.editor serialises to null
        // and the reply carries an error although the page was created.
        let d = w.gql(
            r#"
          mutation ($content: String!, $desc: String!, $css: String, $tags: [String]!, $title: String!,
                    $path: String!, $locale: String!) {
            pages { create(content: $content, description: $desc, editor: "code", isPublished: true,
                           isPrivate: false, locale: $locale, path: $path, tags: $tags, title: $title,
                           scriptCss: $css) {
              responseResult { succeeded message } } }
          }"#,
            json!({"content": content, "desc": PAGE_DESC, "css": css, "tags": PAGE_TAGS,
                   "title": PAGE_TITLE, "path": PAGE_PATH, "locale": PAGE_LOCALE}),
            Some(jwt),
            "pages.create",
        )?;
        check(&d["pages"]["create"], "pages.create")?;
        let pid = find_page(w, jwt)?
            .ok_or_else(|| Fatal(format!("page {PAGE_PATH} was created but does not appear in pages.list")))?;
        println!(
            "page       created {PAGE_LOCALE}/{PAGE_PATH} id {pid} ({} B content, {} B css)",
            content.chars().count(),
            css.chars().count()
        );
        return Ok(pid);
    };

    println!("page       reusing {PAGE_LOCALE}/{PAGE_PATH} id {pid}");
    if !(args.reseed || args.update_css) {
        return Ok(pid);
    }

    let d = w.gql(
        r#"
      query ($id: Int!) { pages { single(id: $id) {
        content title description scriptCss scriptJs tags { tag } } } }"#,
        json!({"id": pid}),
        Some(jwt),
        "pages.single",
    )?;
    let cur = &d["pages"]["single"];
    let content = if args.reseed {
        read_file(&args.skeleton, "page skeleton", "--skeleton")?
    } else {
        cur["content"].as_str().unwrap_or("").to_string()
    };
    let css = if args.update_css {
        read_file(&args.css, "page CSS", "--css")?
    } else {
        cur["scriptCss"].as_str().unwrap_or("").to_string()
    };
    let tags: Vec<Value> = cur["tags"].as_array().map(|a| a.iter().map(|t| t["tag"].clone()).collect()).unwrap_or_default();
    // As admin (write:styles + write:scripts) update() REPLACES scriptCss/scriptJs with
    // whatever is sent, empty included. So always send both, or the CSS is wiped.
    let d = w.gql(
        r#"
      mutation ($id: Int!, $content: String!, $tags: [String]!, $title: String!, $desc: String!,
                $css: String, $js: String) {
        pages { update(id: $id, content: $content, tags: $tags, title: $title, description: $desc,
                       scriptCss: $css, scriptJs: $js, isPublished: true) {
          responseResult { succeeded message } } }
      }"#,
        json!({"id": pid, "content": content, "tags": tags,
               "title": cur["title"], "desc": cur["description"].as_str().unwrap_or(""),
               "css": css, "js": cur["scriptJs"].as_str().unwrap_or("")}),
        Some(jwt),
        "pages.update",
    )?;
    check(&d["pages"]["update"], "pages.update")?;
    let mut done = Vec::new();
    if args.reseed {
        done.push(format!("content reseeded ({} B)", content.chars().count()));
    }
    if args.update_css {
        done.push(format!("scriptCss re-pushed ({} B before minify)", css.chars().count()));
    }
    println!("page       {}", done.join(", "));
    Ok(pid)
}

fn step_smoke(w: &Wiki, key: &str, pid: i64) -> Result<(), Fatal> {
    // Same read the job does (rebuild READ_PAGE), with the bot key.
    let d = w.gql(
        "query ($id: Int!) { pages { single(id: $id) { id path content } } }",
        json!({"id": pid}),
        Some(key),
        "bot read (pages.single)",
    )?;
    let p = &d["pages"]["single"];
    println!(
        "smoke      bot key reads page {} ({}, {} B)",
        py_str(p.get("id")),
        py_str(p.get("path")),
        text_len(&p["content"])
    );
    Ok(())
}

// ---------------------------------------------------------------- main

/// .env values plus the keys this run changed; writes go to disk at once.
struct EnvFile {
    path: PathBuf,
    vals: HashMap<String, String>,
    changed: Vec<String>,
}

impl EnvFile {
    fn get(&self, k: &str) -> &str {
        self.vals.get(k).map_or("", String::as_str)
    }

    /// .env first, then the process environment, then `default` (empty counts as unset).
    fn val(&self, k: &str, default: &str) -> String {
        let f = self.get(k);
        if !f.is_empty() {
            return f.to_string();
        }
        std::env::var(k).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_string())
    }

    /// Written as soon as known: the API key is shown once, so a later failure
    /// must not lose it.
    fn save(&mut self, k: &str, v: &str) -> Result<(), Fatal> {
        if self.vals.get(k).map(String::as_str) != Some(v) {
            write_env_file(&self.path, &[(k, v)])?;
            self.vals.insert(k.into(), v.into());
            self.changed.push(k.into());
            println!(".env       {k} = {}", if k == "WIKI_PAGE_ID" { v.to_string() } else { mask(v) });
        }
        Ok(())
    }
}

pub fn main(args: Args) -> Result<i32, Fatal> {
    let env_path = args.env_file.clone();
    let example = env_path.parent().unwrap_or(Path::new("")).join(".env.example");
    if !env_path.exists() {
        if !example.exists() {
            return Err(Fatal(format!("neither {} nor {} exists", env_path.display(), example.display())));
        }
        let text = fs::read_to_string(&example).map_err(|e| Fatal(format!("cannot read {}: {e}", example.display())))?;
        fs::write(&env_path, text.replace("\r\n", "\n"))
            .map_err(|e| Fatal(format!("cannot write {}: {e}", env_path.display())))?;
        println!(".env       created from .env.example");
    }
    let mut env = EnvFile { vals: read_env_file(&env_path)?, path: env_path, changed: vec![] };

    let base = std::env::var("WIKI_BASE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| Some(env.get("WIKI_BASE").to_string()).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "http://localhost:3000".into());
    let email = env.val("WIKI_ADMIN_EMAIL", "admin@example.com");
    let site_url = env.val("WIKI_SITE_URL", "http://localhost:3000");
    let mut password = env.val("WIKI_ADMIN_PASSWORD", "");
    let mut updates: Vec<(&str, String)> = vec![];
    if env.get("WIKI_ADMIN_EMAIL").is_empty() {
        updates.push(("WIKI_ADMIN_EMAIL", email.clone()));
    }
    if password.is_empty() {
        password = token_urlsafe(24)?;
        updates.push(("WIKI_ADMIN_PASSWORD", password.clone()));
        println!(".env       WIKI_ADMIN_PASSWORD generated {}", mask(&password));
    }
    if !updates.is_empty() {
        // Save before /finalize: if the run dies after setup, the password is not lost.
        let u: Vec<(&str, &str)> = updates.iter().map(|(k, v)| (*k, v.as_str())).collect();
        write_env_file(&env.path, &u)?;
        for (k, v) in &updates {
            env.vals.insert((*k).into(), v.clone());
            env.changed.push((*k).into());
        }
    }

    println!("wiki       {base}");
    let w = Wiki::new(&base)?;
    if let Some(dur) = &args.purge_history {
        // The job writes a page version on every data change (~48/day at 30 min);
        // its key cannot purge history, so this runs as admin.
        w.wait(&[Mode::Ready], 60, "purge-history")?;
        let jwt = step_login(&w, &email, &password)?;
        let d = w.gql(
            "mutation ($o: String!) { pages { purgeHistory(olderThan: $o) { responseResult { succeeded message } } } }",
            json!({"o": dur}),
            Some(&jwt),
            "purgeHistory",
        )?;
        check(&d["pages"]["purgeHistory"], "purge history")?;
        println!("history    purged versions older than {dur} (all pages)");
        return Ok(0);
    }
    step_setup(&w, &email, &password, &site_url)?;
    let jwt = step_login(&w, &email, &password)?;
    step_api_on(&w, &jwt)?;
    let gid = step_group(&w, &jwt)?;
    let pid = step_page(&w, &jwt, &args)?; // before the key: the key check reads this page
    env.save("WIKI_PAGE_ID", &pid.to_string())?;
    let current = env.val("WIKIJS_API_KEY", "");
    let key = step_key(&w, &jwt, gid, &current, pid)?;
    env.save("WIKIJS_API_KEY", &key)?;
    step_smoke(&w, &key, pid)?;

    if env.changed.is_empty() {
        println!("bootstrap  ok (.env unchanged)");
    } else {
        println!("bootstrap  ok (.env updated: {})", env.changed.join(", "));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wiki::testing::{canned, client, serve};

    const SAMPLE: &str = "# Copy to .env\r\n\
        # Values are read by Docker Compose too.\n\
        \n\
        WIKI_BASE=http://localhost:3000\n\
        WIKI_PAGE_ID=\n\
        \x20 WIKIJS_API_KEY = \"abc\"  \n\
        # WIKI_ADMIN_PASSWORD=commented\n\
        WIKI_ADMIN_EMAIL='admin@example.com'\n\
        NVD_API_KEY=x=y\n\
        not a key line\n\
        1BAD=nope\n\
        WIKI_PAGE_ID=7\n";

    #[test]
    fn parse_env_like_python() {
        let v = parse_env(SAMPLE);
        assert_eq!(v["WIKI_BASE"], "http://localhost:3000");
        assert_eq!(v["WIKIJS_API_KEY"], "abc");
        assert_eq!(v["WIKI_ADMIN_EMAIL"], "admin@example.com");
        assert_eq!(v["NVD_API_KEY"], "x=y");
        assert_eq!(v["WIKI_PAGE_ID"], "7"); // later line wins
        assert!(!v.contains_key("WIKI_ADMIN_PASSWORD")); // comment
        assert!(!v.contains_key("1BAD"));
        assert_eq!(v.len(), 5);
    }

    #[test]
    fn render_env_keeps_other_lines() {
        let out = render_env(SAMPLE, &[("WIKIJS_API_KEY", "NEW"), ("WIKI_PAGE_ID", "1"), ("WIKI_ADMIN_PASSWORD", "pw")]);
        assert_eq!(
            out,
            "# Copy to .env\n\
             # Values are read by Docker Compose too.\n\
             \n\
             WIKI_BASE=http://localhost:3000\n\
             WIKI_PAGE_ID=1\n\
             WIKIJS_API_KEY=NEW\n\
             # WIKI_ADMIN_PASSWORD=commented\n\
             WIKI_ADMIN_EMAIL='admin@example.com'\n\
             NVD_API_KEY=x=y\n\
             not a key line\n\
             1BAD=nope\n\
             WIKI_PAGE_ID=7\n\
             WIKI_ADMIN_PASSWORD=pw\n"
        );
        // Only the first WIKI_PAGE_ID line is updated (same as the Python script).
        assert_eq!(parse_env(&out)["WIKIJS_API_KEY"], "NEW");
        assert_eq!(render_env("", &[("A", "1")]), "A=1\n");
    }

    #[test]
    fn env_file_round_trip_on_disk() {
        let dir = std::env::temp_dir().join(format!("ew-bootstrap-env-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join(".env");
        assert!(read_env_file(&p).unwrap().is_empty());
        let orig = "# keep me\nWIKI_PAGE_ID=\n\nUSER_AGENT=\n";
        fs::write(&p, orig).unwrap();
        write_env_file(&p, &[("WIKI_PAGE_ID", "1")]).unwrap();
        write_env_file(&p, &[("WIKIJS_API_KEY", "k.e.y")]).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "# keep me\nWIKI_PAGE_ID=1\n\nUSER_AGENT=\nWIKIJS_API_KEY=k.e.y\n");
        assert!(!dir.join(".env.tmp").exists());
        let v = read_env_file(&p).unwrap();
        assert_eq!((v["WIKI_PAGE_ID"].as_str(), v["WIKIJS_API_KEY"].as_str(), v["USER_AGENT"].as_str()), ("1", "k.e.y", ""));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn masking() {
        assert_eq!(mask(""), "(empty)");
        assert_eq!(mask("abc"), "****abc (3 chars)");
        assert_eq!(mask("0123456789nHf1"), "****nHf1 (14 chars)");
    }

    #[test]
    fn base64url_and_claims() {
        assert_eq!(b64url_encode(b""), "");
        assert_eq!(b64url_encode(b"f"), "Zg");
        assert_eq!(b64url_encode(b"fo"), "Zm8");
        assert_eq!(b64url_encode(b"foo"), "Zm9v");
        assert_eq!(b64url_encode(&[0xfb, 0xff, 0xbf]), "-_-_");
        assert_eq!(b64url_encode(&[7u8; 24]).len(), 32); // token_urlsafe(24) length
        for s in [&b""[..], b"f", b"fo", b"foo", b"foob", &[0xfb, 0xff, 0xbf, 1]] {
            assert_eq!(b64url_decode(&b64url_encode(s)).unwrap(), s);
        }
        assert_eq!(b64url_decode("Zm8=").unwrap(), b"fo");
        assert!(b64url_decode("Zm8*").is_none());
        // {"api":4,"grp":3,"iat":1,"exp":2,"aud":"urn:wiki.js","iss":"urn:wiki.js"}
        let payload = b64url_encode(br#"{"api":4,"grp":3,"iat":1,"exp":2,"aud":"urn:wiki.js","iss":"urn:wiki.js"}"#);
        let c = jwt_claims(&format!("eyJhbGciOiJSUzI1NiJ9.{payload}.sig"));
        assert_eq!((c["api"].as_i64(), c["grp"].as_i64()), (Some(4), Some(3)));
        assert!(jwt_claims("garbage").is_empty());
        assert!(jwt_claims("a.!!!.c").is_empty());
        assert!(jwt_claims(&format!("a.{}.c", b64url_encode(b"[1]"))).is_empty());
    }

    #[test]
    fn python_repr_and_check() {
        assert_eq!(py_repr(&json!({"a": 1, "b": [true, null, "it's"]})), r#"{'a': 1, 'b': [True, None, 'it\'s']}"#);
        assert!(check(&json!({"responseResult": {"succeeded": true, "message": "ok"}}), "x").is_ok());
        assert_eq!(check(&json!({"responseResult": {"succeeded": false, "message": "Nope"}}), "x").unwrap_err().0, "x refused: Nope");
        assert_eq!(
            check(&json!({"responseResult": {"succeeded": false, "message": ""}}), "x").unwrap_err().0,
            "x refused: {'message': '', 'succeeded': False}"
        );
        assert_eq!(check(&Value::Null, "purge history").unwrap_err().0, "purge history refused: {}");
    }

    #[test]
    fn read_file_strips_bom_and_rejects_blank() {
        let dir = std::env::temp_dir().join(format!("ew-bootstrap-rf-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("s.html");
        fs::write(&p, "\u{feff}<p>—</p>").unwrap();
        assert_eq!(read_file(&p, "page skeleton", "--skeleton").unwrap(), "<p>—</p>");
        fs::write(&p, " \n").unwrap();
        assert_eq!(read_file(&p, "page CSS", "--css").unwrap_err().0, format!("page CSS is empty: {}", p.display()));
        let missing = dir.join("nope.css");
        assert_eq!(
            read_file(&missing, "page CSS", "--css").unwrap_err().0,
            format!("page CSS not found: {} (pass --css <path>)", missing.display())
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn login_errors_map_like_python() {
        let (base, _rx) = serve(vec![
            canned(200, r#"{"errors":[{"message":"Too many requests, please try again in 51 seconds."}]}"#),
            canned(200, r#"{"data":{"authentication":{"login":{"jwt":null,"responseResult":{"succeeded":false,"message":"Invalid email / username or password."}}}}}"#),
            canned(200, r#"{"data":{"authentication":{"login":{"jwt":"J","responseResult":{"succeeded":true,"message":"Login success"}}}}}"#),
        ]);
        let w = Wiki::with_client(&base, client());
        assert_eq!(
            step_login(&w, "a@b", "p").unwrap_err().0,
            "admin login: GraphQL errors: Too many requests, please try again in 51 seconds. \
             Wiki.js allows 5 login calls per 60 s (good or bad); wait and rerun"
        );
        assert_eq!(
            step_login(&w, "a@b", "p").unwrap_err().0,
            "admin login failed: Invalid email / username or password. WIKI_ADMIN_EMAIL / WIKI_ADMIN_PASSWORD in .env \
             do not match this wiki's admin (the wiki-data volume keeps the account from its first setup)"
        );
        assert_eq!(step_login(&w, "a@b", "p").unwrap(), "J");
    }

    #[test]
    fn setup_already_finalized_and_finalize_refused() {
        let (base, rx) = serve(vec![
            canned(200, r#"{"data":{"__typename":"Query"}}"#),
            canned(404, "Cannot POST /graphql"),
            canned(200, r#"{"ok":false,"error":"Invalid email"}"#),
        ]);
        let w = Wiki::with_client(&base, client());
        assert!(!step_setup(&w, "a@b", "p", "http://x").unwrap());
        assert_eq!(step_setup(&w, "a@b", "p", "http://x").unwrap_err().0, "POST /finalize refused: Invalid email");
        let reqs: Vec<String> = rx.try_iter().collect();
        assert!(reqs[2].starts_with("POST /finalize "));
        assert!(reqs[2].contains(r#""telemetry":false"#));
    }
}
