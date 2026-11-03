#!/usr/bin/env python3
"""
One-time (and safely repeatable) setup of the local Wiki.js 2.x for the
Exploit Watch job.

  docker compose up -d wiki
  docker compose run --rm job python bootstrap_wiki.py [--reseed] [--update-css]

Steps, each skipped when already done:
  1. Finish the first-run setup wizard (POST /finalize) and wait for the restart.
  2. Log in as the local admin.
  3. Turn the GraphQL API on (it is off by default).
  4. Create/refresh group "exploit-watch": read+write pages under CTP/run-books/,
     plus manage:pages on the one page (needed to read it; see step_group).
  5. Create the page CTP/run-books/Cyber-Exploit-Watch from page/skeleton.html
     with page/style.css as scriptCss. Done as admin, because the bot key
     deliberately lacks write:styles.
  6. Create API key "exploit-watch" bound to that group, unless .env already holds
     a working one (revoking older "exploit-watch" keys). The key is shown once,
     so it goes straight into .env.
  7. Smoke test: the bot key reads the page with pages.single, as the job does.

.env gets WIKIJS_API_KEY, WIKI_PAGE_ID and, if generated, WIKI_ADMIN_PASSWORD
(written as soon as each is known; every other line is kept).

Flags (both act as admin on an existing page):
  --update-css   re-push scriptCss from the CSS file, keep content
  --reseed       overwrite content from the skeleton, keep current scriptCss
                 (combine with --update-css to replace both)
"""

import argparse
import base64
import json
import os
import re
import secrets
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(HERE, ".env")
ENV_EXAMPLE = os.path.join(HERE, ".env.example")

PAGE_PATH = "CTP/run-books/Cyber-Exploit-Watch"
PAGE_LOCALE = "en"
PAGE_TITLE = "Cyber Threat Exploit Watch"
PAGE_DESC = "Exploited-in-the-wild vulnerabilities, critical CVEs and dependency advisories from public feeds. Rebuilt on a schedule."
PAGE_TAGS = ["runbook", "threat-intel"]
RULE_PATH = "CTP/run-books/"
GROUP_NAME = "exploit-watch"
KEY_NAME = "exploit-watch"
KEY_EXPIRATION = "1y"
TIMEOUT = 30


class Fatal(Exception):
    """Abort with a clear message; nothing after the failing step is attempted."""


# ---------------------------------------------------------------- .env

def read_env_file(path):
    vals = {}
    if not os.path.exists(path):
        return vals
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", line.rstrip("\r\n"))
            if m:
                vals[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return vals


def write_env_file(path, updates):
    """Set KEY=value for each update, in place; append keys that are missing."""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    else:
        lines = []
    done = set()
    for i, line in enumerate(lines):
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m and m.group(1) in updates and m.group(1) not in done:
            lines[i] = f"{m.group(1)}={updates[m.group(1)]}"
            done.add(m.group(1))
    for k, v in updates.items():
        if k not in done:
            lines.append(f"{k}={v}")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


def mask(v):
    if not v:
        return "(empty)"
    return f"****{v[-4:]} ({len(v)} chars)"


# ---------------------------------------------------------------- http

class Wiki:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.s = requests.Session()

    def _post(self, path, payload, token=None):
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        return self.s.post(f"{self.base}{path}", json=payload, headers=h, timeout=TIMEOUT)

    def gql(self, query, variables=None, token=None, label="GraphQL"):
        try:
            r = self._post("/graphql", {"query": query, "variables": variables or {}}, token)
        except requests.RequestException as e:
            raise Fatal(f"{label}: cannot reach {self.base}: {e}")
        if r.status_code == 401:
            raise Fatal(f"{label}: HTTP 401 from Wiki.js: API disabled, or the token is wrong/revoked")
        if not r.ok:
            raise Fatal(f"{label}: HTTP {r.status_code}: {r.text[:300]}")
        try:
            j = r.json()
        except ValueError:
            raise Fatal(f"{label}: non-JSON reply (is the wiki still in setup mode?): {r.text[:200]}")
        if j.get("errors"):
            raise Fatal(f"{label}: GraphQL errors: " + "; ".join(e.get("message", "?") for e in j["errors"]))
        return j["data"]

    def mode(self):
        """'ready', 'setup', or None (not answering)."""
        try:
            r = self._post("/graphql", {"query": "{ __typename }"})
        except requests.RequestException:
            return None
        if r.status_code == 404:
            return "setup"  # the setup-wizard app only serves GET * and POST /finalize
        try:
            if r.ok and r.json().get("data", {}).get("__typename"):
                return "ready"
        except ValueError:
            pass
        return None

    def wait(self, want, seconds, what):
        deadline = time.time() + seconds
        last = None
        while time.time() < deadline:
            last = self.mode()
            if last in want:
                return last
            time.sleep(2)
        raise Fatal(f"{what}: Wiki.js at {self.base} not {'/'.join(want)} after {seconds}s "
                    f"(last state: {last or 'no answer'}). Check `docker compose logs wiki`.")


def check(res, what):
    rr = res.get("responseResult") or {}
    if not rr.get("succeeded"):
        raise Fatal(f"{what} refused: {rr.get('message') or rr}")
    return res


# ---------------------------------------------------------------- steps

def step_setup(w, email, password, site_url):
    state = w.wait({"ready", "setup"}, 180, "startup")
    if state == "ready":
        print("setup      already finalized")
        return False
    print(f"setup      finalizing (admin {email}, siteUrl {site_url})")
    try:
        r = w._post("/finalize", {"adminEmail": email, "adminPassword": password,
                                   "siteUrl": site_url, "telemetry": False})
        j = r.json()
    except (requests.RequestException, ValueError) as e:
        raise Fatal(f"POST /finalize failed: {e}")
    if not j.get("ok"):
        raise Fatal(f"POST /finalize refused: {j.get('error') or j}")
    time.sleep(3)  # server tears down the setup app and reboots ~1 s after replying
    w.wait({"ready"}, 180, "restart after setup")
    print("setup      done, wiki restarted")
    return True


def step_login(w, email, password):
    try:
        d = w.gql("""
          mutation ($u: String!, $p: String!) {
            authentication { login(username: $u, password: $p, strategy: "local") {
              jwt responseResult { succeeded message } } }
          }""", {"u": email, "p": password}, label="admin login")
    except Fatal as e:
        if "Too many requests" in str(e):
            raise Fatal(f"{e} Wiki.js allows 5 login calls per 60 s (good or bad); wait and rerun")
        raise
    res = d["authentication"]["login"]
    if not (res.get("responseResult") or {}).get("succeeded") or not res.get("jwt"):
        msg = ((res.get("responseResult") or {}).get("message") or "no message").rstrip(".")
        raise Fatal(f"admin login failed: {msg}. WIKI_ADMIN_EMAIL / "
                    "WIKI_ADMIN_PASSWORD in .env do not match this wiki's admin (the wiki-data "
                    "volume keeps the account from its first setup)")
    print(f"login      ok as {email}")
    return res["jwt"]


def step_api_on(w, jwt):
    on = w.gql("{ authentication { apiState } }", token=jwt, label="apiState")["authentication"]["apiState"]
    if on:
        print("api        already enabled")
        return
    check(w.gql("mutation { authentication { setApiState(enabled: true) { responseResult { succeeded message } } } }",
                token=jwt, label="setApiState")["authentication"]["setApiState"], "setApiState")
    print("api        enabled")


def step_group(w, jwt):
    def find():
        groups = w.gql("{ groups { list { id name } } }", token=jwt, label="groups.list")["groups"]["list"]
        hits = sorted(g["id"] for g in groups if g["name"] == GROUP_NAME)
        if len(hits) > 1:
            print(f"  warning: {len(hits)} groups named {GROUP_NAME!r} (ids {hits}); using {hits[0]}")
        return hits[0] if hits else None

    gid = find()
    if gid is None:
        check(w.gql("mutation ($n: String!) { groups { create(name: $n) { responseResult { succeeded message } } } }",
                    {"n": GROUP_NAME}, token=jwt, label="groups.create")["groups"]["create"], "groups.create")
        gid = find()
        if gid is None:
            raise Fatal(f"group {GROUP_NAME!r} was created but does not appear in groups.list")
        print(f"group      created {GROUP_NAME!r} id {gid}")
    else:
        print(f"group      reusing {GROUP_NAME!r} id {gid}")

    # Always re-apply, so a hand-edited group is put back to least privilege.
    #
    # Why manage:pages: in 2.5.x `pages.single` / `pages.singleByPath` (the only
    # GraphQL reads that return page content) check manage:pages OR delete:pages on
    # the page, NOT read:pages. Without it the job's READ_PAGE fails with "You are
    # not authorized to view this page." manage:pages is the lesser of the two
    # (delete:pages would let the key delete the page), and it is pinned by an
    # EXACT rule to the one page. What it adds there: move (destination still needs
    # write:pages, so only inside CTP/run-books/), convert, restore a version.
    check(w.gql("""
      mutation ($id: Int!, $n: String!, $perm: [String]!, $rules: [PageRuleInput]!) {
        groups { update(id: $id, name: $n, redirectOnLogin: "/", permissions: $perm, pageRules: $rules) {
          responseResult { succeeded message } } }
      }""", {
        "id": gid, "n": GROUP_NAME,
        "perm": ["read:pages", "write:pages", "manage:pages"],
        "rules": [
            {"id": "rb", "deny": False, "match": "START",
             "roles": ["read:pages", "write:pages"], "path": RULE_PATH, "locales": [PAGE_LOCALE]},
            {"id": "ew", "deny": False, "match": "EXACT",
             "roles": ["manage:pages"], "path": PAGE_PATH, "locales": [PAGE_LOCALE]},
        ],
    }, token=jwt, label="groups.update")["groups"]["update"], "groups.update")
    print(f"group      read:pages+write:pages START {RULE_PATH!r}; "
          f"manage:pages EXACT {PAGE_PATH!r}; locale {PAGE_LOCALE}")
    return gid


def jwt_claims(token):
    try:
        part = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (IndexError, ValueError):
        return {}


def key_works(w, key, pid):
    """True only if `key` can do what the job does: pages.single on the page.

    A cheaper check is not enough: Wiki.js treats a malformed or foreign-signed
    key as a guest (HTTP 200), and guests may run pages.list. pages.single needs
    manage:pages on the page, which only our group has.
    """
    if not key:
        return False
    try:
        w.gql("query ($id: Int!) { pages { single(id: $id) { id } } }", {"id": pid},
              token=key, label="key check")
        return True
    except Fatal as e:
        print(f"  key rejected: {e}")
        return False


def step_key(w, jwt, gid, current, pid):
    keys = w.gql("{ authentication { apiKeys { id name isRevoked } } }",
                 token=jwt, label="apiKeys")["authentication"]["apiKeys"] or []
    if current:
        c = jwt_claims(current)
        ours = any(k["id"] == c.get("api") and k["name"] == KEY_NAME and not k["isRevoked"] for k in keys)
        if not ours:
            print(f"  .env key is not a live {KEY_NAME!r} key of this wiki (claims {c or 'unreadable'})")
        elif c.get("grp") != gid:
            print(f"  .env key is bound to group {c.get('grp')}, not {gid}")
        elif key_works(w, current, pid):
            print(f"apikey     .env key works, keeping it ({mask(current)})")
            return current
    for k in keys:
        if k["name"] == KEY_NAME and not k["isRevoked"]:
            check(w.gql("mutation ($id: Int!) { authentication { revokeApiKey(id: $id) { responseResult { succeeded message } } } }",
                        {"id": k["id"]}, token=jwt, label="revokeApiKey")["authentication"]["revokeApiKey"],
                  f"revokeApiKey {k['id']}")
            print(f"apikey     revoked old key id {k['id']}")
    res = check(w.gql("""
      mutation ($n: String!, $exp: String!, $g: Int!) {
        authentication { createApiKey(name: $n, expiration: $exp, fullAccess: false, group: $g) {
          key responseResult { succeeded message } } }
      }""", {"n": KEY_NAME, "exp": KEY_EXPIRATION, "g": gid}, token=jwt,
        label="createApiKey")["authentication"]["createApiKey"], "createApiKey")
    key = res["key"]
    # The new key must be usable right away; fail here rather than in the job.
    for _ in range(5):
        if key_works(w, key, pid):
            break
        time.sleep(2)
    else:
        raise Fatal("createApiKey returned a key that Wiki.js then rejects")
    print(f"apikey     created {KEY_NAME!r} for group {gid}, expires in {KEY_EXPIRATION} ({mask(key)})")
    return key


def find_page(w, jwt):
    pages = w.gql("{ pages { list(limit: 100000) { id path locale } } }",
                  token=jwt, label="pages.list")["pages"]["list"]
    hits = sorted(p["id"] for p in pages if p["path"] == PAGE_PATH and p["locale"] == PAGE_LOCALE)
    return hits[0] if hits else None


def read_file(path, what, flag):
    if not os.path.isfile(path):
        raise Fatal(f"{what} not found: {path} (pass {flag} <path>)")
    with open(path, encoding="utf-8-sig") as f:  # -sig: a BOM must not land in the page
        data = f.read()
    if not data.strip():
        raise Fatal(f"{what} is empty: {path}")
    return data


def step_page(w, jwt, args):
    pid = find_page(w, jwt)
    if pid is None:
        content = read_file(args.skeleton, "page skeleton", "--skeleton")
        css = read_file(args.css, "page CSS", "--css")
        # Do NOT request `page { ... }` in the response: Page.editor serialises to null
        # and the reply carries an error although the page was created.
        check(w.gql("""
          mutation ($content: String!, $desc: String!, $css: String, $tags: [String]!, $title: String!,
                    $path: String!, $locale: String!) {
            pages { create(content: $content, description: $desc, editor: "code", isPublished: true,
                           isPrivate: false, locale: $locale, path: $path, tags: $tags, title: $title,
                           scriptCss: $css) {
              responseResult { succeeded message } } }
          }""", {"content": content, "desc": PAGE_DESC, "css": css, "tags": PAGE_TAGS,
                 "title": PAGE_TITLE, "path": PAGE_PATH, "locale": PAGE_LOCALE},
            token=jwt, label="pages.create")["pages"]["create"], "pages.create")
        pid = find_page(w, jwt)
        if pid is None:
            raise Fatal(f"page {PAGE_PATH} was created but does not appear in pages.list")
        print(f"page       created {PAGE_LOCALE}/{PAGE_PATH} id {pid} "
              f"({len(content)} B content, {len(css)} B css)")
        return pid

    print(f"page       reusing {PAGE_LOCALE}/{PAGE_PATH} id {pid}")
    if not (args.reseed or args.update_css):
        return pid

    cur = w.gql("""
      query ($id: Int!) { pages { single(id: $id) {
        content title description scriptCss scriptJs tags { tag } } } }""",
                {"id": pid}, token=jwt, label="pages.single")["pages"]["single"]
    content = read_file(args.skeleton, "page skeleton", "--skeleton") if args.reseed else cur["content"]
    css = read_file(args.css, "page CSS", "--css") if args.update_css else (cur.get("scriptCss") or "")
    # As admin (write:styles + write:scripts) update() REPLACES scriptCss/scriptJs with
    # whatever is sent, empty included. So always send both, or the CSS is wiped.
    check(w.gql("""
      mutation ($id: Int!, $content: String!, $tags: [String]!, $title: String!, $desc: String!,
                $css: String, $js: String) {
        pages { update(id: $id, content: $content, tags: $tags, title: $title, description: $desc,
                       scriptCss: $css, scriptJs: $js, isPublished: true) {
          responseResult { succeeded message } } }
      }""", {"id": pid, "content": content, "tags": [t["tag"] for t in (cur.get("tags") or [])],
             "title": cur["title"], "desc": cur.get("description") or "",
             "css": css, "js": cur.get("scriptJs") or ""},
        token=jwt, label="pages.update")["pages"]["update"], "pages.update")
    done = []
    if args.reseed:
        done.append(f"content reseeded ({len(content)} B)")
    if args.update_css:
        done.append(f"scriptCss re-pushed ({len(css)} B before minify)")
    print("page       " + ", ".join(done))
    return pid


def step_smoke(w, key, pid):
    # Same read the job does (rebuild.py READ_PAGE), with the bot key.
    p = w.gql("query ($id: Int!) { pages { single(id: $id) { id path content } } }",
              {"id": pid}, token=key, label="bot read (pages.single)")["pages"]["single"]
    print(f"smoke      bot key reads page {p['id']} ({p['path']}, {len(p['content'] or '')} B)")


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--skeleton", default=os.path.join(HERE, "page", "skeleton.html"),
                    help="page content used on create / --reseed (default: page/skeleton.html)")
    ap.add_argument("--css", default=os.path.join(HERE, "page", "style.css"),
                    help="scriptCss used on create / --update-css (default: page/style.css)")
    ap.add_argument("--reseed", action="store_true", help="overwrite page content from --skeleton (as admin)")
    ap.add_argument("--update-css", action="store_true", help="re-push scriptCss from --css (as admin)")
    ap.add_argument("--purge-history", metavar="DURATION",
                    help="only delete page versions older than an ISO 8601 duration, e.g. P7D (as admin; all pages)")
    args = ap.parse_args()

    if not os.path.exists(ENV_PATH):
        if not os.path.exists(ENV_EXAMPLE):
            raise Fatal(f"neither {ENV_PATH} nor {ENV_EXAMPLE} exists")
        with open(ENV_EXAMPLE, encoding="utf-8") as src, \
             open(ENV_PATH, "w", encoding="utf-8", newline="\n") as dst:
            dst.write(src.read())
        print(".env       created from .env.example")
    env = read_env_file(ENV_PATH)

    def val(k, default=""):
        return env.get(k) or os.environ.get(k) or default

    base = os.environ.get("WIKI_BASE") or env.get("WIKI_BASE") or "http://localhost:3000"
    email = val("WIKI_ADMIN_EMAIL", "admin@example.com")
    site_url = val("WIKI_SITE_URL", "http://localhost:3000")
    password = val("WIKI_ADMIN_PASSWORD")
    updates = {}
    if not env.get("WIKI_ADMIN_EMAIL"):
        updates["WIKI_ADMIN_EMAIL"] = email
    if not password:
        password = secrets.token_urlsafe(24)  # [A-Za-z0-9_-]: safe for compose .env parsing
        updates["WIKI_ADMIN_PASSWORD"] = password
        print(f".env       WIKI_ADMIN_PASSWORD generated {mask(password)}")
    if updates:
        # Save before /finalize: if the run dies after setup, the password is not lost.
        write_env_file(ENV_PATH, updates)
        env.update(updates)

    changed = list(updates)

    def save(k, v):
        # Written as soon as known: the API key is shown once, so a later failure
        # must not lose it.
        if v != env.get(k):
            write_env_file(ENV_PATH, {k: v})
            env[k] = v
            changed.append(k)
            print(f".env       {k} = {v if k == 'WIKI_PAGE_ID' else mask(v)}")

    print(f"wiki       {base}")
    w = Wiki(base)
    if args.purge_history:
        # The job writes a page version on every data change (~48/day at 30 min);
        # its key cannot purge history, so this runs as admin.
        w.wait({"ready"}, 60, "purge-history")
        jwt = step_login(w, email, password)
        res = w.gql("mutation ($o: String!) { pages { purgeHistory(olderThan: $o) "
                    "{ responseResult { succeeded message } } } }",
                    {"o": args.purge_history}, jwt, "purgeHistory")
        check(res["pages"]["purgeHistory"], "purge history")
        print(f"history    purged versions older than {args.purge_history} (all pages)")
        return 0
    step_setup(w, email, password, site_url)
    jwt = step_login(w, email, password)
    step_api_on(w, jwt)
    gid = step_group(w, jwt)
    pid = step_page(w, jwt, args)  # before the key: the key check reads this page
    save("WIKI_PAGE_ID", str(pid))
    key = step_key(w, jwt, gid, val("WIKIJS_API_KEY"), pid)
    save("WIKIJS_API_KEY", key)
    step_smoke(w, key, pid)

    print(f"bootstrap  ok ({'.env updated: ' + ', '.join(changed) if changed else '.env unchanged'})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)
