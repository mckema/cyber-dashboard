# Cyber Threat Exploit Watch — scheduled rebuild

Keeps the runbook page at
**[hostname]/run-books/Cyber-Exploit-Watch**
current, by pulling five free public feeds on a schedule and writing the result
back through the Wiki.js GraphQL API.

No paid threat-intel subscription, no API account, no vendor platform.

---

## 1. What already exists

The page is **live and working now**, built by hand on 17 Oct 2026. You are
automating the refresh, not building the page.

| Thing | State |
|---|---|
| Page | id **51**, path `CTP/run-books/Cyber-Exploit-Watch` |
| Content | ~144 KB of HTML: prose, three tables, source cards |
| Styling | ~11 KB in the page's **`scriptCss`** field — **leave this alone** |
| `scriptJs` | Deliberately **empty**. See §7 — it does not work here |
| Editor | `code` / contentType `html` |
| Backend | SQLite |

The job replaces **only** the three `<tbody>` elements and the counters. Prose,
callouts and source cards stay hand-editable — reword the page freely and the
next run will not clobber it.

---

## 2. What you need to create

Three credentials. None exist yet.

### 2a. Turn the Wiki.js API on — *it is currently off*

Checked on 17 Oct: `authentication.apiState` is `false` and there are no keys.
**Nothing can write to the wiki until this is done.**

1. Administration → API → **Enable API**
2. Create a key, note it (shown once)
3. Store as repo secret `WIKIJS_API_KEY`

The key inherits the permissions of the group you attach it to. It needs
`write:pages` on `CTP/run-books/*`. Don't give it admin.

### 2b. A GCP service account that IAP will admit

```bash
PROJECT=<your-project>

gcloud iam service-accounts create exploit-watch-bot \
  --project="$PROJECT" \
  --display-name="Exploit Watch page rebuilder"

# Grant access to the IAP-protected resource. Scope this to the specific
# backend service, not the whole project.
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --service=<wiki-backend-service> \
  --member="serviceAccount:exploit-watch-bot@$PROJECT.iam.gserviceaccount.com" \
  --role="roles/iap.httpsResourceAccessor"
```

### 2c. Workload Identity Federation, so Actions needs no key file

```bash
REPO=<org>/<repo>

gcloud iam workload-identity-pools create github \
  --project="$PROJECT" --location=global \
  --display-name="GitHub Actions"

gcloud iam workload-identity-pools providers create-oidc github \
  --project="$PROJECT" --location=global \
  --workload-identity-pool=github \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='$REPO'"

PROJECT_NUM=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')

gcloud iam service-accounts add-iam-policy-binding \
  "exploit-watch-bot@$PROJECT.iam.gserviceaccount.com" \
  --project="$PROJECT" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUM/locations/global/workloadIdentityPools/github/attribute.repository/$REPO"
```

The `attribute-condition` pinning the repo matters. Without it, any GitHub repo
anywhere can impersonate this service account.

---

## 3. The bit that catches people: two stacked auth layers

The wiki sits behind **two independent gates**, and they both want the
`Authorization` header.

```
GitHub Actions
      │  Proxy-Authorization: Bearer <google-oidc-id-token>   ← outer gate
      │  Authorization:       Bearer <wikijs-api-key>         ← inner gate
      ▼
 Google Cloud IAP  ──consumes Proxy-Authorization, forwards Authorization──▶  Wiki.js
```

IAP consumes `Authorization` and **never forwards it**, so a Wiki.js key sent
that way vanishes in transit and you get a confusing 401 from the app. Sending
the IAP token as `Proxy-Authorization` instead leaves `Authorization` free for
Wiki.js. `rebuild.py` already does this (`wiki_headers()`).

**IAP audience (the OIDC token's `aud`):**

```
67656592571-61jia7k51h2f8nvej0osatfguirrhsc2.apps.googleusercontent.com
```

Read off the sign-in redirect from `my_host` on 17 Oct 2026.
Confirm before relying on it: GCP Console → Security → Identity-Aware Proxy →
select the resource → ⋮ → **OAuth credentials**.

`id_token_include_email: true` in the workflow is **not optional** — IAP rejects
service-account tokens that omit the email claim.

---

## 4. Repo layout

```
.
├── README.md
├── rebuild.py
└── .github/workflows/exploit-watch.yml
```

Drop these into any repo the team already owns. Nothing here is specific to a
particular repo beyond the WIF binding in §2c.

### Repo configuration

**Secrets** (Settings → Secrets and variables → Actions → Secrets):

| Name | Value |
|---|---|
| `WIKIJS_API_KEY` | from §2a |

**Variables** (same page, Variables tab):

| Name | Example |
|---|---|
| `GCP_WIF_PROVIDER` | `projects/123456789/locations/global/workloadIdentityPools/github/providers/github` |
| `GCP_SERVICE_ACCOUNT` | `exploit-watch-bot@your-project.iam.gserviceaccount.com` |
| `IAP_CLIENT_ID` | the audience from §3 |

`GITHUB_TOKEN` is supplied automatically by Actions — it lifts the GitHub
advisories limit from 60 req/hour per IP to 5,000, which matters because
GitHub-hosted runners share egress IPs.

---

## 5. First run

Dry run first. It fetches, builds, diffs and writes **nothing**:

```bash
gh workflow run exploit-watch.yml -f dry_run=true
```

Expected output:

```
window 2026-10-12 -> 2026-10-19
  KEV            9  (catalog 2026.10.16)
  NVD crit      27
  NVD high      98
  GitHub        71
content 144132 -> 144580 bytes
dry run: not writing
```

Then let it write:

```bash
gh workflow run exploit-watch.yml
```

Locally, if you have an IAP token to hand:

```bash
export WIKIJS_API_KEY=...
export IAP_ID_TOKEN=$(gcloud auth print-identity-token \
  --audiences=67656592571-61jia7k51h2f8nvej0osatfguirrhsc2.apps.googleusercontent.com \
  --impersonate-service-account=exploit-watch-bot@$PROJECT.iam.gserviceaccount.com \
  --include-email)
python rebuild.py --dry-run
```

---

## 6. What the job does

1. Rolling 7-day window from "now" (UTC).
2. `GET` CISA KEV — from `cisa.gov` directly.
3. `GET` NVD critical, pause 7s, `GET` NVD high *(5 req/30s unauthenticated)*.
4. `GET` GitHub advisories `type=reviewed`, critical then high — one call each.
5. Build the three tables as HTML using the classes the page's CSS already styles.
6. Read the current page, splice rows into the three `<tbody>`s, update the four
   stat tiles, three counts, window label and rebuild stamp.
7. SHA-256 the result; **skip the write entirely if nothing changed**.
8. One `pages.update` mutation.

Takes ~15 seconds, five outbound requests, at most one write.

---

## 7. Wiki.js quirks — learned the hard way, don't re-derive

These were found by trial against *this* instance on 17 Oct. They are encoded in
`rebuild.py`; this section is so you know why the code looks the way it does.

**Page content is sanitised.** `<style>`, `<script>` and `<link>` are stripped
from page content. Short `style="..."` attributes survive; **long
multi-declaration ones get mangled** — the renderer splits them on spaces into
junk pseudo-attributes (`padding:30px="" 32px;`). Do not try to style this page
with inline styles. The CSS belongs in `scriptCss`, where it already is.

**`scriptJs` is not executed.** On this version it is dumped into `<body>` as raw
markup, so the HTML fragments inside JS string literals get parsed as elements
and splatter across the page. It is deliberately empty. **There is no way to run
JavaScript on a Wiki.js page here** unless an admin disables
*Administration → Rendering → html → Sanitize HTML* — which is global and would
let any wiki editor run script on your IAP-authenticated origin. That is why the
page has no in-page refresh button and is regenerated by this job instead.

**GraphQL `pages.update`:**

| Quirk | Symptom if ignored |
|---|---|
| `tags` is required | `Cannot read properties of undefined (reading 'map')` |
| `content` is required, even when changing only CSS | `Page content cannot be empty` |
| Don't request `page { ... }` in the response | `Cannot return null for non-nullable field Page.editor` — **while the write succeeds**, so it looks like a failure and isn't |
| `editor` cannot be changed by `update` | Silently ignored; use `pages.convert` |

**`scriptCss` is only ever written by hand.** The job never touches it. If the
page's look needs changing, edit that field directly.

---

## 8. Failure behaviour

All-or-nothing on anything that matters. A stale brief beats a half-populated one.

| Condition | Behaviour |
|---|---|
| CISA KEV or either NVD call fails | Nothing written, exit 1 |
| GitHub 403/429 | Exit 1 with an explicit rate-limit message |
| All feeds return empty | Refuses to publish, exit 1 |
| A page anchor id is missing | Exit 1 naming the anchor (someone rewrote the skeleton — re-seed it) |
| Redirected to `accounts.google.com` | Exit 1: IAP token missing/expired, or the SA lacks `roles/iap.httpsResourceAccessor` |
| HTTP 401 from Wiki.js | Exit 1: API disabled, or key wrong/revoked |
| Nothing changed since last run | Logs and exits 0 without writing |

Non-zero exit fails the workflow, which is what should page you. Consider adding
a notification step on `failure()`.

---

## 9. Operational notes

**SQLite + version history.** Every write creates a new page version at ~144 KB.
Weekly is ~52/year (~7 MB) — fine. Daily would be ~365/year (~50 MB) and wants
periodic history pruning. The cron is currently **Fridays 07:00 UTC**; change it
in the workflow if you want a different cadence.

**Rate limits.** NVD allows 5 req/30s unauthenticated — hence the 7-second pause,
which is skipped automatically if you set `NVD_API_KEY` (free, optional). GitHub
is handled by the built-in `GITHUB_TOKEN`.

**The feeds move under you.** Between two pulls 40 minutes apart on 17 Oct, NVD
re-scored the same week from 20 critical / 113 high to 27 / 98. Same 133 CVEs,
different severities. Counts shifting between runs is normal, not a bug.

**Severity is not risk.** The page says this and it bears repeating: CVSS scores
the flaw, not your exposure. The exploited-in-the-wild table is first because it
is ordered by evidence rather than theory.

**NVD scoring lags badly.** In the 10–17 Oct window NVD published 5,531 CVEs and
had scored 409 of them — about one in thirteen. A severity filter hides
everything still awaiting analysis, so an empty NVD table is not an all-clear.
The GitHub feed is less affected because reviewed entries are scored on intake.

---

## 10. Known limitations

- **No in-page refresh button.** Blocked by the sanitiser, §7. The only route to
  one is disabling Sanitize HTML globally.
- **Single page, hardcoded id 51.** Fine for one runbook; parameterise if this
  pattern spreads.
- **The window is wall-clock, not a diff.** Each run replaces the whole table
  with the last 7 days. Something dropping off the bottom is not flagged.
- **Untested end-to-end.** The GraphQL calls are proven — they are exactly what
  built the live page — but the IAP service-account path has never run, because
  the Wiki.js API was off and no service account existed. §5's dry run is the
  first real test. Expect to iterate on §2b–2c, not on the script.

---

## 11. Related files

In `~/Documents/claude/` on Mark's machine:

- `Cyber-Exploit-Watch.html` — the fully interactive single-file version, with a
  working refresh button. Only usable if Sanitize HTML is ever turned off, or
  served from somewhere other than the wiki. Opened as a local `file://` URL its
  button works, which is a handy way to see the intended design.
- `Cyber-Exploit-Watch-WIKI.html` — **deprecated, do not paste into the wiki.**
  This is the inline-styled version whose `style` attributes the renderer
  mangles. It is what produced the garbage on `/en/home`. Delete it.
