# Cyber Threat Exploit Watch

Rebuilds the Wiki.js page `CTP/run-books/Cyber-Exploit-Watch` from free public vulnerability and advisory feeds, so the page always shows the last 7 days.

`Lab prototype` · `Local Docker Compose only` · `As of 2026-11-05`

## Contents

- [Overview](#overview)
- [Status and roadmap](#status-and-roadmap)
- [Getting started](#getting-started)
- [Architecture](#architecture)
- [How a run works](#how-a-run-works)
- [Feeds](#feeds)
- [Triage](#triage)
- [Operations](#operations)
- [Configuration](#configuration)
- [State](#state)
- [Known limitations](#known-limitations)
- [Development](#development)
- [Decisions](#decisions)

## Overview

fairCT is the EU bond Consolidated Tape Provider built by Ediphy. Its DORA milestone MS-30 ("Cyber threat dashboard") has one intake requirement, FR-A1:

> Ingest threat feeds from free, credible sources (CERT-EU, ENISA, CISA KEV, NCSC, NVD/CVE, MISP/CIRCL OSINT) into one dashboard. New items appear within 1 hour of publication; source and timestamp shown for each item.

This repository is a fork of Mark McKee's prototype `mckema/cyber-dashboard` (2026-10-17), which refreshed the page weekly from three feeds with a Python script. The fork:

- reads seven feeds: the FR-A1 sources except MISP/CIRCL OSINT, which Mark McKee dropped on 2026-11-03, plus GitHub Advisory;
- is a single Rust binary, `exploit-watch`;
- runs against a self-hosted Wiki.js 2.5 in Docker Compose for testing. The production page is on `wiki2.internal.ediphy.io` behind Google Cloud IAP and is not written by this fork yet.

The job also covers the next two MS-30 requirements, FR-A2 (triage every new item: relevant to fairCT or not, with a reason and who decided, within one business day) and FR-A3 (a ticket for each relevant item): it matches items against a component list, files one Linear issue per match and shows the untriaged items and open tickets on the page. See [Triage](#triage).

The job only replaces content inside anchored elements of the page (table bodies, counters, a stamp). Prose on the page stays hand-editable.

## Status and roadmap

Where each environment stands is in [Deployment](#deployment); decisions behind the plan are in [Decisions](#decisions).

| Item | Requirement | Status (2026-11-05) |
|---|---|---|
| Replace the sample component list with a test list from colleagues (Rust and UI libraries), then the list agreed with Germano | FR-A2 | Waiting for the list |
| Run `live` against a personal Linear Free workspace, then ask Mark McKee for a sandbox team in Ediphy's Linear | FR-A2, FR-A3, FR-A9 | Personal workspace done on 2026-11-04/05 (18 API and UI checks); sandbox team not requested yet |
| Monthly and on-demand report to the fairCT COO | FR-A4 | Not started |
| Cloud Run Job, Cloud Scheduler, GCS state, Terraform; write to `wiki2` via IAP | — | Deferred |

## Getting started

Requirements: Docker Desktop with Compose v2. No Rust toolchain is needed. Behind the corporate proxy, set `HTTP_PROXY` and `HTTPS_PROXY` on the host; Compose passes them to the build and the job.

```bash
docker compose up -d --wait wiki
docker compose run --rm job bootstrap        # once: admin, API key, page; writes .env
docker compose run --rm job run --dry-run    # fetch and diff, write nothing
docker compose up -d                         # start the job loop
```

The page is at http://localhost:3000/en/CTP/run-books/Cyber-Exploit-Watch. Run commands from the repository root (Git Bash on Windows). Every `docker compose run --rm job …` also starts `linear-mock` (the job waits for it to be healthy), so its image is built on first use.

## Architecture

Diagrams follow the [C4 model](https://c4model.com). Level 4 (code) is not drawn; [Deployment](#deployment) takes its place.

```mermaid
flowchart LR
  classDef person fill:#08427b,stroke:#052e56,color:#fff
  classDef system fill:#1168bd,stroke:#0b4884,color:#fff
  classDef container fill:#438dd5,stroke:#2e6295,color:#fff
  classDef ext fill:#999,stroke:#6b6b6b,color:#fff

  reader["Reader<br/>fairCT team"]:::person
  op["Operator<br/>ISB Vietnam team"]:::person
  ew["Exploit Watch<br/>rebuilds the page"]:::system
  feeds["7 public feeds<br/>CISA KEV · ENISA EUVD · CVE.org · NVD<br/>GitHub Advisory · CERT-EU · NCSC-NL"]:::ext
  wiki["Wiki.js<br/>page CTP/run-books/Cyber-Exploit-Watch"]:::ext
  linear["Linear<br/>Triage inbox of the team"]:::ext

  feeds -->|"HTTPS: JSON, CSV, RSS"| ew
  ew -->|"GraphQL pages.update"| wiki
  ew -->|"GraphQL: create issue, comment, read state"| linear
  reader -->|reads| wiki
  op -->|"bootstrap, run, reseed"| ew
  op -->|"Accept / Decline"| linear
```

*Level 1, System Context.*

```mermaid
flowchart LR
  classDef container fill:#438dd5,stroke:#2e6295,color:#fff
  classDef ext fill:#999,stroke:#6b6b6b,color:#fff

  feeds["Public feeds"]:::ext
  subgraph ew["Exploit Watch"]
    job["job<br/>Rust binary exploit-watch<br/>run --every N"]:::container
    state[("state/<br/>HTTP cache, cursors, seen.json,<br/>triage.json, runs.jsonl")]:::container
    comps["component list<br/>TOML file"]:::container
  end
  mock["linear-mock<br/>Rust binary, local lab only<br/>state/linear-mock/issues.json"]:::container
  linear["Linear<br/>real workspace"]:::ext
  subgraph wk["Wiki.js 2.5"]
    app["wiki<br/>Node.js, GraphQL API"]:::container
    db[("SQLite<br/>volume wiki-data")]:::container
  end

  feeds -->|"conditional GET (ETag, Range)"| job
  job <-->|"read/write files"| state
  comps --> job
  job -->|"GraphQL: issues, comments, states<br/>(compose default)"| mock
  job -.->|"same calls when LINEAR_API_URL<br/>points to api.linear.app"| linear
  job -->|"GraphQL: read page, update page"| app
  app --> db
```

*Level 2, Container.*

```mermaid
flowchart TB
  classDef component fill:#85bbf0,stroke:#5d82a8,color:#000
  classDef ext fill:#999,stroke:#6b6b6b,color:#fff

  main["main.rs<br/>CLI: run · bootstrap · demo · triage"]:::component
  run["run.rs<br/>window, merge, fingerprint, write"]:::component
  tri["triage/<br/>components, matcher, store,<br/>tracker, sync, step"]:::component
  lin["Linear"]:::ext
  feeds["feeds/*.rs<br/>one module per publisher"]:::component
  common["feeds/common.rs<br/>Item contract, GET with ETag cache"]:::component
  st["feeds/state.rs<br/>atomic files under state/"]:::component
  render["render/<br/>HTML for tables and counters, demo"]:::component
  wiki["wiki/mod.rs<br/>GraphQL client"]:::component
  boot["wiki/bootstrap.rs<br/>admin setup, key, page, CSS"]:::component
  wjs["Wiki.js"]:::ext

  main --> run & boot & render
  run --> feeds --> common --> st
  run --> tri --> st
  tri --> lin
  run --> render
  run --> wiki
  boot --> wiki
  wiki --> wjs
```

*Level 3, Component (inside the job; modules under `stack/job/src/`).*

### Deployment

| Environment | Runtime | Wiki | Status (2026-11-04) |
|---|---|---|---|
| Local lab | Docker Compose: `wiki` + `job` + `linear-mock`, loop every 21600 s (6 h); tracker `live` against `linear-mock` | Wiki.js 2.5.317, page id 1 | Running |
| Production | Cloud Scheduler + Cloud Run Job, state in GCS | `wiki2.internal.ediphy.io` via IAP, page id 51 | Decided, not built |

## How a run works

1. Take the lock `state/run.lock`, so only one run uses `state/` at a time. If another run holds it, stop (see the table below).
2. Set the window to the last 7 days (UTC).
3. Call each feed module in order. A module whose `CADENCE` has not elapsed reuses the items of its last successful fetch (`state/items/`).
4. Merge: CISA KEV and ENISA EUVD rows join by CVE into one "exploited" table; NVD scores fill CVE.org records that have no CNA or CISA-ADP score; CERT-EU and NCSC-NL share one advisory table.
5. Triage (see [Triage](#triage)): match every item against the component list, record new decisions in `triage.json`, and, on a writing run only, sync the tracker.
6. Render seven tables (feed health, exploited, advisories, dependencies, CVEs, untriaged, open tickets) and the counters, and splice them into the current page by anchor id. The feed health table ends with a "Linear" row for the tracker (see [Triage](#triage)).
7. Fingerprint the data, leaving out regions that change every run (health table, health count, window label). Write only when the fingerprint changed, when `HEARTBEAT_HOURS` (24 h) has passed since the last write, or when the page no longer carries the current data (after a reseed or a manual edit).
8. Write with one `pages.update` call. `scriptCss` is never sent by the job.
9. Record each item's first-seen time in `seen.json` and one line in `runs.jsonl`.

| Condition | Result |
|---|---|
| CISA KEV or CVE.org cvelistV5 fails (the `CORE` feeds) | `FATAL`, nothing written, exit 1 |
| Any other feed fails after an earlier success | Last good items reused, health row "Stale", page written, exit 0 |
| Any other feed fails with no earlier success | Health row "Error", its table empty |
| A feed module panics | Treated as that feed failing (`internal error: panic: …`) |
| Every feed returns nothing | Refuses to publish, exit 1 |
| A page anchor is missing | `page anchor … not found — re-seed the page skeleton`, exit 1 |
| No data change, heartbeat not due | `skipping write`, no new page version |
| `FATAL` while looping (`--every`) | Logged and recorded as `fatal`; next run proceeds |
| Component list does not load, or `triage.json` is unreadable | Triage skipped; the triage tables say why; feed tables written as usual |
| Tracker call fails | An error of one item (`INPUT_ERROR`, unexpected reply) skips that item; any other error stops issue creates and comments for this run. Issue states are read back in both cases, progress so far is saved, errors go to `runs.jsonl` under `triage.errors` and the first one to the Linear row of the health table; page written |
| Another run holds `state/run.lock` (for example a manual `docker compose run --rm job run` while the loop's run is in progress) | `LOCKED: another run holds …`, one `locked` line in `runs.jsonl`, nothing else written; a single run exits 75, the loop skips that run and tries again at its next interval |

## Feeds

| Source | Endpoint and method | Cadence | Timestamp shown |
|---|---|---|---|
| CISA KEV | `cisa.gov` catalog; on failure the GitHub mirror `cisagov/kev-data` with `If-None-Match` | every run | date |
| ENISA EUVD | `/api/search?fromKEVDate&toKEVDate` (exploited entries only) | every run | date |
| CVE.org cvelistV5 | Range read of `deltaLog.json` (`Accept-Encoding: identity`), then each changed record; first run backfills from daily zips | every run | second, UTC |
| NVD API 2.0 | `lastModStartDate` from the cursor minus 15 min; scores only, merged into CVE.org rows | 2 h | — |
| GitHub Advisory | `type=reviewed`, `published=<date>..<date>`, follows `Link: rel="next"` | every run | second, UTC |
| CERT-EU | RSS every run; JSON per advisory only when new or changed | every run | second, UTC |
| NCSC-NL | `changes.csv` with ETag; CSAF document only when new or changed | every run | second, UTC |

Measured on 2026-11-03 at the earlier 30-minute interval: a normal run made about 10–40 requests, most answered `304 Not Modified`. The first cvelistV5 backfill took 105 requests and 46.7 MB.

## Triage

FR-A2 asks for every new item to be triaged within one business day, with a reason and who decided; FR-A3 asks for a ticket with owner, due date and status for each relevant item. Mark McKee approved this flow on 2026-11-03; the same Linear ticket also serves FR-A9 for now.

```mermaid
flowchart LR
  classDef component fill:#85bbf0,stroke:#5d82a8,color:#000
  classDef ext fill:#999,stroke:#6b6b6b,color:#fff

  items["Items of this run<br/>KEV · EUVD · CVE.org · GitHub · CERT-EU · NCSC-NL"]:::ext
  comps["Component list<br/>COMPONENTS_FILE"]:::ext
  m["Matcher"]:::component
  nr["Not relevant by rule<br/>triager: matcher 1/&lt;list version&gt;"]:::component
  store[("triage.json")]:::component
  lin["Linear Triage inbox<br/>one issue per match"]:::ext
  page["Page: untriaged, open tickets"]:::component

  items --> m
  comps --> m
  m -->|no match| nr --> store
  m -->|match| store --> lin
  lin -->|"Accept: ticket / Decline: reason"| store --> page
```

- **Matcher** (`stack/job/src/triage/matcher.rs`, rule version 1), first rule that fits:
  1. `package`: GitHub advisory ecosystem and package equal a library component.
  2. `cpe`: a CVE.org CPE starts with a component's CPE 2.3 prefix.
  3. `vendor-product`: normalised product (and vendor, if the component lists vendors) from KEV, EUVD or CVE.org equals a component.
  4. `cve-join`: an advisory or other item whose CVE's CVE.org record matches by rules 1–3.

  Affected versions are not checked, so a match is a candidate. An item that matches nothing is recorded as not relevant, with `matcher <rule version>/<component list version>` as the triager.
- **Component list**: TOML, one `[[component]]` per entry (`id`, `kind` = library | image | infra, `ecosystem`, `names`, optional `vendors` and `cpe`). `stack/job/components.sample.toml` is a sample of 17 entries for testing; the real list is to be agreed with Germano (date not stated).
- **Store**: `state/triage.json` keeps one record per new item key with the decision, a copy of the item (so an issue can be filed after the item leaves the 7-day window), the issue and its last known state. Records older than 30 days are dropped once closed, declined with a reason, or not relevant. Every change is also appended to `state/triage-events.jsonl` (see [State](#state)), which keeps the history after the record is dropped; each `decided` event carries the component list version and the sha256 of its file, so a "not relevant by rule" decision can be traced to the exact list it was made with.
- **Tracker** (`LINEAR_MODE`): `off` (default of the binary) records decisions but files nothing; `live` calls a Linear GraphQL endpoint (`issueCreate` in the team's triage state, `commentCreate` when the item changes, issue states read back each run). The endpoint is `LINEAR_API_URL`, by default `https://api.linear.app/graphql`; compose points it at the `linear-mock` service, so the same HTTP client runs end to end without a Linear workspace.
- **Issue ids**: before the first `issueCreate` for a record, the job saves a random UUID v4 in `triage.json` (`issue_create_id`) and sends it as `IssueCreateInput.id` on every attempt. Linear refuses a second insert with the same id (HTTP 200, `INPUT_ERROR` "conflict on insert of Issue") and creates nothing, so when the answer to a create is lost, the next run reads the existing issue with `issue(id:)` and records it ("already existed" on stdout and, in a run without errors, on the Linear row of the health table; `recovered` in `runs.jsonl`). If the id is taken but Linear no longer returns its issue (deleted), the record gets a new id and the issue is filed once more. Linear accepts version 4 ids only; a name-based (v5) id was refused on 2026-11-05.
- **Read-back**: each run reads every issue's state with one `issues` query per 25 issues, including the 50 newest history entries and comments of each issue. Linear state types map to `triage` → untriaged, `backlog`/`unstarted`/`started` → accepted, `completed` → done, `duplicate` → declined, and `canceled` → declined or canceled. Since 2026-11-05 the job tells a Decline from a cancel after Accept: on the Linear test workspace a Decline set `canceledAt` within 3–4 ms of `triagedAt`, while an issue accepted one day and canceled the next had `canceledAt` about 20 hours after `triagedAt` and two history entries (Triage → Backlog, then Backlog → Canceled). So `canceled` with `canceledAt` more than 5 seconds after `triagedAt` is `canceled` (closed, no reason asked, dropped after 30 days like done), otherwise `declined`; without `canceledAt`, the history entry that left Triage decides (to backlog, unstarted, started or completed: canceled). `actor` and `changed` record who triaged the issue and when: `changed` is Linear's `triagedAt`, set by any move out of Triage (Accept, Decline, a status change, Mark as duplicate); `actor` is the name on the history entry within 5 seconds of `triagedAt`, otherwise on the newest entry that left Triage. Later moves, for example by the OAuth app, do not change them. The decline reason is the latest comment the job did not write, written no earlier than 5 seconds before `triagedAt` (a comment from while the issue was still in Triage is no reason); its time is kept as `reason_at`. An issue marked as duplicate without such a comment gets the reason `Marked as duplicate`. The query also reads `createdAt`, `startedAt`, `completedAt` and `canceledAt` into `created`, `started`, `completed` and `canceled` (UTC); records read back before 2026-11-05 lack them until the next read-back. A job image from before this change cannot load a `triage.json` that holds the state `canceled`, so roll back together with that file.
- **Tracker errors** (since 2026-11-05; `stack/job/src/triage/sync.rs`): no tracker error fails the run, and each is recorded. An error of one item or issue (GraphQL `INPUT_ERROR`, an unexpected reply, an id still taken after its retry) skips that item, and the run goes on with the next create or comment. An error that every further call would hit as well (no answer, HTTP error, rate limit, `AUTHENTICATION_ERROR`, `FORBIDDEN`, `INPUT_ERROR` "Entity not found: Team", a settings error, or a GraphQL error with another code) stops creates and comments for this run, because each call can wait up to the 90-second HTTP timeout. In both cases the run still reads every known issue's state back once, so accepts and declines in Linear reach the page while a create keeps failing. Skipped items are tried again next run. Before 2026-11-05 the first error of any kind ended the round, read-back included.
- **Linear row**: the feed health table ends with a "Linear" row: `OK` with the counts of the run (created, already existed, commented, updated) and the number of issues the store tracks; `Error` with the first error of the run (cut to 300 characters) and how many more there were; `Off` when `LINEAR_MODE=off`; `Error` "not configured" when the settings are invalid. A `--dry-run` or `--out` run in live mode calls no tracker and shows no Linear row. The row is not a feed: it is left out of the feed count above the table, the refresh bar and the `feeds` record in `runs.jsonl`. The row's status (`ok`, `error`, `off`) is part of the fingerprint, so a run where Linear goes from ok to error, or back, rewrites the page at once; a new error text or new counts under the same status wait for the next write (data change or the 24-hour heartbeat). The error is in `runs.jsonl` and on stdout at once.
- **Supported triage actions**: the flow approved by Mark McKee on 2026-11-03 is Accept (relevant; set an owner and a due date) and Decline (not relevant; give the reason as a comment), then the ticket's status until it is closed. Mark as duplicate is read as a decline. Snooze, Archive and Delete are not part of the flow and get no special handling (see [Known limitations](#known-limitations)).
- **linear-mock** (`stack/linear-mock/`, local lab only): answers five operations (`TriageState`, `IssueCreate`, `IssueById`, `CommentCreate`, `IssueStates`) with the shapes a real Linear workspace returned on 2026-11-04/05 and keeps issues in `state/linear-mock/issues.json`. To simulate triage, edit an issue's `state` (`accepted`, `declined`, `done`, `duplicate`, or `accepted-canceled` for a ticket accepted and later canceled) with `assignee`, `due` (YYYY-MM-DD), `reason`, `actor` (who triaged it) and optionally `changed` (when), and save; the next run reads it back. The mock returns history and comments newest first, sets `triagedAt` and writes one history entry for leaving Triage (with no states for `duplicate`); `accepted-canceled` gets two entries (Triage → Backlog at `changed`, Backlog → Canceled at `canceledAt`). Since 2026-11-05 it also returns `createdAt` (from `created`), `completedAt` for `done` (optional `completed`, else `changed`), and `canceledAt` for `declined` and `duplicate` (optional `canceled`, else `changed`, as Linear sets it at the Decline) and for `accepted-canceled` (optional `canceled`, else one hour after `changed`); `startedAt` is always null. `IssueCreate` keeps a client `id` (UUID v4) as the issue id and answers a repeated id with Linear's "conflict on insert of Issue" error. As a failure switch, an `IssueCreate` whose title contains `FAIL-CREATE` gets an `INPUT_ERROR` ("linear-mock: create refused") and creates nothing. Rate limits, pagination, other moves after the triage, Snooze and other operations are not simulated.
- **Page**: the untriaged table lists matched items with no decision in Linear, and issues declined without a reason (FR-A2 asks for one), with the note "declined in Linear without a reason" under the issue; such a row stays until a reason is added as a comment in Linear. A row turns red after one business day from first sight, counted Monday to Friday in Europe/Amsterdam time with no holiday calendar. The open-tickets table lists accepted issues with owner, due date (red when past) and state; a missing owner or due date is shown in red as "no owner" or "no due date" and counted in the table header. Only a writing run (not `--dry-run` or `--out`) files issues or saves `triage.json`.

Local test on 2026-11-04 with the sample list over the 7-day window, against `linear-mock`: 3,383 items, 2 matched (`clickhouse` and `vite`, rule `vendor-product`), 3,381 not relevant by rule; two issues filed (`MOCK-1`, `MOCK-2`), one accepted and one declined by editing `state/linear-mock/issues.json`, and the next run showed one open ticket and no untriaged item. With a wrong `LINEAR_API_KEY` the run still wrote the page and recorded the authentication error in `runs.jsonl`.

## Operations

```bash
docker compose ps
docker compose logs -f job
docker compose run --rm job run                          # one run now
docker compose run --rm job run --out state/out.html     # render with live data, no write
docker compose run --rm job bootstrap --update-css       # after editing stack/wiki/page/style.css
docker compose run --rm job bootstrap --reseed --update-css && docker compose run --rm job run
                                                         # after editing stack/wiki/page/skeleton.html
docker compose run --rm job bootstrap --purge-history P7D   # drop page versions older than 7 days (all pages)
docker compose build job                                 # after any change under stack/job/src/
docker compose run --rm job triage --report              # match counts over state/items/, no network
docker compose build linear-mock                         # after any change under stack/linear-mock/src/
docker compose logs linear-mock                          # one line per GraphQL call from the job
tail -5 state/runs.jsonl
```

`bootstrap` is idempotent: a second run keeps the existing key (`bootstrap ok (.env unchanged)`). After `docker compose down -v` the wiki's admin and key are gone; run `bootstrap` again to recreate them.

Only one `run` uses `state/` at a time. A manual `docker compose run --rm job run` started while the loop's run is in progress prints `LOCKED: …`, records `locked` in `runs.jsonl` and exits 75 without doing anything; run it again once `docker compose logs job` shows the loop's run has finished. If the loop's run starts while a manual run holds the lock, the loop skips that run and tries again at its next interval (6 hours).

## Configuration

Read from `.env` (created by `bootstrap` from `.env.example`) and the environment. Compose overrides `WIKI_BASE` and `STATE_DIR` for the job, and supplies `LINEAR_*` defaults that point at `linear-mock` when `.env` leaves them empty.

| Variable | Default | Used for |
|---|---|---|
| `WIKI_BASE` | `https://wiki2.internal.ediphy.io` (compose: `http://wiki:3000`) | Wiki.js URL |
| `WIKI_PAGE_ID` | `51` (local bootstrap writes `1`) | Page to update |
| `WIKIJS_API_KEY` | — | Bot key, sent as `Authorization` |
| `IAP_ID_TOKEN` | — | Google OIDC token, sent as `Proxy-Authorization` (behind IAP only) |
| `WIKI_ADMIN_EMAIL`, `WIKI_ADMIN_PASSWORD` | `admin@example.com`, generated | Local admin, used by `bootstrap` only |
| `STATE_DIR` | `./state` | Job state |
| `INTERVAL_SECONDS` | `21600` | Seconds between runs in the compose loop |
| `HEARTBEAT_HOURS` | `24` | Rewrite the page after this long without a data change |
| `CVE_ROW_CAP` | `300` | Rows shown in the CVE table |
| `GITHUB_TOKEN` | — | Raises the GitHub API limit from 60 to 5,000 requests/h |
| `NVD_API_KEY` | — | Removes the 6 s pause between NVD pages |
| `USER_AGENT` | built-in | User-Agent for feed requests; CERT-EU rejects requests without one |
| `COMPONENTS_FILE` | `stack/job/components.sample.toml` | Component list for the matcher |
| `LINEAR_MODE` | `off` (compose: `live`) | Tracker: `off` or `live` |
| `LINEAR_API_URL` | `https://api.linear.app/graphql` (compose: `http://linear-mock:8080/graphql`) | Linear GraphQL endpoint |
| `LINEAR_API_KEY` | — (compose: `lin_api_mock`) | Live mode only. A Linear personal API key (prefix `lin_api_`, sent as `Authorization: <key>`) or an OAuth access token, e.g. from an OAuth app's `client_credentials` grant (prefix `lin_oauth_`, sent as `Authorization: Bearer <token>`). Never written to logs, errors or the page |
| `LINEAR_TEAM_ID` | — (compose: `mock-team`) | Live mode only: the team whose Triage inbox receives issues |
| `MOCK_APP_TOKEN` (`linear-mock` only) | — (compose: `lin_oauth_mock`) | OAuth access token the mock accepts as `Authorization: Bearer <token>` besides `MOCK_API_KEY`; must differ from `MOCK_API_KEY` and must not start with `lin_api_`. Set `LINEAR_API_KEY=lin_oauth_mock` in `.env` to exercise the job's Bearer path against the mock |

Do not put `$` or quotes in `.env` values: Compose reads the file too.

## State

`state/` is gitignored, owned by uid 1000 (the job's user), and was about 16 MB on 2026-11-03.

| Path | Content |
|---|---|
| `http/` | Conditional-GET cache: ETag and body of the last `200` |
| `items/<module>.json` | Items of each feed's last successful fetch |
| `cursors/` | Per-feed cursors: cvelistV5 `fetchTime`, NVD and CVE stores, CERT-EU and NCSC-NL caches |
| `seen.json` | Item key → first-seen time, kept 30 days |
| `wiki.json` | Data fingerprint and time of the last write |
| `triage.json` | One record per new item: decision, item copy, issue create id (`issue_create_id`), issue and its last read state (`issue_status`: `state` = `triage`, `accepted`, `done`, `declined` or `canceled`, `state_name`, `assignee`, `due`, `reason`, `reason_at`, `actor` = who triaged it, `changed` = when it left Triage, and since 2026-11-05 `created`, `started`, `completed`, `canceled` from Linear). The working set: records are dropped 30 days after first sight once finished |
| `triage-events.jsonl` | Since 2026-11-05: every change to `triage.json` as one JSON line (`decided`, `issue_created`, `triaged`, `state_changed`, `field_changed`, `pruned`), each with a stable `id`, `key`, `at` (when it happened) and `ts` (when it was logged). Appended by writing runs only and never pruned; the source for the FR-A4 report and the audit trail. The first writing run after the upgrade writes a `baseline` of every record held at that time, dated from the record (the decision at first sight, triage and closing at the times Linear gave, owner, due date and reason at the record's last change), so history before 2026-11-05 covers only records still in `triage.json` then. About 3 MB a month with the sample list (estimate) |
| `linear-mock/issues.json` | Issues held by the `linear-mock` service; editable by hand to simulate triage |
| `run.lock` | Lock held by the run in progress (advisory `flock`); while held it contains that run's pid, container hostname and start time, otherwise it is empty. Do not delete it |
| `runs.jsonl` | One line per run: `result` (`written`, `unchanged`, `would-write`, `out`, `locked`, `fatal`, `crash`), per-feed `status`, `items`, `new`, `baseline`, `lag_max_min`, `lag_median_min`, and `triage` (`components` version and `components_sha256` of the list file, `mode`, `endpoint` in live mode, `new_matched`, `new_not_relevant`, `created`, `recovered`, `commented`, `updated`, `pruned`, `missing_owner`, `missing_due`, `missing_reason`, `missing_actor`, `errors`: one line per tracker error of the run) |

Lag is an item's first-seen time minus its first publication time (`published`; a later `updated` time is ignored), in minutes. It is recorded for items new on a run whose publication time has a time of day, and not on a feed's first (baseline) run. It is a metric, not a pass/fail rule (Mark McKee, 2026-11-03).

`missing_owner` and `missing_due` count open tickets without an assignee or a due date; `missing_reason` counts matched items declined without a reason; `missing_actor` counts matched items out of Triage with no name for who triaged them. Since 2026-11-05 a read-back that comes back without `actor` or `changed` for an issue still out of Triage keeps the earlier values. They are counted from `triage.json` on every run, also when no tracker call is made, for the FR-A4 monthly report.

Every `run` takes the lock, including `--dry-run`, `--out` and each `--every` iteration, because all of them write feed caches, cursors and `runs.jsonl`; only the wiki write is skipped. `bootstrap`, `demo` and `triage --report` do not write `state/` and do not take the lock. The lock is released when a run ends in any way, including a panic or `docker compose kill`, so it never needs to be cleared by hand.

Reset only what you need: deleting `http/` forces full downloads; deleting `cursors/cvelist*` forces a 7-day backfill (about 47 MB); deleting `seen.json` makes the next run a baseline with no lag measured. If a root container created files in `state/`, the job cannot write them; fix with `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/app" debian:bookworm-slim chown -R 1000:1000 /app/state`.

## Known limitations

Found by testing against Wiki.js 2.5.317 and the live feeds on 2026-11-03.

**Job**

- The run lock is an advisory `flock` on `state/run.lock`. It works across containers on one Docker host, including Docker Desktop's Windows bind mount (verified 2026-11-04), but not across hosts or on object storage; the production design (Cloud Run Job, state in GCS) needs a different lock, for example a GCS object created with an `ifGenerationMatch=0` precondition (not built).

**Wiki.js**

- The HTML sanitiser strips `<style>`, `<script>` and `<link>` and mangles long inline `style` attributes, so the page has no JavaScript and no inline styles.
- `pages.single` checks `manage:pages`, not `read:pages`. The bot key's group has `read:pages`/`write:pages` on `CTP/run-books/` and `manage:pages` on this page only.
- A wrong key does not return 401: an unknown key reads as guest (HTTP 200, "not authorized"); a revoked key or a disabled API returns HTTP 500.
- An admin `pages.update` without `scriptCss` clears the page CSS; `bootstrap` always resends it. The bot key has no `write:styles`, so job writes keep it.
- Every update creates a page version (about 330 KB each). Old versions are removed only by `bootstrap --purge-history`, as admin.
- `pages.create` reports a misleading "not authorized to delete" message on refusal; only its error code is reliable.
- Behind the corporate proxy the local wiki cannot fetch its locale files, so its chrome shows raw keys such as `header.search`. The page is not affected.

**Feeds**

- `cisa.gov` returns 403 through the corporate proxy; KEV is read from the GitHub mirror, which trailed catalog releases by 1.1–4.4 h (8 releases, 2026-10-21..30).
- NVD scores few new CVEs: a severity filter returned 156 of 3,371 CVEs over 7 days. NVD is used for scores only.
- The GitHub API allows 60 unauthenticated requests per hour per IP, shared by everyone behind the proxy; `304` responses still count.
- CERT-EU's RSS dates carry a "CEST" label; the job uses the per-advisory JSON time (UTC). Whether the label changes to "CET" in winter is not verified.
- Some NCSC-NL documents have only a CVSS 4.0 vector in a note; those items show no score. NCSC-NL titles are in Dutch.
- The CVE table shows the first 300 rows by score (`CVE_ROW_CAP`).
- Items with a date only (KEV, EUVD) have no measurable lag.

**Triage**

- The matcher does not check affected versions; every match needs a person to confirm it in Linear.
- Items cached before 2026-11-04 lack the `products`, `cpes` and `eco_packages` fields the matcher reads until they are fetched again (for CVE.org: delete `state/cursors/cvelist*`).
- The business-day clock has no holiday calendar.
- Linear does not require an owner and a due date on Accept, or a comment on Decline. The job only flags these gaps on the page and counts them in `runs.jsonl`; it does not block triage or write to Linear. Whether to make them mandatory is pending with Mark McKee.
- Linear behaviour the code relies on was checked against a personal Linear Free workspace (EU region) on 2026-11-04/05: a wrong or revoked key gives HTTP 401 with `AUTHENTICATION_ERROR`; history and comments come back newest first and `first: N` keeps the N newest; Mark as duplicate uses its own state type `duplicate` (not `canceled`) and writes a history entry without states; an OAuth app appears as a user in `actor`, not in `botActor`. `linear-mock` follows these results; a passing local run does not prove other Linear behaviour.
- Who triaged an issue is found only while that history entry is among the issue's 50 newest; after more changes `actor` is empty, while `changed` (from `triagedAt`) stays correct.
- Snooze keeps an issue in Triage, so a snoozed item stays untriaged and turns red after one business day; whether Snooze counts as triage is to be decided with Mark McKee.
- Archive is not handled: an issue archived in Linear keeps the state it had, so one archived while still in Triage stays in the untriaged table. The job still reads it (`includeArchived: true`). Linear's UI offers no Archive action for an issue in Triage.
- The decline reason is the latest comment the job did not write, so a comment added after a decline replaces it. The issue a duplicate points to is not recorded.
- Moving an issue back to Triage and out again is not tested; `triagedAt` may keep the first triage time.
- Issue ids are random and kept in `state/triage.json`; if that file is lost or restored from an older copy after an issue was created, the next run can file a second issue for the same item. Linear refused a name-based (v5) id, which would have survived this.
- If an issue is deleted in Linear before the job has recorded it (its create answer was lost), the job files a new issue under a new id. Whether Linear frees a deleted issue's id, and whether `issue(id:)` returns archived or trashed issues, is not verified.
- The path that sends `IssueCreateInput.id` from the job has run against `linear-mock` and in unit tests; on the real workspace only a hand-made create with a fixed id was tested (2026-11-05), because no new item matched the test component list after the change.
- A wrong `LINEAR_TEAM_ID`, or a key not scoped to that team, gets HTTP 200 with `INPUT_ERROR` "Entity not found: Team" from Linear, not `FORBIDDEN`; the error on the Linear row of the health table names both causes, and the run stops creating issues at the first one, as for `FORBIDDEN`.
- Issue references in `state/triage.json` belong to one tracker. Before pointing `LINEAR_API_URL` at another endpoint (mock to real Linear or back), or when resetting `state/linear-mock/`, move `state/triage.json` aside too. Otherwise a comment on an issue the endpoint does not have fails on every run until that item leaves the 7-day window, and the issue keeps its last known state. Before 2026-11-05 the first such error also stopped the read-back of every other issue.
- A hand edit to `state/linear-mock/issues.json` reaches the page on the next writing run: within 6 hours in the loop, or now with `docker compose run --rm job run`. Put a decline reason in `reason`; `comments` holds the job's own comments.
- The job does not obtain or refresh OAuth tokens. A `client_credentials` access token lasts 30 days; after that every Linear call fails with `AUTHENTICATION_ERROR` (shown on the Linear row of the health table and in `runs.jsonl`; the run itself does not fail) until `LINEAR_API_KEY` is replaced with a new token.
- `linear-mock` checks only the header form of the OAuth token; it does not simulate token issuance, expiry, revocation or scopes.

## Development

```text
compose.yml                 all services: wiki (Wiki.js 2.x), job, linear-mock; one folder each in stack/
stack/wiki/page/            skeleton.html (page content with anchor ids), style.css (scriptCss)
stack/job/Cargo.toml        crate exploit-watch (Rust 1.99, edition 2024), with Cargo.lock
stack/job/src/              the crate's source
stack/job/tests/fixtures/   trimmed real payloads for unit tests and demo
stack/job/Dockerfile        build on rust:1.99.1-slim-bookworm, run on debian:bookworm-slim as uid 1000
stack/job/Dockerfile.dockerignore   build context: Cargo.toml, Cargo.lock, src/ only
stack/job/components.sample.toml    sample component list for triage
stack/linear-mock/          crate linear-mock (local stand-in for the Linear API), with its own Cargo.lock and Dockerfile
```

The job container's working directory is the repo root (bind mount `.:/app`), so runtime paths such as `stack/wiki/page/skeleton.html` and `stack/job/components.sample.toml` are relative to the repo root; tests resolve them from the crate directory two levels down.

Unit tests run in a container and make no network calls. Add a test name to run one test; add `-- --ignored` for the tests that call the live feeds.

```bash
MSYS_NO_PATHCONV=1 docker run --rm -e HTTP_PROXY=$HTTP_PROXY -e HTTPS_PROXY=$HTTPS_PROXY \
  -v cargo-registry:/usr/local/cargo/registry -v ew-target:/target -e CARGO_TARGET_DIR=/target \
  -v "$(pwd -W):/src" -w /src/stack/job rust:1.99.1-slim-bookworm cargo test --quiet
```

For `linear-mock`, use `-w /src/stack/linear-mock` and a separate target volume (`-v ew-target-mock:/target`). After changing either crate, rebuild its image: `docker compose build job` or `docker compose build linear-mock`.

`exploit-watch demo OUT.html [--dark]` renders the page from `stack/job/tests/fixtures/render_items.json` for visual review.

To add a feed, write a module in `stack/job/src/feeds/` that follows the contract at the top of `stack/job/src/feeds/common.rs` (`NAME`, `CADENCE`, `fetch(start, end)` returning all items or an error, never a partial list), list it in `feeds::all()`, and decide in `run.rs` which table it fills and whether it is triaged. Page markup must not use inline `style` attributes; all styling goes in `stack/wiki/page/style.css` (see [Known limitations](#known-limitations)).

## Decisions

| Date | Decision | By | Status |
|---|---|---|---|
| 2026-11-03 | Build FR-A1 on the prototype: fork, all FR-A1 sources, self-hosted Wiki.js for testing | ISB Vietnam team lead | Decided |
| 2026-11-03 | "NCSC" in FR-A1 means NCSC-NL | Mark McKee | Decided |
| 2026-11-03 | Run every 6 hours instead of every 30 minutes | Mark McKee | Decided, applied |
| 2026-11-03 | Drop CIRCL OSINT | Mark McKee | Decided, applied |
| 2026-11-03 | Accept the KEV GitHub mirror as fallback until `cisa.gov` is rechecked from GCP | Mark McKee | Decided |
| 2026-11-03 | "Within 1 hour" is not a hard rule; measure lag from first publication only | Mark McKee | Decided, applied |
| 2026-11-03 | FR-A2: items matching no fairCT component are marked not relevant by rule; rule name and version recorded as triager | Mark McKee | Decided, built (local) |
| 2026-11-03 | Component list: a small test list (Rust or UI libraries) for now; final list to be agreed with Germano | Mark McKee | Decided |
| 2026-11-03 | FR-A9: a Linear ticket is sufficient for now | Mark McKee | Decided |
| 2026-11-03 | Production runtime: Cloud Scheduler + Cloud Run Job | Mark McKee | Decided, deferred until the local workflow is verified |
| 2026-11-03 | Do not create the prototype's GitHub Actions workflow for now | ISB Vietnam team | Decided |
| 2026-11-03 | Business day for FR-A2 counted Monday to Friday in Europe/Amsterdam time | ISB Vietnam team | Decided |
| 2026-11-03 | `LINEAR_MODE` defaults to `off` in the binary; compose sets `fake` for local tests | ISB Vietnam team | Replaced on 2026-11-04 |
| 2026-11-04 | One folder per compose service under `stack/` (`wiki`, `job`, `linear-mock`); the job stays one process (feeds, triage, render, write), matching one Cloud Run Job in production | ISB Vietnam team | Decided, applied |
| 2026-11-04 | Local triage tests go through a `linear-mock` service over HTTP; the file-based `fake` tracker is removed and `LINEAR_MODE` is `off` or `live` (compose: `live` against `linear-mock`) | ISB Vietnam team | Decided, applied |
| 2026-11-04 | Verify `live` against a personal Linear Free workspace before asking Mark McKee for a sandbox team in Ediphy's Linear | ISB Vietnam team | Decided |
| 2026-11-04 | One run at a time per `state/` directory: every `run` (also `--dry-run`, `--out` and each `--every` iteration) takes an advisory `flock` on `state/run.lock`; a run that finds it held records `locked` and exits 75, and the loop skips to its next interval. Chosen over a lock file with a stale timeout because the kernel releases a `flock` on any exit; verified across two containers on Docker Desktop's Windows bind mount. Follows two overlapping runs on 2026-11-04 that broke an atomic write of `triage.json` | ISB Vietnam team | Decided, applied |
| 2026-11-04 | `LINEAR_API_KEY` may hold a personal API key or an OAuth access token; the job sends a value starting with `lin_api_` bare and any other value as `Bearer <value>`, with no separate override variable; `linear-mock` also accepts `Bearer <MOCK_APP_TOKEN>`. An OAuth app token (prefix `lin_oauth_`) was verified against a real Linear workspace on 2026-11-04 | ISB Vietnam team | Decided, applied |
| 2026-11-05 | The job supports the approved flow only: Accept with owner and due date, Decline with a reason, then the ticket's status; Snooze, Archive and Delete get no special handling | ISB Vietnam team | Decided |
| 2026-11-05 | Read who triaged an issue and when from Linear's `triagedAt` and the history entry next to it, not from the latest state change; map Linear's `duplicate` state to declined with reason "Marked as duplicate" when no comment gives one; read the 50 newest history entries and comments per issue | ISB Vietnam team | Decided, applied |
| 2026-11-05 | Issue creation is idempotent: the job saves a random UUID v4 per record in `triage.json` before the first attempt and sends it as `IssueCreateInput.id`; Linear's "conflict on insert of Issue" answer means the issue exists, and it is read back by id. A name-based (v5) id was refused by Linear, so the id cannot be derived from the item key | ISB Vietnam team | Decided, applied |
| 2026-11-05 | Flag accepted issues without an owner or due date and declines without a reason as warnings on the page and in `runs.jsonl`; no enforcement in Linear until the mandatory rules are agreed with Mark McKee | ISB Vietnam team | Decided, applied |
