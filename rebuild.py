#!/usr/bin/env python3
"""
Rebuild the Cyber Threat Exploit Watch runbook page on Wiki.js.

Pulls eight public feeds (see feeds/__init__.py), rebuilds the six table bodies
and the counters on the page, and writes the result back through the Wiki.js
GraphQL API.

Only the anchored regions are replaced. Prose, callouts and the source cards
stay hand-editable; a colleague can reword the page and this job will not
clobber it.

Environment:
  WIKI_BASE         https://wiki2.internal.ediphy.io   (compose: http://wiki:3000)
  WIKI_PAGE_ID      51                                  (local bootstrap: 1)
  WIKIJS_API_KEY    Wiki.js API key          -> Authorization header
  IAP_ID_TOKEN      Google OIDC ID token     -> Proxy-Authorization header (only behind IAP)
  STATE_DIR         ./state                  caches, cursors, seen.json, runs.jsonl
  CVE_ROW_CAP       300                      rows shown in the CVE table
  HEARTBEAT_HOURS   6                        rewrite even without data changes after this long
  GITHUB_TOKEN      optional, raises GitHub rate limit 60/hr -> 1000-5000/hr
  NVD_API_KEY       optional, raises NVD rate limit

Usage:
  python rebuild.py --dry-run          # fetch + build + diff, write nothing
  python rebuild.py                    # fetch + build + write if the data changed
  python rebuild.py --out page.html    # fetch + build into page/skeleton.html, no wiki
  python rebuild.py --every 1800       # loop forever, one run every 30 min
"""

import argparse
import hashlib
import importlib
import json
import os
import sys
import time
import traceback
from datetime import timedelta

import requests

import feeds
import render
from feeds import state
from feeds.common import Fatal, Item, SourceError, iso_utc, parse_iso

WIKI_BASE = os.environ.get("WIKI_BASE", "https://wiki2.internal.ediphy.io").rstrip("/")
PAGE_ID = int(os.environ.get("WIKI_PAGE_ID", "51"))
WIKIJS_API_KEY = os.environ.get("WIKIJS_API_KEY", "")
IAP_ID_TOKEN = os.environ.get("IAP_ID_TOKEN", "")
CVE_ROW_CAP = int(os.environ.get("CVE_ROW_CAP", "300"))
HEARTBEAT = timedelta(hours=float(os.environ.get("HEARTBEAT_HOURS", "6")))

TIMEOUT = 90
WINDOW = timedelta(days=7)
SLA = timedelta(hours=1)
SKELETON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "page", "skeleton.html")

# Regions that change on every run without the data changing. They are left out
# of the "did anything change" fingerprint, otherwise every run writes a new
# page version (Wiki.js keeps them all).
VOLATILE = {"t-health", "n-health", "winlabel"}


# ---------------------------------------------------------------- feeds

def load_cached(name):
    c = state.load_json(f"items/{name}.json", None)
    return c, ([Item.from_dict(d) for d in c["items"]] if c else [])


def newest(items):
    return max((i.updated or i.published for i in items), default="")


def fetch_one(name, start, end, now):
    """Fetch one feed module, honouring CADENCE and the failure policy.
    Returns (items, health row). Raises Fatal when a CORE feed fails."""
    mod = importlib.import_module(f"feeds.{name}")
    cached, old = load_cached(name)
    h = {"source": mod.NAME, "status": "", "items": 0, "newest": "",
         "last_success": cached["last_success"] if cached else "", "note": ""}
    age = (now - parse_iso(cached["last_success"])) if cached else None

    if cached and mod.CADENCE and age.total_seconds() < mod.CADENCE:
        items = old
        h["status"] = "cached"
        h["note"] = f"Polled every {mod.CADENCE // 3600} h; next fetch after " \
                    f"{render.ftime(iso_utc(parse_iso(cached['last_success']) + timedelta(seconds=mod.CADENCE)))}."
    else:
        try:
            items = mod.fetch(start, end)
        except Exception as e:  # noqa: BLE001 - a bug in one feed must not blank the page
            msg = str(e) if isinstance(e, SourceError) else f"internal error: {type(e).__name__}: {e}"
            if name in feeds.CORE:
                raise Fatal(f"{mod.NAME}: {msg}")
            print(f"  {mod.NAME}: {msg}", file=sys.stderr)
            items = old
            h["status"] = "stale" if cached else "error"
            h["note"] = (f"Stale since {render.ftime(cached['last_success'])}: " if cached else "") + msg[:200]
        else:
            state.save_json(f"items/{name}.json", {
                "last_success": iso_utc(now), "items": [i.to_dict() for i in items]})
            h["status"], h["last_success"] = "ok", iso_utc(now)
            h["note"] = feed_note(name, mod, items)

    h["items"], h["newest"] = len(items), newest(items)
    return items, h


def feed_note(name, mod, items):
    """One line for the health table: how this run got its data."""
    st = getattr(mod, "STATS", {}) or {}
    if name == "kev" and items:
        via = items[0].extra.get("via", "")
        return f"Read from {via}." + (" cisa.gov refused the request." if via != "cisa.gov" else "")
    if name == "cvelist":
        return f"{st.get('mode', '')}: {st.get('changed', 0)} changed records, {st.get('requests', 0)} requests."
    if name == "nvd":
        return "Enrichment only: adds NVD scores to CVE.org records; polled every 2 h."
    if name == "github":
        return f"{st.get('requests', 0)} requests."
    if name == "circl" and not items:
        return "Fetched; no new or changed events in the window."
    return ""


def merge_exploited(kev, euvd):
    """KEV + EUVD on one row per CVE. CISA rows win (they carry the due date)."""
    rows = {}
    for it in kev:
        it.extra["sources"] = [it.source]
        rows[it.id] = it
    for it in euvd:
        if it.id in rows:
            k = rows[it.id]
            k.extra["sources"].append(it.source)
            for f in ("euvd_id", "exploited_since"):
                k.extra.setdefault(f, it.extra.get(f, ""))
        else:
            it.extra["sources"] = [it.source]
            rows[it.id] = it
    return list(rows.values())


def enrich_cves(cves, nvd):
    """Add NVD's score to CVE.org records; fill the score where the CNA and CISA ADP gave none."""
    by_id = {i.id: i for i in nvd}
    for it in cves:
        n = by_id.get(it.id)
        if not n or not n.score:
            continue
        it.extra["nvd_score"] = n.score
        if not it.score:
            it.score, it.severity = n.score, n.severity
            it.extra["score_source"] = "NVD"
            it.extra.setdefault("vector", n.extra.get("vector", ""))
            if n.extra.get("vendors") and not it.extra.get("vendors"):
                it.extra["vendors"] = n.extra["vendors"]
    return cves


def sla_stats(names, tables, health, now):
    """Record first_seen for every item the page carries; per feed, how late new items were.

    A feed's first run is its baseline: everything is "new" but was published
    days ago, so no lag is measured. Date-only timestamps (KEV dateAdded) can't
    be measured either. NVD only enriches CVE.org rows and has no rows of its own."""
    seen_before = state.load_json("seen.json", {})
    out = {}
    for name, h, items in zip(names, health, tables):
        src = h["source"]
        if name == "nvd":
            out[src] = {"status": h["status"], "items": len(items), "sla": "n/a (enrichment only)"}
            continue
        baseline = not any(k.startswith(src + ":") for k in seen_before)
        new = state.mark_seen([i.key for i in items], now)
        lags = []
        for i in items:
            ts = i.updated or i.published
            if i.key in new and len(ts) > 10 and not baseline:
                lags.append((now - parse_iso(ts)).total_seconds() / 60)
        out[src] = {
            "status": h["status"], "items": len(items), "new": len(new), "baseline": baseline,
            "lag_max_min": round(max(lags), 1) if lags else None,
            "over_sla": sum(1 for x in lags if x > SLA.total_seconds() / 60),
        }
    return out


# ---------------------------------------------------------------- wiki api

def wiki_headers():
    if not WIKIJS_API_KEY:
        raise Fatal("WIKIJS_API_KEY is empty")
    h = {"Content-Type": "application/json", "Authorization": f"Bearer {WIKIJS_API_KEY}"}
    if IAP_ID_TOKEN:
        # IAP consumes Authorization and never forwards it, so the IAP token rides
        # on Proxy-Authorization and Authorization is left for Wiki.js.
        h["Proxy-Authorization"] = f"Bearer {IAP_ID_TOKEN}"
    return h


def gql(query, variables=None):
    try:
        r = requests.post(f"{WIKI_BASE}/graphql", headers=wiki_headers(),
                          json={"query": query, "variables": variables or {}}, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise Fatal(f"cannot reach Wiki.js at {WIKI_BASE}: {e}")
    if r.status_code in (301, 302) or "accounts.google.com" in r.text[:600]:
        raise Fatal("redirected to Google sign-in: the IAP token is missing, expired, "
                    "or the service account lacks roles/iap.httpsResourceAccessor")
    # Wiki.js 2.5 never answers 401 for a bad key: a revoked key or a disabled API
    # is HTTP 500 with a message, and an unknown key is treated as a guest (200 +
    # "not authorized" in errors).
    if not r.ok:
        raise Fatal(f"GraphQL HTTP {r.status_code}: {r.text[:300]}")
    j = r.json()
    if j.get("errors"):
        msg = "; ".join(e.get("message", "?") for e in j["errors"])
        if "not authorized" in msg:
            msg += " (WIKIJS_API_KEY unknown to this wiki, or its group lacks manage:pages on the page)"
        raise Fatal("GraphQL errors: " + msg)
    return j["data"]


READ_PAGE = """
query ($id: Int!) {
  pages { single(id: $id) { content title description tags { tag } } }
}
"""

# Note: do NOT request `page { ... }` in the mutation response. Page.editor is
# non-nullable and serialises to null here, which surfaces as a GraphQL error
# even though the write succeeded. scriptCss is not sent: the job's key has no
# write:styles, so Wiki.js keeps the hand-written CSS.
WRITE_PAGE = """
mutation ($id: Int!, $content: String!, $tags: [String]!, $title: String!, $desc: String!) {
  pages {
    update(id: $id, content: $content, tags: $tags, title: $title,
           description: $desc, isPublished: true) {
      responseResult { succeeded errorCode message }
    }
  }
}
"""


# ---------------------------------------------------------------- main

def fingerprint(regions):
    stable = {
        "tbody": {k: v for k, v in regions["tbody"].items() if k not in VOLATILE},
        "text": {k: v for k, v in regions["text"].items() if k not in VOLATILE},
        # Health statuses count (a feed going stale is news); their timestamps don't.
        "health": regions.get("health_status"),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def run(args):
    t0 = time.monotonic()
    now = state.utcnow()
    end, start = now, now - WINDOW
    print(f"window {iso_utc(start)} -> {iso_utc(end)}")

    got, health = {}, []
    for name in feeds.ALL:
        items, h = fetch_one(name, start, end, now)
        got[name] = items
        health.append(h)
        print(f"  {h['source']:<18} {h['status']:<8} {h['items']:>5}  {h['note'][:90]}")

    if not any(got.values()):
        raise Fatal("every feed came back empty — refusing to publish an empty brief")

    exploited = merge_exploited(got["kev"], got["euvd"])
    cves = enrich_cves(got["cvelist"], got["nvd"])
    adv = got["certeu"] + got["ncscnl"]
    catalog = got["kev"][0].extra.get("catalog_version", "") if got["kev"] else ""

    regions = render.build_regions(exploited, adv, got["github"], cves, got["circl"], health,
                                   start, end, now, kev_catalog=catalog, cap=CVE_ROW_CAP)
    regions["health_status"] = [(h["source"], h["status"]) for h in health]
    fp = fingerprint(regions)
    regions.pop("health_status")

    record = {"run_at": iso_utc(now), "mode": "dry-run" if args.dry_run else ("out" if args.out else "write")}
    last = state.load_json("wiki.json", {})

    if args.out:
        with open(SKELETON, encoding="utf-8") as f:
            doc = render.apply_regions(f.read(), regions)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(doc)
        print(f"wrote {args.out} ({len(doc):,} bytes)")
        record["result"] = "out"
    else:
        page = gql(READ_PAGE, {"id": PAGE_ID})["pages"]["single"]
        doc = render.apply_regions(page["content"], regions)
        due = not last.get("written_at") or now - parse_iso(last["written_at"]) >= HEARTBEAT
        if fp == last.get("fingerprint") and not due:
            print(f"no data change since {last['written_at']} — skipping write")
            record["result"] = "unchanged"
        elif doc == page["content"]:
            print("page already identical — skipping write")
            record["result"] = "unchanged"
        else:
            reason = "data changed" if fp != last.get("fingerprint") else f"heartbeat ({HEARTBEAT})"
            print(f"content {len(page['content']):,} -> {len(doc):,} bytes ({reason})")
            if args.dry_run:
                print("dry run: not writing")
                record["result"] = "would-write"
            else:
                res = gql(WRITE_PAGE, {
                    "id": PAGE_ID, "content": doc,
                    "tags": [t["tag"] for t in (page.get("tags") or [])],   # required: resolver maps over it
                    "title": page["title"], "desc": page.get("description") or "",
                })["pages"]["update"]["responseResult"]
                if not res["succeeded"]:
                    raise Fatal(f"Wiki.js refused the write: {res['message']}")
                print(f"written: {res['message']}")
                state.save_json("wiki.json", {"fingerprint": fp, "written_at": iso_utc(now), "bytes": len(doc)})
                record["result"] = "written"
        record["bytes"] = len(doc)

    # first_seen is only recorded once the page carries the item (or already did).
    if record["result"] in ("written", "unchanged"):
        record["feeds"] = sla_stats(feeds.ALL, [got[n] for n in feeds.ALL], health, now)
    else:
        record["feeds"] = {h["source"]: {"status": h["status"], "items": h["items"]} for h in health}
    record["seconds"] = round(time.monotonic() - t0, 1)
    state.append_run(record)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="build and diff, write nothing")
    ap.add_argument("--out", metavar="FILE", help="render into page/skeleton.html and save to FILE; no wiki")
    ap.add_argument("--every", type=int, metavar="SECONDS", help="loop forever, one run every SECONDS")
    args = ap.parse_args()

    if not args.every:
        return run(args)
    while True:
        started = time.monotonic()
        try:
            run(args)
        except Fatal as e:
            print(f"FATAL: {e}", file=sys.stderr)
            state.append_run({"run_at": iso_utc(state.utcnow()), "result": "fatal", "error": str(e)})
        except Exception:  # noqa: BLE001 - keep the loop alive; the log shows the traceback
            traceback.print_exc()
            state.append_run({"run_at": iso_utc(state.utcnow()), "result": "crash",
                              "error": traceback.format_exc(limit=1).strip()[-300:]})
        sys.stdout.flush()
        time.sleep(max(0, args.every - (time.monotonic() - started)))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)
