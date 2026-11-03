"""
GitHub Advisory Database: reviewed critical and high advisories.

The original fetch_gh read one page per severity and silently dropped the rest
(125 high advisories in the 7 days to 2026-11-03 = 2 pages). This follows
Link: rel="next" until the end, capped at MAX_PAGES.

The query uses whole UTC dates (start date .. today) so the URL stays the same
all day and conditional GETs can return 304; the exact window is applied here.
A 304 may come back without a Link header, so the next-page URL seen on the
last 200 is remembered per page URL.

Rate limit: 60 req/h per IP unauthenticated (shared by everyone behind the
proxy), 1,000/h for an Actions GITHUB_TOKEN; 304s are free only when authenticated.
"""

import os
import re

from . import state
from .common import Item, SourceError, get, iso_utc, parse_iso

NAME = "GitHub Advisory"
TABLE = "dep"
CADENCE = 0

URL = "https://api.github.com/advisories"
SEVERITIES = ("critical", "high")
PER_PAGE = 100
MAX_PAGES = 10
NEXT = "cursors/github_next.json"     # page URL -> next page URL from its last 200

STATS = {}


def headers():
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def next_link(link):
    """URL of rel="next" in a Link header, or None."""
    for part in (link or "").split(","):
        m = re.search(r'<([^>]+)>\s*;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


def _uniq(xs):
    out = []
    for x in xs:
        if x and x not in out:
            out.append(x)
    return out


def score_and_vector(a):
    cs = a.get("cvss_severities") or {}
    for k in ("cvss_v4", "cvss_v3"):
        d = cs.get(k) or {}
        if d.get("score"):
            return float(d["score"]), d.get("vector_string") or ""
    d = a.get("cvss") or {}                   # deprecated field, still filled on older advisories
    return float(d.get("score") or 0), d.get("vector_string") or ""


def to_item(a):
    vulns = a.get("vulnerabilities") or []
    pkgs = _uniq((v.get("package") or {}).get("name") for v in vulns)
    ecos = _uniq((v.get("package") or {}).get("ecosystem") for v in vulns)
    fixed = _uniq(v.get("first_patched_version") for v in vulns)
    score, vec = score_and_vector(a)
    cve = a.get("cve_id") or ""
    return Item(
        source=NAME, id=cve or a["ghsa_id"], url=a["html_url"],
        title=" ".join((a.get("summary") or "").split()),
        published=iso_utc(parse_iso(a["published_at"])),
        updated=iso_utc(parse_iso(a["updated_at"])) if a.get("updated_at") else "",
        cves=[cve] if cve else [], score=score, severity=(a.get("severity") or "").upper(),
        extra={"ghsa": a["ghsa_id"], "ecosystems": sorted(ecos), "packages": sorted(pkgs),
               "fixed": sorted(fixed)[:3], "npkg": len(pkgs), "vector": vec},
    )


def fetch_severity(sev, start, end, nexts):
    url = URL
    params = {"type": "reviewed", "severity": sev, "per_page": PER_PAGE,
              "published": f"{start.date().isoformat()}..{end.date().isoformat()}"}
    rows = []
    for page in range(MAX_PAGES):
        r = get(url, f"{NAME} {sev} page {page + 1}", headers=headers(), params=params)
        STATS["requests"] += 1
        STATS["not_modified"] += r.from_cache
        try:
            rows += r.json()
        except ValueError:
            raise SourceError(f"{NAME} {sev}: response is not JSON")
        if r.from_cache:
            nxt = next_link(r.headers.get("Link")) or nexts.get(r.url)
        else:
            nxt = next_link(r.headers.get("Link"))
            nexts[r.url] = nxt
        if not nxt:
            return rows
        url, params = nxt, None
    raise SourceError(f"{NAME} {sev}: more than {MAX_PAGES} pages ({MAX_PAGES * PER_PAGE} advisories); page cap hit")


def fetch(start, end):
    STATS.clear()
    STATS.update(requests=0, not_modified=0)
    nexts = state.load_json(NEXT, {})
    items = {}
    for sev in SEVERITIES:
        for a in fetch_severity(sev, start, end, nexts):
            if a.get("withdrawn_at"):
                continue
            it = to_item(a)
            if start <= parse_iso(it.published) <= end:
                items[it.extra["ghsa"]] = it
    # Keep only today's page URLs; yesterday's never come back.
    today = end.date().isoformat()
    state.save_json(NEXT, {k: v for k, v in nexts.items() if today in k})
    STATS["items"] = len(items)
    out = list(items.values())
    out.sort(key=lambda i: (i.severity != "CRITICAL", -i.score, i.id))
    return out
