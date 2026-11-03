"""
NVD CVE API 2.0: enrichment only (NVD score and CPE vendors merged into the "cve" table).

NVD asks clients to poll incrementally no more often than every 2 hours with
lastModStartDate/lastModEndDate, so CADENCE is 7200 and each fetch asks only
for what changed since the last one, kept in a local store. No severity filter:
on 2026-11-03 cvssV3Severity matched 156 of 3,371 window CVEs, because most new
CVEs are not analysed yet. No ETag, so no conditional GET.

Rate limit: 5 requests / 30 s without a key, 50 with NVD_API_KEY.
"""

import os
import time
from datetime import timedelta

from . import state
from .common import Item, SourceError, get, iso_utc, parse_iso, severity_for
from .cvelist import vector_bits

NAME = "NVD"
TABLE = "nvd"
CADENCE = 7200

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEY = os.environ.get("NVD_API_KEY", "")
PAGE_SIZE = 2000                      # API maximum
MAX_PAGES = 20
OVERLAP = timedelta(minutes=15)       # NVD indexes lastModified a little late; re-reading is harmless
DESC_MAX = 400

CURSOR = "cursors/nvd.json"
STORE = "cursors/nvd_records.json"

STATS = {}


def nvd_time(dt):
    # NVD wants an explicit offset; requests encodes the '+' as %2B.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def cvss(metrics):
    """(score, severity, vector), NVD's own (Primary) row first, newest CVSS version first."""
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        rows = metrics.get(k) or []
        if rows:
            row = next((r for r in rows if r.get("type") == "Primary"), rows[0])
            d = row.get("cvssData") or {}
            score = float(d.get("baseScore") or 0)
            sev = (d.get("baseSeverity") or "").upper()
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                sev = severity_for(score)
            return score, sev, d.get("vectorString") or ""
    return 0.0, "", ""


def cpe_vendors(c):
    vendors = []
    for cfg in c.get("configurations") or []:
        for n in cfg.get("nodes") or []:
            for cm in n.get("cpeMatch") or []:
                parts = cm.get("criteria", "").split(":")
                if len(parts) > 4 and parts[3] not in vendors:
                    vendors.append(parts[3])
    return vendors


def to_item(c):
    """NVD 'cve' object -> Item, or None for rejected CVEs."""
    if (c.get("vulnStatus") or "").lower() == "rejected" or not c.get("published"):
        return None
    score, sev, vec = cvss(c.get("metrics") or {})
    desc = next((d["value"] for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
    desc = " ".join(desc.split())
    if len(desc) > DESC_MAX:
        desc = desc[:DESC_MAX - 1] + "…"
    av, pr = vector_bits(vec)
    return Item(
        source=NAME, id=c["id"], url=f"https://nvd.nist.gov/vuln/detail/{c['id']}",
        title=desc,
        published=iso_utc(parse_iso(c["published"])),        # NVD sends no zone; it is UTC
        updated=iso_utc(parse_iso(c["lastModified"])) if c.get("lastModified") else "",
        cves=[c["id"]], score=score, severity=sev,
        extra={"vector": vec, "vendors": cpe_vendors(c)[:3], "av": av, "pr": pr,
               "status": c.get("vulnStatus", "")},
    )


def apply(store, c, start):
    item = to_item(c)
    if item is None or parse_iso(item.published) < start:
        store.pop(c["id"], None)
    else:
        store[c["id"]] = item.to_dict()


def fetch(start, end):
    t0 = time.monotonic()
    STATS.clear()
    STATS.update(requests=0, bytes=0)
    cur = state.load_json(CURSOR, {})
    store = state.load_json(STORE, None)
    headers = {"apiKey": KEY} if KEY else {}
    if store is not None and cur.get("last_mod_end"):
        # Anything modified before the window start was also published before it, so
        # the lastMod range never reaches further back than start (<< 120-day cap).
        lo = max(start, parse_iso(cur["last_mod_end"]) - OVERLAP)
        params = {"lastModStartDate": nvd_time(lo), "lastModEndDate": nvd_time(end)}
        STATS["mode"] = "lastMod"
    else:
        # First run: the store only keeps CVEs published in the window, and pub* returns
        # exactly those (3.4k rows on 2026-11-03), where lastMod over 7 days returns 8.9k.
        lo, store = start, {}
        params = {"pubStartDate": nvd_time(start), "pubEndDate": nvd_time(end)}
        STATS["mode"] = "pub"
    params["resultsPerPage"] = PAGE_SIZE

    seen = 0
    for page in range(MAX_PAGES):
        if page:
            time.sleep(0.6 if KEY else 6)    # stay under 5 req / 30 s without a key
        r = get(URL, f"{NAME} page {page}", headers=headers, conditional=False,
                params={**params, "startIndex": seen})
        STATS["requests"] += 1
        STATS["bytes"] += len(r.content)
        try:
            j = r.json()
        except ValueError:
            raise SourceError(f"{NAME}: response is not JSON")
        vulns = j.get("vulnerabilities") or []
        for v in vulns:
            apply(store, v["cve"], start)
        seen += len(vulns)
        if not vulns or seen >= j.get("totalResults", 0):
            break
    else:
        raise SourceError(f"{NAME}: more than {MAX_PAGES} pages of changes; page cap hit")

    store = {k: v for k, v in store.items() if parse_iso(v["published"]) >= start}
    STATS.update(changed=seen, items=len(store), since=iso_utc(lo),
                 seconds=round(time.monotonic() - t0, 1))
    state.save_json(STORE, store)
    state.save_json(CURSOR, {"last_mod_end": iso_utc(end), "stats": dict(STATS)})
    items = [Item.from_dict(d) for d in store.values()]
    items.sort(key=lambda i: (i.published, i.id), reverse=True)
    return items
