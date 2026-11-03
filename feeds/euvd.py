"""
ENISA EU Vulnerability Database, exploited-vulnerability view.

/api/vulnerabilities is 404; /api/search with fromKEVDate/toKEVDate is the
documented query (2026-11-03). The API sends Cache-Control: no-store and no
ETag, so every run is a full (small) fetch. Dates come as "Nov 3, 2026,
12:41:24 AM" with no zone; ENISA serves them in UTC.
"""

import re
from datetime import datetime, timezone

from .common import Item, SourceError, get, iso_utc, severity_for

NAME = "ENISA EUVD"
TABLE = "kev"
CADENCE = 0

URL = "https://euvdservices.enisa.europa.eu/api/search"
PAGE_SIZE = 100          # API maximum
MAX_PAGES = 10

MON = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_DATE = re.compile(r"(\w{3}) (\d{1,2}), (\d{4}), (\d{1,2}):(\d{2}):(\d{2}) ([AP]M)")


def parse_date(s):
    """'Nov 3, 2026, 12:41:24 AM' -> aware UTC datetime. Own parser so %b never depends on locale."""
    m = _DATE.fullmatch((s or "").strip())
    if not m:
        return None
    mon, day, year, hh, mm, ss, ampm = m.groups()
    hh = int(hh) % 12 + (12 if ampm == "PM" else 0)
    return datetime(int(year), MON[mon], int(day), hh, int(mm), int(ss), tzinfo=timezone.utc)


def _uniq(xs):
    out = []
    for x in xs:
        if x and x not in out:
            out.append(x)
    return out


def to_item(v):
    aliases = [a.strip() for a in (v.get("aliases") or "").splitlines() if a.strip()]
    cves = [a for a in aliases if a.startswith("CVE-")]
    euvd_id = v["id"]
    exploited = parse_date(v.get("exploitedSince"))
    published = parse_date(v.get("datePublished"))
    updated = parse_date(v.get("dateUpdated"))
    vendors = _uniq(x.get("vendor", {}).get("name") for x in v.get("enisaIdVendor") or [])
    products = _uniq(x.get("product", {}).get("name") for x in v.get("enisaIdProduct") or [])
    score = float(v.get("baseScore") or 0)
    return Item(
        source=NAME, id=cves[0] if cves else euvd_id,
        url=f"https://euvd.enisa.europa.eu/vulnerability/{euvd_id}",
        title=" ".join((v.get("description") or "").split()),
        # The KEV table is "newly known exploited", so the row date is exploitedSince
        # (always midnight, so a date). The vulnerability's own publication is in extra.
        published=exploited.date().isoformat() if exploited else (iso_utc(published) if published else ""),
        updated=iso_utc(updated) if updated else "",
        cves=cves, score=score, severity=severity_for(score),
        extra={
            "euvd_id": euvd_id,
            "exploited_since": exploited.date().isoformat() if exploited else "",
            "euvd_published": iso_utc(published) if published else "",
            "vendor": ", ".join(vendors[:3]), "product": ", ".join(products[:3]),
            "epss": v.get("epss"),           # percent (27.3 = 27.3 %), not a 0-1 fraction
            "vector": v.get("baseScoreVector") or "", "assigner": v.get("assigner") or "",
        },
    )


def fetch(start, end):
    params = {"fromKEVDate": start.date().isoformat(), "toKEVDate": end.date().isoformat(), "size": PAGE_SIZE}
    rows, total = [], None
    for page in range(MAX_PAGES):
        try:
            j = get(URL, f"{NAME} page {page}", conditional=False, params={**params, "page": page}).json()
        except ValueError:
            raise SourceError(f"{NAME}: response is not JSON")
        total = j.get("total", 0)
        batch = j.get("items") or []
        rows += batch
        if not batch or len(rows) >= total:
            break
    else:
        raise SourceError(f"{NAME}: more than {MAX_PAGES * PAGE_SIZE} results; page cap hit")
    out = [to_item(v) for v in rows]
    out.sort(key=lambda i: (i.published, i.id), reverse=True)
    return out
