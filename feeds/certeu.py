"""
CERT-EU security advisories.

The RSS lists the latest 10 advisories, ordered by latest revision. Its pubDate
carries a zone *label* ("CEST", "CET") that email.utils does not know and would
read as UTC, so the exact time comes from the per-advisory JSON, whose
publish_date is UTC without a marker (checked 2026-11-03: RSS 16:36:26 CEST ==
JSON 14:36:26 on all 10 items). The JSON is fetched only when a serial is new
or its pubDate changed; the result is kept in cursors/certeu.json.

The RSS sends no ETag/Last-Modified and answers If-Modified-Since with 200, so
it is fetched unconditionally (~10 KB). The site sits behind an Azure
Application Gateway that answers 403 to the default python-requests
User-Agent; common.get() always sends ours.
"""

import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from . import state
from .common import Item, SourceError, get, iso_utc

NAME = "CERT-EU"
TABLE = "adv"
CADENCE = 0

RSS = "https://cert.europa.eu/publications/security-advisories-rss"
PAGE = "https://cert.europa.eu/publications/security-advisories/{serial}/"
JSON = PAGE + "json"
CURSOR = "cursors/certeu.json"

# Zone labels seen in the feed. Only used to pre-filter and as a fallback when
# the JSON is unavailable; email.utils already handles GMT/UT and +hhmm.
ZONES = {"CEST": "+0200", "CET": "+0100"}
SERIAL = re.compile(r"^(\d{4}-\d{3,})\s*:\s*(.*)$", re.S)
CVE = re.compile(r"CVE-\d{4}-\d{4,}")


# ---------------------------------------------------------------- parsing

def parse_pubdate(s):
    """'Fri, 23 Oct 2026 16:36:26 CEST' -> aware datetime. None if the zone label is unknown."""
    s = (s or "").strip()
    head, _, zone = s.rpartition(" ")
    if zone in ZONES:
        s = f"{head} {ZONES[zone]}"
    elif zone.isalpha() and zone not in ("GMT", "UT", "UTC", "Z"):
        return None
    try:
        dt = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else None


def parse_rss(content):
    """RSS bytes -> [{serial, title, url, pubdate}] in feed order, one entry per serial."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise SourceError(f"{NAME}: RSS is not valid XML: {e}")
    out, seen = [], set()
    for it in root.iter("item"):
        m = SERIAL.match((it.findtext("title") or "").strip())
        if not m:
            continue  # not an advisory title like "2026-018: …"
        serial = m.group(1)
        if serial in seen:
            continue  # feed is ordered by latest revision: the first entry wins
        seen.add(serial)
        out.append({
            "serial": serial,
            "title": " ".join(m.group(2).split()),
            "url": (it.findtext("link") or "").strip() or PAGE.format(serial=serial),
            "pubdate": (it.findtext("pubDate") or "").strip(),
        })
    return out


def front_matter(md):
    """YAML-ish header of content_markdown -> dict. Values may or may not be quoted."""
    m = re.match(r"\s*---[ \t]*\n(.*?)\n---", md or "", re.S)
    out = {}
    for line in (m.group(1).splitlines() if m else []):
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip()] = v.strip().strip("'\"")
    return out


def first_release_date(md, fm):
    """Date of v1.0 from the History list ('* _20/10/2026 --- v1.0 -- …', underscores optional)."""
    m = re.search(r"(\d{2})/(\d{2})/(\d{4})\s*-+\s*v1\.0\b", md or "")
    if m:
        return f"{m.group(3)}-{m.group(2)}-{m.group(1)}"
    # front-matter `date` matched v1.0 on 9 of 10 advisories checked; original_date
    # is the vendor's disclosure date, not CERT-EU's, so it is not used.
    return fm.get("date", "")


def parse_advisory(j, prev=None):
    """
    Advisory JSON -> Item fields. prev is the cached record for the same serial:
    when it holds an exact v1.0 time, that stays the published time after revisions.
    """
    serial = j["serial_number"]
    md = j.get("content_markdown") or ""
    fm = front_matter(md)
    version = fm.get("version", "")
    latest = iso_utc(datetime.strptime(j["publish_date"], "%d-%m-%Y %H:%M:%S").replace(tzinfo=timezone.utc))
    if version in ("", "1", "1.0"):
        published, updated = latest, ""
    else:
        prev = prev or {}
        exact_v1 = not prev.get("fallback") and not prev.get("updated") and "T" in prev.get("published", "")
        published = prev["published"] if exact_v1 else first_release_date(md, fm)
        updated = latest
    summary = re.sub(r"<[^>]+>", " ", j.get("description") or "")
    return {
        "id": serial,
        "url": PAGE.format(serial=serial),
        "title": " ".join((j.get("title") or "").split()),
        "published": published,
        "updated": updated,
        "cves": sorted(set(CVE.findall(md))),
        "extra": {"version": version, "summary": " ".join(summary.split())},
    }


def from_rss(e):
    """Fallback record when the JSON is unavailable: RSS time via the zone map, no CVEs."""
    dt = parse_pubdate(e["pubdate"])
    if dt is None:
        raise SourceError(f"{NAME}: {e['serial']} JSON unavailable and pubDate {e['pubdate']!r} has an unknown zone; add it to ZONES")
    return {
        "id": e["serial"], "url": PAGE.format(serial=e["serial"]), "title": e["title"],
        "published": iso_utc(dt), "updated": "", "cves": [],
        "extra": {"version": "", "summary": ""}, "fallback": True,
    }


def in_window(ts, start, end):
    """ts is ISO UTC or a bare date; a bare date counts if the day overlaps the window."""
    if not ts:
        return False
    if "T" not in ts:
        return start.date().isoformat() <= ts <= end.date().isoformat()
    return iso_utc(start) <= ts <= iso_utc(end)


# ---------------------------------------------------------------- fetch

def fetch(start, end):
    entries = parse_rss(get(RSS, f"{NAME} RSS", conditional=False).content)
    if not entries:
        raise SourceError(f"{NAME}: RSS has no advisory items; the feed format may have changed")

    cache = state.load_json(CURSOR, {})
    keep, items = {}, []
    for e in entries:
        rec = cache.get(e["serial"])
        if rec and rec.get("pubdate") == e["pubdate"] and not rec.get("fallback"):
            keep[e["serial"]] = rec
        else:
            # pubDate is the latest revision time, so an advisory last touched more
            # than a day (zone slack) before the window cannot be in it: skip the JSON.
            approx = parse_pubdate(e["pubdate"])
            if approx is not None and approx < start - timedelta(days=1):
                continue
            try:
                j = get(JSON.format(serial=e["serial"]), f"{NAME} {e['serial']} JSON", conditional=False).json()
                rec = parse_advisory(j, rec)
            except (SourceError, ValueError, KeyError) as err:
                print(f"  note: {NAME} {e['serial']}: JSON failed ({err}); using RSS pubDate", file=sys.stderr)
                rec = from_rss(e)
            rec["pubdate"] = e["pubdate"]
            keep[e["serial"]] = rec
        if in_window(rec["published"], start, end) or in_window(rec["updated"], start, end):
            items.append(Item(source=NAME, **{k: rec[k] for k in ("id", "url", "title", "published", "updated", "cves", "extra")}))

    # Only serials still in the RSS are kept, so the cursor stays at ~10 entries.
    state.save_json(CURSOR, keep)
    items.sort(key=lambda i: i.updated or i.published, reverse=True)
    return items
