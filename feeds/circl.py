"""
CIRCL OSINT MISP feed.

manifest.json (~1.4 MB, ~1,700 events) is the only file read: one entry per
event with Orgc, Tag, info, date, analysis, threat_level_id, timestamp. It
supports ETag/Last-Modified, so an unchanged manifest costs a 304.

`date` is the event date the analyst set (often the date of the reported
activity, not of publication); `timestamp` is the last modification. The
manifest has no publish_timestamp; that lives only in each event file, and
reading ~1,700 of them is not worth it. An event counts as new when either
value falls in the window. An empty result is normal: on 2026-11-03 the
newest `date` was 2026-08-13 and one event had a `timestamp` in the last 7 days.
"""

from datetime import datetime, timezone

from .common import Item, SourceError, get, iso_utc

NAME = "CIRCL OSINT"
TABLE = "osint"
CADENCE = 0          # an unchanged manifest is one 304 (~1 s); daily polling would break the 1-hour target

MANIFEST = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
EVENT = "https://www.circl.lu/doc/misp/feed-osint/{uuid}.json"
LEVELS = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}


def parse_manifest(m, start, end):
    """manifest dict -> Items whose date or timestamp falls in [start, end]."""
    if not isinstance(m, dict) or not m:
        raise SourceError(f"{NAME}: manifest is empty or not a JSON object")
    d0, d1 = start.date().isoformat(), end.date().isoformat()
    items = []
    for uuid, ev in m.items():
        day = str(ev.get("date") or "")
        try:
            ts = datetime.fromtimestamp(int(ev.get("timestamp") or 0), timezone.utc)
        except (TypeError, ValueError, OverflowError):
            ts = None
        if not (d0 <= day <= d1 or (ts and start <= ts <= end)):
            continue
        try:
            level = LEVELS.get(int(ev.get("threat_level_id") or 4), "Undefined")
        except (TypeError, ValueError):
            level = "Undefined"
        items.append(Item(
            source=NAME,
            id=uuid,
            url=EVENT.format(uuid=uuid),
            title=" ".join(str(ev.get("info") or "").split()),
            published=day,
            updated=iso_utc(ts) if ts else "",
            extra={
                "threat_level": level,
                "tags": [t["name"] for t in ev.get("Tag") or [] if t.get("name")],
                "org": (ev.get("Orgc") or {}).get("name", ""),
            },
        ))
    items.sort(key=lambda i: max(i.published, i.updated), reverse=True)
    return items


def fetch(start, end):
    r = get(MANIFEST, f"{NAME} manifest")
    try:
        m = r.json()
    except ValueError as e:
        raise SourceError(f"{NAME}: manifest is not valid JSON: {e}")
    return parse_manifest(m, start, end)
