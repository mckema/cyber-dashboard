"""
CVE.org cvelistV5: the primary CVE feed (CNA-published records, minutes after publication).

Steady state reads only the head of cves/deltaLog.json (36 MB, newest first)
with a byte Range, takes the entries newer than the saved cursor, and fetches
those records' raw JSON (~45 per 30-minute run). Every in-window record lives
in a local store, so each run returns the full window and the renderer filters.

First run, or a cursor too old for the 4 MB deltaLog cap: rebuild the store
from the GitHub release zips (one ~2 MB end-of-day delta per window day, plus
today's latest hourly delta, which is cumulative since midnight), then catch up
from the deltaLog, which is also read back to the window start so the commit
just after each midnight (missing from both adjacent zips) can be replayed.
Release downloads go to github.com, not api.github.com, so
they do not spend the 60 req/h API budget. Never touch *_all_CVEs_at_midnight
(650 MB).
"""

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from . import state
from .common import Item, SourceError, get, iso_utc, parse_iso, severity_for

NAME = "CVE.org cvelistV5"
TABLE = "cve"
CADENCE = 0

DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
RELEASE_URL = "https://github.com/CVEProject/cvelistV5/releases/download/{tag}/{asset}"
CHUNK = 128 * 1024                     # ~2-4 h of deltaLog at 2026-11 volume
MAX_DELTA = 4 * 1024 * 1024            # ~3 days; past that, backfill is cheaper
MAX_CURSOR_AGE = timedelta(days=3)
OVERLAP = timedelta(minutes=15)        # re-read a little before a release snapshot; refetching is harmless
BACKFILL_CHUNK = 1024 * 1024           # backfill reads the log back to the window start (~1.3 MB/day)
BACKFILL_DELTA = 16 * 1024 * 1024
# The first commit after 00:00 UTC is in neither the day's end-of-day zip nor the next
# day's "since midnight" zips (2026-11-03: fetchTime 00:06:24, 5 records). Backfill
# replays deltaLog entries in this slot around every midnight.
MIDNIGHT_GAP = (timedelta(minutes=-15), timedelta(minutes=45))
WORKERS = 8
MAX_RETRY = 3                          # runs a 404 record is retried before it is dropped
DESC_MAX = 400

CURSOR = "cursors/cvelist.json"
STORE = "cursors/cvelist_records.json"

# Cost of the last fetch(); rebuild.py may log it. Not part of the feed contract.
STATS = {}

SEVERITY_WORDS = {"critical": "CRITICAL", "high": "HIGH", "important": "HIGH",
                  "medium": "MEDIUM", "moderate": "MEDIUM", "low": "LOW"}


# ---------------------------------------------------------------- record parsing

def vector_bits(vec):
    """(av, pr) from a CVSS 3.x or 4.0 vector, same buckets as Mark's NVD table."""
    av = "network" if "AV:N" in vec else "local" if "AV:L" in vec else ""
    pr = "none" if "PR:N" in vec else "low" if "PR:L" in vec else "high" if "PR:H" in vec else ""
    return av, pr


def cvss(metrics):
    """(score, severity, vector) from a CVE 5 metrics[] list, newest CVSS version first; None if unscored."""
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        for m in metrics or []:
            d = m.get(key)
            if d and d.get("baseScore") is not None:
                score = float(d["baseScore"])
                sev = (d.get("baseSeverity") or "").upper()
                if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    sev = severity_for(score)      # also maps v4 "NONE" to ""
                return score, sev, d.get("vectorString") or ""
    return None


def other_severity(metrics):
    """Some CNAs rate in words only (metrics[].other, e.g. Red Hat "Important")."""
    for m in metrics or []:
        c = (m.get("other") or {}).get("content")
        if isinstance(c, dict):
            c = c.get("text") or c.get("value") or c.get("baseSeverity")
        if isinstance(c, str) and c.strip().lower() in SEVERITY_WORDS:
            return SEVERITY_WORDS[c.strip().lower()]
    return ""


def ssvc_exploitation(metrics):
    for m in metrics or []:
        o = m.get("other") or {}
        if o.get("type") == "ssvc":
            for opt in (o.get("content") or {}).get("options") or []:
                if "Exploitation" in opt:
                    return str(opt["Exploitation"]).lower()
    return ""


def parse_record(rec):
    """CVE JSON 5 record -> Item, or None when it is not a published record."""
    meta = rec.get("cveMetadata") or {}
    if meta.get("state") != "PUBLISHED" or not meta.get("datePublished"):
        return None
    cid = meta["cveId"]
    containers = rec.get("containers") or {}
    cna = containers.get("cna") or {}
    adp = next((a for a in containers.get("adp") or []
                if (a.get("providerMetadata") or {}).get("shortName") == "CISA-ADP"), {})

    # The CNA's own score wins; CISA-ADP (Vulnrichment) fills in when the CNA gave none.
    scored, src = cvss(cna.get("metrics")), "CNA"
    if not scored:
        scored, src = cvss(adp.get("metrics")), "CISA-ADP"
    if scored:
        score, sev, vec = scored
    else:
        score, vec = 0.0, ""
        sev = other_severity(cna.get("metrics"))
        src = "CNA" if sev else ""

    desc = next((d.get("value", "") for d in cna.get("descriptions") or []
                 if (d.get("lang") or "").lower().startswith("en")), "")
    desc = " ".join(desc.split())
    if len(desc) > DESC_MAX:
        desc = desc[:DESC_MAX - 1] + "…"
    vendors = []
    for a in cna.get("affected") or []:
        v = (a.get("vendor") or "").strip()
        if v and v.lower() != "n/a" and v not in vendors:
            vendors.append(v)
    av, pr = vector_bits(vec)
    return Item(
        source=NAME, id=cid, url=f"https://www.cve.org/CVERecord?id={cid}",
        title=desc or cna.get("title", ""),
        published=iso_utc(parse_iso(meta["datePublished"])),
        updated=iso_utc(parse_iso(meta["dateUpdated"])) if meta.get("dateUpdated") else "",
        cves=[cid], score=score, severity=sev,
        extra={
            "score_source": src, "vector": vec, "av": av, "pr": pr, "vendors": vendors[:3],
            "ssvc_exploitation": ssvc_exploitation(adp.get("metrics")),
            "assigner": meta.get("assignerShortName", ""), "nvd_score": "",
        },
    )


def apply(store, rec, start):
    """Upsert one record into the store; drop it if rejected or published before the window."""
    cid = (rec.get("cveMetadata") or {}).get("cveId")
    if not cid:
        return
    item = parse_record(rec)
    if item is None or parse_iso(item.published) < start:
        store.pop(cid, None)
    else:
        store[cid] = item.to_dict()


def prune(store, start):
    return {k: v for k, v in store.items() if parse_iso(v["published"]) >= start}


# ---------------------------------------------------------------- http with cost accounting

def _get(url, label, **kw):
    r = get(url, label, **kw)
    STATS["requests"] = STATS.get("requests", 0) + 1
    STATS["bytes"] = STATS.get("bytes", 0) + len(r.content)
    return r


def _is_404(e):
    # common.get only reports the status in the message.
    return str(e).endswith("HTTP 404")


# ---------------------------------------------------------------- deltaLog

def parse_delta_prefix(buf):
    """Complete entries from the head of a JSON array cut off at an arbitrary byte."""
    text = buf.decode("utf-8", errors="replace")    # a cut multibyte char can only be in the dropped tail
    i = text.find("[")
    if i < 0:
        raise SourceError(f"{NAME}: deltaLog does not start with a JSON array")
    dec, i, n, out = json.JSONDecoder(), i + 1, len(text), []
    while True:
        while i < n and text[i] in " \t\r\n,":
            i += 1
        if i >= n or text[i] == "]":
            return out
        try:
            obj, i = dec.raw_decode(text, i)
        except json.JSONDecodeError:
            return out                                # truncated last entry
        out.append(obj)


def read_delta(since, chunk=CHUNK, cap=MAX_DELTA):
    """
    Entries with fetchTime > since, newest first, and whether the read got back to since.
    Reads the head in chunk steps up to cap bytes. Accept-Encoding: identity is required:
    with gzip the Range applies to the compressed bytes.
    """
    for _attempt in range(3):
        buf, etag, entries = b"", None, []
        while len(buf) < cap:
            r = _get(DELTA_URL, f"{NAME} deltaLog", conditional=False,
                     byte_range=(len(buf), len(buf) + chunk - 1),
                     headers={"Accept-Encoding": "identity"})
            tag = r.headers.get("ETag")
            if etag and tag != etag:
                break                                 # file was rewritten between chunks; offsets moved
            etag = tag
            whole = r.status == 200                   # server ignored Range and sent everything
            buf = r.content if whole else buf + r.content
            entries = parse_delta_prefix(buf)
            newer = [e for e in entries if parse_iso(e["fetchTime"]) > since]
            if len(newer) < len(entries):
                return newer, True
            if whole or len(r.content) < chunk:
                return newer, False                   # end of file, cursor older than the log
        else:
            return [e for e in entries if parse_iso(e["fetchTime"]) > since], False
    raise SourceError(f"{NAME}: deltaLog kept changing between range requests")


def changed_links(entries):
    """cveId -> raw record URL for every new/updated entry (errors are not records)."""
    links = {}
    for e in entries:
        for c in (e.get("new") or []) + (e.get("updated") or []):
            if c.get("cveId") and c.get("githubLink"):
                links.setdefault(c["cveId"], c["githubLink"])
    return links


def fetch_records(links):
    """Fetch raw records in parallel. Returns ({cveId: record}, [cveIds that were 404])."""
    def one(item):
        cid, url = item
        try:
            return cid, get(url, f"{NAME} {cid}", conditional=False), None
        except SourceError as e:
            return cid, None, e

    recs, missing = {}, []
    with ThreadPoolExecutor(WORKERS) as pool:
        for cid, r, err in pool.map(one, sorted(links.items())):
            if err is not None:
                # A 404 is usually CDN lag or a moved file: retry next run instead of
                # failing a core feed forever. Anything else fails the feed.
                if _is_404(err):
                    missing.append(cid)
                    continue
                raise err
            STATS["requests"] = STATS.get("requests", 0) + 1
            STATS["bytes"] = STATS.get("bytes", 0) + len(r.content)
            try:
                recs[cid] = r.json()
            except ValueError:
                raise SourceError(f"{NAME} {cid}: record is not JSON")
    return recs, missing


# ---------------------------------------------------------------- backfill from release zips

def zip_records(content):
    """Yield CVE records from a release zip (layout deltaCves/CVE-*.json, checked 2026-11-03)."""
    try:
        z = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise SourceError(f"{NAME}: release asset is not a zip")
    for name in z.namelist():
        base = name.rsplit("/", 1)[-1]
        if base.startswith("CVE-") and base.endswith(".json"):
            yield json.loads(z.read(name))


def release_zip(tag, asset):
    if "_all_CVEs_" in asset:
        raise SourceError(f"{NAME}: refusing to download {asset} (650 MB)")
    try:
        return _get(RELEASE_URL.format(tag=tag, asset=asset), f"{NAME} {asset}", conditional=False).content
    except SourceError as e:
        if _is_404(e):
            return None                               # release not published yet
        raise


def day_snapshot(day, last_hour):
    """
    (zip bytes, time covered up to) for one UTC day: the end-of-day delta when it
    exists, else the latest hourly delta (cumulative since midnight).
    """
    ds = day.isoformat()
    midnight = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    if last_hour == 23:
        z = release_zip(f"cve_{ds}_at_end_of_day", f"{ds}_delta_CVEs_at_end_of_day.zip")
        if z is not None:
            return z, midnight + timedelta(days=1)
    for h in range(last_hour, -1, -1):
        z = release_zip(f"cve_{ds}_{h:02d}00Z", f"{ds}_delta_CVEs_at_{h:02d}00Z.zip")
        if z is not None:
            return z, midnight + timedelta(hours=h)
    return None, None


def backfill(start, now):
    """Rebuild the store from release zips. Returns (store, snapshot time the zips cover up to)."""
    store, snap, today = {}, None, now.date()
    day = start.date()
    while day <= today:
        z, covered = day_snapshot(day, 23 if day < today else now.hour)
        if z is None:
            if day < today:
                raise SourceError(f"{NAME}: no release zip found for {day.isoformat()}")
            break                                     # just after midnight: the deltaLog covers today
        for rec in zip_records(z):
            apply(store, rec, start)
        snap = covered
        day += timedelta(days=1)
    STATS["backfill_records"] = len(store)
    return store, snap


def near_midnight(t):
    day = datetime(t.year, t.month, t.day, tzinfo=timezone.utc)
    lo, hi = MIDNIGHT_GAP
    return t - day <= hi or (day + timedelta(days=1)) - t <= -lo


def backfill_catch_up(start, snap):
    """
    deltaLog entries to replay after a zip backfill: everything after the snapshot,
    plus the midnight slots the zips miss. Raises if the log does not reach the snapshot.
    """
    since = (snap or start) - OVERLAP
    entries, reached = read_delta(start, chunk=BACKFILL_CHUNK, cap=BACKFILL_DELTA)
    STATS["log_reaches_start"] = reached         # False: older midnights are not replayed
    if not any(parse_iso(e["fetchTime"]) <= since for e in entries):
        raise SourceError(f"{NAME}: deltaLog head ({BACKFILL_DELTA} bytes) does not reach back to "
                          f"the backfill snapshot {iso_utc(since)}")
    newer = [e for e in entries if parse_iso(e["fetchTime"]) > since]
    gap = [e for e in entries if parse_iso(e["fetchTime"]) <= since and near_midnight(parse_iso(e["fetchTime"]))]
    STATS["midnight_entries"] = len(gap)
    return newer, gap


# ---------------------------------------------------------------- fetch

def fetch(start, end):
    t0 = time.monotonic()
    STATS.clear()
    STATS.update(requests=0, bytes=0, mode="delta")
    cur = state.load_json(CURSOR, {})
    store = state.load_json(STORE, None)
    since = parse_iso(cur["fetch_time"]) if cur.get("fetch_time") else None

    newer, gap = None, []
    if store is not None and since and since > max(start, end - MAX_CURSOR_AGE):
        newer, reached = read_delta(since)
        if not reached:
            newer = None
    if newer is None:
        STATS["mode"] = "backfill"
        store, snap = backfill(start, end)
        since = (snap or start) - OVERLAP
        newer, gap = backfill_catch_up(start, snap)

    retry = {k: v for k, v in (cur.get("retry") or {}).items() if v[1] < MAX_RETRY}
    links = {cid: v[0] for cid, v in retry.items()}
    links.update(changed_links(gap + newer))
    recs, missing = fetch_records(links)
    for rec in recs.values():
        apply(store, rec, start)
    store = prune(store, start)

    STATS.update(changed=len(links), missing=len(missing), items=len(store),
                 seconds=round(time.monotonic() - t0, 1))
    # Store before cursor: a crash between the two re-reads the same deltas next run.
    state.save_json(STORE, store)
    state.save_json(CURSOR, {
        # Keep the raw fetchTime (ms precision) so the boundary entry is not re-read.
        "fetch_time": newer[0]["fetchTime"] if newer else (
            cur["fetch_time"] if STATS["mode"] == "delta" else iso_utc(since)),
        "run_at": iso_utc(end),
        "retry": {cid: [links[cid], retry.get(cid, ["", 0])[1] + 1] for cid in missing},
        "stats": dict(STATS),
    })
    items = [Item.from_dict(d) for d in store.values()]
    items.sort(key=lambda i: (i.published, i.id), reverse=True)
    return items
