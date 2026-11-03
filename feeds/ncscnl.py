"""
NCSC-NL security advisories, read as CSAF 2.0.

provider-metadata.json (/.well-known/csaf/) points at the directory
https://advisories.ncsc.nl/csaf/v2/. Its changes.csv (~71 KB, newest first)
lists every document once with the time of its latest revision, and supports
ETag, so most runs cost one 304. Each document is fetched once per
(path, timestamp); the parsed result is kept in cursors/ncscnl.json.

The RSS (https://advisories.ncsc.nl/rss/advisories, 25 items, titles like
"NCSC-2026-0464 [1.00] [M/H] …") carries the same data in a lossy form and is
not used.
"""

import csv
import io
import re

from . import state
from .common import Item, SourceError, get, iso_utc, parse_iso, severity_for

NAME = "NCSC-NL"
TABLE = "adv"
CADENCE = 0

BASE = "https://advisories.ncsc.nl/csaf/v2/"
CHANGES = BASE + "changes.csv"
# The RSS link (advisory?id=…) is a JavaScript redirect to this page; link it directly.
PAGE = "https://advisories.ncsc.nl/{year}/{id}.html"
CURSOR = "cursors/ncscnl.json"

PATH = re.compile(r"^\d{4}/ncsc-\d{4}-\d{4,}\.json$")
LEVEL = {"high": "H", "medium": "M", "low": "L"}   # "Kans" / "Schade" note text


# ---------------------------------------------------------------- parsing

def parse_changes(text):
    """changes.csv -> [(path, timestamp)]. Rows that are not CSAF document paths are skipped."""
    out = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and PATH.match(row[0].strip()):
            out.append((row[0].strip(), row[1].strip()))
    return out


def products(tree):
    """product_tree.branches vendor -> product_name as 'Vendor Product', without repeating the vendor."""
    out = []

    def walk(branches, vendor):
        for b in branches or []:
            cat, name = b.get("category"), (b.get("name") or "").strip()
            if cat == "vendor":
                walk(b.get("branches"), name)
            elif cat == "product_name":
                label = name if not vendor or name.lower().startswith(vendor.lower()) else f"{vendor} {name}"
                if label not in out:
                    out.append(label)
            else:
                walk(b.get("branches"), vendor)

    walk((tree or {}).get("branches"), "")
    return out


def max_score(vulns):
    """Highest CVSS base score in vulnerabilities[].scores. Documents that only carry a
    CVSS 4.0 vector (as a note titled 'CVSSV4') have no score here and yield 0."""
    best = 0.0
    for v in vulns:
        for s in v.get("scores") or []:
            for k in ("cvss_v4", "cvss_v3", "cvss_v2"):
                best = max(best, float((s.get(k) or {}).get("baseScore") or 0))
    return best


def parse_csaf(doc):
    """CSAF document -> Item."""
    d = doc["document"]
    tr = d["tracking"]
    tid = tr["id"]
    notes = {(n.get("title") or ""): (n.get("text") or "").strip() for n in d.get("notes") or []}
    vulns = doc.get("vulnerabilities") or []
    first = parse_iso(tr["initial_release_date"])
    latest = parse_iso(tr["current_release_date"])
    score = max_score(vulns)
    cves = []
    for v in vulns:
        if v.get("cve") and v["cve"] not in cves:
            cves.append(v["cve"])
    return Item(
        source=NAME,
        id=tid,
        url=PAGE.format(year=tid.split("-")[1], id=tid.lower()),
        title=" ".join((d.get("title") or "").split()),
        published=iso_utc(first),
        updated=iso_utc(latest) if latest > first else "",
        cves=cves,
        score=score,
        severity=severity_for(score),
        extra={
            "version": tr.get("version", ""),
            "products": products(doc.get("product_tree")),
            "probability": LEVEL.get(notes.get("Kans", "").lower(), notes.get("Kans", "")),
            "impact": LEVEL.get(notes.get("Schade", "").lower(), notes.get("Schade", "")),
            "summary": notes.get("Feiten", ""),   # Dutch, one or two sentences
        },
    )


# ---------------------------------------------------------------- fetch

def fetch(start, end):
    rows = parse_changes(get(CHANGES, f"{NAME} changes.csv").text)
    if not rows:
        raise SourceError(f"{NAME}: changes.csv has no document rows; the CSAF layout may have changed")

    cache = state.load_json(CURSOR, {})
    keep, items, done = {}, [], False
    try:
        for path, ts in rows:
            try:
                t = parse_iso(ts)
            except ValueError:
                raise SourceError(f"{NAME}: changes.csv row {path} has a bad timestamp {ts!r}")
            if not start <= t <= end:
                continue  # the row time is the latest revision, so older rows cannot be in the window
            rec = cache.get(path)
            if not rec or rec.get("ts") != ts:
                # Our cursor is the cache, so no HTTP body cache (the Apple ones are ~300 KB).
                r = get(BASE + path, f"{NAME} {path}", conditional=False)
                try:
                    item = parse_csaf(r.json())
                except (ValueError, KeyError, IndexError, TypeError) as e:
                    raise SourceError(f"{NAME}: {path} is not a readable CSAF document: {e!r}")
                rec = {"ts": ts, "item": item.to_dict()}
            keep[path] = rec
            items.append(Item.from_dict(rec["item"]))
        done = True
    finally:
        # On success keep only rows in the window; on failure keep everything, so
        # documents already fetched are not fetched again on the next run.
        state.save_json(CURSOR, keep if done else {**cache, **keep})

    items.sort(key=lambda i: i.updated or i.published, reverse=True)
    return items
