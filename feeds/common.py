"""
Shared contract for every feed module.

A feed module exposes:

  NAME      display name, e.g. "CISA KEV"               (shown in the health table)
  TABLE     which page table its items go to: "kev" | "adv" | "dep" | "cve" | "nvd" | "osint"
  CADENCE   minimum seconds between real fetches (0 = every run). Between fetches
            rebuild.py reuses the items cached from the last success.
  fetch(start, end) -> list[Item]
            start/end are timezone-aware UTC datetimes bounding the 7-day window.
            Raise SourceError on any failure; never return a partial list.

Item.extra keys per table (render.py reads these; anything else is ignored):

  kev    vendor, product, due (YYYY-MM-DD, CISA only), euvd_id, exploited_since,
         sources (list of feed NAMEs, filled when rebuild.py merges KEV + EUVD)
  adv    version, products (list[str]), probability, impact (NCSC-NL "Kans"/"Schade": H/M/L)
  dep    ghsa, ecosystems (list), packages (list), fixed (list), npkg (int)
  cve    score_source ("CNA" | "CISA-ADP" | "NVD"), vector, av, pr, vendors (list),
         ssvc_exploitation ("none" | "poc" | "active" | ""), assigner, nvd_score
  nvd    vector, vendors (list)      -- enrichment only, merged into "cve" items
  osint  threat_level, tags (list), org
  any    summary (short description, optional; CERT-EU in English, NCSC-NL in Dutch)

Health rows (built by rebuild.py, rendered by render.build_health_rows):
  {source, status: "ok" | "cached" | "stale" | "error", items, newest, last_success, note}
  ok      fetched this run          cached  not due yet (CADENCE), last success reused
  stale   failed, last success reused     error   failed and never succeeded
"""

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import requests

from . import state

TIMEOUT = 90
# `or`, not a get() default: compose passes USER_AGENT= from .env as an empty
# string, and CERT-EU answers 403 to a request without a User-Agent.
USER_AGENT = (os.environ.get("USER_AGENT")
              or "fairct-exploit-watch/0.2 (+https://github.com/ediphy-tthau/cyber-dashboard-poc)")


class Fatal(Exception):
    """Abort without writing. A half-populated threat brief is worse than a stale one."""


class SourceError(Exception):
    """One feed failed. rebuild.py decides whether that is fatal for the run."""


@dataclass
class Item:
    source: str            # feed NAME that produced the item
    id: str                # source-native id: CVE-…, GHSA-…, NCSC-2026-0464, 2026-018, MISP uuid
    url: str               # link to the publisher's own page for this item
    title: str
    published: str         # ISO 8601 UTC "2026-11-03T02:31:19Z", or "2026-11-03" if the source gives a date only
    updated: str = ""      # same format; empty when the source has no revision time
    cves: list = field(default_factory=list)
    score: float = 0.0     # CVSS base score, 0 when unscored
    severity: str = ""     # CRITICAL | HIGH | MEDIUM | LOW | ""
    extra: dict = field(default_factory=dict)

    @property
    def key(self):
        return f"{self.source}:{self.id}"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


def iso_utc(dt):
    """datetime -> '2026-11-03T02:31:19Z' (seconds precision, UTC)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    """Parse ISO 8601 with or without 'Z'/offset/fraction; naive values are taken as UTC."""
    s = s.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def severity_for(score):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return ""


# ---------------------------------------------------------------- http

class Response:
    def __init__(self, status, content, headers, url, from_cache=False):
        self.status = status          # 200, 206, or 304 (body then comes from the cache)
        self.content = content
        self.headers = headers
        self.url = url
        self.from_cache = from_cache

    @property
    def text(self):
        return self.content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.content)


def _cache_name(url):
    return "http/" + hashlib.sha1(url.encode()).hexdigest()


def get(url, label, headers=None, conditional=True, byte_range=None, params=None):
    """
    GET with a polite User-Agent, conditional request and on-disk body cache.

    conditional=True sends If-None-Match / If-Modified-Since from the last 200
    and, on 304, returns the cached body with from_cache=True, so callers can
    always parse .content. byte_range=(first, last) sends a Range header and
    skips the cache. Any network error or non-2xx/304 status raises SourceError.
    """
    h = {"User-Agent": USER_AGENT}
    h.update(headers or {})
    full = requests.Request("GET", url, params=params).prepare().url
    meta = state.load_json(_cache_name(full) + ".json", None) if conditional and not byte_range else None
    if meta:
        if meta.get("etag"):
            h["If-None-Match"] = meta["etag"]
        if meta.get("last_modified"):
            h["If-Modified-Since"] = meta["last_modified"]
    if byte_range:
        h["Range"] = f"bytes={byte_range[0]}-{byte_range[1]}"
    try:
        r = requests.get(full, headers=h, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise SourceError(f"{label}: network error: {e}")
    if r.status_code == 304 and meta:
        body = state.load_bytes(_cache_name(full) + ".body")
        if body is not None:
            return Response(304, body, r.headers, full, from_cache=True)
        raise SourceError(f"{label}: 304 but the cached body is missing; delete state/http and rerun")
    if r.status_code in (403, 429):
        raise SourceError(f"{label}: HTTP {r.status_code} (blocked or rate limited)")
    if not r.ok:
        raise SourceError(f"{label}: HTTP {r.status_code}")
    if conditional and not byte_range and r.status_code == 200 and (r.headers.get("ETag") or r.headers.get("Last-Modified")):
        state.save_bytes(_cache_name(full) + ".body", r.content)
        state.save_json(_cache_name(full) + ".json", {
            "url": full, "etag": r.headers.get("ETag", ""),
            "last_modified": r.headers.get("Last-Modified", ""),
        })
    return Response(r.status_code, r.content, r.headers, full)
