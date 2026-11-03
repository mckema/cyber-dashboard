#!/usr/bin/env python3
"""
HTML builders for the Cyber Threat Exploit Watch page.

Pure functions: lists of feeds.common.Item in, HTML strings out. No network and
no file I/O, except the --demo preview CLI at the bottom.

Every builder emits only the class names styled by page/style.css (the page's
scriptCss) and no long inline style attributes, because the Wiki.js sanitiser
mangles those (README §7).

Times: every timestamp on the page is UTC and carries the "UTC" label.
Date-only source values (e.g. CISA dueDate) are shown as a date with no time.

Anchors filled on the page (see page/skeleton.html):
  tbody  t-health t-kev t-adv t-dep t-nvd t-osint
  text   s-kev s-crit s-high s-dep s-adv s-osint
         n-health n-kev n-adv n-dep n-nvd n-cvecap n-osint winlabel
  stamp  rstat   (inner HTML, contains <b>; must never contain a <div>)

Preview:
  python render.py --demo state/preview.html [--dark]
"""

import argparse
import html
import json
import os
import re
import sys
from datetime import datetime, timezone

from feeds.common import Fatal, Item, severity_for

MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
DESC_MAX = 300

TBODY_IDS = ["t-health", "t-kev", "t-adv", "t-dep", "t-nvd", "t-osint"]
TEXT_IDS = ["s-kev", "s-crit", "s-high", "s-dep", "s-adv", "s-osint",
            "n-health", "n-kev", "n-adv", "n-dep", "n-nvd", "n-cvecap", "n-osint", "winlabel"]
STAMP_ID = "rstat"


# ---------------------------------------------------------------- helpers

def esc(s):
    return html.escape("" if s is None else str(s), quote=True)


def _parse(v):
    """-> (aware UTC datetime, has_time) or (None, False). Accepts datetime or ISO 8601 text."""
    if not v:
        return None, False
    if isinstance(v, datetime):
        dt = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc), True
    s = str(v).strip()
    try:
        if len(s) == 10:
            return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc), False
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None, False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc), True


def _day(dt, year):
    return f"{dt.day} {MON[dt.month - 1]}" + (f" {dt.year}" if year else "")


def fdate(d, year=False):
    """'2026-11-03' or any ISO timestamp -> '3 Nov' (HTML-safe). Empty -> &mdash;."""
    dt, _ = _parse(d)
    if dt is None:
        return esc(d) if d else "&mdash;"
    return _day(dt, year)


def ftime(s, year=False):
    """'2026-11-03T02:31:19Z' -> '3 Nov 02:31 UTC'; date-only input -> '3 Nov'. HTML-safe."""
    dt, has_time = _parse(s)
    if dt is None:
        return esc(s) if s else "&mdash;"
    return f"{_day(dt, year)} {dt:%H:%M} UTC" if has_time else _day(dt, year)


def _ts(s):
    dt, _ = _parse(s)
    return dt.timestamp() if dt else 0.0


def plural(n, word, many=None):
    return f"{n:,} {word if n == 1 else (many or word + 's')}"


def href(url, fallback=""):
    """Only http(s) links reach the page; anything else falls back (or to '#')."""
    for u in (url, fallback):
        if u and re.match(r"^https?://", str(u), re.I):
            return esc(u)
    return "#"


def cve_link(cve):
    return f"https://www.cve.org/CVERecord?id={cve}"


def link(url, text, cls=""):
    c = f' class="{cls}"' if cls else ""
    return f'<a{c} href="{href(url)}" target="_blank" rel="noopener">{esc(text)}</a>'


def empty(cols, msg):
    return f'<tr><td colspan="{cols}" class="empty">{esc(msg)}</td></tr>'


_SRC_FAMILY = [
    ("kev", "us"), ("cisa", "us"), ("euvd", "eu"), ("enisa", "eu"), ("cert-eu", "eu"),
    ("ncsc", "nl"), ("github", "gh"), ("ghsa", "gh"), ("nvd", "cve"), ("cve", "cve"),
    ("circl", "osint"), ("misp", "osint"),
]


def src_pill(name):
    """Source label. Colour family is chosen by keyword so feed NAME wording can change freely."""
    n = (name or "").lower()
    fam = next((f for k, f in _SRC_FAMILY if k in n), "x")
    return f'<span class="src src-{fam}">{esc(name)}</span>'


def _sev(it):
    s = (it.severity or "").upper()
    return s if s else severity_for(it.score or 0)


def sev_pill(sev):
    return f'<span class="sv sv-{esc(sev)}">{esc(sev)}</span>' if sev else ""


def _more(items, n, fmt, noun):
    """First n formatted items joined by <br>, then '+ k more <noun>'."""
    head = "<br>".join(fmt(x) for x in items[:n])
    rest = len(items) - n
    return head + (f'<span class="sub">+ {plural(rest, "more " + noun, "more " + noun + "s")}</span>' if rest > 0 else "")


# ---------------------------------------------------------------- feed health

HEALTH = {
    "ok": ("ok", "OK"),
    "not-modified": ("ok", "Not modified"),
    "cached": ("cached", "Cached"),
    "stale": ("stale", "Stale"),
    "error": ("error", "Error"),
}


def build_health_rows(health):
    """health: [{source, status, items, newest, last_success, note}]  -> 6 columns."""
    if not health:
        return empty(6, "No feed has reported yet.")
    out = []
    for h in health:
        cls, label = HEALTH.get(h.get("status") or "", ("stale", h.get("status") or "Unknown"))
        out.append(
            f'<tr><td>{src_pill(h.get("source"))}</td>'
            f'<td><span class="hs hs-{cls}">{esc(label)}</span></td>'
            f'<td class="num">{int(h.get("items") or 0):,}</td>'
            f'<td class="due">{ftime(h.get("newest"), year=True)}</td>'
            f'<td class="due">{ftime(h.get("last_success"), year=True)}</td>'
            f'<td class="desc">{esc(h.get("note") or "")}</td></tr>'
        )
    return "".join(out)


def health_summary(health):
    """Plain text for n-health, e.g. '8 feeds · 6 ok · 1 cached · 1 error'."""
    counts = {}
    for h in health or []:
        cls = HEALTH.get(h.get("status") or "", ("stale",))[0]
        counts[cls] = counts.get(cls, 0) + 1
    parts = [plural(len(health or []), "feed")]
    for cls in ("ok", "cached", "stale", "error"):
        if counts.get(cls):
            parts.append(f"{counts[cls]} {cls}")
    return " &middot; ".join(parts)


# ---------------------------------------------------------------- exploited (KEV + EUVD)

def build_kev_rows(items, today):
    """CISA KEV and ENISA EUVD exploited items, merged by CVE upstream. 5 columns.
    today: 'YYYY-MM-DD' (UTC) used for the overdue flag, as in Mark's original."""
    if not items:
        return empty(5, "No new entries this window.")
    out = []
    for it in sorted(items, key=lambda i: -_ts(i.published)):
        x = it.extra or {}
        due = x.get("due") or ""
        past = bool(due) and due < today
        srcs = x.get("sources") or [it.source]
        euvd = x.get("euvd_id") or ""
        vendor, product = x.get("vendor") or "", x.get("product") or ""
        since = x.get("exploited_since") or ""
        since_html = ""
        if since and fdate(since) != fdate(it.published):
            since_html = f'<span class="sub">exploited since {fdate(since)}</span>'
        out.append(
            f'<tr><td class="id">{link(it.url or cve_link(it.id), it.id)}'
            f'<span class="sv sv-EXPLOITED">Exploited</span>'
            f'<span class="srcs">{"".join(src_pill(s) for s in srcs)}</span>'
            + (f'<span class="sub mono">{esc(euvd)}</span>' if euvd else "")
            + "</td>"
            + (f'<td><span class="tgt">{esc(vendor)}</span><span class="sub">{esc(product)}</span></td>'
               if vendor or product else "<td>&mdash;</td>")
            + f'<td class="desc">{esc(it.title)}</td>'
            f'<td class="due">{ftime(it.published)}{since_html}</td>'
            f'<td class="due{" past" if past else ""}">{fdate(due)}'
            + ('<span class="sub">overdue</span>' if past else "")
            + "</td></tr>"
        )
    return "".join(out)


def kev_overdue(items, today):
    return sum(1 for it in items if (it.extra or {}).get("due") and it.extra["due"] < today)


# ---------------------------------------------------------------- EU / national advisories

def _rating(it):
    x = it.extra or {}
    parts = []
    if it.score:
        cls = "crit" if _sev(it) == "CRITICAL" else "high" if _sev(it) == "HIGH" else "other"
        parts.append(f'<span class="score sm score-{cls}">{float(it.score):.1f}</span>{sev_pill(_sev(it))}')
    elif it.severity:
        parts.append(sev_pill(it.severity.upper()))
    p, i = (x.get("probability") or "").upper(), (x.get("impact") or "").upper()
    if p or i:
        parts.append(f'<span class="pi pi-{esc(i or "X")}" title="probability / impact (NCSC-NL)">'
                     f'P:{esc(p or "?")} / I:{esc(i or "?")}</span>')
    return "".join(parts) or "&mdash;"


def build_adv_rows(items):
    """CERT-EU and NCSC-NL advisories. 6 columns."""
    if not items:
        return empty(6, "No new advisories this window.")
    out = []
    for it in sorted(items, key=lambda i: -_ts(i.published)):
        x = it.extra or {}
        ver = x.get("version") or ""
        upd = ""
        if it.updated and it.updated != it.published:
            upd = f'<span class="sub">updated {ftime(it.updated)}</span>'
        products = x.get("products") or []
        prod = (f'<span class="sub">{esc(", ".join(products[:3]))}'
                + (f" + {len(products) - 3} more" if len(products) > 3 else "") + "</span>") if products else ""
        cves = _more(it.cves or [], 3, lambda c: link(cve_link(c), c, "mono"), "CVE") or "&mdash;"
        out.append(
            f'<tr><td class="id">{link(it.url, it.id)}'
            + (f'<span class="sub">version {esc(ver)}</span>' if ver else "")
            + f"</td><td>{src_pill(it.source)}</td>"
            f'<td class="due">{ftime(it.published)}{upd}</td>'
            f'<td class="desc">{link(it.url, it.title, "ttl")}{prod}</td>'
            f'<td class="cves">{cves}</td>'
            f'<td class="rate">{_rating(it)}</td></tr>'
        )
    return "".join(out)


# ---------------------------------------------------------------- GitHub (packages)

def _dep_sort(it):
    return (_sev(it) != "CRITICAL", -(it.score or 0), it.id)


def build_dep_rows(items):
    """GitHub reviewed advisories. Mark's 6-column layout plus the published time. 6 columns."""
    if not items:
        return empty(6, "No reviewed advisories this window.")
    out = []
    for it in sorted(items, key=_dep_sort):
        x = it.extra or {}
        pkgs = x.get("packages") or []
        npkg = int(x.get("npkg") or len(pkgs))
        if npkg > 3 and pkgs:
            pkg = (f'<span class="pkg">{esc(pkgs[0])}</span>'
                   f'<span class="sub">+ {npkg - 1} more packages</span>')
        else:
            pkg = '<span class="pkg">' + "<br>".join(esc(p) for p in pkgs) + "</span>" if pkgs else "&mdash;"
        ghsa = x.get("ghsa") or ""
        fallback = f"https://github.com/advisories/{ghsa}" if ghsa else (cve_link(it.id) if it.id.startswith("CVE-") else "")
        ecos = "".join(f'<span class="eco">{esc(e)}</span>' for e in (x.get("ecosystems") or [])) or "&mdash;"
        fixed = "<br>".join(esc(f) for f in (x.get("fixed") or [])[:3]) or "&mdash;"
        sev = _sev(it)
        out.append(
            f'<tr><td class="id"><a href="{href(it.url, fallback)}" target="_blank" rel="noopener">{esc(it.id)}</a>'
            f'<span class="sub">{ftime(it.published)}</span></td>'
            f"<td>{sev_pill(sev) or '&mdash;'}</td>"
            f"<td>{ecos}</td><td>{pkg}</td>"
            f'<td><span class="fix">{fixed}</span></td>'
            f'<td class="desc">{esc(it.title)}</td></tr>'
        )
    return "".join(out)


# ---------------------------------------------------------------- CVEs (cvelistV5 + NVD)

_AV = {"n": "network", "a": "adjacent", "l": "local", "p": "physical"}
_PR = {"n": "none", "l": "low", "h": "high"}
_AV_BIT = {"network": "AV:N network", "adjacent": "AV:A adjacent", "local": "AV:L local", "physical": "AV:P physical"}
_PR_BIT = {"none": "PR:N unauthenticated", "low": "PR:L low priv", "high": "PR:H admin"}


def _vec(x):
    """(av, pr) as words. Uses extra av/pr ('network'/'N'...) or falls back to the vector string."""
    vec = x.get("vector") or ""
    av = (x.get("av") or "").strip().lower()
    pr = (x.get("pr") or "").strip().lower()
    if not av:
        m = re.search(r"\bAV:([NALP])", vec)
        av = m.group(1).lower() if m else ""
    if not pr:
        m = re.search(r"\bPR:([NLH])", vec)
        pr = m.group(1).lower() if m else ""
    return _AV.get(av, av), _PR.get(pr, pr)


def cve_keep(items):
    """CRITICAL/HIGH, or SSVC exploitation 'active' at any score; score desc, then newest first."""
    keep = [it for it in items
            if _sev(it) in ("CRITICAL", "HIGH")
            or ((it.extra or {}).get("ssvc_exploitation") or "").lower() == "active"]
    keep.sort(key=lambda it: (-(it.score or 0), -_ts(it.published), it.id))
    return keep


def build_cve_rows(items, cap=300):
    """-> (html, shown, total). 4 columns. cap <= 0 or None means no cap."""
    keep = cve_keep(items)
    total = len(keep)
    if not keep:
        return empty(4, "No critical or high CVEs published this window."), 0, 0
    rows = keep[:cap] if cap and cap > 0 else keep
    out = []
    for it in rows:
        x = it.extra or {}
        sev = _sev(it)
        cls = "crit" if sev == "CRITICAL" else "high" if sev == "HIGH" else "other"
        av, pr = _vec(x)
        bits = [b for b in (_AV_BIT.get(av), _PR_BIT.get(pr)) if b]
        hot = " hot" if av == "network" and pr == "none" else ""
        vendors = x.get("vendors") or []
        vend = ("<br>".join(f'<span class="tgt">{esc(v)}</span>' for v in vendors[:3])
                or '<span class="sub">vendor not stated</span>')
        desc = it.title or ""
        desc = desc[:DESC_MAX].rstrip() + "…" if len(desc) > DESC_MAX else desc
        ssvc = (x.get("ssvc_exploitation") or "").lower()
        ssvc_html = {"active": '<span class="ssvc ssvc-active">SSVC: exploited</span>',
                     "poc": '<span class="ssvc ssvc-poc">SSVC: PoC public</span>'}.get(ssvc, "")
        score_src = x.get("score_source") or ""
        assigner = x.get("assigner") or ""
        nvd = x.get("nvd_score")
        nvd_html = ""
        if nvd not in (None, "") and abs(float(nvd) - float(it.score or 0)) >= 0.05:
            nvd_html = f'<span class="sub">NVD {float(nvd):.1f}</span>'
        score = f"{float(it.score):.1f}" if it.score else "&mdash;"
        out.append(
            f'<tr><td class="id">{link(it.url or cve_link(it.id), it.id)}'
            f'<span class="sub">{ftime(it.published)}</span>{ssvc_html}</td>'
            f'<td class="sc"><span class="score score-{cls}">{score}</span>{sev_pill(sev)}'
            + (f'<span class="ssrc" title="who assigned this score">{esc(score_src)}'
               + (f" &middot; {esc(assigner)}" if assigner and score_src == "CNA" else "") + "</span>"
               if score_src else "")
            + f"{nvd_html}</td>"
            f"<td>{vend}</td>"
            f'<td class="desc">{esc(desc)}'
            + (f'<span class="vecbits{hot}">{" &middot; ".join(esc(b) for b in bits)}</span>' if bits else "")
            + "</td></tr>"
        )
    return "".join(out), len(rows), total


# ---------------------------------------------------------------- OSINT (CIRCL MISP)

_TL = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}


def build_osint_rows(items):
    """CIRCL OSINT MISP events. 5 columns."""
    if not items:
        return empty(5, "No OSINT events published this window.")
    out = []
    for it in sorted(items, key=lambda i: -_ts(i.published)):
        x = it.extra or {}
        tl = str(x.get("threat_level") or "").strip()
        tl = _TL.get(tl, tl.capitalize() if tl else "Undefined")
        tags = x.get("tags") or []
        tag_html = "".join(f'<span class="tag">{esc(t)}</span>' for t in tags[:4])
        if len(tags) > 4:
            tag_html += f'<span class="sub">+ {len(tags) - 4} more</span>'
        upd = ""
        if it.updated and it.updated != it.published:
            upd = f'<span class="sub">updated {ftime(it.updated, year=True)}</span>'
        out.append(
            f'<tr><td class="desc">{link(it.url, it.title or it.id, "ttl")}'
            f'<span class="sub mono">{esc(it.id[:8])}</span></td>'
            f'<td class="due">{ftime(it.published, year=True)}{upd}</td>'
            f'<td><span class="tl tl-{esc(tl.lower())}">{esc(tl)}</span></td>'
            f'<td class="tags">{tag_html or "&mdash;"}</td>'
            f'<td>{esc(x.get("org") or "")}</td></tr>'
        )
    return "".join(out)


# ---------------------------------------------------------------- whole page

def build_stamp(now, kev_catalog="", health=None):
    """Inner HTML of <div id="rstat">. Contains <b>; never a <div>."""
    s = f'Rebuilt <b>{_day(now.astimezone(timezone.utc), True)}, {now.astimezone(timezone.utc):%H:%M} UTC</b>'
    if kev_catalog:
        s += f" &nbsp;&middot;&nbsp; CISA KEV catalog <b>{esc(kev_catalog)}</b>"
    if health:
        s += f" &nbsp;&middot;&nbsp; feeds: {health_summary(health)}"
    s += (" &nbsp;&middot;&nbsp; regenerated on a schedule; this wiki strips JavaScript from "
          "page content, so there is no in-page refresh button.")
    return s


def build_regions(kev, adv, dep, cve, osint, health, start, end, now, kev_catalog="", cap=300):
    """Everything the job writes, as {"tbody": {id: rows}, "text": {id: text}, "stamp": html}.
    start/end/now: aware datetimes (UTC). Lists are Items; health is a list of dicts."""
    today = end.astimezone(timezone.utc).strftime("%Y-%m-%d")
    cve_html, shown, total = build_cve_rows(cve, cap)
    kept = cve_keep(cve)
    n_crit = sum(1 for it in kept if _sev(it) == "CRITICAL")
    n_high = sum(1 for it in kept if _sev(it) == "HIGH")
    overdue = kev_overdue(kev, today)
    s, e = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    return {
        "tbody": {
            "t-health": build_health_rows(health),
            "t-kev": build_kev_rows(kev, today),
            "t-adv": build_adv_rows(adv),
            "t-dep": build_dep_rows(dep),
            "t-nvd": cve_html,
            "t-osint": build_osint_rows(osint),
        },
        "text": {
            "s-kev": f"{len(kev):,}",
            "s-crit": f"{n_crit:,}",
            "s-high": f"{n_high:,}",
            "s-dep": f"{len(dep):,}",
            "s-adv": f"{len(adv):,}",
            "s-osint": f"{len(osint):,}",
            "n-health": health_summary(health),
            "n-kev": plural(len(kev), "entry", "entries") + (f" &middot; {overdue} past deadline" if overdue else ""),
            "n-adv": plural(len(adv), "advisory", "advisories"),
            "n-dep": plural(len(dep), "advisory", "advisories"),
            "n-nvd": plural(total, "CVE"),
            "n-cvecap": (f"Showing {shown:,} of {total:,}, highest score first." if shown < total
                         else f"All {total:,} shown."),
            "n-osint": plural(len(osint), "event"),
            "winlabel": f"{_day(s, False)} {s:%H:%M} &rarr; {_day(e, False)} {e:%H:%M} UTC",
        },
        "stamp": build_stamp(now, kev_catalog, health),
    }


def apply_regions(doc, regions):
    """Splice regions into the page HTML. Same regexes as rebuild.py's replacers, plus rstat.
    Raises Fatal naming the first missing anchor. Idempotent."""
    for tid, rows in regions["tbody"].items():
        pat = re.compile(rf'(<tbody id="{re.escape(tid)}">).*?(</tbody>)', re.S)
        if not pat.search(doc):
            raise Fatal(f'page anchor <tbody id="{tid}"> not found — re-seed the page skeleton')
        doc = pat.sub(lambda m, r=rows: m.group(1) + r + m.group(2), doc, count=1)
    items = list(regions["text"].items()) + [(STAMP_ID, regions["stamp"])]
    for eid, text in items:
        tag = "div" if eid == STAMP_ID else "[a-zA-Z0-9]+"
        pat = re.compile(rf'(<({tag})[^>]*\bid="{re.escape(eid)}"[^>]*>)(.*?)(</\2>)', re.S)
        if not pat.search(doc):
            raise Fatal(f'page anchor id="{eid}" not found — re-seed the page skeleton')
        doc = pat.sub(lambda m, t=text: m.group(1) + t + m.group(4), doc, count=1)
    return doc


# ---------------------------------------------------------------- demo CLI

HERE = os.path.dirname(os.path.abspath(__file__))

PREVIEW_BASE = """
body{margin:0;background:#f2f3f5;font-family:Roboto,"Segoe UI",Helvetica,Arial,sans-serif}
.theme--dark{background:#1a1a1a}
.preview-note{font:12px/1.4 monospace;color:#777;padding:8px 24px}
.contents{max-width:1180px;margin:0 auto;padding:24px 32px 64px;background:#fff}
.theme--dark .contents{background:#212121;color:#ddd}
"""


def load_fixture(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    for k in ("kev", "adv", "dep", "cve", "osint"):
        d[k] = [Item.from_dict(x) for x in d.get(k, [])]
    for k in ("start", "end", "now"):
        d[k] = _parse(d[k])[0]
    return d


def render_demo(fixture, dark=False):
    d = load_fixture(fixture)
    with open(os.path.join(HERE, "page", "skeleton.html"), encoding="utf-8") as f:
        skel = f.read()
    with open(os.path.join(HERE, "page", "style.css"), encoding="utf-8") as f:
        css = f.read()
    regions = build_regions(d["kev"], d["adv"], d["dep"], d["cve"], d["osint"], d["health"],
                            d["start"], d["end"], d["now"], d.get("kev_catalog", ""), d.get("cap", 300))
    body = apply_regions(skel, regions)
    theme = "theme--dark" if dark else "theme--light"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Exploit Watch preview</title><style>{PREVIEW_BASE}\n{css}</style></head>"
        f'<body><div class="v-application {theme}">'
        '<div class="preview-note">Preview only: fixture data from tests/fixtures/render_items.json. '
        "On the wiki, page/skeleton.html is the page content and page/style.css is scriptCss.</div>"
        f'<div class="contents">{body}</div></div></body></html>'
    )


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render a standalone preview of the Exploit Watch page.")
    ap.add_argument("--demo", metavar="OUT.html", required=True, help="write a standalone preview file")
    ap.add_argument("--fixture", default=os.path.join(HERE, "tests", "fixtures", "render_items.json"))
    ap.add_argument("--dark", action="store_true", help="preview inside Wiki.js's theme--dark class")
    a = ap.parse_args(argv)
    out = render_demo(a.fixture, a.dark)
    os.makedirs(os.path.dirname(os.path.abspath(a.demo)), exist_ok=True)
    with open(a.demo, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"wrote {a.demo} ({len(out):,} bytes)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)
