#!/usr/bin/env python3
"""
Rebuild the Cyber Threat Exploit Watch runbook page on wiki2.internal.ediphy.io.

Pulls five public feeds, rebuilds the three table bodies and the counters on the
page, and writes the result back through the Wiki.js GraphQL API.

Only the generated regions are replaced. Prose, callouts and the source cards
stay hand-editable; a colleague can reword the page and this job will not
clobber it.

Environment:
  WIKI_BASE         https://wiki2.internal.ediphy.io
  WIKI_PAGE_ID      51
  WIKIJS_API_KEY    Wiki.js API key          -> Authorization header
  IAP_ID_TOKEN      Google OIDC ID token     -> Proxy-Authorization header
  GITHUB_TOKEN      optional, raises GitHub rate limit 60/hr -> 5000/hr
  NVD_API_KEY       optional, raises NVD rate limit

Usage:
  python rebuild.py --dry-run     # fetch + build + diff, write nothing
  python rebuild.py               # fetch + build + write if changed
"""

import argparse
import hashlib
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

WIKI_BASE = os.environ.get("WIKI_BASE", "https://wiki2.internal.ediphy.io").rstrip("/")
PAGE_ID = int(os.environ.get("WIKI_PAGE_ID", "51"))
WIKIJS_API_KEY = os.environ.get("WIKIJS_API_KEY", "")
IAP_ID_TOKEN = os.environ.get("IAP_ID_TOKEN", "")
GH_TOKEN = os.environ.get("GITHUB_TOKEN", "")
NVD_KEY = os.environ.get("NVD_API_KEY", "")

TIMEOUT = 90
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


class Fatal(Exception):
    """Abort without writing. A half-populated threat brief is worse than a stale one."""


def esc(s):
    return html.escape("" if s is None else str(s), quote=True)


def fdate(d):
    if not d:
        return "&mdash;"
    p = str(d).split("-")
    return f"{int(p[2])} {MON[int(p[1]) - 1]}"


# ---------------------------------------------------------------- feeds

def get_json(url, headers=None, label=""):
    try:
        r = requests.get(url, headers=headers or {}, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise Fatal(f"{label}: network error: {e}")
    if r.status_code in (403, 429):
        raise Fatal(
            f"{label}: rate limited (HTTP {r.status_code}). "
            f"GitHub allows 60 req/hour per IP unauthenticated; set GITHUB_TOKEN for 5000."
        )
    if not r.ok:
        raise Fatal(f"{label}: HTTP {r.status_code}")
    return r.json()


def fetch_kev(start, end):
    # Straight from cisa.gov. The raw.githubusercontent mirror is only needed in a
    # browser, where cisa.gov sends no CORS header; server-side we use the origin.
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    j = get_json(url, label="CISA KEV")
    rows = [
        {
            "cve": v["cveID"], "added": v["dateAdded"], "due": v.get("dueDate", ""),
            "vendor": v["vendorProject"], "product": v["product"],
            "desc": (v.get("shortDescription") or "").strip(),
        }
        for v in j.get("vulnerabilities", [])
        if start <= v["dateAdded"] <= end
    ]
    rows.sort(key=lambda r: r["added"], reverse=True)
    return rows, j.get("catalogVersion", "?")


def fetch_nvd(sev, start, end):
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start}T00:00:00.000&pubEndDate={end}T23:59:59.999"
        f"&cvssV3Severity={sev}&resultsPerPage=200"
    )
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    j = get_json(url, headers, label=f"NVD {sev}")
    total, got = j.get("totalResults", 0), len(j.get("vulnerabilities", []))
    if total > got:
        print(f"  note: NVD {sev} returned {got} of {total}; page size needs raising", file=sys.stderr)
    out = []
    for v in j.get("vulnerabilities", []):
        c = v["cve"]
        m = c.get("metrics", {})
        score, severity, vec = 0, "", ""
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if m.get(k):
                dd = m[k][0]["cvssData"]
                score = dd.get("baseScore") or 0
                severity = (dd.get("baseSeverity") or "").upper()
                vec = dd.get("vectorString") or ""
                break
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        vendors = []
        for cfg in c.get("configurations", []):
            for n in cfg.get("nodes", []):
                for cm in n.get("cpeMatch", []):
                    parts = cm.get("criteria", "").split(":")
                    if len(parts) > 4 and parts[3] not in vendors:
                        vendors.append(parts[3])
        out.append({
            "cve": c["id"], "score": score, "sev": severity, "vendors": vendors[:3],
            "desc": re.sub(r"\s+", " ", desc).strip(),
            "av": "network" if "AV:N" in vec else "local" if "AV:L" in vec else "",
            "pr": "none" if "PR:N" in vec else "low" if "PR:L" in vec else "high" if "PR:H" in vec else "",
            "pub": (c.get("published") or "")[:10],
        })
    return out


def fetch_gh(sev, start, end):
    url = (
        f"https://api.github.com/advisories?severity={sev}&type=reviewed"
        f"&published={start}..{end}&per_page=100"
    )
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    j = get_json(url, headers, label=f"GitHub {sev}")
    out = []
    for a in j:
        names, ecos, fixed = [], [], []
        for v in a.get("vulnerabilities", []):
            p = v.get("package") or {}
            if p.get("name") and p["name"] not in names:
                names.append(p["name"])
            if p.get("ecosystem") and p["ecosystem"] not in ecos:
                ecos.append(p["ecosystem"])
            if v.get("first_patched_version") and v["first_patched_version"] not in fixed:
                fixed.append(v["first_patched_version"])
        out.append({
            "id": a.get("cve_id") or a["ghsa_id"], "ghsa": a["ghsa_id"],
            "sev": (a.get("severity") or "").upper(),
            "eco": sorted(ecos), "pkgs": sorted(names), "npkg": len(names),
            "fixed": sorted(fixed)[:3],
            "summary": re.sub(r"\s+", " ", a.get("summary") or "").strip(),
            "score": (a.get("cvss") or {}).get("score") or 0,
        })
    return out


# ---------------------------------------------------------------- rows

def nvd_link(cve):
    return f"https://nvd.nist.gov/vuln/detail/{esc(cve)}"


def build_kev_rows(kev, today):
    if not kev:
        return '<tr><td colspan="5" class="empty">No new entries this window.</td></tr>'
    out = []
    for k in kev:
        past = bool(k["due"]) and k["due"] < today
        out.append(
            f'<tr><td class="id"><a href="{nvd_link(k["cve"])}" target="_blank" rel="noopener">{esc(k["cve"])}</a>'
            f'<span class="sv sv-EXPLOITED" style="margin-top:6px">Exploited</span></td>'
            f'<td><span class="tgt">{esc(k["vendor"])}</span><span class="sub">{esc(k["product"])}</span></td>'
            f'<td class="desc">{esc(k["desc"])}</td>'
            f'<td class="due">{fdate(k["added"])}</td>'
            f'<td class="due{" past" if past else ""}">{fdate(k["due"])}'
            + ('<span class="sub" style="color:inherit">overdue</span>' if past else "")
            + "</td></tr>"
        )
    return "".join(out)


def build_dep_rows(deps):
    out = []
    for d in deps:
        if d["npkg"] > 3:
            pkg = (f'<span class="pkg">{esc(d["pkgs"][0])}</span>'
                   f'<span class="sub">+ {d["npkg"] - 1} more packages</span>')
        else:
            pkg = '<span class="pkg">' + "<br>".join(esc(p) for p in d["pkgs"]) + "</span>"
        href = nvd_link(d["id"]) if d["id"].startswith("CVE-") else f'https://github.com/advisories/{esc(d["ghsa"])}'
        ecos = "".join(f'<span class="eco">{esc(e)}</span>' for e in d["eco"])
        fixed = "<br>".join(esc(f) for f in d["fixed"]) or "&mdash;"
        out.append(
            f'<tr><td class="id"><a href="{href}" target="_blank" rel="noopener">{esc(d["id"])}</a></td>'
            f'<td><span class="sv sv-{esc(d["sev"])}">{esc(d["sev"])}</span></td>'
            f"<td>{ecos}</td><td>{pkg}</td>"
            f'<td><span class="fix">{fixed}</span></td>'
            f'<td class="desc">{esc(d["summary"])}</td></tr>'
        )
    return "".join(out)


def build_nvd_rows(nvd):
    out = []
    for r in nvd:
        bits = []
        if r["av"] == "network": bits.append("AV:N network")
        if r["av"] == "local":   bits.append("AV:L local")
        if r["pr"] == "none":    bits.append("PR:N unauthenticated")
        if r["pr"] == "low":     bits.append("PR:L low priv")
        if r["pr"] == "high":    bits.append("PR:H admin")
        cls = "crit" if r["sev"] == "CRITICAL" else "high"
        vend = ("<br>".join(f'<span class="tgt">{esc(v)}</span>' for v in r["vendors"])
                or '<span class="sub" style="margin:0">no CPE yet</span>')
        desc = r["desc"][:300] + "…" if len(r["desc"]) > 300 else r["desc"]
        sev_pill = f'<span class="sv sv-{esc(r["sev"])}" style="margin-top:6px">{esc(r["sev"])}</span>' if r["sev"] else ""
        out.append(
            f'<tr><td class="id"><a href="{nvd_link(r["cve"])}" target="_blank" rel="noopener">{esc(r["cve"])}</a>'
            f'<span class="sub">{esc(r["pub"])}</span></td>'
            f'<td><span class="score" style="color:var(--{cls})">{float(r["score"]):.1f}</span>{sev_pill}</td>'
            f"<td>{vend}</td>"
            f'<td class="desc">{esc(desc)}'
            + (f'<span class="vecbits">{esc("  ·  ".join(bits))}</span>' if bits else "")
            + "</td></tr>"
        )
    return "".join(out)


# ---------------------------------------------------------------- splice

def replace_tbody(doc, tid, rows):
    pat = re.compile(rf'(<tbody id="{re.escape(tid)}">).*?(</tbody>)', re.S)
    if not pat.search(doc):
        raise Fatal(f'page anchor <tbody id="{tid}"> not found — the page skeleton was edited; re-seed it')
    return pat.sub(lambda m: m.group(1) + rows + m.group(2), doc, count=1)


def replace_inner(doc, eid, text):
    """Replace the inner text of a single element by id. Element must not contain child tags."""
    pat = re.compile(rf'(<([a-zA-Z0-9]+)[^>]*\bid="{re.escape(eid)}"[^>]*>)(.*?)(</\2>)', re.S)
    if not pat.search(doc):
        raise Fatal(f'page anchor id="{eid}" not found — the page skeleton was edited; re-seed it')
    return pat.sub(lambda m: m.group(1) + text + m.group(4), doc, count=1)


def replace_refresh_bar(doc, stamp_html):
    pat = re.compile(r'<div class="refresh">.*?</div>\s*</div>', re.S)
    block = ('<div class="refresh"><div class="wrap"><div class="rstat">'
             + stamp_html + "</div></div></div>")
    if not pat.search(doc):
        raise Fatal('page anchor <div class="refresh"> not found — the page skeleton was edited; re-seed it')
    return pat.sub(block, doc, count=1)


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
    r = requests.post(f"{WIKI_BASE}/graphql", headers=wiki_headers(),
                      json={"query": query, "variables": variables or {}}, timeout=TIMEOUT)
    if r.status_code in (301, 302) or "accounts.google.com" in r.text[:600]:
        raise Fatal("redirected to Google sign-in: the IAP token is missing, expired, "
                    "or the service account lacks roles/iap.httpsResourceAccessor")
    if r.status_code == 401:
        raise Fatal("HTTP 401 from Wiki.js: API disabled, or the API key is wrong/revoked")
    if not r.ok:
        raise Fatal(f"GraphQL HTTP {r.status_code}: {r.text[:300]}")
    j = r.json()
    if j.get("errors"):
        raise Fatal("GraphQL errors: " + "; ".join(e.get("message", "?") for e in j["errors"]))
    return j["data"]


READ_PAGE = """
query ($id: Int!) {
  pages { single(id: $id) { content title description tags { tag } } }
}
"""

# Note: do NOT request `page { ... }` in the mutation response. Page.editor is
# non-nullable and serialises to null here, which surfaces as a GraphQL error
# even though the write succeeded.
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="build and diff, write nothing")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    end = now.strftime("%Y-%m-%d")
    start = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    print(f"window {start} -> {end}")

    kev, catalog = fetch_kev(start, end)
    print(f"  KEV         {len(kev):>4}  (catalog {catalog})")

    crit = fetch_nvd("CRITICAL", start, end)
    print(f"  NVD crit    {len(crit):>4}")
    if not NVD_KEY:
        time.sleep(7)  # unauthenticated NVD allows 5 requests / 30s
    high = fetch_nvd("HIGH", start, end)
    print(f"  NVD high    {len(high):>4}")

    seen, nvd = set(), []
    for r in sorted(crit + high, key=lambda x: -x["score"]):
        if r["cve"] not in seen:
            seen.add(r["cve"])
            nvd.append(r)

    deps = fetch_gh("critical", start, end) + fetch_gh("high", start, end)
    deps.sort(key=lambda d: (d["sev"] != "CRITICAL", -(d["score"] or 0), d["id"]))
    print(f"  GitHub      {len(deps):>4}")

    if not kev and not nvd and not deps:
        raise Fatal("every feed came back empty — refusing to publish an empty brief")

    page = gql(READ_PAGE, {"id": PAGE_ID})["pages"]["single"]
    doc = page["content"]
    before = hashlib.sha256(doc.encode()).hexdigest()

    n_crit = sum(1 for r in nvd if r["sev"] == "CRITICAL")
    n_high = sum(1 for r in nvd if r["sev"] == "HIGH")
    overdue = sum(1 for k in kev if k["due"] and k["due"] < end)

    doc = replace_tbody(doc, "t-kev", build_kev_rows(kev, end))
    doc = replace_tbody(doc, "t-dep", build_dep_rows(deps))
    doc = replace_tbody(doc, "t-nvd", build_nvd_rows(nvd))
    doc = replace_inner(doc, "s-kev", str(len(kev)))
    doc = replace_inner(doc, "s-crit", str(n_crit))
    doc = replace_inner(doc, "s-high", str(n_high))
    doc = replace_inner(doc, "s-dep", str(len(deps)))
    doc = replace_inner(doc, "n-kev", f"{len(kev)} entries" + (f" &middot; {overdue} past deadline" if overdue else ""))
    doc = replace_inner(doc, "n-dep", f"{len(deps)} advisories")
    doc = replace_inner(doc, "n-nvd", f"{len(nvd)} CVEs")
    doc = replace_inner(doc, "winlabel", f"{fdate(start)} &rarr; {fdate(end)}")
    doc = replace_refresh_bar(doc, (
        f'Rebuilt <b>{now.strftime("%-d %b %Y, %H:%M")} UTC</b> &nbsp;&middot;&nbsp; '
        f"CISA KEV catalog <b>{esc(catalog)}</b> &nbsp;&middot;&nbsp; "
        "regenerated on a schedule; this wiki strips JavaScript from page content, "
        "so there is no in-page refresh button."
    ))

    after = hashlib.sha256(doc.encode()).hexdigest()
    if before == after:
        print("no change since last run — skipping write")
        return 0

    print(f"content {len(page['content'])} -> {len(doc)} bytes")
    if args.dry_run:
        print("dry run: not writing")
        return 0

    res = gql(WRITE_PAGE, {
        "id": PAGE_ID, "content": doc,
        "tags": [t["tag"] for t in (page.get("tags") or [])],   # required: resolver maps over it
        "title": page["title"], "desc": page.get("description") or "",
    })["pages"]["update"]["responseResult"]

    if not res["succeeded"]:
        raise Fatal(f"Wiki.js refused the write: {res['message']}")
    print(f"written: {res['message']}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)
