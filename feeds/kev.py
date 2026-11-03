"""
CISA Known Exploited Vulnerabilities catalog.

cisa.gov answers 403 to some egress proxies (ours, 2026-11-03), so the cisagov
GitHub mirror is the fallback. The mirror carries the same file and a weak ETag,
so a repeat run costs a 304. dateAdded is a date only; the catalog-level
dateReleased is the only precise timestamp CISA publishes.
"""

from .common import Item, SourceError, get, iso_utc, parse_iso

NAME = "CISA KEV"
TABLE = "kev"
CADENCE = 0

SOURCES = [
    ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "cisa.gov"),
    ("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json", "github mirror"),
]


def cve_link(cve):
    return f"https://www.cve.org/CVERecord?id={cve}"


def load_catalog():
    """Return (catalog json, via). Tries each source in order; raises only if all fail."""
    errors = []
    for url, via in SOURCES:
        try:
            j = get(url, f"{NAME} ({via})").json()
        except SourceError as e:
            errors.append(str(e))
            continue
        except ValueError:
            # A proxy block page comes back as 200 HTML; treat it like a failure.
            errors.append(f"{NAME} ({via}): response is not JSON")
            continue
        if not isinstance(j, dict) or "vulnerabilities" not in j:
            errors.append(f"{NAME} ({via}): no 'vulnerabilities' key")
            continue
        return j, via
    raise SourceError("; ".join(errors))


def parse(j, via, start, end):
    first, last = start.date().isoformat(), end.date().isoformat()
    released = j.get("dateReleased") or ""
    if released:
        released = iso_utc(parse_iso(released))
    out = []
    for v in j.get("vulnerabilities", []):
        added = v.get("dateAdded") or ""
        if not (first <= added <= last):
            continue
        cve = v["cveID"]
        out.append(Item(
            source=NAME, id=cve, url=cve_link(cve),
            title=" ".join((v.get("shortDescription") or "").split()),
            published=added, cves=[cve],
            extra={
                "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
                "due": v.get("dueDate", ""), "catalog_released": released,
                "catalog_version": j.get("catalogVersion", ""), "via": via,
            },
        ))
    out.sort(key=lambda i: (i.published, i.id), reverse=True)
    return out


def fetch(start, end):
    j, via = load_catalog()
    return parse(j, via, start, end)
