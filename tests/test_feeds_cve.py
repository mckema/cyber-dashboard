"""
Parsing tests for the CVE-side feeds (kev, euvd, cvelist, nvd, github). No network:
every HTTP call goes through a fake common.get.

  python -m unittest discover -s tests -p "test_feeds_cve.py"
"""

import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from unittest import mock

from feeds import common, cvelist, euvd, github, kev, nvd, state
from feeds.common import Response, SourceError

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
START = datetime(2026, 10, 27, 3, 0, tzinfo=timezone.utc)
END = datetime(2026, 11, 3, 3, 0, tzinfo=timezone.utc)


def fixture(name, mode="r"):
    with open(os.path.join(FIX, name), mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
        return f.read()


def resp(body, status=200, headers=None, url="https://example.test/", from_cache=False):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode() if not isinstance(body, str) else body.encode()
    return Response(status, body, headers or {}, url, from_cache)


class TempState(unittest.TestCase):
    """Point feeds.state at a throwaway directory."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        p = mock.patch.object(state, "STATE_DIR", self.dir)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.dir, True)


# ---------------------------------------------------------------- kev

class KevTest(unittest.TestCase):
    def test_window_and_fields(self):
        items = kev.parse(json.loads(fixture("kev_catalog.json")), "github mirror", START, END)
        self.assertEqual([i.id for i in items], ["CVE-2026-76418", "CVE-2026-97229"])
        i = items[0]
        self.assertEqual(i.source, "CISA KEV")
        self.assertEqual(i.published, "2026-10-29")
        self.assertEqual(i.url, "https://www.cve.org/CVERecord?id=CVE-2026-76418")
        self.assertEqual(i.extra["due"], "2026-11-01")
        self.assertEqual(i.extra["vendor"], "Cisco")
        self.assertEqual(i.extra["catalog_released"], "2026-10-30T17:02:45Z")
        self.assertEqual(i.extra["via"], "github mirror")

    def test_falls_back_to_mirror(self):
        cat = json.loads(fixture("kev_catalog.json"))

        def fake(url, label, **kw):
            if "cisa.gov" in url:
                raise SourceError(f"{label}: HTTP 403 (blocked or rate limited)")
            return resp(cat)
        with mock.patch.object(kev, "get", fake):
            items = kev.fetch(START, END)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].extra["via"], "github mirror")

    def test_both_fail(self):
        def fake(url, label, **kw):
            if "cisa.gov" in url:
                raise SourceError(f"{label}: HTTP 403 (blocked or rate limited)")
            return resp("<html>proxy says no</html>")
        with mock.patch.object(kev, "get", fake):
            with self.assertRaises(SourceError) as cm:
                kev.fetch(START, END)
        self.assertIn("CISA KEV (cisa.gov): HTTP 403", str(cm.exception))
        self.assertIn("CISA KEV (github mirror): response is not JSON", str(cm.exception))


# ---------------------------------------------------------------- euvd

class EuvdTest(unittest.TestCase):
    def test_parse_date(self):
        self.assertEqual(euvd.parse_date("Nov 3, 2026, 12:41:24 AM"),
                         datetime(2026, 11, 3, 0, 41, 24, tzinfo=timezone.utc))
        self.assertEqual(euvd.parse_date("Oct 15, 2026, 8:56:58 PM").hour, 20)
        self.assertEqual(euvd.parse_date("Oct 15, 2026, 12:05:00 PM").hour, 12)
        self.assertIsNone(euvd.parse_date(""))

    def test_item(self):
        rows = json.loads(fixture("euvd_search.json"))["items"]
        i = euvd.to_item(rows[0])
        self.assertEqual(i.id, "CVE-2026-111357")          # first CVE alias, though GHSA is listed first
        self.assertEqual(i.cves, ["CVE-2026-111357"])
        self.assertEqual(i.published, "2026-10-30")        # exploitedSince
        self.assertEqual(i.updated, "2026-10-31T03:56:17Z")
        self.assertEqual(i.extra["euvd_id"], "EUVD-2026-102437")
        self.assertEqual(i.extra["euvd_published"], "2026-10-15T20:56:58Z")
        self.assertEqual(i.extra["vendor"], "Ivanti")
        self.assertEqual(i.extra["product"], "Connect Secure")
        self.assertEqual(i.severity, "HIGH")
        self.assertEqual(i.url, "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-102437")
        cisco = euvd.to_item(rows[1])
        self.assertEqual(cisco.extra["product"].count("Adaptive Security Appliance"), 1)   # de-duplicated

    def test_paging(self):
        rows = json.loads(fixture("euvd_search.json"))["items"]
        calls = []

        def fake(url, label, **kw):
            calls.append(kw["params"])
            self.assertFalse(kw["conditional"])
            page = kw["params"]["page"]
            return resp({"items": rows[page:page + 1], "total": 2})
        with mock.patch.object(euvd, "get", fake):
            items = euvd.fetch(START, END)
        self.assertEqual(len(items), 2)
        self.assertEqual([c["page"] for c in calls], [0, 1])
        self.assertEqual(calls[0]["fromKEVDate"], "2026-10-27")
        self.assertEqual(calls[0]["toKEVDate"], "2026-11-03")


# ---------------------------------------------------------------- cvelist

def make_record(cid, published, state_="PUBLISHED", cna_metrics=None):
    return {"cveMetadata": {"cveId": cid, "state": state_, "datePublished": published,
                            "dateUpdated": published, "assignerShortName": "test"},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": f"{cid} desc"}],
                                   "affected": [{"vendor": "n/a"}, {"vendor": "Acme"}],
                                   "metrics": cna_metrics or []}}}


def make_zip(records):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(f"deltaCves/{r['cveMetadata']['cveId']}.json", json.dumps(r))
        z.writestr("deltaCves/README.txt", "not a record")
    return buf.getvalue()


def delta_log(entries):
    return json.dumps(entries, indent=2).encode()


def entry(fetch_time, *cves, kind="new"):
    rows = [{"cveId": c, "githubLink": f"https://raw.test/{c}.json", "dateUpdated": fetch_time} for c in cves]
    return {"fetchTime": fetch_time, "numberOfChanges": len(rows),
            "new": rows if kind == "new" else [], "updated": rows if kind == "updated" else [], "error": []}


class FakeRaw:
    """Serves a deltaLog with Range support, raw records and release zips."""

    def __init__(self, log, records=None, zips=None, etag='"v1"'):
        self.log, self.records, self.zips, self.etag = log, records or {}, zips or {}, etag
        self.calls = []

    def __call__(self, url, label, headers=None, conditional=True, byte_range=None, params=None):
        self.calls.append(url)
        if url == cvelist.DELTA_URL:
            assert headers == {"Accept-Encoding": "identity"}
            a, b = byte_range
            return resp(self.log[a:b + 1], status=206, headers={"ETag": self.etag})
        if url.startswith("https://raw.test/"):
            cid = url.rsplit("/", 1)[1][:-5]
            if cid not in self.records:
                raise SourceError(f"{label}: HTTP 404")
            return resp(self.records[cid])
        if url in self.zips:
            return resp(self.zips[url])
        raise SourceError(f"{label}: HTTP 404")


class CvelistParseTest(unittest.TestCase):
    def test_delta_prefix_truncated(self):
        entries = cvelist.parse_delta_prefix(fixture("cvelist_delta_prefix.bin", "rb"))
        self.assertGreaterEqual(len(entries), 3)
        self.assertEqual(entries[0]["fetchTime"], "2026-11-03T02:36:31.191Z")
        self.assertEqual(entries[0]["new"][0]["cveId"], "CVE-2026-111464")
        links = cvelist.changed_links(entries)
        self.assertIn("CVE-2026-6324", links)              # from updated[]

    def test_cna_record(self):
        i = cvelist.parse_record(json.loads(fixture("cve_record_cna.json")))
        self.assertEqual(i.id, "CVE-2026-105770")
        self.assertEqual(i.published, "2026-11-03T00:41:24Z")
        self.assertEqual((i.score, i.severity), (5.3, "MEDIUM"))
        self.assertEqual(i.extra["score_source"], "CNA")
        self.assertEqual((i.extra["av"], i.extra["pr"]), ("network", "none"))
        self.assertEqual(i.extra["assigner"], "chainguard")
        self.assertEqual(i.extra["vendors"], ["octo-sts"])
        self.assertEqual(i.url, "https://www.cve.org/CVERecord?id=CVE-2026-105770")
        self.assertLessEqual(len(i.title), cvelist.DESC_MAX)

    def test_adp_record(self):
        i = cvelist.parse_record(json.loads(fixture("cve_record_adp.json")))
        self.assertEqual((i.score, i.severity), (8.1, "HIGH"))
        self.assertEqual(i.extra["score_source"], "CISA-ADP")
        self.assertEqual(i.extra["ssvc_exploitation"], "poc")
        self.assertEqual(i.extra["pr"], "low")

    def test_cvss_preference_and_words(self):
        m = [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/PR:N"}},
             {"cvssV4_0": {"baseScore": 9.3, "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/AV:L/PR:H"}}]
        self.assertEqual(cvelist.cvss(m), (9.3, "CRITICAL", "CVSS:4.0/AV:L/PR:H"))
        self.assertEqual(cvelist.cvss([{"cvssV4_0": {"baseScore": 0.0, "baseSeverity": "NONE"}}])[1], "")
        i = cvelist.parse_record(make_record("CVE-2026-1", "2026-11-01T00:00:00.000Z",
                                             cna_metrics=[{"other": {"type": "Red Hat severity rating",
                                                                     "content": {"value": "Important"}}}]))
        self.assertEqual((i.score, i.severity, i.extra["score_source"]), (0.0, "HIGH", "CNA"))
        self.assertEqual(i.extra["vendors"], ["Acme"])     # "n/a" dropped
        self.assertEqual(cvelist.vector_bits("CVSS:4.0/AV:N/AC:L/AT:N/PR:L"), ("network", "low"))

    def test_rejected_and_window(self):
        store = {"CVE-2026-2": {"published": "2026-11-01T00:00:00Z"}}
        cvelist.apply(store, make_record("CVE-2026-2", "2026-11-01T00:00:00Z", state_="REJECTED"), START)
        self.assertNotIn("CVE-2026-2", store)
        cvelist.apply(store, make_record("CVE-2025-9", "2025-01-01T00:00:00Z"), START)
        self.assertNotIn("CVE-2025-9", store)
        cvelist.apply(store, make_record("CVE-2026-3", "2026-11-02T10:00:00.123Z"), START)
        self.assertEqual(store["CVE-2026-3"]["published"], "2026-11-02T10:00:00Z")

    def test_near_midnight(self):
        t = lambda s: datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        self.assertTrue(cvelist.near_midnight(t("2026-11-03T00:06:24")))
        self.assertTrue(cvelist.near_midnight(t("2026-11-02T23:50:00")))
        self.assertFalse(cvelist.near_midnight(t("2026-11-03T00:50:00")))
        self.assertFalse(cvelist.near_midnight(t("2026-11-02T23:40:00")))

    def test_zip_records(self):
        z = make_zip([make_record("CVE-2026-4", "2026-11-01T00:00:00Z")])
        self.assertEqual([r["cveMetadata"]["cveId"] for r in cvelist.zip_records(z)], ["CVE-2026-4"])
        with self.assertRaises(SourceError):
            list(cvelist.zip_records(b"not a zip"))
        with self.assertRaises(SourceError):
            cvelist.release_zip("cve_2026-11-03_0200Z", "2026-11-03_all_CVEs_at_midnight.zip.zip")


class CvelistFetchTest(TempState):
    def test_read_delta_needs_several_chunks(self):
        log = delta_log([entry(f"2026-11-03T02:{m:02d}:00.000Z", f"CVE-2026-{m}") for m in range(59, 0, -1)])
        fake = FakeRaw(log)
        with mock.patch.object(cvelist, "get", fake):
            newer, reached = cvelist.read_delta(datetime(2026, 11, 3, 2, 10, tzinfo=timezone.utc), chunk=1024)
        self.assertTrue(reached)
        self.assertEqual(len(newer), 49)
        self.assertEqual(newer[-1]["fetchTime"], "2026-11-03T02:11:00.000Z")
        self.assertGreater(fake.calls.count(cvelist.DELTA_URL), 1)

    def test_steady_state_delta(self):
        state.save_json(cvelist.CURSOR, {"fetch_time": "2026-11-03T02:00:00.000Z"})
        state.save_json(cvelist.STORE, {
            "CVE-2026-10": cvelist.parse_record(make_record("CVE-2026-10", "2026-10-30T00:00:00Z")).to_dict(),
            "CVE-2026-11": {"published": "2026-10-20T00:00:00Z"},          # fell out of the window
        })
        log = delta_log([
            entry("2026-11-03T02:40:00.000Z", "CVE-2026-12", "CVE-2026-13"),
            entry("2026-11-03T02:20:00.000Z", "CVE-2026-10", kind="updated"),
            entry("2026-11-03T02:00:00.000Z", "CVE-2026-99"),                # already processed
        ])
        recs = {"CVE-2026-12": make_record("CVE-2026-12", "2026-11-03T02:35:00Z"),
                "CVE-2026-10": make_record("CVE-2026-10", "2026-10-30T00:00:00Z", state_="REJECTED")}
        fake = FakeRaw(log, recs)                                            # CVE-2026-13 -> 404
        with mock.patch.object(cvelist, "get", fake):
            items = cvelist.fetch(START, END)
        self.assertEqual([i.id for i in items], ["CVE-2026-12"])
        self.assertNotIn("https://raw.test/CVE-2026-99.json", fake.calls)
        cur = state.load_json(cvelist.CURSOR, {})
        self.assertEqual(cur["fetch_time"], "2026-11-03T02:40:00.000Z")
        self.assertEqual(cur["retry"], {"CVE-2026-13": ["https://raw.test/CVE-2026-13.json", 1]})
        self.assertEqual(cvelist.STATS["mode"], "delta")

        # Next run: nothing new in the log, the 404 record is retried and now exists.
        fake.records["CVE-2026-13"] = make_record("CVE-2026-13", "2026-11-03T02:39:00Z")
        with mock.patch.object(cvelist, "get", fake):
            items = cvelist.fetch(START, END)
        self.assertEqual([i.id for i in items], ["CVE-2026-13", "CVE-2026-12"])
        cur = state.load_json(cvelist.CURSOR, {})
        self.assertEqual(cur["fetch_time"], "2026-11-03T02:40:00.000Z")
        self.assertEqual(cur["retry"], {})

    def test_backfill_first_run(self):
        base = "https://github.com/CVEProject/cvelistV5/releases/download/"
        zips = {}
        for d in range(27, 32):
            ds = f"2026-10-{d}"
            zips[f"{base}cve_{ds}_at_end_of_day/{ds}_delta_CVEs_at_end_of_day.zip"] = make_zip(
                [make_record(f"CVE-2026-{d}", f"{ds}T12:00:00Z")])
        zips[f"{base}cve_2026-11-01_at_end_of_day/2026-11-01_delta_CVEs_at_end_of_day.zip"] = make_zip(
            [make_record("CVE-2026-27", "2026-10-27T12:00:00Z", state_="REJECTED")])
        # 2026-11-02: end-of-day zip not published yet, fall back to its 2300Z hourly
        zips[f"{base}cve_2026-11-02_2300Z/2026-11-02_delta_CVEs_at_2300Z.zip"] = make_zip(
            [make_record("CVE-2026-102", "2026-11-02T22:00:00Z")])
        # today 03:00 -> 0300Z missing, 0200Z exists
        zips[f"{base}cve_2026-11-03_0200Z/2026-11-03_delta_CVEs_at_0200Z.zip"] = make_zip(
            [make_record("CVE-2026-103", "2026-11-03T01:00:00Z"), make_record("CVE-2025-1", "2025-01-01T00:00:00Z")])
        log = delta_log([entry("2026-11-03T02:50:00.000Z", "CVE-2026-104"),
                         entry("2026-11-03T01:30:00.000Z", "CVE-2026-103", kind="updated"),
                         entry("2026-11-01T12:00:00.000Z", "CVE-2026-29", kind="updated"),
                         entry("2026-11-01T00:06:24.148Z", "CVE-2026-900"),     # in neither zip
                         entry("2026-10-26T12:00:00.000Z", "CVE-2026-1")])
        recs = {"CVE-2026-104": make_record("CVE-2026-104", "2026-11-03T02:45:00Z"),
                "CVE-2026-103": make_record("CVE-2026-103", "2026-11-03T01:00:00Z"),
                "CVE-2026-900": make_record("CVE-2026-900", "2026-10-31T23:58:00Z")}
        fake = FakeRaw(log, recs, zips)
        with mock.patch.object(cvelist, "get", fake):
            items = cvelist.fetch(START, END)
        ids = [i.id for i in items]
        self.assertEqual(ids, ["CVE-2026-104", "CVE-2026-103", "CVE-2026-102", "CVE-2026-900", "CVE-2026-31",
                               "CVE-2026-30", "CVE-2026-29", "CVE-2026-28"])   # 27 rejected later, 2025-1 outside
        self.assertEqual(cvelist.STATS["mode"], "backfill")
        self.assertEqual(cvelist.STATS["midnight_entries"], 1)
        self.assertTrue(cvelist.STATS["log_reaches_start"])
        # Catch-up starts 15 min before the 0200Z snapshot, so the 01:30 entry is not re-read,
        # and a midday entry covered by a zip is not replayed either.
        self.assertNotIn("https://raw.test/CVE-2026-103.json", fake.calls)
        self.assertNotIn("https://raw.test/CVE-2026-29.json", fake.calls)
        self.assertFalse(any("_all_CVEs_" in u for u in fake.calls))
        self.assertEqual(state.load_json(cvelist.CURSOR, {})["fetch_time"], "2026-11-03T02:50:00.000Z")


# ---------------------------------------------------------------- nvd

class NvdTest(TempState):
    def test_item(self):
        page = json.loads(fixture("nvd_page.json"))
        i = nvd.to_item(page["vulnerabilities"][0]["cve"])
        self.assertEqual((i.score, i.severity), (7.5, "HIGH"))           # NVD Primary row wins
        self.assertEqual(i.published, "2026-10-28T16:15:42Z")
        self.assertEqual(i.extra["vendors"], ["cisco"])
        self.assertEqual(i.title, "A vulnerability in Cisco Secure Firewall ASA could allow an unauthenticated, "
                                  "remote attacker to cause a reload.")
        self.assertIsNone(nvd.to_item(page["vulnerabilities"][2]["cve"]))
        self.assertEqual(nvd.nvd_time(START), "2026-10-27T03:00:00.000+00:00")

    def test_incremental(self):
        page = json.loads(fixture("nvd_page.json"))
        calls = []

        def fake(url, label, **kw):
            calls.append(kw["params"])
            return resp(page)
        with mock.patch.object(nvd, "get", fake):
            items = nvd.fetch(START, END)
        self.assertEqual([i.id for i in items], ["CVE-2026-111464", "CVE-2026-76418"])
        self.assertEqual(calls[0]["pubStartDate"], "2026-10-27T03:00:00.000+00:00")   # first run
        self.assertNotIn("lastModStartDate", calls[0])
        self.assertEqual(calls[0]["startIndex"], 0)

        later = datetime(2026, 11, 3, 5, 0, tzinfo=timezone.utc)
        empty = {"totalResults": 0, "vulnerabilities": []}
        with mock.patch.object(nvd, "get", lambda url, label, **kw: calls.append(kw["params"]) or resp(empty)):
            items = nvd.fetch(START, later)
        self.assertEqual(len(items), 2)                                   # kept from the store
        self.assertEqual(calls[1]["lastModStartDate"], "2026-11-03T02:45:00.000+00:00")


# ---------------------------------------------------------------- github

class GithubTest(TempState):
    def test_next_link(self):
        link = ('<https://api.github.com/advisories?per_page=100&after=Y3Vy>; rel="next", '
                '<https://api.github.com/advisories?per_page=100&before=Y3V>; rel="prev"')
        self.assertEqual(github.next_link(link), "https://api.github.com/advisories?per_page=100&after=Y3Vy")
        self.assertIsNone(github.next_link(""))

    def test_item(self):
        i = github.to_item(json.loads(fixture("github_advisories.json"))[0])
        self.assertEqual(i.id, "CVE-2026-111497")
        self.assertEqual(i.url, "https://github.com/advisories/GHSA-9v8h-qqgm-4m35")
        self.assertEqual((i.score, i.severity), (9.2, "CRITICAL"))
        self.assertEqual(i.published, "2026-10-30T18:22:05Z")
        self.assertEqual(i.extra["packages"], ["brotli", "brotli-wasm"])
        self.assertEqual(i.extra["ecosystems"], ["npm", "pip"])
        self.assertEqual(i.extra["fixed"], ["1.2.1", "1.3.1", "3.0.2"])
        self.assertEqual(i.extra["npkg"], 2)
        self.assertEqual(i.title, "Brotli decoder heap overflow")

    def test_follows_pages_and_filters_window(self):
        adv = json.loads(fixture("github_advisories.json"))
        page2 = "https://api.github.com/advisories?severity=high&after=abc&published=2026-10-27..2026-11-03"
        first = {}

        def fake(url, label, headers=None, conditional=True, byte_range=None, params=None):
            if params:
                full = f"{url}?severity={params['severity']}&published={params['published']}"
                first[params["severity"]] = full
                if params["severity"] == "critical":
                    return resp([adv[0]], url=full)
                return resp([adv[1]], url=full, headers={"Link": f'<{page2}>; rel="next"'})
            self.assertEqual(url, page2)
            hi = dict(adv[0], ghsa_id="GHSA-xxxx-yyyy-zzzz", cve_id=None, severity="high",
                      html_url="https://github.com/advisories/GHSA-xxxx-yyyy-zzzz")
            return resp([hi], url=page2)
        with mock.patch.object(github, "get", fake):
            items = github.fetch(START, END)
        self.assertEqual([i.id for i in items], ["CVE-2026-111497", "GHSA-xxxx-yyyy-zzzz"])   # page 2 kept, old one dropped
        self.assertEqual(github.STATS["requests"], 3)

        # Second run: every page is a 304 without a Link header; page 2 is still found.
        def cached(url, label, headers=None, conditional=True, byte_range=None, params=None):
            full = first[params["severity"]] if params else url
            return resp(fake(url, label, params=params).content, status=304, url=full, from_cache=True)
        with mock.patch.object(github, "get", cached):
            items = github.fetch(START, END)
        self.assertEqual(len(items), 2)
        self.assertEqual(github.STATS["not_modified"], 3)

    def test_page_cap(self):
        def endless(url, label, **kw):
            return resp([], headers={"Link": '<https://api.github.com/advisories?after=x&published=2026-11-03>; rel="next"'})
        with mock.patch.object(github, "get", endless):
            with self.assertRaises(SourceError) as cm:
                github.fetch(START, END)
        self.assertIn("page cap hit", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
