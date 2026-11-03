"""
Parsing tests for the advisory/OSINT feeds: certeu, ncscnl, circl.

No network: fetch() is exercised with common.get replaced by a fake that serves
trimmed live samples from tests/fixtures (captured 2026-11-03), and STATE_DIR
pointed at a temp dir.

  python -m unittest discover -s tests -p "test_feeds_adv.py"
"""

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone

from feeds import certeu, circl, ncscnl, state
from feeds.common import Response, SourceError

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name):
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


def utc(*a):
    return datetime(*a, tzinfo=timezone.utc)


class FakeGet:
    """Stands in for common.get: url -> bytes, or an exception to raise. Records calls."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, url, label, headers=None, conditional=True, byte_range=None, params=None):
        self.calls.append(url)
        body = self.routes.get(url)
        if body is None:
            raise SourceError(f"{label}: HTTP 404")
        if isinstance(body, Exception):
            raise body
        return Response(200, body, {}, url)


class StateDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old_state = state.STATE_DIR
        state.STATE_DIR = self.tmp

    def tearDown(self):
        state.STATE_DIR = self.old_state
        shutil.rmtree(self.tmp, ignore_errors=True)

    def patch_get(self, module, routes):
        fake = FakeGet(routes)
        old = module.get
        module.get = fake
        self.addCleanup(setattr, module, "get", old)
        return fake


# ---------------------------------------------------------------- CERT-EU

class CertEuParse(unittest.TestCase):
    def test_pubdate_zone_labels(self):
        # "CEST" is unknown to email.utils, which would read it as UTC (2 h off).
        self.assertEqual(certeu.parse_pubdate("Fri, 23 Oct 2026 16:36:26 CEST"), utc(2026, 10, 23, 14, 36, 26))
        self.assertEqual(certeu.parse_pubdate("Mon, 02 Mar 2026 18:00:00 CET"), utc(2026, 3, 2, 17, 0, 0))
        self.assertEqual(certeu.parse_pubdate("Mon, 02 Nov 2026 09:17:50 +0000"), utc(2026, 11, 2, 9, 17, 50))
        self.assertEqual(certeu.parse_pubdate("Mon, 02 Nov 2026 09:17:50 GMT"), utc(2026, 11, 2, 9, 17, 50))
        self.assertIsNone(certeu.parse_pubdate("Mon, 02 Nov 2026 09:17:50 EEST"))
        self.assertIsNone(certeu.parse_pubdate(""))

    def test_rss(self):
        e = certeu.parse_rss(fixture("certeu_rss.xml"))
        self.assertEqual([x["serial"] for x in e], ["2026-018", "2026-019", "2026-017"])
        self.assertEqual(e[0]["title"], "Critical Vulnerabilities in PHP")
        self.assertEqual(e[0]["url"], "https://cert.europa.eu/publications/security-advisories/2026-018/")
        self.assertEqual(e[0]["pubdate"], "Fri, 23 Oct 2026 16:36:26 CEST")

    def test_rss_dedup_keeps_first(self):
        xml = b"""<rss><channel>
          <item><title>2026-018: New title</title><pubDate>Fri, 23 Oct 2026 16:36:26 CEST</pubDate></item>
          <item><title>2026-018: Old title</title><pubDate>Tue, 20 Oct 2026 10:00:00 CEST</pubDate></item>
          <item><title>Not an advisory</title></item>
        </channel></rss>"""
        e = certeu.parse_rss(xml)
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["title"], "New title")

    def test_rss_bad_xml(self):
        with self.assertRaisesRegex(SourceError, "CERT-EU: RSS is not valid XML"):
            certeu.parse_rss(b"<html>maintenance")

    def test_front_matter_quoted_and_bare(self):
        fm = certeu.front_matter("---    \ntitle: 'A: B'\nversion: '1.2'\ndate: 2026-09-09\n---\nbody")
        self.assertEqual(fm, {"title": "A: B", "version": "1.2", "date": "2026-09-09"})
        self.assertEqual(certeu.first_release_date("* 09/09/2026 --- v1.0 -- Initial publication.", {}), "2026-09-09")
        self.assertEqual(certeu.first_release_date("* _20/10/2026 --- v1.0 -- Initial_", {}), "2026-10-20")
        self.assertEqual(certeu.first_release_date("no history", {"date": "2026-10-21"}), "2026-10-21")

    def test_advisory_revised(self):
        r = certeu.parse_advisory(json.loads(fixture("certeu_2026-018.json")))
        self.assertEqual(r["id"], "2026-018")
        self.assertEqual(r["url"], "https://cert.europa.eu/publications/security-advisories/2026-018/")
        self.assertEqual(r["published"], "2026-10-20")              # v1.0 date from History
        self.assertEqual(r["updated"], "2026-10-23T14:36:26Z")      # publish_date is UTC
        self.assertEqual(r["extra"]["version"], "1.2")
        self.assertEqual(r["cves"], ["CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"])
        self.assertNotIn("<br>", r["extra"]["summary"])

    def test_advisory_first_version(self):
        r = certeu.parse_advisory(json.loads(fixture("certeu_2026-019.json")))
        self.assertEqual((r["published"], r["updated"]), ("2026-10-22T09:14:22Z", ""))
        self.assertEqual(r["cves"], ["CVE-2026-110264"])

    def test_revision_keeps_exact_v1_time(self):
        prev = {"published": "2026-10-20T08:00:00Z", "updated": ""}
        r = certeu.parse_advisory(json.loads(fixture("certeu_2026-018.json")), prev)
        self.assertEqual(r["published"], "2026-10-20T08:00:00Z")


class CertEuFetch(StateDir):
    START, END = utc(2026, 10, 21), utc(2026, 10, 28)

    def routes(self, **over):
        r = {
            certeu.RSS: fixture("certeu_rss.xml"),
            certeu.JSON.format(serial="2026-018"): fixture("certeu_2026-018.json"),
            certeu.JSON.format(serial="2026-019"): fixture("certeu_2026-019.json"),
        }
        r.update(over)
        return r

    def test_window_and_cache(self):
        fake = self.patch_get(certeu, self.routes())
        items = certeu.fetch(self.START, self.END)
        self.assertEqual([i.id for i in items], ["2026-018", "2026-019"])
        self.assertTrue(all(i.source == "CERT-EU" for i in items))
        # 2026-017 (15 Oct) is older than the window: its JSON is never requested.
        self.assertEqual(len(fake.calls), 3)
        fake.calls.clear()
        again = certeu.fetch(self.START, self.END)
        self.assertEqual([i.to_dict() for i in again], [i.to_dict() for i in items])
        self.assertEqual(fake.calls, [certeu.RSS])                  # run 2: cache hits only

    def test_json_failure_falls_back_to_rss_time(self):
        url = certeu.JSON.format(serial="2026-019")
        fake = self.patch_get(certeu, self.routes(**{url: SourceError("CERT-EU 2026-019 JSON: HTTP 503")}))
        items = {i.id: i for i in certeu.fetch(self.START, self.END)}
        self.assertEqual(items["2026-019"].published, "2026-10-22T09:14:22Z")
        self.assertEqual(items["2026-019"].cves, [])
        # A fallback record is not trusted as cached: the next run asks for the JSON again.
        fake.routes[url] = fixture("certeu_2026-019.json")
        fake.calls.clear()
        items = {i.id: i for i in certeu.fetch(self.START, self.END)}
        self.assertIn(url, fake.calls)
        self.assertEqual(items["2026-019"].cves, ["CVE-2026-110264"])

    def test_rss_failure_raises(self):
        self.patch_get(certeu, self.routes(**{certeu.RSS: SourceError("CERT-EU RSS: HTTP 403 (blocked or rate limited)")}))
        with self.assertRaisesRegex(SourceError, "CERT-EU RSS: HTTP 403"):
            certeu.fetch(self.START, self.END)

    def test_empty_rss_raises(self):
        self.patch_get(certeu, self.routes(**{certeu.RSS: b"<rss><channel></channel></rss>"}))
        with self.assertRaisesRegex(SourceError, "RSS has no advisory items"):
            certeu.fetch(self.START, self.END)


# ---------------------------------------------------------------- NCSC-NL

class NcscNlParse(unittest.TestCase):
    def test_changes(self):
        rows = ncscnl.parse_changes(fixture("ncscnl_changes.csv").decode() + '"index.txt","x"\n\n')
        self.assertEqual(len(rows), 12)
        self.assertEqual(rows[0], ("2026/ncsc-2026-0464.json", "2026-11-02T09:17:50.006979+00:00"))

    def test_cvss4_only_document(self):
        i = ncscnl.parse_csaf(json.loads(fixture("ncscnl_2026-0464.json")))
        self.assertEqual(i.id, "NCSC-2026-0464")
        self.assertEqual(i.url, "https://advisories.ncsc.nl/2026/ncsc-2026-0464.html")
        self.assertEqual(i.published, "2026-11-02T09:17:50Z")
        self.assertEqual(i.updated, "")
        self.assertEqual(i.cves, ["CVE-2026-112816"])
        self.assertEqual((i.score, i.severity), (0.0, ""))            # only a CVSS 4.0 vector note
        self.assertEqual(i.extra["probability"], "M")
        self.assertEqual(i.extra["impact"], "H")
        self.assertEqual(i.extra["products"], ["Canonical LXD", "Debian lxd"])
        self.assertEqual(i.extra["version"], "1.0.0")
        self.assertTrue(i.title.startswith("Kwetsbaarheid verholpen in LXD"))

    def test_cvss3_and_vendor_not_repeated(self):
        i = ncscnl.parse_csaf(json.loads(fixture("ncscnl_2026-0463.json")))
        self.assertEqual((i.score, i.severity), (8.6, "HIGH"))
        self.assertTrue(i.extra["products"])
        self.assertFalse(any(p.startswith("Cisco Cisco") for p in i.extra["products"]))

    def test_revision(self):
        i = ncscnl.parse_csaf(json.loads(fixture("ncscnl_2026-0455.json")))
        self.assertEqual(i.extra["version"], "1.0.1")
        self.assertEqual(i.published, "2026-10-27T08:05:01Z")
        self.assertEqual(i.updated, "2026-10-28T14:17:59Z")


class NcscNlFetch(StateDir):
    START, END = utc(2026, 11, 1), utc(2026, 11, 3)

    def routes(self):
        return {
            ncscnl.CHANGES: fixture("ncscnl_changes.csv"),
            ncscnl.BASE + "2026/ncsc-2026-0464.json": fixture("ncscnl_2026-0464.json"),
        }

    def test_window_cache_and_revision(self):
        fake = self.patch_get(ncscnl, self.routes())
        items = ncscnl.fetch(self.START, self.END)
        self.assertEqual([i.id for i in items], ["NCSC-2026-0464"])
        self.assertEqual(len(fake.calls), 2)
        fake.calls.clear()
        ncscnl.fetch(self.START, self.END)
        self.assertEqual(fake.calls, [ncscnl.CHANGES])               # run 2: cursor hit
        # A new revision time in changes.csv makes the document be fetched again.
        fake.routes[ncscnl.CHANGES] = fixture("ncscnl_changes.csv").replace(
            b"2026-11-02T09:17:50.006979", b"2026-11-02T15:00:00.000000")
        fake.calls.clear()
        ncscnl.fetch(self.START, self.END)
        self.assertEqual(len(fake.calls), 2)

    def test_document_failure_raises_and_keeps_progress(self):
        r = self.routes()
        r[ncscnl.BASE + "2026/ncsc-2026-0463.json"] = SourceError("NCSC-NL 2026/ncsc-2026-0463.json: HTTP 503")
        self.patch_get(ncscnl, r)
        with self.assertRaisesRegex(SourceError, "HTTP 503"):
            ncscnl.fetch(utc(2026, 10, 30, 14), self.END)
        self.assertIn("2026/ncsc-2026-0464.json", state.load_json(ncscnl.CURSOR, {}))

    def test_broken_document(self):
        r = self.routes()
        r[ncscnl.BASE + "2026/ncsc-2026-0464.json"] = b'{"document": {}}'
        self.patch_get(ncscnl, r)
        with self.assertRaisesRegex(SourceError, "not a readable CSAF document"):
            ncscnl.fetch(self.START, self.END)


# ---------------------------------------------------------------- CIRCL

class Circl(StateDir):
    def manifest(self):
        return json.loads(fixture("circl_manifest.json"))

    def test_timestamp_in_window(self):
        items = circl.parse_manifest(self.manifest(), utc(2026, 10, 27, 3), utc(2026, 11, 3, 3))
        self.assertEqual(len(items), 1)
        i = items[0]
        self.assertEqual(i.id, "ea593018-b2e9-4e7e-8da9-cc20a751e3f6")
        self.assertEqual(i.url, "https://www.circl.lu/doc/misp/feed-osint/ea593018-b2e9-4e7e-8da9-cc20a751e3f6.json")
        self.assertEqual(i.published, "2023-07-21")                  # date-only
        self.assertEqual(i.updated, "2026-10-31T00:11:56Z")
        self.assertEqual(i.extra["threat_level"], "High")
        self.assertEqual(i.extra["org"], "ESET")
        self.assertIn("tlp:white", i.extra["tags"])

    def test_date_in_window(self):
        items = circl.parse_manifest(self.manifest(), utc(2026, 8, 10), utc(2026, 8, 14))
        self.assertIn("6cb37027-b16f-4d80-aa77-a0dfd2dfe872", [i.id for i in items])

    def test_nothing_new_is_success(self):
        self.assertEqual(circl.parse_manifest(self.manifest(), utc(2030, 1, 1), utc(2030, 1, 8)), [])

    def test_bad_manifest(self):
        with self.assertRaisesRegex(SourceError, "manifest is empty or not a JSON object"):
            circl.parse_manifest([], utc(2026, 1, 1), utc(2026, 1, 8))
        self.patch_get(circl, {circl.MANIFEST: b"<html>502 Bad Gateway</html>"})
        with self.assertRaisesRegex(SourceError, "CIRCL OSINT: manifest is not valid JSON"):
            circl.fetch(utc(2026, 1, 1), utc(2026, 1, 8))


if __name__ == "__main__":
    unittest.main()
