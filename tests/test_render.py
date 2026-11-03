"""Tests for render.py and the page skeleton/CSS. Run from the repo root:

  python -m unittest discover -s tests -p "test_render.py" -v
"""

import os
import re
import sys
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import render  # noqa: E402
from feeds.common import Fatal, Item  # noqa: E402

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "render_items.json")


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


SKEL = read("page", "skeleton.html")
CSS = read("page", "style.css")

EVIL = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


def evil_item(**kw):
    d = dict(source=EVIL, id="CVE-2026-0001" + EVIL, url="javascript:alert(3)", title=EVIL,
             published="2026-11-03T02:31:19Z", updated="2026-11-03T03:00:00Z",
             cves=["CVE-2026-0002" + EVIL], score=9.8, severity="CRITICAL",
             extra={"vendor": EVIL, "product": EVIL, "due": "2026-11-01", "euvd_id": EVIL,
                    "sources": [EVIL], "version": EVIL, "products": [EVIL],
                    "probability": EVIL, "impact": "H", "ghsa": EVIL, "ecosystems": [EVIL],
                    "packages": [EVIL], "fixed": [EVIL], "npkg": 1, "score_source": EVIL,
                    "vector": EVIL, "vendors": [EVIL], "ssvc_exploitation": "active",
                    "assigner": EVIL, "nvd_score": 7.0, "threat_level": EVIL, "tags": [EVIL], "org": EVIL})
    d.update(kw)
    return Item(**d)


def assert_clean(tc, out):
    tc.assertNotIn("<script", out)
    tc.assertNotIn("<img", out)
    tc.assertNotIn("javascript:", out)
    tc.assertIn("&lt;script&gt;", out)


def first_row_cells(rows_html):
    first = re.match(r"<tr>(.*?)</tr>", rows_html, re.S).group(1)
    tds = re.findall(r"<td\b([^>]*)>", first)
    if len(tds) == 1:
        m = re.search(r'colspan="(\d+)"', tds[0])
        return int(m.group(1)) if m else 1
    return len(tds)


def thead_cols(tbody_id):
    m = re.search(r"<thead>((?:(?!<thead>).)*?)</thead>\s*<tbody id=\"%s\">" % re.escape(tbody_id), SKEL, re.S)
    return len(re.findall(r"<th\b", m.group(1)))


class SkeletonTest(unittest.TestCase):
    def test_every_anchor_exactly_once(self):
        for a in render.TBODY_IDS + render.TEXT_IDS + [render.STAMP_ID]:
            with self.subTest(anchor=a):
                self.assertEqual(SKEL.count(f'id="{a}"'), 1)
        for t in render.TBODY_IDS:
            with self.subTest(tbody=t):
                self.assertEqual(SKEL.count(f'<tbody id="{t}">'), 1)

    def test_plain_text_anchors_have_no_child_tags(self):
        for a in render.TEXT_IDS:
            with self.subTest(anchor=a):
                m = re.search(rf'<([a-zA-Z0-9]+)[^>]*\bid="{a}"[^>]*>(.*?)</\1>', SKEL, re.S)
                self.assertIsNotNone(m)
                self.assertNotIn("<", m.group(2))

    def test_refresh_bar_exact(self):
        self.assertIn('<div class="refresh"><div class="wrap"><div class="rstat" id="rstat">', SKEL)
        m = re.search(r'id="rstat">(.*?)</div></div></div>', SKEL, re.S)
        self.assertIsNotNone(m)
        self.assertNotIn("<div", m.group(1))

    def test_no_stripped_or_document_tags(self):
        for bad in ("<style", "<script", "<link", "<html", "<head", "<body", "style="):
            with self.subTest(tag=bad):
                self.assertNotIn(bad, SKEL.lower())

    def test_wrapper_and_balanced_divs(self):
        self.assertTrue(SKEL.lstrip().startswith('<div class="xw">'))
        self.assertEqual(SKEL.count("<div"), SKEL.count("</div>"))
        self.assertEqual(SKEL.count("<table"), SKEL.count("</table>"))

    def test_css_is_scoped(self):
        body = re.sub(r"/\*.*?\*/", "", CSS, flags=re.S)
        body = re.sub(r"@media[^{]*\{", "", body)
        for sel in re.findall(r"([^{}]+)\{", body):
            for part in sel.split(","):
                part = part.strip()
                if part:
                    with self.subTest(selector=part):
                        self.assertIn(".xw", part)
        self.assertNotIn("</style", CSS.lower())


class HelperTest(unittest.TestCase):
    def test_ftime(self):
        self.assertEqual(render.ftime("2026-11-03T02:31:19Z"), "3 Nov 02:31 UTC")
        self.assertEqual(render.ftime("2026-11-02T09:17:50.123456Z"), "2 Nov 09:17 UTC")
        self.assertEqual(render.ftime("2026-11-03T03:31:19+01:00"), "3 Nov 02:31 UTC")
        self.assertEqual(render.ftime("2026-11-03"), "3 Nov")
        self.assertEqual(render.ftime("2026-08-13T14:02:11Z", year=True), "13 Aug 2026 14:02 UTC")
        self.assertEqual(render.ftime(""), "&mdash;")
        self.assertEqual(render.ftime("<b>junk"), "&lt;b&gt;junk")

    def test_fdate(self):
        self.assertEqual(render.fdate("2026-10-16"), "16 Oct")
        self.assertEqual(render.fdate("2026-11-03T02:31:19Z"), "3 Nov")
        self.assertEqual(render.fdate(None), "&mdash;")

    def test_href_only_http(self):
        self.assertEqual(render.href("javascript:alert(1)"), "#")
        self.assertEqual(render.href("javascript:x", "https://a.example/?q=1&b=2"), "https://a.example/?q=1&amp;b=2")


class BuilderEscapeTest(unittest.TestCase):
    def test_health(self):
        out = render.build_health_rows([{"source": EVIL, "status": EVIL, "items": 1,
                                         "newest": EVIL, "last_success": "", "note": EVIL}])
        assert_clean(self, out)
        self.assertIn("hs-stale", out)  # unknown status renders as stale, label escaped

    def test_kev(self):
        assert_clean(self, render.build_kev_rows([evil_item()], "2026-11-03"))

    def test_adv(self):
        assert_clean(self, render.build_adv_rows([evil_item(cves=[EVIL] * 5)]))

    def test_dep(self):
        assert_clean(self, render.build_dep_rows([evil_item()]))
        assert_clean(self, render.build_dep_rows([evil_item(extra={"packages": [EVIL] * 5, "npkg": 5})]))

    def test_cve(self):
        out, shown, total = render.build_cve_rows([evil_item()])
        assert_clean(self, out)
        self.assertEqual((shown, total), (1, 1))

    def test_osint(self):
        assert_clean(self, render.build_osint_rows([evil_item()]))


class BuilderLogicTest(unittest.TestCase):
    def mk(self, i, score, sev="", ssvc="none", pub="2026-11-01T00:00:00Z"):
        return Item(source="CVE.org", id=f"CVE-2026-{i:06d}", url="", title="t", published=pub,
                    score=score, severity=sev, extra={"ssvc_exploitation": ssvc, "score_source": "CNA"})

    def test_cve_cap_and_order(self):
        items = [self.mk(i, 7.0 + (i % 30) / 10, "") for i in range(50)]
        out, shown, total = render.build_cve_rows(items, cap=7)
        self.assertEqual((shown, total), (7, 50))
        self.assertEqual(out.count("<tr>"), 7)
        scores = [float(s) for s in re.findall(r'class="score score-\w+">([\d.]+)<', out)]
        self.assertEqual(scores, sorted(scores, reverse=True))
        _, shown, total = render.build_cve_rows(items, cap=0)
        self.assertEqual((shown, total), (50, 50))

    def test_cve_filter(self):
        items = [self.mk(1, 5.4, "MEDIUM"), self.mk(2, 6.5, "MEDIUM", "active"),
                 self.mk(3, 9.8, "CRITICAL"), self.mk(4, 0, "", "active"), self.mk(5, 7.1)]
        out, shown, total = render.build_cve_rows(items)
        self.assertEqual(total, 4)
        self.assertNotIn("CVE-2026-000001", out)
        self.assertIn("SSVC: exploited", out)

    def test_cve_tie_breaks_newest_first(self):
        a = self.mk(1, 9.8, pub="2026-11-01T00:00:00Z")
        b = self.mk(2, 9.8, pub="2026-11-02T00:00:00Z")
        out, _, _ = render.build_cve_rows([a, b])
        self.assertLess(out.index("CVE-2026-000002"), out.index("CVE-2026-000001"))

    def test_kev_overdue(self):
        it = Item(source="CISA KEV", id="CVE-2026-1", url="", title="x", published="2026-10-28T17:02:45Z",
                  extra={"vendor": "V", "product": "P", "due": "2026-10-31"})
        out = render.build_kev_rows([it], "2026-11-03")
        self.assertIn('class="due past"', out)
        self.assertIn("overdue", out)
        self.assertNotIn("past", render.build_kev_rows([it], "2026-10-30"))

    def test_adv_cves_and_rating(self):
        it = Item(source="NCSC-NL", id="NCSC-2026-0464", url="https://advisories.ncsc.nl/x", title="t",
                  published="2026-11-02T09:17:50Z", updated="2026-11-02T10:00:00Z",
                  cves=[f"CVE-2026-{i}" for i in range(5)], score=8.7, severity="HIGH",
                  extra={"probability": "M", "impact": "H"})
        out = render.build_adv_rows([it])
        self.assertIn("+ 2 more CVEs", out)
        self.assertIn("P:M / I:H", out)
        self.assertIn("8.7", out)
        self.assertIn("updated 2 Nov 10:00 UTC", out)

    def test_empty_rows(self):
        self.assertIn('colspan="6" class="empty"', render.build_health_rows([]))
        self.assertIn('colspan="5" class="empty"', render.build_kev_rows([], "2026-11-03"))
        self.assertIn('colspan="6" class="empty"', render.build_adv_rows([]))
        self.assertIn('colspan="6" class="empty"', render.build_dep_rows([]))
        self.assertIn('colspan="4" class="empty"', render.build_cve_rows([])[0])
        self.assertIn('colspan="5" class="empty"', render.build_osint_rows([]))


class PageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = render.load_fixture(FIXTURE)
        cls.d = d
        cls.regions = render.build_regions(d["kev"], d["adv"], d["dep"], d["cve"], d["osint"], d["health"],
                                           d["start"], d["end"], d["now"], d["kev_catalog"])

    def test_column_counts_match_thead(self):
        for tid, rows in self.regions["tbody"].items():
            with self.subTest(tbody=tid):
                self.assertEqual(first_row_cells(rows), thead_cols(tid))
        empties = {"t-health": render.build_health_rows([]), "t-kev": render.build_kev_rows([], ""),
                   "t-adv": render.build_adv_rows([]), "t-dep": render.build_dep_rows([]),
                   "t-nvd": render.build_cve_rows([])[0], "t-osint": render.build_osint_rows([])}
        for tid, rows in empties.items():
            with self.subTest(empty=tid):
                self.assertEqual(first_row_cells(rows), thead_cols(tid))

    def test_text_regions_have_no_tags(self):
        for k, v in self.regions["text"].items():
            with self.subTest(anchor=k):
                self.assertNotIn("<", v)
        self.assertNotIn("<div", self.regions["stamp"])
        self.assertIn("<b>", self.regions["stamp"])

    def test_counts(self):
        t = self.regions["text"]
        self.assertEqual(t["s-kev"], "3")
        self.assertEqual(t["s-crit"], "2")
        self.assertEqual(t["s-high"], "1")
        self.assertEqual(t["n-nvd"], "4 CVEs")
        self.assertEqual(t["n-cvecap"], "All 4 shown.")
        self.assertEqual(t["n-kev"], "3 entries &middot; 1 past deadline")
        self.assertEqual(t["winlabel"], "27 Oct 02:45 &rarr; 3 Nov 02:45 UTC")

    def test_apply_is_idempotent_and_fills(self):
        once = render.apply_regions(SKEL, self.regions)
        twice = render.apply_regions(once, self.regions)
        self.assertEqual(once, twice)
        self.assertNotIn("Not generated yet.", once)
        self.assertIn("CVE-2026-111464", once)
        self.assertIn("NCSC-2026-0464", once)
        self.assertEqual(once.count("<div"), once.count("</div>"))

    def test_missing_anchor_is_fatal(self):
        with self.assertRaises(Fatal):
            render.apply_regions(SKEL.replace('id="t-osint"', 'id="t-gone"'), self.regions)
        with self.assertRaises(Fatal):
            render.apply_regions(SKEL.replace('id="n-cvecap"', ""), self.regions)

    def test_demo_renders(self):
        out = render.render_demo(FIXTURE)
        self.assertTrue(out.startswith("<!doctype html>"))
        self.assertIn("<style>", out)
        self.assertIn("CVE-2026-111464", out)


if __name__ == "__main__":
    unittest.main()
