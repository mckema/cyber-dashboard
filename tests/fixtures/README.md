# Test fixtures

Payloads for the unit tests and `exploit-watch demo`. "Excerpt" means records copied from the public feed and trimmed (fewer entries or fields, long texts cut, marked `[trimmed]` where a text was cut); "synthetic" means written for the tests, with ids and dates that only look real. The licence column applies to the excerpted records; synthetic data carries none.

| File | Source (feed / API) | Licence / terms | Content |
|---|---|---|---|
| `kev_catalog.json` | CISA Known Exploited Vulnerabilities catalog (cisagov/kev-data) | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) | Excerpt: 3 catalog entries with the catalog header (`count` set to 3) |
| `euvd_search.json` | ENISA EUVD search API | Reproduction authorised, source acknowledged (ENISA) | Excerpt: one search page |
| `euvd_search_exploited.json` | ENISA EUVD search API (exploited) | Reproduction authorised, source acknowledged (ENISA) | Excerpt: one search page |
| `cvelist_delta_prefix.bin` | CVE.org cvelistV5 `cves/deltaLog.json` | [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse); © 1999-2026, The MITRE Corporation | Excerpt: the first 3,000 bytes, cut mid-record on purpose (tests the prefix read) |
| `cve_record_cna.json` | CVE.org cvelistV5 record (CNA scores) | [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse); © 1999-2026, The MITRE Corporation | Excerpt: one CVE record |
| `cve_record_adp.json` | CVE.org cvelistV5 record (CISA-ADP scores and SSVC) | [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse); © 1999-2026, The MITRE Corporation | Excerpt: one CVE record |
| `nvd_page.json` | NVD CVE API 2.0 | [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use); this product uses the NVD API but is not endorsed or certified by the NVD | Mixed: the first CVE is an edited excerpt (description shortened, a second-language entry added); the other two (`cna@example.org`) are synthetic |
| `github_advisories.json` | GitHub Advisory Database REST API (`/advisories`) | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), [github.com/advisories](https://github.com/advisories) | Mixed: the first advisory is an edited excerpt (line break in the summary, a repeated package range); `GHSA-aaaa-bbbb-cccc` is synthetic |
| `certeu_rss.xml` | CERT-EU security advisories RSS | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), credit CERT-EU ([legal notice](https://cert.europa.eu/legal-notice)) | Excerpt: the feed with three items |
| `certeu_2026-018.json`, `certeu_2026-019.json` | CERT-EU advisory JSON | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), credit CERT-EU ([legal notice](https://cert.europa.eu/legal-notice)) | Excerpt: one advisory each |
| `ncscnl_changes.csv` | NCSC-NL CSAF `changes.csv` | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) | Excerpt: the first lines of the change list |
| `ncscnl_2026-0455.json`, `ncscnl_2026-0463.json`, `ncscnl_2026-0464.json` | NCSC-NL CSAF 2.0 advisories | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) | Excerpt: one advisory each, legal disclaimer cut (`[trimmed]`) |
| `render_items.json` | This job's merged items (input of `exploit-watch demo` and the render tests) | — | Synthetic: illustrative rows, not a feed snapshot (see its `_comment`) |
| `report_events.jsonl`, `report_runs.jsonl` | This job's event log and run log (input of the report tests) | — | Synthetic: invented items, tickets and runs; the last event line is half-written on purpose |
| `linear_*.json` | Linear GraphQL API | — | Linear API response shapes, synthetic data |

Feed terms and the attribution text shown to readers: the "Sources and licences" block in `page/skeleton.html` (page footer) and in the appendix of `src/report/report.typ`.
