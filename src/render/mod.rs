//! HTML builders for the Cyber Threat Exploit Watch page.
//!
//! Pure functions: slices of Item in, HTML strings out. No network and no file
//! I/O, except demo().
//!
//! Every builder emits only the class names styled by stack/wiki/page/style.css (the page's
//! scriptCss) and no inline style attributes, because the Wiki.js sanitiser
//! mangles long ones (README.md, Known limitations). The row vocabulary (td.id, sv sv-*, tgt, sub,
//! desc, due/due past, pkg, eco, fix, score, vecbits, empty) is the one of the
//! original page's row builders; feed, hs-*, ssrc, ssvc-*, pi-*, tl-*, tag are
//! the additions for the tables the original did not have.
//!
//! Times: every timestamp on the page is UTC and carries the "UTC" label.
//! Date-only source values (e.g. CISA dueDate) are shown as a date with no time.
//!
//! Anchors filled on the page (see stack/wiki/page/skeleton.html):
//!   tbody  t-health t-kev t-adv t-dep t-nvd t-osint
//!   text   s-kev s-crit s-high s-dep s-adv s-osint
//!          n-health n-kev n-adv n-dep n-nvd n-cvecap n-osint winlabel
//!   stamp  rstat   (inner HTML, contains <b>; must never contain a <div>)
//!
//! Item.extra values are read through Item::x / x_list / x_num, so a value of
//! another type than the one feeds/common.rs lists for its key counts as missing.
//!
//! Modules: fmt (dates, escaping, small HTML helpers), tables (one builder per
//! table body), demo (the standalone preview page).
//!
//! Preview:
//!   exploit-watch demo state/preview.html [--dark]

mod demo;
mod fmt;
mod tables;

use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::feeds::common::{Fatal, Item};

pub use demo::{DemoArgs, demo};
pub use fmt::{esc, ftime, plural, thousands};
use fmt::{day, hm};
use tables::{
    build_adv_rows, build_cve_rows, build_dep_rows, build_health_rows, build_kev_rows, build_osint_rows, cve_keep,
    health_summary, kev_overdue, sev,
};

pub const TBODY_IDS: [&str; 6] = ["t-health", "t-kev", "t-adv", "t-dep", "t-nvd", "t-osint"];
pub const TEXT_IDS: [&str; 14] = [
    "s-kev", "s-crit", "s-high", "s-dep", "s-adv", "s-osint",
    "n-health", "n-kev", "n-adv", "n-dep", "n-nvd", "n-cvecap", "n-osint", "winlabel",
];
pub const STAMP_ID: &str = "rstat";

/// Page content and scriptCss, relative to the repo root (the job and demo run from there).
pub const SKELETON_PATH: &str = "stack/wiki/page/skeleton.html";
pub const STYLE_PATH: &str = "stack/wiki/page/style.css";

/// One row of the feed health table, built by run.rs.
/// status: "ok" | "not-modified" | "cached" | "stale" | "error" (anything else renders as stale)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthRow {
    pub source: String,
    pub status: String,
    pub items: usize,
    pub newest: String,
    pub last_success: String,
    pub note: String,
}

/// Everything the job writes, in a fixed order (tbody ids, then text ids, then rstat).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Regions {
    pub tbody: Vec<(String, String)>,
    pub text: Vec<(String, String)>,
    pub stamp: String,
}

impl Regions {
    /// The value of a tbody or text region by anchor id ("" when absent).
    pub fn get(&self, id: &str) -> &str {
        if id == STAMP_ID {
            return &self.stamp;
        }
        self.tbody.iter().chain(self.text.iter()).find(|(k, _)| k == id).map(|(_, v)| v.as_str()).unwrap_or("")
    }
}

// ---------------------------------------------------------------- whole page

/// Inner HTML of <div id="rstat">. Contains <b>; never a <div>.
pub fn build_stamp(now: DateTime<Utc>, kev_catalog: &str, health: &[HealthRow]) -> String {
    let mut s = format!("Generated <b>{}, {} UTC</b>", day(&now, true), hm(&now));
    if !kev_catalog.is_empty() {
        s.push_str(&format!(" &nbsp;&middot;&nbsp; CISA KEV catalog <b>{}</b>", esc(kev_catalog)));
    }
    if !health.is_empty() {
        s.push_str(&format!(" &nbsp;&middot;&nbsp; feeds: {}", health_summary(health)));
    }
    s.push_str(
        " &nbsp;&middot;&nbsp; this wiki strips JavaScript from page content, so the brief is \
         rebuilt by a scheduled job rather than by a button.",
    );
    s
}

/// Everything the job writes. start/end/now are UTC. cap 0 means no CVE row cap.
#[allow(clippy::too_many_arguments)]
pub fn build_regions(
    kev: &[Item], adv: &[Item], dep: &[Item], cve: &[Item], osint: &[Item], health: &[HealthRow],
    start: DateTime<Utc>, end: DateTime<Utc>, now: DateTime<Utc>, kev_catalog: &str, cap: usize,
) -> Regions {
    let today = end.format("%Y-%m-%d").to_string();
    let (cve_html, shown, total) = build_cve_rows(cve, cap);
    let kept = cve_keep(cve);
    let n_crit = kept.iter().filter(|it| sev(it) == "CRITICAL").count();
    let n_high = kept.iter().filter(|it| sev(it) == "HIGH").count();
    let overdue = kev_overdue(kev, &today);

    let tbody = [
        build_health_rows(health),
        build_kev_rows(kev, &today),
        build_adv_rows(adv),
        build_dep_rows(dep),
        cve_html,
        build_osint_rows(osint),
    ];
    let mut n_kev = plural(kev.len(), "entry", Some("entries"));
    if overdue > 0 {
        n_kev.push_str(&format!(" &middot; {overdue} past deadline"));
    }
    let text = [
        thousands(kev.len()),
        thousands(n_crit),
        thousands(n_high),
        thousands(dep.len()),
        thousands(adv.len()),
        thousands(osint.len()),
        health_summary(health),
        n_kev,
        plural(adv.len(), "advisory", Some("advisories")),
        plural(dep.len(), "advisory", Some("advisories")),
        plural(total, "CVE", None),
        if shown < total {
            format!("Showing {} of {}, highest score first.", thousands(shown), thousands(total))
        } else {
            format!("All {} shown.", thousands(total))
        },
        plural(osint.len(), "event", None),
        format!("{} {} &rarr; {} {} UTC", day(&start, false), hm(&start), day(&end, false), hm(&end)),
    ];
    Regions {
        tbody: TBODY_IDS.iter().map(|s| s.to_string()).zip(tbody).collect(),
        text: TEXT_IDS.iter().map(|s| s.to_string()).zip(text).collect(),
        stamp: build_stamp(now, kev_catalog, health),
    }
}

static TAG_OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^<([a-zA-Z0-9]+)[^>]*>").unwrap());

/// The first element whose opening tag carries id="EID", up to the first closing
/// tag of the same name. TAG is "div" when div_only, else any `[a-zA-Z0-9]+`.
/// Same match as `(<(TAG)[^>]*\bid="EID"[^>]*>)(.*?)(</\2>)` (dot matches newline);
/// the regex crate has no backreference, so this walks that search order by hand:
/// leftmost '<', then the longest tag name first.
/// -> (start, end of the opening tag, start of the closing tag, end of the match).
fn find_element(doc: &str, eid: &str, div_only: bool) -> Option<(usize, usize, usize, usize)> {
    let id_attr = format!("id=\"{eid}\"");
    for (p, _) in doc.match_indices('<') {
        let Some(m) = TAG_OPEN.captures(&doc[p..]) else { continue };
        let open = m.get(0).unwrap();
        let name = m.get(1).unwrap().as_str();
        let tag_text = open.as_str();
        // \bid="EID" somewhere after the name, inside this tag.
        let has_id = tag_text.match_indices(&id_attr).any(|(i, _)| {
            i > name.len() && !tag_text[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_')
        });
        if !has_id {
            continue;
        }
        let open_end = p + open.end();
        let names: Vec<&str> = if div_only {
            if name.starts_with("div") { vec!["div"] } else { vec![] }
        } else {
            (1..=name.len()).rev().map(|l| &name[..l]).collect()
        };
        for tag in names {
            let close = format!("</{tag}>");
            if let Some(i) = doc[open_end..].find(&close) {
                let cs = open_end + i;
                return Some((p, open_end, cs, cs + close.len()));
            }
        }
    }
    None
}

/// Splice regions into the page HTML. Err names the first missing anchor. Idempotent.
pub fn apply_regions(doc: &str, regions: &Regions) -> Result<String, Fatal> {
    let mut doc = doc.to_string();
    for (tid, rows) in &regions.tbody {
        let open = format!("<tbody id=\"{tid}\">");
        let found = doc.find(&open).and_then(|s| {
            let body = s + open.len();
            doc[body..].find("</tbody>").map(|i| (body, body + i))
        });
        let Some((a, b)) = found else {
            return Err(Fatal(format!("page anchor <tbody id=\"{tid}\"> not found — re-seed the page skeleton")));
        };
        doc.replace_range(a..b, rows);
    }
    let stamp = (STAMP_ID.to_string(), regions.stamp.clone());
    for (eid, text) in regions.text.iter().chain(std::iter::once(&stamp)) {
        let Some((_, open_end, close_start, _)) = find_element(&doc, eid, eid == STAMP_ID) else {
            return Err(Fatal(format!("page anchor id=\"{eid}\" not found — re-seed the page skeleton")));
        };
        doc.replace_range(open_end..close_start, text);
    }
    Ok(doc)
}

// ---------------------------------------------------------------- tests

/// Inputs shared by the tests of the render modules.
#[cfg(test)]
mod test_support {
    use std::path::{Path, PathBuf};

    use regex::Regex;
    use serde_json::json;

    use crate::feeds::common::Item;

    pub const ROOT: &str = env!("CARGO_MANIFEST_DIR");
    pub const EVIL: &str = r#"<script>alert(1)</script>"><img src=x onerror=alert(2)>"#;

    pub fn read(rel: &str) -> String {
        super::demo::read_text(&Path::new(ROOT).join(rel)).unwrap()
    }

    pub fn fixture_path() -> PathBuf {
        Path::new(ROOT).join("tests/fixtures/render_items.json")
    }

    pub fn re(p: &str) -> Regex {
        Regex::new(p).unwrap()
    }

    pub fn evil_item() -> Item {
        let mut it = Item::new(EVIL, &format!("CVE-2026-0001{EVIL}"), "javascript:alert(3)", EVIL, "2026-11-03T02:31:19Z");
        it.updated = "2026-11-03T03:00:00Z".into();
        it.cves = vec![format!("CVE-2026-0002{EVIL}")];
        it.score = 9.8;
        it.severity = "CRITICAL".into();
        it.extra = json!({"vendor": EVIL, "product": EVIL, "due": "2026-11-01", "euvd_id": EVIL,
            "sources": [EVIL], "version": EVIL, "products": [EVIL],
            "probability": EVIL, "impact": "H", "ghsa": EVIL, "ecosystems": [EVIL],
            "packages": [EVIL], "fixed": [EVIL], "npkg": 1, "score_source": EVIL,
            "vector": EVIL, "vendors": [EVIL], "ssvc_exploitation": "active",
            "assigner": EVIL, "nvd_score": 7.0, "threat_level": EVIL, "tags": [EVIL], "org": EVIL})
        .as_object()
        .unwrap()
        .clone();
        it
    }

    pub fn assert_clean(out: &str) {
        assert!(!out.contains("<script"), "{out}");
        assert!(!out.contains("<img"), "{out}");
        assert!(!out.contains("javascript:"), "{out}");
        assert!(out.contains("&lt;script&gt;"), "{out}");
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{evil_item, fixture_path, re, read};
    use super::*;

    fn skel() -> String {
        read(SKELETON_PATH)
    }

    fn first_row_cells(rows: &str) -> usize {
        let first = re(r"(?s)^<tr>(.*?)</tr>").captures(rows).unwrap()[1].to_string();
        let tds: Vec<String> = re(r"<td\b([^>]*)>").captures_iter(&first).map(|c| c[1].to_string()).collect();
        if tds.len() == 1 {
            return re(r#"colspan="(\d+)""#).captures(&tds[0]).map_or(1, |m| m[1].parse().unwrap());
        }
        tds.len()
    }

    /// Number of <th> in the <thead> right before <tbody id="tid">.
    fn thead_cols(tid: &str) -> usize {
        let s = skel();
        let t = s.find(&format!("<tbody id=\"{tid}\">")).unwrap();
        let before = s[..t].trim_end();
        let close = before.strip_suffix("</thead>").map(str::len).unwrap();
        let open = before[..close].rfind("<thead>").unwrap() + "<thead>".len();
        re(r"<th\b").find_iter(&before[open..close]).count()
    }

    /// Regions of the demo fixture.
    fn load() -> Regions {
        demo::load_fixture(&fixture_path()).unwrap().regions()
    }

    fn all_anchors() -> Vec<&'static str> {
        TBODY_IDS.iter().chain(TEXT_IDS.iter()).copied().chain([STAMP_ID]).collect()
    }

    // ------------------------------------------------ skeleton

    #[test]
    fn every_anchor_exactly_once() {
        let s = skel();
        for a in all_anchors() {
            assert_eq!(s.matches(&format!("id=\"{a}\"")).count(), 1, "{a}");
        }
        for t in TBODY_IDS {
            assert_eq!(s.matches(&format!("<tbody id=\"{t}\">")).count(), 1, "{t}");
        }
    }

    #[test]
    fn plain_text_anchors_have_no_child_tags() {
        let s = skel();
        for a in TEXT_IDS {
            let (_, open_end, close_start, _) = find_element(&s, a, false).unwrap_or_else(|| panic!("{a}"));
            assert!(!s[open_end..close_start].contains('<'), "{a}");
        }
    }

    #[test]
    fn refresh_bar_exact() {
        let s = skel();
        assert!(s.contains(r#"<div class="refresh"><div class="wrap"><div class="rstat" id="rstat">"#));
        let m = re(r#"(?s)id="rstat">(.*?)</div></div></div>"#).captures(&s).expect("rstat");
        assert!(!m[1].contains("<div"));
    }

    #[test]
    fn no_stripped_or_document_tags() {
        let s = skel().to_lowercase();
        // \b so that the page's own <header> is not taken for <head>.
        for bad in [r"<style\b", r"<script\b", r"<link\b", r"<html\b", r"<head\b", r"<body\b", r"\bstyle="] {
            assert!(!re(bad).is_match(&s), "{bad}");
        }
    }

    #[test]
    fn wrapper_and_balanced_divs() {
        let s = skel();
        assert!(s.trim_start().starts_with(r#"<div id="ew">"#));
        assert_eq!(s.matches("<div").count(), s.matches("</div>").count());
        assert_eq!(s.matches("<table").count(), s.matches("</table>").count());
    }

    #[test]
    fn css_is_scoped() {
        let css = read(STYLE_PATH);
        let body = re(r"(?s)/\*.*?\*/").replace_all(&css, "").to_string();
        let body = re(r"@import[^;]*;").replace_all(&body, "").to_string();
        let body = re(r"@media[^{]*\{").replace_all(&body, "").to_string();
        for m in re(r"([^{}]+)\{").captures_iter(&body) {
            for part in m[1].split(',') {
                let part = part.trim();
                if !part.is_empty() {
                    assert!(part.contains("#ew"), "{part}");
                }
            }
        }
        assert!(!css.to_lowercase().contains("</style"));
        // Only the font import may sit outside a rule, and it must come first.
        assert_eq!(css.matches("@import").count(), 1);
        assert!(css.starts_with("@import url(https://fonts.googleapis.com/"));
    }

    // ------------------------------------------------ whole page

    #[test]
    fn column_counts_match_thead() {
        let r = load();
        for (tid, rows) in &r.tbody {
            assert_eq!(first_row_cells(rows), thead_cols(tid), "{tid}");
        }
        let empties = [
            ("t-health", build_health_rows(&[])), ("t-kev", build_kev_rows(&[], "")),
            ("t-adv", build_adv_rows(&[])), ("t-dep", build_dep_rows(&[])),
            ("t-nvd", build_cve_rows(&[], 300).0), ("t-osint", build_osint_rows(&[])),
        ];
        for (tid, rows) in empties {
            assert_eq!(first_row_cells(&rows), thead_cols(tid), "empty {tid}");
        }
    }

    #[test]
    fn text_regions_have_no_tags() {
        let r = load();
        for (k, v) in &r.text {
            assert!(!v.contains('<'), "{k}");
        }
        assert!(!r.stamp.contains("<div"));
        assert!(r.stamp.contains("<b>"));
    }

    #[test]
    fn counts() {
        let r = load();
        assert_eq!(r.get("s-kev"), "3");
        assert_eq!(r.get("s-crit"), "2");
        assert_eq!(r.get("s-high"), "1");
        assert_eq!(r.get("n-nvd"), "4 CVEs");
        assert_eq!(r.get("n-cvecap"), "All 4 shown.");
        assert_eq!(r.get("n-kev"), "3 entries &middot; 1 past deadline");
        assert_eq!(r.get("winlabel"), "27 Oct 02:45 &rarr; 3 Nov 02:45 UTC");
    }

    #[test]
    fn apply_is_idempotent_and_fills() {
        let r = load();
        let once = apply_regions(&skel(), &r).unwrap();
        let twice = apply_regions(&once, &r).unwrap();
        assert_eq!(once, twice);
        assert!(!once.contains("Not generated yet."));
        assert!(once.contains("CVE-2026-111464"));
        assert!(once.contains("NCSC-2026-0464"));
        assert_eq!(once.matches("<div").count(), once.matches("</div>").count());
        assert!(!once.contains("style="));
    }

    /// Every class on the filled page has a rule in style.css, except modifiers
    /// that deliberately fall back to their base class's look.
    #[test]
    fn every_class_is_styled() {
        let r = load();
        let page = apply_regions(&skel(), &r).unwrap();
        let mut evil = String::new();
        evil.push_str(&build_cve_rows(&[evil_item()], 300).0);
        evil.push_str(&build_osint_rows(&[evil_item()]));
        let css = read(STYLE_PATH);
        let fallback = ["sm", "score-other", "pi-L", "pi-X", "tl-low", "tl-undefined", "tags", "sv-MEDIUM", "sv-LOW"];
        for c in re(r#"class="([^"]*)""#).captures_iter(&(page + &evil)) {
            for cls in c[1].split_whitespace() {
                if fallback.contains(&cls) || c[1].contains('&') {
                    continue;
                }
                assert!(re(&format!(r"\.{}\b", regex::escape(cls))).is_match(&css), "no rule for .{cls}");
            }
        }
    }

    #[test]
    fn missing_anchor_is_fatal() {
        let r = load();
        assert!(apply_regions(&skel().replace(r#"id="t-osint""#, r#"id="t-gone""#), &r).is_err());
        assert!(apply_regions(&skel().replace(r#"id="n-cvecap""#, ""), &r).is_err());
    }
}
