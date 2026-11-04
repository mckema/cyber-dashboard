//! Row builders, one per table body on the page, plus the counts derived from them.

use std::cmp::{Ordering, Reverse};
use std::sync::LazyLock;

use regex::Regex;

use super::{HealthRow, TicketRow, TriageRow};
use super::fmt::{
    cve_link, empty, esc, f1, fdate, feed_pill, ftime, fwhen, href, link, more, or_mdash, plural, sev_pill, thousands,
    when_key,
};
use crate::feeds::common::{Item, severity_for};

const DESC_MAX: usize = 300;

/// Upper-case severity, or the band of the score when the source gave none.
pub(super) fn sev(it: &Item) -> String {
    let s = it.severity.to_uppercase();
    if s.is_empty() { severity_for(it.score).to_string() } else { s }
}

/// Text cut to DESC_MAX characters, with an ellipsis when cut (not escaped).
fn clip(s: &str) -> String {
    if s.chars().count() > DESC_MAX {
        let head: String = s.chars().take(DESC_MAX).collect();
        format!("{}…", head.trim_end())
    } else {
        s.to_string()
    }
}

/// Descending order of two scores.
fn by_score_desc(a: f64, b: f64) -> Ordering {
    b.partial_cmp(&a).unwrap_or(Ordering::Equal)
}

fn by_newest(items: &[Item]) -> Vec<&Item> {
    let mut v: Vec<&Item> = items.iter().collect();
    v.sort_by_cached_key(|it| Reverse(when_key(&it.published)));
    v
}

// ---------------------------------------------------------------- feed health

fn health_class(status: &str) -> Option<(&'static str, &'static str)> {
    match status {
        "ok" => Some(("ok", "OK")),
        "not-modified" => Some(("ok", "Not modified")),
        "cached" => Some(("cached", "Cached")),
        "stale" => Some(("stale", "Stale")),
        "error" => Some(("error", "Error")),
        _ => None,
    }
}

/// 6 columns: source, status, items, newest, last success, note.
pub fn build_health_rows(health: &[HealthRow]) -> String {
    if health.is_empty() {
        return empty(6, "No feed has reported yet.");
    }
    let mut out = String::new();
    for h in health {
        let (cls, label) = health_class(&h.status)
            .unwrap_or(("stale", if h.status.is_empty() { "Unknown" } else { h.status.as_str() }));
        out.push_str(&format!(
            concat!(
                r#"<tr><td>{}</td>"#,
                r#"<td><span class="hs hs-{}">{}</span></td>"#,
                r#"<td class="num">{}</td>"#,
                r#"<td class="due">{}</td>"#,
                r#"<td class="due">{}</td>"#,
                r#"<td class="desc">{}</td></tr>"#,
            ),
            feed_pill(&h.source),
            cls,
            esc(label),
            thousands(h.items),
            fwhen(&h.newest, true),
            fwhen(&h.last_success, true),
            esc(&h.note),
        ));
    }
    out
}

/// Plain text for n-health, e.g. '7 feeds &middot; 5 ok &middot; 1 cached &middot; 1 error'.
pub fn health_summary(health: &[HealthRow]) -> String {
    let mut parts = vec![plural(health.len(), "feed", None)];
    for cls in ["ok", "cached", "stale", "error"] {
        let n = health.iter().filter(|h| health_class(&h.status).map_or("stale", |c| c.0) == cls).count();
        if n > 0 {
            parts.push(format!("{n} {cls}"));
        }
    }
    parts.join(" &middot; ")
}

// ---------------------------------------------------------------- exploited (KEV + EUVD)

/// CISA KEV and ENISA EUVD exploited items, merged by CVE upstream. 5 columns.
/// today: "YYYY-MM-DD" (UTC) used for the overdue flag.
pub fn build_kev_rows(items: &[Item], today: &str) -> String {
    if items.is_empty() {
        return empty(5, "No new entries this window.");
    }
    let mut out = String::new();
    for it in by_newest(items) {
        let due = it.x("due");
        let past = !due.is_empty() && due < today;
        let mut srcs = it.x_list("sources");
        if srcs.is_empty() {
            srcs.push(&it.source);
        }
        let euvd = it.x("euvd_id");
        let (vendor, product) = (it.x("vendor"), it.x("product"));
        let since = it.x("exploited_since");
        let mut since_html = String::new();
        if !since.is_empty() && fdate(since, false) != fdate(&it.published, false) {
            since_html = format!(r#"<span class="sub">exploited since {}</span>"#, fdate(since, false));
        }
        let url = if it.url.is_empty() { cve_link(&it.id) } else { it.url.clone() };
        out.push_str(&format!(
            r#"<tr><td class="id">{}<span class="sv sv-EXPLOITED">Exploited</span><span class="feeds">{}</span>"#,
            link(&url, &it.id, ""),
            srcs.iter().map(|s| feed_pill(s)).collect::<String>(),
        ));
        if !euvd.is_empty() {
            out.push_str(&format!(r#"<span class="sub mono">{}</span>"#, esc(euvd)));
        }
        out.push_str("</td>");
        if !vendor.is_empty() || !product.is_empty() {
            out.push_str(&format!(
                r#"<td><span class="tgt">{}</span><span class="sub">{}</span></td>"#,
                esc(vendor),
                esc(product)
            ));
        } else {
            out.push_str("<td>&mdash;</td>");
        }
        out.push_str(&format!(
            r#"<td class="desc">{}</td><td class="due">{}{}</td><td class="due{}">{}"#,
            esc(&it.title),
            fwhen(&it.published, false),
            since_html,
            if past { " past" } else { "" },
            fdate(due, false),
        ));
        if past {
            out.push_str(r#"<span class="sub">overdue</span>"#);
        }
        out.push_str("</td></tr>");
    }
    out
}

/// Exploited items whose CISA due date is before today.
pub fn kev_overdue(items: &[Item], today: &str) -> usize {
    items.iter().filter(|it| !it.x("due").is_empty() && it.x("due") < today).count()
}

// ---------------------------------------------------------------- EU / national advisories

fn rating(it: &Item) -> String {
    let mut parts = String::new();
    if it.score != 0.0 {
        let s = sev(it);
        let cls = match s.as_str() {
            "CRITICAL" => "crit",
            "HIGH" => "high",
            _ => "other",
        };
        parts.push_str(&format!(r#"<span class="score sm score-{cls}">{}</span>{}"#, f1(it.score), sev_pill(&s)));
    } else if !it.severity.is_empty() {
        parts.push_str(&sev_pill(&it.severity.to_uppercase()));
    }
    let (p, i) = (it.x("probability").to_uppercase(), it.x("impact").to_uppercase());
    if !p.is_empty() || !i.is_empty() {
        parts.push_str(&format!(
            r#"<span class="pi pi-{}" title="probability / impact (NCSC-NL)">P:{} / I:{}</span>"#,
            esc(if i.is_empty() { "X" } else { &i }),
            esc(if p.is_empty() { "?" } else { &p }),
            esc(if i.is_empty() { "?" } else { &i }),
        ));
    }
    or_mdash(parts)
}

/// CERT-EU and NCSC-NL advisories. 5 columns (the source label sits under the id).
pub fn build_adv_rows(items: &[Item]) -> String {
    if items.is_empty() {
        return empty(5, "No new advisories this window.");
    }
    let mut out = String::new();
    for it in by_newest(items) {
        let ver = it.x("version");
        let mut upd = String::new();
        if !it.updated.is_empty() && it.updated != it.published {
            upd = format!(r#"<span class="sub">updated {}</span>"#, ftime(&it.updated, false));
        }
        let products = it.x_list("products");
        let prod = if products.is_empty() {
            String::new()
        } else {
            let extra = if products.len() > 3 { format!(" + {} more", products.len() - 3) } else { String::new() };
            format!(r#"<span class="sub">{}{extra}</span>"#, esc(&products[..products.len().min(3)].join(", ")))
        };
        let cves = or_mdash(more(&it.cves, 3, |c| link(&cve_link(c), c, "mono"), "CVE"));
        out.push_str(&format!(
            r#"<tr><td class="id">{}<span class="feeds">{}</span>"#,
            link(&it.url, &it.id, ""),
            feed_pill(&it.source),
        ));
        if !ver.is_empty() {
            out.push_str(&format!(r#"<span class="sub">version {}</span>"#, esc(ver)));
        }
        out.push_str(&format!(
            concat!(
                r#"</td>"#,
                r#"<td class="due">{}{}</td>"#,
                r#"<td class="desc">{}{}</td>"#,
                r#"<td class="cves">{}</td>"#,
                r#"<td class="rate">{}</td></tr>"#,
            ),
            fwhen(&it.published, false),
            upd,
            link(&it.url, &it.title, "ttl"),
            prod,
            cves,
            rating(it),
        ));
    }
    out
}

// ---------------------------------------------------------------- GitHub (packages)

/// GitHub reviewed advisories: critical first, then score desc, then id. 6 columns.
pub fn build_dep_rows(items: &[Item]) -> String {
    if items.is_empty() {
        return empty(6, "No reviewed advisories this window.");
    }
    let mut v: Vec<(&Item, String)> = items.iter().map(|it| (it, sev(it))).collect();
    v.sort_by(|(a, sa), (b, sb)| {
        (sa != "CRITICAL")
            .cmp(&(sb != "CRITICAL"))
            .then(by_score_desc(a.score, b.score))
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut out = String::new();
    for (it, sev) in v {
        let pkgs = it.x_list("packages");
        let npkg = match it.x_num("npkg") {
            Some(n) if n >= 1.0 => n as usize,
            _ => pkgs.len(),
        };
        let pkg = if npkg > 3 && !pkgs.is_empty() {
            format!(r#"<span class="pkg">{}</span><span class="sub">+ {} more packages</span>"#, esc(pkgs[0]), npkg - 1)
        } else if !pkgs.is_empty() {
            format!(r#"<span class="pkg">{}</span>"#, pkgs.iter().map(|p| esc(p)).collect::<Vec<_>>().join("<br>"))
        } else {
            "&mdash;".into()
        };
        let ghsa = it.x("ghsa");
        let fallback = if !ghsa.is_empty() {
            format!("https://github.com/advisories/{ghsa}")
        } else if it.id.starts_with("CVE-") {
            cve_link(&it.id)
        } else {
            String::new()
        };
        let ecos = or_mdash(it.x_list("ecosystems").iter().map(|e| format!(r#"<span class="eco">{}</span>"#, esc(e))).collect());
        let fixed = or_mdash(it.x_list("fixed").iter().take(3).map(|f| esc(f)).collect::<Vec<_>>().join("<br>"));
        let sp = sev_pill(&sev);
        out.push_str(&format!(
            concat!(
                r#"<tr><td class="id"><a href="{}" target="_blank" rel="noopener">{}</a>"#,
                r#"<span class="sub">{}</span></td>"#,
                r#"<td>{}</td>"#,
                r#"<td>{}</td><td>{}</td>"#,
                r#"<td><span class="fix">{}</span></td>"#,
                r#"<td class="desc">{}</td></tr>"#,
            ),
            href(&it.url, &fallback),
            esc(&it.id),
            ftime(&it.published, false),
            or_mdash(sp),
            ecos,
            pkg,
            fixed,
            esc(&it.title),
        ));
    }
    out
}

// ---------------------------------------------------------------- CVEs (cvelistV5 + NVD)

static AV_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bAV:([NALP])").unwrap());
static PR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bPR:([NLH])").unwrap());

/// (av, pr) as words. Uses extra av/pr ("network"/"N"...) or falls back to the vector string.
fn vec_words(it: &Item) -> (String, String) {
    let vec = it.x("vector");
    let mut av = it.x("av").trim().to_lowercase();
    let mut pr = it.x("pr").trim().to_lowercase();
    if av.is_empty() {
        av = AV_RE.captures(vec).map_or(String::new(), |m| m[1].to_lowercase());
    }
    if pr.is_empty() {
        pr = PR_RE.captures(vec).map_or(String::new(), |m| m[1].to_lowercase());
    }
    let av = match av.as_str() {
        "n" => "network".into(),
        "a" => "adjacent".into(),
        "l" => "local".into(),
        "p" => "physical".into(),
        _ => av,
    };
    let pr = match pr.as_str() {
        "n" => "none".into(),
        "l" => "low".into(),
        "h" => "high".into(),
        _ => pr,
    };
    (av, pr)
}

/// CRITICAL/HIGH, or SSVC exploitation "active" at any score; score desc, then newest first, then id.
pub fn cve_keep(items: &[Item]) -> Vec<&Item> {
    let mut keep: Vec<&Item> = items
        .iter()
        .filter(|it| {
            let s = sev(it);
            s == "CRITICAL" || s == "HIGH" || it.x("ssvc_exploitation").to_lowercase() == "active"
        })
        .collect();
    keep.sort_by(|a, b| {
        by_score_desc(a.score, b.score)
            .then_with(|| when_key(&b.published).cmp(&when_key(&a.published)))
            .then_with(|| a.id.cmp(&b.id))
    });
    keep
}

/// -> (html, shown, total). 4 columns. cap 0 means no cap.
pub fn build_cve_rows(items: &[Item], cap: usize) -> (String, usize, usize) {
    let keep = cve_keep(items);
    let total = keep.len();
    if keep.is_empty() {
        return (empty(4, "No critical or high CVEs published this window."), 0, 0);
    }
    let rows = if cap > 0 { &keep[..cap.min(total)] } else { &keep[..] };
    let mut out = String::new();
    for it in rows {
        let sev = sev(it);
        let cls = match sev.as_str() {
            "CRITICAL" => "crit",
            "HIGH" => "high",
            _ => "other",
        };
        let (av, pr) = vec_words(it);
        let av_bit = match av.as_str() {
            "network" => Some("AV:N network"),
            "adjacent" => Some("AV:A adjacent"),
            "local" => Some("AV:L local"),
            "physical" => Some("AV:P physical"),
            _ => None,
        };
        let pr_bit = match pr.as_str() {
            "none" => Some("PR:N unauthenticated"),
            "low" => Some("PR:L low priv"),
            "high" => Some("PR:H admin"),
            _ => None,
        };
        let bits: Vec<&str> = [av_bit, pr_bit].into_iter().flatten().collect();
        let hot = if av == "network" && pr == "none" { " hot" } else { "" };
        let mut vend = it.x_list("vendors").iter().take(3).map(|v| format!(r#"<span class="tgt">{}</span>"#, esc(v))).collect::<Vec<_>>().join("<br>");
        if vend.is_empty() {
            vend = r#"<span class="sub">vendor not stated</span>"#.into();
        }
        let desc = clip(&it.title);
        let ssvc_html = match it.x("ssvc_exploitation").to_lowercase().as_str() {
            "active" => r#"<span class="ssvc ssvc-active">SSVC: exploited</span>"#,
            "poc" => r#"<span class="ssvc ssvc-poc">SSVC: PoC public</span>"#,
            _ => "",
        };
        let score_src = it.x("score_source");
        let assigner = it.x("assigner");
        let nvd_html = match it.x_num("nvd_score") {
            Some(nvd) if (nvd - it.score).abs() >= 0.05 => format!(r#"<span class="sub">NVD {}</span>"#, f1(nvd)),
            _ => String::new(),
        };
        let score = if it.score != 0.0 { f1(it.score) } else { "&mdash;".into() };
        let url = if it.url.is_empty() { cve_link(&it.id) } else { it.url.clone() };
        out.push_str(&format!(
            concat!(
                r#"<tr><td class="id">{}<span class="sub">{}</span>{}</td>"#,
                r#"<td class="sc"><span class="score score-{}">{}</span>{}"#,
            ),
            link(&url, &it.id, ""),
            ftime(&it.published, false),
            ssvc_html,
            cls,
            score,
            sev_pill(&sev),
        ));
        if !score_src.is_empty() {
            out.push_str(&format!(r#"<span class="ssrc" title="who assigned this score">{}"#, esc(score_src)));
            if !assigner.is_empty() && score_src == "CNA" {
                out.push_str(&format!(" &middot; {}", esc(assigner)));
            }
            out.push_str("</span>");
        }
        out.push_str(&format!(r#"{nvd_html}</td><td class="vend">{vend}</td><td class="desc">{}"#, esc(&desc)));
        if !bits.is_empty() {
            out.push_str(&format!(
                r#"<span class="vecbits{hot}">{}</span>"#,
                bits.iter().map(|b| esc(b)).collect::<Vec<_>>().join(" &middot; ")
            ));
        }
        out.push_str("</td></tr>");
    }
    (out, rows.len(), total)
}

// ---------------------------------------------------------------- triage (FR-A2/A3)

/// Item cell of the triage tables: the id linked to the publisher (a CVE id falls back
/// to cve.org; any other id without an http(s) URL is plain text), the title underneath.
fn item_cell(id: &str, url: &str, title: &str) -> String {
    let fallback = if id.starts_with("CVE-") { cve_link(id) } else { String::new() };
    let to = href(url, &fallback);
    let mut s = if to == "#" {
        format!(r#"<td class="item"><span class="mono">{}</span>"#, esc(id))
    } else {
        format!(r#"<td class="item"><a href="{to}" target="_blank" rel="noopener">{}</a>"#, esc(id))
    };
    if !title.is_empty() {
        s.push_str(&format!(r#"<span class="sub">{}</span>"#, esc(&clip(title))));
    }
    s.push_str("</td>");
    s
}

/// Issue cell: the identifier linked to the issue (plain text without an http(s) URL),
/// or "pending" before the issue exists.
fn issue_cell(identifier: &str, url: &str) -> String {
    if identifier.is_empty() {
        r#"<td class="id"><span class="pend">pending</span></td>"#.into()
    } else if href(url, "") == "#" {
        format!(r#"<td class="id"><span class="mono">{}</span></td>"#, esc(identifier))
    } else {
        format!(r#"<td class="id">{}</td>"#, link(url, identifier, ""))
    }
}

/// Matched items not yet accepted or declined, oldest first. 4 columns.
/// Overdue rows (waited more than one business day) carry tr.overdue and a red first-seen cell.
pub fn build_untriaged_rows(rows: &[TriageRow], mode_note: Option<&str>) -> String {
    if rows.is_empty() {
        return empty(4, mode_note.unwrap_or("No matched item is waiting for triage."));
    }
    let mut v: Vec<&TriageRow> = rows.iter().collect();
    v.sort_by_cached_key(|r| (when_key(&r.first_seen), r.item_id.clone()));
    let mut out = String::new();
    for r in v {
        let comp = if r.component.is_empty() { "&mdash;".into() } else { format!(r#"<span class="tgt">{}</span>"#, esc(&r.component)) };
        let rule = if r.rule.is_empty() { String::new() } else { format!(r#"<span class="sub">rule: {}</span>"#, esc(&r.rule)) };
        out.push_str(&format!(
            concat!(
                r#"<tr{}>{}"#,
                r#"<td>{}{}</td>"#,
                r#"<td class="due{}">{}{}</td>"#,
                r#"{}</tr>"#,
            ),
            if r.overdue { r#" class="overdue""# } else { "" },
            item_cell(&r.item_id, &r.item_url, &r.title),
            comp,
            rule,
            if r.overdue { " past" } else { "" },
            fwhen(&r.first_seen, false),
            if r.overdue { r#"<span class="sub">overdue</span>"# } else { "" },
            issue_cell(&r.issue_identifier, &r.issue_url),
        ));
    }
    out
}

/// Tickets whose due date is before today ("YYYY-MM-DD", UTC).
pub fn tickets_past_due(rows: &[TicketRow], today: &str) -> usize {
    rows.iter().filter(|r| !r.due.is_empty() && r.due.as_str() < today).count()
}

/// Accepted issues that are not closed: earliest due date first, no due date last. 6 columns.
pub fn build_ticket_rows(rows: &[TicketRow], today: &str, mode_note: Option<&str>) -> String {
    if rows.is_empty() {
        return empty(6, mode_note.unwrap_or("No open tickets."));
    }
    let mut v: Vec<&TicketRow> = rows.iter().collect();
    v.sort_by(|a, b| {
        a.due.is_empty()
            .cmp(&b.due.is_empty())
            .then_with(|| a.due.cmp(&b.due))
            .then_with(|| a.issue_identifier.cmp(&b.issue_identifier))
    });
    let mut out = String::new();
    for r in v {
        let past = !r.due.is_empty() && r.due.as_str() < today;
        out.push_str(&format!(
            concat!(
                r#"<tr>{}{}"#,
                r#"<td>{}</td>"#,
                r#"<td>{}</td>"#,
                r#"<td class="due{}">{}{}</td>"#,
                r#"<td>{}</td></tr>"#,
            ),
            issue_cell(&r.issue_identifier, &r.issue_url),
            item_cell(&r.item_id, "", &r.title),
            or_mdash(if r.component.is_empty() { String::new() } else { format!(r#"<span class="tgt">{}</span>"#, esc(&r.component)) }),
            or_mdash(esc(&r.assignee)),
            if past { " past" } else { "" },
            fdate(&r.due, false),
            if past { r#"<span class="sub">overdue</span>"# } else { "" },
            or_mdash(esc(&r.state_name)),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::test_support::{EVIL, assert_clean, evil_item, re};
    use super::*;

    // ------------------------------------------------ escaping

    #[test]
    fn escape_health() {
        let out = build_health_rows(&[HealthRow {
            source: EVIL.into(), status: EVIL.into(), items: 1, newest: EVIL.into(),
            last_success: String::new(), note: EVIL.into(),
        }]);
        assert_clean(&out);
        assert!(out.contains("hs-stale")); // unknown status renders as stale, label escaped
    }

    #[test]
    fn escape_kev() {
        assert_clean(&build_kev_rows(&[evil_item()], "2026-11-03"));
    }

    #[test]
    fn escape_adv() {
        let mut it = evil_item();
        it.cves = vec![EVIL.to_string(); 5];
        assert_clean(&build_adv_rows(&[it]));
    }

    #[test]
    fn escape_dep() {
        assert_clean(&build_dep_rows(&[evil_item()]));
        let mut it = evil_item();
        it.extra = json!({"packages": [EVIL, EVIL, EVIL, EVIL, EVIL], "npkg": 5}).as_object().unwrap().clone();
        assert_clean(&build_dep_rows(&[it]));
    }

    #[test]
    fn escape_cve() {
        let (out, shown, total) = build_cve_rows(&[evil_item()], 300);
        assert_clean(&out);
        assert_eq!((shown, total), (1, 1));
    }

    // ------------------------------------------------ logic

    fn mk(i: u32, score: f64, sev: &str, ssvc: &str, published: &str) -> Item {
        let mut it = Item::new("CVE.org", &format!("CVE-2026-{i:06}"), "", "t", published);
        it.score = score;
        it.severity = sev.into();
        it.extra = json!({"ssvc_exploitation": ssvc, "score_source": "CNA"}).as_object().unwrap().clone();
        it
    }

    const PUB: &str = "2026-11-01T00:00:00Z";

    #[test]
    fn cve_cap_and_order() {
        let items: Vec<Item> = (0..50).map(|i| mk(i, 7.0 + f64::from(i % 30) / 10.0, "", "none", PUB)).collect();
        let (out, shown, total) = build_cve_rows(&items, 7);
        assert_eq!((shown, total), (7, 50));
        assert_eq!(out.matches("<tr>").count(), 7);
        let scores: Vec<f64> = re(r#"class="score score-\w+">([\d.]+)<"#)
            .captures_iter(&out)
            .map(|c| c[1].parse().unwrap())
            .collect();
        let mut sorted = scores.clone();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
        assert_eq!(scores, sorted);
        let (_, shown, total) = build_cve_rows(&items, 0);
        assert_eq!((shown, total), (50, 50));
    }

    #[test]
    fn cve_filter() {
        let items = [
            mk(1, 5.4, "MEDIUM", "none", PUB), mk(2, 6.5, "MEDIUM", "active", PUB),
            mk(3, 9.8, "CRITICAL", "none", PUB), mk(4, 0.0, "", "active", PUB), mk(5, 7.1, "", "none", PUB),
        ];
        let (out, _, total) = build_cve_rows(&items, 300);
        assert_eq!(total, 4);
        assert!(!out.contains("CVE-2026-000001"));
        assert!(out.contains("SSVC: exploited"));
    }

    #[test]
    fn cve_tie_breaks_newest_first() {
        let a = mk(1, 9.8, "", "none", "2026-11-01T00:00:00Z");
        let b = mk(2, 9.8, "", "none", "2026-11-02T00:00:00Z");
        let (out, _, _) = build_cve_rows(&[a, b], 300);
        assert!(out.find("CVE-2026-000002").unwrap() < out.find("CVE-2026-000001").unwrap());
    }

    #[test]
    fn kev_overdue_flag() {
        let mut it = Item::new("CISA KEV", "CVE-2026-1", "", "x", "2026-10-28T17:02:45Z");
        it.extra = json!({"vendor": "V", "product": "P", "due": "2026-10-31"}).as_object().unwrap().clone();
        let out = build_kev_rows(std::slice::from_ref(&it), "2026-11-03");
        assert!(out.contains(r#"class="due past""#));
        assert!(out.contains("overdue"));
        assert_eq!(kev_overdue(std::slice::from_ref(&it), "2026-11-03"), 1);
        assert!(!build_kev_rows(&[it], "2026-10-30").contains("past"));
    }

    #[test]
    fn adv_cves_and_rating() {
        let mut it = Item::new("NCSC-NL", "NCSC-2026-0464", "https://advisories.ncsc.nl/x", "t", "2026-11-02T09:17:50Z");
        it.updated = "2026-11-02T10:00:00Z".into();
        it.cves = (0..5).map(|i| format!("CVE-2026-{i}")).collect();
        it.score = 8.7;
        it.severity = "HIGH".into();
        it.extra = json!({"probability": "M", "impact": "H"}).as_object().unwrap().clone();
        let out = build_adv_rows(&[it]);
        assert!(out.contains("+ 2 more CVEs"));
        assert!(out.contains("P:M / I:H"));
        assert!(out.contains("8.7"));
        assert!(out.contains("updated 2 Nov 10:00 UTC"));
    }

    #[test]
    fn empty_rows() {
        assert!(build_health_rows(&[]).contains(r#"colspan="6" class="empty""#));
        assert!(build_kev_rows(&[], "2026-11-03").contains(r#"colspan="5" class="empty""#));
        assert!(build_adv_rows(&[]).contains(r#"colspan="5" class="empty""#));
        assert!(build_dep_rows(&[]).contains(r#"colspan="6" class="empty""#));
        assert!(build_cve_rows(&[], 300).0.contains(r#"colspan="4" class="empty""#));
        assert!(build_untriaged_rows(&[], None).contains(r#"colspan="4" class="empty""#));
        assert!(build_ticket_rows(&[], "2026-11-03", None).contains(r#"colspan="6" class="empty""#));
    }

    // ------------------------------------------------ triage

    fn trow(id: &str, first_seen: &str, issue: &str, overdue: bool) -> TriageRow {
        TriageRow {
            item_id: id.into(), item_url: String::new(), title: "t".into(), component: "tokio".into(),
            rule: "package".into(), first_seen: first_seen.into(), issue_identifier: issue.into(),
            issue_url: if issue.is_empty() { String::new() } else { format!("https://linear.invalid/fake/issue/{issue}") },
            overdue,
        }
    }

    fn ticket(id: &str, due: &str) -> TicketRow {
        TicketRow {
            issue_identifier: id.into(), issue_url: format!("https://linear.invalid/fake/issue/{id}"),
            item_id: "GHSA-xxxx-yyyy-zzzz".into(), title: "t".into(), component: "hyper".into(),
            assignee: String::new(), due: due.into(), state_name: "Todo".into(),
        }
    }

    #[test]
    fn escape_triage() {
        let t = super::super::test_support::evil_triage();
        let out = build_untriaged_rows(&t.untriaged, None);
        assert_clean(&out);
        assert!(!out.contains("<a "), "javascript: URLs must not become links: {out}");
        assert_clean(&build_ticket_rows(&t.tickets, "2026-11-03", None));
        assert_clean(&build_untriaged_rows(&[], Some(EVIL)));
        assert_clean(&build_ticket_rows(&[], "2026-11-03", Some(EVIL)));
    }

    #[test]
    fn untriaged_overdue_pending_and_order() {
        let rows = [
            trow("CVE-2026-3", "2026-11-03T02:31:19Z", "", false),
            trow("GHSA-1", "2026-10-30T09:12:00Z", "FAKE-3", true),
        ];
        let out = build_untriaged_rows(&rows, None);
        assert_eq!(out.matches("<tr").count(), 2);
        // Oldest first: the overdue row leads, with tr.overdue and a red first-seen cell.
        assert!(out.starts_with(r#"<tr class="overdue">"#), "{out}");
        assert!(out.contains(r#"<td class="due past">30 Oct<span class="sub">09:12 UTC</span><span class="sub">overdue</span></td>"#));
        assert_eq!(out.matches("overdue").count(), 2);
        // No issue yet -> pending; a CVE id without a URL links to cve.org; a GHSA id without one is plain text.
        assert!(out.contains(r#"<span class="pend">pending</span>"#));
        assert!(out.contains("https://www.cve.org/CVERecord?id=CVE-2026-3"));
        assert!(out.contains(r#"<span class="mono">GHSA-1</span>"#));
        assert!(out.contains(r#"<span class="sub">rule: package</span>"#));
        assert!(out.contains(r#"href="https://linear.invalid/fake/issue/FAKE-3""#));
        // A note never replaces rows.
        assert_eq!(build_untriaged_rows(&rows, Some("off")), out);
    }

    #[test]
    fn tickets_due_and_order() {
        let rows = [ticket("FAKE-9", ""), ticket("FAKE-2", "2026-11-14"), ticket("FAKE-1", "2026-10-31"), ticket("FAKE-4", "2026-11-03")];
        let out = build_ticket_rows(&rows, "2026-11-03", None);
        let order: Vec<usize> = ["FAKE-1", "FAKE-4", "FAKE-2", "FAKE-9"].iter().map(|i| out.find(i).unwrap()).collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "earliest due first, no due date last: {out}");
        assert_eq!(out.matches(r#"class="due past""#).count(), 1); // due today is not past
        assert!(out.contains(r#"<td class="due past">31 Oct<span class="sub">overdue</span></td>"#));
        assert_eq!(tickets_past_due(&rows, "2026-11-03"), 1);
        assert_eq!(tickets_past_due(&rows, "2026-11-15"), 3);
        assert!(out.contains("<td>&mdash;</td>")); // no assignee
    }

    #[test]
    fn triage_mode_note_replaces_empty_message() {
        let out = build_untriaged_rows(&[], Some("Linear sync is off."));
        assert_eq!(out, r#"<tr><td colspan="4" class="empty">Linear sync is off.</td></tr>"#);
        assert!(build_ticket_rows(&[], "", Some("Linear sync is off.")).contains(">Linear sync is off.<"));
        assert!(build_ticket_rows(&[], "", None).contains(">No open tickets.<"));
    }
}
