//! Formatting helpers shared by the table builders: dates and times, escaping,
//! counts, links and the small HTML pieces every table uses.

use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, Timelike, Utc};

use crate::feeds::common::{is_http_url, parse_iso};

const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// ---------------------------------------------------------------- time

/// A feed timestamp as (UTC time, has_time). A bare date ("2026-11-03") has no
/// time; anything else goes through common::parse_iso. None when unparsable.
fn parse_when(s: &str) -> Option<(DateTime<Utc>, bool)> {
    let s = s.trim();
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some((d.and_time(NaiveTime::MIN).and_utc(), false));
    }
    parse_iso(s).map(|dt| (dt, true))
}

/// Sort key for "newest first": the parsed time, or the epoch when unparsable.
pub(super) fn when_key(s: &str) -> DateTime<Utc> {
    parse_when(s).map_or(DateTime::UNIX_EPOCH, |(dt, _)| dt)
}

pub(super) fn day(dt: &DateTime<Utc>, year: bool) -> String {
    let mut s = format!("{} {}", dt.day(), MON[dt.month0() as usize]);
    if year {
        s.push_str(&format!(" {}", dt.year()));
    }
    s
}

pub(super) fn hm(dt: &DateTime<Utc>) -> String {
    format!("{:02}:{:02}", dt.hour(), dt.minute())
}

/// "2026-11-03" or any ISO timestamp -> "3 Nov" (HTML-safe). Empty -> &mdash;.
pub fn fdate(d: &str, year: bool) -> String {
    match parse_when(d) {
        Some((dt, _)) => day(&dt, year),
        None if d.is_empty() => "&mdash;".into(),
        None => esc(d),
    }
}

/// UTC timestamp for display, e.g. "3 Nov 02:31 UTC" (date-only input renders the date only).
/// HTML-safe: unparsable input is escaped, empty input is &mdash;.
pub fn ftime(s: &str, year: bool) -> String {
    match parse_when(s) {
        Some((dt, true)) => format!("{} {} UTC", day(&dt, year), hm(&dt)),
        Some((dt, false)) => day(&dt, year),
        None if s.is_empty() => "&mdash;".into(),
        None => esc(s),
    }
}

/// Table-cell form of ftime: the short date as the cell text ("3 Nov", as on the
/// original page) and the time on a sub-line ("02:31 UTC"). Same escaping rules.
pub fn fwhen(s: &str, year: bool) -> String {
    match parse_when(s) {
        Some((dt, true)) => format!(r#"{}<span class="sub">{} UTC</span>"#, day(&dt, year), hm(&dt)),
        _ => ftime(s, year),
    }
}

// ---------------------------------------------------------------- text

/// HTML-escape text and attribute values: & < > " and ' (as &#x27;).
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#x27;"),
            c => o.push(c),
        }
    }
    o
}

/// 1234567 -> "1,234,567".
pub fn thousands(n: usize) -> String {
    let d = n.to_string();
    let mut o = String::with_capacity(d.len() + d.len() / 3);
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i).is_multiple_of(3) {
            o.push(',');
        }
        o.push(c);
    }
    o
}

/// "1 feed", "8 feeds", "1,234 entries".
pub fn plural(n: usize, word: &str, many: Option<&str>) -> String {
    let w = if n == 1 {
        word.to_string()
    } else {
        many.filter(|m| !m.is_empty()).map_or_else(|| format!("{word}s"), str::to_string)
    };
    format!("{} {w}", thousands(n))
}

/// One decimal, e.g. a CVSS score "9.8" (round half to even on the exact binary value).
pub(super) fn f1(f: f64) -> String {
    format!("{f:.1}")
}

// ---------------------------------------------------------------- HTML pieces

/// Only http(s) links reach the page; anything else falls back (or to '#').
pub fn href(url: &str, fallback: &str) -> String {
    for u in [url, fallback] {
        if is_http_url(u) {
            return esc(u);
        }
    }
    "#".into()
}

pub(super) fn cve_link(cve: &str) -> String {
    format!("https://www.cve.org/CVERecord?id={cve}")
}

pub(super) fn link(url: &str, text: &str, cls: &str) -> String {
    let c = if cls.is_empty() { String::new() } else { format!(r#" class="{cls}""#) };
    format!(r#"<a{c} href="{}" target="_blank" rel="noopener">{}</a>"#, href(url, ""), esc(text))
}

/// A table body with one full-width "nothing here" row.
pub(super) fn empty(cols: usize, msg: &str) -> String {
    format!(r#"<tr><td colspan="{cols}" class="empty">{}</td></tr>"#, esc(msg))
}

/// Source label, e.g. "CISA KEV". Class "feed" because "src" is the source card on the page.
pub fn feed_pill(name: &str) -> String {
    format!(r#"<span class="feed">{}</span>"#, esc(name))
}

pub(super) fn sev_pill(sev: &str) -> String {
    if sev.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="sv sv-{0}">{0}</span>"#, esc(sev))
    }
}

/// First n formatted items joined by <br>, then '+ k more <noun>'.
pub(super) fn more(items: &[String], n: usize, fmt: impl Fn(&str) -> String, noun: &str) -> String {
    let head: Vec<String> = items.iter().take(n).map(|x| fmt(x)).collect();
    let mut s = head.join("<br>");
    let rest = items.len().saturating_sub(n);
    if rest > 0 {
        let one = format!("more {noun}");
        let many = format!("more {noun}s");
        s.push_str(&format!(r#"<span class="sub">+ {}</span>"#, plural(rest, &one, Some(&many))));
    }
    s
}

pub(super) fn or_mdash(s: String) -> String {
    if s.is_empty() { "&mdash;".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ftime_formats() {
        assert_eq!(ftime("2026-11-03T02:31:19Z", false), "3 Nov 02:31 UTC");
        assert_eq!(ftime("2026-11-02T09:17:50.123456Z", false), "2 Nov 09:17 UTC");
        assert_eq!(ftime("2026-11-03T03:31:19+01:00", false), "3 Nov 02:31 UTC");
        assert_eq!(ftime("2026-11-03", false), "3 Nov");
        assert_eq!(ftime("2026-08-13T14:02:11Z", true), "13 Aug 2026 14:02 UTC");
        assert_eq!(ftime("", false), "&mdash;");
        assert_eq!(ftime("<b>junk", false), "&lt;b&gt;junk");
        assert_eq!(fwhen("2026-11-03T02:31:19Z", false), r#"3 Nov<span class="sub">02:31 UTC</span>"#);
        assert_eq!(fwhen("2026-08-13T14:02:11Z", true), r#"13 Aug 2026<span class="sub">14:02 UTC</span>"#);
        assert_eq!(fwhen("2026-11-03", false), "3 Nov");
        assert_eq!(fwhen("", true), "&mdash;");
        assert_eq!(fwhen("<b>junk", false), "&lt;b&gt;junk");
    }

    #[test]
    fn fdate_formats() {
        assert_eq!(fdate("2026-10-16", false), "16 Oct");
        assert_eq!(fdate("2026-11-03T02:31:19Z", false), "3 Nov");
        assert_eq!(fdate("", false), "&mdash;");
    }

    #[test]
    fn parse_when_forms() {
        let utc = |s: &str| parse_when(s).map(|(dt, t)| (dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true), t));
        assert_eq!(utc("2026-11-03"), Some(("2026-11-03T00:00:00Z".into(), false)));
        assert_eq!(utc(" 2026-11-03 "), Some(("2026-11-03T00:00:00Z".into(), false)));
        assert_eq!(utc("2026-11-03T02:31:19Z"), Some(("2026-11-03T02:31:19Z".into(), true)));
        assert_eq!(utc("2026-11-03T02:31:19.5+01:00"), Some(("2026-11-03T01:31:19.500Z".into(), true)));
        assert_eq!(utc("2026-11-03T02:31"), Some(("2026-11-03T02:31:00Z".into(), true)));
        for bad in ["", "junk", "2026-02-30", "2026-11-03T24:00:00Z"] {
            assert_eq!(utc(bad), None, "{bad}");
        }
        assert_eq!(when_key("junk"), DateTime::UNIX_EPOCH);
    }

    #[test]
    fn number_formats() {
        assert_eq!(f1(8.75), "8.8");
        assert_eq!(f1(8.65), "8.7");
        assert_eq!(f1(0.05), "0.1");
        assert_eq!(f1(9.95), "9.9");
        assert_eq!(f1(0.25), "0.2");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(0), "0");
        assert_eq!(plural(1, "feed", None), "1 feed");
        assert_eq!(plural(1234, "entry", Some("entries")), "1,234 entries");
    }

    #[test]
    fn href_only_http() {
        assert_eq!(href("javascript:alert(1)", ""), "#");
        assert_eq!(href("javascript:x", "https://a.example/?q=1&b=2"), "https://a.example/?q=1&amp;b=2");
    }
}
