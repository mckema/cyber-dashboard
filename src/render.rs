//! HTML builders for the Cyber Threat Exploit Watch page. Port of render.py.
//!
//! Pure functions: slices of Item in, HTML strings out. No network and no file
//! I/O, except demo().
//!
//! Every builder emits only the class names styled by page/style.css (the page's
//! scriptCss) and no long inline style attributes, because the Wiki.js sanitiser
//! mangles those (README §7).
//!
//! Times: every timestamp on the page is UTC and carries the "UTC" label.
//! Date-only source values (e.g. CISA dueDate) are shown as a date with no time.
//!
//! Anchors filled on the page (see page/skeleton.html):
//!   tbody  t-health t-kev t-adv t-dep t-nvd t-osint
//!   text   s-kev s-crit s-high s-dep s-adv s-osint
//!          n-health n-kev n-adv n-dep n-nvd n-cvecap n-osint winlabel
//!   stamp  rstat   (inner HTML, contains <b>; must never contain a <div>)
//!
//! Output is byte-identical to render.py for the same input. Item.extra values
//! are read with Python's semantics (`x.get(k) or ""`, `str()` of numbers,
//! iterating a string yields its characters), so a feed that writes a number
//! where a string is expected renders the same as it did under Python.
//!
//! Preview:
//!   exploit-watch demo state/preview.html [--dark]

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveTime, Timelike, Utc, Weekday};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::feeds::common::{Fatal, Item, severity_for};

const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DESC_MAX: usize = 300;

pub const TBODY_IDS: [&str; 6] = ["t-health", "t-kev", "t-adv", "t-dep", "t-nvd", "t-osint"];
pub const TEXT_IDS: [&str; 14] = [
    "s-kev", "s-crit", "s-high", "s-dep", "s-adv", "s-osint",
    "n-health", "n-kev", "n-adv", "n-dep", "n-nvd", "n-cvecap", "n-osint", "winlabel",
];
pub const STAMP_ID: &str = "rstat";

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

#[derive(clap::Args)]
pub struct DemoArgs {
    /// Output HTML file
    pub out: PathBuf,
    /// Render the dark theme
    #[arg(long)]
    pub dark: bool,
    /// Fixture with items per table and health rows
    #[arg(long, default_value = "tests/fixtures/render_items.json")]
    pub fixture: PathBuf,
}

// ---------------------------------------------------------------- Python semantics

/// Python truthiness of a JSON value (None, False, 0, "", [], {} are falsy).
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_none_or(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python float repr: shortest round-trip digits, "1.0", "1e+16", "1e-05".
fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let s = format!("{f:?}");
    match s.find('e') {
        Some(i) => {
            let (m, e) = (&s[..i], &s[i + 1..]);
            let (sign, digits) = match e.strip_prefix('-') {
                Some(d) => ("-", d),
                None => ("+", e),
            };
            format!("{m}e{sign}{digits:0>2}")
        }
        None => s,
    }
}

/// Python repr() of a str.
fn py_str_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut o = String::with_capacity(s.len() + 2);
    o.push(q);
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '\t' => o.push_str("\\t"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c if c == q => {
                o.push('\\');
                o.push(c);
            }
            c if !py_printable(c) => {
                let n = c as u32;
                if n < 0x100 {
                    o.push_str(&format!("\\x{n:02x}"));
                } else if n < 0x10000 {
                    o.push_str(&format!("\\u{n:04x}"));
                } else {
                    o.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => o.push(c),
        }
    }
    o.push(q);
    o
}

/// Approximation of str.isprintable() for one character (control, format,
/// separator other than space, private use and unassigned are not printable).
fn py_printable(c: char) -> bool {
    let n = c as u32;
    !(c.is_control()
        || (c != ' ' && c.is_whitespace())
        || n == 0xAD
        || (0x200B..=0x200F).contains(&n)
        || (0x202A..=0x202E).contains(&n)
        || (0x2060..=0x206F).contains(&n)
        || n == 0xFEFF
        || (0xE000..=0xF8FF).contains(&n)
        || (0xFFF9..=0xFFFB).contains(&n))
}

/// Python repr() of a JSON value as Python would hold it after json.load.
fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                py_float(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => py_str_repr(s),
        Value::Array(a) => format!("[{}]", a.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter().map(|(k, v)| format!("{}: {}", py_str_repr(k), py_repr(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// What esc() sees for a value: None -> "", str as is, anything else str().
fn py_str(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => py_repr(other),
    }
}

/// `x.get(k) or ""` as a string.
fn xs(x: &Map<String, Value>, k: &str) -> String {
    match x.get(k) {
        Some(v) if truthy(v) => py_str(v),
        _ => String::new(),
    }
}

/// Iterating a Python value: list items, str characters, dict keys. Anything
/// else is not iterable in Python (TypeError); here it yields nothing.
fn py_iter(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::String(s) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        Value::Object(o) => o.keys().map(|k| Value::String(k.clone())).collect(),
        _ => Vec::new(),
    }
}

/// `x.get(k) or []`, each element as esc() would see it.
fn xlist(x: &Map<String, Value>, k: &str) -> Vec<String> {
    match x.get(k) {
        Some(v) if truthy(v) => py_iter(v).iter().map(py_str).collect(),
        _ => Vec::new(),
    }
}

/// int(v) for a truthy value. None where Python would raise.
fn py_int(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(b) => Some(*b as i64),
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc() as i64)),
        Value::String(s) => py_strip(s).replace('_', "").parse().ok(),
        _ => None,
    }
}

/// float(v). None where Python would raise.
fn py_float_of(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(*b as i64 as f64),
        Value::Number(n) => n.as_f64(),
        Value::String(s) => py_strip(s).replace('_', "").parse().ok(),
        _ => None,
    }
}

/// str.isspace() for one character.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

/// str.capitalize(): first character in title case, the rest lower case.
fn py_capitalize(s: &str) -> String {
    let mut cs = s.chars();
    let Some(first) = cs.next() else { return String::new() };
    let head: String = match first {
        'ß' => "Ss".into(),
        'Ǆ' | 'ǅ' | 'ǆ' => "ǅ".into(),
        'Ǉ' | 'ǈ' | 'ǉ' => "ǈ".into(),
        'Ǌ' | 'ǋ' | 'ǌ' => "ǋ".into(),
        'Ǳ' | 'ǲ' | 'ǳ' => "ǲ".into(),
        'ﬀ' => "Ff".into(),
        'ﬁ' => "Fi".into(),
        'ﬂ' => "Fl".into(),
        'ﬃ' => "Ffi".into(),
        'ﬄ' => "Ffl".into(),
        'ﬅ' | 'ﬆ' => "St".into(),
        c => c.to_uppercase().collect(),
    };
    head + &cs.as_str().to_lowercase()
}

/// Python "{:,}" for an integer.
fn thou(n: i64) -> String {
    let d = n.unsigned_abs().to_string();
    let mut o = String::with_capacity(d.len() + d.len() / 3 + 1);
    if n < 0 {
        o.push('-');
    }
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            o.push(',');
        }
        o.push(c);
    }
    o
}

/// Python "{:.1f}" (round half to even on the exact binary value, as Rust does).
fn f1(f: f64) -> String {
    format!("{f:.1}")
}

// ---------------------------------------------------------------- time

// strptime's regex for "%Y-%m-%d"; \d is Unicode (Nd), as in Python's _strptime.
static STRP_DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{4})-(1[0-2]|0[1-9]|[1-9])-(3[01]|[12]\d|0[1-9]|[1-9]| [1-9])$").unwrap()
});
static ND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d$").unwrap());

/// int() of a run of Unicode decimal digits. Nd characters come in contiguous
/// runs of ten (0..9), so a digit's value is its offset from the run start, mod 10.
fn nd_int(s: &str) -> Option<u32> {
    let mut v = 0u32;
    for c in s.chars() {
        let d = match c.to_digit(10) {
            Some(d) => d,
            None => {
                let mut start = c as u32;
                while let Some(p) = char::from_u32(start - 1) {
                    if !ND.is_match(p.encode_utf8(&mut [0; 4])) {
                        break;
                    }
                    start -= 1;
                }
                (c as u32 - start) % 10
            }
        };
        v = v.checked_mul(10)?.checked_add(d)?;
    }
    Some(v)
}

/// render.py _parse(): (UTC datetime, has_time), or None.
/// A 10-character value goes through strptime("%Y-%m-%d"); anything else through
/// Python 3.12 datetime.fromisoformat() after replacing every "Z" with "+00:00".
fn py_parse(v: &str) -> Option<(DateTime<Utc>, bool)> {
    if v.is_empty() {
        return None;
    }
    let s = py_strip(v);
    if s.chars().count() == 10 {
        let c = STRP_DATE.captures(s)?;
        let d = NaiveDate::from_ymd_opt(
            nd_int(&c[1])? as i32,
            nd_int(&c[2])?,
            nd_int(c[3].trim_start())?,
        )?;
        if d.year() < 1 {
            return None;
        }
        return Some((d.and_hms_opt(0, 0, 0)?.and_utc(), false));
    }
    from_isoformat(&s.replace('Z', "+00:00")).map(|dt| (dt, true))
}

/// Byte at i, or 0 past the end (CPython reads the NUL terminator).
fn at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

fn digits(b: &[u8], p: usize, n: usize) -> Option<u32> {
    let mut v = 0u32;
    for i in 0..n {
        let c = at(b, p + i);
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
    }
    Some(v)
}

/// CPython _find_isoformat_datetime_separator.
fn iso_separator(b: &[u8]) -> Option<usize> {
    let len = b.len();
    if len == 7 {
        return Some(7);
    }
    if at(b, 4) == b'-' {
        if at(b, 5) == b'W' {
            if len < 8 {
                return None;
            }
            if len > 8 && at(b, 8) == b'-' {
                if len == 9 {
                    return None;
                }
                if len > 10 && at(b, 10).is_ascii_digit() {
                    return Some(8);
                }
                return Some(10);
            }
            return Some(8);
        }
        return Some(10);
    }
    if at(b, 4) == b'W' {
        let mut idx = 7;
        while idx < len && b[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx < 9 {
            return Some(idx);
        }
        return Some(if idx % 2 == 0 { 7 } else { 8 });
    }
    Some(8)
}

/// CPython parse_isoformat_date -> (year, month, day).
fn iso_date(b: &[u8], len: usize) -> Option<NaiveDate> {
    let year = digits(b, 0, 4)? as i32;
    let mut p = 4;
    let use_sep = at(b, p) == b'-';
    if use_sep {
        p += 1;
    }
    if at(b, p) == b'W' {
        p += 1;
        let week = digits(b, p, 2)?;
        p += 2;
        let day = if p < len {
            if use_sep {
                if at(b, p) != b'-' {
                    return None;
                }
                p += 1;
            }
            digits(b, p, 1)?
        } else {
            1
        };
        let wd = match day {
            1 => Weekday::Mon,
            2 => Weekday::Tue,
            3 => Weekday::Wed,
            4 => Weekday::Thu,
            5 => Weekday::Fri,
            6 => Weekday::Sat,
            7 => Weekday::Sun,
            _ => return None,
        };
        return NaiveDate::from_isoywd_opt(year, week, wd);
    }
    let month = digits(b, p, 2)?;
    p += 2;
    if use_sep {
        if at(b, p) != b'-' {
            return None;
        }
        p += 1;
    }
    let day = digits(b, p, 2)?;
    NaiveDate::from_ymd_opt(year, month, day)
}

/// CPython parse_hh_mm_ss_ff over b[p..end] -> ([h, m, s], microsecond, trailing).
fn hh_mm_ss_ff(b: &[u8], mut p: usize, end: usize) -> Option<([u32; 3], u32, bool)> {
    let mut vals = [0u32; 3];
    let mut has_sep = true;
    #[allow(clippy::needless_range_loop)]
    for i in 0..3 {
        vals[i] = digits(b, p, 2)?;
        p += 2;
        let c = at(b, p);
        p += 1;
        if i == 0 {
            has_sep = c == b':';
        }
        if p >= end {
            return Some((vals, 0, c != 0));
        } else if has_sep && c == b':' {
            continue;
        } else if c == b'.' || c == b',' {
            break;
        } else if !has_sep {
            p -= 1;
        } else {
            return None;
        }
    }
    let to_parse = (end - p).min(6);
    if to_parse == 0 {
        return None;
    }
    let mut us = digits(b, p, to_parse)?;
    p += to_parse;
    us *= 10u32.pow((6 - to_parse) as u32);
    while at(b, p).is_ascii_digit() {
        p += 1;
    }
    Some((vals, us, at(b, p) != 0))
}

/// Python 3.12 datetime.fromisoformat(s), converted to UTC (naive values are UTC).
fn from_isoformat(s: &str) -> Option<DateTime<Utc>> {
    if s.chars().count() < 7 {
        return None;
    }
    let b = s.as_bytes();
    let len = b.len();
    let sep = iso_separator(b)?;
    let date = iso_date(b, sep)?;
    if !(1..=9999).contains(&date.year()) {
        return None;
    }
    let (mut hms, mut us, mut off_us) = ([0u32; 3], 0u32, 0i64);
    if len > sep {
        // The separator may be any one character, including a multi-byte one.
        let start = sep + s.get(sep..).and_then(|t| t.chars().next()).map_or(1, char::len_utf8);
        let mut tz = start;
        loop {
            let c = at(b, tz);
            if c == b'Z' || c == b'+' || c == b'-' {
                break;
            }
            tz += 1;
            if tz >= len {
                break;
            }
        }
        let (t, u, trailing) = hh_mm_ss_ff(b, start, tz)?;
        hms = t;
        us = u;
        if tz >= len {
            if trailing {
                return None;
            }
        } else if at(b, tz) == b'Z' {
            if at(b, tz + 1) != 0 {
                return None;
            }
        } else {
            let sign: i64 = if at(b, tz) == b'-' { -1 } else { 1 };
            let (o, ou, trailing) = hh_mm_ss_ff(b, tz + 1, len)?;
            if trailing {
                return None;
            }
            let secs = i64::from(o[0]) * 3600 + i64::from(o[1]) * 60 + i64::from(o[2]);
            off_us = sign * (secs * 1_000_000 + i64::from(ou));
            if off_us.abs() >= 86_400_000_000 {
                return None;
            }
        }
    }
    let time = NaiveTime::from_hms_micro_opt(hms[0], hms[1], hms[2], us)?;
    let utc = date.and_time(time).checked_sub_signed(Duration::microseconds(off_us))?;
    if !(1..=9999).contains(&utc.year()) {
        return None;
    }
    Some(utc.and_utc())
}

fn day(dt: &DateTime<Utc>, year: bool) -> String {
    let mut s = format!("{} {}", dt.day(), MON[dt.month0() as usize]);
    if year {
        s.push_str(&format!(" {}", dt.year()));
    }
    s
}

fn hm(dt: &DateTime<Utc>) -> String {
    format!("{:02}:{:02}", dt.hour(), dt.minute())
}

/// "2026-11-03" or any ISO timestamp -> "3 Nov" (HTML-safe). Empty -> &mdash;.
pub fn fdate(d: &str, year: bool) -> String {
    match py_parse(d) {
        Some((dt, _)) => day(&dt, year),
        None if d.is_empty() => "&mdash;".into(),
        None => esc(d),
    }
}

/// UTC timestamp for display, e.g. "3 Nov 02:31 UTC" (date-only input renders the date only).
/// HTML-safe: unparsable input is escaped, empty input is &mdash;.
pub fn ftime(s: &str, year: bool) -> String {
    match py_parse(s) {
        Some((dt, true)) => format!("{} {} UTC", day(&dt, year), hm(&dt)),
        Some((dt, false)) => day(&dt, year),
        None if s.is_empty() => "&mdash;".into(),
        None => esc(s),
    }
}

/// Seconds since the epoch as Python's datetime.timestamp() gives it; 0 when unparsable.
fn ts(s: &str) -> f64 {
    py_parse(s).map_or(0.0, |(dt, _)| dt.timestamp_micros() as f64 / 1e6)
}

fn cmp_f(a: f64, b: f64) -> std::cmp::Ordering {
    a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
}

// ---------------------------------------------------------------- helpers

/// Python html.escape(s, quote=True).
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

/// "1 feed", "8 feeds", "1,234 entries".
pub fn plural(n: i64, word: &str, many: Option<&str>) -> String {
    let w = if n == 1 {
        word.to_string()
    } else {
        many.filter(|m| !m.is_empty()).map_or_else(|| format!("{word}s"), str::to_string)
    };
    format!("{} {w}", thou(n))
}

static HTTP_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^https?://").unwrap());

/// Only http(s) links reach the page; anything else falls back (or to '#').
pub fn href(url: &str, fallback: &str) -> String {
    for u in [url, fallback] {
        if !u.is_empty() && HTTP_RE.is_match(u) {
            return esc(u);
        }
    }
    "#".into()
}

fn cve_link(cve: &str) -> String {
    format!("https://www.cve.org/CVERecord?id={cve}")
}

fn link(url: &str, text: &str, cls: &str) -> String {
    let c = if cls.is_empty() { String::new() } else { format!(r#" class="{cls}""#) };
    format!(r#"<a{c} href="{}" target="_blank" rel="noopener">{}</a>"#, href(url, ""), esc(text))
}

fn empty(cols: usize, msg: &str) -> String {
    format!(r#"<tr><td colspan="{cols}" class="empty">{}</td></tr>"#, esc(msg))
}

const SRC_FAMILY: [(&str, &str); 12] = [
    ("kev", "us"), ("cisa", "us"), ("euvd", "eu"), ("enisa", "eu"), ("cert-eu", "eu"),
    ("ncsc", "nl"), ("github", "gh"), ("ghsa", "gh"), ("nvd", "cve"), ("cve", "cve"),
    ("circl", "osint"), ("misp", "osint"),
];

/// Source label. Colour family is chosen by keyword so feed NAME wording can change freely.
pub fn src_pill(name: &str) -> String {
    let n = name.to_lowercase();
    let fam = SRC_FAMILY.iter().find(|(k, _)| n.contains(k)).map_or("x", |(_, f)| f);
    format!(r#"<span class="src src-{fam}">{}</span>"#, esc(name))
}

fn sev(it: &Item) -> String {
    let s = it.severity.to_uppercase();
    if s.is_empty() { severity_for(it.score).to_string() } else { s }
}

fn sev_pill(sev: &str) -> String {
    if sev.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="sv sv-{0}">{0}</span>"#, esc(sev))
    }
}

/// First n formatted items joined by <br>, then '+ k more <noun>'.
fn more(items: &[String], n: usize, fmt: impl Fn(&str) -> String, noun: &str) -> String {
    let head: Vec<String> = items.iter().take(n).map(|x| fmt(x)).collect();
    let mut s = head.join("<br>");
    let rest = items.len() as i64 - n as i64;
    if rest > 0 {
        let one = format!("more {noun}");
        let many = format!("more {noun}s");
        s.push_str(&format!(r#"<span class="sub">+ {}</span>"#, plural(rest, &one, Some(&many))));
    }
    s
}

fn or_mdash(s: String) -> String {
    if s.is_empty() { "&mdash;".into() } else { s }
}

fn by_newest(items: &[Item]) -> Vec<&Item> {
    let mut v: Vec<&Item> = items.iter().collect();
    v.sort_by(|a, b| cmp_f(-ts(&a.published), -ts(&b.published)));
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
            src_pill(&h.source),
            cls,
            esc(label),
            thou(h.items as i64),
            ftime(&h.newest, true),
            ftime(&h.last_success, true),
            esc(&h.note),
        ));
    }
    out
}

/// Plain text for n-health, e.g. '8 feeds &middot; 6 ok &middot; 1 cached &middot; 1 error'.
pub fn health_summary(health: &[HealthRow]) -> String {
    let mut parts = vec![plural(health.len() as i64, "feed", None)];
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
        let x = &it.extra;
        let due = xs(x, "due");
        let past = !due.is_empty() && due.as_str() < today;
        let srcs = match x.get("sources") {
            Some(v) if truthy(v) => py_iter(v).iter().map(py_str).collect(),
            _ => vec![it.source.clone()],
        };
        let euvd = xs(x, "euvd_id");
        let (vendor, product) = (xs(x, "vendor"), xs(x, "product"));
        let since = xs(x, "exploited_since");
        let mut since_html = String::new();
        if !since.is_empty() && fdate(&since, false) != fdate(&it.published, false) {
            since_html = format!(r#"<span class="sub">exploited since {}</span>"#, fdate(&since, false));
        }
        let url = if it.url.is_empty() { cve_link(&it.id) } else { it.url.clone() };
        out.push_str(&format!(
            r#"<tr><td class="id">{}<span class="sv sv-EXPLOITED">Exploited</span><span class="srcs">{}</span>"#,
            link(&url, &it.id, ""),
            srcs.iter().map(|s| src_pill(s)).collect::<String>(),
        ));
        if !euvd.is_empty() {
            out.push_str(&format!(r#"<span class="sub mono">{}</span>"#, esc(&euvd)));
        }
        out.push_str("</td>");
        if !vendor.is_empty() || !product.is_empty() {
            out.push_str(&format!(
                r#"<td><span class="tgt">{}</span><span class="sub">{}</span></td>"#,
                esc(&vendor),
                esc(&product)
            ));
        } else {
            out.push_str("<td>&mdash;</td>");
        }
        out.push_str(&format!(
            r#"<td class="desc">{}</td><td class="due">{}{}</td><td class="due{}">{}"#,
            esc(&it.title),
            ftime(&it.published, false),
            since_html,
            if past { " past" } else { "" },
            fdate(&due, false),
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
    items
        .iter()
        .filter(|it| matches!(it.extra.get("due"), Some(v) if truthy(v) && py_str(v).as_str() < today))
        .count()
}

// ---------------------------------------------------------------- EU / national advisories

fn rating(it: &Item) -> String {
    let x = &it.extra;
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
    let (p, i) = (xs(x, "probability").to_uppercase(), xs(x, "impact").to_uppercase());
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

/// CERT-EU and NCSC-NL advisories. 6 columns.
pub fn build_adv_rows(items: &[Item]) -> String {
    if items.is_empty() {
        return empty(6, "No new advisories this window.");
    }
    let mut out = String::new();
    for it in by_newest(items) {
        let x = &it.extra;
        let ver = xs(x, "version");
        let mut upd = String::new();
        if !it.updated.is_empty() && it.updated != it.published {
            upd = format!(r#"<span class="sub">updated {}</span>"#, ftime(&it.updated, false));
        }
        let products = xlist(x, "products");
        let prod = if products.is_empty() {
            String::new()
        } else {
            let head: Vec<&str> = products.iter().take(3).map(String::as_str).collect();
            let extra = if products.len() > 3 { format!(" + {} more", products.len() - 3) } else { String::new() };
            format!(r#"<span class="sub">{}{extra}</span>"#, esc(&head.join(", ")))
        };
        let cves = or_mdash(more(&it.cves, 3, |c| link(&cve_link(c), c, "mono"), "CVE"));
        out.push_str(&format!(r#"<tr><td class="id">{}"#, link(&it.url, &it.id, "")));
        if !ver.is_empty() {
            out.push_str(&format!(r#"<span class="sub">version {}</span>"#, esc(&ver)));
        }
        out.push_str(&format!(
            concat!(
                r#"</td><td>{}</td>"#,
                r#"<td class="due">{}{}</td>"#,
                r#"<td class="desc">{}{}</td>"#,
                r#"<td class="cves">{}</td>"#,
                r#"<td class="rate">{}</td></tr>"#,
            ),
            src_pill(&it.source),
            ftime(&it.published, false),
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
            .then(cmp_f(-a.score, -b.score))
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut out = String::new();
    for (it, sev) in v {
        let x = &it.extra;
        let pkgs = xlist(x, "packages");
        let npkg = match x.get("npkg") {
            Some(v) if truthy(v) => py_int(v).unwrap_or(pkgs.len() as i64),
            _ => pkgs.len() as i64,
        };
        let pkg = if npkg > 3 && !pkgs.is_empty() {
            format!(r#"<span class="pkg">{}</span><span class="sub">+ {} more packages</span>"#, esc(&pkgs[0]), npkg - 1)
        } else if !pkgs.is_empty() {
            format!(r#"<span class="pkg">{}</span>"#, pkgs.iter().map(|p| esc(p)).collect::<Vec<_>>().join("<br>"))
        } else {
            "&mdash;".into()
        };
        let ghsa = xs(x, "ghsa");
        let fallback = if !ghsa.is_empty() {
            format!("https://github.com/advisories/{ghsa}")
        } else if it.id.starts_with("CVE-") {
            cve_link(&it.id)
        } else {
            String::new()
        };
        let ecos = or_mdash(xlist(x, "ecosystems").iter().map(|e| format!(r#"<span class="eco">{}</span>"#, esc(e))).collect());
        let fixed = or_mdash(xlist(x, "fixed").iter().take(3).map(|f| esc(f)).collect::<Vec<_>>().join("<br>"));
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
            if sp.is_empty() { "&mdash;".to_string() } else { sp },
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
fn vec_words(x: &Map<String, Value>) -> (String, String) {
    let vec = xs(x, "vector");
    let mut av = py_strip(&xs(x, "av")).to_lowercase();
    let mut pr = py_strip(&xs(x, "pr")).to_lowercase();
    if av.is_empty() {
        av = AV_RE.captures(&vec).map_or(String::new(), |m| m[1].to_lowercase());
    }
    if pr.is_empty() {
        pr = PR_RE.captures(&vec).map_or(String::new(), |m| m[1].to_lowercase());
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
            s == "CRITICAL" || s == "HIGH" || xs(&it.extra, "ssvc_exploitation").to_lowercase() == "active"
        })
        .collect();
    keep.sort_by(|a, b| {
        cmp_f(-a.score, -b.score)
            .then(cmp_f(-ts(&a.published), -ts(&b.published)))
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
        let x = &it.extra;
        let sev = sev(it);
        let cls = match sev.as_str() {
            "CRITICAL" => "crit",
            "HIGH" => "high",
            _ => "other",
        };
        let (av, pr) = vec_words(x);
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
        let vendors = xlist(x, "vendors");
        let mut vend = vendors.iter().take(3).map(|v| format!(r#"<span class="tgt">{}</span>"#, esc(v))).collect::<Vec<_>>().join("<br>");
        if vend.is_empty() {
            vend = r#"<span class="sub">vendor not stated</span>"#.into();
        }
        let desc = if it.title.chars().count() > DESC_MAX {
            let head: String = it.title.chars().take(DESC_MAX).collect();
            format!("{}…", head.trim_end_matches(py_space))
        } else {
            it.title.clone()
        };
        let ssvc_html = match xs(x, "ssvc_exploitation").to_lowercase().as_str() {
            "active" => r#"<span class="ssvc ssvc-active">SSVC: exploited</span>"#,
            "poc" => r#"<span class="ssvc ssvc-poc">SSVC: PoC public</span>"#,
            _ => "",
        };
        let score_src = xs(x, "score_source");
        let assigner = xs(x, "assigner");
        let mut nvd_html = String::new();
        match x.get("nvd_score") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s.is_empty() => {}
            Some(v) => {
                if let Some(nvd) = py_float_of(v) {
                    if (nvd - it.score).abs() >= 0.05 {
                        nvd_html = format!(r#"<span class="sub">NVD {}</span>"#, f1(nvd));
                    }
                }
            }
        }
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
            out.push_str(&format!(r#"<span class="ssrc" title="who assigned this score">{}"#, esc(&score_src)));
            if !assigner.is_empty() && score_src == "CNA" {
                out.push_str(&format!(" &middot; {}", esc(&assigner)));
            }
            out.push_str("</span>");
        }
        out.push_str(&format!(r#"{nvd_html}</td><td>{vend}</td><td class="desc">{}"#, esc(&desc)));
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

// ---------------------------------------------------------------- OSINT (CIRCL MISP)

/// CIRCL OSINT MISP events. 5 columns.
pub fn build_osint_rows(items: &[Item]) -> String {
    if items.is_empty() {
        return empty(5, "No OSINT events published this window.");
    }
    let mut out = String::new();
    for it in by_newest(items) {
        let x = &it.extra;
        let raw = xs(x, "threat_level");
        let tl = py_strip(&raw);
        let tl = match tl {
            "1" => "High".to_string(),
            "2" => "Medium".to_string(),
            "3" => "Low".to_string(),
            "4" => "Undefined".to_string(),
            "" => "Undefined".to_string(),
            t => py_capitalize(t),
        };
        let tags = xlist(x, "tags");
        let mut tag_html: String = tags.iter().take(4).map(|t| format!(r#"<span class="tag">{}</span>"#, esc(t))).collect();
        if tags.len() > 4 {
            tag_html.push_str(&format!(r#"<span class="sub">+ {} more</span>"#, tags.len() - 4));
        }
        let mut upd = String::new();
        if !it.updated.is_empty() && it.updated != it.published {
            upd = format!(r#"<span class="sub">updated {}</span>"#, ftime(&it.updated, true));
        }
        let title = if it.title.is_empty() { &it.id } else { &it.title };
        let short_id: String = it.id.chars().take(8).collect();
        out.push_str(&format!(
            concat!(
                r#"<tr><td class="desc">{}"#,
                r#"<span class="sub mono">{}</span></td>"#,
                r#"<td class="due">{}{}</td>"#,
                r#"<td><span class="tl tl-{}">{}</span></td>"#,
                r#"<td class="tags">{}</td>"#,
                r#"<td>{}</td></tr>"#,
            ),
            link(&it.url, title, "ttl"),
            esc(&short_id),
            ftime(&it.published, true),
            upd,
            esc(&tl.to_lowercase()),
            esc(&tl),
            or_mdash(tag_html),
            esc(&xs(x, "org")),
        ));
    }
    out
}

// ---------------------------------------------------------------- whole page

/// Inner HTML of <div id="rstat">. Contains <b>; never a <div>.
pub fn build_stamp(now: DateTime<Utc>, kev_catalog: &str, health: &[HealthRow]) -> String {
    let mut s = format!("Rebuilt <b>{}, {} UTC</b>", day(&now, true), hm(&now));
    if !kev_catalog.is_empty() {
        s.push_str(&format!(" &nbsp;&middot;&nbsp; CISA KEV catalog <b>{}</b>", esc(kev_catalog)));
    }
    if !health.is_empty() {
        s.push_str(&format!(" &nbsp;&middot;&nbsp; feeds: {}", health_summary(health)));
    }
    s.push_str(
        " &nbsp;&middot;&nbsp; regenerated on a schedule; this wiki strips JavaScript from \
         page content, so there is no in-page refresh button.",
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
    let n = |v: usize| thou(v as i64);

    let tbody = [
        build_health_rows(health),
        build_kev_rows(kev, &today),
        build_adv_rows(adv),
        build_dep_rows(dep),
        cve_html,
        build_osint_rows(osint),
    ];
    let mut n_kev = plural(kev.len() as i64, "entry", Some("entries"));
    if overdue > 0 {
        n_kev.push_str(&format!(" &middot; {overdue} past deadline"));
    }
    let text = [
        n(kev.len()),
        n(n_crit),
        n(n_high),
        n(dep.len()),
        n(adv.len()),
        n(osint.len()),
        health_summary(health),
        n_kev,
        plural(adv.len() as i64, "advisory", Some("advisories")),
        plural(dep.len() as i64, "advisory", Some("advisories")),
        plural(total as i64, "CVE", None),
        if shown < total {
            format!("Showing {} of {}, highest score first.", n(shown), n(total))
        } else {
            format!("All {} shown.", n(total))
        },
        plural(osint.len() as i64, "event", None),
        format!("{} {} &rarr; {} {} UTC", day(&start, false), hm(&start), day(&end, false), hm(&end)),
    ];
    Regions {
        tbody: TBODY_IDS.iter().map(|s| s.to_string()).zip(tbody).collect(),
        text: TEXT_IDS.iter().map(|s| s.to_string()).zip(text).collect(),
        stamp: build_stamp(now, kev_catalog, health),
    }
}

static TAG_OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^<([a-zA-Z0-9]+)[^>]*>").unwrap());

/// Python `re.search(r'(<(TAG)[^>]*\bid="EID"[^>]*>)(.*?)(</\2>)', doc, re.S)` with
/// TAG = "div" when div_only, else `[a-zA-Z0-9]+`. Rust's regex has no backreference,
/// so this walks the same search order: leftmost '<', then the longest tag name first.
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

// ---------------------------------------------------------------- demo CLI

const PREVIEW_BASE: &str = r#"
body{margin:0;background:#f2f3f5;font-family:Roboto,"Segoe UI",Helvetica,Arial,sans-serif}
.theme--dark{background:#1a1a1a}
.preview-note{font:12px/1.4 monospace;color:#777;padding:8px 24px}
.contents{max-width:1180px;margin:0 auto;padding:24px 32px 64px;background:#fff}
.theme--dark .contents{background:#212121;color:#ddd}
"#;

/// The demo fixture: items per table, health rows and the window.
struct Fixture {
    kev: Vec<Item>,
    adv: Vec<Item>,
    dep: Vec<Item>,
    cve: Vec<Item>,
    osint: Vec<Item>,
    health: Vec<HealthRow>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    now: DateTime<Utc>,
    kev_catalog: String,
    cap: usize,
}

impl Fixture {
    fn regions(&self) -> Regions {
        build_regions(
            &self.kev, &self.adv, &self.dep, &self.cve, &self.osint, &self.health,
            self.start, self.end, self.now, &self.kev_catalog, self.cap,
        )
    }
}

/// Text file read the way Python's open(..., encoding="utf-8") reads it (universal newlines).
fn read_text(path: &Path) -> Result<String, Fatal> {
    let s = std::fs::read_to_string(path).map_err(|e| Fatal(format!("{}: {e}", path.display())))?;
    Ok(if s.contains('\r') { s.replace("\r\n", "\n").replace('\r', "\n") } else { s })
}

fn load_fixture(path: &Path) -> Result<Fixture, Fatal> {
    let bad = |m: String| Fatal(format!("{}: {m}", path.display()));
    let d: Map<String, Value> = serde_json::from_str(&read_text(path)?).map_err(|e| bad(e.to_string()))?;
    let items = |k: &str| -> Result<Vec<Item>, Fatal> {
        match d.get(k) {
            None => Ok(Vec::new()),
            Some(v) => serde_json::from_value(v.clone()).map_err(|e| bad(format!("{k}: {e}"))),
        }
    };
    let when = |k: &str| -> Result<DateTime<Utc>, Fatal> {
        d.get(k)
            .and_then(Value::as_str)
            .and_then(py_parse)
            .map(|(dt, _)| dt)
            .ok_or_else(|| bad(format!("{k}: missing or not an ISO 8601 time")))
    };
    let health = match d.get("health") {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| bad(format!("health: {e}")))?,
        None => return Err(bad("health: missing".into())),
    };
    Ok(Fixture {
        kev: items("kev")?,
        adv: items("adv")?,
        dep: items("dep")?,
        cve: items("cve")?,
        osint: items("osint")?,
        health,
        start: when("start")?,
        end: when("end")?,
        now: when("now")?,
        kev_catalog: d.get("kev_catalog").filter(|v| truthy(v)).map(py_str).unwrap_or_default(),
        cap: match d.get("cap") {
            None => 300,
            Some(v) => py_int(v).filter(|c| *c > 0).unwrap_or(0) as usize,
        },
    })
}

/// The standalone preview page. root holds page/skeleton.html and page/style.css.
fn render_demo(fixture: &Path, dark: bool, root: &Path) -> Result<String, Fatal> {
    let d = load_fixture(fixture)?;
    let skel = read_text(&root.join("page").join("skeleton.html"))?;
    let css = read_text(&root.join("page").join("style.css"))?;
    let body = apply_regions(&skel, &d.regions())?;
    let theme = if dark { "theme--dark" } else { "theme--light" };
    Ok(format!(
        concat!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8">"#,
            r#"<meta name="viewport" content="width=device-width, initial-scale=1">"#,
            "<title>Exploit Watch preview</title><style>{}\n{}</style></head>",
            r#"<body><div class="v-application {}">"#,
            r#"<div class="preview-note">Preview only: fixture data from tests/fixtures/render_items.json. "#,
            "On the wiki, page/skeleton.html is the page content and page/style.css is scriptCss.</div>",
            r#"<div class="contents">{}</div></div></body></html>"#,
        ),
        PREVIEW_BASE, css, theme, body
    ))
}

/// `exploit-watch demo OUT.html [--dark] [--fixture F]`. Reads page/ from the
/// current directory (run it from the repo root, like the other subcommands).
pub fn demo(args: DemoArgs) -> Result<(), Fatal> {
    let out = render_demo(&args.fixture, args.dark, Path::new("."))?;
    let path = &args.out;
    if let Some(dir) = std::path::absolute(path).ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        std::fs::create_dir_all(&dir).map_err(|e| Fatal(format!("{}: {e}", dir.display())))?;
    }
    std::fs::write(path, &out).map_err(|e| Fatal(format!("{}: {e}", path.display())))?;
    // Python's len() counts characters, not bytes.
    println!("wrote {} ({} bytes)", path.display(), thou(out.chars().count() as i64));
    Ok(())
}

// ---------------------------------------------------------------- tests (port of tests/test_render.py)

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ROOT: &str = env!("CARGO_MANIFEST_DIR");
    const EVIL: &str = r#"<script>alert(1)</script>"><img src=x onerror=alert(2)>"#;

    fn read(rel: &str) -> String {
        read_text(&Path::new(ROOT).join(rel)).unwrap()
    }

    fn skel() -> String {
        read("page/skeleton.html")
    }

    fn fixture_path() -> PathBuf {
        Path::new(ROOT).join("tests/fixtures/render_items.json")
    }

    fn re(p: &str) -> Regex {
        Regex::new(p).unwrap()
    }

    fn evil_item() -> Item {
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

    fn assert_clean(out: &str) {
        assert!(!out.contains("<script"), "{out}");
        assert!(!out.contains("<img"), "{out}");
        assert!(!out.contains("javascript:"), "{out}");
        assert!(out.contains("&lt;script&gt;"), "{out}");
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
        let before = s[..t].trim_end_matches(py_space);
        let close = before.strip_suffix("</thead>").map(str::len).unwrap();
        let open = before[..close].rfind("<thead>").unwrap() + "<thead>".len();
        re(r"<th\b").find_iter(&before[open..close]).count()
    }

    fn load() -> (Fixture, Regions) {
        let d = load_fixture(&fixture_path()).unwrap();
        let r = build_regions(&d.kev, &d.adv, &d.dep, &d.cve, &d.osint, &d.health, d.start, d.end, d.now, &d.kev_catalog, 300);
        (d, r)
    }

    fn all_anchors() -> Vec<&'static str> {
        TBODY_IDS.iter().chain(TEXT_IDS.iter()).copied().chain([STAMP_ID]).collect()
    }

    // ------------------------------------------------ SkeletonTest

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
        for bad in ["<style", "<script", "<link", "<html", "<head", "<body", "style="] {
            assert!(!s.contains(bad), "{bad}");
        }
    }

    #[test]
    fn wrapper_and_balanced_divs() {
        let s = skel();
        assert!(s.trim_start_matches(py_space).starts_with(r#"<div class="xw">"#));
        assert_eq!(s.matches("<div").count(), s.matches("</div>").count());
        assert_eq!(s.matches("<table").count(), s.matches("</table>").count());
    }

    #[test]
    fn css_is_scoped() {
        let css = read("page/style.css");
        let body = re(r"(?s)/\*.*?\*/").replace_all(&css, "").to_string();
        let body = re(r"@media[^{]*\{").replace_all(&body, "").to_string();
        for m in re(r"([^{}]+)\{").captures_iter(&body) {
            for part in m[1].split(',') {
                let part = py_strip(part);
                if !part.is_empty() {
                    assert!(part.contains(".xw"), "{part}");
                }
            }
        }
        assert!(!css.to_lowercase().contains("</style"));
    }

    // ------------------------------------------------ HelperTest

    #[test]
    fn ftime_formats() {
        assert_eq!(ftime("2026-11-03T02:31:19Z", false), "3 Nov 02:31 UTC");
        assert_eq!(ftime("2026-11-02T09:17:50.123456Z", false), "2 Nov 09:17 UTC");
        assert_eq!(ftime("2026-11-03T03:31:19+01:00", false), "3 Nov 02:31 UTC");
        assert_eq!(ftime("2026-11-03", false), "3 Nov");
        assert_eq!(ftime("2026-08-13T14:02:11Z", true), "13 Aug 2026 14:02 UTC");
        assert_eq!(ftime("", false), "&mdash;");
        assert_eq!(ftime("<b>junk", false), "&lt;b&gt;junk");
    }

    #[test]
    fn fdate_formats() {
        assert_eq!(fdate("2026-10-16", false), "16 Oct");
        assert_eq!(fdate("2026-11-03T02:31:19Z", false), "3 Nov");
        // Python: fdate(None); every caller here passes `x.get(k) or ""`.
        assert_eq!(fdate("", false), "&mdash;");
    }

    #[test]
    fn href_only_http() {
        assert_eq!(href("javascript:alert(1)", ""), "#");
        assert_eq!(href("javascript:x", "https://a.example/?q=1&b=2"), "https://a.example/?q=1&amp;b=2");
    }

    // ------------------------------------------------ BuilderEscapeTest

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

    #[test]
    fn escape_osint() {
        assert_clean(&build_osint_rows(&[evil_item()]));
    }

    // ------------------------------------------------ BuilderLogicTest

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
        assert!(build_adv_rows(&[]).contains(r#"colspan="6" class="empty""#));
        assert!(build_dep_rows(&[]).contains(r#"colspan="6" class="empty""#));
        assert!(build_cve_rows(&[], 300).0.contains(r#"colspan="4" class="empty""#));
        assert!(build_osint_rows(&[]).contains(r#"colspan="5" class="empty""#));
    }

    // ------------------------------------------------ PageTest

    #[test]
    fn column_counts_match_thead() {
        let (_, r) = load();
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
        let (_, r) = load();
        for (k, v) in &r.text {
            assert!(!v.contains('<'), "{k}");
        }
        assert!(!r.stamp.contains("<div"));
        assert!(r.stamp.contains("<b>"));
    }

    #[test]
    fn counts() {
        let (_, r) = load();
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
        let (_, r) = load();
        let once = apply_regions(&skel(), &r).unwrap();
        let twice = apply_regions(&once, &r).unwrap();
        assert_eq!(once, twice);
        assert!(!once.contains("Not generated yet."));
        assert!(once.contains("CVE-2026-111464"));
        assert!(once.contains("NCSC-2026-0464"));
        assert_eq!(once.matches("<div").count(), once.matches("</div>").count());
    }

    #[test]
    fn missing_anchor_is_fatal() {
        let (_, r) = load();
        assert!(apply_regions(&skel().replace(r#"id="t-osint""#, r#"id="t-gone""#), &r).is_err());
        assert!(apply_regions(&skel().replace(r#"id="n-cvecap""#, ""), &r).is_err());
    }

    #[test]
    fn demo_renders() {
        let out = render_demo(&fixture_path(), false, Path::new(ROOT)).unwrap();
        assert!(out.starts_with("<!doctype html>"));
        assert!(out.contains("<style>"));
        assert!(out.contains("CVE-2026-111464"));
    }

    // ------------------------------------------------ Rust-only checks of the Python semantics

    #[test]
    fn python_number_formats() {
        // Reference values from Python 3.12.
        assert_eq!(f1(8.75), "8.8");
        assert_eq!(f1(8.65), "8.7");
        assert_eq!(f1(0.05), "0.1");
        assert_eq!(f1(9.95), "9.9");
        assert_eq!(f1(0.25), "0.2");
        assert_eq!(thou(1234567), "1,234,567");
        assert_eq!(thou(999), "999");
        assert_eq!(py_float(1.0), "1.0");
        assert_eq!(py_float(1e16), "1e+16");
        assert_eq!(py_float(1e-5), "1e-05");
        assert_eq!(py_float(123456789012345678.0), "1.2345678901234568e+17");
        assert_eq!(py_float(0.0001), "0.0001");
        assert_eq!(py_capitalize("ßa"), "Ssa");
        assert_eq!(py_strip("\x1c a\x1f"), "a");
    }

    #[test]
    fn python_fromisoformat_cases() {
        // Reference values from Python 3.12 datetime.fromisoformat / strptime.
        let ok = [
            ("2026-11-03T02:31:19.1234567Z", "2026-11-03T02:31:19.123456Z"),
            ("2026-11-03 02:31", "2026-11-03T02:31:00Z"),
            ("2026-11-03T02", "2026-11-03T02:00:00Z"),
            ("2026-11-03x02:31:19", "2026-11-03T02:31:19Z"),
            ("20261103", "2026-11-03T00:00:00Z"),
            ("20261103T023119Z", "2026-11-03T02:31:19Z"),
            ("2026-11-03T02:31:19+0100", "2026-11-03T01:31:19Z"),
            ("2026-11-03T02:31:19+01", "2026-11-03T01:31:19Z"),
            ("2026-11-03T02:31:19,5Z", "2026-11-03T02:31:19.500Z"),
            (" 2026-11-03T02:31Z", "2026-11-03T02:31:00Z"),
            ("2026-11-03T023119", "2026-11-03T02:31:19Z"),
            ("2026-11-03T02:31:19 +01:00", "2026-11-03T01:31:19Z"),
            ("2026-11-03T0231", "2026-11-03T02:31:00Z"),
            ("2026-11-03\u{e9}02:31", "2026-11-03T02:31:00Z"),
            ("\u{662}\u{660}\u{662}\u{666}-11-03", "2026-11-03T00:00:00Z"),
        ];
        for (s, want) in ok {
            let got = py_parse(s).unwrap_or_else(|| panic!("{s}")).0;
            assert_eq!(got.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true), want, "{s}");
        }
        for s in ["2026-W45-2", "2026-11-03T24:00:00", "2026-11-03T02:31:19ZZ", "2026-11-3", "2026-1-03 ",
                  "2026-11-03T02:31:19+01:00Z", "2026-11-03T02:31:60Z", "2026-02-30"] {
            assert!(py_parse(s).is_none(), "{s}");
        }
        assert_eq!(py_parse("2026-11-03").unwrap().1, false);
    }

    /// Differential check against Python. Not run by default:
    ///   RB_CASES=cases.json RB_OUT=rust.json cargo test -- --ignored parity_dump
    #[test]
    #[ignore]
    fn parity_dump() {
        let cases: Value = serde_json::from_str(&std::fs::read_to_string(std::env::var("RB_CASES").unwrap()).unwrap()).unwrap();
        let mut out = Map::new();
        let dates: Vec<Value> = cases["dates"].as_array().unwrap().iter().map(|d| {
            let s = d.as_str().unwrap();
            json!([ftime(s, false), ftime(s, true), fdate(s, false), fdate(s, true), ts(s)])
        }).collect();
        out.insert("dates".into(), Value::Array(dates));
        let hrefs: Vec<Value> = cases["hrefs"].as_array().unwrap().iter()
            .map(|p| json!(href(p[0].as_str().unwrap(), p[1].as_str().unwrap()))).collect();
        out.insert("hrefs".into(), Value::Array(hrefs));
        let pills: Vec<Value> = cases["pills"].as_array().unwrap().iter()
            .map(|p| json!([src_pill(p.as_str().unwrap()), esc(p.as_str().unwrap())])).collect();
        out.insert("pills".into(), Value::Array(pills));
        let sets: Vec<Value> = cases["item_sets"].as_array().unwrap().iter().map(|c| {
            let items: Vec<Item> = serde_json::from_value(c["items"].clone()).unwrap();
            let today = c["today"].as_str().unwrap();
            let cap = c["cap"].as_u64().unwrap() as usize;
            let (h, shown, total) = build_cve_rows(&items, cap);
            json!({
                "kev": build_kev_rows(&items, today),
                "kev_overdue": kev_overdue(&items, today),
                "adv": build_adv_rows(&items),
                "dep": build_dep_rows(&items),
                "cve": [h, shown, total],
                "osint": build_osint_rows(&items),
            })
        }).collect();
        out.insert("item_sets".into(), Value::Array(sets));
        let health: Vec<Value> = cases["health_sets"].as_array().unwrap().iter().map(|h| {
            let rows: Vec<HealthRow> = serde_json::from_value(h.clone()).unwrap();
            json!([build_health_rows(&rows), health_summary(&rows)])
        }).collect();
        out.insert("health_sets".into(), Value::Array(health));
        let (_, r) = load();
        let mut regions = Map::new();
        let mut order = Vec::new();
        for (k, v) in r.tbody.iter().chain(r.text.iter()) {
            regions.insert(k.clone(), json!(v));
            order.push(json!(k));
        }
        regions.insert(STAMP_ID.into(), json!(r.stamp));
        order.push(json!(STAMP_ID));
        out.insert("fixture_regions".into(), Value::Object(regions));
        out.insert("fixture_order".into(), Value::Array(order));
        std::fs::write(std::env::var("RB_OUT").unwrap(), serde_json::to_string_pretty(&out).unwrap()).unwrap();
    }
}
