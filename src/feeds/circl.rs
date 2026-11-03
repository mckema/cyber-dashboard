//! CIRCL OSINT MISP feed.
//!
//! manifest.json (~1.4 MB, ~1,700 events) is the only file read: one entry per
//! event with Orgc, Tag, info, date, analysis, threat_level_id, timestamp. It
//! supports ETag/Last-Modified, so an unchanged manifest costs a 304.
//!
//! `date` is the event date the analyst set (often the date of the reported
//! activity, not of publication); `timestamp` is the last modification. The
//! manifest has no publish_timestamp; that lives only in each event file, and
//! reading ~1,700 of them is not worth it. An event counts as new when either
//! value falls in the window. An empty result is normal: on 2026-11-03 the
//! newest `date` was 2026-08-13 and one event had a `timestamp` in the last 7 days.

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};

use super::common::{self, FetchOutput, GetOpts, Item, Response, SourceError, iso_utc};

pub const NAME: &str = "CIRCL OSINT";
/// An unchanged manifest is one 304 (~1 s); daily polling would break the 1-hour target.
pub const CADENCE: u64 = 0;

pub const MANIFEST: &str = "https://www.circl.lu/doc/misp/feed-osint/manifest.json";

fn event_url(uuid: &str) -> String {
    format!("https://www.circl.lu/doc/misp/feed-osint/{uuid}.json")
}

fn level(n: i64) -> &'static str {
    match n {
        1 => "High",
        2 => "Medium",
        3 => "Low",
        _ => "Undefined",
    }
}

/// The pluggable GET, so tests can serve fixtures. Production passes common::get.
pub type Getter<'a> = dyn FnMut(&str, &str, GetOpts) -> Result<Response, SourceError> + 'a;

/// The manifest as parsed JSON. An object keeps its entries in file order (serde_json's
/// Map would sort them, and the order decides ties in the final sort).
#[derive(Debug)]
pub enum Manifest {
    Object(Vec<(String, Value)>),
    /// Any other JSON value (list, string, number, null).
    Other,
}

impl<'de> Deserialize<'de> for Manifest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Manifest;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Manifest, A::Error> {
                // Duplicate keys: the last value wins and keeps the position of the first.
                let mut out: Vec<(String, Value)> = Vec::new();
                let mut at: HashMap<String, usize> = HashMap::new();
                while let Some((k, v)) = a.next_entry::<String, Value>()? {
                    match at.get(&k) {
                        Some(&i) => out[i].1 = v,
                        None => {
                            at.insert(k.clone(), out.len());
                            out.push((k, v));
                        }
                    }
                }
                Ok(Manifest::Object(out))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Manifest, A::Error> {
                while a.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Manifest::Other)
            }
            fn visit_bool<E>(self, _: bool) -> Result<Manifest, E> {
                Ok(Manifest::Other)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Manifest, E> {
                Ok(Manifest::Other)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Manifest, E> {
                Ok(Manifest::Other)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Manifest, E> {
                Ok(Manifest::Other)
            }
            fn visit_str<E>(self, _: &str) -> Result<Manifest, E> {
                Ok(Manifest::Other)
            }
            fn visit_unit<E>(self) -> Result<Manifest, E> {
                Ok(Manifest::Other)
            }
        }
        d.deserialize_any(V)
    }
}

// ---------------------------------------------------------------- loose JSON helpers

/// Whitespace: Unicode White_Space plus the ASCII separators \x1c..\x1f.
fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// Runs of whitespace collapsed to one space, trimmed at both ends.
fn squash(s: &str) -> String {
    s.split(is_space).filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ")
}

/// False for null, false, 0, "", [] and {}; true otherwise.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// v as text: a string as is, true as "True", a number in JSON form; "" when falsy (see truthy).
fn text_of(v: Option<&Value>) -> String {
    match v.filter(|x| truthy(x)) {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(_)) => "True".into(),
        Some(other) => other.to_string(),
    }
}

/// v as an integer (number, bool or integer string; floats truncate); default when falsy,
/// None when not convertible or out of range.
fn int_of(v: Option<&Value>, default: i64) -> Option<i64> {
    match v.filter(|x| truthy(x)) {
        None => Some(default),
        Some(Value::Bool(_)) => Some(1),
        Some(Value::Number(n)) => n.as_i64().or_else(|| {
            let f = n.as_f64()?;
            (f.is_finite() && f.abs() < 9.2e18).then(|| f.trunc() as i64)
        }),
        Some(Value::String(s)) => {
            let t = s.trim().replace('_', "");
            t.strip_prefix('+').unwrap_or(&t).parse::<i64>().ok()
        }
        Some(_) => None,
    }
}

// ---------------------------------------------------------------- parsing

/// manifest -> Items whose date or timestamp falls in [start, end].
pub fn parse_manifest(m: &Manifest, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Item>, SourceError> {
    let events = match m {
        Manifest::Object(ev) if !ev.is_empty() => ev,
        _ => return Err(SourceError::new(format!("{NAME}: manifest is empty or not a JSON object"))),
    };
    let (d0, d1) = (start.date_naive().to_string(), end.date_naive().to_string());
    let mut items = Vec::new();
    for (uuid, ev) in events {
        let day = text_of(ev.get("date"));
        // Timestamps past the year 9999 count as no timestamp.
        let ts = int_of(ev.get("timestamp"), 0)
            .filter(|&s| s <= 253_402_300_799)
            .and_then(|s| DateTime::<Utc>::from_timestamp(s, 0));
        let day_in = d0.as_str() <= day.as_str() && day.as_str() <= d1.as_str();
        if !(day_in || ts.is_some_and(|t| start <= t && t <= end)) {
            continue;
        }
        let threat = int_of(ev.get("threat_level_id"), 4).map_or("Undefined", level);
        let tags: Vec<Value> = ev
            .get("Tag")
            .filter(|t| truthy(t))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|t| t.get("name").filter(|n| truthy(n)).cloned())
            .collect();
        let org = ev.get("Orgc").filter(|o| truthy(o)).and_then(|o| o.get("name")).cloned().unwrap_or_else(|| json!(""));

        let mut extra = Map::new();
        extra.insert("threat_level".into(), json!(threat));
        extra.insert("tags".into(), Value::Array(tags));
        extra.insert("org".into(), org);
        let mut item = Item::new(NAME, uuid, &event_url(uuid), &squash(&text_of(ev.get("info"))), &day);
        // A missing timestamp is epoch 0, which is still a time: "1970-01-01T00:00:00Z".
        item.updated = ts.map(iso_utc).unwrap_or_default();
        item.extra = extra;
        items.push(item);
    }
    let key = |i: &Item| std::cmp::max(i.published.clone(), i.updated.clone());
    items.sort_by(|a, b| key(b).cmp(&key(a)));
    Ok(items)
}

// ---------------------------------------------------------------- fetch

pub fn fetch(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    fetch_with(start, end, &mut common::get)
}

pub fn fetch_with(start: DateTime<Utc>, end: DateTime<Utc>, get: &mut Getter) -> Result<FetchOutput, SourceError> {
    let r = get(MANIFEST, &format!("{NAME} manifest"), GetOpts::default())?;
    let body = r.content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&r.content);
    let m: Manifest =
        serde_json::from_slice(body).map_err(|e| SourceError::new(format!("{NAME}: manifest is not valid JSON: {e}")))?;
    Ok(parse_manifest(&m, start, end)?.into())
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::super::certeu::fake::{FakeGet, fixture, utc};
    use super::super::state;
    use super::*;

    fn manifest() -> Manifest {
        serde_json::from_slice(&fixture("circl_manifest.json")).unwrap()
    }

    #[test]
    fn timestamp_in_window() {
        let items = parse_manifest(&manifest(), utc(2026, 10, 27, 3), utc(2026, 11, 3, 3)).unwrap();
        assert_eq!(items.len(), 1);
        let i = &items[0];
        assert_eq!(i.id, "ea593018-b2e9-4e7e-8da9-cc20a751e3f6");
        assert_eq!(i.url, "https://www.circl.lu/doc/misp/feed-osint/ea593018-b2e9-4e7e-8da9-cc20a751e3f6.json");
        assert_eq!(i.published, "2023-07-21"); // date-only
        assert_eq!(i.updated, "2026-10-31T00:11:56Z");
        assert_eq!(i.x("threat_level"), "High");
        assert_eq!(i.x("org"), "ESET");
        assert!(i.extra["tags"].as_array().unwrap().contains(&json!("tlp:white")));
    }

    #[test]
    fn date_in_window() {
        let items = parse_manifest(&manifest(), utc(2026, 8, 10, 0), utc(2026, 8, 14, 0)).unwrap();
        assert!(items.iter().any(|i| i.id == "6cb37027-b16f-4d80-aa77-a0dfd2dfe872"));
    }

    #[test]
    fn nothing_new_is_success() {
        assert_eq!(parse_manifest(&manifest(), utc(2030, 1, 1, 0), utc(2030, 1, 8, 0)).unwrap(), vec![]);
    }

    #[test]
    fn bad_manifest() {
        let list: Manifest = serde_json::from_str("[]").unwrap();
        let err = parse_manifest(&list, utc(2026, 1, 1, 0), utc(2026, 1, 8, 0)).unwrap_err();
        assert!(err.message.contains("manifest is empty or not a JSON object"), "{err}");
        let _t = state::testing::temp_state("circl-bad");
        let mut fake = FakeGet::new([(MANIFEST.to_string(), Ok(b"<html>502 Bad Gateway</html>".to_vec()))]);
        let err = fetch_with(utc(2026, 1, 1, 0), utc(2026, 1, 8, 0), &mut |u: &str, l: &str, o: GetOpts| fake.call(u, l, o))
            .unwrap_err();
        assert!(err.message.starts_with("CIRCL OSINT: manifest is not valid JSON"), "{err}");
        assert_eq!(fake.conditional, [true]); // manifest is a conditional GET
    }

    // ------------------------------------------------ live (manual)

    /// EW_STATE_COPY=<copy of state/> cargo test -- --ignored circl::tests::live_state_copy --nocapture
    #[test]
    #[ignore]
    fn live_state_copy() {
        super::super::certeu::fake::live_twice("circl", fetch_with);
    }
}
