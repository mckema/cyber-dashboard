//! Reading the inputs of a report: the event log (triage-events.jsonl, format in
//! the module doc of triage/store.rs) and runs.jsonl, and replaying the events of
//! each item key up to a moment.

use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::feeds::common::parse_iso;

/// Key prefix of the events the monthly close appends (close.rs); skipped here.
pub const REPORT_KEY_PREFIX: &str = "report:";

/// One event of the log, with its time parsed.
#[derive(Debug, Clone)]
pub struct Ev {
    pub kind: String,
    pub key: String,
    pub at: DateTime<Utc>,
    /// Line number in the log: the order the job learned things in.
    pub seq: usize,
    pub v: Value,
}

impl Ev {
    pub fn s(&self, field: &str) -> &str {
        self.v.get(field).and_then(Value::as_str).unwrap_or("")
    }
}

/// The event log as the report uses it.
#[derive(Debug, Clone)]
pub struct Log {
    /// Sorted by `at` (log order among equal times), repeats removed.
    pub events: Vec<Ev>,
    /// `ts` of the first line: when the log (its baseline) was started.
    pub coverage_from: DateTime<Utc>,
    /// Lines in the middle of the file that did not parse (or had no usable time).
    pub skipped_lines: usize,
    /// The last line did not parse: a write in progress or cut off by a crash.
    pub half_written_tail: bool,
    /// Events dropped as repeats of an earlier `id`, and extra `decided` per key.
    pub duplicates: usize,
}

/// Parse the event log. Tolerant: a last line that does not parse is a write in
/// progress and skipped; other bad lines are counted. Repeated `id`s and every
/// `decided` of a key after its earliest are dropped (a crash before triage.json
/// was saved can log a second decision with a new first_seen).
pub fn read_events(raw: &str) -> Result<Log, String> {
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    let last = lines.len().saturating_sub(1);
    let (mut skipped_lines, mut half_written_tail) = (0, false);
    let mut parsed: Vec<(usize, Ev, Option<String>)> = Vec::new();
    let mut coverage_from = None;
    for (i, line) in lines.iter().enumerate() {
        let v: Value = match serde_json::from_str(line) {
            Ok(v @ Value::Object(_)) => v,
            _ if i == last => {
                half_written_tail = true;
                continue;
            }
            _ => {
                skipped_lines += 1;
                continue;
            }
        };
        if coverage_from.is_none() {
            coverage_from = v.get("ts").and_then(Value::as_str).and_then(parse_iso);
        }
        let Some(at) = v.get("at").and_then(Value::as_str).and_then(parse_iso) else {
            skipped_lines += 1;
            continue;
        };
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let (kind, key) = (s("event"), s("key"));
        // The monthly close's own events (report_frozen, …) are about a report, not an item.
        if key.starts_with(REPORT_KEY_PREFIX) {
            continue;
        }
        let id = v.get("id").and_then(Value::as_str).map(String::from);
        parsed.push((i, Ev { kind, key, at, seq: i, v }, id));
    }
    let coverage_from = coverage_from.ok_or("the event log has no line with a readable `ts`")?;

    let mut seen_ids = HashSet::new();
    let mut duplicates = 0;
    parsed.retain(|(_, _, id)| match id {
        Some(id) if !seen_ids.insert(id.clone()) => {
            duplicates += 1;
            false
        }
        _ => true,
    });
    // One decision per key: the earliest.
    let mut first_decided: BTreeMap<String, (DateTime<Utc>, usize)> = BTreeMap::new();
    for (i, e, _) in &parsed {
        if e.kind == "decided" {
            let cur = first_decided.entry(e.key.clone()).or_insert((e.at, *i));
            if (e.at, *i) < *cur {
                *cur = (e.at, *i);
            }
        }
    }
    parsed.retain(|(i, e, _)| {
        let keep = e.kind != "decided" || first_decided.get(&e.key).is_some_and(|(_, j)| j == i);
        if !keep {
            duplicates += 1;
        }
        keep
    });
    parsed.sort_by_key(|(i, e, _)| (e.at, *i));
    Ok(Log {
        events: parsed.into_iter().map(|(_, e, _)| e).collect(),
        coverage_from,
        skipped_lines,
        half_written_tail,
        duplicates,
    })
}

/// `decided` events logged before 2026-11-05 lack score, severity, exploited and
/// exploited_source. Fill them, in memory only, from the item copy the store still
/// holds (triage.json `records[key].item`); the log itself is never rewritten. A
/// key no longer in triage.json keeps the gap (shown as unscored, not exploited).
/// Returns how many events were filled.
pub fn backfill(log: &mut Log, triage: &Value) -> usize {
    let mut n = 0;
    for e in log.events.iter_mut().filter(|e| e.kind == "decided" && e.v.get("exploited").is_none()) {
        // triage.json is the records map itself (Store is serde-transparent).
        let Some(item) = triage.get(&e.key).and_then(|r| r.get("item"))
            .and_then(|v| serde_json::from_value::<crate::feeds::common::Item>(v.clone()).ok()) else { continue };
        if let Value::Object(o) = &mut e.v {
            o.extend(crate::triage::store::item_risk(&item));
            o.insert("backfilled".into(), Value::Bool(true));
            n += 1;
        }
    }
    n
}

/// One runs.jsonl line with a readable `run_at`.
#[derive(Debug, Clone)]
pub struct Run {
    pub at: DateTime<Utc>,
    pub v: Value,
}

impl Run {
    pub fn s(&self, field: &str) -> &str {
        self.v.get(field).and_then(Value::as_str).unwrap_or("")
    }

    /// A run that wrote state: `run` without --dry-run / --out. `fatal` and `crash`
    /// lines carry no mode; they come from such runs as well (the loop) and count too.
    pub fn is_writing(&self) -> bool {
        self.s("mode") == "write" || (self.s("mode").is_empty() && matches!(self.s("result"), "fatal" | "crash"))
    }

    /// A writing run that got as far as the tracker read-back.
    pub fn read_back(&self) -> bool {
        self.s("mode") == "write" && matches!(self.s("result"), "written" | "unchanged" | "would-write")
    }
}

/// runs.jsonl lines in file order; lines that do not parse are skipped.
pub fn read_runs(raw: &str) -> Vec<Run> {
    raw.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| Some(Run { at: v.get("run_at").and_then(Value::as_str).and_then(parse_iso)?, v }))
        .collect()
}

/// A triage decision in Linear (`triaged` event).
#[derive(Debug, Clone, PartialEq)]
pub struct Triaged {
    pub at: DateTime<Utc>,
    /// accepted | declined
    pub state: String,
    pub actor: String,
    /// The event's `ts`: the read-back (log write) that saw the triage.
    pub ts: String,
}

/// What the log says about one item key up to a moment.
#[derive(Debug, Clone, Default)]
pub struct Item {
    pub key: String,
    /// `decided` event (None: the log holds later events only).
    pub first_seen: Option<DateTime<Utc>>,
    pub matched: bool,
    pub component: String,
    pub source: String,
    pub title: String,
    pub url: String,
    /// Source-native id (CVE-…, GHSA-…) and the CVEs the item names.
    pub item_id: String,
    pub cves: Vec<String>,
    /// CVSS base score (None: unscored) and severity, from the `decided` event.
    pub score: Option<f64>,
    pub severity: String,
    /// Known exploited and why (triage::store::exploited_source; widened by build.rs).
    pub exploited: bool,
    pub exploited_source: String,
    pub identifier: String,
    pub issue_url: String,
    pub issue_created: Option<DateTime<Utc>>,
    pub first_triaged: Option<Triaged>,
    /// IssueState name; "none" before the first read-back.
    pub state: String,
    pub state_name: String,
    pub state_at: Option<DateTime<Utc>>,
    /// Ev::seq of the state_changed that set `state`.
    pub state_seq: usize,
    pub assignee: String,
    pub due: String,
    pub reason: String,
    /// When the current (non-empty) reason arrived; None while there is none. A
    /// reason replaced by a newer comment keeps the first one's time.
    pub reason_since: Option<DateTime<Utc>>,
    pub pruned: bool,
}

impl Item {
    /// Declined in Linear with no reason: a decline needs one, so not assessed yet
    /// (like the dashboard's untriaged table, triage::store::Store::untriaged).
    pub fn declined_without_reason(&self) -> bool {
        self.state == "declined" && self.reason.trim().is_empty()
    }

    /// Not assessed yet: in Triage, never read back and never triaged, or declined
    /// without a reason (one definition of "waiting" on the page and in the PDF).
    pub fn pending(&self) -> bool {
        self.state == "triage" || (self.state == "none" && self.first_triaged.is_none()) || self.declined_without_reason()
    }

    /// When the item was assessed, None while pending(). Accepted (also later closed):
    /// the triage time. Declined: the later of the triage time and the time its reason
    /// arrived (reason_since).
    pub fn assessed_at(&self) -> Option<DateTime<Utc>> {
        let t = self.first_triaged.as_ref()?;
        if self.pending() {
            return None;
        }
        Some(if self.state == "declined" { self.reason_since.map_or(t.at, |r| r.max(t.at)) } else { t.at })
    }
}

/// When the reason of a `field_changed` reason event arrived: its `reason_at` (when
/// the comment was written, logged since 2026-11-06). Without one (older events, or a
/// duplicate without a comment): the triage time when the same read-back saw the
/// triage (same `ts`: the reason came with the decline), else the event's `at`, the
/// read-back that first saw the reason (at most one run interval late).
fn reason_time(e: &Ev, triaged: Option<&Triaged>) -> DateTime<Utc> {
    if let Some(t) = e.v.get("reason_at").and_then(Value::as_str).and_then(parse_iso) {
        return t;
    }
    match triaged {
        Some(t) if !t.ts.is_empty() && t.ts == e.s("ts") => t.at,
        _ => e.at,
    }
}

/// Replay every event before `until` (exclusive) per key.
pub fn replay(events: &[Ev], until: DateTime<Utc>) -> BTreeMap<String, Item> {
    let mut items: BTreeMap<String, Item> = BTreeMap::new();
    for e in events.iter().take_while(|e| e.at < until) {
        let it = items.entry(e.key.clone()).or_insert_with(|| Item {
            key: e.key.clone(),
            state: "none".into(),
            ..Item::default()
        });
        match e.kind.as_str() {
            "decided" => {
                it.first_seen = Some(e.at);
                it.matched = e.s("decision") == "matched";
                it.component = e.s("component").into();
                it.source = e.s("item_source").into();
                it.title = e.s("title").into();
                it.url = e.s("url").into();
                it.item_id = e.s("item_id").into();
                it.cves = e.v.get("cves").and_then(Value::as_array).into_iter().flatten()
                    .filter_map(Value::as_str).map(String::from).collect();
                it.score = e.v.get("score").and_then(Value::as_f64).filter(|s| *s > 0.0);
                it.severity = e.s("severity").into();
                it.exploited = e.v.get("exploited").and_then(Value::as_bool).unwrap_or(false);
                it.exploited_source = e.s("exploited_source").into();
            }
            "issue_created" => {
                it.identifier = e.s("identifier").into();
                it.issue_url = e.s("url").into();
                it.issue_created = Some(e.at);
            }
            "triaged" => {
                if it.first_triaged.is_none() {
                    it.first_triaged = Some(Triaged { at: e.at, state: e.s("state").into(), actor: e.s("actor").into(),
                                                      ts: e.s("ts").into() });
                }
            }
            // The state is the one logged last, not the one with the latest `at`: a
            // reopened ticket carries its triage time, earlier than the cancel it undoes.
            "state_changed" if it.state_at.is_none() || e.seq >= it.state_seq => {
                it.state = e.s("to").into();
                it.state_name = e.s("state_name").into();
                it.state_at = Some(e.at);
                it.state_seq = e.seq;
            }
            "field_changed" => {
                let to = e.s("to").to_string();
                match e.s("field") {
                    "assignee" => it.assignee = to,
                    "due" => it.due = to,
                    "reason" => {
                        if to.trim().is_empty() {
                            it.reason_since = None;
                        } else if it.reason.trim().is_empty() || it.reason_since.is_none() {
                            it.reason_since = Some(reason_time(e, it.first_triaged.as_ref()));
                        }
                        it.reason = to;
                    }
                    _ => {}
                }
            }
            "pruned" => it.pruned = true,
            _ => {}
        }
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(id: &str, kind: &str, key: &str, at: &str) -> String {
        format!(r#"{{"id":"{id}","event":"{kind}","key":"{key}","at":"{at}","ts":"2026-11-01T00:00:00Z","decision":"matched"}}"#)
    }

    #[test]
    fn tolerant_read_drops_repeats_and_half_line() {
        let raw = [
            line("a", "decided", "K1", "2026-11-02T00:00:00Z"),
            "not json".to_string(),
            line("a", "decided", "K1", "2026-11-02T00:00:00Z"),
            line("b", "decided", "K1", "2026-11-01T00:00:00Z"), // earlier decision of K1 wins
            line("c", "triaged", "K1", "2026-11-03T00:00:00Z"),
            r#"{"id":"d","event":"tri"#.to_string(),
        ]
        .join("\n");
        let log = read_events(&raw).unwrap();
        assert_eq!((log.skipped_lines, log.half_written_tail, log.duplicates), (1, true, 2));
        let ids: Vec<&str> = log.events.iter().map(|e| e.s("id")).collect();
        assert_eq!(ids, ["b", "c"]);
        assert_eq!(log.coverage_from, parse_iso("2026-11-01T00:00:00Z").unwrap());
    }

    #[test]
    fn empty_log_is_an_error() {
        assert!(read_events("").is_err());
        assert!(read_events("{\"half").is_err());
    }
}
