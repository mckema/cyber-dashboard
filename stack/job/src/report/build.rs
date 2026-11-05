//! The report data (report.json without generated_at) from the event log and
//! runs.jsonl. Pure: the period, the cut-off and "tickets as of" are parameters.
//!
//! Definitions (plan R1, as implemented):
//!   intake          `decided` events in the period, per item source
//!   triage          not relevant / matched among them; triaged = the key's first
//!                   `triaged` event falls in the period (whenever it was decided);
//!                   declined with a reason = its reason at the cut-off is set;
//!                   untriaged at the cut-off = matched, still in Triage or never read
//!                   back; time to triage = business_time(first_seen, triaged.at)
//!   SLA breaches    triaged in the period after more than one business day, and
//!                   untriaged items already past one business day at the cut-off
//!   actions taken   `state_changed` to done / canceled / declined in the period
//!                   (last one per key); on time = Amsterdam close date <= due;
//!                   MTTR = median(done.at - first_seen)
//!   actions open    replayed state at the cut-off = accepted (not pruned);
//!                   overdue = due < Amsterdam date of the cut-off;
//!                   age = cut-off - issue creation (else first_seen), whole days
//!   exceptions      open without owner / due, declined without reason at the
//!                   cut-off, triaged in the period without actor, tracker errors of
//!                   the runs in the period, unreadable log lines
//! The cut-off is the end of the period, or now for a period not over yet.
//! All times are written as Europe/Amsterdam local time with offset.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::{Value, json};

use super::model::{Item, Log, Run, replay};
use crate::triage::store::{amsterdam_offset, business_time, to_amsterdam};

/// Everything build() needs besides the data.
pub struct Frame {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// min(end, now): the moment states, ages and SLA are measured at.
    pub cut: DateTime<Utc>,
    pub as_of: DateTime<Utc>,
}

/// Amsterdam local time with its offset, e.g. 2026-11-05T08:31:08+01:00.
pub fn local(t: DateTime<Utc>) -> String {
    let off = if amsterdam_offset(t) == Duration::hours(2) { "+02:00" } else { "+01:00" };
    format!("{}{off}", to_amsterdam(t).format("%Y-%m-%dT%H:%M:%S"))
}

fn local_opt(t: Option<DateTime<Utc>>) -> Value {
    t.map_or(Value::Null, |t| json!(local(t)))
}

fn local_date(t: DateTime<Utc>) -> NaiveDate {
    to_amsterdam(t).date()
}

/// One decimal.
fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn hours(d: Duration) -> f64 {
    round1(d.num_seconds() as f64 / 3600.0)
}

fn median(mut v: Vec<Duration>) -> Option<Duration> {
    if v.is_empty() {
        return None;
    }
    v.sort();
    let n = v.len();
    Some(if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2 })
}

fn sla_over(d: Duration) -> bool {
    d > Duration::days(1)
}

fn row(it: &Item) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("key".into(), json!(it.key));
    m.insert("identifier".into(), json!(it.identifier));
    m.insert("title".into(), json!(it.title));
    m.insert("component".into(), json!(it.component));
    m.insert("url".into(), json!(if it.issue_url.is_empty() { &it.url } else { &it.issue_url }));
    m
}

fn with(mut m: serde_json::Map<String, Value>, extra: Value) -> Value {
    if let Value::Object(e) = extra {
        m.extend(e);
    }
    Value::Object(m)
}

/// The report sections (header data included, generated_at excluded).
pub fn build(log: &Log, runs: &[Run], f: &Frame) -> Value {
    let in_period = |t: DateTime<Utc>| f.start <= t && t < f.cut;
    let at_cut = replay(&log.events, f.cut);
    let get = |k: &str| at_cut.get(k).cloned().unwrap_or_default();

    // ---------------------------------------------------------- intake
    let decided: Vec<&Item> = at_cut.values().filter(|i| i.first_seen.is_some_and(in_period)).collect();
    let mut by_source: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for i in &decided {
        let e = by_source.entry(i.source.as_str()).or_default();
        if i.matched { e.0 += 1 } else { e.1 += 1 }
    }
    let matched = decided.iter().filter(|i| i.matched).count();
    let not_relevant = decided.len() - matched;
    let intake = json!({
        "total": decided.len(), "matched": matched, "not_relevant": not_relevant,
        "by_source": by_source.iter().map(|(s, (m, n))| json!({"source": s, "total": m + n, "matched": m, "not_relevant": n}))
            .collect::<Vec<_>>(),
    });

    let mut components: BTreeMap<(String, String), u64> = BTreeMap::new();
    for e in log.events.iter().filter(|e| e.kind == "decided" && in_period(e.at)) {
        *components.entry((e.s("components_version").into(), e.s("components_sha256").into())).or_default() += 1;
    }

    // ---------------------------------------------------------- triage
    let triaged: Vec<&Item> = at_cut.values()
        .filter(|i| i.matched && i.first_triaged.as_ref().is_some_and(|t| in_period(t.at)))
        .collect();
    let declined = |i: &&&Item| i.first_triaged.as_ref().is_some_and(|t| t.state == "declined");
    let accepted = triaged.iter().filter(|i| !declined(i)).count();
    let with_reason = triaged.iter().filter(declined).filter(|i| !i.reason.trim().is_empty()).count();
    let without_reason = triaged.iter().filter(declined).count() - with_reason;
    let untriaged: Vec<&Item> = at_cut.values()
        .filter(|i| i.matched && !i.pruned && (i.state == "triage" || (i.state == "none" && i.first_triaged.is_none())))
        .collect();

    let mut ttt = Vec::new();
    let mut breaches = Vec::new();
    for i in &triaged {
        let (Some(seen), Some(t)) = (i.first_seen, &i.first_triaged) else { continue };
        let d = business_time(seen, t.at);
        ttt.push(d);
        if sla_over(d) {
            breaches.push((seen, with(row(i), json!({"first_seen": local(seen), "triaged_at": local(t.at),
                                                      "business_hours": hours(d)}))));
        }
    }
    for i in &untriaged {
        let Some(seen) = i.first_seen else { continue };
        let d = business_time(seen, f.cut);
        if sla_over(d) {
            breaches.push((seen, with(row(i), json!({"first_seen": local(seen), "triaged_at": null,
                                                      "business_hours": hours(d)}))));
        }
    }
    breaches.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1["key"].as_str().cmp(&b.1["key"].as_str())));
    let ttt_max = ttt.iter().max().copied();
    let triage = json!({
        "auto_not_relevant": not_relevant,
        "matched": matched,
        "triaged": {"total": triaged.len(), "accepted": accepted, "declined_with_reason": with_reason,
                    "declined_without_reason": without_reason},
        "untriaged_at_end": untriaged.len(),
        "time_to_triage": {"count": ttt.len(), "median_business_hours": median(ttt).map(hours),
                           "max_business_hours": ttt_max.map(hours)},
        "sla_breaches": breaches.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
    });

    // ---------------------------------------------------------- actions taken
    let mut closed: BTreeMap<&str, BTreeMap<&str, DateTime<Utc>>> = BTreeMap::new();
    for e in log.events.iter().filter(|e| e.kind == "state_changed" && in_period(e.at)) {
        let to = e.s("to");
        if matches!(to, "done" | "canceled" | "declined") {
            closed.entry(to).or_default().insert(e.key.as_str(), e.at);
        }
    }
    let list = |to: &str| -> Vec<(Item, DateTime<Utc>)> {
        let mut v: Vec<_> = closed.get(to).into_iter().flatten().map(|(k, at)| (get(k), *at)).collect();
        v.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.key.cmp(&b.0.key)));
        v
    };
    let mut ttr = Vec::new();
    let (mut on_time, mut late, mut no_due) = (0, 0, 0);
    let done: Vec<Value> = list("done").into_iter().map(|(i, at)| {
        if let Some(seen) = i.first_seen {
            ttr.push(at - seen);
        }
        let due = NaiveDate::parse_from_str(i.due.trim(), "%Y-%m-%d").ok();
        let ok = due.map(|d| local_date(at) <= d);
        match ok { Some(true) => on_time += 1, Some(false) => late += 1, None => no_due += 1 }
        with(row(&i), json!({"owner": i.assignee, "due": i.due, "closed_at": local(at), "on_time": ok,
                             "first_seen": local_opt(i.first_seen)}))
    }).collect();
    let canceled: Vec<Value> = list("canceled").into_iter()
        .map(|(i, at)| with(row(&i), json!({"owner": i.assignee, "due": i.due, "closed_at": local(at)})))
        .collect();
    let declined_list: Vec<Value> = list("declined").into_iter()
        .map(|(i, at)| with(row(&i), json!({"reason": i.reason, "actor": i.first_triaged.map(|t| t.actor).unwrap_or_default(),
                                            "declined_at": local(at)})))
        .collect();
    let actions_taken = json!({
        "done": done, "done_count": on_time + late + no_due, "on_time": on_time, "late": late, "no_due": no_due,
        "mttr_median_days": median(ttr).map(|d| round1(d.num_seconds() as f64 / 86400.0)),
        "canceled": canceled, "declined": declined_list,
    });

    // ---------------------------------------------------------- actions open
    let today = local_date(f.cut);
    let mut open: Vec<&Item> = at_cut.values().filter(|i| i.state == "accepted" && !i.pruned).collect();
    open.sort_by(|a, b| a.due.is_empty().cmp(&b.due.is_empty()).then(a.due.cmp(&b.due)).then(a.key.cmp(&b.key)));
    let mut overdue_n = 0;
    let open_rows: Vec<Value> = open.iter().map(|i| {
        let overdue = NaiveDate::parse_from_str(i.due.trim(), "%Y-%m-%d").is_ok_and(|d| d < today);
        overdue_n += usize::from(overdue);
        let since = i.issue_created.or(i.first_seen);
        with(row(i), json!({"owner": i.assignee, "due": i.due, "state_name": i.state_name, "overdue": overdue,
                            "age_days": since.map(|s| (f.cut - s).num_days())}))
    }).collect();
    let actions_open = json!({"count": open_rows.len(), "overdue": overdue_n, "items": open_rows});

    // ---------------------------------------------------------- runs, feeds, tracker
    let period_runs: Vec<&Run> = runs.iter().filter(|r| in_period(r.at)).collect();
    let mut by_result: BTreeMap<String, u64> = BTreeMap::new();
    let mut feeds: BTreeMap<String, (BTreeMap<String, u64>, String)> = BTreeMap::new();
    let mut writing = 0;
    for r in period_runs.iter().filter(|r| r.is_writing()) {
        writing += 1;
        *by_result.entry(r.s("result").to_string()).or_default() += 1;
        if let Some(Value::Object(fs)) = r.v.get("feeds") {
            for (name, fv) in fs {
                let st = fv.get("status").and_then(Value::as_str).unwrap_or("unknown").to_string();
                let e = feeds.entry(name.clone()).or_default();
                *e.0.entry(st.clone()).or_default() += 1;
                e.1 = st;
            }
        }
    }
    let feeds: Vec<Value> = feeds.into_iter().map(|(name, (st, last))| json!({
        "feed": name, "runs": st.values().sum::<u64>(), "ok": st.get("ok").copied().unwrap_or(0),
        "by_status": st, "last_status": last,
    })).collect();
    let tracker_errors: Vec<Value> = period_runs.iter().flat_map(|r| {
        r.v.pointer("/triage/errors").and_then(Value::as_array).into_iter().flatten()
            .map(|e| json!({"run_at": local(r.at), "error": clip(e.as_str().unwrap_or(""), 300)}))
    }).collect();
    let endpoint_of = |r: &&Run| r.v.pointer("/triage/endpoint").and_then(Value::as_str).map(String::from);
    let endpoint = runs.iter().filter(|r| r.at < f.cut).rev().find_map(|r| endpoint_of(&r))
        .or_else(|| runs.iter().rev().find_map(|r| endpoint_of(&r)))
        .unwrap_or_default();

    // ---------------------------------------------------------- exceptions
    let ids = |v: Vec<&Item>| -> Vec<Value> {
        v.into_iter().map(|i| json!({"identifier": i.identifier, "title": i.title, "key": i.key})).collect()
    };
    let exceptions = json!({
        "open_without_owner": ids(open.iter().copied().filter(|i| i.assignee.trim().is_empty()).collect()),
        "open_without_due": ids(open.iter().copied().filter(|i| i.due.trim().is_empty()).collect()),
        "declined_without_reason": ids(at_cut.values()
            .filter(|i| i.matched && i.state == "declined" && i.reason.trim().is_empty()).collect()),
        "triaged_without_actor": ids(triaged.iter().copied()
            .filter(|i| i.first_triaged.as_ref().is_some_and(|t| t.actor.trim().is_empty())).collect()),
        "tracker_errors": tracker_errors,
        "log_lines_skipped": log.skipped_lines,
    });

    json!({
        "period": {"start": local(f.start), "end": local(f.end), "complete": f.cut >= f.end,
                   "data_to": local(f.cut)},
        "tickets_as_of": local(f.as_of),
        "coverage": {"from": local(log.coverage_from), "partial": f.start < log.coverage_from,
                     "duplicates_dropped": log.duplicates, "half_written_tail": log.half_written_tail},
        "tracker": {"endpoint": endpoint, "lab_data": endpoint.contains("linear-mock")},
        "components": components.into_iter()
            .map(|((v, s), n)| json!({"version": v, "sha256": s, "decisions": n})).collect::<Vec<_>>(),
        "runs": {"writing": writing, "by_result": by_result},
        "feeds": feeds,
        "intake": intake,
        "triage": triage,
        "actions_taken": actions_taken,
        "actions_open": actions_open,
        "exceptions": exceptions,
    })
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n - 1).collect::<String>() + "…" }
}
