//! The triage step of one run: match this run's items, record decisions, sync
//! the tracker and build the two page tables.
//!
//! Nothing here can fail the run. A component list that does not load, or a
//! tracker that errors, leaves the feed tables as they are and is reported in
//! the run record and on stdout; the triage tables then say why they are empty.
//!
//! Only a writing run (not --dry-run or --out) saves state/triage.json or calls
//! the tracker, so a preview never files an issue.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::components;
use super::matcher;
use super::store::Store;
use super::sync::sync;
use super::tracker;
use super::types::Decision;
use crate::feeds::common::Item;
use crate::render::{TicketRow, TriageRow, TriageView};

/// What the step hands back to run.rs: the page view and a runs.jsonl entry.
pub struct Outcome {
    pub view: TriageView,
    pub record: Value,
}

/// `items` are this run's items from every feed that can be triaged (NVD, which
/// only adds scores, is left out); `cves` are the CVE.org records used by the
/// cve-join rule.
pub fn step(items: &[Item], cves: &[Item], now: DateTime<Utc>, write: bool) -> Outcome {
    let comps = match components::load() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("component list not loaded: {e}");
            println!("  triage: {msg}");
            return Outcome {
                view: TriageView { mode_note: Some(format!("Triage did not run: {msg}.")), ..Default::default() },
                record: json!({"error": msg}),
            };
        }
    };
    let mut store = match Store::load() {
        Ok(s) => s,
        Err(e) => {
            println!("  triage: {}", e.0);
            return Outcome {
                view: TriageView { mode_note: Some(format!("Triage did not run: {}.", e.0)), ..Default::default() },
                record: json!({"error": e.0}),
            };
        }
    };

    let index = matcher::cve_index(cves);
    let (mut matched, mut not_relevant) = (0usize, 0usize);
    for it in items {
        let d = matcher::match_item(it, &comps, &index);
        let is_match = matches!(d, Decision::Matched(_));
        if store.record_decision(it, d, now) {
            if is_match { matched += 1 } else { not_relevant += 1 }
        }
    }

    let tracker = tracker::from_env();
    let (mode, mode_note) = match &tracker {
        Ok(None) => ("off".to_string(),
                     Some("Linear sync is off (LINEAR_MODE=off): matched items are recorded but no issue is filed.".to_string())),
        Ok(Some(_)) => (std::env::var("LINEAR_MODE").unwrap_or_default().trim().to_ascii_lowercase(), None),
        Err(e) => ("error".to_string(), Some(format!("Linear sync is not configured: {e}."))),
    };

    let mut record = json!({
        "components": comps.version, "mode": mode,
        "new_matched": matched, "new_not_relevant": not_relevant,
    });
    if mode == "live" {
        // So a run against linear-mock can be told apart from one against Linear.
        let url = std::env::var("LINEAR_API_URL").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
            .unwrap_or_else(|| tracker::ENDPOINT.to_string());
        record["endpoint"] = json!(url);
    }
    if write {
        match tracker {
            Ok(Some(mut t)) => {
                let rep = sync(&mut store, t.as_mut(), items, now);
                println!("  triage: {}", rep.note());
                record["created"] = json!(rep.created);
                record["commented"] = json!(rep.commented);
                record["updated"] = json!(rep.updated);
                if !rep.errors.is_empty() {
                    record["errors"] = json!(rep.errors);
                }
            }
            _ => {
                store.refresh_pending(items, now);
            }
        }
        let pruned = store.prune(now);
        record["pruned"] = json!(pruned);
        store.save();
    } else {
        store.refresh_pending(items, now);
    }
    println!("  triage: {matched} new matched, {not_relevant} new not relevant by rule ({})", comps.version);

    Outcome { view: view(&store, items, now, mode_note), record }
}

/// The two page tables from the store. "Not relevant by rule" counts the items
/// of this window, so the number follows the page's other window counts.
fn view(store: &Store, items: &[Item], now: DateTime<Utc>, mode_note: Option<String>) -> TriageView {
    let untriaged = store.untriaged(now).into_iter().filter_map(|u| {
        let m = u.record.matched()?;
        let issue = u.record.issue.as_ref();
        Some(TriageRow {
            item_id: u.record.item.id.clone(),
            item_url: u.record.url().to_string(),
            title: u.record.title().to_string(),
            component: m.component.clone(),
            rule: m.rule.clone(),
            first_seen: u.record.first_seen.clone(),
            issue_identifier: issue.map(|i| i.identifier.clone()).unwrap_or_default(),
            issue_url: issue.map(|i| i.url.clone()).unwrap_or_default(),
            overdue: u.overdue,
        })
    }).collect();
    let tickets = store.open_tickets().into_iter().filter_map(|(_, r)| {
        let m = r.matched()?;
        let issue = r.issue.as_ref()?;
        let st = r.issue_status.as_ref();
        Some(TicketRow {
            issue_identifier: issue.identifier.clone(),
            issue_url: issue.url.clone(),
            item_id: r.item.id.clone(),
            title: r.title().to_string(),
            component: m.component.clone(),
            assignee: st.map(|s| s.assignee.clone()).unwrap_or_default(),
            due: st.map(|s| s.due.clone()).unwrap_or_default(),
            state_name: st.map(|s| s.state_name.clone()).unwrap_or_default(),
        })
    }).collect();
    let auto_not_relevant = items.iter()
        .filter(|it| store.records.get(&it.key())
            .is_some_and(|r| matches!(r.decision, Decision::NotRelevantByRule { .. })))
        .count();
    TriageView { untriaged, tickets, auto_not_relevant, mode_note }
}
