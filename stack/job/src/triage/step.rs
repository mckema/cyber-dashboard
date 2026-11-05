//! The triage step of one run: match this run's items, record decisions, sync
//! the tracker and build the two page tables.
//!
//! Nothing here can fail the run. A component list that does not load, or a
//! tracker that errors, leaves the feed tables as they are and is reported in
//! the run record and on stdout; the triage tables then say why they are empty.
//!
//! Only a writing run (not --dry-run or --out) saves state/triage.json or calls
//! the tracker, so a preview never files an issue.
//!
//! Triage that Linear lets through incomplete is a warning, never enforced: an
//! issue declined without a reason stays in the untriaged table with a note, and
//! open tickets without an owner or a due date are flagged by render. The counts
//! go to runs.jsonl (missing_owner, missing_due, missing_reason) on every run.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::components;
use super::matcher;
use super::store::{Gaps, Store};
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
                record["recovered"] = json!(rep.recovered);
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

    // Warnings only (FR-A2/A3 rules Linear does not enforce): counted for the
    // monthly report, shown on the page, never written back to the tracker.
    let gaps = store.gaps();
    record["missing_owner"] = json!(gaps.missing_owner);
    record["missing_due"] = json!(gaps.missing_due);
    record["missing_reason"] = json!(gaps.missing_reason);
    if gaps != Gaps::default() {
        println!("  triage: {}", gaps_note(gaps));
    }

    Outcome { view: view(&store, items, now, mode_note), record }
}

/// Untriaged-table note on an issue declined without a reason.
const NO_REASON_NOTE: &str = "declined in Linear without a reason";

/// "incomplete triage: 1 open ticket without an owner, 2 without a due date, 1 declined without a reason"
fn gaps_note(g: Gaps) -> String {
    format!(
        "incomplete triage: {} without an owner, {} without a due date, {} declined without a reason",
        crate::render::plural(g.missing_owner, "open ticket", None), g.missing_due, g.missing_reason,
    )
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
            note: if u.no_reason { NO_REASON_NOTE.to_string() } else { String::new() },
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
            assignee: st.map(|s| s.assignee.trim().to_string()).unwrap_or_default(),
            due: st.map(|s| s.due.trim().to_string()).unwrap_or_default(),
            state_name: st.map(|s| s.state_name.clone()).unwrap_or_default(),
        })
    }).collect();
    let auto_not_relevant = items.iter()
        .filter(|it| store.records.get(&it.key())
            .is_some_and(|r| matches!(r.decision, Decision::NotRelevantByRule { .. })))
        .count();
    TriageView { untriaged, tickets, auto_not_relevant, mode_note }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::triage::tracker::{IssueRef, IssueState, IssueStatus};
    use crate::triage::types::Match;

    fn at(d: u32, h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, d, h, 0, 0).unwrap() // 2026-11-02 is a Monday
    }

    /// One matched record per (state, assignee, due, reason), first seen Monday 08:00.
    fn store(cases: &[(IssueState, &str, &str, &str)]) -> Store {
        let mut s = Store::default();
        for (i, (state, assignee, due, reason)) in cases.iter().enumerate() {
            let id = format!("CVE-2026-{i}");
            let it = Item::new("CISA KEV", &id, "", &format!("{id}: flaw"), "2026-11-02");
            let m = Match { component: "tokio".into(), rule: "package".into(), evidence: "rust:tokio".into() };
            s.record_decision(&it, Decision::Matched(m), at(2, 8));
            let iref = IssueRef { id: format!("uuid-{i}"), identifier: format!("TRI-{i}"), url: format!("https://linear.app/x/issue/TRI-{i}") };
            s.set_issue(&it.key(), iref.clone(), at(2, 8));
            let st = IssueStatus { state: *state, state_name: "Todo".into(), assignee: (*assignee).into(), due: (*due).into(),
                                   reason: (*reason).into(), ..Default::default() };
            s.apply_statuses(&[(iref, st)], at(2, 9));
        }
        s
    }

    #[test]
    fn declined_without_reason_is_an_untriaged_row_with_a_note() {
        let s = store(&[
            (IssueState::Triage, "", "", ""),
            (IssueState::Declined, "", "", "  "),
            (IssueState::Declined, "", "", "not shipped"),
            (IssueState::Canceled, "", "", ""), // canceled after Accept: closed, no reason asked
        ]);
        let v = view(&s, &[], at(4, 9), None);
        let rows: Vec<(&str, &str, bool, &str)> =
            v.untriaged.iter().map(|r| (r.item_id.as_str(), r.issue_identifier.as_str(), r.overdue, r.note.as_str())).collect();
        assert_eq!(rows, [("CVE-2026-0", "TRI-0", true, ""), ("CVE-2026-1", "TRI-1", true, NO_REASON_NOTE)]);
        assert!(v.tickets.is_empty());
        assert_eq!(s.gaps().missing_reason, 1);
    }

    #[test]
    fn open_tickets_keep_blank_owner_and_due_blank() {
        let s = store(&[(IssueState::Accepted, " ", "", ""), (IssueState::Accepted, "Henry", " 2026-11-10 ", "")]);
        let v = view(&s, &[], at(4, 9), None);
        let rows: Vec<(&str, &str)> = v.tickets.iter().map(|t| (t.assignee.as_str(), t.due.as_str())).collect();
        assert_eq!(rows, [("Henry", "2026-11-10"), ("", "")]);
        assert_eq!(s.gaps(), Gaps { missing_owner: 1, missing_due: 1, missing_reason: 0 });
    }

    #[test]
    fn gaps_note_wording() {
        let g = Gaps { missing_owner: 1, missing_due: 2, missing_reason: 3 };
        assert_eq!(gaps_note(g),
                   "incomplete triage: 1 open ticket without an owner, 2 without a due date, 3 declined without a reason");
    }
}
