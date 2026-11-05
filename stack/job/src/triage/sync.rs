//! One tracker round per run (FR-A2/A3): bring the tracker and the triage store
//! in line. In order:
//!
//!   1. refresh the snapshot of records without an issue from this run's items
//!   2. give each pending record its issue_create_id (a new UUID v4) and save the
//!      store before any create sends one; then create an issue for each pending
//!      record (from its snapshot, so also for items that left the 7-day window)
//!      with that id; save the store after each create, so a crash cannot cause a
//!      duplicate. A create whose answer was lost is sent again with the same id
//!      next run and comes back as the existing issue (recovered); an id whose
//!      issue was deleted (IdTaken) is replaced by a new one and tried once more
//!   3. comment on items whose fields changed since their issue was created or
//!      last commented on
//!   4. read every issue's state back and store it
//!   5. save the store
//!
//! Tracker errors are not fatal for the run: the first one stops the tracker
//! calls for this run, is recorded in the report, and what succeeded before it
//! is kept (and saved). The next run picks up where this one stopped.

use chrono::{DateTime, Utc};

use super::store::Store;
use super::tracker::{Tracker, TrackerError, new_issue_id, update_comment};
use super::types::Match;
use crate::feeds::common::Item;

/// What one sync() did, for the health note.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Issues created (including the recovered ones).
    pub created: usize,
    /// Of `created`: issues an earlier run had created but never got the answer for.
    pub recovered: usize,
    /// Update comments added.
    pub commented: usize,
    /// Records whose issue state (or ref) changed.
    pub updated: usize,
    /// One line per error; the tracker is not called again after the first.
    pub errors: Vec<String>,
}

impl SyncReport {
    /// "tracker: 2 created, 1 commented, 3 updated" plus "; error: …" when one occurred;
    /// "2 created (1 already existed)" when issues were recovered.
    pub fn note(&self) -> String {
        let existed = if self.recovered > 0 { format!(" ({} already existed)", self.recovered) } else { String::new() };
        let mut s = format!("tracker: {} created{existed}, {} commented, {} updated", self.created, self.commented,
                            self.updated);
        for e in &self.errors {
            s.push_str("; error: ");
            s.push_str(e);
        }
        s
    }
}

/// Run steps 1-5 of the module doc. `items` are this run's feed items.
pub fn sync(store: &mut Store, tracker: &mut dyn Tracker, items: &[Item], now: DateTime<Utc>) -> SyncReport {
    let mut rep = SyncReport::default();
    let recovered_before = tracker.recovered();
    if let Err(e) = round(store, tracker, items, now, &mut rep) {
        rep.errors.push(e);
    }
    rep.recovered = tracker.recovered().saturating_sub(recovered_before);
    store.save();
    rep
}

/// Steps 1-4. Err (one line) on the first tracker error.
fn round(store: &mut Store, tracker: &mut dyn Tracker, items: &[Item], now: DateTime<Utc>, rep: &mut SyncReport)
         -> Result<(), String> {
    store.refresh_pending(items, now);

    if store.assign_create_ids(new_issue_id) > 0 {
        store.save(); // on disk before any create sends them
    }
    let pending: Vec<(String, Item, Match, String)> = store
        .pending_issues()
        .into_iter()
        .map(|(k, it, m)| (k.to_string(), it.clone(), m.clone(), store.create_id(k).unwrap_or_default().to_string()))
        .collect();
    for (key, item, m, id) in pending {
        let issue = match tracker.create_issue(&item, &m, &id) {
            Err(TrackerError::IdTaken(_)) => {
                // The id's issue was deleted and Linear keeps the id: file the item under a new one.
                let fresh = new_issue_id();
                store.renew_create_id(&key, fresh.clone(), now);
                store.save();
                tracker.create_issue(&item, &m, &fresh)
            }
            r => r,
        }
        .map_err(|e| format!("create issue for {key}: {e}"))?;
        let identifier = issue.identifier.clone();
        if !store.set_issue(&key, issue, now) {
            // Cannot happen (pending records have no issue); never lose the created one silently.
            return Err(format!("created {identifier} for {key} but the store refused it"));
        }
        store.save();
        rep.created += 1;
    }

    for (item, issue) in store.changed_items(items) {
        tracker.comment(&issue, &update_comment(item)).map_err(|e| format!("comment on {}: {e}", issue.identifier))?;
        store.mark_commented(item, now);
        rep.commented += 1;
    }

    let issues = store.issues();
    if !issues.is_empty() {
        let states = tracker.fetch_states(&issues).map_err(|e| format!("read issue states: {e}"))?;
        rep.updated = store.apply_statuses(&states, now);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;
    use std::sync::{Arc, Mutex};

    use serde_json::Value;

    use crate::feeds::state;
    use crate::triage::tracker::{FAKE_FILE, FakeTracker, HttpReply, IssueRef, IssueState, IssueStatus, LinearTracker,
                                 Transport};
    use crate::triage::types::Decision;

    fn at(d: u32, h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, d, h, 0, 0).unwrap()
    }

    fn item(id: &str) -> Item {
        let mut it = Item::new("NCSC-NL", id, &format!("https://advisories.ncsc.nl/advisory?id={id}"), &format!("{id}: flaw"), "2026-11-03");
        it.cves = vec![format!("CVE-2026-{}", &id[10..])];
        it
    }

    fn matched() -> Decision {
        Decision::Matched(Match { component: "nginx".into(), rule: "vendor-product".into(), evidence: "f5:nginx".into() })
    }

    fn store_with(ids: &[&str]) -> Store {
        let mut s = Store::default();
        for (n, id) in ids.iter().enumerate() {
            s.record_decision(&item(id), matched(), at(3, 8 + n as u32));
        }
        s
    }

    /// Tracker that fails on its `fail_at`-th call (0-based) and logs every call.
    struct Flaky {
        fail_at: usize,
        calls: Vec<String>,
    }

    impl Flaky {
        fn call(&mut self, what: String) -> Result<(), TrackerError> {
            self.calls.push(what);
            if self.calls.len() - 1 == self.fail_at {
                Err(TrackerError::Network("error sending request: connection refused".into()))
            } else {
                Ok(())
            }
        }
    }

    impl Tracker for Flaky {
        fn create_issue(&mut self, item: &Item, _m: &Match, _id: &str) -> Result<IssueRef, TrackerError> {
            self.call(format!("create {}", item.id))?;
            let n = &item.id[10..]; // NCSC-2026-0464 -> CTP-0464
            Ok(IssueRef { id: format!("id-{n}"), identifier: format!("CTP-{n}"), url: format!("https://linear.app/x/issue/CTP-{n}") })
        }

        fn comment(&mut self, issue: &IssueRef, _body: &str) -> Result<(), TrackerError> {
            self.call(format!("comment {}", issue.identifier))
        }

        fn fetch_states(&mut self, issues: &[IssueRef]) -> Result<Vec<(IssueRef, IssueStatus)>, TrackerError> {
            self.call(format!("fetch {}", issues.len()))?;
            Ok(issues
                .iter()
                .map(|r| (r.clone(), IssueStatus { state: IssueState::Triage, state_name: "Triage".into(), ..Default::default() }))
                .collect())
        }
    }

    #[test]
    fn fake_tracker_round_trip() {
        let t = state::testing::temp_state("triage-sync");
        let mut tr = FakeTracker::with_clock(|| at(3, 12));
        let ids = ["NCSC-2026-0464", "NCSC-2026-0465"];
        let mut s = store_with(&ids);
        s.record_decision(&item("NCSC-2026-0466"), Decision::NotRelevantByRule { triager: "matcher 1/3".into() }, at(3, 8));
        let items: Vec<Item> = ids.iter().map(|i| item(i)).collect();

        let r = sync(&mut s, &mut tr, &items, at(3, 12));
        assert_eq!(r, SyncReport { created: 2, recovered: 0, commented: 0, updated: 2, errors: vec![] });
        assert_eq!(r.note(), "tracker: 2 created, 0 commented, 2 updated");
        assert_eq!(Store::load().unwrap(), s, "saved");
        assert_eq!(s.records["NCSC-NL:NCSC-2026-0464"].issue.as_ref().unwrap().identifier, "FAKE-1");
        assert_eq!(sync(&mut s, &mut tr, &items, at(3, 13)), SyncReport::default(), "nothing new");

        let mut changed = items.clone();
        changed[1].updated = "2026-11-03T14:00:00Z".into();
        assert_eq!(sync(&mut s, &mut tr, &changed, at(3, 14)).commented, 1);
        assert_eq!(sync(&mut s, &mut tr, &changed, at(3, 15)).commented, 0);

        let p = t.dir.join(FAKE_FILE);
        let mut j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        j["issues"][0]["state"] = json!("accepted");
        std::fs::write(&p, j.to_string()).unwrap();
        let r = sync(&mut s, &mut tr, &changed, at(3, 16));
        assert_eq!((r.created, r.commented, r.updated), (0, 0, 1));
        assert_eq!(s.open_tickets().len(), 1);
        assert_eq!(FakeTracker::load().unwrap().issues.len(), 2);
    }

    #[test]
    fn creates_from_snapshot_after_item_left_window() {
        let _t = state::testing::temp_state("triage-sync-window");
        let mut s = store_with(&["NCSC-2026-0464"]);
        // The tracker was off (or failing) while the item was in the window; now it is gone.
        let r = sync(&mut s, &mut FakeTracker::with_clock(|| at(12, 9)), &[], at(12, 9));
        assert_eq!((r.created, r.errors.len()), (1, 0));
        let f = FakeTracker::load().unwrap();
        assert_eq!(f.issues[0].item_key, "NCSC-NL:NCSC-2026-0464");
        assert_eq!(f.issues[0].title, "[CVE-2026-0464] NCSC-2026-0464: flaw");
    }

    #[test]
    fn first_tracker_error_stops_the_round_and_keeps_progress() {
        let _t = state::testing::temp_state("triage-sync-fail");
        let ids = ["NCSC-2026-0464", "NCSC-2026-0465", "NCSC-2026-0466"];
        let items: Vec<Item> = ids.iter().map(|i| item(i)).collect();
        let mut s = store_with(&ids);

        // Second create fails: no further calls, the first issue is kept and saved.
        let mut tr = Flaky { fail_at: 1, calls: vec![] };
        let r = sync(&mut s, &mut tr, &items, at(3, 12));
        assert_eq!(tr.calls, ["create NCSC-2026-0464", "create NCSC-2026-0465"]);
        assert_eq!((r.created, r.commented, r.updated), (1, 0, 0));
        assert_eq!(r.errors, ["create issue for NCSC-NL:NCSC-2026-0465: \
                               Linear: network error: error sending request: connection refused"]);
        assert_eq!(r.note(), "tracker: 1 created, 0 commented, 0 updated; error: create issue for \
                              NCSC-NL:NCSC-2026-0465: Linear: network error: error sending request: connection refused");
        assert_eq!(Store::load().unwrap(), s);
        assert_eq!(s.pending_issues().len(), 2);

        // Next run: only the two missing issues are created, a changed item gets its
        // comment, then the state read fails.
        let mut changed = items.clone();
        changed[0].score = 7.5;
        let mut tr = Flaky { fail_at: 3, calls: vec![] };
        let r = sync(&mut s, &mut tr, &changed, at(3, 13));
        assert_eq!(tr.calls, ["create NCSC-2026-0465", "create NCSC-2026-0466", "comment CTP-0464", "fetch 3"]);
        assert_eq!((r.created, r.commented, r.updated), (2, 1, 0));
        assert!(r.errors[0].starts_with("read issue states: Linear: network error"), "{:?}", r.errors);
        assert!(s.pending_issues().is_empty());
        assert_eq!(Store::load().unwrap(), s);

        // A comment failure leaves the fingerprint alone, so the comment is retried next run.
        changed[0].score = 8.0;
        let mut tr = Flaky { fail_at: 0, calls: vec![] };
        let r = sync(&mut s, &mut tr, &changed, at(3, 14));
        assert_eq!(tr.calls, ["comment CTP-0464"]);
        assert_eq!(r.commented, 0);
        let r = sync(&mut s, &mut Flaky { fail_at: 99, calls: vec![] }, &changed, at(3, 15));
        assert_eq!((r.commented, r.updated, r.errors.len()), (1, 3, 0));
    }

    // ------------------------------------------------ lost answers, over a Linear-like transport

    /// What the fake Linear server holds: issue ids (in creation order), ids that
    /// are taken by deleted issues, the answers to lose, and every operation seen.
    #[derive(Default)]
    struct Server {
        issues: Vec<String>,
        deleted: Vec<String>,
        lose_creates: usize,
        ops: Vec<String>,
    }

    /// Transport that answers like Linear (T15): IssueCreate stores input.id, a
    /// second create with that id is INPUT_ERROR "conflict on insert of Issue"
    /// (HTTP 200), IssueById finds an issue by id. A "lost" create is stored on
    /// the server but the client gets a network error, as on a proxy reset.
    struct FakeLinear(Arc<Mutex<Server>>);

    fn ok(v: Value) -> Result<HttpReply, String> {
        Ok(HttpReply { status: 200, headers: vec![], body: v.to_string().into_bytes() })
    }

    fn node(id: &str, n: usize) -> Value {
        json!({"id": id, "identifier": format!("TRI-{n}"), "url": format!("https://linear.app/x/issue/TRI-{n}"),
               "state": {"type": "triage", "name": "Triage"}, "assignee": null, "dueDate": null,
               "history": {"nodes": []}, "comments": {"nodes": []}})
    }

    impl Transport for FakeLinear {
        fn post(&mut self, body: &Value) -> Result<HttpReply, String> {
            let mut s = self.0.lock().unwrap();
            let q = body["query"].as_str().unwrap_or("");
            let op = q.split(['(', ' ']).nth(1).unwrap_or("").to_string();
            s.ops.push(op.clone());
            let find = |s: &Server, id: &str| s.issues.iter().position(|i| i == id).map(|n| node(id, n + 1));
            match op.as_str() {
                "TriageState" => ok(json!({"data": {"workflowStates": {"nodes": [{"id": "st", "name": "Triage", "type": "triage"}]}}})),
                "IssueCreate" => {
                    let id = body["variables"]["input"]["id"].as_str().unwrap_or("").to_string();
                    if s.issues.contains(&id) || s.deleted.contains(&id) {
                        return ok(json!({"errors": [{"message": "conflict on insert of Issue", "path": ["issueCreate"],
                                                     "extensions": {"type": "invalid input", "code": "INPUT_ERROR",
                                                                    "statusCode": 400, "userError": true}}],
                                         "data": null}));
                    }
                    s.issues.push(id.clone());
                    if s.lose_creates > 0 {
                        s.lose_creates -= 1;
                        return Err("error sending request: operation timed out".into());
                    }
                    let n = find(&s, &id).unwrap();
                    ok(json!({"data": {"issueCreate": {"success": true, "issue": n}}}))
                }
                "IssueById" => {
                    let id = body["variables"]["id"].as_str().unwrap_or("");
                    match find(&s, id) {
                        Some(n) => ok(json!({"data": {"issue": n}})),
                        None => ok(json!({"errors": [{"message": "Entity not found: Issue",
                                                      "extensions": {"code": "INPUT_ERROR"}}], "data": null})),
                    }
                }
                "IssueStates" => {
                    let ids: Vec<&str> = body["variables"]["ids"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
                    let nodes: Vec<Value> = ids.iter().filter_map(|i| find(&s, i)).collect();
                    ok(json!({"data": {"issues": {"nodes": nodes}}}))
                }
                _ => panic!("unexpected operation {op:?}"),
            }
        }
    }

    fn fake_linear(server: &Arc<Mutex<Server>>) -> LinearTracker {
        LinearTracker::new(Box::new(FakeLinear(server.clone())), "team-uuid")
    }

    /// The create succeeds on the server but its answer is lost: the run reports the
    /// error and keeps the id on disk; the next run sends the same id, gets the
    /// conflict, reads the issue back and records it. One issue per item.
    #[test]
    fn lost_create_answer_is_recovered_next_run() {
        let _t = state::testing::temp_state("triage-sync-lost");
        let ids = ["NCSC-2026-0464", "NCSC-2026-0465"];
        let items: Vec<Item> = ids.iter().map(|i| item(i)).collect();
        let mut s = store_with(&ids);
        let server = Arc::new(Mutex::new(Server { lose_creates: 1, ..Default::default() }));

        let r = sync(&mut s, &mut fake_linear(&server), &items, at(3, 12));
        assert_eq!((r.created, r.recovered), (0, 0));
        assert_eq!(r.errors, ["create issue for NCSC-NL:NCSC-2026-0464: \
                               Linear: network error: issueCreate: error sending request: operation timed out"]);
        assert_eq!(server.lock().unwrap().issues.len(), 1, "Linear has the issue, the job does not know it");
        let sent = s.create_id("NCSC-NL:NCSC-2026-0464").unwrap().to_string();
        assert_eq!(server.lock().unwrap().issues[0], sent);
        assert_eq!(Store::load().unwrap(), s, "the id is on disk although the create failed");

        // Next run, from the saved store (a fresh process).
        let mut s = Store::load().unwrap();
        server.lock().unwrap().ops.clear();
        let r = sync(&mut s, &mut fake_linear(&server), &items, at(3, 18));
        assert_eq!(r, SyncReport { created: 2, recovered: 1, commented: 0, updated: 2, errors: vec![] });
        assert_eq!(r.note(), "tracker: 2 created (1 already existed), 0 commented, 2 updated");
        let srv = server.lock().unwrap();
        assert_eq!(srv.ops, ["TriageState", "IssueCreate", "IssueById", "IssueCreate", "IssueStates"]);
        assert_eq!(srv.issues.len(), 2, "no second issue for the first item");
        let first = s.records["NCSC-NL:NCSC-2026-0464"].issue.clone().unwrap();
        assert_eq!((first.id.as_str(), first.identifier.as_str()), (sent.as_str(), "TRI-1"));
        assert_eq!(s.records["NCSC-NL:NCSC-2026-0465"].issue.as_ref().unwrap().identifier, "TRI-2");
        assert_eq!(s.untriaged(at(3, 18)).len(), 2);
    }

    /// The id's issue was deleted and Linear keeps the id: the record gets a new
    /// id (saved first) and the issue is filed once, in the same run.
    #[test]
    fn id_of_a_deleted_issue_is_replaced_once() {
        let _t = state::testing::temp_state("triage-sync-deleted");
        let items = vec![item("NCSC-2026-0464")];
        let mut s = store_with(&["NCSC-2026-0464"]);
        s.assign_create_ids(|| "0f0e0d0c-0b0a-4908-8706-050403020100".into());
        let server = Arc::new(Mutex::new(Server { deleted: vec!["0f0e0d0c-0b0a-4908-8706-050403020100".into()],
                                                   ..Default::default() }));
        let r = sync(&mut s, &mut fake_linear(&server), &items, at(3, 12));
        assert_eq!((r.created, r.recovered, r.errors.len()), (1, 0, 0), "{:?}", r.errors);
        let srv = server.lock().unwrap();
        assert_eq!(srv.ops, ["TriageState", "IssueCreate", "IssueById", "IssueCreate", "IssueStates"]);
        let rec = &s.records["NCSC-NL:NCSC-2026-0464"];
        let new_id = rec.issue_create_id.clone().unwrap();
        assert_ne!(new_id, "0f0e0d0c-0b0a-4908-8706-050403020100");
        assert_eq!(rec.issue.as_ref().unwrap().id, new_id);
        assert_eq!(srv.issues, [new_id]);
    }
}
