//! One tracker round per run: bring the tracker and the triage store
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
//! Tracker errors are not fatal for the run. Each one is recorded in the report
//! and what succeeded before it is kept (and saved). An error of one item or
//! issue (`INPUT_ERROR`, an unexpected reply, an id still taken after the retry)
//! skips that item and steps 2-3 go on with the next. An error every further
//! call would hit as well (no answer, rate limit, HTTP error, authentication or
//! permission, settings; see `repeats`) ends steps 2-3 for this run. Step 4 is
//! tried once in every case, so the issue states stay current while a create or
//! comment keeps failing. The next run picks up the items left over.

use chrono::{DateTime, Utc};

use super::store::Store;
use super::tracker::{Tracker, TrackerError, new_issue_id, update_comment};
use super::types::Match;
use crate::feeds::common::Item;

/// What one sync() did, for stdout, runs.jsonl and the "Linear" row of the health table.
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
    /// One line per error, in call order (module doc: which errors end the round).
    pub errors: Vec<String>,
}

impl SyncReport {
    /// "tracker: 2 created, 1 commented, 3 updated" plus "; error: …" per error
    /// (stdout); "2 created (1 already existed)" when issues were recovered.
    pub fn note(&self) -> String {
        let mut s = format!("tracker: {}", self.counts());
        for e in &self.errors {
            s.push_str("; error: ");
            s.push_str(e);
        }
        s
    }

    /// "2 created (1 already existed), 1 commented, 3 updated"; the note of the Linear health row.
    pub fn counts(&self) -> String {
        let existed = if self.recovered > 0 { format!(" ({} already existed)", self.recovered) } else { String::new() };
        format!("{} created{existed}, {} commented, {} updated", self.created, self.commented, self.updated)
    }
}

/// Run steps 1-5 of the module doc. `items` are this run's feed items.
pub fn sync(store: &mut Store, tracker: &mut dyn Tracker, items: &[Item], now: DateTime<Utc>) -> SyncReport {
    let mut rep = SyncReport::default();
    let recovered_before = tracker.recovered();
    round(store, tracker, items, now, &mut rep);
    rep.recovered = tracker.recovered().saturating_sub(recovered_before);
    store.save();
    rep
}

/// Steps 1-4. Every tracker error goes to `rep.errors`; one that `repeats` ends
/// steps 2-3, and step 4 is tried in any case.
fn round(store: &mut Store, tracker: &mut dyn Tracker, items: &[Item], now: DateTime<Utc>, rep: &mut SyncReport) {
    store.refresh_pending(items, now);

    if store.assign_create_ids(new_issue_id) > 0 {
        store.save(); // on disk before any create sends them
    }
    let pending: Vec<(String, Item, Match, String)> = store
        .pending_issues()
        .into_iter()
        .map(|(k, it, m)| (k.to_string(), it.clone(), m.clone(), store.create_id(k).unwrap_or_default().to_string()))
        .collect();
    let mut halted = false;
    for (key, item, m, id) in pending {
        let created = match tracker.create_issue(&item, &m, &id) {
            Err(TrackerError::IdTaken(_)) => {
                // The id's issue was deleted and Linear keeps the id: file the item under a new one.
                let fresh = new_issue_id();
                store.renew_create_id(&key, fresh.clone(), now);
                store.save();
                tracker.create_issue(&item, &m, &fresh)
            }
            r => r,
        };
        let issue = match created {
            Ok(issue) => issue,
            Err(e) => {
                rep.errors.push(format!("create issue for {key}: {e}"));
                if repeats(&e) {
                    halted = true;
                    break;
                }
                continue;
            }
        };
        let identifier = issue.identifier.clone();
        if !store.set_issue(&key, issue, now) {
            // Cannot happen (pending records have no issue); never lose the created one silently.
            rep.errors.push(format!("created {identifier} for {key} but the store refused it"));
            continue;
        }
        store.save();
        rep.created += 1;
    }

    if !halted {
        for (item, issue) in store.changed_items(items) {
            match tracker.comment(&issue, &update_comment(item)) {
                Ok(()) => {
                    store.mark_commented(item, now);
                    rep.commented += 1;
                }
                Err(e) => {
                    // The fingerprint stays, so the comment is tried again next run.
                    rep.errors.push(format!("comment on {}: {e}", issue.identifier));
                    if repeats(&e) {
                        break;
                    }
                }
            }
        }
    }

    let issues = store.issues();
    if !issues.is_empty() {
        match tracker.fetch_states(&issues) {
            Ok(states) => rep.updated = store.apply_statuses(&states, now),
            Err(e) => rep.errors.push(format!("read issue states: {e}")),
        }
    }
}

/// True for an error every further call of this run would hit as well: no
/// answer, rate limit, HTTP error, `AUTHENTICATION*` or `FORBIDDEN`, settings.
/// Steps 2-3 stop there; with an HTTP timeout of 90 s (feeds/common.rs), trying
/// each remaining item could hold the run for long. False for an error of the
/// item or issue at hand (`INPUT_ERROR`, an unexpected reply, an id still taken
/// after the retry): it is recorded and the next item is tried. A GraphQL error
/// with none of these codes counts as repeating, and so does Linear's
/// `INPUT_ERROR` "Entity not found: Team".
fn repeats(e: &TrackerError) -> bool {
    match e {
        TrackerError::Network(_) | TrackerError::RateLimited { .. } | TrackerError::Http { .. }
        | TrackerError::Config(_) => true,
        TrackerError::GraphQl { message, codes } => {
            codes.iter().any(|c| c.starts_with("AUTHENTICATION") || c == "FORBIDDEN")
                || !codes.iter().any(|c| c == "INPUT_ERROR")
                // A wrong LINEAR_TEAM_ID comes as INPUT_ERROR too (tracker.rs, checked on real Linear).
                || message.contains("Entity not found: Team")
        }
        TrackerError::Reply(_) | TrackerError::IdTaken(_) => false,
        #[cfg(test)]
        TrackerError::Fake(_) => true,
    }
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

    /// Tracker that fails on its `fail_at`-th call (0-based) with `err()` and logs every call.
    struct Flaky {
        fail_at: usize,
        err: fn() -> TrackerError,
        calls: Vec<String>,
    }

    fn network() -> TrackerError {
        TrackerError::Network("error sending request: connection refused".into())
    }

    fn input_error() -> TrackerError {
        TrackerError::GraphQl { message: "Argument Validation Error".into(), codes: vec!["INPUT_ERROR".into()] }
    }

    impl Flaky {
        fn new(fail_at: usize, err: fn() -> TrackerError) -> Self {
            Flaky { fail_at, err, calls: vec![] }
        }

        fn call(&mut self, what: String) -> Result<(), TrackerError> {
            self.calls.push(what);
            if self.calls.len() - 1 == self.fail_at { Err((self.err)()) } else { Ok(()) }
        }
    }

    impl Tracker for Flaky {
        fn create_task(&mut self, _spec: &crate::triage::tracker::TaskSpec, _id: &str) -> Result<IssueRef, TrackerError> {
            Err(TrackerError::Reply("Flaky: no tasks".into()))
        }

        fn create_issue(&mut self, item: &Item, _m: &Match, _id: &str) -> Result<IssueRef, TrackerError> {
            self.call(format!("create {}", item.id))?;
            let n = &item.id[10..]; // NCSC-2026-0464 -> SEC-0464
            Ok(IssueRef { id: format!("id-{n}"), identifier: format!("SEC-{n}"), url: format!("https://linear.app/x/issue/SEC-{n}") })
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

    /// A repeating error ends creates and comments but not the read-back; what
    /// succeeded is kept and saved, and later runs pick up the rest.
    #[test]
    fn repeating_error_stops_creates_keeps_progress_and_reads_back() {
        let _t = state::testing::temp_state("triage-sync-fail");
        let ids = ["NCSC-2026-0464", "NCSC-2026-0465", "NCSC-2026-0466"];
        let items: Vec<Item> = ids.iter().map(|i| item(i)).collect();
        let mut s = store_with(&ids);

        // Second create fails: no third create, the first issue is kept, saved and read back.
        let mut tr = Flaky::new(1, network);
        let r = sync(&mut s, &mut tr, &items, at(3, 12));
        assert_eq!(tr.calls, ["create NCSC-2026-0464", "create NCSC-2026-0465", "fetch 1"]);
        assert_eq!((r.created, r.commented, r.updated), (1, 0, 1));
        assert_eq!(r.errors, ["create issue for NCSC-NL:NCSC-2026-0465: \
                               Linear: network error: error sending request: connection refused"]);
        assert_eq!(r.note(), "tracker: 1 created, 0 commented, 1 updated; error: create issue for \
                              NCSC-NL:NCSC-2026-0465: Linear: network error: error sending request: connection refused");
        assert_eq!(Store::load().unwrap(), s);
        assert_eq!(s.pending_issues().len(), 2);

        // Next run: only the two missing issues are created, a changed item gets its
        // comment, then the state read fails.
        let mut changed = items.clone();
        changed[0].score = 7.5;
        let mut tr = Flaky::new(3, network);
        let r = sync(&mut s, &mut tr, &changed, at(3, 13));
        assert_eq!(tr.calls, ["create NCSC-2026-0465", "create NCSC-2026-0466", "comment SEC-0464", "fetch 3"]);
        assert_eq!((r.created, r.commented, r.updated), (2, 1, 0));
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].starts_with("read issue states: Linear: network error"), "{:?}", r.errors);
        assert!(s.pending_issues().is_empty());
        assert_eq!(Store::load().unwrap(), s);

        // A comment failure leaves the fingerprint alone, so the comment is retried next
        // run; the states are still read (the two issues of the failed read get theirs).
        changed[0].score = 8.0;
        let mut tr = Flaky::new(0, network);
        let r = sync(&mut s, &mut tr, &changed, at(3, 14));
        assert_eq!(tr.calls, ["comment SEC-0464", "fetch 3"]);
        assert_eq!((r.commented, r.updated, r.errors.len()), (0, 2, 1));
        assert!(r.errors[0].starts_with("comment on SEC-0464: Linear: network error"), "{:?}", r.errors);
        let r = sync(&mut s, &mut Flaky::new(99, network), &changed, at(3, 15));
        assert_eq!((r.commented, r.updated, r.errors.len()), (1, 0, 0));
    }

    /// A network error on a create: no further create or comment, one state read.
    #[test]
    fn network_error_stops_creating_but_still_reads_back() {
        let _t = state::testing::temp_state("triage-sync-network");
        let ids = ["NCSC-2026-0464", "NCSC-2026-0465", "NCSC-2026-0466"];
        let mut s = store_with(&ids);
        let filed = IssueRef { id: "id-0464".into(), identifier: "SEC-0464".into(),
                               url: "https://linear.app/x/issue/SEC-0464".into() };
        assert!(s.set_issue("NCSC-NL:NCSC-2026-0464", filed, at(3, 9)));
        let mut changed: Vec<Item> = ids.iter().map(|i| item(i)).collect();
        changed[0].score = 7.5; // would get a comment

        let mut tr = Flaky::new(0, network);
        let r = sync(&mut s, &mut tr, &changed, at(3, 12));
        assert_eq!(tr.calls, ["create NCSC-2026-0465", "fetch 1"]);
        assert_eq!((r.created, r.commented, r.updated, r.errors.len()), (0, 0, 1, 1));
        assert_eq!(s.records["NCSC-NL:NCSC-2026-0464"].issue_status.as_ref().unwrap().state_name, "Triage");
        assert_eq!(s.pending_issues().len(), 2);
        assert_eq!(Store::load().unwrap(), s);
    }

    /// An error of one item (INPUT_ERROR, an odd reply) skips that item only.
    #[test]
    fn item_error_skips_that_item_and_goes_on() {
        let _t = state::testing::temp_state("triage-sync-item");
        let ids = ["NCSC-2026-0464", "NCSC-2026-0465", "NCSC-2026-0466"];
        let items: Vec<Item> = ids.iter().map(|i| item(i)).collect();
        let mut s = store_with(&ids);

        let mut tr = Flaky::new(1, input_error);
        let r = sync(&mut s, &mut tr, &items, at(3, 12));
        assert_eq!(tr.calls, ["create NCSC-2026-0464", "create NCSC-2026-0465", "create NCSC-2026-0466", "fetch 2"]);
        assert_eq!((r.created, r.commented, r.updated), (2, 0, 2));
        assert_eq!(r.errors, ["create issue for NCSC-NL:NCSC-2026-0465: Linear: GraphQL errors: Argument Validation Error"]);
        assert_eq!(s.pending_issues().len(), 1);
        assert_eq!(Store::load().unwrap(), s);

        // Comments: the failing one is skipped, the next is sent, the states are read.
        let mut changed = items.clone();
        changed[0].score = 7.5;
        changed[2].score = 7.5;
        let mut tr = Flaky::new(1, || TrackerError::Reply("commentCreate on SEC-0464: success is not true".into()));
        let r = sync(&mut s, &mut tr, &changed, at(3, 13));
        assert_eq!(tr.calls, ["create NCSC-2026-0465", "comment SEC-0464", "comment SEC-0466", "fetch 3"]);
        assert_eq!((r.created, r.commented, r.updated), (1, 1, 1));
        assert_eq!(r.errors, ["comment on SEC-0464: Linear: unexpected reply to commentCreate on SEC-0464: success is not true"]);
        assert_eq!(s.changed_items(&changed).len(), 1, "SEC-0464 is commented on next run");
    }

    #[test]
    fn which_errors_repeat() {
        let gql = |m: &str, c: &[&str]| TrackerError::GraphQl { message: m.into(), codes: c.iter().map(|s| s.to_string()).collect() };
        for e in [network(), TrackerError::Http { status: 502, body: "".into() },
                  TrackerError::RateLimited { message: "".into(), limits: "".into() }, TrackerError::Config("".into()),
                  gql("x", &["AUTHENTICATION_ERROR"]), gql("x", &["FORBIDDEN"]), gql("x", &["INPUT_ERROR", "FORBIDDEN"]),
                  gql("x", &["INTERNAL_SERVER_ERROR"]), gql("x", &[]),
                  gql("teams: Entity not found: Team (wrong LINEAR_TEAM_ID…)", &["INPUT_ERROR"])] {
            assert!(repeats(&e), "{e:?}");
        }
        for e in [input_error(), TrackerError::Reply("".into()), TrackerError::IdTaken("".into())] {
            assert!(!repeats(&e), "{e:?}");
        }
    }

    // ------------------------------------------------ lost answers, over a Linear-like transport

    /// What the fake Linear server holds: issue ids (in creation order), ids that
    /// are taken by deleted issues, the answers to lose, and every operation seen.
    #[derive(Default)]
    struct Server {
        issues: Vec<String>,
        deleted: Vec<String>,
        lose_creates: usize,
        /// Creates whose title contains one of these are refused with INPUT_ERROR.
        refuse: Vec<String>,
        ops: Vec<String>,
    }

    /// Transport that answers like Linear did on 2026-11-05: IssueCreate stores input.id, a
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
                    let title = body["variables"]["input"]["title"].as_str().unwrap_or("");
                    if s.refuse.iter().any(|r| title.contains(r.as_str())) {
                        return ok(json!({"errors": [{"message": "Argument Validation Error", "path": ["issueCreate"],
                                                     "extensions": {"code": "INPUT_ERROR", "userError": true}}],
                                         "data": null}));
                    }
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
    /// error, stops creating and keeps the id on disk; the next run sends the same id, gets the
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
        // A network error repeats: the second item is not tried; no issue is known yet, so nothing to read back.
        assert_eq!(server.lock().unwrap().ops, ["TriageState", "IssueCreate"]);
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

    /// Over the Linear client: a create refused with INPUT_ERROR is recorded, the
    /// next item is still filed and both issues' states are read back.
    #[test]
    fn refused_create_does_not_stop_the_round() {
        let _t = state::testing::temp_state("triage-sync-refused");
        let ids = ["NCSC-2026-0464", "NCSC-2026-0465", "NCSC-2026-0466"];
        let items: Vec<Item> = ids.iter().map(|i| item(i)).collect();
        let mut s = store_with(&ids);
        let server = Arc::new(Mutex::new(Server { refuse: vec!["NCSC-2026-0464".into()], ..Default::default() }));
        let r = sync(&mut s, &mut fake_linear(&server), &items, at(3, 12));
        assert_eq!((r.created, r.updated), (2, 2));
        assert_eq!(r.errors, ["create issue for NCSC-NL:NCSC-2026-0464: \
                               Linear: GraphQL errors: issueCreate: Argument Validation Error"]);
        assert_eq!(server.lock().unwrap().ops, ["TriageState", "IssueCreate", "IssueCreate", "IssueCreate", "IssueStates"]);
        assert!(s.records["NCSC-NL:NCSC-2026-0464"].issue.is_none());
        assert_eq!(s.untriaged(at(3, 12)).len(), 3, "the refused item stays on the page as pending");
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
