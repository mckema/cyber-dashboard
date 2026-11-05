//! Triage state: STATE_DIR/triage.json, one record per new item key.
//!
//!   {
//!    "CISA KEV:CVE-2026-1234": {
//!     "first_seen": "2026-11-03T08:00:00Z",
//!     "decision": {"decision": "matched", "component": "fairct-scorer", "rule": "package", "evidence": "rust:tokio"},
//!     "issue_create_id": "5f0c…-4…",     UUID v4 sent as IssueCreateInput.id; set and saved
//!                                        before the first create, absent on records without one
//!     "issue": {"id": "…", "identifier": "CTP-123", "url": "https://linear.app/…"},      null until created
//!     "issue_status": {"state": "accepted", "assignee": "…", "due": "2026-11-10", …},  null until read back
//!     "item_fingerprint": "3f9c…",       hash of the item fields that matter; a change -> comment
//!     "updated": "2026-11-03T08:00:00Z", last change of this record
//!     "item": {"source": "CISA KEV", "id": "CVE-2026-1234", "url": "…", "title": "…", …}
//!                                        the item as last seen (feeds/common.rs Item): the issue
//!                                        is created from it and the page tables show it, also
//!                                        after the item has left the 7-day feed window
//!    },
//!    "GitHub:GHSA-…": {"decision": {"decision": "not-relevant-by-rule", "triager": "matcher 1/3"}, …}
//!   }
//!
//! The store is what keeps one issue per item: an issue is created only for a
//! matched record without one, and set_issue() refuses a second. Save it right
//! after each create, so a crash between create and save cannot cause a duplicate
//! (sync.rs does). A create whose answer is lost is covered by issue_create_id:
//! assign_create_ids() gives each pending record its id once, sync saves it
//! before the first create, and every retry sends the same id, which Linear
//! refuses to insert twice (tracker.rs).
//!
//! FR-A2 "triaged within 1 business day" is counted in Amsterdam local time
//! (Ediphy), Monday to Friday, no holiday calendar: business_time() / is_overdue().
//!
//! Everything here is pure except load()/save(); the clock is a parameter.
//! Records are kept 30 days (like seen.json) unless their ticket is still open or
//! their triage is incomplete (declined without a reason).

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveDateTime, Utc, Weekday};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::tracker::{IssueRef, IssueState, IssueStatus};
use super::types::{Decision, Match};
use crate::feeds::common::{Fatal, Item, iso_utc, parse_iso};
use crate::feeds::state;

pub const FILE: &str = "triage.json";
/// Same retention as seen.json.
pub const KEEP_DAYS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub first_seen: String,
    pub decision: Decision,
    /// The id every issueCreate for this record sends (UUID v4), so a retry after a
    /// lost answer cannot file a second issue. Kept after the issue is created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_create_id: Option<String>,
    #[serde(default)]
    pub issue: Option<IssueRef>,
    #[serde(default)]
    pub issue_status: Option<IssueStatus>,
    pub item_fingerprint: String,
    pub updated: String,
    /// The item as last seen: at first sight, refreshed while no issue exists
    /// (refresh_pending) and after each update comment (mark_commented).
    pub item: Item,
}

impl Record {
    pub fn matched(&self) -> Option<&Match> {
        match &self.decision {
            Decision::Matched(m) => Some(m),
            Decision::NotRelevantByRule { .. } => None,
        }
    }

    pub fn state(&self) -> Option<IssueState> {
        self.issue_status.as_ref().map(|s| s.state)
    }

    pub fn title(&self) -> &str {
        &self.item.title
    }

    pub fn url(&self) -> &str {
        &self.item.url
    }

    /// Declined in the tracker with no reason. FR-A2 asks for one, so the triage is
    /// not complete; Linear does not require it, so this is a warning only.
    pub fn declined_without_reason(&self) -> bool {
        self.issue_status.as_ref().is_some_and(|s| s.state == IssueState::Declined && s.reason.trim().is_empty())
    }
}

/// A matched item whose triage is not complete: no issue, the issue is still in
/// Triage, or it was declined without a reason.
#[derive(Debug, Clone, PartialEq)]
pub struct Untriaged<'a> {
    pub key: &'a str,
    pub record: &'a Record,
    /// More than one business day since first_seen: shown red.
    pub overdue: bool,
    /// Declined in the tracker, but no reason was given (Record::declined_without_reason).
    pub no_reason: bool,
}

/// Triage the tracker let through incomplete (FR-A2/A3). Warnings only: nothing is
/// blocked and nothing is written back to the tracker.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Gaps {
    /// Open tickets (Store::open_tickets) with no assignee.
    pub missing_owner: usize,
    /// Open tickets with no due date.
    pub missing_due: usize,
    /// Matched records declined without a reason.
    pub missing_reason: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Store {
    pub records: BTreeMap<String, Record>,
}

/// Hash of the item fields whose change is worth a comment on the issue.
pub fn fingerprint(item: &Item) -> String {
    let v = json!([item.title, item.url, item.updated, item.cves, item.score, item.severity]);
    hex::encode(&Sha256::digest(v.to_string().as_bytes())[..8])
}

// ---------------------------------------------------------------- Amsterdam business time

/// Last Sunday of March or October (both have 31 days).
fn last_sunday(year: i32, month: u32) -> NaiveDate {
    let last = NaiveDate::from_ymd_opt(year, month, 31).expect("March or October");
    last - Duration::days(i64::from(last.weekday().num_days_from_sunday()))
}

/// Amsterdam's UTC offset at `t`, by the EU rule (no tz database): CEST = UTC+2
/// from 01:00 UTC on the last Sunday of March to 01:00 UTC on the last Sunday of
/// October, CET = UTC+1 otherwise.
pub fn amsterdam_offset(t: DateTime<Utc>) -> Duration {
    let switch = |month| last_sunday(t.year(), month).and_hms_opt(1, 0, 0).unwrap().and_utc();
    if switch(3) <= t && t < switch(10) { Duration::hours(2) } else { Duration::hours(1) }
}

/// Amsterdam wall-clock time at `t`.
pub fn to_amsterdam(t: DateTime<Utc>) -> NaiveDateTime {
    t.naive_utc() + amsterdam_offset(t)
}

/// The instant of an Amsterdam wall-clock time. A time in the autumn hour that
/// occurs twice is its first (CEST) occurrence; one in the spring hour that does
/// not exist comes out an hour later. Midnight is never either.
pub fn from_amsterdam(local: NaiveDateTime) -> DateTime<Utc> {
    let cest = (local - Duration::hours(2)).and_utc();
    if amsterdam_offset(cest) == Duration::hours(2) { cest } else { (local - Duration::hours(1)).and_utc() }
}

/// Time between `start` and `end` that falls on Monday to Friday in Amsterdam
/// local time (no holiday calendar). Zero when end <= start.
pub fn business_time(start: DateTime<Utc>, end: DateTime<Utc>) -> Duration {
    let mut total = Duration::zero();
    let mut t = start;
    while t < end {
        let local = to_amsterdam(t);
        let midnight = from_amsterdam((local.date() + Duration::days(1)).and_hms_opt(0, 0, 0).unwrap());
        let seg_end = midnight.min(end);
        if !matches!(local.weekday(), Weekday::Sat | Weekday::Sun) {
            total += seg_end - t;
        }
        t = seg_end;
    }
    total
}

/// More than one business day since `first_seen`. An unreadable time counts as overdue.
pub fn is_overdue(first_seen: &str, now: DateTime<Utc>) -> bool {
    parse_iso(first_seen).is_none_or(|t| business_time(t, now) > Duration::days(1))
}

// ---------------------------------------------------------------- store

impl Store {
    /// The store, or an empty one when the file does not exist. Err when it does
    /// not parse: starting empty would create a second issue for every item.
    pub fn load() -> Result<Self, Fatal> {
        let Some(raw) = state::load_bytes(FILE) else {
            return Ok(Self::default());
        };
        serde_json::from_slice(&raw)
            .map_err(|e| Fatal(format!("{}/{FILE} is not valid ({e}); fix or remove it", state::dir().display())))
    }

    pub fn save(&self) {
        state::save_json(FILE, self);
    }

    /// Record the matcher's decision for a new item. False (and no change) when
    /// the key already has a record: the first decision stands.
    pub fn record_decision(&mut self, item: &Item, decision: Decision, now: DateTime<Utc>) -> bool {
        let key = item.key();
        if self.records.contains_key(&key) {
            return false;
        }
        let stamp = iso_utc(now);
        self.records.insert(key, Record {
            first_seen: stamp.clone(), decision, issue_create_id: None, issue: None, issue_status: None,
            item_fingerprint: fingerprint(item), updated: stamp, item: item.clone(),
        });
        true
    }

    /// Records without an issue take the current version of their item from this
    /// run, so the issue is created from the latest fields (nothing to comment on
    /// yet). Items that left the window keep their snapshot. Returns how many changed.
    pub fn refresh_pending(&mut self, items: &[Item], now: DateTime<Utc>) -> usize {
        let mut n = 0;
        for it in items {
            let Some(r) = self.records.get_mut(&it.key()) else { continue };
            if r.issue.is_some() || r.item == *it {
                continue;
            }
            r.item_fingerprint = fingerprint(it);
            r.item = it.clone();
            r.updated = iso_utc(now);
            n += 1;
        }
        n
    }

    /// Matched records that still need an issue: (key, item snapshot, match),
    /// oldest first. The snapshot is enough to create the issue, so a create that
    /// failed earlier is retried even after the item has left the feed window.
    pub fn pending_issues(&self) -> Vec<(&str, &Item, &Match)> {
        let mut v: Vec<(&str, &Record, &Match)> = self
            .records
            .iter()
            .filter(|(_, r)| r.issue.is_none())
            .filter_map(|(k, r)| r.matched().map(|m| (k.as_str(), r, m)))
            .collect();
        v.sort_by(|a, b| a.1.first_seen.cmp(&b.1.first_seen).then(a.0.cmp(b.0)));
        v.into_iter().map(|(k, r, m)| (k, &r.item, m)).collect()
    }

    /// Give every pending record (pending_issues) without an issue_create_id one
    /// from `new_id`. Save before sending any of them. Returns how many were set.
    pub fn assign_create_ids(&mut self, mut new_id: impl FnMut() -> String) -> usize {
        let mut n = 0;
        for r in self.records.values_mut() {
            if r.issue.is_none() && r.issue_create_id.is_none() && r.matched().is_some() {
                r.issue_create_id = Some(new_id());
                n += 1;
            }
        }
        n
    }

    /// The id the next issueCreate for `key` sends.
    pub fn create_id(&self, key: &str) -> Option<&str> {
        self.records.get(key)?.issue_create_id.as_deref()
    }

    /// Replace the create id of a record without an issue (its old id belongs to a
    /// deleted issue). False when the key is unknown or already has an issue.
    pub fn renew_create_id(&mut self, key: &str, id: String, now: DateTime<Utc>) -> bool {
        match self.records.get_mut(key) {
            Some(r) if r.issue.is_none() => {
                r.issue_create_id = Some(id);
                r.updated = iso_utc(now);
                true
            }
            _ => false,
        }
    }

    /// Attach the created issue. False when the key is unknown or already has an issue.
    pub fn set_issue(&mut self, key: &str, issue: IssueRef, now: DateTime<Utc>) -> bool {
        match self.records.get_mut(key) {
            Some(r) if r.issue.is_none() => {
                r.issue = Some(issue);
                r.updated = iso_utc(now);
                true
            }
            _ => false,
        }
    }

    /// Items of this run that have an issue and changed since it was created or
    /// last commented on. After commenting, call mark_commented().
    pub fn changed_items<'a>(&self, items: &'a [Item]) -> Vec<(&'a Item, IssueRef)> {
        items
            .iter()
            .filter_map(|it| {
                let r = self.records.get(&it.key())?;
                let issue = r.issue.as_ref()?;
                (r.item_fingerprint != fingerprint(it)).then(|| (it, issue.clone()))
            })
            .collect()
    }

    /// The item's current fields are now known to the issue.
    pub fn mark_commented(&mut self, item: &Item, now: DateTime<Utc>) {
        if let Some(r) = self.records.get_mut(&item.key()) {
            r.item_fingerprint = fingerprint(item);
            r.item = item.clone();
            r.updated = iso_utc(now);
        }
    }

    /// Every issue in the store, for fetch_states(). Closed ones are included so a
    /// reopened issue is noticed.
    pub fn issues(&self) -> Vec<IssueRef> {
        self.records.values().filter_map(|r| r.issue.clone()).collect()
    }

    /// Store what the tracker said. Matches on IssueRef.id; the ref itself is
    /// refreshed too (identifier and URL change when an issue moves team).
    /// Returns how many records changed.
    pub fn apply_statuses(&mut self, statuses: &[(IssueRef, IssueStatus)], now: DateTime<Utc>) -> usize {
        let mut n = 0;
        for r in self.records.values_mut() {
            let Some(id) = r.issue.as_ref().map(|i| i.id.clone()) else { continue };
            let Some((iref, st)) = statuses.iter().find(|(i, _)| i.id == id) else { continue };
            if r.issue.as_ref() != Some(iref) || r.issue_status.as_ref() != Some(st) {
                r.issue = Some(iref.clone());
                r.issue_status = Some(st.clone());
                r.updated = iso_utc(now);
                n += 1;
            }
        }
        n
    }

    /// Matched items not yet triaged, oldest first. An item declined without a reason
    /// counts as not triaged (FR-A2 asks for a reason); it leaves once one is added.
    pub fn untriaged(&self, now: DateTime<Utc>) -> Vec<Untriaged<'_>> {
        let mut v: Vec<Untriaged> = self
            .records
            .iter()
            .filter(|(_, r)| {
                r.matched().is_some()
                    && (matches!(r.state(), None | Some(IssueState::Triage)) || r.declined_without_reason())
            })
            .map(|(k, r)| Untriaged {
                key: k, record: r, overdue: is_overdue(&r.first_seen, now), no_reason: r.declined_without_reason(),
            })
            .collect();
        v.sort_by(|a, b| a.record.first_seen.cmp(&b.record.first_seen).then(a.key.cmp(b.key)));
        v
    }

    /// Accepted, not yet done: by due date (none last), then first_seen.
    pub fn open_tickets(&self) -> Vec<(&str, &Record)> {
        let mut v: Vec<(&str, &Record)> = self
            .records
            .iter()
            .filter(|(_, r)| r.state() == Some(IssueState::Accepted))
            .map(|(k, r)| (k.as_str(), r))
            .collect();
        let due = |r: &Record| r.issue_status.as_ref().map(|s| s.due.clone()).filter(|d| !d.is_empty());
        v.sort_by(|a, b| {
            let (da, db) = (due(a.1), due(b.1));
            (da.is_none(), da, &a.1.first_seen, a.0).cmp(&(db.is_none(), db, &b.1.first_seen, b.0))
        });
        v
    }

    /// Open tickets without an owner or a due date, and declines without a reason.
    pub fn gaps(&self) -> Gaps {
        let blank = |r: &Record, f: fn(&IssueStatus) -> &str| r.issue_status.as_ref().is_none_or(|s| f(s).trim().is_empty());
        let open = self.open_tickets();
        Gaps {
            missing_owner: open.iter().filter(|(_, r)| blank(r, |s| s.assignee.as_str())).count(),
            missing_due: open.iter().filter(|(_, r)| blank(r, |s| s.due.as_str())).count(),
            missing_reason: self.records.values().filter(|r| r.matched().is_some() && r.declined_without_reason()).count(),
        }
    }

    /// Drop records first seen more than KEEP_DAYS ago that need nothing more:
    /// not relevant by rule, or the issue is done/declined with a reason. Matched
    /// records whose issue is missing, untriaged, open or declined without a reason
    /// stay. Returns how many were dropped.
    pub fn prune(&mut self, now: DateTime<Utc>) -> usize {
        let cutoff = iso_utc(now - Duration::days(KEEP_DAYS));
        let before = self.records.len();
        self.records.retain(|_, r| {
            let finished = r.matched().is_none()
                || (r.state().is_some_and(IssueState::is_closed) && !r.declined_without_reason());
            !(finished && r.first_seen < cutoff)
        });
        before - self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::triage::sync::sync;
    use crate::triage::tracker::FakeTracker;

    fn at(d: u32, h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, d, h, m, 0).unwrap() // 2026-11-02 is a Monday
    }

    fn utc(s: &str) -> DateTime<Utc> {
        parse_iso(s).unwrap()
    }

    /// Amsterdam wall-clock time -> instant.
    fn ams(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        from_amsterdam(NaiveDate::from_ymd_opt(y, mo, d).unwrap().and_hms_opt(h, mi, 0).unwrap())
    }

    fn item(id: &str) -> Item {
        let mut it = Item::new("CISA KEV", id, &format!("https://www.cve.org/CVERecord?id={id}"), &format!("{id}: flaw"), "2026-11-03");
        it.cves = vec![id.into()];
        it
    }

    fn matched(c: &str) -> Decision {
        Decision::Matched(Match { component: c.into(), rule: "cve-join".into(), evidence: "CVE-x".into() })
    }

    fn not_relevant() -> Decision {
        Decision::NotRelevantByRule { triager: "matcher 1/3".into() }
    }

    fn iref(n: u32) -> IssueRef {
        IssueRef { id: format!("uuid-{n}"), identifier: format!("CTP-{n}"), url: format!("https://linear.app/x/issue/CTP-{n}") }
    }

    /// A complete triage: an owner, and for a decline a reason.
    fn status(state: IssueState, due: &str) -> IssueStatus {
        let reason = if state == IssueState::Declined { "not shipped" } else { "" };
        IssueStatus { state, state_name: String::new(), assignee: "Henry".into(), due: due.into(), reason: reason.into(),
                      actor: String::new(), changed: String::new() }
    }

    fn with(mut st: IssueStatus, assignee: &str, reason: &str) -> IssueStatus {
        st.assignee = assignee.into();
        st.reason = reason.into();
        st
    }

    #[test]
    fn amsterdam_offset_follows_eu_rule() {
        let h = Duration::hours;
        assert_eq!(last_sunday(2026, 3), NaiveDate::from_ymd_opt(2026, 3, 29).unwrap());
        assert_eq!(last_sunday(2026, 10), NaiveDate::from_ymd_opt(2026, 10, 25).unwrap());
        assert_eq!(last_sunday(2027, 3), NaiveDate::from_ymd_opt(2027, 3, 28).unwrap());
        assert_eq!(last_sunday(2027, 10), NaiveDate::from_ymd_opt(2027, 10, 31).unwrap(), "the 31st itself is a Sunday");

        assert_eq!(amsterdam_offset(utc("2026-01-15T12:00:00Z")), h(1));
        assert_eq!(amsterdam_offset(utc("2026-03-29T00:59:59Z")), h(1));
        assert_eq!(amsterdam_offset(utc("2026-03-29T01:00:00Z")), h(2));
        assert_eq!(amsterdam_offset(utc("2026-07-01T12:00:00Z")), h(2));
        assert_eq!(amsterdam_offset(utc("2026-10-25T00:59:59Z")), h(2));
        assert_eq!(amsterdam_offset(utc("2026-10-25T01:00:00Z")), h(1));
        assert_eq!(amsterdam_offset(utc("2026-12-31T23:30:00Z")), h(1));

        let local = |s: &str| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap();
        assert_eq!(to_amsterdam(utc("2026-07-01T10:00:00Z")), local("2026-07-01 12:00"));
        assert_eq!(to_amsterdam(utc("2026-12-31T23:30:00Z")), local("2027-01-01 00:30"));
        assert_eq!(from_amsterdam(local("2026-11-09 00:00")), utc("2026-11-08T23:00:00Z"));
        assert_eq!(from_amsterdam(local("2026-07-01 00:00")), utc("2026-06-30T22:00:00Z"));
        assert_eq!(from_amsterdam(local("2026-10-25 02:30")), utc("2026-10-25T00:30:00Z"), "repeated hour: first one");
        assert_eq!(from_amsterdam(local("2026-10-25 03:00")), utc("2026-10-25T02:00:00Z"));
        assert_eq!(from_amsterdam(local("2026-03-29 02:30")), utc("2026-03-29T01:30:00Z"), "missing hour: one later");
        assert_eq!(from_amsterdam(local("2026-03-29 03:00")), utc("2026-03-29T01:00:00Z"));
    }

    #[test]
    fn business_time_weekends_and_edges() {
        let h = Duration::hours;
        assert_eq!(business_time(ams(2026, 11, 3, 10, 0), ams(2026, 11, 4, 10, 0)), h(24)); // Tue -> Wed
        assert_eq!(business_time(ams(2026, 11, 6, 10, 0), ams(2026, 11, 9, 10, 0)), h(24)); // Fri -> Mon
        assert_eq!(business_time(ams(2026, 11, 7, 9, 0), ams(2026, 11, 8, 23, 0)), h(0)); // Sat -> Sun
        assert_eq!(business_time(ams(2026, 11, 7, 9, 0), ams(2026, 11, 9, 6, 0)), h(6)); // Sat -> Mon morning
        assert_eq!(business_time(ams(2026, 11, 2, 0, 0), ams(2026, 11, 16, 0, 0)), h(240)); // two full weeks
        assert_eq!(business_time(at(4, 0, 0), at(3, 0, 0)), h(0));
        // Days are Amsterdam days, not UTC days: Fri 23:30 UTC is already Saturday there,
        // Sun 23:30 UTC is already Monday.
        assert_eq!(business_time(utc("2026-11-06T23:30:00Z"), utc("2026-11-09T00:00:00Z")), h(1));
        assert_eq!(business_time(utc("2026-11-06T22:30:00Z"), utc("2026-11-06T23:30:00Z")), Duration::minutes(30));
        assert_eq!(business_time(utc("2026-11-08T22:00:00Z"), utc("2026-11-08T23:30:00Z")), Duration::minutes(30));
    }

    #[test]
    fn business_time_over_dst_weekends() {
        let h = Duration::hours;
        // Weekends only, including the switch nights: nothing counts.
        assert_eq!(business_time(ams(2026, 10, 24, 0, 0), ams(2026, 10, 26, 0, 0)), h(0));
        assert_eq!(business_time(ams(2026, 3, 28, 0, 0), ams(2026, 3, 30, 0, 0)), h(0));
        // Friday counts 24 h although 73 h (autumn) or 71 h (spring) pass on the wall clock.
        assert_eq!(ams(2026, 10, 26, 0, 0) - ams(2026, 10, 23, 0, 0), h(73));
        assert_eq!(business_time(ams(2026, 10, 23, 0, 0), ams(2026, 10, 26, 0, 0)), h(24));
        assert_eq!(ams(2026, 3, 30, 0, 0) - ams(2026, 3, 27, 0, 0), h(71));
        assert_eq!(business_time(ams(2026, 3, 27, 0, 0), ams(2026, 3, 30, 0, 0)), h(24));

        // Autumn: Fri 2026-10-23 17:00 CEST (15:00Z) -> due Mon 2026-10-26 17:00 CET (16:00Z).
        let fri = "2026-10-23T15:00:00Z";
        assert_eq!(business_time(utc(fri), utc("2026-10-26T16:00:00Z")), h(24));
        assert!(!is_overdue(fri, utc("2026-10-26T16:00:00Z")));
        assert!(is_overdue(fri, utc("2026-10-26T16:00:01Z")));
        // Spring: Fri 2026-03-27 17:00 CET (16:00Z) -> due Mon 2026-03-30 17:00 CEST (15:00Z).
        let fri = "2026-03-27T16:00:00Z";
        assert!(!is_overdue(fri, utc("2026-03-30T15:00:00Z")));
        assert!(is_overdue(fri, utc("2026-03-30T15:00:01Z")));
    }

    #[test]
    fn overdue_after_one_amsterdam_business_day() {
        // Fri 2026-11-06 18:00 CET: 6 h on Friday, the other 18 h on Monday -> Mon 18:00 CET (17:00Z).
        let fri = "2026-11-06T17:00:00Z";
        assert!(!is_overdue(fri, utc("2026-11-09T16:59:59Z")));
        assert!(!is_overdue(fri, utc("2026-11-09T17:00:00Z")), "exactly one business day is not more than one");
        assert!(is_overdue(fri, utc("2026-11-09T17:00:01Z")));
        // Fri 23:30 UTC = Sat 00:30 in Amsterdam: the clock starts Mon 00:00, due Tue 00:00 (Mon 23:00Z).
        let late = "2026-11-06T23:30:00Z";
        assert!(!is_overdue(late, utc("2026-11-09T23:00:00Z")));
        assert!(is_overdue(late, utc("2026-11-09T23:00:01Z")));
        // Sunday noon: same, the clock starts Monday 00:00 Amsterdam.
        let sun = "2026-11-08T12:00:00Z";
        assert!(!is_overdue(sun, utc("2026-11-09T23:00:00Z")));
        assert!(is_overdue(sun, utc("2026-11-09T23:00:01Z")));
        // Sun 23:30 UTC = Mon 00:30 in Amsterdam: due Tue 00:30 (Mon 23:30Z).
        let sun_late = "2026-11-08T23:30:00Z";
        assert!(!is_overdue(sun_late, utc("2026-11-09T23:30:00Z")));
        assert!(is_overdue(sun_late, utc("2026-11-09T23:30:01Z")));
        // Weekday morning.
        assert!(!is_overdue("2026-11-03T08:00:00Z", at(4, 7, 0)));
        assert!(is_overdue("2026-11-03T08:00:00Z", at(4, 9, 0)));
        assert!(is_overdue("garbage", at(4, 9, 0)));
    }

    #[test]
    fn decisions_pending_and_one_issue_per_key() {
        let mut s = Store::default();
        assert!(s.record_decision(&item("CVE-2"), matched("nginx"), at(3, 9, 0)));
        assert!(s.record_decision(&item("CVE-1"), matched("tokio"), at(3, 8, 0)));
        assert!(s.record_decision(&item("CVE-3"), not_relevant(), at(3, 8, 0)));
        assert!(!s.record_decision(&item("CVE-1"), not_relevant(), at(3, 10, 0)), "first decision stands");
        assert_eq!(s.records["CISA KEV:CVE-1"].matched().unwrap().component, "tokio");

        let p: Vec<(&str, &str, &str)> =
            s.pending_issues().into_iter().map(|(k, i, m)| (k, i.id.as_str(), m.component.as_str())).collect();
        assert_eq!(p, [("CISA KEV:CVE-1", "CVE-1", "tokio"), ("CISA KEV:CVE-2", "CVE-2", "nginx")]);
        assert!(s.set_issue("CISA KEV:CVE-1", iref(1), at(3, 8, 1)));
        assert!(!s.set_issue("CISA KEV:CVE-1", iref(9), at(3, 8, 2)), "never a second issue");
        assert!(!s.set_issue("CISA KEV:nope", iref(9), at(3, 8, 2)));
        assert_eq!(s.records["CISA KEV:CVE-1"].issue, Some(iref(1)));
        assert_eq!(s.records["CISA KEV:CVE-1"].updated, "2026-11-03T08:01:00Z");
        assert_eq!(s.pending_issues().len(), 1);
        assert_eq!(s.issues(), vec![iref(1)]);
    }

    #[test]
    fn create_ids_are_assigned_once_and_kept() {
        let t = state::testing::temp_state("triage-create-ids");
        let mut s = Store::default();
        s.record_decision(&item("CVE-1"), matched("c"), at(3, 8, 0));
        s.record_decision(&item("CVE-2"), matched("c"), at(3, 8, 0));
        s.record_decision(&item("CVE-3"), not_relevant(), at(3, 8, 0));
        s.record_decision(&item("CVE-4"), matched("c"), at(3, 8, 0));
        s.set_issue("CISA KEV:CVE-4", iref(4), at(3, 8, 0));
        let mut n = 0;
        let mut gen_id = || {
            n += 1;
            format!("id-{n}")
        };
        assert_eq!(s.assign_create_ids(&mut gen_id), 2, "matched records without an issue only");
        assert_eq!(s.assign_create_ids(&mut gen_id), 0, "an id, once given, is never replaced");
        assert_eq!((s.create_id("CISA KEV:CVE-1"), s.create_id("CISA KEV:CVE-2")), (Some("id-1"), Some("id-2")));
        assert_eq!((s.create_id("CISA KEV:CVE-3"), s.create_id("CISA KEV:CVE-4"), s.create_id("nope")), (None, None, None));

        // Saved with the record; records without one have no such key.
        s.save();
        let j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(t.dir.join(FILE)).unwrap()).unwrap();
        assert_eq!(j["CISA KEV:CVE-1"]["issue_create_id"], "id-1");
        assert!(j["CISA KEV:CVE-3"].get("issue_create_id").is_none());
        assert_eq!(Store::load().unwrap(), s);

        assert!(s.renew_create_id("CISA KEV:CVE-1", "id-9".into(), at(3, 9, 0)));
        assert_eq!(s.create_id("CISA KEV:CVE-1"), Some("id-9"));
        assert!(!s.renew_create_id("CISA KEV:CVE-4", "id-9".into(), at(3, 9, 0)), "not once the issue exists");
        s.set_issue("CISA KEV:CVE-1", iref(1), at(3, 9, 0));
        assert_eq!(s.create_id("CISA KEV:CVE-1"), Some("id-9"), "kept after the issue is created");
    }

    #[test]
    fn snapshot_refresh_and_comment() {
        let mut s = Store::default();
        s.record_decision(&item("CVE-1"), matched("c"), at(3, 8, 0));
        s.record_decision(&item("CVE-2"), matched("c"), at(3, 8, 0));
        s.set_issue("CISA KEV:CVE-2", iref(2), at(3, 8, 0));
        let r = &s.records["CISA KEV:CVE-1"];
        assert_eq!((r.title(), r.url()), ("CVE-1: flaw", "https://www.cve.org/CVERecord?id=CVE-1"));

        // Both items change. Without an issue the snapshot just follows; with one, it waits for the comment.
        let mut now = vec![item("CVE-1"), item("CVE-2"), item("CVE-9")];
        for it in &mut now {
            it.title = format!("{} (updated)", it.title);
        }
        assert_eq!(s.refresh_pending(&now, at(3, 9, 0)), 1);
        assert_eq!(s.refresh_pending(&now, at(3, 9, 30)), 0, "no change, no touch");
        let r = &s.records["CISA KEV:CVE-1"];
        assert_eq!((r.title(), r.updated.as_str()), ("CVE-1: flaw (updated)", "2026-11-03T09:00:00Z"));
        assert_eq!(r.item_fingerprint, fingerprint(&now[0]));
        assert_eq!(s.pending_issues()[0].1, &now[0], "the issue is created from the latest version");
        assert!(!s.records.contains_key("CISA KEV:CVE-9"), "refresh never adds records");

        let changed = s.changed_items(&now);
        assert_eq!(changed, vec![(&now[1], iref(2))]);
        assert_eq!(s.records["CISA KEV:CVE-2"].title(), "CVE-2: flaw");
        s.mark_commented(&now[1], at(3, 10, 0));
        assert_eq!(s.records["CISA KEV:CVE-2"].title(), "CVE-2: flaw (updated)");
        assert!(s.changed_items(&now).is_empty());

        // The item leaves the window: the snapshot stays and is still what pending_issues() yields.
        assert_eq!(s.refresh_pending(&[], at(4, 9, 0)), 0);
        assert_eq!(s.pending_issues()[0].1.title, "CVE-1: flaw (updated)");
    }

    #[test]
    fn statuses_untriaged_and_open_tickets() {
        let mut s = Store::default();
        for (i, d) in [(1, 3), (2, 3), (3, 4), (4, 4), (5, 5)] {
            s.record_decision(&item(&format!("CVE-{i}")), matched("c"), at(d, 8, i));
            s.set_issue(&format!("CISA KEV:CVE-{i}"), iref(i), at(d, 8, i));
        }
        s.record_decision(&item("CVE-6"), matched("c"), at(5, 9, 0)); // no issue yet (tracker off or failed)
        s.record_decision(&item("CVE-7"), not_relevant(), at(3, 0, 0));

        let mut moved = iref(4);
        moved.identifier = "OPS-4".into();
        let st = vec![
            (iref(1), status(IssueState::Triage, "")),
            (iref(2), status(IssueState::Accepted, "")),
            (iref(3), status(IssueState::Accepted, "2026-11-20")),
            (moved.clone(), status(IssueState::Accepted, "2026-11-10")),
            (iref(5), status(IssueState::Declined, "")),
            (iref(99), status(IssueState::Done, "")),
        ];
        assert_eq!(s.apply_statuses(&st, at(5, 10, 0)), 5);
        assert_eq!(s.apply_statuses(&st, at(5, 11, 0)), 0, "unchanged statuses do not touch records");
        assert_eq!(s.records["CISA KEV:CVE-4"].issue, Some(moved));
        assert_eq!(s.records["CISA KEV:CVE-1"].updated, "2026-11-05T10:00:00Z");

        let u = s.untriaged(at(5, 9, 30)); // Thu 09:30
        let rows: Vec<(&str, bool)> = u.iter().map(|r| (r.key, r.overdue)).collect();
        assert_eq!(rows, [("CISA KEV:CVE-1", true), ("CISA KEV:CVE-6", false)]);

        let open: Vec<&str> = s.open_tickets().into_iter().map(|(k, _)| k).collect();
        assert_eq!(open, ["CISA KEV:CVE-4", "CISA KEV:CVE-3", "CISA KEV:CVE-2"]);
        assert_eq!(s.gaps(), Gaps { missing_owner: 0, missing_due: 1, missing_reason: 0 });
    }

    /// FR-A2 asks for a reason on every decline; Linear does not. A decline without one
    /// stays in the untriaged table (red after one business day from first_seen) until a
    /// reason is read back, and is not pruned meanwhile. A duplicate has its own reason.
    #[test]
    fn declined_without_reason_stays_untriaged() {
        let mut s = Store::default();
        for (i, d) in [(1, 2), (2, 5), (3, 2), (4, 2)] {
            s.record_decision(&item(&format!("CVE-{i}")), matched("c"), at(d, 8, 0));
            s.set_issue(&format!("CISA KEV:CVE-{i}"), iref(i), at(d, 8, 0));
        }
        let declined = |reason: &str| with(status(IssueState::Declined, ""), "", reason);
        let st = vec![
            (iref(1), declined("")),
            (iref(2), declined(" \n ")), // whitespace is no reason
            (iref(3), declined(crate::triage::tracker::DUPLICATE_REASON)),
            (iref(4), declined("not shipped")),
        ];
        s.apply_statuses(&st, at(5, 10, 0));
        assert!(s.records["CISA KEV:CVE-1"].declined_without_reason());
        assert!(!s.records["CISA KEV:CVE-3"].declined_without_reason());

        let rows: Vec<(&str, bool, bool)> = s.untriaged(at(5, 10, 0)).iter().map(|u| (u.key, u.overdue, u.no_reason)).collect();
        assert_eq!(rows, [("CISA KEV:CVE-1", true, true), ("CISA KEV:CVE-2", false, true)]);
        assert!(s.open_tickets().is_empty());
        assert_eq!(s.gaps(), Gaps { missing_owner: 0, missing_due: 0, missing_reason: 2 });

        // 30 days on: the complete declines go, the incomplete ones stay.
        assert_eq!(s.prune(at(30, 12, 0) + Duration::days(5)), 2);
        let left: Vec<&str> = s.records.keys().map(String::as_str).collect();
        assert_eq!(left, ["CISA KEV:CVE-1", "CISA KEV:CVE-2"]);

        // A reason added later (a comment in Linear) is read back: triage complete.
        s.apply_statuses(&[(iref(1), declined("vendor build only"))], at(6, 9, 0));
        let keys: Vec<&str> = s.untriaged(at(6, 9, 0)).iter().map(|u| u.key).collect();
        assert_eq!(keys, ["CISA KEV:CVE-2"]);
        assert_eq!(s.gaps().missing_reason, 1);
    }

    /// FR-A3 asks for an owner and a due date on every ticket. Only open tickets count;
    /// a blank or whitespace value is missing.
    #[test]
    fn gaps_count_open_tickets_without_owner_or_due() {
        let mut s = Store::default();
        for i in 1..=6 {
            s.record_decision(&item(&format!("CVE-{i}")), matched("c"), at(3, 8, i));
            s.set_issue(&format!("CISA KEV:CVE-{i}"), iref(i), at(3, 8, i));
        }
        let st = vec![
            (iref(1), with(status(IssueState::Accepted, ""), "", "")),
            (iref(2), with(status(IssueState::Accepted, "2026-11-10"), " ", "")),
            (iref(3), status(IssueState::Accepted, " ")),
            (iref(4), status(IssueState::Accepted, "2026-11-12")),
            (iref(5), with(status(IssueState::Done, ""), "", "")),
            (iref(6), with(status(IssueState::Triage, ""), "", "")),
        ];
        s.apply_statuses(&st, at(4, 9, 0));
        assert_eq!(s.open_tickets().len(), 4);
        assert_eq!(s.gaps(), Gaps { missing_owner: 2, missing_due: 2, missing_reason: 0 });
        assert_eq!(Store::default().gaps(), Gaps::default());
    }

    #[test]
    fn prune_keeps_open_work() {
        let mut s = Store::default();
        let old = at(1, 0, 0);
        let cases = [("CVE-1", matched("c"), Some(IssueState::Done)), ("CVE-2", matched("c"), Some(IssueState::Declined)),
                     ("CVE-3", not_relevant(), None), ("CVE-4", matched("c"), Some(IssueState::Accepted)),
                     ("CVE-5", matched("c"), Some(IssueState::Triage)), ("CVE-6", matched("c"), None)];
        for (i, (id, d, st)) in cases.into_iter().enumerate() {
            s.record_decision(&item(id), d, old);
            if let Some(st) = st {
                let r = s.records.get_mut(&format!("CISA KEV:{id}")).unwrap();
                r.issue = Some(iref(i as u32));
                r.issue_status = Some(status(st, ""));
            }
        }
        s.record_decision(&item("CVE-7"), not_relevant(), at(20, 0, 0));
        assert_eq!(s.prune(at(30, 0, 0)), 0, "29 days: nothing is old enough");
        assert_eq!(s.prune(Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 1).unwrap()), 3);
        let left: Vec<&str> = s.records.keys().map(String::as_str).collect();
        assert_eq!(left, ["CISA KEV:CVE-4", "CISA KEV:CVE-5", "CISA KEV:CVE-6", "CISA KEV:CVE-7"]);
    }

    #[test]
    fn save_load_shape_and_bad_file() {
        let t = state::testing::temp_state("triage-store");
        assert_eq!(Store::load().unwrap(), Store::default());
        let mut s = Store::default();
        s.record_decision(&item("CVE-1"), matched("tokio"), at(3, 8, 0));
        s.record_decision(&item("CVE-2"), not_relevant(), at(3, 8, 0));
        s.set_issue("CISA KEV:CVE-1", iref(1), at(3, 8, 0));
        s.save();
        let j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(t.dir.join(FILE)).unwrap()).unwrap();
        assert_eq!(j["CISA KEV:CVE-1"]["decision"]["decision"], "matched");
        assert_eq!(j["CISA KEV:CVE-1"]["decision"]["component"], "tokio");
        assert_eq!(j["CISA KEV:CVE-1"]["issue"]["identifier"], "CTP-1");
        assert!(j["CISA KEV:CVE-1"]["issue_status"].is_null());
        assert_eq!(j["CISA KEV:CVE-1"]["item"]["title"], "CVE-1: flaw");
        assert_eq!(j["CISA KEV:CVE-1"]["item"]["cves"], json!(["CVE-1"]));
        assert_eq!(j["CISA KEV:CVE-2"]["decision"], json!({"decision": "not-relevant-by-rule", "triager": "matcher 1/3"}));
        assert_eq!(Store::load().unwrap(), s);

        std::fs::write(t.dir.join(FILE), "{\"CISA KEV:CVE-1\": {").unwrap();
        assert!(Store::load().unwrap_err().0.contains("triage.json is not valid"));
    }

    /// The approved flow end to end on the fake tracker: one issue per item, a
    /// changed item becomes a comment, triage done by editing the fake file.
    #[test]
    fn flow_with_fake_tracker() {
        let t = state::testing::temp_state("triage-flow");
        let mut tr = FakeTracker::new();
        let mut s = Store::default();
        let items = vec![item("CVE-1"), item("CVE-2")];
        for it in &items {
            s.record_decision(it, matched("tokio"), at(3, 8, 0));
        }
        let mut run = |s: &mut Store, items: &[Item], now| {
            let r = sync(s, &mut tr, items, now);
            assert!(r.errors.is_empty(), "{:?}", r.errors);
        };

        run(&mut s, &items, at(3, 8, 0));
        run(&mut s, &items, at(3, 9, 0)); // same items again: nothing new
        let f = FakeTracker::load().unwrap();
        assert_eq!(f.issues.len(), 2);
        assert!(f.issues.iter().all(|i| i.comments.is_empty()));
        assert_eq!(s.untriaged(at(3, 9, 0)).len(), 2);

        let mut changed = items.clone();
        changed[0].updated = "2026-11-03T10:00:00Z".into();
        changed[0].score = 9.8;
        run(&mut s, &changed, at(3, 10, 0));
        run(&mut s, &changed, at(3, 11, 0));
        let f = FakeTracker::load().unwrap();
        assert_eq!(f.issues.len(), 2, "a change is a comment, not a new issue");
        assert_eq!(f.issues[0].comments.len(), 1);
        assert!(f.issues[0].comments[0].body.contains("2026-11-03T10:00:00Z"));

        // Triage by hand: accept FAKE-1, decline FAKE-2.
        let p = t.dir.join(crate::triage::tracker::FAKE_FILE);
        let mut j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        j["issues"][0]["state"] = json!("accepted");
        j["issues"][0]["due"] = json!("2026-11-06");
        j["issues"][1]["state"] = json!("declined");
        j["issues"][1]["reason"] = json!("not shipped");
        std::fs::write(&p, j.to_string()).unwrap();
        run(&mut s, &changed, at(4, 9, 0));
        assert!(s.untriaged(at(4, 9, 0)).is_empty());
        let open = s.open_tickets();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].1.issue.as_ref().unwrap().identifier, "FAKE-1");
        assert_eq!(s.records["CISA KEV:CVE-2"].issue_status.as_ref().unwrap().reason, "not shipped");
        assert_eq!(Store::load().unwrap(), s, "sync saved the store");
    }
}
