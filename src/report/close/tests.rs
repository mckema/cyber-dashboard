//! Monthly close tests: the report fixtures (November 2026 has one automatically
//! ruled-out item, GitHub:GHSA-gggg), FakeTracker for Linear, a recording closure
//! for the wiki upload and a stand-in renderer (no typst in the test image).

use std::cell::RefCell;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::*;
use crate::feeds::kev::testutil::fixture;
use crate::feeds::state::testing::{TempState, temp_state};
use crate::triage::tracker::{FakeState, FakeTracker};

fn utc(s: &str) -> DateTime<Utc> {
    parse_iso(s).unwrap()
}

/// The report fixtures without the half-written last line (appends follow).
fn lab(tag: &str) -> TempState {
    let t = temp_state(tag);
    let raw = String::from_utf8(fixture("report_events.jsonl")).unwrap();
    let clean: String = raw.lines().filter(|l| serde_json::from_str::<Value>(l).is_ok()).map(|l| format!("{l}\n")).collect();
    std::fs::write(t.dir.join(EVENTS_FILE), clean).unwrap();
    std::fs::write(t.dir.join("runs.jsonl"), fixture("report_runs.jsonl")).unwrap();
    t
}

fn nov() -> Period {
    Period::Month { year: 2026, month: 11 }
}

/// 06:00 Amsterdam on 1 December.
const DEC1: &str = "2026-12-01T05:00:00Z";

fn fake_pdf(_: &Value, data_sha: &str, _: DateTime<Utc>) -> Result<Vec<u8>, Fatal> {
    Ok(format!("%PDF-1.7 fake {data_sha}").into_bytes())
}

/// Wiki uploads seen, and what the next ones answer.
#[derive(Default)]
struct Wiki {
    calls: RefCell<Vec<(String, usize)>>,
    fail: RefCell<Option<String>>,
}

impl Wiki {
    fn upload(&self, name: &str, bytes: &[u8]) -> Result<String, Fatal> {
        self.calls.borrow_mut().push((name.to_string(), bytes.len()));
        match self.fail.borrow().clone() {
            Some(e) => Err(Fatal(e)),
            None => Ok(format!("/exploit-watch/{name}")),
        }
    }
}

fn vars(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
}

/// close_month with the stand-ins; `tracker` None = LINEAR_MODE=off.
fn close(now: &str, wiki: &Wiki, tracker: Result<Option<Box<dyn Tracker>>, String>, test_run: bool,
         var: &dyn Fn(&str) -> Option<String>) -> Closed {
    let mut up = |n: &str, b: &[u8]| wiki.upload(n, b);
    let mut o = CloseOpts { pdf: true, render: Some(fake_pdf), test_run, upload: &mut up, tracker, var };
    close_month(&nov(), utc(now), &mut o).unwrap()
}

fn fake() -> Result<Option<Box<dyn Tracker>>, String> {
    Ok(Some(Box::new(FakeTracker::with_clock(|| parse_iso(DEC1).unwrap()))))
}

fn events(t: &TempState) -> Vec<Value> {
    std::fs::read_to_string(t.dir.join(EVENTS_FILE)).unwrap().lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|v| v["key"].as_str().unwrap_or("").starts_with("report:"))
        .collect()
}

fn read(t: &TempState, f: &str) -> Value {
    serde_json::from_slice(&std::fs::read(t.dir.join("reports/2026-11").join(f)).unwrap()).unwrap()
}

fn is_uuid_v4(s: &str) -> bool {
    s.len() == 36 && s.as_bytes()[14] == b'4' && s.chars().filter(|c| *c == '-').count() == 4
}

#[test]
fn skips_with_a_reason() {
    let t = lab("close-skip");
    let wiki = Wiki::default();
    let none = vars(&[]);
    // not over: 23:30 Amsterdam on 30 November
    let c = close("2026-11-30T22:30:00Z", &wiki, fake(), false, &none);
    assert_eq!(c.skipped, "2026-11 is not over (it ends 2026-12-01T00:00:00+01:00)");
    assert!(!c.frozen && !t.dir.join("reports/2026-11").exists());
    assert_eq!(c.record(), json!({"month": "2026-11", "skipped": "2026-11 is not over (it ends 2026-12-01T00:00:00+01:00)"}));
    // September ends before the log starts (2026-10-20)
    let mut up = |n: &str, b: &[u8]| wiki.upload(n, b);
    let mut o = CloseOpts { pdf: true, render: Some(fake_pdf), test_run: false, upload: &mut up, tracker: fake(), var: &none };
    let c = close_month(&Period::Month { year: 2026, month: 9 }, utc(DEC1), &mut o).unwrap();
    assert_eq!(c.skipped, "the event log covers from 2026-10-20T10:00:00+02:00 only; no report for 2026-09");
    // no event log at all
    std::fs::remove_file(t.dir.join(EVENTS_FILE)).unwrap();
    let c = close(DEC1, &wiki, fake(), false, &none);
    assert_eq!(c.skipped, "no event log (triage-events.jsonl) yet");
    assert!(wiki.calls.borrow().is_empty());
    assert!(FakeTracker::load().unwrap().issues.is_empty());
    assert!(matches!(close_month(&Period::MonthToDate, utc(DEC1), &mut o), Err(_)));
}

#[test]
fn closes_once_and_a_second_call_changes_nothing() {
    let t = lab("close-once");
    let wiki = Wiki::default();
    let var = vars(&[("WIKI_PUBLIC_URL", "http://localhost:3000/en/exploit-watch")]);
    let c = close(DEC1, &wiki, fake(), false, &var);
    assert_eq!((c.skipped.as_str(), c.frozen, c.uploaded, c.review_created), ("", true, true, true));
    assert_eq!((c.sample, c.candidates), (1, 1));
    assert_eq!(c.marking, "LAB DATA", "EW_ENVIRONMENT unset: lab");
    assert_eq!(c.events, ["report_frozen", "sample_drawn", "review_issue_created"]);
    assert!(!c.has_error());

    // frozen.json, report.json with the sample, the PDF, SHA256SUMS
    let frozen = read(&t, FROZEN);
    let report = read(&t, "report.json");
    assert_eq!(frozen["frozen_at"], json!("2026-12-01T05:00:00Z"));
    assert_eq!((frozen["status"].clone(), frozen["document_id"].clone()), (json!("Final monthly"), json!("EW-CTR-2026-11")));
    assert_eq!(frozen["data_sha"], json!(super::super::data_sha(&report)));
    assert_eq!(frozen["marking"], json!("LAB DATA"));
    assert_eq!(frozen["test_run"], json!(false));
    let pdf = std::fs::read(t.dir.join("reports/2026-11/report.pdf")).unwrap();
    assert_eq!(frozen["pdf_sha"], json!(sha_hex(&pdf)));
    assert_eq!(frozen["content_sha"], json!(super::super::content_sha(&report)));
    let rs = &report["review_sample"];
    assert_eq!((rs["size"].clone(), rs["candidates"].clone()), (json!(10), json!(1)));
    assert_eq!(rs["items"][0]["key"], json!("GitHub:GHSA-gggg"));
    assert_eq!(rs["items"][0]["from"], json!("event log"));
    assert_eq!(rs["items"][0]["url"], json!("https://example.invalid/g1"), "no triage.json record: the event's url");

    // upload: once, under the month's name
    assert_eq!(*wiki.calls.borrow(), [("cyber-threat-report-2026-11.pdf".to_string(), pdf.len())]);
    let up = read(&t, UPLOAD);
    assert_eq!((up["path"].clone(), up["pdf_sha"].clone()), (json!("/exploit-watch/cyber-threat-report-2026-11.pdf"), frozen["pdf_sha"].clone()));

    // review.json: sample, the create id kept, the issue
    let review = read(&t, REVIEW);
    assert_eq!(review["sample"], *rs);
    assert!(is_uuid_v4(review["create_id"].as_str().unwrap()), "{review}");
    assert_eq!(review["issue"]["identifier"], json!("FAKE-1"));
    assert_eq!(review["title"], json!("Review monthly cyber threat report — November 2026"));

    // the reminder: a Todo, not in Triage; links, checklist, sample
    let f = FakeTracker::load().unwrap();
    assert_eq!(f.issues.len(), 1);
    let i = &f.issues[0];
    assert_eq!((i.state, i.task_id.as_str(), i.item_key.as_str()), (FakeState::Accepted, review["create_id"].as_str().unwrap(), ""));
    assert_eq!((i.assignee.as_str(), i.due.as_str()), ("", ""), "no assignee or due date unless configured");
    let d = &i.description;
    for want in ["- Dashboard: [Cyber Threat Dashboard](http://localhost:3000/en/exploit-watch)",
                 "- Report PDF: [cyber-threat-report-2026-11.pdf](http://localhost:3000/exploit-watch/cyber-threat-report-2026-11.pdf)",
                 "- [ ] Check the figures and the exceptions in the PDF against the dashboard",
                 "- [ ] Download the PDF", "- [ ] Send it to its recipients (Internal, TLP:AMBER)", "- [ ] Close this issue",
                 "**Quality check sample — really not relevant?**", "add a comment on this issue",
                 "- [ ] [GitHub:GHSA-gggg](https://example.invalid/g1) — G: not relevant, November",
                 "document EW-CTR-2026-11"] {
        assert!(d.contains(want), "{want}\n---\n{d}");
    }
    assert!(!d.contains("Test run"));

    // events: report:2026-11, same line shape as the store's
    let ev = events(&t);
    assert_eq!(ev.iter().map(|e| e["event"].as_str().unwrap()).collect::<Vec<_>>(),
               ["report_frozen", "sample_drawn", "review_issue_created"]);
    for e in &ev {
        assert_eq!((e["key"].as_str(), e["source"].as_str()), (Some("report:2026-11"), Some("live")));
        let id = e["id"].as_str().unwrap();
        assert!(id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
        assert!(parse_iso(e["at"].as_str().unwrap()).is_some() && parse_iso(e["ts"].as_str().unwrap()).is_some());
    }
    assert_eq!(ev[0]["data_sha"], frozen["data_sha"]);
    assert_eq!(ev[1]["keys"], json!(["GitHub:GHSA-gggg"]));
    assert_eq!(ev[1]["seed"], rs["seed"]);
    assert_eq!(ev[2]["identifier"], json!("FAKE-1"));

    // what the card reads
    let m = latest_monthly().unwrap();
    assert_eq!(m, MonthlyUpload {
        month: "2026-11".into(), title: "November 2026".into(), path: "/exploit-watch/cyber-threat-report-2026-11.pdf".into(),
        pdf_sha: frozen["pdf_sha"].as_str().unwrap().into(), frozen_at: "2026-12-01T05:00:00Z".into(),
        review: Some(ReviewRef { identifier: "FAKE-1".into(), url: "https://linear.invalid/fake/issue/FAKE-1".into() }),
    });

    // second call (the next run, or the scheduler after the loop): nothing new
    let files = |n: &str| std::fs::read(t.dir.join("reports/2026-11").join(n)).unwrap();
    let before: Vec<Vec<u8>> = ["report.json", "report.pdf", "SHA256SUMS", FROZEN, UPLOAD, REVIEW].iter().map(|n| files(n)).collect();
    let log_before = std::fs::read(t.dir.join(EVENTS_FILE)).unwrap();
    let c2 = close("2026-12-01T11:00:00Z", &wiki, fake(), false, &var);
    assert_eq!(c2.skipped, "already frozen at 2026-12-01T05:00:00Z");
    assert!(!c2.frozen && !c2.uploaded && !c2.review_created && c2.events.is_empty());
    assert_eq!(c2.review.as_ref().unwrap().identifier, "FAKE-1");
    assert_eq!(c2.record(), json!({"month": "2026-11", "skipped": "already frozen at 2026-12-01T05:00:00Z"}));
    let after: Vec<Vec<u8>> = ["report.json", "report.pdf", "SHA256SUMS", FROZEN, UPLOAD, REVIEW].iter().map(|n| files(n)).collect();
    assert_eq!(before, after, "the folder is not rewritten");
    assert_eq!(std::fs::read(t.dir.join(EVENTS_FILE)).unwrap(), log_before, "no new events");
    assert_eq!(wiki.calls.borrow().len(), 1, "no second upload");
    assert_eq!(FakeTracker::load().unwrap().issues.len(), 1, "one reminder");

    // `report --month 2026-11` refuses the frozen folder
    let e = generate(&nov(), utc("2026-12-02T08:00:00Z"), &Opts::default()).unwrap_err();
    assert!(e.0.contains("reports/2026-11 is frozen (frozen.json at 2026-12-01T05:00:00Z)"), "{}", e.0);
    assert_eq!(files("report.json"), before[0]);
}

/// Linear created the reminder but its answer was lost: the next call sends the
/// same id (saved in review.json before the attempt) and gets that issue back.
#[test]
fn lost_create_answer_is_recovered_by_id() {
    struct Lossy(FakeTracker);
    impl Tracker for Lossy {
        fn create_task(&mut self, spec: &TaskSpec, id: &str) -> Result<IssueRef, TrackerError> {
            self.0.create_task(spec, id)?;
            Err(TrackerError::Network("issueCreate: operation timed out".into()))
        }
        fn create_issue(&mut self, _: &Item, _: &crate::triage::types::Match, _: &str) -> Result<IssueRef, TrackerError> {
            unreachable!()
        }
        fn comment(&mut self, _: &IssueRef, _: &str) -> Result<(), TrackerError> {
            unreachable!()
        }
        fn fetch_states(&mut self, _: &[IssueRef]) -> Result<Vec<(IssueRef, crate::triage::tracker::IssueStatus)>, TrackerError> {
            unreachable!()
        }
    }

    let t = lab("close-lost");
    let wiki = Wiki::default();
    let none = vars(&[]);
    let c = close(DEC1, &wiki, Ok(Some(Box::new(Lossy(FakeTracker::new())))), false, &none);
    assert!(c.frozen && c.review.is_none());
    assert_eq!(c.review_error.as_deref(), Some("Linear: network error: issueCreate: operation timed out"));
    assert_eq!(c.record()["review_error"], json!("Linear: network error: issueCreate: operation timed out"));
    let id = read(&t, REVIEW)["create_id"].as_str().unwrap().to_string();
    assert_eq!(read(&t, REVIEW)["issue"], Value::Null);
    assert_eq!(events(&t).len(), 2, "no review_issue_created yet");

    let c = close("2026-12-01T11:00:00Z", &wiki, fake(), false, &none);
    assert!(c.review_created && c.review_error.is_none());
    assert_eq!(c.review.as_ref().unwrap().identifier, "FAKE-1");
    let f = FakeTracker::load().unwrap();
    assert_eq!(f.issues.len(), 1, "no second issue");
    assert_eq!(f.issues[0].task_id, id, "the same id was sent again");
    assert_eq!(read(&t, REVIEW)["create_id"], json!(id));
    assert_eq!(events(&t).iter().filter(|e| e["event"] == "review_issue_created").count(), 1);
    // and a third call does nothing
    assert!(!close("2026-12-01T17:00:00Z", &wiki, fake(), false, &none).review_created);
    assert_eq!(FakeTracker::load().unwrap().issues.len(), 1);
}

#[test]
fn failed_upload_is_retried_without_refreezing() {
    let t = lab("close-upload");
    let wiki = Wiki::default();
    let none = vars(&[]);
    *wiki.fail.borrow_mut() = Some("wiki asset upload: cannot reach Wiki.js".into());
    let c = close(DEC1, &wiki, fake(), false, &none);
    assert!(c.frozen && !c.uploaded && c.has_error());
    assert_eq!(c.upload_error.as_deref(), Some("wiki asset upload: cannot reach Wiki.js"));
    assert!(c.review_created, "the reminder does not wait for the upload");
    assert!(FakeTracker::load().unwrap().issues[0].description.contains("`/exploit-watch/cyber-threat-report-2026-11.pdf` on the wiki"),
            "no WIKI_PUBLIC_URL: the asset path");
    assert!(!t.dir.join("reports/2026-11").join(UPLOAD).exists());
    assert!(latest_monthly().is_none(), "nothing on the wiki yet");
    let frozen = read(&t, FROZEN);

    *wiki.fail.borrow_mut() = None;
    let c = close("2026-12-01T11:00:00Z", &wiki, fake(), false, &none);
    assert!(c.uploaded && !c.frozen && !c.review_created && !c.has_error());
    assert_eq!(read(&t, FROZEN), frozen);
    assert_eq!(wiki.calls.borrow().len(), 2);
    assert_eq!(latest_monthly().unwrap().month, "2026-11");
    assert_eq!(c.record()["uploaded"], json!(true));
}

#[test]
fn tracker_off_or_misconfigured() {
    let _t = lab("close-off");
    let wiki = Wiki::default();
    let none = vars(&[]);
    let c = close(DEC1, &wiki, Ok(None), false, &none);
    assert_eq!(c.review_skipped, "LINEAR_MODE=off: no review reminder filed");
    assert!(c.frozen && c.uploaded && !c.has_error());
    let c = close("2026-12-01T11:00:00Z", &wiki, Err("LINEAR_MODE=live needs LINEAR_API_KEY".into()), false, &none);
    assert_eq!(c.review_error.as_deref(), Some("tracker settings: LINEAR_MODE=live needs LINEAR_API_KEY"));
    // once configured, the reminder is filed for the frozen month
    let c = close("2026-12-02T11:00:00Z", &wiki, fake(), false, &none);
    assert!(c.review_created);
    assert_eq!(latest_monthly().unwrap().review.unwrap().identifier, "FAKE-1");
}

#[test]
fn test_run_marks_and_prefixes_and_settings_apply() {
    let _t = lab("close-test-run");
    let wiki = Wiki::default();
    let var = vars(&[("EW_ENVIRONMENT", "production"), ("REPORT_REVIEW_ASSIGNEE_ID", "user-reviewer"),
                     ("REPORT_REVIEW_DUE_DAYS", "3"), ("REVIEW_SAMPLE_SIZE", "0"),
                     ("REPORT_AUDIENCE", "Board"), ("REPORT_TLP", "TLP:AMBER+STRICT")]);
    let c = close(DEC1, &wiki, fake(), true, &var);
    assert_eq!(c.marking, "TEST DATA", "production, but --now");
    let i = &FakeTracker::load().unwrap().issues[0];
    assert_eq!(i.title, "[TEST] Review monthly cyber threat report — November 2026");
    assert!(i.description.starts_with("**Test run** (`report --close-month --now`)"));
    assert!(i.description.contains("- [ ] Send it to its recipients (Board, TLP:AMBER+STRICT)\n"), "{}", i.description);
    // 30 November 2026 is a Monday: 3 business days later is Thursday 3 December
    assert_eq!((i.assignee.as_str(), i.due.as_str()), ("user-reviewer", "2026-12-03"));
    assert!(i.description.contains("Sampling is turned off (REVIEW_SAMPLE_SIZE=0)."), "{}", i.description);
    assert_eq!(c.sample, 0);
}

#[test]
fn production_close_has_no_marking() {
    let t = lab("close-prod");
    let wiki = Wiki::default();
    let c = close(DEC1, &wiki, Ok(None), false, &vars(&[("EW_ENVIRONMENT", "production")]));
    assert_eq!(c.marking, "");
    assert_eq!(read(&t, "report.json")["marking"]["label"], json!(""));
}

// ------------------------------------------------------------------ sample

fn decided(key: &str, at: &str, decision: &str, title: &str) -> String {
    json!({"id": format!("d|{key}"), "event": "decided", "key": key, "at": at, "ts": "2026-10-01T00:00:00Z",
           "decision": decision, "item_source": key.split_once(':').unwrap().0, "title": title, "url": ""}).to_string()
}

fn log_of(lines: &[String]) -> Log {
    model::read_events(&lines.join("\n")).unwrap()
}

fn draw(log: &Log, size: usize, triage: &Value) -> Value {
    let (start, end) = nov().bounds(utc(DEC1));
    draw_sample(log, "2026-11", start, end, size, triage)
}

fn keys(sample: &Value) -> Vec<String> {
    sample["items"].as_array().unwrap().iter().map(|i| i["key"].as_str().unwrap().to_string()).collect()
}

#[test]
fn sample_is_deterministic_and_limited() {
    let mut lines: Vec<String> = (0..15)
        .map(|n| decided(&format!("CVE.org cvelistV5:CVE-2026-{n:04}"), &format!("2026-11-{:02}T08:00:00Z", n + 2),
                         "not-relevant-by-rule", "t"))
        .collect();
    lines.push(decided("CISA KEV:CVE-2026-9999", "2026-11-03T08:00:00Z", "matched", "m"));
    lines.push(decided("CVE.org cvelistV5:CVE-2026-8888", "2026-10-30T08:00:00Z", "not-relevant-by-rule", "october"));
    let a = draw(&log_of(&lines), 10, &Value::Null);
    assert_eq!((a["candidates"].clone(), a["size"].clone(), a["note"].clone()), (json!(15), json!(10), json!("")));
    let ka = keys(&a);
    assert_eq!(ka.len(), 10);
    assert!(!ka.iter().any(|k| k.ends_with("9999") || k.ends_with("8888")), "matched and October are no candidates");
    let firsts: Vec<&str> = a["items"].as_array().unwrap().iter().map(|i| i["first_seen"].as_str().unwrap()).collect();
    assert!(firsts.windows(2).all(|w| w[0] <= w[1]), "listed by first seen");
    // the same data in another order: the same sample and seed
    let mut shuffled = lines.clone();
    shuffled.reverse();
    let b = draw(&log_of(&shuffled), 10, &Value::Null);
    assert_eq!((keys(&b), b["seed"].clone()), (ka.clone(), a["seed"].clone()));
    // the seed is sha256 of the month and the sorted candidate keys
    let mut cand: Vec<String> = (0..15).map(|n| format!("CVE.org cvelistV5:CVE-2026-{n:04}")).collect();
    cand.sort();
    assert_eq!(a["seed"], json!(sha_hex(format!("2026-11\n{}", cand.join("\n")).as_bytes())));
    // another candidate changes the seed (and may change the draw); a smaller N is a prefix in rank order
    let small = draw(&log_of(&lines), 3, &Value::Null);
    assert!(keys(&small).iter().all(|k| ka.contains(k)));
    // fewer than N: all of them
    assert_eq!(keys(&draw(&log_of(&lines[..4]), 10, &Value::Null)).len(), 4);
    // a key link for every source
    assert!(a["items"].as_array().unwrap().iter().all(|i| i["url"].as_str().unwrap().starts_with("https://www.cve.org/")));
}

#[test]
fn sample_of_a_month_without_candidates() {
    let s = draw(&log_of(&[decided("CISA KEV:CVE-2026-1", "2026-11-03T08:00:00Z", "matched", "m")]), 10, &Value::Null);
    assert_eq!((s["candidates"].clone(), s["items"].clone()), (json!(0), json!([])));
    assert_eq!(s["note"], json!("No automatically ruled-out items in the period."));
    let spec = reminder_spec(&ReminderInput { month: "2026-11", frozen: &json!({}), sample: &s, asset_path: "", test_run: false },
                             &|_| None);
    assert!(spec.description.contains("No automatically ruled-out items in the period."));
    assert_eq!((spec.state_type.as_str(), spec.assignee_id.clone(), spec.due_date), ("unstarted", None, None));
}

#[test]
fn sample_items_are_enriched_from_triage_json() {
    let lines = [decided("CISA KEV:CVE-2026-0101", "2026-11-03T08:00:00Z", "not-relevant-by-rule", "from the log"),
                 decided("GitHub Advisory:GHSA-aaaa-bbbb-cccc", "2026-11-04T08:00:00Z", "not-relevant-by-rule", ""),
                 decided("NCSC-NL:NCSC-2026-0464", "2026-11-05T08:00:00Z", "not-relevant-by-rule", ""),
                 decided("CERT-EU:2026-018", "2026-11-06T08:00:00Z", "not-relevant-by-rule", "")];
    let triage = json!({
        "CISA KEV:CVE-2026-0101": {"item": {"source": "CISA KEV", "id": "CVE-2026-0101", "url": "https://kev.example/0101",
                                            "title": "Acme Router [RCE]", "published": "2026-11-03",
                                            "extra": {"vendor": "Acme", "product": "Router"}}},
        "GitHub Advisory:GHSA-aaaa-bbbb-cccc": {"item": {"source": "GitHub Advisory", "id": "GHSA-aaaa-bbbb-cccc", "url": "",
                                            "title": "left-pad", "published": "2026-11-04",
                                            "extra": {"eco_packages": ["npm:left-pad"]}}},
    });
    let s = draw(&log_of(&lines), 10, &triage);
    let i = s["items"].as_array().unwrap();
    assert_eq!((i[0]["title"].clone(), i[0]["vendor_product"].clone(), i[0]["url"].clone(), i[0]["from"].clone()),
               (json!("Acme Router [RCE]"), json!("Acme / Router"), json!("https://kev.example/0101"), json!("triage.json")));
    assert_eq!((i[1]["vendor_product"].clone(), i[1]["url"].clone()),
               (json!("npm:left-pad"), json!("https://github.com/advisories/GHSA-aaaa-bbbb-cccc")));
    assert_eq!((i[2]["from"].clone(), i[2]["url"].clone()),
               (json!("key"), json!("https://advisories.ncsc.nl/2026/ncsc-2026-0464.html")));
    assert_eq!(i[3]["url"], json!("https://cert.europa.eu/publications/security-advisories/2026-018/"));
    let spec = reminder_spec(&ReminderInput { month: "2026-11", frozen: &json!({"data_sha": "abc"}), sample: &s,
                                              asset_path: "/exploit-watch/cyber-threat-report-2026-11.pdf", test_run: false }, &|_| None);
    assert!(spec.description.contains("- [ ] [CISA KEV:CVE-2026-0101](https://kev.example/0101) — Acme Router \\[RCE\\] · Acme / Router"),
            "{}", spec.description);
}

#[test]
fn sample_links_are_http_and_inert() {
    let lines = [decided("CISA KEV:CVE-2026-0101", "2026-11-03T08:00:00Z", "not-relevant-by-rule", ""),
                 decided("NCSC-NL:NCSC-2026-0464", "2026-11-04T08:00:00Z", "not-relevant-by-rule", "")];
    let triage = json!({
        "CISA KEV:CVE-2026-0101": {"item": {"source": "CISA KEV", "id": "CVE-2026-0101", "url": "javascript:alert(1)",
                                            "title": "![](https://evil.example/p.png)", "published": "2026-11-03"}},
        "NCSC-NL:NCSC-2026-0464": {"item": {"source": "NCSC-NL", "id": "NCSC-2026-0464",
                                            "url": "https://x.example/a) [Re-authenticate](https://evil.example",
                                            "title": "t", "published": "2026-11-04"}},
    });
    let s = draw(&log_of(&lines), 10, &triage);
    let i = s["items"].as_array().unwrap();
    // a non-http url never reaches the PDF: the link is built from the key instead
    assert_eq!(i[0]["url"], json!("https://www.cve.org/CVERecord?id=CVE-2026-0101"));
    let spec = reminder_spec(&ReminderInput { month: "2026-11", frozen: &json!({"data_sha": "abc"}), sample: &s,
                                              asset_path: "/x.pdf", test_run: false }, &|_| None);
    let d = &spec.description;
    assert!(d.contains("— !\\[\\](https://evil.example/p.png)"), "{d}");
    assert!(d.contains("- [ ] [NCSC-NL:NCSC-2026-0464](https://x.example/a%29%20%5BRe-authenticate%5D%28https://evil.example) — t"),
            "{d}");
}

#[test]
fn helpers() {
    let d = |s: &str| NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
    assert_eq!(business_days_after(d("2026-11-30"), 0), d("2026-11-30"));
    assert_eq!(business_days_after(d("2026-11-30"), 5), d("2026-12-07"));
    assert_eq!(business_days_after(d("2026-10-31"), 1), d("2026-11-02"), "Saturday + 1 = Monday");
    assert_eq!(origin("http://localhost:3000/en/exploit-watch"), Some("http://localhost:3000"));
    assert_eq!(origin("https://wiki.example.com"), Some("https://wiki.example.com"));
    assert_eq!(origin("/en/page"), None);
    assert_eq!(month_title("2026-10"), "October 2026");
    assert_eq!(previous_month(utc("2026-12-01T05:00:00Z")), nov());
    assert_eq!(previous_month(utc("2026-11-30T23:30:00Z")), nov(), "00:30 on 1 December in Amsterdam");
    assert_eq!(previous_month(utc("2026-11-30T22:30:00Z")), Period::Month { year: 2026, month: 10 });
    assert_eq!(previous_month(utc("2027-01-01T08:00:00Z")), Period::Month { year: 2026, month: 12 });
    assert_eq!(key_link("CVE.org cvelistV5:CVE-2026-1"), "https://www.cve.org/CVERecord?id=CVE-2026-1");
    assert_eq!(key_link("ENISA EUVD:EUVD-2026-5"), "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-5");
    assert_eq!(key_link("odd"), "");
}

/// REPORTS_BUCKET "ev" under REPORTS_PREFIX "monthly" on the fake GCS at `base`.
fn reports_vars(base: String) -> impl Fn(&str) -> Option<String> {
    move |k: &str| match k {
        "REPORTS_BUCKET" => Some("ev".into()),
        "REPORTS_PREFIX" => Some("/monthly/".into()),
        "GCS_ENDPOINT" => Some(base.clone()),
        _ => None,
    }
}

#[test]
fn evidence_is_copied_once_and_objects_already_there_are_skipped() {
    use crate::wiki::testing::{canned, serve};
    let t = lab("close-archive");
    let wiki = Wiki::default();
    let ok_gen = |g: u32| canned(200, &json!({"generation": g.to_string()}).to_string());
    // report.pdf is already in the bucket (412): skipped without an error
    let (base, rx) = serve(vec![ok_gen(1), canned(412, "conditionNotMet"), ok_gen(3), ok_gen(4)]);
    let var = reports_vars(base);
    let c = close(DEC1, &wiki, Ok(None), false, &var);
    assert!(c.frozen && !c.has_error(), "{:?}", c.lines());
    assert_eq!(c.archived, ["monthly/2026-11/report.json", "monthly/2026-11/SHA256SUMS", "monthly/2026-11/frozen.json"]);
    assert_eq!(c.record()["archived"], json!(c.archived));
    let reqs: Vec<String> = rx.try_iter().collect();
    assert_eq!(reqs.len(), 4);
    for (r, f) in reqs.iter().zip(EVIDENCE) {
        assert!(r.starts_with("POST /upload/storage/v1/b/ev/o?uploadType=multipart&ifGenerationMatch=0 "), "{r}");
        assert!(r.contains(&format!("{{\"name\":\"monthly/2026-11/{f}\"}}")), "{r}");
    }
    let pdf = std::fs::read(t.dir.join("reports/2026-11/report.pdf")).unwrap();
    assert!(reqs[1].contains(&*String::from_utf8_lossy(&pdf)), "the PDF bytes are sent");
    let a = read(&t, ARCHIVE);
    assert_eq!((a["bucket"].clone(), a["data_sha"].clone()), (json!("ev"), read(&t, FROZEN)["data_sha"].clone()));
    assert_eq!(a["objects"].as_array().unwrap().len(), 4);
    // A later call copies nothing (the server has no more replies) and stays idle.
    let c = close(DEC1, &wiki, Ok(None), false, &var);
    assert!(c.archived.is_empty() && !c.has_error());
    assert_eq!(c.record(), json!({"month": "2026-11", "skipped": "already frozen at 2026-12-01T05:00:00Z"}));
}

#[test]
fn an_evidence_copy_error_is_recorded_and_retried_on_the_next_call() {
    use crate::wiki::testing::{canned, serve};
    let t = lab("close-archive-err");
    let wiki = Wiki::default();
    let (base, _rx) = serve(vec![canned(403, "denied")]);
    let c = close(DEC1, &wiki, Ok(None), false, &reports_vars(base));
    assert!(c.frozen && c.uploaded, "the close goes on");
    assert!(c.has_error());
    let err = c.archive_error.clone().unwrap();
    assert!(err.starts_with("evidence copy: upload gs://ev/monthly/2026-11/report.json: HTTP 403"), "{err}");
    assert!(c.record()["archive_error"].is_string());
    assert!(!t.dir.join("reports/2026-11").join(ARCHIVE).exists());
    let ok_gen = || canned(200, r#"{"generation": "1"}"#);
    let (base, _rx) = serve(vec![ok_gen(), ok_gen(), ok_gen(), ok_gen()]);
    let c = close(DEC1, &wiki, Ok(None), false, &reports_vars(base));
    assert_eq!((c.archived.len(), c.has_error()), (4, false));
    assert!(t.dir.join("reports/2026-11").join(ARCHIVE).exists());
}

#[test]
fn no_reports_bucket_no_copy() {
    let t = lab("close-archive-off");
    let c = close(DEC1, &Wiki::default(), Ok(None), false, &vars(&[]));
    assert!(c.frozen && c.archived.is_empty() && c.archive_error.is_none());
    assert!(!t.dir.join("reports/2026-11").join(ARCHIVE).exists());
}
