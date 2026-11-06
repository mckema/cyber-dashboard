//! Report engine tests on tests/fixtures/report_events.jsonl and report_runs.jsonl:
//! items A..I (titles say what each one is for), a repeated id, a second decision
//! of a key after a crash and a half-written last line; coverage from 2026-10-20.
//! The RAG, bottom-line and exploited tests build small logs inline (`Case`).

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::*;
use crate::feeds::kev::testutil::fixture;
use crate::feeds::state::testing::{TempState, temp_state};

fn utc(s: &str) -> DateTime<Utc> {
    parse_iso(s).unwrap()
}

fn lab(tag: &str) -> TempState {
    let t = temp_state(tag);
    std::fs::write(t.dir.join(EVENTS_FILE), fixture("report_events.jsonl")).unwrap();
    std::fs::write(t.dir.join("runs.jsonl"), fixture("report_runs.jsonl")).unwrap();
    t
}

fn nov() -> Period {
    Period::Month { year: 2026, month: 11 }
}

fn no_pdf() -> Opts {
    Opts { pdf: false, environment: Some("lab".into()), ..Default::default() }
}

fn idents(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x["identifier"].as_str().unwrap()).collect()
}

/// kpis[key] -> (value, status, previous).
fn kpi(j: &Value, key: &str) -> (String, String, String) {
    let k = j["kpis"].as_array().unwrap().iter().find(|k| k["key"] == key).unwrap();
    let s = |f: &str| k[f].as_str().unwrap().to_string();
    (s("value"), s("status"), s("previous"))
}

fn texts(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x["text"].as_str().unwrap().to_string()).collect()
}

#[test]
fn november_figures() {
    let _t = lab("report-nov");
    let g = generate(&nov(), utc("2026-12-03T08:00:00Z"), &no_pdf()).unwrap();
    let j = &g.json;
    assert_eq!(g.label, "Monthly report 2026-11");
    assert_eq!(j["title"], json!("Cyber threat report — November 2026"));
    assert_eq!(j["subtitle"], json!("Monthly report"));
    assert_eq!(g.as_of, "2026-11-29T10:00:00Z", "last writing run with a read-back");
    assert_eq!(j["as_of"], json!("2026-11-29T10:00:00Z"));
    assert_eq!(j["tickets_as_of"], json!("2026-11-29T11:00:00+01:00"));
    assert_eq!(g.coverage_from, "2026-10-20T08:00:00Z");
    assert_eq!(j["period"]["start"], json!("2026-11-01T00:00:00+01:00"));
    assert_eq!(j["period"]["end"], json!("2026-12-01T00:00:00+01:00"));
    assert_eq!((j["period"]["complete"].clone(), j["coverage"]["partial"].clone()), (json!(true), json!(false)));
    assert_eq!(j["coverage"]["duplicates_dropped"], json!(2), "repeated id + second decision of B");
    assert_eq!(j["coverage"]["half_written_tail"], json!(true));
    assert_eq!(j["coverage"]["backfilled"], json!(0), "no triage.json");
    assert_eq!(j["tracker"], json!({"endpoint": "http://linear-mock:8080/graphql"}));
    assert_eq!(j["marking"]["label"], json!("LAB DATA"), "EW_ENVIRONMENT unset = lab, tracker linear-mock");
    assert_eq!(j["components"][0]["decisions"], json!(7));
    assert_eq!(j["component_list"]["version"], json!("sample-2026-11-04"));
    // writing runs only: the dry run is out, fatal (no mode) and locked are in
    assert_eq!(j["runs"], json!({"writing": 5, "by_result": {"fatal": 1, "locked": 1, "unchanged": 1, "written": 2}}));
    // feeds of the last run only; NVD was reported earlier in the period
    assert_eq!(j["feeds"], json!([{"feed": "CISA KEV", "runs": 3, "ok": 2, "by_status": {"error": 1, "ok": 2},
                                   "last_status": "ok", "healthy": true}]));
    assert_eq!(j["feeds_removed"], json!(["NVD"]));
    assert_eq!(j["monitoring"]["sentence"], json!(
        "1 public source (CISA KEV) checked in 5 scheduled runs (every 6 h) against component list sample-2026-11-04. \
         Limits: components not on the list are not checked; affected versions are not checked."));

    let fu = &j["funnel"];
    assert_eq!((fu["notices"].clone(), fu["auto_ruled_out"].clone(), fu["relevant"].clone()), (json!(7), json!(1), json!(6)));
    // A was assessed in October: counted there although it closed in November.
    // D, declined without a reason, is waiting (since 2026-11-06), not ruled out by a person.
    assert_eq!((fu["assessed"].clone(), fu["action_planned"].clone(), fu["ruled_out_by_person"].clone(), fu["waiting"].clone()),
               (json!(4), json!(3), json!(1), json!(2)));
    assert_eq!(fu["waiting_without_reason"], json!(1));
    assert_eq!(fu["time_to_assess"], json!({"count": 4, "median_business_hours": 1.5, "max_business_hours": 49.0}));
    assert_eq!(idents(&fu["over_one_day"]), ["MOCK-4", "MOCK-5", "MOCK-7"]);
    assert_eq!((fu["over_one_day"][0]["assessed_at"].clone(), fu["over_one_day"][0]["declined_without_reason"].clone()),
               (Value::Null, json!(true)), "D waits for its reason");
    assert_eq!(fu["over_one_day"][1]["business_hours"], json!(49.0));
    assert_eq!(fu["over_one_day"][2]["assessed_at"], Value::Null, "still waiting");
    assert_eq!(fu["over_one_day"][2]["declined_without_reason"], json!(false));
    assert_eq!(fu["by_source"], json!([
        {"source": "CISA KEV", "total": 6, "relevant": 6, "auto_ruled_out": 0},
        {"source": "GitHub Advisory", "total": 1, "relevant": 0, "auto_ruled_out": 1}]));

    let o = &j["outcomes"];
    assert_eq!(idents(&o["fixed"]), ["MOCK-1"]);
    assert_eq!((o["fixed"][0]["on_time"].clone(), o["fixed"][0]["owner"].clone()), (json!(true), json!("Ann")));
    assert_eq!((o["on_time"].clone(), o["late"].clone(), o["mttr_median_days"].clone()), (json!(1), json!(0), json!(7.0)));
    assert_eq!(idents(&o["closed_without_fix"]), ["MOCK-5"]);
    assert_eq!(idents(&o["ruled_out"]), ["MOCK-3"], "D has no reason: waiting, not resolved");
    assert_eq!(o["ruled_out"][0]["reason"], json!("component not deployed"));
    assert_eq!(o["ruled_out"][0]["declined_at"], json!("2026-11-03T11:00:00+01:00"), "reason logged with the decline");
    let outcome: Vec<&str> = j["resolved"].as_array().unwrap().iter().map(|r| r["outcome"].as_str().unwrap()).collect();
    assert_eq!(outcome, ["ruled out by Henry: component not deployed", "fixed on 4 Nov (on time)", "closed without fix on 12 Nov"]);
    assert_eq!(j["resolved"][0]["warn"], json!(false));

    let oa = &j["open_actions"];
    assert_eq!(idents(&oa["items"]), ["MOCK-2", "MOCK-6"]);
    assert_eq!((oa["count"].clone(), oa["overdue"].clone()), (json!(2), json!(1)));
    let b = &oa["items"][0];
    assert_eq!((b["owner"].clone(), b["overdue"].clone(), b["state_name"].clone()), (json!("Bob"), json!(true), json!("In Progress")));
    assert_eq!((b["age_days"].clone(), b["carried_over"].clone()), (json!(28), json!(false)), "first seen 2 Nov, to 30 Nov");
    assert_eq!((b["vulnerability"].clone(), b["exploited"].clone(), b["exploited_source"].clone(), b["severity"].clone(), b["score"].clone()),
               (json!("CVE-2026-0002"), json!(true), json!("CISA KEV"), json!("HIGH"), json!(7.5)));
    assert_eq!(oa["items"][1]["exploited"], json!(false), "no risk fields and no triage.json");
    assert!(oa["items"][1]["title"].as_str().unwrap().ends_with('…'), "titles are cut to 60 characters");

    // KPIs and status: B is overdue and exploited, F waits 6.6 business days, D (no reason) longer -> RED
    assert_eq!(kpi(j, "relevant"), ("6".into(), "—".into(), "1".into()));
    assert_eq!(kpi(j, "assessed"), ("3 of 6 (50%)".into(), "Red".into(), "1 of 1 (100%)".into()));
    assert_eq!(kpi(j, "open"), ("2 (1 overdue)".into(), "Red".into(), "1 (0 overdue)".into()));
    assert_eq!(kpi(j, "fixed"), ("1 of 1 (100%)".into(), "Green".into(), "—".into()));
    assert_eq!(kpi(j, "exploited"), ("1".into(), "Red".into(), "0".into()));
    assert_eq!(kpi(j, "sources"), ("1/1".into(), "Green".into(), "1/1".into()));
    assert_eq!(j["previous"], json!({"month": "2026-10", "label": "October 2026", "covered": true, "partial": true}));
    assert_eq!(j["status"]["rag"], json!("RED"));
    assert_eq!(texts(&j["status"]["reasons"]), [
        "MOCK-4 (x): ruled out without a reason, so not assessed after more than 3 business days, first seen 4 Nov",
        "MOCK-7 (x): relevant item not assessed after more than 3 business days, first seen 20 Nov",
        "MOCK-2 (CVE-2026-0002, known exploited): action overdue since 3 Nov (owner Bob)",
        "MOCK-5: assessment took 2.0 business days",
        "MOCK-6 (x): open action without an owner or a due date",
        "Ticket tracker errors in 1 run, the last on 15 Nov",
    ]);
    // Grouped by kind, worst first, ticket ids only; a past slow assessment is not an attention point.
    assert_eq!(texts(&j["attention"]), [
        "Overdue action on a known-exploited vulnerability (1): MOCK-2",
        "Not assessed after 1 business day (2): MOCK-4 (declined without a reason, over 3 business days), MOCK-7 (over 3 business days)",
        "Open action without owner or due date (1): MOCK-6",
        "Ticket tracker errors: 1 run (last on 15 Nov), see appendix",
    ]);
    assert_eq!((j["attention"][1]["group"].clone(), j["attention"][1]["count"].clone(), j["attention"][1]["rag"].clone()),
               (json!("waiting"), json!(2), json!("RED")));
    // Two sentences, no figure of the key figures table.
    assert_eq!(j["bottom_line"], json!([
        "Red: an action on a known-exploited vulnerability is overdue and relevant items have waited more than 3 business days for assessment.",
        "The points below need a decision or follow-up.",
    ]));
    let trend: Vec<&str> = j["kpis"].as_array().unwrap().iter().map(|k| k["trend"].as_str().unwrap()).collect();
    assert_eq!(trend, ["▲", "▼", "▲", "—", "▲", "="], "against October; no fix in October");

    // The month in review: backlog reconciles, waiting at the end, merged closed list.
    assert_eq!(j["backlog"], json!({"open_start": 1, "accepted": 3, "reopened": 0, "fixed": 1, "closed_without_fix": 1,
                                    "other": 0, "open_end": 2}));
    assert_eq!(idents(&j["waiting_items"]), ["MOCK-4", "MOCK-7"]);
    let w = &j["waiting_items"][0];
    assert_eq!((w["overdue"].clone(), w["over_three_days"].clone(), w["declined_without_reason"].clone(), w["carried_over"].clone()),
               (json!(true), json!(true), json!(true), json!(false)));
    let kinds: Vec<&str> = j["resolved"].as_array().unwrap().iter().map(|r| r["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["ruled_out", "fixed", "closed_without_fix"]);
    assert_eq!((j["resolved"][1]["by"].clone(), j["resolved"][1]["detail"].clone(), j["resolved"][1]["date"].clone()),
               (json!("Ann"), json!("on time (due 10 Nov)"), json!("2026-11-04T11:00:00+01:00")));
    assert_eq!((j["resolved"][0]["by"].clone(), j["resolved"][0]["detail"].clone()), (json!("Henry"), json!("component not deployed")));

    let e = &j["exceptions"];
    assert_eq!(idents(&e["overdue"]), ["MOCK-2"]);
    assert_eq!(idents(&e["open_without_owner"]), ["MOCK-6"]);
    assert_eq!(idents(&e["open_without_due"]), ["MOCK-6"]);
    assert_eq!(idents(&e["unassessed_over_one_day"]), ["MOCK-4", "MOCK-7"]);
    assert_eq!(idents(&e["declined_without_reason"]), ["MOCK-4"]);
    assert_eq!(idents(&e["triaged_without_actor"]), ["MOCK-4"]);
    assert_eq!(e["tracker_errors"], json!([{"run_at": "2026-11-15T11:00:00+01:00",
                                            "error": "read issue states: Linear: network error"}]));
    assert_eq!(e["log_lines_skipped"], json!(0));
    assert_eq!(j["document"]["id"], json!("EW-CTR-2026-11"));
    assert_eq!(j["document"]["status"], json!("Final monthly"));

    // files: report.json and SHA256SUMS, no PDF
    let dir = g.dir.clone();
    assert!(dir.ends_with("reports/2026-11"));
    let written: Value = serde_json::from_slice(&std::fs::read(dir.join("report.json")).unwrap()).unwrap();
    assert_eq!(&written, j);
    assert_eq!(data_sha(&written), g.data_sha);
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
    let json_sha = hex::encode(Sha256::digest(std::fs::read(dir.join("report.json")).unwrap()));
    assert_eq!(sums, format!("{json_sha}  report.json\n"));
    assert!(!dir.join("report.pdf").exists());
}

#[test]
fn backfill_from_triage_json() {
    let t = lab("report-backfill");
    // I's `decided` line has no risk fields; triage.json still holds its item.
    std::fs::write(t.dir.join(crate::triage::store::FILE), json!({
        "CISA KEV:CVE-2026-0006": {"item": {"source": "CISA KEV", "id": "CVE-2026-0006", "url": "u", "title": "I",
                                            "published": "2026-11-10", "cves": ["CVE-2026-0006"], "score": 9.8,
                                            "severity": "CRITICAL"}},
        "CISA KEV:CVE-2026-0002": {"item": {"source": "GitHub Advisory", "id": "x", "url": "u", "title": "B",
                                            "published": "2026-11-02"}},
    }).to_string()).unwrap();
    let before = std::fs::read(t.dir.join(EVENTS_FILE)).unwrap();
    let g = generate(&nov(), utc("2026-12-03T08:00:00Z"), &no_pdf()).unwrap();
    let j = &g.json;
    assert_eq!(j["coverage"]["backfilled"], json!(1), "B already has its fields: not overwritten");
    let i = &j["open_actions"]["items"][1];
    assert_eq!((i["identifier"].clone(), i["exploited"].clone(), i["exploited_source"].clone(), i["severity"].clone(), i["score"].clone()),
               (json!("MOCK-6"), json!(true), json!("CISA KEV"), json!("CRITICAL"), json!(9.8)));
    assert_eq!(j["open_actions"]["items"][0]["exploited_source"], json!("CISA KEV"));
    assert_eq!(kpi(j, "exploited").0, "2");
    assert_eq!(std::fs::read(t.dir.join(EVENTS_FILE)).unwrap(), before, "the event log is never rewritten");
}

#[test]
fn october_starts_before_coverage_and_is_reconstructed() {
    let _t = lab("report-oct");
    let g = generate(&Period::Month { year: 2026, month: 10 }, utc("2026-12-03T08:00:00Z"), &no_pdf()).unwrap();
    let j = &g.json;
    assert_eq!(j["coverage"]["partial"], json!(true), "October starts before 2026-10-20");
    assert_eq!(j["funnel"]["notices"], json!(2));
    assert_eq!(j["funnel"]["action_planned"], json!(1));
    assert_eq!(j["outcomes"]["fixed_count"], json!(0), "A closed in November");
    // A at the end of October: accepted, owner and due date known, not overdue yet
    assert_eq!(idents(&j["open_actions"]["items"]), ["MOCK-1"]);
    assert_eq!(j["open_actions"]["items"][0]["due"], json!("2026-11-10"));
    assert_eq!(j["open_actions"]["items"][0]["overdue"], json!(false));
    assert_eq!(g.as_of, "2026-10-31T10:00:00Z");
    // September ends before the log starts: no comparison
    assert_eq!(j["previous"]["covered"], json!(false));
    assert_eq!(kpi(j, "relevant").2, "first period");
    assert_eq!(j["status"]["rag"], json!("GREEN"));
    assert_eq!(j["bottom_line"], json!([
        "Every relevant item was assessed within 1 business day, no action is overdue and monitoring ran without problems.",
        "No decision is needed from you."]));
    assert_eq!(j["backlog"], json!({"open_start": 0, "accepted": 1, "reopened": 0, "fixed": 0, "closed_without_fix": 0,
                                    "other": 0, "open_end": 1}));
}

#[test]
fn refuses_periods_before_coverage_and_a_missing_log() {
    let t = lab("report-refuse");
    let now = utc("2026-12-03T08:00:00Z");
    let err = generate(&Period::Month { year: 2026, month: 9 }, now, &no_pdf()).unwrap_err();
    assert!(err.0.contains("covers from 2026-10-20"), "{}", err.0);
    std::fs::remove_file(t.dir.join(EVENTS_FILE)).unwrap();
    let err = generate(&nov(), now, &no_pdf()).unwrap_err();
    assert!(err.0.contains("triage-events.jsonl not found"), "{}", err.0);
}

#[test]
fn data_sha_ignores_generated_at_only() {
    let _t = lab("report-sha");
    let a = generate(&nov(), utc("2026-12-03T08:00:00Z"), &no_pdf()).unwrap();
    let b = generate(&nov(), utc("2026-12-10T08:00:00Z"), &no_pdf()).unwrap();
    assert_ne!(a.json["generated_at"], b.json["generated_at"]);
    assert_eq!(a.data_sha, b.data_sha);
    let c = generate(&nov(), utc("2026-12-10T08:00:00Z"),
                     &Opts { pdf: false, tickets_as_of: Some(utc("2026-11-30T12:00:00Z")), ..Default::default() }).unwrap();
    assert_ne!(a.data_sha, c.data_sha, "tickets as of is data");
    assert_eq!(c.as_of, "2026-11-30T12:00:00Z");
    assert_eq!(a.content_sha, c.content_sha, "content does not move with tickets as of");
}

#[test]
fn content_sha_does_not_move_with_the_clock() {
    let _t = lab("report-content");
    // Month to date, two cut-offs with no event in between (I on the 10th, E canceled on the 12th).
    let at = |s: &str| {
        let now = utc(s);
        generate(&Period::MonthToDate, now, &Opts { pdf: false, tickets_as_of: Some(now), ..Default::default() }).unwrap()
    };
    let (a, b) = (at("2026-11-11T09:00:00Z"), at("2026-11-11T15:00:00Z"));
    assert_ne!(a.data_sha, b.data_sha, "the cut-off is data");
    assert_eq!(a.content_sha, b.content_sha);
}

#[test]
fn month_to_date_runs_to_now() {
    let _t = lab("report-mtd");
    let now = utc("2026-11-10T12:00:00Z");
    let g = generate(&Period::MonthToDate, now, &Opts { pdf: false, tickets_as_of: Some(now), ..Default::default() }).unwrap();
    assert_eq!(g.label, "On-demand snapshot 2026-11 (to 2026-11-10) – not the official monthly report");
    assert!(g.dir.ends_with("reports/month-to-date"));
    let j = &g.json;
    assert_eq!(j["title"], json!("Cyber threat report — November 2026, month to date (1–10 Nov)"));
    assert_eq!(j["subtitle"], json!("Month-to-date snapshot – not the official monthly report"));
    assert_eq!(j["document"], json!({
        "id": "EW-CTR-2026-11-MTD-20261110-1300", "version": "1.0", "status": "Snapshot",
        "prepared_by": "Exploit Watch job, operated by the ISB Vietnam team",
        "distribution": "fairCT COO; others on a need-to-know basis (TLP:AMBER+STRICT)",
        "retention": "to be agreed with fairCT"}));
    assert_eq!(j["bottom_line"].as_array().unwrap().len(), 2);
    // A partial month against a full one: the previous value as a reference, no trend arrow.
    for k in j["kpis"].as_array().unwrap() {
        assert_eq!(k["trend"], json!("partial month"), "{k}");
    }
    assert_eq!(kpi(j, "relevant").2, "1", "October's value is still shown");
    assert_eq!((j["period"]["kind"].clone(), j["period"]["complete"].clone()), (json!("month-to-date"), json!(true)));
    assert_eq!(j["period"]["end"], json!("2026-11-10T13:00:00+01:00"));
    // E is canceled on the 12th: still open on the 10th; F is decided on the 20th;
    // D, declined without a reason on the 4th, is waiting (was 0 before 2026-11-06)
    assert_eq!(idents(&j["open_actions"]["items"]), ["MOCK-2", "MOCK-5", "MOCK-6"]);
    assert_eq!(j["funnel"]["waiting"], json!(1));
    assert_eq!(j["funnel"]["notices"], json!(6));
}

#[test]
fn current_month_is_marked_incomplete() {
    let _t = lab("report-partial");
    let g = generate(&nov(), utc("2026-11-10T12:00:00Z"), &no_pdf()).unwrap();
    assert_eq!(g.json["period"]["complete"], json!(false));
    assert_eq!(g.json["period"]["data_to"], json!("2026-11-10T13:00:00+01:00"));
    assert_eq!(g.json["document"]["status"], json!("Interim (period not over)"));
    assert_eq!(g.as_of, "2026-11-10T10:00:00Z");
}

#[test]
fn amsterdam_month_bounds_and_dst() {
    let b = |y, m| Period::Month { year: y, month: m }.bounds(utc("2027-01-01T00:00:00Z"));
    // October 2026 starts in CEST (+2) and ends in CET (+1): the clocks go back on the 25th
    assert_eq!(b(2026, 10), (utc("2026-09-30T22:00:00Z"), utc("2026-10-31T23:00:00Z")));
    assert_eq!(b(2026, 11), (utc("2026-10-31T23:00:00Z"), utc("2026-11-30T23:00:00Z")));
    assert_eq!(b(2026, 3), (utc("2026-02-28T23:00:00Z"), utc("2026-03-31T22:00:00Z")));
    assert_eq!(b(2026, 12), (utc("2026-11-30T23:00:00Z"), utc("2026-12-31T23:00:00Z")));
    // month to date: 00:30 on 1 November in Amsterdam is still 31 October in UTC
    let now = utc("2026-10-31T23:30:00Z");
    assert_eq!(Period::MonthToDate.bounds(now), (utc("2026-10-31T23:00:00Z"), now));
    assert_eq!(Period::MonthToDate.month_name(now), "2026-11");
    let now = utc("2026-10-31T22:30:00Z");
    assert_eq!(Period::MonthToDate.bounds(now).0, utc("2026-09-30T22:00:00Z"));

    // An event at 23:30 Amsterdam on 31 October belongs to October, one at 00:30 on 1 November to November.
    let log = model::read_events(concat!(
        r#"{"id":"1","event":"decided","key":"k1","at":"2026-10-31T22:30:00Z","ts":"2026-10-01T00:00:00Z","decision":"matched"}"#, "\n",
        r#"{"id":"2","event":"decided","key":"k2","at":"2026-10-31T23:30:00Z","ts":"2026-10-01T00:00:00Z","decision":"matched"}"#, "\n",
    )).unwrap();
    let count = |(start, end): (DateTime<Utc>, DateTime<Utc>)| {
        build::build(&log, &[], &build::Frame { start, end, cut: end, as_of: end, mtd: false, list: None,
                                                  environment: "lab".into(), test_run: false })["funnel"]["notices"].clone()
    };
    assert_eq!((count(b(2026, 10)), count(b(2026, 11))), (json!(1), json!(1)));
}

#[test]
fn month_argument() {
    assert_eq!(Period::parse_month("2026-11").unwrap(), nov());
    for bad in ["2026-13", "2026-1", "26-11", "2026/11", "november"] {
        assert!(Period::parse_month(bad).is_err(), "{bad}");
    }
    assert_eq!(nov().label(utc("2026-12-01T00:00:00Z")), "Monthly report 2026-11");
}

// ------------------------------------------------------------------ small inline logs

const KEY: &str = "CVE.org cvelistV5:CVE-2026-1";
const ALL_FEEDS: [&str; 7] = ["CISA KEV", "ENISA EUVD", "CVE.org cvelistV5", "NVD", "GitHub Advisory", "CERT-EU", "NCSC-NL"];

fn line(kind: &str, key: &str, at: &str, extra: Value) -> String {
    let mut v = json!({"id": format!("{kind}|{key}|{at}"), "event": kind, "key": key, "at": at, "ts": "2026-11-01T00:00:00Z"});
    v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    v.to_string()
}

fn decided(key: &str, at: &str, matched: bool, cves: &[&str]) -> String {
    let (src, id) = key.split_once(':').unwrap();
    line("decided", key, at, json!({
        "decision": if matched { "matched" } else { "not-relevant-by-rule" }, "component": if matched { "clickhouse" } else { "" },
        "components_version": "t1", "components_sha256": "abc", "item_source": src, "item_id": id,
        "title": format!("{id} in ClickHouse"), "url": "u", "cves": cves,
        "score": 9.5, "severity": "CRITICAL", "exploited": false, "exploited_source": "",
    }))
}

fn run(at: &str, feeds: &[(&str, &str)], errors: &[&str]) -> Value {
    let fs: serde_json::Map<String, Value> = feeds.iter().map(|(f, s)| (f.to_string(), json!({"status": s}))).collect();
    json!({"run_at": at, "mode": "write", "result": "written", "feeds": fs,
           "triage": {"endpoint": "https://api.linear.app/graphql", "components": "t1", "components_sha256": "abc", "errors": errors}})
}

fn ok_feeds() -> Vec<(&'static str, &'static str)> {
    ALL_FEEDS.iter().map(|f| (*f, if *f == "NVD" { "cached" } else { "ok" })).collect()
}

/// A good November so far: one relevant item (plus one ruled out by rule), assessed
/// within an hour and accepted with an owner and a due date; every source healthy.
struct Case {
    events: Vec<String>,
    runs: Vec<Value>,
    now: &'static str,
}

impl Case {
    fn good() -> Self {
        Self {
            events: vec![
                decided(KEY, "2026-11-02T08:00:00Z", true, &["CVE-2026-1"]),
                decided("GitHub Advisory:GHSA-1", "2026-11-02T08:00:00Z", false, &[]),
                line("issue_created", KEY, "2026-11-02T08:01:00Z", json!({"identifier": "MOCK-1", "url": "t"})),
                line("triaged", KEY, "2026-11-02T09:00:00Z", json!({"state": "accepted", "actor": "Henry"})),
                line("state_changed", KEY, "2026-11-02T09:00:00Z", json!({"from": "none", "to": "accepted", "state_name": "Todo"})),
                line("field_changed", KEY, "2026-11-02T10:00:00Z", json!({"field": "assignee", "from": "", "to": "Henry"})),
                line("field_changed", KEY, "2026-11-02T10:00:01Z", json!({"field": "due", "from": "", "to": "2026-11-20"})),
            ],
            runs: vec![run("2026-11-09T10:00:00Z", &ok_feeds(), &[])],
            now: "2026-11-10T11:00:00Z",
        }
    }

    /// Drop the events whose id starts with `prefix` (kind|key|at).
    fn without(mut self, prefix: &str) -> Self {
        self.events.retain(|l| !l.contains(&format!("\"id\":\"{prefix}")));
        self
    }

    fn with(mut self, l: String) -> Self {
        self.events.push(l);
        self
    }

    fn build(&self) -> Value {
        let log = model::read_events(&self.events.join("\n")).unwrap();
        let runs = model::read_runs(&self.runs.iter().map(Value::to_string).collect::<Vec<_>>().join("\n"));
        let now = utc(self.now);
        let (start, end) = nov().bounds(now);
        build::build(&log, &runs, &build::Frame { start, end, cut: end.min(now), as_of: now, mtd: false,
                                                  list: Some(("abc".into(), 12)), environment: "lab".into(), test_run: false })
    }
}

fn due(d: &str) -> String {
    line("field_changed", KEY, "2026-11-02T10:00:02Z", json!({"field": "due", "from": "2026-11-20", "to": d}))
}

const ALL_GOOD: [&str; 2] = [
    "Every relevant item was assessed within 1 business day, no action is overdue and monitoring ran without problems.",
    "No decision is needed from you.",
];

#[test]
fn rag_green_and_bottom_line_all_good() {
    let j = Case::good().build();
    assert_eq!(j["status"], json!({"rag": "GREEN", "reasons": []}));
    assert_eq!(j["attention"], json!([]));
    assert_eq!(j["bottom_line"], json!(ALL_GOOD));
    assert_eq!(kpi(&j, "assessed").0, "1 of 1 (100%)");
    assert_eq!(kpi(&j, "sources"), ("7/7".into(), "Green".into(), "first period".into()));
    assert_eq!(j["monitoring"]["sentence"], json!(
        "7 public sources (CISA KEV, ENISA EUVD, CVE.org, GitHub Advisory, CERT-EU, NCSC-NL; NVD for scores) checked in \
         1 scheduled run (every 6 h) against component list t1 (12 components). Limits: components not on the list are not \
         checked; affected versions are not checked."));
    let i = &j["open_actions"]["items"][0];
    assert_eq!((i["vulnerability"].clone(), i["severity"].clone(), i["exploited"].clone()), (json!("CVE-2026-1"), json!("CRITICAL"), json!(false)));
    assert_eq!(j["kpis"][0]["trend"], json!("—"), "no previous month in the log");
}

#[test]
fn rag_amber_rules() {
    let amber = |c: Case, want: &str| {
        let j = c.build();
        assert_eq!(j["status"]["rag"], json!("AMBER"), "{want}: {}", j["status"]);
        assert!(texts(&j["status"]["reasons"]).iter().any(|t| t.contains(want)), "{want}: {}", j["status"]);
        j
    };
    // overdue on a non-exploited item
    let j = amber(Case::good().with(due("2026-11-05")), "MOCK-1 (CVE-2026-1): action overdue since 5 Nov (owner Henry)");
    assert_eq!(j["bottom_line"], json!(["Amber: an action is overdue.", "The points below need a decision or follow-up."]));
    assert_eq!(texts(&j["attention"]), ["Overdue action (1): MOCK-1"]);
    assert_eq!(kpi(&j, "open"), ("1 (1 overdue)".into(), "Amber".into(), "first period".into()));
    // open action without an owner
    let j = amber(Case::good().without("field_changed|CVE.org cvelistV5:CVE-2026-1|2026-11-02T10:00:00Z"), "open action without an owner");
    assert_eq!(texts(&j["attention"]), ["Open action without owner or due date (1): MOCK-1"]);
    // assessment after more than one business day (Mon 09:00 -> Tue 10:00 Amsterdam)
    let slow = Case::good().without("triaged|").with(line("triaged", KEY, "2026-11-03T09:00:00Z", json!({"state": "accepted", "actor": "Henry"})));
    let j = amber(slow, "assessment took 1.0 business days");
    assert_eq!(j["attention"], json!([]), "a past slow assessment is not an attention point");
    assert_eq!(j["bottom_line"], json!(["Amber: an assessment took more than 1 business day.", "No decision is needed from you."]));
    // a source stale in the last run; a tracker error
    let mut stale = Case::good();
    stale.runs = vec![run("2026-11-09T10:00:00Z", &[("CISA KEV", "ok"), ("CVE.org cvelistV5", "ok"), ("GitHub Advisory", "stale")], &[])];
    let j = amber(stale, "GitHub Advisory stale");
    assert_eq!(kpi(&j, "sources").0, "2/3");
    assert_eq!(texts(&j["attention"]), ["Source failing or stale in the last run (1): GitHub Advisory (stale)"]);
    assert_eq!(j["bottom_line"], json!(["Amber: a source was stale or failing in the last run.",
                                        "Monitoring needs follow-up (below); no ticket needs a decision from you."]));
    let mut tracker = Case::good();
    tracker.runs = vec![run("2026-11-09T10:00:00Z", &ok_feeds(), &["read issue states: HTTP 500"])];
    let j = amber(tracker, "Ticket tracker errors in 1 run, the last on 9 Nov");
    assert_eq!(texts(&j["attention"]), ["Ticket tracker errors: 1 run (last on 9 Nov), see appendix"]);
}

/// A decline without a reason waits like any other item (Henry, 2026-11-06): no
/// status rule and no attention line within 1 business day.
#[test]
fn decline_without_reason_within_one_business_day_is_green() {
    let mut c = declined_case();
    c.now = "2026-11-02T12:00:00Z";
    c.runs = vec![run("2026-11-02T10:00:00Z", &ok_feeds(), &[])];
    let j = c.build();
    assert_eq!(j["status"], json!({"rag": "GREEN", "reasons": []}));
    assert_eq!(j["attention"], json!([]));
    assert_eq!(assessed_waiting(&j), (json!(0), json!(0), json!(1)), "it still counts as waiting");
    assert_eq!(j["resolved"], json!([]), "waiting, not resolved");
    assert_eq!(kpi(&j, "assessed"), ("—".into(), "Green".into(), "first period".into()));
    assert_eq!(idents(&j["waiting_items"]), ["MOCK-1"]);
    assert_eq!((j["waiting_items"][0]["overdue"].clone(), j["waiting_items"][0]["declined_without_reason"].clone()),
               (json!(false), json!(true)));
    assert_eq!(idents(&j["exceptions"]["declined_without_reason"]), ["MOCK-1"]);
}

#[test]
fn rag_red_rules() {
    let red = |c: Case, want: &str| {
        let j = c.build();
        assert_eq!(j["status"]["rag"], json!("RED"), "{want}: {}", j["status"]);
        assert_eq!(j["status"]["reasons"][0]["rag"], json!("RED"), "red reasons first");
        assert!(texts(&j["status"]["reasons"]).iter().any(|t| t.contains(want)), "{want}: {}", j["status"]);
        j
    };
    // overdue on a known-exploited item: the CVE is also in CISA KEV
    let j = red(Case::good().with(due("2026-11-05")).with(decided("CISA KEV:CVE-2026-1", "2026-11-03T08:00:00Z", false, &["CVE-2026-1"])),
                "MOCK-1 (CVE-2026-1, known exploited): action overdue since 5 Nov");
    assert_eq!(kpi(&j, "exploited"), ("1".into(), "Red".into(), "first period".into()));
    assert_eq!(j["bottom_line"][0], json!("Red: an action on a known-exploited vulnerability is overdue."));
    assert_eq!(texts(&j["attention"]), ["Overdue action on a known-exploited vulnerability (1): MOCK-1"]);
    // a relevant item not assessed for more than 3 business days
    let waiting = Case::good().without("triaged|").without("state_changed|").without("field_changed|");
    let j = red(waiting, "MOCK-1 (CVE-2026-1): relevant item not assessed after more than 3 business days, first seen 2 Nov");
    assert_eq!(j["bottom_line"][0], json!("Red: a relevant item has waited more than 3 business days for assessment."));
    assert_eq!(texts(&j["attention"]), ["Not assessed after 1 business day (1): MOCK-1 (over 3 business days)"]);
    assert_eq!(kpi(&j, "assessed").0, "0 of 1 (0%)");
    // a core source failing for more than two days (fatal runs name it)
    let mut down = Case::good();
    let fatal = |at: &str| json!({"run_at": at, "result": "fatal", "error": "CISA KEV: network error"});
    down.runs = vec![run("2026-11-02T10:00:00Z", &ok_feeds(), &[]), fatal("2026-11-03T10:00:00Z"), fatal("2026-11-09T10:00:00Z")];
    let j = red(down, "CISA KEV failing since 3 Nov (more than 2 days)");
    assert_eq!(kpi(&j, "sources").0, "6/7", "the fatal run marks CISA KEV failing");
    assert_eq!(texts(&j["attention"]), ["Source failing or stale in the last run (1): CISA KEV (failing since 3 Nov)"]);
    assert_eq!(j["bottom_line"][0], json!("Red: a core source has been failing for more than 2 days."));
}

/// The good case declined in Linear (Mon 2 Nov 10:00 Amsterdam, first seen 09:00), no reason yet.
fn declined_case() -> Case {
    Case::good().without("triaged|").without("state_changed|").without("field_changed|")
        .with(line("triaged", KEY, "2026-11-02T09:00:00Z", json!({"state": "declined", "actor": "Henry"})))
        .with(line("state_changed", KEY, "2026-11-02T09:00:00Z", json!({"from": "none", "to": "declined", "state_name": "Canceled"})))
}

/// The reason read back at `at` (log write `ts`), with the comment's time when given.
fn reason_line(at: &str, ts: &str, reason_at: Option<&str>) -> String {
    let mut extra = json!({"field": "reason", "from": "", "to": "not deployed", "ts": ts});
    if let Some(r) = reason_at {
        extra["reason_at"] = json!(r);
    }
    line("field_changed", KEY, at, extra)
}

/// (assessed, ruled out by a person, waiting) of the funnel.
fn assessed_waiting(j: &Value) -> (Value, Value, Value) {
    let f = &j["funnel"];
    (f["assessed"].clone(), f["ruled_out_by_person"].clone(), f["waiting"].clone())
}

/// One definition of waiting (Henry, 2026-11-06): a decline without a reason is not
/// assessed; it waits, and turns overdue after 1 business day like any waiting item.
#[test]
fn decline_without_reason_waits_and_turns_overdue() {
    let mut c = declined_case();
    c.now = "2026-11-03T12:00:00Z"; // Tue 13:00 Amsterdam: 28 business hours since first seen
    c.runs = vec![run("2026-11-03T10:00:00Z", &ok_feeds(), &[])];
    let j = c.build();
    assert_eq!(assessed_waiting(&j), (json!(0), json!(0), json!(1)));
    assert_eq!(j["funnel"]["waiting_without_reason"], json!(1));
    assert_eq!(j["funnel"]["time_to_assess"]["count"], json!(0));
    assert_eq!(idents(&j["funnel"]["over_one_day"]), ["MOCK-1"]);
    let row = &j["funnel"]["over_one_day"][0];
    assert_eq!((row["assessed_at"].clone(), row["declined_without_reason"].clone()), (Value::Null, json!(true)));
    assert_eq!(idents(&j["exceptions"]["unassessed_over_one_day"]), ["MOCK-1"]);
    assert_eq!(idents(&j["exceptions"]["declined_without_reason"]), ["MOCK-1"]);
    assert_eq!(idents(&j["exceptions"]["triaged_without_actor"]), Vec::<&str>::new());
    assert_eq!(kpi(&j, "assessed"), ("0 of 1 (0%)".into(), "Amber".into(), "first period".into()));
    assert_eq!(j["status"]["rag"], json!("AMBER"));
    assert_eq!(texts(&j["status"]["reasons"]),
               ["MOCK-1 (CVE-2026-1): ruled out without a reason, so not assessed after more than 1 business day, first seen 2 Nov"]);
    assert_eq!(texts(&j["attention"]), ["Not assessed after 1 business day (1): MOCK-1 (declined without a reason)"]);
    assert_eq!((j["resolved"].clone(), j["outcomes"]["ruled_out"].clone()), (json!([]), json!([])));
    // more than 3 business days: red, as for an item still in Triage
    let mut late = declined_case();
    late.now = "2026-11-10T11:00:00Z";
    let j = late.build();
    assert_eq!(j["status"]["rag"], json!("RED"));
    assert_eq!(texts(&j["status"]["reasons"]),
               ["MOCK-1 (CVE-2026-1): ruled out without a reason, so not assessed after more than 3 business days, first seen 2 Nov"]);
}

/// A reason added later: assessed when it arrived (comment written Tue 14:00
/// Amsterdam, read back at 15:00), not at the decline; resolved then too.
#[test]
fn reason_added_later_assesses_at_the_reason_time() {
    let c = declined_case().with(reason_line("2026-11-03T14:00:00Z", "2026-11-03T14:00:00Z", Some("2026-11-03T13:00:00Z")));
    let j = c.build();
    assert_eq!(assessed_waiting(&j), (json!(1), json!(1), json!(0)));
    assert_eq!(j["funnel"]["time_to_assess"], json!({"count": 1, "median_business_hours": 29.0, "max_business_hours": 29.0}));
    let row = &j["funnel"]["over_one_day"][0];
    assert_eq!((row["assessed_at"].clone(), row["business_hours"].clone()), (json!("2026-11-03T14:00:00+01:00"), json!(29.0)));
    assert_eq!(kpi(&j, "assessed"), ("0 of 1 (0%)".into(), "Amber".into(), "first period".into()));
    assert_eq!(texts(&j["status"]["reasons"]), ["MOCK-1: assessment took 1.2 business days"]);
    assert_eq!(j["attention"], json!([]), "a past slow assessment is not an attention point");
    assert_eq!(j["resolved"][0]["outcome"], json!("ruled out by Henry: not deployed"));
    assert_eq!(j["outcomes"]["ruled_out"][0]["declined_at"], json!("2026-11-03T14:00:00+01:00"));
    assert_eq!(j["exceptions"]["declined_without_reason"], json!([]));
    assert_eq!(j["bottom_line"][0], json!("Amber: an assessment took more than 1 business day."));
    assert_eq!(j["resolved"][0]["detail"], json!("not deployed"));

    // Written but not read back yet at the cut-off: still waiting.
    let mut before = declined_case().with(reason_line("2026-11-03T14:00:00Z", "2026-11-03T14:00:00Z", Some("2026-11-03T13:00:00Z")));
    before.now = "2026-11-03T13:30:00Z";
    assert_eq!(assessed_waiting(&before.build()), (json!(0), json!(0), json!(1)));

    // An event logged before 2026-11-06 has no reason_at: the read-back that first saw it.
    let old = declined_case().with(reason_line("2026-11-03T14:00:00Z", "2026-11-03T14:00:00Z", None));
    assert_eq!(old.build()["funnel"]["time_to_assess"]["max_business_hours"], json!(30.0));
}

/// A reason written with the decline (a comment up to 5 s before it counts):
/// assessed at the triage time, whether the event has reason_at or not.
#[test]
fn reason_with_the_decline_assesses_at_triage_time() {
    for reason_at in [Some("2026-11-02T08:59:57Z"), Some(""), None] {
        // Same log write as the triage (Case lines share one `ts`).
        let c = declined_case().with(reason_line("2026-11-02T10:00:00Z", "2026-11-01T00:00:00Z", reason_at));
        let j = c.build();
        assert_eq!(assessed_waiting(&j), (json!(1), json!(1), json!(0)), "{reason_at:?}");
        assert_eq!(j["funnel"]["time_to_assess"], json!({"count": 1, "median_business_hours": 1.0, "max_business_hours": 1.0}));
        assert_eq!(j["outcomes"]["ruled_out"][0]["declined_at"], json!("2026-11-02T10:00:00+01:00"));
        assert_eq!(j["status"], json!({"rag": "GREEN", "reasons": []}));
        assert_eq!(kpi(&j, "assessed").0, "1 of 1 (100%)");
        assert_eq!(j["bottom_line"], json!(ALL_GOOD));
    }
}

/// Canceled, then reopened: the reopen carries the triage time, earlier than the
/// cancel, but was logged later; the ticket is open and not resolved.
#[test]
fn reopened_ticket_is_open() {
    let c = Case::good()
        .with(line("state_changed", KEY, "2026-11-03T10:00:00Z", json!({"from": "accepted", "to": "canceled", "state_name": "Canceled"})))
        .with(line("state_changed", KEY, "2026-11-02T09:00:30Z", json!({"from": "canceled", "to": "accepted", "state_name": "Todo"})));
    let j = c.build();
    assert_eq!(idents(&j["open_actions"]["items"]), ["MOCK-1"]);
    assert_eq!(j["resolved"], json!([]));
    assert_eq!(j["status"]["rag"], json!("GREEN"));
    assert_backlog(&j, [0, 1, 0, 0, 0, 1]);
}

/// [open at start, accepted, reopened, fixed, closed without fix, open at end]; the
/// backlog reconciles with no "other" change, and open at end is the open actions.
fn assert_backlog(j: &Value, want: [i64; 6]) {
    let b = &j["backlog"];
    let n = |k: &str| b[k].as_i64().unwrap();
    assert_eq!([n("open_start"), n("accepted"), n("reopened"), n("fixed"), n("closed_without_fix"), n("open_end")], want, "{b}");
    assert_eq!(n("other"), 0, "{b}");
    assert_eq!(n("open_start") + n("accepted") + n("reopened") - n("fixed") - n("closed_without_fix") + n("other"), n("open_end"));
    assert_eq!(json!(n("open_end")), j["open_actions"]["count"]);
}

/// Action backlog: open at start + accepted + reopened - fixed - closed without fix
/// = open at end, from the event log.
#[test]
fn action_backlog_reconciles() {
    // The fixture month: A open from October and fixed; B, E, I accepted; E canceled.
    let _t = lab("report-backlog");
    let j = generate(&nov(), utc("2026-12-03T08:00:00Z"), &no_pdf()).unwrap().json;
    assert_backlog(&j, [1, 3, 0, 1, 1, 2]);

    // Accepted and done between two read-backs: no `accepted` state was ever logged.
    let quick = Case::good().without("state_changed|")
        .with(line("state_changed", KEY, "2026-11-04T09:00:00Z", json!({"from": "none", "to": "done", "state_name": "Done"})));
    assert_backlog(&quick.build(), [0, 1, 0, 1, 0, 0]);

    // Accepted and fixed in October, reopened in November: carried in as reopened.
    let oct = |s: &str| s.replace("2026-11-02", "2026-10-05");
    let mut re = Case::good();
    re.events = re.events.iter().map(|l| oct(l)).collect();
    let re = re
        .with(line("state_changed", KEY, "2026-10-06T09:00:00Z", json!({"from": "accepted", "to": "done", "state_name": "Done"})))
        .with(line("state_changed", KEY, "2026-11-03T09:00:00Z", json!({"from": "done", "to": "accepted", "state_name": "Todo"})));
    let j = re.build();
    assert_backlog(&j, [0, 0, 1, 0, 0, 1]);
    assert_eq!(j["open_actions"]["items"][0]["carried_over"], json!(true));

    // Open from October, canceled in November.
    let oct_open = Case { events: Case::good().events.iter().map(|l| oct(l)).collect(), ..Case::good() }
        .with(line("state_changed", KEY, "2026-11-04T09:00:00Z", json!({"from": "accepted", "to": "canceled", "state_name": "Canceled"})));
    assert_backlog(&oct_open.build(), [1, 0, 0, 0, 1, 0]);
}

/// The review reminder of a closed month is printed in the appendix when review.json
/// already names its issue; a month to date never carries it.
#[test]
fn review_issue_from_review_json() {
    let t = lab("report-review-issue");
    let now = utc("2026-12-03T08:00:00Z");
    assert!(generate(&nov(), now, &no_pdf()).unwrap().json.get("review_issue").is_none());
    std::fs::write(t.dir.join("reports/2026-11/review.json"),
                   json!({"month": "2026-11", "issue": {"id": "u", "identifier": "MOCK-9", "url": "x"}}).to_string()).unwrap();
    assert_eq!(generate(&nov(), now, &no_pdf()).unwrap().json["review_issue"], json!("MOCK-9"));
    let mtd = utc("2026-11-20T08:00:00Z");
    assert!(generate(&Period::MonthToDate, mtd, &no_pdf()).unwrap().json.get("review_issue").is_none());
}

#[test]
fn bottom_line_zero_relevant() {
    let c = Case { events: vec![decided("GitHub Advisory:GHSA-1", "2026-11-02T08:00:00Z", false, &[]),
                                decided("GitHub Advisory:GHSA-2", "2026-11-02T08:00:00Z", false, &[])],
                   ..Case::good() };
    let j = c.build();
    assert_eq!(j["status"]["rag"], json!("GREEN"));
    assert_eq!(j["bottom_line"], json!([
        "No new public vulnerability notice concerned a component on fairCT's list, and monitoring ran without problems.",
        "No decision is needed from you.",
    ]));
    assert_eq!(kpi(&j, "assessed").0, "—");
    assert_eq!(kpi(&j, "fixed"), ("—".into(), "—".into(), "first period".into()));
    assert_eq!(j["open_actions"]["count"], json!(0));
}

#[test]
fn exploited_by_cve_and_ssvc() {
    // The event's own flag (SSVC active) is kept; a KEV decision for the same CVE marks another item.
    let ssvc = Case::good().without("decided|CVE.org").with(line("decided", KEY, "2026-11-02T08:00:00Z", json!({
        "decision": "matched", "component": "clickhouse", "item_source": "CVE.org cvelistV5", "item_id": "CVE-2026-1",
        "title": "t", "cves": ["CVE-2026-1"], "exploited": true, "exploited_source": "SSVC active"})));
    assert_eq!(ssvc.build()["open_actions"]["items"][0]["exploited_source"], json!("SSVC active"));
    let euvd = Case::good().with(decided("ENISA EUVD:CVE-2026-1", "2026-11-04T08:00:00Z", false, &["CVE-2026-1"]));
    let j = euvd.build();
    assert_eq!(j["open_actions"]["items"][0]["exploited_source"], json!("ENISA EUVD"));
    assert_eq!(kpi(&j, "exploited"), ("1".into(), "Green".into(), "first period".into()), "open on plan");
    // not yet known at an earlier cut-off
    let mut early = Case::good().with(decided("ENISA EUVD:CVE-2026-1", "2026-11-04T08:00:00Z", false, &["CVE-2026-1"]));
    early.now = "2026-11-03T12:00:00Z";
    assert_eq!(early.build()["open_actions"]["items"][0]["exploited"], json!(false));
}

#[test]
fn previous_month_uses_the_same_rules() {
    // October: the good case; November: nothing new, the action still open.
    // The log (its first line) starts on 1 October.
    let oct = |s: &str| s.replace("2026-11-02", "2026-10-05").replace("\"ts\":\"2026-11-01", "\"ts\":\"2026-10-01");
    let mut c = Case::good();
    c.events = c.events.iter().map(|l| oct(l)).collect();
    let j = c.build();
    assert_eq!(j["previous"], json!({"month": "2026-10", "label": "October 2026", "covered": true, "partial": true}));
    assert_eq!(kpi(&j, "relevant"), ("0".into(), "—".into(), "1".into()));
    assert_eq!(kpi(&j, "open"), ("1 (0 overdue)".into(), "Green".into(), "1 (0 overdue)".into()));
    assert_eq!(kpi(&j, "sources").2, "no data", "no run in October");
}

#[test]
#[ignore = "needs the typst CLI (TYPST_BIN); the job image has it"]
fn renders_pdf_with_typst() {
    let _t = lab("report-pdf");
    let g = generate(&nov(), utc("2026-12-03T08:00:00Z"), &Opts { pdf: true, ..Default::default() }).unwrap();
    let pdf = g.pdf.as_ref().unwrap();
    assert!(pdf.starts_with(b"%PDF-"));
    assert_eq!(g.pdf_sha, hex::encode(Sha256::digest(pdf)));
    let sums = std::fs::read_to_string(g.dir.join("SHA256SUMS")).unwrap();
    assert!(sums.ends_with(&format!("{}  report.pdf\n", g.pdf_sha)), "{sums}");
}

// ------------------------------------------------------------------ marking, KPI note, close events

#[test]
fn marking_by_environment() {
    let mock = "http://linear-mock:8080/graphql";
    let real = "https://api.linear.app/graphql";
    assert_eq!(build::marking("lab", mock, false).0, "LAB DATA");
    assert_eq!(build::marking("lab", real, false).0, "TEST DATA");
    assert_eq!(build::marking("test", real, false).0, "TEST DATA");
    assert_eq!(build::marking("test", mock, false).0, "LAB DATA");
    assert_eq!(build::marking("production", real, false), ("", String::new()));
    assert_eq!(build::marking(" Production ", mock, false).0, "", "production: no marking, whatever the tracker");
    assert_eq!(build::marking("prod", real, false).0, "TEST DATA", "an unknown value is not production");
    // --now: at least TEST DATA
    let (label, notice) = build::marking("production", real, true);
    assert_eq!(label, "TEST DATA");
    assert!(notice.ends_with("not fairCT's. A test run with a set clock; not a report to send."), "{notice}");
    assert_eq!(build::marking("lab", mock, true).0, "LAB DATA");
    assert!(build::marking("lab", mock, true).1.ends_with("A test run with a set clock; not a report to send."));
    assert!(environment_from(&|_| None) == "lab");
    assert_eq!(environment_from(&|_| Some(" TEST ".into())), "test");
}

#[test]
fn marking_in_report_json_and_fix_target_note() {
    let _t = lab("report-marking");
    let opts = |env: &str| Opts { pdf: false, environment: Some(env.into()), ..Default::default() };
    let now = utc("2026-12-03T08:00:00Z");
    let j = generate(&nov(), now, &opts("production")).unwrap().json;
    assert_eq!(j["marking"], json!({"label": "", "notice": "", "environment": "production", "test_run": false}));
    let j = generate(&nov(), now, &Opts { test_run: true, ..opts("production") }).unwrap().json;
    assert_eq!(j["marking"]["label"], json!("LAB DATA"), "--now: marked; the fixture's tracker is linear-mock");
    let fixed = j["kpis"].as_array().unwrap().iter().find(|k| k["key"] == "fixed").unwrap();
    assert_eq!((fixed["target"].clone(), fixed["target_note"].clone()),
               (json!("≥ 95%"), json!("team proposal, pending agreement")));
    let open = j["kpis"].as_array().unwrap().iter().find(|k| k["key"] == "open").unwrap();
    assert_eq!(open["target_note"], Value::Null);
    // The template prints the marking and the note, not a fixed LAB DATA.
    let t = pdf::TEMPLATE;
    assert!(!t.contains("[LAB DATA]") && !t.contains("lab_data"));
    assert!(t.contains("#let mark = d.marking.label") && t.contains("k.target_note"));
    assert!(t.contains("team proposal pending agreement") && t.contains("NIST SP 800-40r4"));
    assert!(t.contains("Quality check sample — automatically ruled-out items"));
    // Review is reminder-only: no signature lines; the footer carries no data sha.
    assert!(!t.contains("Reviewed by") && !t.contains("Acknowledged by"));
    assert!(!t.contains("== Exceptions") && !t.contains("Resolved in the period"));
}

/// The monthly close appends report_frozen, sample_drawn and review_issue_created
/// with key report:YYYY-MM to the same log: the report counts nothing new.
#[test]
fn close_events_do_not_change_the_report() {
    let t = temp_state("report-close-events");
    // The fixture without its half-written last line, which an append would turn into a bad middle line.
    let raw = String::from_utf8(fixture("report_events.jsonl")).unwrap();
    let clean: String = raw.lines().filter(|l| serde_json::from_str::<Value>(l).is_ok()).map(|l| format!("{l}\n")).collect();
    std::fs::write(t.dir.join(EVENTS_FILE), &clean).unwrap();
    std::fs::write(t.dir.join("runs.jsonl"), fixture("report_runs.jsonl")).unwrap();
    let now = utc("2026-12-03T08:00:00Z");
    let before = generate(&nov(), now, &no_pdf()).unwrap();
    let mtd_now = utc("2026-11-25T08:00:00Z");
    let mtd = |n| generate(&Period::MonthToDate, n, &Opts { tickets_as_of: Some(n), ..no_pdf() }).unwrap();
    let mtd_before = mtd(mtd_now);
    let ev = |kind: &str, at: &str, f: Value| crate::triage::store::event(kind, "report:2026-11", at, &[kind], now, "live", f);
    crate::feeds::state::append_jsonl(EVENTS_FILE, &[
        ev("report_frozen", "2026-11-20T06:00:00Z", json!({"data_sha": "x", "pdf_sha": "y", "marking": "LAB DATA"})),
        ev("sample_drawn", "2026-11-20T06:00:00Z", json!({"size": 10, "candidates": 1, "keys": ["GitHub:GHSA-gggg"]})),
        ev("review_issue_created", "2026-11-20T06:00:01Z", json!({"issue_id": "i", "identifier": "MOCK-9", "url": "u"})),
    ]);
    let after = generate(&nov(), now, &no_pdf()).unwrap();
    assert_eq!(after.data_sha, before.data_sha, "same data");
    assert_eq!(after.json["funnel"], before.json["funnel"]);
    assert_eq!(after.json["kpis"], before.json["kpis"]);
    assert_eq!(after.json["coverage"]["duplicates_dropped"], before.json["coverage"]["duplicates_dropped"]);
    assert_eq!(after.json["exceptions"]["log_lines_skipped"], json!(0));
    let mtd_after = mtd(mtd_now);
    assert_eq!((mtd_after.data_sha, mtd_after.as_of), (mtd_before.data_sha, mtd_before.as_of));
    let log = model::read_events(&std::fs::read_to_string(t.dir.join(EVENTS_FILE)).unwrap()).unwrap();
    assert!(log.events.iter().all(|e| !e.key.starts_with("report:")));
}

#[test]
#[ignore = "needs the typst CLI (TYPST_BIN); the job image has it"]
fn renders_monthly_pdf_with_sample_and_test_marking() {
    let _t = lab("report-pdf-monthly");
    let sample = json!({"size": 10, "candidates": 2, "seed": "ab".repeat(32), "method": "m", "note": "",
                        "items": [{"key": "GitHub Advisory:GHSA-gggg-1111-2222", "source": "GitHub Advisory",
                                   "first_seen": "2026-11-02T09:30:00+01:00", "title": "G: a library [x] #1 *bold* _u_ $5",
                                   "vendor_product": "npm:left-pad", "url": "https://github.com/advisories/GHSA-gggg-1111-2222",
                                   "from": "triage.json"},
                                  {"key": "NCSC-NL:NCSC-2026-0001", "source": "NCSC-NL", "first_seen": "2026-11-03T09:30:00+01:00",
                                   "title": "", "vendor_product": "", "url": "", "from": "key"}]});
    let opts = Opts { pdf: true, environment: Some("production".into()), test_run: true, sample: Some(sample),
                      ..Default::default() };
    let g = generate(&nov(), utc("2026-12-01T05:00:00Z"), &opts).unwrap();
    assert!(g.pdf.as_ref().unwrap().starts_with(b"%PDF-"));
    assert_eq!(g.json["marking"]["label"], json!("LAB DATA"));
    // and an empty sample, production without marking
    std::fs::remove_dir_all(g.dir.clone()).unwrap();
    let empty = json!({"size": 10, "candidates": 0, "seed": "cd".repeat(32), "method": "m",
                       "note": "No automatically ruled-out items in the period.", "items": []});
    let g = generate(&nov(), utc("2026-12-01T05:00:00Z"),
                     &Opts { pdf: true, environment: Some("production".into()), sample: Some(empty), ..Default::default() }).unwrap();
    assert!(g.pdf.as_ref().unwrap().starts_with(b"%PDF-"));
    assert_eq!(g.json["marking"]["label"], json!(""));
}
