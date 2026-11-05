//! Report engine tests on tests/fixtures/report_events.jsonl and report_runs.jsonl:
//! items A..I (titles say what each one is for), a repeated id, a second decision
//! of a key after a crash and a half-written last line; coverage from 2026-10-20.

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
    Opts { pdf: false, tickets_as_of: None }
}

fn idents(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x["identifier"].as_str().unwrap()).collect()
}

#[test]
fn november_figures() {
    let _t = lab("report-nov");
    let g = generate(&nov(), utc("2026-12-03T08:00:00Z"), &no_pdf()).unwrap();
    let j = &g.json;
    assert_eq!(g.label, "Monthly report 2026-11");
    assert_eq!(g.as_of, "2026-11-29T10:00:00Z", "last writing run with a read-back");
    assert_eq!(j["as_of"], json!("2026-11-29T10:00:00Z"));
    assert_eq!(j["tickets_as_of"], json!("2026-11-29T11:00:00+01:00"));
    assert_eq!(g.coverage_from, "2026-10-20T08:00:00Z");
    assert_eq!(j["period"]["start"], json!("2026-11-01T00:00:00+01:00"));
    assert_eq!(j["period"]["end"], json!("2026-12-01T00:00:00+01:00"));
    assert_eq!((j["period"]["complete"].clone(), j["coverage"]["partial"].clone()), (json!(true), json!(false)));
    assert_eq!(j["coverage"]["duplicates_dropped"], json!(2), "repeated id + second decision of B");
    assert_eq!(j["coverage"]["half_written_tail"], json!(true));
    assert_eq!(j["tracker"], json!({"endpoint": "http://linear-mock:8080/graphql", "lab_data": true}));
    assert_eq!(j["components"][0]["decisions"], json!(7));
    // writing runs only: the dry run is out, fatal (no mode) and locked are in
    assert_eq!(j["runs"], json!({"writing": 5, "by_result": {"fatal": 1, "locked": 1, "unchanged": 1, "written": 2}}));
    assert_eq!(j["feeds"][0], json!({"feed": "CISA KEV", "runs": 3, "ok": 2, "by_status": {"error": 1, "ok": 2},
                                     "last_status": "ok"}));

    assert_eq!(j["intake"]["total"], json!(7));
    assert_eq!(j["intake"]["by_source"], json!([
        {"source": "CISA KEV", "total": 6, "matched": 6, "not_relevant": 0},
        {"source": "GitHub Advisory", "total": 1, "matched": 0, "not_relevant": 1}]));

    let t = &j["triage"];
    assert_eq!((t["auto_not_relevant"].clone(), t["matched"].clone()), (json!(1), json!(6)));
    // A was triaged in October: not counted here although it closed in November
    assert_eq!(t["triaged"], json!({"total": 5, "accepted": 3, "declined_with_reason": 1, "declined_without_reason": 1}));
    assert_eq!(t["untriaged_at_end"], json!(1));
    assert_eq!(t["time_to_triage"], json!({"count": 5, "median_business_hours": 1.0, "max_business_hours": 49.0}));
    let br = t["sla_breaches"].as_array().unwrap();
    assert_eq!(idents(&t["sla_breaches"]), ["MOCK-5", "MOCK-7"]);
    assert_eq!((br[0]["triaged_at"].clone(), br[0]["business_hours"].clone()), (json!("2026-11-09T10:00:00+01:00"), json!(49.0)));
    assert_eq!((br[1]["triaged_at"].clone(), br[1]["business_hours"].clone()), (Value::Null, json!(159.0)), "not yet");

    let a = &j["actions_taken"];
    assert_eq!(idents(&a["done"]), ["MOCK-1"]);
    assert_eq!(a["done"][0]["on_time"], json!(true));
    assert_eq!(a["done"][0]["owner"], json!("Ann"));
    assert_eq!((a["on_time"].clone(), a["late"].clone(), a["mttr_median_days"].clone()), (json!(1), json!(0), json!(7.0)));
    assert_eq!(idents(&a["canceled"]), ["MOCK-5"]);
    assert_eq!(idents(&a["declined"]), ["MOCK-3", "MOCK-4"]);
    assert_eq!(a["declined"][0]["reason"], json!("component not deployed"));

    let o = &j["actions_open"];
    assert_eq!(idents(&o["items"]), ["MOCK-2", "MOCK-6"]);
    assert_eq!((o["count"].clone(), o["overdue"].clone()), (json!(2), json!(1)));
    assert_eq!(o["items"][0]["owner"], json!("Bob"));
    assert_eq!((o["items"][0]["overdue"].clone(), o["items"][0]["age_days"].clone()), (json!(true), json!(28)));
    assert_eq!(o["items"][0]["state_name"], json!("In Progress"));

    let e = &j["exceptions"];
    assert_eq!(idents(&e["open_without_owner"]), ["MOCK-6"]);
    assert_eq!(idents(&e["open_without_due"]), ["MOCK-6"]);
    assert_eq!(idents(&e["declined_without_reason"]), ["MOCK-4"]);
    assert_eq!(idents(&e["triaged_without_actor"]), ["MOCK-4"]);
    assert_eq!(e["tracker_errors"], json!([{"run_at": "2026-11-15T11:00:00+01:00",
                                            "error": "read issue states: Linear: network error"}]));
    assert_eq!(e["log_lines_skipped"], json!(0));

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
fn october_starts_before_coverage_and_is_reconstructed() {
    let _t = lab("report-oct");
    let g = generate(&Period::Month { year: 2026, month: 10 }, utc("2026-12-03T08:00:00Z"), &no_pdf()).unwrap();
    let j = &g.json;
    assert_eq!(j["coverage"]["partial"], json!(true), "October starts before 2026-10-20");
    assert_eq!(j["intake"]["total"], json!(2));
    assert_eq!(j["triage"]["triaged"]["accepted"], json!(1));
    assert_eq!(j["actions_taken"]["done_count"], json!(0), "A closed in November");
    // A at the end of October: accepted, owner and due date known, not overdue yet
    assert_eq!(idents(&j["actions_open"]["items"]), ["MOCK-1"]);
    assert_eq!(j["actions_open"]["items"][0]["due"], json!("2026-11-10"));
    assert_eq!(j["actions_open"]["items"][0]["overdue"], json!(false));
    assert_eq!(g.as_of, "2026-10-31T10:00:00Z");
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
                     &Opts { pdf: false, tickets_as_of: Some(utc("2026-11-30T12:00:00Z")) }).unwrap();
    assert_ne!(a.data_sha, c.data_sha, "tickets as of is data");
    assert_eq!(c.as_of, "2026-11-30T12:00:00Z");
}

#[test]
fn month_to_date_runs_to_now() {
    let _t = lab("report-mtd");
    let now = utc("2026-11-10T12:00:00Z");
    let g = generate(&Period::MonthToDate, now, &Opts { pdf: false, tickets_as_of: Some(now) }).unwrap();
    assert_eq!(g.label, "On-demand snapshot 2026-11 (to 2026-11-10) – not the official monthly report");
    assert!(g.dir.ends_with("reports/month-to-date"));
    let j = &g.json;
    assert_eq!((j["period"]["kind"].clone(), j["period"]["complete"].clone()), (json!("month-to-date"), json!(true)));
    assert_eq!(j["period"]["end"], json!("2026-11-10T13:00:00+01:00"));
    // E is canceled on the 12th: still open on the 10th; F is decided on the 20th
    assert_eq!(idents(&j["actions_open"]["items"]), ["MOCK-2", "MOCK-5", "MOCK-6"]);
    assert_eq!(j["triage"]["untriaged_at_end"], json!(0));
    assert_eq!(j["intake"]["total"], json!(6));
}

#[test]
fn current_month_is_marked_incomplete() {
    let _t = lab("report-partial");
    let g = generate(&nov(), utc("2026-11-10T12:00:00Z"), &no_pdf()).unwrap();
    assert_eq!(g.json["period"]["complete"], json!(false));
    assert_eq!(g.json["period"]["data_to"], json!("2026-11-10T13:00:00+01:00"));
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
        build::build(&log, &[], &build::Frame { start, end, cut: end, as_of: end })["intake"]["total"].clone()
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

#[test]
#[ignore = "needs the typst CLI (TYPST_BIN); the job image has it"]
fn renders_pdf_with_typst() {
    let _t = lab("report-pdf");
    let g = generate(&nov(), utc("2026-12-03T08:00:00Z"), &Opts { pdf: true, tickets_as_of: None }).unwrap();
    let pdf = g.pdf.as_ref().unwrap();
    assert!(pdf.starts_with(b"%PDF-"));
    assert_eq!(g.pdf_sha, hex::encode(Sha256::digest(pdf)));
    let sums = std::fs::read_to_string(g.dir.join("SHA256SUMS")).unwrap();
    assert!(sums.ends_with(&format!("{}  report.pdf\n", g.pdf_sha)), "{sums}");
}
