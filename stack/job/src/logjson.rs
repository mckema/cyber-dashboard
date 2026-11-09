//! One structured log line per run, for Cloud Logging (README, Deployment).
//!
//! With `LOG_FORMAT=json` every line `run` adds to runs.jsonl (written,
//! unchanged, would-write, out, locked, fatal, crash) is also printed to stdout
//! as one JSON object, which Cloud Logging stores as `jsonPayload` with the
//! given `severity`:
//!
//!   {"severity":"INFO","message":"run written","event":"run_summary",
//!    "result":"written","tracker_errors":0,"report_error":false,
//!    "close_month_error":false,"run_at":"…","seconds":41.2}
//!
//! The log-based metrics and alerts in deploy/terraform read `event`, `result`,
//! `tracker_errors`, `report_error` and `close_month_error`. Other output stays
//! plain text. Without `LOG_FORMAT=json` nothing is printed here.

use serde_json::{Map, Value, json};

pub fn enabled() -> bool {
    enabled_from(std::env::var("LOG_FORMAT").ok().as_deref())
}

fn enabled_from(v: Option<&str>) -> bool {
    v.is_some_and(|s| s.trim().eq_ignore_ascii_case("json"))
}

/// Print the summary of one runs.jsonl line of `run` (no-op unless enabled).
pub fn run_summary(rec: &Value) {
    if enabled() {
        println!("{}", summary(rec));
    }
}

fn is_set(v: Option<&Value>) -> bool {
    matches!(v, Some(x) if !x.is_null() && x.as_str() != Some(""))
}

/// The JSON line for one runs.jsonl record.
pub fn summary(rec: &Value) -> Value {
    let result = rec.get("result").and_then(Value::as_str).unwrap_or("unknown");
    let tracker_errors = rec
        .pointer("/triage/errors")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let report_error = rec
        .get("report")
        .is_some_and(|r| is_set(r.get("error")) || is_set(r.get("upload_error")));
    let close_month_error = rec.get("close_month").is_some_and(|c| {
        ["error", "upload_error", "review_error", "archive_error"]
            .iter()
            .any(|k| is_set(c.get(*k)))
    });
    let severity = match result {
        "fatal" | "crash" => "ERROR",
        "locked" => "WARNING",
        _ if tracker_errors > 0 || report_error || close_month_error => "WARNING",
        _ => "INFO",
    };
    let mut m = Map::new();
    m.insert("severity".into(), json!(severity));
    let mut message = format!("run {result}");
    if let Some(e) = rec.get("error").and_then(Value::as_str) {
        message.push_str(": ");
        message.push_str(e);
    }
    m.insert("message".into(), json!(message));
    m.insert("event".into(), json!("run_summary"));
    m.insert("result".into(), json!(result));
    m.insert("tracker_errors".into(), json!(tracker_errors));
    m.insert("report_error".into(), json!(report_error));
    m.insert("close_month_error".into(), json!(close_month_error));
    for k in ["run_at", "mode", "seconds"] {
        if let Some(v) = rec.get(k) {
            m.insert(k.into(), v.clone());
        }
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_only_for_json() {
        assert!(enabled_from(Some("json")));
        assert!(enabled_from(Some(" JSON ")));
        assert!(!enabled_from(Some("text")));
        assert!(!enabled_from(None));
    }

    #[test]
    fn written_run_is_info() {
        let s = summary(&json!({"run_at": "2026-11-09T00:00:00Z", "result": "written", "seconds": 4.2,
                                "triage": {"errors": []}, "report": {"uploaded": true, "upload_error": null}}));
        assert_eq!(s["severity"], "INFO");
        assert_eq!(s["event"], "run_summary");
        assert_eq!(s["result"], "written");
        assert_eq!(s["message"], "run written");
        assert_eq!(s["tracker_errors"], 0);
        assert_eq!(s["report_error"], false);
        assert_eq!(s["close_month_error"], false);
        assert_eq!(s["seconds"], 4.2);
    }

    #[test]
    fn soft_errors_are_warnings() {
        let s = summary(&json!({"result": "unchanged", "triage": {"errors": [{"m": 1}, {"m": 2}]}}));
        assert_eq!((s["severity"].as_str(), s["tracker_errors"].as_u64()), (Some("WARNING"), Some(2)));
        let s = summary(&json!({"result": "written", "report": {"upload_error": "HTTP 500"}}));
        assert_eq!((s["severity"].as_str(), s["report_error"].as_bool()), (Some("WARNING"), Some(true)));
        for k in ["error", "upload_error", "review_error", "archive_error"] {
            let s = summary(&json!({"result": "written", "close_month": {k: "x"}}));
            assert_eq!(s["close_month_error"], true, "{k}");
            assert_eq!(s["severity"], "WARNING", "{k}");
        }
        let s = summary(&json!({"result": "written", "close_month": {"upload_error": null, "skipped": "not due"}}));
        assert_eq!(s["severity"], "INFO");
    }

    #[test]
    fn fatal_crash_locked() {
        let s = summary(&json!({"result": "fatal", "error": "CISA KEV: HTTP 503"}));
        assert_eq!(s["severity"], "ERROR");
        assert_eq!(s["message"], "run fatal: CISA KEV: HTTP 503");
        assert_eq!(summary(&json!({"result": "crash"}))["severity"], "ERROR");
        assert_eq!(summary(&json!({"result": "locked", "mode": "write"}))["severity"], "WARNING");
        assert_eq!(summary(&json!({"result": "locked", "mode": "write"}))["mode"], "write");
    }
}
