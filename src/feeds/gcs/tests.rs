//! GCS client, state mirror and lease against the canned HTTP server of
//! wiki::testing (one reply per request, in order; no network).

use std::panic::{AssertUnwindSafe, catch_unwind};

use chrono::Duration as Days;
use serde_json::json;

use super::*;
use crate::feeds::common::iso_utc;
use crate::feeds::state::{self, testing::temp_gcs_state};
use crate::wiki::testing::{Canned, canned, serve};

fn ok(v: Value) -> Canned {
    canned(200, &v.to_string())
}

fn generation(g: i64) -> Canned {
    ok(json!({"name": "x", "generation": g.to_string()}))
}

fn empty_list() -> Canned {
    ok(json!({"kind": "storage#objects"}))
}

/// The raw requests the server saw (all of them; the server thread may still be finishing).
fn seen(rx: &std::sync::mpsc::Receiver<String>, n: usize) -> Vec<String> {
    (0..n).map(|_| rx.recv_timeout(std::time::Duration::from_secs(5)).expect("request")).collect()
}

fn first_line(r: &str) -> &str {
    r.lines().next().unwrap_or("")
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
}

#[test]
fn encodes_object_names_and_builds_a_multipart_body() {
    assert_eq!(enc("p/reports/2026-11/report.json"), "p%2Freports%2F2026-11%2Freport.json");
    assert_eq!(enc("a b+c~_."), "a%20b%2Bc~_.");
    let data = b"\x00binary\r\n--not-a-boundary";
    let (ct, body) = multipart("p/run.lock", data);
    let boundary = ct.strip_prefix("multipart/related; boundary=").expect(&ct);
    let text = String::from_utf8_lossy(&body);
    let want_head = format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{{\"name\":\"p/run.lock\"}}\r\n\
                             --{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n");
    assert!(text.starts_with(&want_head), "{text}");
    assert!(body.ends_with(format!("\r\n--{boundary}--\r\n").as_bytes()));
    let start = want_head.len();
    assert_eq!(&body[start..start + data.len()], data);
    assert_eq!(body.len(), want_head.len() + data.len() + boundary.len() + 8);
}

#[test]
fn lists_every_page() {
    let (base, rx) = serve(vec![
        ok(json!({"items": [{"name": "p/a.json", "generation": "1"}], "nextPageToken": "t 1/2"})),
        ok(json!({"items": [{"name": "p/b.json", "generation": 22}]})),
    ]);
    let g = Gcs::test(&base, None);
    assert_eq!(g.list("b", "p/").unwrap(), vec![("p/a.json".to_string(), 1), ("p/b.json".to_string(), 22)]);
    let r = seen(&rx, 2);
    assert!(first_line(&r[0]).starts_with("GET /storage/v1/b/b/o?prefix=p%2F&fields=items%28name%2Cgeneration%29%2CnextPageToken HTTP"),
            "{}", r[0]);
    assert!(first_line(&r[1]).contains("&pageToken=t%201%2F2 "), "{}", r[1]);
}

#[test]
fn retries_transient_errors_but_not_others() {
    let (base, _rx) = serve(vec![canned(503, "busy"), empty_list(), canned(403, "denied")]);
    let g = Gcs::test(&base, None);
    assert_eq!(g.list("b", "").unwrap(), vec![]);
    let e = g.list("b", "").unwrap_err();
    assert_eq!((e.status, e.transient), (Some(403), false));
    assert!(e.message.contains("HTTP 403 denied"), "{e}");
}

#[test]
fn an_unsure_upload_that_landed_is_recognised() {
    // 503: did it land? The retry gets 412; the object holds our bytes, so it did.
    let (base, rx) = serve(vec![
        canned(503, ""), canned(412, "precondition"),
        ok(json!({"generation": "9", "size": "5"})), canned(200, "hello"),
    ]);
    let g = Gcs::test(&base, None);
    assert_eq!(g.upload("b", "p/x", b"hello", 0).unwrap(), 9);
    let r = seen(&rx, 4);
    assert!(first_line(&r[1]).starts_with("POST /upload/storage/v1/b/b/o?uploadType=multipart&ifGenerationMatch=0 "));
    assert!(first_line(&r[3]).starts_with("GET /storage/v1/b/b/o/p%2Fx?alt=media "));
    // A plain 412 is a conflict.
    let (base, _rx) = serve(vec![canned(412, "")]);
    assert!(Gcs::test(&base, None).upload("b", "p/x", b"hello", 3).unwrap_err().conflict());
}

#[test]
fn token_is_cached_until_shortly_before_expiry() {
    let (base, rx) = serve(vec![
        ok(json!({"access_token": "tok1", "expires_in": 3599, "token_type": "Bearer"})),
        empty_list(), empty_list(),
    ]);
    let g = Gcs::test(&base, Some(format!("{base}/computeMetadata/v1/instance/service-accounts/default/token")));
    g.list("b", "").unwrap();
    g.list("b", "").unwrap();
    let r = seen(&rx, 3);
    assert!(first_line(&r[0]).starts_with("GET /computeMetadata/v1/instance/service-accounts/default/token "));
    assert!(r[0].to_lowercase().contains("metadata-flavor: google"));
    for x in &r[1..] {
        assert!(x.to_lowercase().contains("authorization: bearer tok1"), "{x}");
    }
    // expires_in under the 60 s margin: fetched again every time.
    let (base, rx) = serve(vec![
        ok(json!({"access_token": "a", "expires_in": 30})), ok(json!({"access_token": "b", "expires_in": 30})),
    ]);
    let t = TokenSource::new(format!("{base}/token"));
    assert_eq!((t.get().unwrap(), t.get().unwrap()), ("a".to_string(), "b".to_string()));
    assert_eq!(seen(&rx, 2).len(), 2);
    let (base, _rx) = serve(vec![canned(404, "no metadata server")]);
    assert_eq!(TokenSource::new(format!("{base}/token")).get().unwrap_err().status, Some(404));
}

#[test]
fn settings_from_the_environment() {
    assert!(Mirror::from_var(&|_| None).is_none(), "no STATE_BUCKET: local state only");
    assert!(Mirror::from_var(&|k| (k == "STATE_BUCKET").then(|| " ".into())).is_none());
    let env = |k: &str| match k {
        "STATE_BUCKET" => Some("ew-state".into()),
        "STATE_PREFIX" => Some("/lab/".into()),
        "GCS_ENDPOINT" => Some("http://gcs:4443/".into()),
        _ => None,
    };
    let m = Mirror::from_var(&env).unwrap();
    assert_eq!((m.object("run.lock"), m.url("seen.json")), ("lab/run.lock".into(), "gs://ew-state/lab/seen.json".into()));
    assert_eq!((m.gcs.base.as_str(), m.gcs.token.is_none()), ("http://gcs:4443", true), "emulator: no auth");
    let m = Mirror::from_var(&|k| (k == "STATE_BUCKET").then(|| "b".into())).unwrap();
    assert_eq!(m.object("run.lock"), "run.lock");
    assert_eq!(m.gcs.base, DEFAULT_ENDPOINT);
    assert_eq!(m.gcs.token.as_ref().unwrap().url,
               "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token");
    let g = Gcs::from_var(&|k| (k == "GCE_METADATA_HOST").then(|| "127.0.0.1:8181".into()));
    assert_eq!(g.token.unwrap().url, "http://127.0.0.1:8181/computeMetadata/v1/instance/service-accounts/default/token");
    for (rel, want) in [("seen.json", true), ("http/ab.body", true), ("seen.json.tmp", false), ("run.lock", false),
                        ("../x", false), ("a//b", false), ("dir/", false)] {
        assert_eq!(mirrored(rel), want, "{rel}");
    }
}

#[test]
fn without_state_bucket_state_stays_local() {
    let t = state::testing::temp_state("gcs-off");
    assert!(active().is_none());
    state::save_json("a.json", &json!({"x": 1}));
    state::append_jsonl("runs.jsonl", &[json!({"r": 1})]);
    state::remove("a.json");
    assert!(!t.dir.join("a.json").exists());
    assert_eq!(std::fs::read_to_string(t.dir.join("runs.jsonl")).unwrap(), "{\"r\":1}\n");
}

#[test]
fn sync_downloads_changes_and_removes_what_is_gone() {
    let (base, rx) = serve(vec![
        // 1st sync: a.json and http/c.body are new; the lock and temp files are not mirrored
        ok(json!({"items": [{"name": "p/a.json", "generation": "1"}, {"name": "p/run.lock", "generation": "5"},
                            {"name": "p/x.tmp", "generation": "6"}, {"name": "p/http/c.body", "generation": "2"}]})),
        canned(200, "{\"a\": 1}"), canned(200, "body"),
        // 2nd sync: a.json gone, http/c.body changed
        ok(json!({"items": [{"name": "p/http/c.body", "generation": "3"}]})), canned(200, "body v3"),
        // 3rd sync: nothing changed, nothing downloaded
        ok(json!({"items": [{"name": "p/http/c.body", "generation": "3"}]})),
    ]);
    let t = temp_gcs_state("gcs-sync", &base);
    let m = active().unwrap();
    assert_eq!(m.sync(&t.dir).unwrap(), Synced { objects: 2, downloaded: 2, removed: 0 });
    assert_eq!(std::fs::read_to_string(t.dir.join("a.json")).unwrap(), "{\"a\": 1}");
    assert!(!t.dir.join("run.lock").exists() && !t.dir.join("x.tmp").exists());
    assert_eq!(m.sync(&t.dir).unwrap(), Synced { objects: 1, downloaded: 1, removed: 1 });
    assert!(!t.dir.join("a.json").exists());
    assert_eq!(std::fs::read_to_string(t.dir.join("http/c.body")).unwrap(), "body v3");
    assert_eq!(m.sync(&t.dir).unwrap(), Synced { objects: 1, downloaded: 0, removed: 0 });
    let r = seen(&rx, 6);
    assert!(first_line(&r[1]).starts_with("GET /storage/v1/b/b/o/p%2Fa.json?alt=media "), "{}", r[1]);
}

#[test]
fn writes_go_through_at_the_known_generation_and_412_stops_the_run() {
    let (base, rx) = serve(vec![
        generation(7), empty_list(),          // lock, re-sync
        generation(11), generation(12),       // seen.json new, then at 11
        canned(412, "conditionNotMet"),       // runs.jsonl: another writer created it
        canned(204, ""),                      // release
    ]);
    let t = temp_gcs_state("gcs-write", &base);
    let lock = state::lock_run(Utc::now()).unwrap().expect("lease");
    state::save_json("seen.json", &json!({"k": "2026-11-09T00:00:00Z"}));
    state::save_json("seen.json", &json!({"k": "2026-11-09T01:00:00Z"}));
    let p = catch_unwind(AssertUnwindSafe(|| state::append_run(&json!({"result": "written"})))).unwrap_err();
    let msg = panic_text(p);
    assert!(msg.contains("gs://b/p/runs.jsonl was changed by another writer") && msg.contains("lock was lost"), "{msg}");
    assert!(t.dir.join("runs.jsonl").exists(), "the local write happened first");
    // Sticky: a later write stops without a request, even if the first panic was caught.
    let p = catch_unwind(AssertUnwindSafe(|| state::save_json("wiki.json", &json!({})))).unwrap_err();
    assert!(panic_text(p).contains("the run lock was lost (gs://b/p/runs.jsonl was changed"));
    drop(lock);
    let r = seen(&rx, 6);
    assert!(first_line(&r[0]).starts_with("POST /upload/storage/v1/b/b/o?uploadType=multipart&ifGenerationMatch=0 "));
    assert!(r[0].contains("{\"name\":\"p/run.lock\"}") && r[0].contains("\"expires_at\""), "{}", r[0]);
    assert!(r[0].to_lowercase().contains("content-type: multipart/related; boundary=ew_"));
    assert!(first_line(&r[2]).ends_with("ifGenerationMatch=0 HTTP/1.1") && r[2].contains("{\"name\":\"p/seen.json\"}"));
    assert!(r[2].contains("\"k\": \"2026-11-09T00:00:00Z\""), "the whole file: {}", r[2]);
    assert!(first_line(&r[3]).ends_with("ifGenerationMatch=11 HTTP/1.1"), "{}", r[3]);
    assert!(r[4].contains("{\"name\":\"p/runs.jsonl\"}"));
    assert!(first_line(&r[5]).starts_with("DELETE /storage/v1/b/b/o/p%2Frun.lock?ifGenerationMatch=7 "), "{}", r[5]);
}

#[test]
fn appends_upload_the_whole_file_and_remove_deletes_the_object() {
    let (base, rx) = serve(vec![
        generation(1), ok(json!({"items": [{"name": "p/r.pdf", "generation": "4"}]})), canned(200, "%PDF"),
        generation(2), generation(3),          // runs.jsonl twice
        canned(204, ""),                       // delete r.pdf at 4
        canned(204, ""),                       // release
    ]);
    let t = temp_gcs_state("gcs-append", &base);
    let lock = state::lock_run(Utc::now()).unwrap().expect("lease");
    assert_eq!(std::fs::read(t.dir.join("r.pdf")).unwrap(), b"%PDF", "re-synced after the lock");
    state::append_run(&json!({"n": 1}));
    state::append_run(&json!({"n": 2}));
    state::remove("r.pdf");
    assert!(!t.dir.join("r.pdf").exists());
    drop(lock);
    let r = seen(&rx, 7);
    assert!(r[4].contains("{\"n\":1}\n{\"n\":2}\n") && first_line(&r[4]).contains("ifGenerationMatch=2 "), "{}", r[4]);
    assert!(first_line(&r[5]).starts_with("DELETE /storage/v1/b/b/o/p%2Fr.pdf?ifGenerationMatch=4 "), "{}", r[5]);
}

#[test]
fn writes_without_the_lease_stay_local() {
    let (base, _rx) = serve(vec![]);
    let t = temp_gcs_state("gcs-nolease", &base);
    state::save_json("runs.jsonl", &json!({"result": "locked"}));
    assert!(t.dir.join("runs.jsonl").exists(), "no request made: the server has no replies");
}

#[test]
fn a_held_lease_is_busy_with_its_holder() {
    let now = Utc::now();
    let holder = json!({"pid": 42, "host": "job-abc", "started": iso_utc(now), "expires_at": iso_utc(now + Days::minutes(30))});
    let (base, _rx) = serve(vec![
        canned(412, ""), ok(json!({"generation": "3"})), canned(200, &format!("{holder}\n")),
    ]);
    let _t = temp_gcs_state("gcs-busy", &base);
    let busy = state::lock_run(now).unwrap().err().expect("busy");
    assert_eq!(busy, holder.to_string());
}

#[test]
fn an_expired_lease_is_taken_over_and_released_at_our_generation() {
    let now = Utc::now();
    let old = json!({"pid": 1, "host": "dead", "started": "2026-11-09T00:00:00Z", "expires_at": iso_utc(now - Days::seconds(1))});
    let (base, rx) = serve(vec![
        canned(412, ""), ok(json!({"generation": "3"})), canned(200, &old.to_string()),
        canned(204, ""),                 // delete the stale lease at 3
        generation(4), empty_list(),     // create, re-sync
        canned(412, ""),                 // release: no longer ours, logged and ignored
    ]);
    let _t = temp_gcs_state("gcs-steal", &base);
    let lock = state::lock_run(now).unwrap().expect("taken over");
    drop(lock);
    let r = seen(&rx, 7);
    assert!(first_line(&r[3]).starts_with("DELETE /storage/v1/b/b/o/p%2Frun.lock?ifGenerationMatch=3 "), "{}", r[3]);
    assert!(first_line(&r[6]).starts_with("DELETE /storage/v1/b/b/o/p%2Frun.lock?ifGenerationMatch=4 "), "{}", r[6]);
}

#[test]
fn a_lease_without_expires_at_expires_by_its_creation_time() {
    let now = Utc::now();
    let created = iso_utc(now - Days::seconds(2701));
    let (base, _rx) = serve(vec![
        canned(412, ""), ok(json!({"generation": "3", "timeCreated": created})), canned(200, "garbage"),
        canned(204, ""), generation(4), empty_list(), canned(204, ""),
    ]);
    let _t = temp_gcs_state("gcs-nottl", &base);
    assert!(state::lock_run(now).unwrap().is_ok());
}

#[test]
fn an_unreachable_bucket_is_fatal_for_the_lock() {
    let (base, _rx) = serve(vec![canned(403, "forbidden")]);
    let _t = temp_gcs_state("gcs-403", &base);
    let e = state::lock_run(Utc::now()).err().expect("fatal");
    assert!(e.0.starts_with("cannot lock gs://b/p/run.lock: ") && e.0.contains("HTTP 403"), "{e}");
}

/// Against fake-gcs-server (no network otherwise):
/// EW_GCS_EMULATOR=http://gcs:4443 cargo test -- --ignored gcs::tests::emulator_roundtrip --nocapture
#[test]
#[ignore]
fn emulator_roundtrip() {
    let Ok(base) = std::env::var("EW_GCS_EMULATOR") else {
        eprintln!("EW_GCS_EMULATOR not set; skipped");
        return;
    };
    let bucket = format!("ew-test-{}", std::process::id());
    let r = direct_client().post(format!("{base}/storage/v1/b")).header(CONTENT_TYPE, "application/json")
        .body(json!({"name": bucket}).to_string()).send().unwrap();
    assert!(r.status().is_success(), "create bucket: {}", r.status());
    let g = Gcs::test(&base, None);
    let now = Utc::now();

    // lease, second lease busy, write-through, appends
    let t = state::testing::temp_state("gcs-emu");
    set_active(Some(Mirror::new(Gcs::test(&base, None), &bucket, "lab")));
    let lock = state::lock_run(now).unwrap().expect("lease");
    let busy = state::lock_run(now).unwrap().err().expect("busy");
    assert!(busy.contains(&format!("\"pid\":{}", std::process::id())) && busy.contains("expires_at"), "{busy}");
    state::save_json("seen.json", &json!({"a": 1}));
    state::save_json("seen.json", &json!({"a": 2}));
    state::append_run(&json!({"n": 1}));
    state::append_run(&json!({"n": 2}));
    state::save_bytes("reports/2026-11/report.pdf", b"%PDF");
    assert_eq!(g.download(&bucket, "lab/runs.jsonl").unwrap(), std::fs::read(t.dir.join("runs.jsonl")).unwrap());
    assert_eq!(g.download(&bucket, "lab/seen.json").unwrap(), std::fs::read(t.dir.join("seen.json")).unwrap());
    state::remove("reports/2026-11/report.pdf");
    assert!(g.metadata(&bucket, "lab/reports/2026-11/report.pdf").unwrap_err().not_found());

    // another writer changes seen.json: our next write stops with 412
    let cur = int_of(&g.metadata(&bucket, "lab/seen.json").unwrap()["generation"]).unwrap();
    g.upload(&bucket, "lab/seen.json", b"{\"other\": true}", cur).unwrap();
    let p = catch_unwind(AssertUnwindSafe(|| state::save_json("seen.json", &json!({"a": 3})))).unwrap_err();
    assert!(panic_text(p).contains("changed by another writer"));
    drop(lock);
    assert!(g.metadata(&bucket, "lab/run.lock").unwrap_err().not_found(), "released");
    drop(t);

    // a fresh process: the first sync brings everything, including the other writer's file
    let t = state::testing::temp_state("gcs-emu2");
    let m = Mirror::new(Gcs::test(&base, None), &bucket, "lab");
    assert_eq!(m.sync(&t.dir).unwrap(), Synced { objects: 2, downloaded: 2, removed: 0 });
    assert_eq!(std::fs::read_to_string(t.dir.join("seen.json")).unwrap(), "{\"other\": true}");

    // a stale lease is taken over
    let old = json!({"pid": 1, "host": "dead", "started": "2026-11-09T00:00:00Z", "expires_at": iso_utc(now - Days::seconds(1))});
    g.upload(&bucket, "lab/run.lock", old.to_string().as_bytes(), 0).unwrap();
    set_active(Some(m));
    let lock = state::lock_run(now).unwrap().expect("taken over");
    let held = String::from_utf8(g.download(&bucket, "lab/run.lock").unwrap()).unwrap();
    assert!(held.contains(&format!("\"pid\":{}", std::process::id())), "{held}");
    drop(lock);

    // evidence copy: an object already there is a conflict, never replaced
    g.upload(&bucket, "2026-11/frozen.json", b"one", 0).unwrap();
    assert!(g.upload(&bucket, "2026-11/frozen.json", b"two", 0).unwrap_err().conflict());
    assert_eq!(g.download(&bucket, "2026-11/frozen.json").unwrap(), b"one");
    drop(t);
}
