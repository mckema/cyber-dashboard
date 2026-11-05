//! Small on-disk state under STATE_DIR (default ./state). The file formats are
//! kept stable, so a new build picks up the state an older one left behind.
//!
//!   http/                 conditional-GET cache (ETag + body), owned by common::get()
//!   items/<module>.json   items from the last successful fetch, per feed module
//!   cursors/<module>.json free-form per-module cursor (e.g. cvelistV5 deltaLog fetchTime)
//!   seen.json             item key -> first_seen (UTC ISO); basis of the publication lag metric
//!   wiki.json             data fingerprint and time of the last page write
//!   runs.jsonl            one line per run: counts, errors, publication lag
//!   run.lock              held by the run in progress (see RunLock); never deleted
//!
//! Writes are atomic (temp file + rename) so a killed run never leaves half a file.
//! Only one run may write at a time: two runs share the same `.tmp` names, so a
//! second run renames the first one's temp file away under it.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::RwLock;
#[cfg(test)]
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::common::iso_utc;

static DIR: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Tests that touch state hold this lock and point the directory at a temp dir.
#[cfg(test)]
pub static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Override STATE_DIR for this process (tests, or a copy of state for comparisons).
pub fn set_dir(p: impl Into<PathBuf>) {
    *DIR.write().unwrap() = Some(p.into());
}

pub fn dir() -> PathBuf {
    if let Some(p) = DIR.read().unwrap().clone() {
        return p;
    }
    PathBuf::from(std::env::var("STATE_DIR").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "state".into()))
}

fn path(name: &str) -> PathBuf {
    let p = dir().join(name);
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    p
}

fn atomic_write(name: &str, data: &[u8]) {
    let p = path(name);
    let tmp = PathBuf::from(format!("{}.tmp", p.display()));
    fs::write(&tmp, data).unwrap_or_else(|e| panic!("cannot write {}: {e}", tmp.display()));
    fs::rename(&tmp, &p).unwrap_or_else(|e| panic!("cannot rename {} -> {}: {e}", tmp.display(), p.display()));
}

/// None when the file is missing or not valid JSON for T.
pub fn load_json<T: DeserializeOwned>(name: &str) -> Option<T> {
    let raw = fs::read(dir().join(name)).ok()?;
    serde_json::from_slice(&raw).ok()
}

pub fn save_json<T: Serialize + ?Sized>(name: &str, obj: &T) {
    // indent=1: one space per level keeps the files small and still diffable
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
    obj.serialize(&mut ser).expect("serialisable state");
    atomic_write(name, &buf);
}

pub fn load_bytes(name: &str) -> Option<Vec<u8>> {
    fs::read(dir().join(name)).ok()
}

pub fn save_bytes(name: &str, data: &[u8]) {
    atomic_write(name, data);
}

/// Record first_seen for keys not seen before. Returns {key: first_seen} for the new ones.
pub fn mark_seen<I, S>(keys: I, now: DateTime<Utc>, keep_days: i64) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen: BTreeMap<String, String> = load_json("seen.json").unwrap_or_default();
    let stamp = iso_utc(now);
    let mut new = BTreeMap::new();
    for k in keys {
        let k = k.as_ref();
        if !seen.contains_key(k) {
            new.insert(k.to_string(), stamp.clone());
        }
    }
    seen.extend(new.clone());
    let cutoff = iso_utc(now - Duration::days(keep_days));
    seen.retain(|_, v| *v >= cutoff);
    save_json("seen.json", &seen);
    new
}

pub fn seen() -> BTreeMap<String, String> {
    load_json("seen.json").unwrap_or_default()
}

pub fn append_run(record: &serde_json::Value) {
    let p = path("runs.jsonl");
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&p)
        .unwrap_or_else(|e| panic!("cannot open {}: {e}", p.display()));
    // One write call per line: a `locked` line may be appended while another run holds the lock.
    let line = serde_json::to_string(record).expect("json") + "\n";
    f.write_all(line.as_bytes()).expect("append runs.jsonl");
}

// ---------------------------------------------------------------- run lock

const LOCK_FILE: &str = "run.lock";

/// Exclusive hold on STATE_DIR for one run. An advisory flock(2) on `run.lock`:
/// the kernel releases it when the file is closed, so dropping the guard (also
/// while unwinding from a panic) or the process dying in any way frees it, and
/// there is no stale lock to time out. The file itself is never deleted (a
/// delete would let two runs lock two different files of the same name).
/// Verified on 2026-11-04 across two containers bind-mounting the same Windows
/// folder through Docker Desktop (9p drvfs).
pub struct RunLock {
    file: fs::File,
}

impl Drop for RunLock {
    fn drop(&mut self) {
        // Leave no holder details behind; closing the file releases the lock.
        let _ = self.file.set_len(0);
    }
}

/// Ok(Ok(lock)) when this process now holds the lock; Ok(Err(holder)) when
/// another run does, with what that run wrote into the file (pid, host, start).
/// Err when the lock file cannot be opened or the filesystem refuses locks.
pub fn lock_run(now: DateTime<Utc>) -> Result<Result<RunLock, String>, super::common::Fatal> {
    let p = path(LOCK_FILE);
    let fatal = |e: std::io::Error| super::common::Fatal(format!("cannot lock {}: {e}", p.display()));
    // No truncate: a run that finds the lock busy must not wipe the holder's details.
    let mut file = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&p)
        .map_err(fatal)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            let holder = fs::read_to_string(&p).unwrap_or_default().trim().to_string();
            return Ok(Err(if holder.is_empty() { "holder unknown".into() } else { holder }));
        }
        Err(fs::TryLockError::Error(e)) => return Err(fatal(e)),
    }
    let host = std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
        .or_else(|| fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|s| s.trim().to_string()))
        .unwrap_or_default();
    let info = serde_json::json!({"pid": std::process::id(), "host": host, "started": iso_utc(now)});
    // Best effort: the details only feed the message a waiting run prints.
    let _ = file.set_len(0).and_then(|_| file.write_all(format!("{info}\n").as_bytes()));
    Ok(Ok(RunLock { file }))
}

pub fn utcnow() -> DateTime<Utc> {
    Utc::now()
}

#[cfg(test)]
pub mod testing {
    //! A temp STATE_DIR for one test; hold the guard for the whole test.
    use super::*;

    pub struct TempState {
        pub dir: PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for TempState {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
            *DIR.write().unwrap() = None;
        }
    }

    pub fn temp_state(tag: &str) -> TempState {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("ew-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        set_dir(&dir);
        TempState { dir, _guard: guard }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_seen_records_only_new_keys() {
        let _t = testing::temp_state("seen");
        let now = Utc::now();
        let a = mark_seen(["a", "b"], now, 30);
        assert_eq!(a.len(), 2);
        let b = mark_seen(["a", "c"], now, 30);
        assert_eq!(b.keys().collect::<Vec<_>>(), vec!["c"]);
        assert_eq!(seen().len(), 3);
    }

    #[test]
    fn json_roundtrip_and_missing() {
        let _t = testing::temp_state("json");
        assert!(load_json::<serde_json::Value>("nope.json").is_none());
        save_json("cursors/x.json", &serde_json::json!({"fetch_time": "2026-11-03T04:22:45.004Z"}));
        let v: serde_json::Value = load_json("cursors/x.json").unwrap();
        assert_eq!(v["fetch_time"], "2026-11-03T04:22:45.004Z");
    }

    #[test]
    fn run_lock_is_exclusive_and_released_on_drop() {
        let t = testing::temp_state("lock");
        let now = Utc::now();
        // flock(2) locks belong to the open file, so a second open in this process conflicts like another process would.
        let held = lock_run(now).unwrap().ok().expect("first lock");
        let holder = lock_run(now).unwrap().err().expect("second lock must be refused");
        assert!(holder.contains(&format!("\"pid\":{}", std::process::id())), "{holder}");
        drop(held);
        assert_eq!(fs::read_to_string(t.dir.join(LOCK_FILE)).unwrap(), "");
        let again = lock_run(now).unwrap();
        assert!(again.is_ok(), "lock must be free after drop");
    }

    #[test]
    fn run_lock_released_when_a_panic_unwinds() {
        let _t = testing::temp_state("lock-panic");
        let now = Utc::now();
        let r = std::panic::catch_unwind(|| {
            let _l = lock_run(now).unwrap().ok().unwrap();
            panic!("boom");
        });
        assert!(r.is_err());
        assert!(lock_run(now).unwrap().is_ok());
    }
}
