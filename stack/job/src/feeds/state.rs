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
//!
//! With STATE_BUCKET set, STATE_DIR is a mirror of a GCS bucket (gcs.rs): it is
//! synced from the bucket when state is first used and each time the run lock is
//! taken, every write here is uploaded right after the local write, and the run
//! lock is a lease object instead of flock. Without STATE_BUCKET nothing changes.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
#[cfg(test)]
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::common::iso_utc;
use super::gcs;

static DIR: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Tests that touch state hold this lock and point the directory at a temp dir.
#[cfg(test)]
pub static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Override STATE_DIR for this process (tests, or a copy of state for comparisons).
pub fn set_dir(p: impl Into<PathBuf>) {
    *DIR.write().unwrap() = Some(p.into());
}

/// STATE_DIR. With STATE_BUCKET set, the first call syncs the mirror (gcs::active).
pub fn dir() -> PathBuf {
    let _ = gcs::active();
    local_dir()
}

/// STATE_DIR without touching the bucket (gcs.rs uses this while it syncs).
pub(crate) fn local_dir() -> PathBuf {
    if let Some(p) = DIR.read().unwrap().clone() {
        return p;
    }
    PathBuf::from(std::env::var("STATE_DIR").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "state".into()))
}

/// Explicit start of state mode (main.rs): with STATE_BUCKET set, sync the local
/// mirror now, so a bucket problem is a clear FATAL instead of a panic later.
pub fn init() -> Result<(), super::common::Fatal> {
    gcs::init().map(|_| ()).map_err(super::common::Fatal)
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
    if let Some(m) = gcs::active() {
        m.push(name, data);
    }
}

/// Delete STATE_DIR/name (and its object in state mode); a missing file is fine.
pub fn remove(name: &str) {
    let _ = fs::remove_file(dir().join(name));
    if let Some(m) = gcs::active() {
        m.remove(name);
    }
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
    // One write call per line: a `locked` line may be appended while another run holds the lock.
    append_jsonl("runs.jsonl", std::slice::from_ref(record));
}

/// Append one JSON line per value to STATE_DIR/name, in a single write call.
pub fn append_jsonl(name: &str, values: &[serde_json::Value]) {
    if values.is_empty() {
        return;
    }
    let p = path(name);
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&p)
        .unwrap_or_else(|e| panic!("cannot open {}: {e}", p.display()));
    let text: String = values.iter().map(|v| serde_json::to_string(v).expect("json") + "\n").collect();
    f.write_all(text.as_bytes()).unwrap_or_else(|e| panic!("append {}: {e}", p.display()));
    if let Some(m) = gcs::active() {
        // GCS objects cannot be appended to: upload the whole file.
        drop(f);
        let all = fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
        m.push(name, &all);
    }
}

/// STATE_DIR/name exists.
pub fn exists(name: &str) -> bool {
    dir().join(name).exists()
}

// ---------------------------------------------------------------- run lock

pub(crate) const LOCK_FILE: &str = "run.lock";
/// State mode: a lease older than this is taken over (LOCK_TTL_SECONDS).
const DEFAULT_LOCK_TTL_SECS: i64 = 2700;

/// Where the run lock lives, for messages: the lease object in state mode
/// (gs://bucket/prefix/run.lock), otherwise STATE_DIR/run.lock.
pub fn lock_location() -> String {
    match super::gcs::active() {
        Some(m) => m.url(LOCK_FILE),
        None => dir().join(LOCK_FILE).display().to_string(),
    }
}

/// Exclusive hold on STATE_DIR for one run. An advisory flock(2) on `run.lock`:
/// the kernel releases it when the file is closed, so dropping the guard (also
/// while unwinding from a panic) or the process dying in any way frees it, and
/// there is no stale lock to time out. The file itself is never deleted (a
/// delete would let two runs lock two different files of the same name).
/// Verified on 2026-11-04 across two containers bind-mounting the same Windows
/// folder through Docker Desktop (9p drvfs).
///
/// State mode (STATE_BUCKET): a lease instead, the object run.lock created with
/// ifGenerationMatch=0 and carrying expires_at (now + LOCK_TTL_SECONDS, default
/// 2700); dropping the guard deletes it at its generation. A process that dies
/// leaves it behind until expires_at, after which the next run takes it over.
pub struct RunLock {
    kind: LockKind,
}

enum LockKind {
    File(fs::File),
    Lease(Arc<gcs::Mirror>),
}

impl Drop for RunLock {
    fn drop(&mut self) {
        match &self.kind {
            // Leave no holder details behind; closing the file releases the lock.
            LockKind::File(f) => {
                let _ = f.set_len(0);
            }
            LockKind::Lease(m) => m.release(),
        }
    }
}

/// pid, host and start time of this run: the holder details a waiting run prints.
fn holder_info(now: DateTime<Utc>) -> serde_json::Value {
    let host = std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
        .or_else(|| std::env::var("CLOUD_RUN_EXECUTION").ok().filter(|s| !s.is_empty()))
        .or_else(|| fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|s| s.trim().to_string()))
        .unwrap_or_default();
    serde_json::json!({"pid": std::process::id(), "host": host, "started": iso_utc(now)})
}

/// Ok(Ok(lock)) when this process now holds the lock; Ok(Err(holder)) when
/// another run does, with what that run wrote into the file (pid, host, start).
/// Err when the lock file cannot be opened or the filesystem refuses locks
/// (state mode: when the bucket cannot be reached or the re-sync fails).
pub fn lock_run(now: DateTime<Utc>) -> Result<Result<RunLock, String>, super::common::Fatal> {
    if let Some(m) = gcs::active() {
        return lock_lease(m, now);
    }
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
    let info = holder_info(now);
    // Best effort: the details only feed the message a waiting run prints.
    let _ = file.set_len(0).and_then(|_| file.write_all(format!("{info}\n").as_bytes()));
    Ok(Ok(RunLock { kind: LockKind::File(file) }))
}

/// lock_run in state mode: take the lease, then re-sync the mirror under it.
fn lock_lease(m: Arc<gcs::Mirror>, now: DateTime<Utc>) -> Result<Result<RunLock, String>, super::common::Fatal> {
    let fatal = |what: &str, e: gcs::GcsError| super::common::Fatal(format!("cannot {what} {}: {e}", m.url(LOCK_FILE)));
    let ttl = std::env::var("LOCK_TTL_SECONDS").ok().and_then(|v| v.trim().parse().ok()).filter(|t| *t > 0)
        .unwrap_or(DEFAULT_LOCK_TTL_SECS);
    let mut info = holder_info(now);
    info["expires_at"] = serde_json::json!(iso_utc(now + Duration::seconds(ttl)));
    if let Err(holder) = m.acquire(&info, now, ttl).map_err(|e| fatal("lock", e))? {
        return Ok(Err(holder));
    }
    let lock = RunLock { kind: LockKind::Lease(m.clone()) };
    // Dropping `lock` on error releases the lease again.
    m.sync(&local_dir()).map_err(|e| fatal("sync state after taking", e))?;
    Ok(Ok(lock))
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
            gcs::set_active(None);
        }
    }

    /// Local state only (no STATE_BUCKET), whatever the environment says.
    pub fn temp_state(tag: &str) -> TempState {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("ew-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        set_dir(&dir);
        gcs::set_active(None);
        TempState { dir, _guard: guard }
    }

    /// State mode against a fake GCS at `base` (no auth): bucket "b", prefix "p".
    pub fn temp_gcs_state(tag: &str, base: &str) -> TempState {
        let t = temp_state(tag);
        gcs::set_active(Some(gcs::Mirror::new(gcs::Gcs::test(base, None), "b", "p")));
        t
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
