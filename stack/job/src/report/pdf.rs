//! report.json -> report.pdf with the typst CLI (TYPST_BIN, default `typst`; the
//! job image has it at /usr/local/bin/typst). The template report.typ is compiled
//! into the binary; it and data.json (the report plus data_sha) go into a fresh
//! temp folder that is also typst's --root, so nothing else is readable. Only the
//! fonts typst embeds are used (--ignore-system-fonts), the output is PDF/A-2b and
//! the PDF creation date is "tickets as of" (--creation-timestamp).

use std::path::PathBuf;
use std::process::Command;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::feeds::common::Fatal;

pub const TEMPLATE: &str = include_str!("report.typ");

/// Deleted on drop.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn typst_bin() -> String {
    std::env::var("TYPST_BIN").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "typst".into())
}

pub fn render(report: &Value, data_sha: &str, as_of: DateTime<Utc>) -> Result<Vec<u8>, Fatal> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = TempDir(std::env::temp_dir().join(format!("ew-report-{}-{nanos}", std::process::id())));
    let io = |what: &str, e: std::io::Error| Fatal(format!("report pdf: {what} in {}: {e}", tmp.0.display()));
    std::fs::create_dir_all(&tmp.0).map_err(|e| io("create folder", e))?;
    let mut data = report.clone();
    data["data_sha"] = json!(data_sha);
    std::fs::write(tmp.0.join("main.typ"), TEMPLATE).map_err(|e| io("write main.typ", e))?;
    std::fs::write(tmp.0.join("data.json"), serde_json::to_vec(&data).expect("json")).map_err(|e| io("write data.json", e))?;

    let bin = typst_bin();
    let out = Command::new(&bin)
        .current_dir(&tmp.0)
        .arg("compile")
        .arg("--root").arg(&tmp.0)
        .arg("--ignore-system-fonts")
        .args(["--pdf-standard", "a-2b"])
        .arg("--creation-timestamp").arg(as_of.timestamp().max(0).to_string())
        .args(["main.typ", "out.pdf"])
        .output()
        .map_err(|e| Fatal(format!("report pdf: cannot run {bin:?} ({e}); install typst, set TYPST_BIN, or use --no-pdf")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(Fatal(format!("report pdf: typst failed ({}): {}", out.status, err.trim().chars().take(1500).collect::<String>())));
    }
    std::fs::read(tmp.0.join("out.pdf")).map_err(|e| io("read out.pdf", e))
}
