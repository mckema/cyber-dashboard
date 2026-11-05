//! `exploit-watch demo`: the page filled from a fixture, as one standalone HTML file.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use super::{HealthRow, Regions, SKELETON_PATH, STYLE_PATH, TriageView, apply_regions, build_regions, thousands};
use crate::feeds::common::{Fatal, Item, parse_iso};

#[derive(clap::Args)]
pub struct DemoArgs {
    /// Output HTML file
    pub out: PathBuf,
    /// Render the dark theme
    #[arg(long)]
    pub dark: bool,
    /// Fixture with items per table and health rows
    #[arg(long, default_value = "stack/job/tests/fixtures/render_items.json")]
    pub fixture: PathBuf,
}

const PREVIEW_BASE: &str = r#"
body{margin:0;background:#f2f3f5;font-family:Roboto,"Segoe UI",Helvetica,Arial,sans-serif}
.theme--dark{background:#1a1a1a}
.preview-note{font:12px/1.4 monospace;color:#777;padding:8px 24px}
.contents{max-width:1180px;margin:0 auto;padding:24px 32px 64px;background:#fff}
.theme--dark .contents{background:#212121;color:#ddd}
"#;

/// The demo fixture: items per table, health rows, the tracker row, the triage view and the window.
pub(super) struct Fixture {
    kev: Vec<Item>,
    adv: Vec<Item>,
    dep: Vec<Item>,
    cve: Vec<Item>,
    health: Vec<HealthRow>,
    tracker: Option<HealthRow>,
    triage: TriageView,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    now: DateTime<Utc>,
    kev_catalog: String,
    cap: usize,
}

impl Fixture {
    pub(super) fn regions(&self) -> Regions {
        build_regions(
            &self.kev, &self.adv, &self.dep, &self.cve, &self.health, self.tracker.as_ref(), &self.triage,
            self.start, self.end, self.now, &self.kev_catalog, self.cap,
        )
    }
}

/// UTF-8 text file with CRLF and lone CR line ends turned into LF.
pub(super) fn read_text(path: &Path) -> Result<String, Fatal> {
    let s = std::fs::read_to_string(path).map_err(|e| Fatal(format!("{}: {e}", path.display())))?;
    Ok(if s.contains('\r') { s.replace("\r\n", "\n").replace('\r', "\n") } else { s })
}

pub(super) fn load_fixture(path: &Path) -> Result<Fixture, Fatal> {
    let bad = |m: String| Fatal(format!("{}: {m}", path.display()));
    let d: Map<String, Value> = serde_json::from_str(&read_text(path)?).map_err(|e| bad(e.to_string()))?;
    let items = |k: &str| -> Result<Vec<Item>, Fatal> {
        match d.get(k) {
            None => Ok(Vec::new()),
            Some(v) => serde_json::from_value(v.clone()).map_err(|e| bad(format!("{k}: {e}"))),
        }
    };
    let when = |k: &str| -> Result<DateTime<Utc>, Fatal> {
        d.get(k)
            .and_then(Value::as_str)
            .and_then(parse_iso)
            .ok_or_else(|| bad(format!("{k}: missing or not an ISO 8601 time")))
    };
    let health = match d.get("health") {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| bad(format!("health: {e}")))?,
        None => return Err(bad("health: missing".into())),
    };
    // Missing: no "Linear" row in the health table.
    let tracker = match d.get("tracker") {
        Some(v) => Some(serde_json::from_value(v.clone()).map_err(|e| bad(format!("tracker: {e}")))?),
        None => None,
    };
    // Missing: empty triage tables.
    let triage = match d.get("triage") {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| bad(format!("triage: {e}")))?,
        None => TriageView::default(),
    };
    Ok(Fixture {
        kev: items("kev")?,
        adv: items("adv")?,
        dep: items("dep")?,
        cve: items("cve")?,
        health,
        tracker,
        triage,
        start: when("start")?,
        end: when("end")?,
        now: when("now")?,
        kev_catalog: d.get("kev_catalog").and_then(Value::as_str).unwrap_or("").to_string(),
        // Missing: 300 rows, as the job's default. Anything but a positive integer: no cap.
        cap: d.get("cap").map_or(300, |v| v.as_u64().unwrap_or(0) as usize),
    })
}

/// The standalone preview page. root holds SKELETON_PATH and STYLE_PATH.
fn render_demo(fixture: &Path, dark: bool, root: &Path) -> Result<String, Fatal> {
    let d = load_fixture(fixture)?;
    let skel = read_text(&root.join(SKELETON_PATH))?;
    let css = read_text(&root.join(STYLE_PATH))?;
    let body = apply_regions(&skel, &d.regions())?;
    let theme = if dark { "theme--dark" } else { "theme--light" };
    Ok(format!(
        concat!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8">"#,
            r#"<meta name="viewport" content="width=device-width, initial-scale=1">"#,
            "<title>Exploit Watch preview</title><style>{}\n{}</style></head>",
            r#"<body><div class="v-application {}">"#,
            r#"<div class="preview-note">Preview only: fixture data from stack/job/tests/fixtures/render_items.json. "#,
            "On the wiki, stack/wiki/page/skeleton.html is the page content and stack/wiki/page/style.css is scriptCss.</div>",
            r#"<div class="contents">{}</div></div></body></html>"#,
        ),
        PREVIEW_BASE, css, theme, body
    ))
}

/// `exploit-watch demo OUT.html [--dark] [--fixture F]`. Reads stack/wiki/page/ from the
/// current directory (run it from the repo root, like the other subcommands).
pub fn demo(args: DemoArgs) -> Result<(), Fatal> {
    let out = render_demo(&args.fixture, args.dark, Path::new("."))?;
    let path = &args.out;
    if let Some(dir) = std::path::absolute(path).ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        std::fs::create_dir_all(&dir).map_err(|e| Fatal(format!("{}: {e}", dir.display())))?;
    }
    std::fs::write(path, &out).map_err(|e| Fatal(format!("{}: {e}", path.display())))?;
    // Size in characters, the same count `run --out` prints.
    println!("wrote {} ({} bytes)", path.display(), thousands(out.chars().count()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{fixture_path, repo_root};
    use super::*;

    #[test]
    fn demo_renders() {
        let out = render_demo(&fixture_path(), false, &repo_root()).unwrap();
        assert!(out.starts_with("<!doctype html>"));
        assert!(out.contains("<style>"));
        assert!(out.contains("CVE-2026-111464"));
    }
}
