//! HTML builders for the Cyber Threat Exploit Watch page. Port of render.py
//! (stub until the port lands; the public API below is the contract run.rs uses).
//!
//! Pure functions: slices of Item in, HTML strings out. No network and no file
//! I/O, except demo().
//!
//! Anchors filled on the page (see page/skeleton.html):
//!   tbody  t-health t-kev t-adv t-dep t-nvd t-osint
//!   text   s-kev s-crit s-high s-dep s-adv s-osint
//!          n-health n-kev n-adv n-dep n-nvd n-cvecap n-osint winlabel
//!   stamp  rstat   (inner HTML, contains <b>; must never contain a <div>)

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::feeds::common::{Fatal, Item};

/// One row of the feed health table, built by run.rs.
/// status: "ok" | "cached" | "stale" | "error"
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HealthRow {
    pub source: String,
    pub status: String,
    pub items: usize,
    pub newest: String,
    pub last_success: String,
    pub note: String,
}

/// Everything the job writes, in a fixed order (tbody ids, then text ids, then rstat).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Regions {
    pub tbody: Vec<(String, String)>,
    pub text: Vec<(String, String)>,
    pub stamp: String,
}

#[derive(clap::Args)]
pub struct DemoArgs {
    /// Output HTML file
    pub out: PathBuf,
    /// Render the dark theme
    #[arg(long)]
    pub dark: bool,
    /// Fixture with items per table and health rows
    #[arg(long, default_value = "tests/fixtures/render_items.json")]
    pub fixture: PathBuf,
}

/// UTC timestamp for display, e.g. "3 Nov 02:31 UTC" (date-only input renders the date only).
pub fn ftime(_s: &str, _year: bool) -> String {
    todo!("render::ftime")
}

#[allow(clippy::too_many_arguments)]
pub fn build_regions(
    _kev: &[Item], _adv: &[Item], _dep: &[Item], _cve: &[Item], _osint: &[Item], _health: &[HealthRow],
    _start: DateTime<Utc>, _end: DateTime<Utc>, _now: DateTime<Utc>, _kev_catalog: &str, _cap: usize,
) -> Regions {
    todo!("render::build_regions")
}

/// Splice regions into the page HTML. Err names the first missing anchor. Idempotent.
pub fn apply_regions(_doc: &str, _regions: &Regions) -> Result<String, Fatal> {
    todo!("render::apply_regions")
}

pub fn demo(_args: DemoArgs) -> Result<(), Fatal> {
    todo!("render::demo")
}
