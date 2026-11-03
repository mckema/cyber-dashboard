//! One rebuild of the page. Port of rebuild.py (stub until the port lands).

use std::path::PathBuf;

use crate::feeds::common::Fatal;

#[derive(clap::Args)]
pub struct Args {
    /// Build and diff, write nothing
    #[arg(long)]
    pub dry_run: bool,
    /// Render into page/skeleton.html and save to FILE; no wiki
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Loop forever, one run every SECONDS
    #[arg(long, value_name = "SECONDS")]
    pub every: Option<u64>,
}

pub fn main(_args: Args) -> Result<i32, Fatal> {
    todo!("run::main")
}
