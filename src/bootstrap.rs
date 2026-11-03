//! Wiki.js setup for the job. Port of bootstrap_wiki.py (stub until the port lands).

use std::path::PathBuf;

use crate::feeds::common::Fatal;

#[derive(clap::Args)]
pub struct Args {
    /// Page content used on create / --reseed
    #[arg(long, default_value = "page/skeleton.html")]
    pub skeleton: PathBuf,
    /// scriptCss used on create / --update-css
    #[arg(long, default_value = "page/style.css")]
    pub css: PathBuf,
    /// Overwrite page content from --skeleton (as admin)
    #[arg(long)]
    pub reseed: bool,
    /// Re-push scriptCss from --css (as admin)
    #[arg(long)]
    pub update_css: bool,
    /// Only delete page versions older than an ISO 8601 duration, e.g. P7D (as admin; all pages)
    #[arg(long, value_name = "DURATION")]
    pub purge_history: Option<String>,
    /// .env file read and updated by bootstrap
    #[arg(long, default_value = ".env")]
    pub env_file: PathBuf,
}

pub fn main(_args: Args) -> Result<i32, Fatal> {
    todo!("bootstrap::main")
}
