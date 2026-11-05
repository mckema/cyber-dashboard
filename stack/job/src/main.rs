//! exploit-watch: rebuild the Cyber Threat Exploit Watch page on Wiki.js.
//!
//!   exploit-watch run [--dry-run] [--out FILE] [--every SECONDS]
//!   exploit-watch bootstrap [--reseed] [--update-css] [--purge-history P7D]
//!   exploit-watch demo OUT.html [--dark]
//!   exploit-watch triage --report
//!   exploit-watch report (--month YYYY-MM | --month-to-date) [--no-pdf]
//!   exploit-watch serve [--port 8090] [--healthcheck]
//!
//! See README.md (Architecture) for how the pieces fit together.

mod feeds;
mod render;
mod report;
mod run;
mod serve;
mod triage;
mod wiki;

use clap::{Parser, Subcommand};

use feeds::common::Fatal;

#[derive(Parser)]
#[command(name = "exploit-watch", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch the feeds, rebuild the page regions and write the page if the data changed.
    Run(run::Args),
    /// Set up Wiki.js (admin, API, least-privilege key, page) and keep .env in sync.
    Bootstrap(wiki::bootstrap::Args),
    /// Render the page from a fixture into a standalone HTML file for review.
    Demo(render::DemoArgs),
    /// Match the cached feed items against the component list and print the counts (no network).
    Triage(triage::report::Args),
    /// FR-A4 resolution report for a month or month to date: JSON and PDF under state/reports/.
    Report(report::Args),
    /// Local lab: refresh tickets and serve the month-to-date report PDF on click.
    Serve(serve::Args),
}

fn main() {
    let cli = Cli::parse();
    let res: Result<i32, Fatal> = match cli.cmd {
        Command::Run(a) => run::main(a),
        Command::Bootstrap(a) => wiki::bootstrap::main(a),
        Command::Demo(a) => render::demo(a).map(|_| 0),
        Command::Triage(a) => triage::report::main(a),
        Command::Report(a) => report::main(a),
        Command::Serve(a) => serve::main(a),
    };
    match res {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        }
    }
}
