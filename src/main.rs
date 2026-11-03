//! exploit-watch: rebuild the Cyber Threat Exploit Watch page on Wiki.js.
//!
//!   exploit-watch run [--dry-run] [--out FILE] [--every SECONDS]
//!   exploit-watch bootstrap [--reseed] [--update-css] [--purge-history P7D]
//!   exploit-watch demo OUT.html [--dark]
//!
//! See RUNBOOK.md for how the pieces fit together.

mod bootstrap;
mod feeds;
mod render;
mod run;
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
    Bootstrap(bootstrap::Args),
    /// Render the page from a fixture into a standalone HTML file for review.
    Demo(render::DemoArgs),
}

fn main() {
    let cli = Cli::parse();
    let res: Result<i32, Fatal> = match cli.cmd {
        Command::Run(a) => run::main(a),
        Command::Bootstrap(a) => bootstrap::main(a),
        Command::Demo(a) => render::demo(a).map(|_| 0),
    };
    match res {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        }
    }
}
