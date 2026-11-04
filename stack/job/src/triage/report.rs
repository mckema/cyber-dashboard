//! `exploit-watch triage --report`: run the matcher over the items of the last
//! successful fetch of each feed (state/items/) and print how many match, by
//! rule and by component. No network, no writes: a quick way to see what a
//! component list would do to the current window.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::components;
use super::matcher;
use super::types::Decision;
use crate::feeds::common::{Fatal, Item};
use crate::feeds::state;

/// The feeds whose items are triaged, in the order run.rs passes them.
const FEEDS: [&str; 6] = ["kev", "euvd", "cvelist", "github", "certeu", "ncscnl"];

#[derive(clap::Args)]
pub struct Args {
    /// Print the counts (the only mode for now)
    #[arg(long)]
    pub report: bool,
}

#[derive(Deserialize)]
struct Cached {
    #[serde(default)]
    items: Vec<Item>,
}

pub fn main(_args: Args) -> Result<i32, Fatal> {
    let comps = components::load()?;
    let by_feed: Vec<(&str, Vec<Item>)> = FEEDS.iter()
        .map(|k| (*k, state::load_json::<Cached>(&format!("items/{k}.json")).map(|c| c.items).unwrap_or_default()))
        .collect();
    let cves: Vec<Item> = by_feed.iter().find(|(k, _)| *k == "cvelist").map(|(_, v)| v.clone()).unwrap_or_default();
    let index = matcher::cve_index(&cves);

    println!("components {} ({} entries, {})", comps.version, comps.components.len(), components::path().display());
    println!("{:<22} {:>7} {:>8}", "feed", "items", "matched");
    let (mut rules, mut comps_hit) = (BTreeMap::<String, usize>::new(), BTreeMap::<String, usize>::new());
    let (mut total, mut total_matched) = (0, 0);
    for (key, items) in &by_feed {
        let mut n = 0;
        for it in items {
            if let Decision::Matched(m) = matcher::match_item(it, &comps, &index) {
                n += 1;
                *rules.entry(m.rule).or_default() += 1;
                *comps_hit.entry(m.component).or_default() += 1;
            }
        }
        let name = items.first().map_or(*key, |i| i.source.as_str());
        println!("{:<22} {:>7} {:>8}", name, items.len(), n);
        total += items.len();
        total_matched += n;
    }
    println!("{:<22} {:>7} {:>8}", "total", total, total_matched);
    println!("not relevant by rule: {} (triager \"{}\")", total - total_matched, matcher::triager(&comps));
    for (title, map) in [("by rule", &rules), ("by component", &comps_hit)] {
        if !map.is_empty() {
            println!("{title}:");
            for (k, v) in map {
                println!("  {k:<20} {v:>6}");
            }
        }
    }
    Ok(0)
}
