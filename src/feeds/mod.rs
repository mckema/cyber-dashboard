//! Feed modules for the Exploit Watch page. See common.rs for the contract.
//!
//! all() lists the modules in the order run.rs fetches them. CORE are the feeds
//! whose failure aborts the run (nothing is written).

pub mod common;
pub mod state;

pub mod certeu;
pub mod circl;
pub mod cvelist;
pub mod euvd;
pub mod github;
pub mod kev;
pub mod ncscnl;
pub mod nvd;

use chrono::{DateTime, Utc};

use common::{FetchOutput, SourceError};

pub type FetchFn = fn(DateTime<Utc>, DateTime<Utc>) -> Result<FetchOutput, SourceError>;

#[derive(Clone, Copy)]
pub struct Feed {
    pub key: &'static str, // module name; also the state file name (items/<key>.json)
    pub name: &'static str,
    pub cadence: u64,
    pub fetch: FetchFn,
}

macro_rules! feed {
    ($m:ident) => {
        Feed { key: stringify!($m), name: $m::NAME, cadence: $m::CADENCE, fetch: $m::fetch }
    };
}

pub fn all() -> Vec<Feed> {
    vec![feed!(kev), feed!(euvd), feed!(cvelist), feed!(nvd), feed!(github), feed!(certeu), feed!(ncscnl), feed!(circl)]
}

pub const CORE: &[&str] = &["kev", "cvelist"];
