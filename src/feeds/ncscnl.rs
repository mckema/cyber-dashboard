//! NCSC-NL. Port of feeds/ncscnl.py (stub until the port lands).

use chrono::{DateTime, Utc};

use super::common::{FetchOutput, SourceError};

pub const NAME: &str = "NCSC-NL";
pub const TABLE: &str = "adv";
pub const CADENCE: u64 = 0;

pub fn fetch(_start: DateTime<Utc>, _end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    Err(SourceError::new(format!("{NAME}: not implemented yet")))
}
