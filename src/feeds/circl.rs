//! CIRCL OSINT. Port of feeds/circl.py (stub until the port lands).

use chrono::{DateTime, Utc};

use super::common::{FetchOutput, SourceError};

pub const NAME: &str = "CIRCL OSINT";
pub const TABLE: &str = "osint";
pub const CADENCE: u64 = 0;

pub fn fetch(_start: DateTime<Utc>, _end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    Err(SourceError::new(format!("{NAME}: not implemented yet")))
}
