//! NVD. Port of feeds/nvd.py (stub until the port lands).

use chrono::{DateTime, Utc};

use super::common::{FetchOutput, SourceError};

pub const NAME: &str = "NVD";
pub const TABLE: &str = "nvd";
pub const CADENCE: u64 = 7200;

pub fn fetch(_start: DateTime<Utc>, _end: DateTime<Utc>) -> Result<FetchOutput, SourceError> {
    Err(SourceError::new(format!("{NAME}: not implemented yet")))
}
