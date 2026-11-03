//! Triage of new feed items against the fairCT component list (FR-A2) and the
//! tickets that follow from it (FR-A3; for now also FR-A9). The matcher decides
//! whether an item touches a listed component, the store records that decision
//! per new item key, and the tracker files (or updates) the Linear issue. Items
//! that match nothing are "not relevant" by rule.
//!
//!   types       Match / Decision, shared by the matcher and the Linear side
//!   components  the component list (TOML) and its validation
//!   matcher     the rules (pure functions)
//!   store       state/triage.json: one record per new item key, plus the page tables
//!   tracker     where tickets live: Linear (live), a JSON file (fake), or nothing (off)

pub mod components;
pub mod matcher;
pub mod store;
pub mod tracker;
pub mod types;
