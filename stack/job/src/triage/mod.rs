//! Triage of new feed items against the fairCT component list (FR-A2) and the
//! tickets that follow from it (FR-A3; for now also FR-A9). The matcher decides
//! whether an item touches a listed component, the store records that decision
//! per new item key, and the tracker files (or updates) the Linear issue. Items
//! that match nothing are "not relevant" by rule.
//!
//!   types       Match / Decision, shared by the matcher and the Linear side
//!   components  the component list (TOML) and its validation
//!   matcher     the rules (pure functions)
//!   store       state/triage.json: one record (with an item snapshot) per new item key,
//!               the page tables, and the Amsterdam business-day clock (overdue = red)
//!   tracker     where tickets live: nothing (off, default) or the Linear GraphQL API (live;
//!               LINEAR_API_URL points it at the linear-mock service in the compose lab)
//!   linear_oauth  the live tracker's OAuth app token (client_credentials) when LINEAR_API_KEY is unset
//!   sync        one tracker round per run: create, comment, read states back, save
//!   step        the triage part of one run, called by run.rs; builds the page tables
//!   report      `exploit-watch triage --report`: match counts over state/items/, offline

pub mod components;
pub mod linear_oauth;
pub mod matcher;
pub mod report;
pub mod step;
pub mod store;
pub mod sync;
pub mod tracker;
pub mod types;
