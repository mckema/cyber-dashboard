//! Types shared by the triage modules (FR-A2/A3).

use serde::{Deserialize, Serialize};

/// Why an item is relevant: the component it matched and how.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Match {
    pub component: String, // component id from the component list
    pub rule: String,      // "package" | "cpe" | "vendor-product" | "cve-join"
    pub evidence: String,  // the value that matched, e.g. "rust:tokio" or "cpe:2.3:a:f5:nginx"
}

/// Outcome of matching one item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "kebab-case")]
pub enum Decision {
    Matched(Match),
    NotRelevantByRule { triager: String }, // "matcher <RULE_VERSION>/<components version>"
}
