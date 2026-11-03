//! Wiki.js 2.5 GraphQL client shared by `run` (bot API key, optional IAP token)
//! and `bootstrap` (admin JWT). Stub until the port of the GraphQL parts of
//! rebuild.py / bootstrap_wiki.py lands.

use serde_json::Value;

use crate::feeds::common::Fatal;

/// GraphQL call as the job: WIKI_BASE + WIKIJS_API_KEY (+ IAP_ID_TOKEN as
/// Proxy-Authorization when set). Returns `data`, or Fatal with the same
/// messages as rebuild.py's gql().
pub fn gql_bot(_query: &str, _variables: Value) -> Result<Value, Fatal> {
    todo!("wiki::gql_bot")
}
