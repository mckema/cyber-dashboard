//! The fairCT component list the matcher checks items against (FR-A2).
//!
//! A TOML file, path from COMPONENTS_FILE (default stack/job/components.sample.toml,
//! relative to the working directory, which is the repo in compose):
//!
//!   version = "sample-2026-11-04"     recorded in the triager string of every
//!                                     "not relevant" decision
//!   [[component]]
//!   id = "nginx"                      unique
//!   kind = "image"                    library | image | infra
//!   ecosystem = ""                    libraries: GitHub advisory ecosystem ("rust", "npm", ...)
//!   names = ["nginx"]                 package or product names, case-insensitive
//!   vendors = ["f5", "nginx"]         optional; when set, vendor-product matches need one of them
//!   cpe = ["cpe:2.3:a:f5:nginx"]      optional CPE 2.3 prefixes
//!
//! The real list is still to be agreed (2026-11-04); the sample only exercises the rules.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::feeds::common::Fatal;

pub const ENV: &str = "COMPONENTS_FILE";
pub const DEFAULT_PATH: &str = "stack/job/components.sample.toml";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Library,
    Image,
    Infra,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub id: String,
    pub kind: Kind,
    #[serde(default)]
    pub ecosystem: String,
    pub names: Vec<String>,
    #[serde(default)]
    pub vendors: Vec<String>,
    #[serde(default)]
    pub cpe: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Components {
    pub version: String,
    #[serde(rename = "component", default)]
    pub components: Vec<Component>,
    /// sha256 hex of the file's text, set by parse(). `version` is typed by hand;
    /// the hash shows which list a decision was really made with (triage events,
    /// runs.jsonl).
    #[serde(skip)]
    pub sha256: String,
}

/// The list is missing, unparseable or fails validation.
#[derive(Debug, thiserror::Error)]
#[error("component list {path}: {message}")]
pub struct ComponentsError {
    pub path: String,
    pub message: String,
}

impl From<ComponentsError> for Fatal {
    fn from(e: ComponentsError) -> Self {
        Fatal(e.to_string())
    }
}

/// COMPONENTS_FILE when set and non-empty, else DEFAULT_PATH.
pub fn path() -> PathBuf {
    std::env::var(ENV).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| DEFAULT_PATH.into()).into()
}

/// Load and validate the list at path().
pub fn load() -> Result<Components, ComponentsError> {
    load_file(&path())
}

pub fn load_file(p: &Path) -> Result<Components, ComponentsError> {
    let label = p.display().to_string();
    let text = std::fs::read_to_string(p).map_err(|e| ComponentsError { path: label.clone(), message: e.to_string() })?;
    parse(&text).map_err(|message| ComponentsError { path: label, message })
}

/// Parse and validate TOML text. Err is the reason; a TOML syntax or type error
/// keeps toml's own multi-line report (line, column, caret).
pub fn parse(text: &str) -> Result<Components, String> {
    let mut c: Components = toml::from_str(text).map_err(|e| e.to_string().trim_end().to_string())?;
    validate(&c)?;
    c.sha256 = hex::encode(Sha256::digest(text.as_bytes()));
    Ok(c)
}

fn validate(c: &Components) -> Result<(), String> {
    if c.version.trim().is_empty() {
        return Err("version is empty".into());
    }
    if c.components.is_empty() {
        return Err("no [[component]] entries".into());
    }
    let mut seen: Vec<&str> = Vec::new();
    for (n, comp) in c.components.iter().enumerate() {
        let at = format!("component #{} ({:?})", n + 1, comp.id);
        if comp.id.trim().is_empty() {
            return Err(format!("{at}: id is empty"));
        }
        if seen.contains(&comp.id.as_str()) {
            return Err(format!("{at}: duplicate id"));
        }
        seen.push(&comp.id);
        if comp.names.is_empty() || comp.names.iter().any(|x| x.trim().is_empty()) {
            return Err(format!("{at}: names must be a non-empty list of non-empty strings"));
        }
        if comp.vendors.iter().any(|x| x.trim().is_empty()) {
            return Err(format!("{at}: empty string in vendors"));
        }
        if let Some(bad) = comp.cpe.iter().find(|x| !x.to_lowercase().starts_with("cpe:2.3:")) {
            return Err(format!("{at}: cpe {bad:?} is not a CPE 2.3 prefix (cpe:2.3:part:vendor:product)"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = r#"
        version = "t1"
        [[component]]
        id = "nginx"
        kind = "image"
        names = ["nginx"]
        vendors = ["f5", "nginx"]
        cpe = ["cpe:2.3:a:f5:nginx"]
    "#;

    fn err(text: &str) -> String {
        parse(text).unwrap_err()
    }

    #[test]
    fn parses_with_defaults() {
        let c = parse(ONE).unwrap();
        assert_eq!(c.version, "t1");
        assert_eq!(c.sha256.len(), 64, "sha256 hex of the text");
        assert_ne!(c.sha256, parse(&ONE.replace("\"t1\"", "\"t2\"")).unwrap().sha256);
        let n = &c.components[0];
        assert_eq!((n.id.as_str(), n.kind, n.ecosystem.as_str()), ("nginx", Kind::Image, ""));
        assert_eq!(n.cpe, ["cpe:2.3:a:f5:nginx"]);
        let lib = parse("version = \"t\"\n[[component]]\nid = \"tokio\"\nkind = \"library\"\necosystem = \"rust\"\nnames = [\"tokio\"]\n").unwrap();
        assert_eq!((lib.components[0].vendors.len(), lib.components[0].cpe.len()), (0, 0));
    }

    #[test]
    fn validation_errors() {
        let dup = format!("{ONE}\n[[component]]\nid = \"nginx\"\nkind = \"infra\"\nnames = [\"x\"]\n");
        assert_eq!(err(&dup), "component #2 (\"nginx\"): duplicate id");
        assert!(err(&ONE.replace("\"image\"", "\"container\"")).contains("unknown variant `container`"));
        assert_eq!(err(&ONE.replace("[\"nginx\"]\n", "[]\n")), "component #1 (\"nginx\"): names must be a non-empty list of non-empty strings");
        assert!(err(&ONE.replace("names = [\"nginx\"]", "")).contains("missing field `names`"));
        assert!(err(&ONE.replace("id = \"nginx\"", "id = \" \"")).contains("id is empty"));
        assert!(err(&ONE.replace("cpe:2.3:a:f5:nginx", "cpe:/a:f5:nginx")).contains("not a CPE 2.3 prefix"));
        assert_eq!(err(&ONE.replace("\"t1\"", "\"\"")), "version is empty");
        assert_eq!(err("version = \"t\""), "no [[component]] entries");
        assert!(err(&ONE.replace("vendors", "vendor")).contains("unknown field `vendor`")); // typo caught
        assert!(err("version = ").contains("TOML parse error"));
    }

    #[test]
    fn load_file_names_the_path() {
        let e = load_file(Path::new("/nonexistent/components.toml")).unwrap_err();
        assert!(e.to_string().starts_with("component list /nonexistent/components.toml: "), "{e}");
    }

    #[test]
    fn sample_file_parses() {
        let p = crate::feeds::kev::testutil::repo_root().join(DEFAULT_PATH);
        let c = load_file(&p).unwrap();
        assert!(c.version.starts_with("sample-"), "{}", c.version);
        assert!(c.components.len() >= 12, "{}", c.components.len());
        for k in [Kind::Library, Kind::Image, Kind::Infra] {
            assert!(c.components.iter().any(|x| x.kind == k), "{k:?}");
        }
        // every library has an ecosystem, so the package rule can reach it
        assert!(c.components.iter().filter(|x| x.kind == Kind::Library).all(|x| !x.ecosystem.is_empty()));
    }
}
