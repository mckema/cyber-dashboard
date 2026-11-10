//! Triage matcher: does a feed item concern a listed component?
//!
//! Pure functions, no I/O. Rules run in this order and the first match wins
//! (within a rule, the first component in list order):
//!
//!   1 package         GitHub Advisory: an extra.eco_packages "ecosystem:package" pair
//!                     equals a library component's ecosystem and one of its names
//!   2 cpe             an extra.cpes entry (CVE.org records) starts with one of a
//!                     component's cpe prefixes, ending there or at a ":"
//!   3 vendor-product  CISA KEV, ENISA EUVD, CVE.org: a normalised product (norm())
//!                     equals a component name and, when the component lists vendors,
//!                     a normalised vendor equals one of them. CVE.org pairs every
//!                     product with every vendor of the record.
//!   4 cve-join        any item with CVEs (CERT-EU, NCSC-NL, and the feeds above when
//!                     1-3 found nothing): rules 1-3 on the CVE.org record of each CVE
//!
//! Comparisons ignore case. No match -> NotRelevantByRule with triager
//! "matcher <RULE_VERSION>/<component list version>"; bump RULE_VERSION whenever a
//! rule changes what it matches, so earlier decisions stay traceable.
//!
//! A match means "candidate", not "affected": version ranges are not checked
//! against what is deployed. A person confirms or dismisses it in triage.

use std::collections::HashMap;

use super::components::{Component, Components, Kind};
use super::types::{Decision, Match};
use crate::feeds::common::Item;
use crate::feeds::{cvelist, euvd, github, kev};

pub const RULE_VERSION: &str = "1";

/// Feeds whose vendor/product fields rule 3 reads.
const VENDOR_PRODUCT_SOURCES: [&str; 3] = [kev::NAME, euvd::NAME, cvelist::NAME];

/// "matcher 1/sample-2026-11-04": who decided "not relevant".
pub fn triager(comps: &Components) -> String {
    format!("matcher {RULE_VERSION}/{}", comps.version)
}

/// CVE id -> CVE.org record, for the cve-join rule. Ids are upper-cased.
pub fn cve_index(items: &[Item]) -> HashMap<String, &Item> {
    items.iter().filter(|i| i.source == cvelist::NAME).map(|i| (i.id.to_uppercase(), i)).collect()
}

/// Decide one item. cve_index maps CVE id (upper case) -> the CVE.org item.
pub fn match_item(item: &Item, comps: &Components, cve_index: &HashMap<String, &Item>) -> Decision {
    match direct(item, comps).or_else(|| cve_join(item, comps, cve_index)) {
        Some(m) => Decision::Matched(m),
        None => Decision::NotRelevantByRule { triager: triager(comps) },
    }
}

/// Lowercase, punctuation dropped, whitespace collapsed: " Wiki.js  Server" -> "wikijs server".
pub fn norm(s: &str) -> String {
    let kept: String = s.to_lowercase().chars().filter(|c| c.is_alphanumeric() || c.is_whitespace()).collect();
    kept.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Rules 1-3 on the item itself.
fn direct(item: &Item, comps: &Components) -> Option<Match> {
    package(item, comps).or_else(|| cpe(item, comps)).or_else(|| vendor_product(item, comps))
}

fn found(c: &Component, rule: &str, evidence: String) -> Match {
    Match { component: c.id.clone(), rule: rule.into(), evidence }
}

fn eq_ci(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// extra[k] as a list: array items, or a string split on ", " (EUVD joins names that way).
fn list<'a>(item: &'a Item, k: &str) -> Vec<&'a str> {
    let xs: Vec<&str> = match item.x(k) {
        "" => item.x_list(k),
        s => s.split(", ").collect(),
    };
    xs.into_iter().map(str::trim).filter(|x| !x.is_empty()).collect()
}

fn package(item: &Item, comps: &Components) -> Option<Match> {
    if item.source != github::NAME {
        return None;
    }
    let pairs: Vec<(&str, &str)> = if item.extra.contains_key("eco_packages") {
        list(item, "eco_packages").into_iter().filter_map(|p| p.split_once(':')).collect()
    } else {
        // Items cached before eco_packages existed: every ecosystem x package (may over-match).
        let pkgs = list(item, "packages");
        list(item, "ecosystems").into_iter().flat_map(|e| pkgs.iter().map(move |p| (e, *p))).collect()
    };
    comps.components.iter().filter(|c| c.kind == Kind::Library && !c.ecosystem.is_empty()).find_map(|c| {
        pairs.iter()
            .find(|(e, p)| eq_ci(e, &c.ecosystem) && c.names.iter().any(|n| eq_ci(n, p)))
            .map(|(e, p)| found(c, "package", format!("{e}:{p}")))
    })
}

/// cpe starts with prefix (any case) and the prefix ends at a ":" or at the end.
pub fn cpe_has_prefix(cpe: &str, prefix: &str) -> bool {
    let (c, p) = (cpe.to_lowercase(), prefix.to_lowercase());
    !p.is_empty() && c.starts_with(&p) && (c.len() == p.len() || p.ends_with(':') || c[p.len()..].starts_with(':'))
}

fn cpe(item: &Item, comps: &Components) -> Option<Match> {
    let cpes = list(item, "cpes");
    if cpes.is_empty() {
        return None;
    }
    comps.components.iter().find_map(|c| {
        cpes.iter()
            .find(|x| c.cpe.iter().any(|p| cpe_has_prefix(x, p)))
            .map(|x| found(c, "cpe", x.to_string()))
    })
}

fn vendor_product(item: &Item, comps: &Components) -> Option<Match> {
    if !VENDOR_PRODUCT_SOURCES.contains(&item.source.as_str()) {
        return None;
    }
    // KEV/EUVD: vendor + product strings; CVE.org: vendors + products lists.
    let mut vendors = list(item, "vendor");
    vendors.extend(list(item, "vendors"));
    let mut products = list(item, "product");
    products.extend(list(item, "products"));
    if vendors.is_empty() {
        vendors.push("");
    }
    let vendors: Vec<(&str, String)> = vendors.into_iter().map(|v| (v, norm(v))).collect();
    let products: Vec<(&str, String)> = products.into_iter().map(|p| (p, norm(p))).filter(|(_, n)| !n.is_empty()).collect();
    comps.components.iter().find_map(|c| {
        let names: Vec<String> = c.names.iter().map(|n| norm(n)).collect();
        let want: Vec<String> = c.vendors.iter().map(|v| norm(v)).collect();
        products.iter().filter(|(_, pn)| names.contains(pn)).find_map(|(p, _)| {
            vendors.iter()
                .find(|(_, vn)| want.is_empty() || (!vn.is_empty() && want.contains(vn)))
                .map(|(v, _)| found(c, "vendor-product", if v.is_empty() { p.to_string() } else { format!("{v} / {p}") }))
        })
    })
}

fn cve_join(item: &Item, comps: &Components, cve_index: &HashMap<String, &Item>) -> Option<Match> {
    item.cves.iter().find_map(|cve| {
        let rec = cve_index.get(&cve.to_uppercase())?;
        if rec.key() == item.key() {
            return None; // the CVE.org record itself: rules 1-3 already ran
        }
        let m = direct(rec, comps)?;
        Some(Match { component: m.component, rule: "cve-join".into(), evidence: format!("{cve} {}: {}", m.rule, m.evidence) })
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::super::components;
    use super::*;
    use crate::feeds::kev::testutil::*;

    const LIST: &str = r#"
        version = "t1"
        [[component]]
        id = "tokio"
        kind = "library"
        ecosystem = "rust"
        names = ["Tokio"]
        vendors = ["tokio-rs"]
        cpe = ["cpe:2.3:a:tokio:tokio"]

        [[component]]
        id = "brotli-py"
        kind = "library"
        ecosystem = "pip"
        names = ["brotli"]

        [[component]]
        id = "brotli-js"
        kind = "library"
        ecosystem = "npm"
        names = ["brotli"]

        [[component]]
        id = "serde"
        kind = "library"
        ecosystem = "rust"
        names = ["serde"]

        [[component]]
        id = "nginx"
        kind = "image"
        names = ["nginx", "nginx open source"]
        vendors = ["f5", "nginx"]
        cpe = ["cpe:2.3:a:f5:nginx"]

        [[component]]
        id = "wikijs"
        kind = "infra"
        names = ["wiki.js"]
        cpe = ["cpe:2.3:a:requarks:wiki.js:"]
    "#;

    fn comps() -> Components {
        components::parse(LIST).unwrap()
    }

    fn item(source: &str, id: &str, extra: Value) -> Item {
        let mut i = Item::new(source, id, "u", "t", "2026-11-03");
        i.extra = extra.as_object().unwrap().clone();
        if id.starts_with("CVE-") {
            i.cves = vec![id.to_string()];
        }
        i
    }

    fn no_index() -> HashMap<String, &'static Item> {
        HashMap::new()
    }

    fn matched(d: Decision) -> (String, String, String) {
        match d {
            Decision::Matched(m) => (m.component, m.rule, m.evidence),
            other => panic!("not matched: {other:?}"),
        }
    }

    fn m(item: &Item) -> Decision {
        match_item(item, &comps(), &no_index())
    }

    fn not_relevant() -> Decision {
        Decision::NotRelevantByRule { triager: "matcher 1/t1".into() }
    }

    fn s3(a: &str, b: &str, c: &str) -> (String, String, String) {
        (a.into(), b.into(), c.into())
    }

    // ------------------------------------------------------------ rules

    #[test]
    fn package_rule() {
        let gh = item(github::NAME, "GHSA-1", json!({"eco_packages": ["rust:TOKIO"], "ecosystems": ["rust"], "packages": ["TOKIO"]}));
        assert_eq!(matched(m(&gh)), s3("tokio", "package", "rust:TOKIO"));
        // same package name in another ecosystem: no match
        let npm = item(github::NAME, "GHSA-2", json!({"eco_packages": ["npm:tokio"]}));
        assert_eq!(m(&npm), not_relevant());
        // only GitHub items carry packages
        let other = item(cvelist::NAME, "CVE-2026-1", json!({"eco_packages": ["rust:tokio"]}));
        assert_eq!(m(&other), not_relevant());
    }

    #[test]
    fn package_rule_keeps_the_pairing() {
        // Real advisory: pip:brotli and npm:brotli-wasm. The npm component named
        // "brotli" must not match through the separate ecosystems/packages lists.
        let gh = github::to_item(&fixture_json("github_advisories.json")[0]).unwrap();
        let only_js = components::parse(&LIST.replace("ecosystem = \"pip\"", "ecosystem = \"go\"")).unwrap();
        assert_eq!(match_item(&gh, &only_js, &no_index()), not_relevant());
        assert_eq!(matched(m(&gh)), s3("brotli-py", "package", "pip:brotli"));
        // An item cached before eco_packages existed falls back to every pairing.
        let mut old = gh.clone();
        old.extra.remove("eco_packages");
        assert_eq!(matched(match_item(&old, &only_js, &no_index())).0, "brotli-js");
    }

    #[test]
    fn cpe_rule() {
        let rec = |cpes: Value| item(cvelist::NAME, "CVE-2026-1", json!({"cpes": cpes}));
        let hit = rec(json!(["cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*", "CPE:2.3:A:F5:NGINX:1.25.3:*:*:*:*:*:*:*"]));
        assert_eq!(matched(m(&hit)), s3("nginx", "cpe", "CPE:2.3:A:F5:NGINX:1.25.3:*:*:*:*:*:*:*"));
        assert_eq!(matched(m(&rec(json!(["cpe:2.3:a:f5:nginx"])))).0, "nginx"); // whole string
        assert_eq!(m(&rec(json!(["cpe:2.3:a:f5:nginx_plus:*:*:*:*:*:*:*:*"]))), not_relevant()); // not at ":"
        assert_eq!(m(&rec(json!(["cpe:2.3:a:f5:nginx_plus"]))), not_relevant());
        assert_eq!(matched(m(&rec(json!(["cpe:2.3:a:requarks:wiki.js:2.5.300"])))).0, "wikijs"); // prefix ends in ":"
        assert_eq!(m(&rec(json!([]))), not_relevant());
    }

    #[test]
    fn cpe_prefix_boundaries() {
        assert!(cpe_has_prefix("cpe:2.3:a:f5:nginx:1.0", "cpe:2.3:a:f5:nginx"));
        assert!(cpe_has_prefix("cpe:2.3:a:f5:nginx", "CPE:2.3:A:F5:NGINX"));
        assert!(!cpe_has_prefix("cpe:2.3:a:f5:nginxx", "cpe:2.3:a:f5:nginx"));
        assert!(!cpe_has_prefix("cpe:2.3:a:f5", "cpe:2.3:a:f5:nginx"));
        assert!(!cpe_has_prefix("cpe:2.3:a:f5:nginx", ""));
    }

    #[test]
    fn vendor_product_rule() {
        let kv = |v: &str, p: &str| item(kev::NAME, "CVE-2026-1", json!({"vendor": v, "product": p}));
        assert_eq!(matched(m(&kv("Nginx", "NGINX"))), s3("nginx", "vendor-product", "Nginx / NGINX"));
        assert_eq!(matched(m(&kv("F5", "  nginx OPEN  source"))).0, "nginx"); // normalised
        assert_eq!(m(&kv("Acme", "nginx")), not_relevant()); // vendor not listed by the component
        assert_eq!(m(&kv("", "nginx")), not_relevant());
        assert_eq!(m(&kv("F5", "BIG-IP")), not_relevant());
        assert_eq!(m(&kv("F5", "nginx plus")), not_relevant()); // equality, not substring
        // no vendors on the component: any vendor (or none)
        assert_eq!(matched(m(&kv("", "Serde"))), s3("serde", "vendor-product", "Serde"));
        assert_eq!(matched(m(&kv("Requarks", "Wiki.JS"))).0, "wikijs");
        // EUVD joins the first three names with ", "
        let euvd = item(euvd::NAME, "CVE-2026-2", json!({"vendor": "Cisco, F5", "product": "ASA Software, NGINX Open Source"}));
        assert_eq!(matched(m(&euvd)), s3("nginx", "vendor-product", "F5 / NGINX Open Source"));
        // CVE.org: products x vendors
        let cve = item(cvelist::NAME, "CVE-2026-3", json!({"vendors": ["tokio-rs"], "products": ["tokio-util", "tokio"]}));
        assert_eq!(matched(m(&cve)), s3("tokio", "vendor-product", "tokio-rs / tokio"));
        // other feeds do not take part
        let ncsc = item("NCSC-NL", "NCSC-2026-1", json!({"products": ["nginx"], "vendor": "nginx"}));
        assert_eq!(m(&ncsc), not_relevant());
    }

    #[test]
    fn vendor_product_on_a_real_record() {
        // affected[].packageName "github.com/octo-sts/app" from the CNA record
        let rec = cvelist::parse_record(&fixture_json("cve_record_cna.json")).unwrap().unwrap();
        let list = components::parse(r#"version = "t"
            [[component]]
            id = "octo-sts"
            kind = "library"
            ecosystem = "go"
            names = ["github.com/octo-sts/app"]
            vendors = ["Octo-STS"]"#).unwrap();
        assert_eq!(matched(match_item(&rec, &list, &no_index())),
                   s3("octo-sts", "vendor-product", "octo-sts / github.com/octo-sts/app"));
        assert_eq!(match_item(&rec, &comps(), &no_index()), not_relevant());
    }

    #[test]
    fn rule_order() {
        // cpe points at wikijs, the product at nginx (listed earlier): cpe wins.
        let both = item(cvelist::NAME, "CVE-2026-1", json!({"cpes": ["cpe:2.3:a:requarks:wiki.js:2"],
                                                           "vendors": ["F5"], "products": ["nginx"]}));
        assert_eq!(matched(m(&both)).1, "cpe");
        assert_eq!(matched(m(&both)).0, "wikijs");
        // package beats a cve-join hit on another component
        let rec = item(cvelist::NAME, "CVE-2026-9", json!({"cpes": ["cpe:2.3:a:f5:nginx:1"]}));
        let idx = cve_index(std::slice::from_ref(&rec));
        let mut gh = item(github::NAME, "CVE-2026-9", json!({"eco_packages": ["rust:serde"]}));
        gh.cves = vec!["CVE-2026-9".into()];
        assert_eq!(matched(match_item(&gh, &comps(), &idx)), s3("serde", "package", "rust:serde"));
        gh.extra.insert("eco_packages".into(), json!(["rust:other"]));
        assert_eq!(matched(match_item(&gh, &comps(), &idx)).1, "cve-join");
    }

    #[test]
    fn cve_join_rule() {
        let recs = vec![
            item(cvelist::NAME, "CVE-2026-1", json!({"vendors": ["Acme"], "products": ["Widget"]})),
            item(cvelist::NAME, "CVE-2026-2", json!({"vendors": ["F5"], "products": ["NGINX Open Source"]})),
            item(kev::NAME, "CVE-2026-3", json!({"vendor": "F5", "product": "nginx"})), // not a CVE.org record
        ];
        let idx = cve_index(&recs);
        assert_eq!(idx.len(), 2);
        let mut adv = item("CERT-EU", "2026-018", json!({"products": ["nginx"]}));
        adv.cves = vec!["CVE-2026-1".into(), "cve-2026-2".into()];
        assert_eq!(matched(match_item(&adv, &comps(), &idx)),
                   s3("nginx", "cve-join", "cve-2026-2 vendor-product: F5 / NGINX Open Source"));
        adv.cves = vec!["CVE-2026-1".into(), "CVE-2026-3".into(), "CVE-2026-404".into()];
        assert_eq!(match_item(&adv, &comps(), &idx), not_relevant());
        // the CVE.org record does not join with itself
        assert_eq!(match_item(&recs[0], &comps(), &idx), not_relevant());
    }

    // ------------------------------------------------------------ decision

    #[test]
    fn triager_and_json_shape() {
        assert_eq!(triager(&comps()), "matcher 1/t1");
        let nr = m(&item("CERT-EU", "2026-1", json!({})));
        assert_eq!(serde_json::to_value(&nr).unwrap(), json!({"decision": "not-relevant-by-rule", "triager": "matcher 1/t1"}));
        let hit = m(&item(github::NAME, "GHSA-1", json!({"eco_packages": ["rust:tokio"]})));
        assert_eq!(serde_json::to_value(&hit).unwrap(),
                   json!({"decision": "matched", "component": "tokio", "rule": "package", "evidence": "rust:tokio"}));
        let back: Decision = serde_json::from_value(serde_json::to_value(&hit).unwrap()).unwrap();
        assert_eq!(back, hit);
    }

    #[test]
    fn norm_examples() {
        assert_eq!(norm(" Wiki.js  Server "), "wikijs server");
        assert_eq!(norm("NGINX Open-Source"), "nginx opensource");
        assert_eq!(norm("..."), "");
    }

    #[test]
    fn sample_list_on_real_fixtures() {
        let p = repo_root().join(components::DEFAULT_PATH);
        let sample = components::load_file(&p).unwrap();
        let mut items = kev::parse(&fixture_json("kev_catalog.json"), "github mirror", start(), end()).unwrap();
        items.extend(fixture_json("github_advisories.json").as_array().unwrap().iter().map(|a| github::to_item(a).unwrap()));
        items.extend(fixture_json("euvd_search.json")["items"].as_array().unwrap().iter().map(|v| euvd::to_item(v).unwrap()));
        items.push(cvelist::parse_record(&fixture_json("cve_record_cna.json")).unwrap().unwrap());
        let idx = cve_index(&items);
        // Cisco, GitLab, Ivanti, brotli, octo-sts: none is on the sample list.
        for i in &items {
            assert_eq!(match_item(i, &sample, &idx), Decision::NotRelevantByRule { triager: "matcher 1/sample-2026-11-04".into() },
                       "{}", i.key());
        }
        // The same advisory for a crate on the list is a candidate.
        let mut a = fixture_json("github_advisories.json")[0].clone();
        a["vulnerabilities"][1]["package"] = json!({"ecosystem": "rust", "name": "hyper"});
        assert_eq!(matched(match_item(&github::to_item(&a).unwrap(), &sample, &idx)), s3("hyper", "package", "rust:hyper"));
    }
}
