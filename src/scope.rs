//! Scope rule compilation and matching.
//!
//! A `ScopeMatcher` is built once from a list of rules and indexed by kind
//! for O(1) amortized matching per asset. Rules that can't be classified are
//! silently dropped (matching Python behavior).

use std::collections::{HashMap, HashSet};

use crate::classify::classify_str;
use crate::dedupe::is_covered_by_wildcard;
use crate::model::{Asset, AssetKind};

#[derive(Debug, Clone)]
struct Rule {
    raw: String,
    kind: RuleKind,
    canonical: String,
    registrable: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleKind {
    Apex,
    Subdomain,
    Wildcard,
    Ip,
    Url,
}

#[derive(Debug, Default)]
pub struct ScopeMatcher {
    exact_apex: HashMap<String, Vec<String>>,     // canonical → rules
    exact_subdomain: HashMap<String, Vec<String>>,
    exact_url: HashMap<String, Vec<String>>,
    exact_ip: HashMap<String, Vec<String>>,
    wildcards_by_reg: HashMap<String, Vec<(String, String)>>, // reg → (canonical, raw)
}

impl ScopeMatcher {
    pub fn compile<I, S>(rules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut m = Self::default();
        for raw in rules {
            let raw = raw.as_ref().trim();
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }
            let asset = classify_str(raw);
            if asset.kind == AssetKind::Garbage {
                continue;
            }
            let kind = if raw.contains("://") {
                RuleKind::Url
            } else {
                match asset.kind {
                    AssetKind::Apex => RuleKind::Apex,
                    AssetKind::Subdomain => RuleKind::Subdomain,
                    AssetKind::Wildcard => RuleKind::Wildcard,
                    AssetKind::Ip => RuleKind::Ip,
                    AssetKind::Garbage => continue,
                }
            };
            let canonical = host_without_port(&asset);
            let rule = Rule {
                raw: raw.to_string(),
                kind,
                canonical: canonical.clone(),
                registrable: asset.registrable.clone(),
            };
            match rule.kind {
                RuleKind::Apex => m
                    .exact_apex
                    .entry(canonical)
                    .or_default()
                    .push(rule.raw.clone()),
                RuleKind::Subdomain => m
                    .exact_subdomain
                    .entry(canonical)
                    .or_default()
                    .push(rule.raw.clone()),
                RuleKind::Url => m
                    .exact_url
                    .entry(canonical)
                    .or_default()
                    .push(rule.raw.clone()),
                RuleKind::Ip => m
                    .exact_ip
                    .entry(canonical)
                    .or_default()
                    .push(rule.raw.clone()),
                RuleKind::Wildcard => {
                    if let Some(reg) = rule.registrable.clone() {
                        m.wildcards_by_reg
                            .entry(reg)
                            .or_default()
                            .push((rule.canonical.clone(), rule.raw.clone()));
                    }
                }
            }
        }
        m
    }

    /// Return all scope rules that match this asset. Empty vec = out-of-scope.
    pub fn matches(&self, asset: &Asset, strict: bool) -> Vec<&str> {
        let mut hits: HashSet<&str> = HashSet::new();

        if asset.kind == AssetKind::Garbage {
            return Vec::new();
        }

        let host = host_without_port(asset);

        match asset.kind {
            AssetKind::Ip => {
                if let Some(rules) = self.exact_ip.get(&host) {
                    for r in rules {
                        hits.insert(r.as_str());
                    }
                }
            }
            AssetKind::Apex => {
                for bucket in [&self.exact_apex, &self.exact_url] {
                    if let Some(rules) = bucket.get(&host) {
                        for r in rules {
                            hits.insert(r.as_str());
                        }
                    }
                }
                if !strict {
                    // loose: apex can match *.registrable via wildcard? No — strict/loose
                    // loose affects subdomain→apex, not apex itself.
                }
            }
            AssetKind::Subdomain => {
                for bucket in [&self.exact_subdomain, &self.exact_url] {
                    if let Some(rules) = bucket.get(&host) {
                        for r in rules {
                            hits.insert(r.as_str());
                        }
                    }
                }
                if let Some(reg) = &asset.registrable {
                    if let Some(cands) = self.wildcards_by_reg.get(reg) {
                        for (wildcard, raw) in cands {
                            if is_covered_by_wildcard(&host, wildcard) {
                                hits.insert(raw.as_str());
                            }
                        }
                    }
                }
                if !strict {
                    // Walk parents: if apex/url/subdomain rule equals a parent domain,
                    // the sub is considered in-scope.
                    let mut parent = host.as_str();
                    while let Some((_, rest)) = parent.split_once('.') {
                        parent = rest;
                        for bucket in [
                            &self.exact_apex,
                            &self.exact_url,
                            &self.exact_subdomain,
                        ] {
                            if let Some(rules) = bucket.get(parent) {
                                for r in rules {
                                    hits.insert(r.as_str());
                                }
                            }
                        }
                    }
                }
            }
            AssetKind::Wildcard => {
                if let Some(reg) = &asset.registrable {
                    if let Some(cands) = self.wildcards_by_reg.get(reg) {
                        for (wildcard, raw) in cands {
                            if wildcard == &host {
                                hits.insert(raw.as_str());
                            }
                        }
                    }
                }
            }
            AssetKind::Garbage => {}
        }

        hits.into_iter().collect()
    }

    pub fn is_in_scope(&self, asset: &Asset, strict: bool) -> bool {
        !self.matches(asset, strict).is_empty()
    }
}

fn host_without_port(asset: &Asset) -> String {
    match asset.port {
        None => asset.canonical.clone(),
        Some(_) => {
            if asset.canonical.starts_with('[') {
                asset
                    .canonical
                    .rsplit_once("]:")
                    .map(|(h, _)| h.trim_start_matches('[').to_string())
                    .unwrap_or_else(|| asset.canonical.clone())
            } else {
                asset
                    .canonical
                    .rsplit_once(':')
                    .map(|(h, _)| h.to_string())
                    .unwrap_or_else(|| asset.canonical.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify_str;

    #[test]
    fn strict_subdomain_rule_is_exact() {
        let m = ScopeMatcher::compile(["api.example.com"]);
        assert!(m.is_in_scope(&classify_str("api.example.com"), true));
        assert!(!m.is_in_scope(&classify_str("foo.api.example.com"), true));
        assert!(m.is_in_scope(&classify_str("foo.api.example.com"), false));
    }

    #[test]
    fn wildcard_rule_covers_subs_strictly() {
        let m = ScopeMatcher::compile(["*.example.com"]);
        assert!(m.is_in_scope(&classify_str("foo.example.com"), true));
        assert!(!m.is_in_scope(&classify_str("example.com"), true));
    }
}
