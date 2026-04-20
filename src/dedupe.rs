//! Semantic deduplication and wildcard-coverage annotation.

use std::collections::HashMap;

use crate::model::{Asset, AssetKind};

/// Merge assets by canonical_key and annotate wildcard coverage in O(n).
pub fn dedupe(records: Vec<Asset>) -> Vec<Asset> {
    let mut merged: HashMap<String, Asset> = HashMap::with_capacity(records.len());
    let mut order: Vec<String> = Vec::new();

    for record in records {
        let key = record.canonical_key();
        if let Some(existing) = merged.get_mut(&key) {
            merge_into(existing, record);
        } else {
            order.push(key.clone());
            merged.insert(key, record);
        }
    }

    // Bucket wildcards by registrable domain for O(1) lookup per host.
    let mut wildcard_by_reg: HashMap<String, Vec<String>> = HashMap::new();
    let mut wildcard_keys: HashMap<String, String> = HashMap::new();
    for (key, asset) in merged.iter() {
        if asset.kind == AssetKind::Wildcard {
            if let Some(reg) = &asset.registrable {
                wildcard_by_reg
                    .entry(reg.clone())
                    .or_default()
                    .push(wildcard_host(asset));
                wildcard_keys.insert(wildcard_host(asset), key.clone());
            }
        }
    }

    for asset in merged.values_mut() {
        if !matches!(asset.kind, AssetKind::Apex | AssetKind::Subdomain) {
            continue;
        }
        let Some(reg) = &asset.registrable else {
            continue;
        };
        let Some(candidates) = wildcard_by_reg.get(reg) else {
            continue;
        };
        let host = host_without_port(asset);
        for wildcard in candidates {
            if is_covered_by_wildcard(&host, wildcard) {
                if let Some(wkey) = wildcard_keys.get(wildcard) {
                    if !asset.covered_by.contains(wkey) {
                        asset.covered_by.push(wkey.clone());
                    }
                }
            }
        }
        asset.covered_by.sort();
    }

    order.into_iter().filter_map(|k| merged.remove(&k)).collect()
}

fn merge_into(target: &mut Asset, incoming: Asset) {
    // Union covered_by.
    for c in incoming.covered_by {
        if !target.covered_by.contains(&c) {
            target.covered_by.push(c);
        }
    }
    target.covered_by.sort();

    // Promote scheme/port/registrable if target is missing them.
    if target.scheme.is_none() {
        target.scheme = incoming.scheme;
    }
    if target.registrable.is_none() {
        target.registrable = incoming.registrable;
    }
    if target.cname.is_none() {
        target.cname = incoming.cname;
    }
    for ip in incoming.ips {
        if !target.ips.contains(&ip) {
            target.ips.push(ip);
        }
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

fn wildcard_host(asset: &Asset) -> String {
    host_without_port(asset)
}

/// Returns true if `host` is strictly covered by the wildcard expression
/// (e.g. `api.example.com` is covered by `*.example.com`). Same-level is false.
pub fn is_covered_by_wildcard(host: &str, wildcard: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let host = host.trim_matches('.');
    let wildcard = wildcard.to_ascii_lowercase();
    let wildcard = wildcard.trim_matches('.');
    let Some(base) = wildcard.strip_prefix("*.") else {
        return false;
    };
    host != base && host.ends_with(&format!(".{base}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify_str;

    #[test]
    fn wildcard_covers_subdomain() {
        assert!(is_covered_by_wildcard("api.example.com", "*.example.com"));
        assert!(!is_covered_by_wildcard("example.com", "*.example.com"));
    }

    #[test]
    fn dedupe_merges_and_marks_coverage() {
        let records = vec![
            classify_str("api.example.com"),
            classify_str("*.example.com"),
            classify_str("api.example.com"),
        ];
        let out = dedupe(records);
        assert_eq!(out.len(), 2);
        let api = out
            .iter()
            .find(|a| a.kind == AssetKind::Subdomain)
            .unwrap();
        assert!(!api.covered_by.is_empty());
    }
}
