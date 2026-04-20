//! End-to-end smoke tests that exercise the full extract → classify → dedupe
//! pipeline through the library API (mirroring what the CLI does, minus IO).
//!
//! Keeping these in `tests/` makes them integration tests that compile against
//! the public surface — if any item used here becomes `pub(crate)`, the build
//! fails loudly.

use assetcanon::classify::classify_str;
use assetcanon::dedupe::dedupe;
use assetcanon::extract;
use assetcanon::model::{AssetKind, DnsStatus};
use assetcanon::scope::ScopeMatcher;

fn run_pipeline(text: &str) -> Vec<assetcanon::model::Asset> {
    let cands = extract::from_text(text);
    let assets: Vec<_> = cands.iter().map(|s| classify_str(s)).collect();
    let assets: Vec<_> = assets
        .into_iter()
        .filter(|a| a.kind != AssetKind::Garbage)
        .collect();
    dedupe(assets)
}

#[test]
fn multi_line_hosts_are_all_extracted() {
    let input = "example.com\napi.example.com\n1.1.1.1\n*.cdn.example.com\n[2001:db8::1]:443\n";
    let out = run_pipeline(input);
    let canonicals: Vec<&str> = out.iter().map(|a| a.canonical.as_str()).collect();
    assert!(canonicals.contains(&"example.com"));
    assert!(canonicals.contains(&"api.example.com"));
    assert!(canonicals.contains(&"1.1.1.1"));
    assert!(canonicals.contains(&"*.cdn.example.com"));
    assert!(canonicals.contains(&"[2001:db8::1]:443"));
    // Inner bare IPv6 must NOT be emitted as a duplicate once the bracketed
    // form was captured.
    assert!(!canonicals.contains(&"2001:db8::1"));
}

#[test]
fn dedupe_collapses_equivalent_inputs() {
    let input = "https://api.example.com/foo\napi.example.com\nhttp://api.example.com\n";
    let out = run_pipeline(input);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].canonical, "api.example.com");
}

#[test]
fn email_local_parts_are_not_mistaken_for_hosts() {
    let input = "contact foo@bar.com then visit https://baz.com";
    let out = run_pipeline(input);
    let canonicals: Vec<&str> = out.iter().map(|a| a.canonical.as_str()).collect();
    assert!(canonicals.contains(&"baz.com"));
    assert!(!canonicals.iter().any(|v| *v == "bar.com"));
}

#[test]
fn scope_matcher_roundtrip() {
    let rules = ["*.example.com", "foo.org"];
    let matcher = ScopeMatcher::compile(rules);
    let assets = [
        classify_str("api.example.com"),
        classify_str("deep.api.example.com"),
        classify_str("bar.foo.org"),
        classify_str("out.of.scope.net"),
    ];
    let in_scope: Vec<&str> = assets
        .iter()
        .filter(|a| matcher.is_in_scope(a, false))
        .map(|a| a.canonical.as_str())
        .collect();
    assert_eq!(
        in_scope,
        vec!["api.example.com", "deep.api.example.com", "bar.foo.org"]
    );
}

#[test]
fn dns_status_default_is_unknown() {
    let a = classify_str("example.com");
    assert_eq!(a.dns, DnsStatus::Unknown);
}

#[test]
fn wildcard_coverage_is_annotated() {
    let input = "api.example.com\n*.example.com\n";
    let out = run_pipeline(input);
    let api = out
        .iter()
        .find(|a| a.kind == AssetKind::Subdomain)
        .expect("subdomain in output");
    assert!(!api.covered_by.is_empty(), "api.example.com should be covered by *.example.com");
}
