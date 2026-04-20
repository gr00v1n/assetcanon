//! Canonical asset classification.
//!
//! Takes a normalized input and produces an `Asset` with a final `AssetKind`,
//! registrable domain (if applicable), and the canonical display value.

use std::net::IpAddr;

use publicsuffix::Psl;
use regex::Regex;

use crate::model::{Asset, AssetKind, DnsStatus, ScopeStatus};
use crate::normalize::{canonical_value, normalize, Normalized};
use crate::psl::LIST;

static LABEL_RE: once_cell::sync::Lazy<Regex> =
    once_cell::sync::Lazy::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").unwrap());

pub fn classify_str(raw: &str) -> Asset {
    classify(normalize(raw))
}

pub fn classify(norm: Normalized) -> Asset {
    if !norm.valid {
        return Asset::garbage(
            norm.raw,
            norm.reason.unwrap_or("invalid-syntax").to_string(),
        );
    }

    let host = norm.host.trim();
    if host.is_empty() {
        return Asset::garbage(norm.raw, "empty");
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        let canonical_host = ip.to_string();
        let canonical = canonical_value(&canonical_host, norm.port);
        return Asset {
            raw: norm.raw,
            canonical,
            kind: AssetKind::Ip,
            registrable: None,
            port: norm.port,
            scheme: norm.scheme,
            reason: None,
            covered_by: Vec::new(),
            dns: DnsStatus::Unknown,
            ips: Vec::new(),
            cname: None,
            scope: ScopeStatus::Unknown,
        };
    }

    if has_invalid_domain_syntax(host) {
        return Asset::garbage(norm.raw, "invalid-domain-syntax");
    }

    let wildcard = host.starts_with("*.");
    let base = if wildcard { &host[2..] } else { host };
    if base.starts_with('.') || base.contains('*') {
        return Asset::garbage(norm.raw, "invalid-wildcard");
    }

    let registrable = match registrable_domain(base) {
        Some(d) => d,
        None => {
            let reason = if wildcard {
                "invalid-wildcard-domain"
            } else {
                "invalid-domain"
            };
            return Asset::garbage(norm.raw, reason);
        }
    };

    let kind = if wildcard {
        AssetKind::Wildcard
    } else if base == registrable {
        AssetKind::Apex
    } else {
        AssetKind::Subdomain
    };

    let canonical_host = if wildcard {
        format!("*.{base}")
    } else {
        base.to_string()
    };
    let canonical = canonical_value(&canonical_host, norm.port);

    Asset {
        raw: norm.raw,
        canonical,
        kind,
        registrable: Some(registrable),
        port: norm.port,
        scheme: norm.scheme,
        reason: None,
        covered_by: Vec::new(),
        dns: DnsStatus::Unknown,
        ips: Vec::new(),
        cname: None,
        scope: ScopeStatus::Unknown,
    }
}

fn registrable_domain(host: &str) -> Option<String> {
    let bytes = host.as_bytes();
    let domain = LIST.domain(bytes)?;
    let s = std::str::from_utf8(domain.as_bytes()).ok()?;
    if !s.contains('.') {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

fn has_invalid_domain_syntax(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return true;
    }
    if host.starts_with('.') || host.ends_with('.') {
        return true;
    }
    if host.contains("..") {
        return true;
    }
    if host.contains('@') || host.chars().any(|c| c.is_whitespace()) {
        return true;
    }
    if host.contains('*') && !host.starts_with("*.") {
        return true;
    }
    let labels_src: &str = if let Some(rest) = host.strip_prefix("*.") {
        rest
    } else {
        host
    };
    let labels: Vec<&str> = labels_src.split('.').collect();
    if labels.len() < 2 {
        return true;
    }
    labels.iter().any(|label| label.is_empty() || !LABEL_RE.is_match(label))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apex_and_subdomain() {
        assert_eq!(classify_str("example.com").kind, AssetKind::Apex);
        assert_eq!(classify_str("api.example.com").kind, AssetKind::Subdomain);
        assert_eq!(
            classify_str("api.example.com").registrable.as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn wildcard() {
        let a = classify_str("*.example.com");
        assert_eq!(a.kind, AssetKind::Wildcard);
        assert_eq!(a.canonical, "*.example.com");
    }

    #[test]
    fn ipv4_and_ipv6() {
        assert_eq!(classify_str("192.168.1.1").kind, AssetKind::Ip);
        assert_eq!(classify_str("::1").kind, AssetKind::Ip);
        let bracket = classify_str("[2001:db8::1]:8080");
        assert_eq!(bracket.kind, AssetKind::Ip);
        assert_eq!(bracket.canonical, "[2001:db8::1]:8080");
    }

    #[test]
    fn idn_is_normalized() {
        let a = classify_str("中文.com");
        assert_eq!(a.kind, AssetKind::Apex);
        assert_eq!(a.canonical, "xn--fiq228c.com");
    }

    #[test]
    fn garbage() {
        assert_eq!(classify_str("https://").kind, AssetKind::Garbage);
        assert_eq!(classify_str("not a domain").kind, AssetKind::Garbage);
        assert_eq!(classify_str("").kind, AssetKind::Garbage);
    }
}
