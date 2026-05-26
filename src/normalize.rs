//! Syntax-level normalization.
//!
//! Turns a raw input string into a canonical host form with optional port and
//! scheme. Does not classify (that's `classify.rs`). Pure function — no IO,
//! no allocations beyond the returned struct.

use std::net::IpAddr;

use crate::model::{Asset, AssetKind, DnsStatus, ScopeStatus};

const SURROUNDING: &[char] = &['"', '\'', '`', '<', '>', '(', ')', '{', '}'];

#[derive(Debug, Clone)]
pub struct Normalized {
    pub raw: String,
    pub host: String,
    pub port: Option<u16>,
    pub scheme: Option<String>,
    pub valid: bool,
    pub reason: Option<&'static str>,
}

impl Normalized {
    pub fn invalid(raw: String, host: String, reason: &'static str) -> Self {
        Self {
            raw,
            host,
            port: None,
            scheme: None,
            valid: false,
            reason: Some(reason),
        }
    }
}

/// Normalize a raw candidate. Never fails — invalid inputs become `valid=false`
/// with a reason string, consumed by the classifier to produce Garbage.
pub fn normalize(raw_input: &str) -> Normalized {
    let raw = raw_input.to_string();
    let trimmed = raw_input.trim();
    if trimmed.is_empty() {
        return Normalized::invalid(raw, String::new(), "empty");
    }
    let trimmed = trimmed.trim_matches(SURROUNDING);

    let parsed = parse(trimmed);
    let (host, port, scheme, reason) = match parsed {
        Some(p) => p,
        None => return Normalized::invalid(raw, trimmed.to_ascii_lowercase(), "unparseable"),
    };

    if let Some(r) = reason {
        return Normalized::invalid(raw, host.to_ascii_lowercase(), r);
    }

    let host = host.trim().trim_matches(SURROUNDING);
    if host.is_empty() {
        return Normalized::invalid(raw, String::new(), "missing-host");
    }

    let wildcard = host.starts_with("*.");
    let body = if wildcard { &host[2..] } else { host };
    let body = body.trim_end_matches('.');

    let canonical_host = if let Some(ip) = normalize_ip(body) {
        ip
    } else {
        match normalize_domain(body) {
            Some(domain) => {
                if wildcard {
                    format!("*.{domain}")
                } else {
                    domain
                }
            }
            None => {
                return Normalized::invalid(raw, host.to_ascii_lowercase(), "invalid-idna");
            }
        }
    };

    let is_default = is_default_port(scheme.as_deref(), port);
    let final_port = if is_default { None } else { port };

    Normalized {
        raw,
        host: canonical_host,
        port: final_port,
        scheme,
        valid: true,
        reason: None,
    }
}

type ParsedInput = (String, Option<u16>, Option<String>, Option<&'static str>);

fn parse(raw: &str) -> Option<ParsedInput> {
    if has_scheme(raw) || raw.starts_with("//") {
        parse_url(raw)
    } else {
        parse_bare(raw)
    }
}

fn has_scheme(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut iter = bytes.iter();
    let Some(&first) = iter.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    for (seen, &b) in (1..).zip(iter) {
        if b == b':' {
            return seen >= 1 && raw.len() > seen + 2 && &raw[seen..seen + 3] == "://";
        }
        if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')) {
            return false;
        }
    }
    false
}

fn parse_url(raw: &str) -> Option<ParsedInput> {
    let normalized = if raw.starts_with("//") {
        format!("http:{raw}")
    } else {
        raw.to_string()
    };

    // Hand-roll a tiny URL host extractor (we don't need full URL parsing).
    let scheme_end = normalized.find("://")?;
    let scheme = normalized[..scheme_end].to_ascii_lowercase();
    let after = &normalized[scheme_end + 3..];

    // Strip userinfo if present.
    let authority = match after.find('/') {
        Some(i) => &after[..i],
        None => after,
    };
    let authority = match authority.find('?') {
        Some(i) => &authority[..i],
        None => authority,
    };
    let authority = match authority.find('#') {
        Some(i) => &authority[..i],
        None => authority,
    };
    let authority = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };

    if authority.is_empty() {
        return Some((String::new(), None, Some(scheme), Some("missing-host")));
    }

    // IPv6 literal?
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[1..end];
        let rest = &authority[end + 1..];
        if rest.is_empty() {
            return Some((host.to_string(), None, Some(scheme), None));
        }
        if let Some(port_str) = rest.strip_prefix(':') {
            let (port, reason) = parse_port(port_str);
            return Some((host.to_string(), port, Some(scheme), reason));
        }
        return Some((
            host.to_string(),
            None,
            Some(scheme),
            Some("invalid-ipv6-port"),
        ));
    }

    // hostname[:port]
    if let Some(colon) = authority.rfind(':') {
        // Avoid treating bare IPv6 (without brackets) as host:port — but urlsplit
        // normally rejects those. Still, guard it.
        let (host, port_str) = authority.split_at(colon);
        let port_str = &port_str[1..];
        if port_str.is_empty() {
            return Some((host.to_string(), None, Some(scheme), None));
        }
        let (port, reason) = parse_port(port_str);
        return Some((host.to_string(), port, Some(scheme), reason));
    }

    Some((authority.to_string(), None, Some(scheme), None))
}

fn parse_bare(raw: &str) -> Option<ParsedInput> {
    if raw.contains('@') {
        return Some((raw.to_string(), None, None, Some("contains-at")));
    }

    let head = raw
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("")
        .trim();

    if head.is_empty() {
        return Some((String::new(), None, None, Some("missing-host")));
    }
    if head.chars().any(|c| c.is_whitespace()) {
        return Some((head.to_string(), None, None, Some("contains-space")));
    }

    if let Some(rest) = head.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if after.is_empty() {
            return Some((host.to_string(), None, None, None));
        }
        if let Some(port_str) = after.strip_prefix(':') {
            let (port, reason) = parse_port(port_str);
            return Some((host.to_string(), port, None, reason));
        }
        return Some((host.to_string(), None, None, Some("invalid-ipv6-port")));
    }

    if normalize_ip(head).is_some() {
        return Some((head.to_string(), None, None, None));
    }

    let colon_count = head.matches(':').count();
    if colon_count == 1 {
        let (host, port_str) = head.rsplit_once(':').unwrap();
        let (port, reason) = parse_port(port_str);
        return Some((host.to_string(), port, None, reason));
    }

    if colon_count > 1 {
        if normalize_ip(head).is_some() {
            return Some((head.to_string(), None, None, None));
        }
        return Some((head.to_string(), None, None, Some("invalid-ipv6")));
    }

    Some((head.to_string(), None, None, None))
}

fn parse_port(s: &str) -> (Option<u16>, Option<&'static str>) {
    match s.parse::<u32>() {
        Ok(p) if (1..=65535).contains(&p) => (Some(p as u16), None),
        _ => (None, Some("invalid-port")),
    }
}

fn normalize_ip(host: &str) -> Option<String> {
    host.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

fn normalize_domain(host: &str) -> Option<String> {
    let lowered = host.trim().trim_end_matches('.').to_lowercase();
    if lowered.is_empty() {
        return None;
    }
    let (ascii, result) = idna::domain_to_ascii_cow(lowered.as_bytes(), idna::AsciiDenyList::URL)
        .ok()
        .map(|cow| (cow.into_owned(), Ok::<(), ()>(())))
        .unwrap_or_else(|| (lowered.clone(), Err(())));
    // hickory-dns 0.26 pairs with idna 1.x which returns Result from domain_to_ascii.
    // Keep the fallback path explicit.
    if result.is_err() && ascii == lowered {
        // Try plain IDNA per-label as a simpler fallback.
        let labels: Option<Vec<String>> = lowered
            .split('.')
            .map(|label| {
                if label.is_empty() {
                    return None;
                }
                if label.is_ascii() {
                    return Some(label.to_string());
                }
                idna::domain_to_ascii_cow(label.as_bytes(), idna::AsciiDenyList::URL)
                    .ok()
                    .map(|cow| cow.into_owned())
            })
            .collect();
        return labels.map(|v| v.join(".").to_ascii_lowercase());
    }
    Some(ascii.to_ascii_lowercase())
}

fn is_default_port(scheme: Option<&str>, port: Option<u16>) -> bool {
    match (scheme, port) {
        (_, None) => false,
        (Some("http"), Some(80)) => true,
        (Some("https"), Some(443)) => true,
        _ => false,
    }
}

/// Build a canonical host[:port] display value. Mirrors Python `canonical_value`.
pub fn canonical_value(host: &str, port: Option<u16>) -> String {
    match port {
        None => host.to_string(),
        Some(p) if host.contains(':') && !host.starts_with("*.") => format!("[{host}]:{p}"),
        Some(p) => format!("{host}:{p}"),
    }
}

/// Build a partial Asset with classification fields unset. The classifier fills
/// `kind`, `registrable`, and promotes invalid normalizations to Garbage.
pub fn to_asset_skeleton(norm: Normalized) -> Asset {
    if !norm.valid {
        return Asset {
            raw: norm.raw,
            canonical: norm.host,
            kind: AssetKind::Garbage,
            registrable: None,
            port: norm.port,
            scheme: norm.scheme,
            reason: norm.reason.map(|r| r.to_string()),
            covered_by: Vec::new(),
            dns: DnsStatus::Unknown,
            ips: Vec::new(),
            cnames: Vec::new(),
            wildcard_root: None,
            wildcard_reason: None,
            wildcard_ip_overlap_count: 0,
            wildcard_cname_overlap_count: 0,
            wildcard_host_ip_count: 0,
            wildcard_signature_ip_count: 0,
            wildcard_signature_cname_count: 0,
            resolver_disagreement: false,
            dead_zone: None,
            flaky_zone: None,
            cdn: None,
            confidence: None,
            scope: ScopeStatus::Unknown,
        };
    }
    Asset {
        raw: norm.raw,
        canonical: norm.host,
        kind: AssetKind::Garbage, // placeholder — classifier will overwrite
        registrable: None,
        port: norm.port,
        scheme: norm.scheme,
        reason: None,
        covered_by: Vec::new(),
        dns: DnsStatus::Unknown,
        ips: Vec::new(),
        cnames: Vec::new(),
        wildcard_root: None,
        wildcard_reason: None,
        wildcard_ip_overlap_count: 0,
        wildcard_cname_overlap_count: 0,
        wildcard_host_ip_count: 0,
        wildcard_signature_ip_count: 0,
        wildcard_signature_cname_count: 0,
        resolver_disagreement: false,
        dead_zone: None,
        flaky_zone: None,
        cdn: None,
        confidence: None,
        scope: ScopeStatus::Unknown,
    }
}
