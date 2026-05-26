//! CDN IP range lookup.
//!
//! Built from a vendored snapshot at `assets/cdn_ranges.txt`. The lookup is
//! used by DNS validation to (a) tag CDN-fronted hosts and (b) avoid the
//! common false-positive where a CDN-fronted real host gets classified as
//! `wildcard_ip` because its rotating CDN IPs overlap the parent's wildcard
//! signature.
//!
//! Bundled providers: Cloudflare, Fastly, GitHub Pages. Refresh by replacing
//! the asset file from the upstream feeds noted there.

use std::net::IpAddr;

use ipnet::{Ipv4Net, Ipv6Net};
use once_cell::sync::Lazy;

const CDN_RANGES_RAW: &str = include_str!("../assets/cdn_ranges.txt");

#[derive(Debug)]
struct V4Range {
    provider: &'static str,
    net: Ipv4Net,
}

#[derive(Debug)]
struct V6Range {
    provider: &'static str,
    net: Ipv6Net,
}

struct CdnTable {
    v4: Vec<V4Range>,
    v6: Vec<V6Range>,
}

static TABLE: Lazy<CdnTable> = Lazy::new(|| parse_table(CDN_RANGES_RAW));

/// CNAME-target suffixes that identify a CDN/PaaS host even when its
/// IPs are out-of-range (Akamai never publishes complete ranges; CloudFront's
/// ranges are huge and span shared AWS prefixes; some providers front through
/// rotating addresses that won't all be in our IP table).
///
/// Ordering matters when two suffixes overlap — more specific first.
const CDN_CNAME_SUFFIXES: &[(&str, &str)] = &[
    ("cdn.cloudflare.net", "cloudflare"),
    ("akamaiedge.net", "akamai"),
    ("akamaihd.net", "akamai"),
    ("akamai.net", "akamai"),
    ("edgekey.net", "akamai"),
    ("edgesuite.net", "akamai"),
    ("cloudfront.net", "cloudfront"),
    ("fastlylb.net", "fastly"),
    ("fastly.net", "fastly"),
    ("azureedge.net", "azure"),
    ("azurefd.net", "azure"),
    ("vercel-dns.com", "vercel"),
    ("vercel.app", "vercel"),
    ("netlify.app", "netlify"),
    ("netlifyglobalcdn.com", "netlify"),
    ("herokuapp.com", "heroku"),
    ("herokudns.com", "heroku"),
    ("github.io", "github_pages"),
];

/// Match `cname` against a CDN suffix. Must terminate at a zone boundary so
/// `notakamai.net` doesn't match `akamai.net`.
fn matches_zone_suffix(cname: &str, suffix: &str) -> bool {
    if cname == suffix {
        return true;
    }
    if cname.len() <= suffix.len() {
        return false;
    }
    if !cname.ends_with(suffix) {
        return false;
    }
    cname.as_bytes()[cname.len() - suffix.len() - 1] == b'.'
}

/// Identify a CDN from the terminal (last) CNAME in a resolution chain. Returns
/// `Some(provider)` when the terminal target matches any known CDN suffix. The
/// terminal is preferred because that's where the host actually resolves; any
/// intermediate hop in the chain is a hint at best.
pub fn lookup_cname_terminal(cnames: &[String]) -> Option<&'static str> {
    let terminal = cnames.last()?;
    let normalized = terminal.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    for (suffix, provider) in CDN_CNAME_SUFFIXES {
        if matches_zone_suffix(&normalized, suffix) {
            return Some(provider);
        }
    }
    None
}

/// Returns the CDN provider name (e.g. `"cloudflare"`) if `ip` is inside any
/// bundled CDN range, otherwise `None`. Provider strings are `&'static`.
pub fn lookup(ip: IpAddr) -> Option<&'static str> {
    let t = &*TABLE;
    match ip {
        IpAddr::V4(v4) => {
            t.v4.iter()
                .find(|r| r.net.contains(&v4))
                .map(|r| r.provider)
        }
        IpAddr::V6(v6) => {
            t.v6.iter()
                .find(|r| r.net.contains(&v6))
                .map(|r| r.provider)
        }
    }
}

/// Returns the dominant CDN provider across a set of IPs: `Some(name)` iff
/// *every* IP maps to the same provider (and there is at least one IP).
/// `None` if the set is empty, mixed across providers, or contains a
/// non-CDN IP. The all-or-nothing rule matters because the caller uses this
/// to override an IP-overlap wildcard verdict — a single non-CDN IP would
/// keep the verdict.
pub fn dominant_provider<'a, I>(ips: I) -> Option<&'static str>
where
    I: IntoIterator<Item = &'a IpAddr>,
{
    let mut seen: Option<&'static str> = None;
    let mut any = false;
    for ip in ips {
        any = true;
        match lookup(*ip) {
            Some(p) => match seen {
                None => seen = Some(p),
                Some(prev) if prev == p => {}
                Some(_) => return None,
            },
            None => return None,
        }
    }
    if any {
        seen
    } else {
        None
    }
}

fn parse_table(raw: &str) -> CdnTable {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let provider = match parts.next() {
            Some(p) => intern(p),
            None => continue,
        };
        let cidr = match parts.next().map(str::trim) {
            Some(c) if !c.is_empty() => c,
            _ => continue,
        };
        if let Ok(net) = cidr.parse::<Ipv4Net>() {
            v4.push(V4Range { provider, net });
        } else if let Ok(net) = cidr.parse::<Ipv6Net>() {
            v6.push(V6Range { provider, net });
        } else {
            // Skip malformed line silently; bad vendored data shouldn't crash
            // the binary. Tests assert the bundled file parses cleanly.
        }
    }
    CdnTable { v4, v6 }
}

/// Map known provider tokens to `&'static str`. The bundled asset uses a
/// small fixed vocabulary; unknown tokens are dropped (we'd rather miss a
/// tag than emit garbage).
fn intern(s: &str) -> &'static str {
    match s {
        "cloudflare" => "cloudflare",
        "fastly" => "fastly",
        "github_pages" => "github_pages",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_table_parses_and_has_entries() {
        let t = &*TABLE;
        assert!(t.v4.len() >= 30, "expected at least 30 v4 ranges");
        assert!(t.v6.len() >= 5, "expected at least 5 v6 ranges");
        for r in &t.v4 {
            assert!(!r.provider.is_empty(), "every v4 range has a provider");
        }
        for r in &t.v6 {
            assert!(!r.provider.is_empty(), "every v6 range has a provider");
        }
    }

    #[test]
    fn cloudflare_v4_lookup() {
        let ip: IpAddr = "104.16.1.1".parse().unwrap();
        assert_eq!(lookup(ip), Some("cloudflare"));
    }

    #[test]
    fn fastly_v4_lookup() {
        let ip: IpAddr = "151.101.1.1".parse().unwrap();
        assert_eq!(lookup(ip), Some("fastly"));
    }

    #[test]
    fn github_pages_v4_lookup() {
        let ip: IpAddr = "185.199.108.153".parse().unwrap();
        assert_eq!(lookup(ip), Some("github_pages"));
    }

    #[test]
    fn cloudflare_v6_lookup() {
        let ip: IpAddr = "2606:4700::1".parse().unwrap();
        assert_eq!(lookup(ip), Some("cloudflare"));
    }

    #[test]
    fn non_cdn_returns_none() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(lookup(ip), None);
    }

    #[test]
    fn dominant_provider_all_cf() {
        let ips: Vec<IpAddr> = vec!["104.16.1.1".parse().unwrap(), "172.64.1.1".parse().unwrap()];
        assert_eq!(dominant_provider(ips.iter()), Some("cloudflare"));
    }

    #[test]
    fn dominant_provider_mixed_returns_none() {
        let ips: Vec<IpAddr> = vec![
            "104.16.1.1".parse().unwrap(),  // cloudflare
            "151.101.1.1".parse().unwrap(), // fastly
        ];
        assert_eq!(dominant_provider(ips.iter()), None);
    }

    #[test]
    fn dominant_provider_with_non_cdn_returns_none() {
        let ips: Vec<IpAddr> = vec!["104.16.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()];
        assert_eq!(dominant_provider(ips.iter()), None);
    }

    #[test]
    fn dominant_provider_empty_returns_none() {
        let ips: Vec<IpAddr> = Vec::new();
        assert_eq!(dominant_provider(ips.iter()), None);
    }

    #[test]
    fn cname_terminal_matches_akamai() {
        let chain: Vec<String> = vec!["foo.bar".into(), "e1234.dscb.akamaiedge.net".into()];
        assert_eq!(lookup_cname_terminal(&chain), Some("akamai"));
    }

    #[test]
    fn cname_terminal_matches_cloudfront() {
        let chain: Vec<String> = vec!["d12345.cloudfront.net".into()];
        assert_eq!(lookup_cname_terminal(&chain), Some("cloudfront"));
    }

    #[test]
    fn cname_terminal_matches_fastly() {
        let chain: Vec<String> = vec!["dualstack.somesite.map.fastly.net".into()];
        assert_eq!(lookup_cname_terminal(&chain), Some("fastly"));
    }

    #[test]
    fn cname_terminal_matches_vercel() {
        let chain: Vec<String> = vec!["myapp.vercel.app".into()];
        assert_eq!(lookup_cname_terminal(&chain), Some("vercel"));
    }

    #[test]
    fn cname_terminal_strips_trailing_dot_and_lowercases() {
        let chain: Vec<String> = vec!["E1234.AkamaiEdge.Net.".into()];
        assert_eq!(lookup_cname_terminal(&chain), Some("akamai"));
    }

    #[test]
    fn cname_terminal_empty_chain_returns_none() {
        let chain: Vec<String> = Vec::new();
        assert_eq!(lookup_cname_terminal(&chain), None);
    }

    #[test]
    fn cname_terminal_non_cdn_returns_none() {
        let chain: Vec<String> = vec!["legacy.example.com".into()];
        assert_eq!(lookup_cname_terminal(&chain), None);
    }

    #[test]
    fn cname_suffix_zone_boundary_rejects_false_match() {
        // `notakamai.net` must NOT match the `akamai.net` suffix.
        assert!(!matches_zone_suffix("notakamai.net", "akamai.net"));
        // But proper subdomains do match.
        assert!(matches_zone_suffix("foo.akamai.net", "akamai.net"));
        // Exact suffix match too.
        assert!(matches_zone_suffix("akamai.net", "akamai.net"));
    }
}
