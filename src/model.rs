//! Unified asset model — replaces the three-layer
//! `Candidate` / `NormalizedCandidate` / `AssetRecord` chain from the Python
//! reference implementation with a single struct plus typed state.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Classification of an asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetKind {
    Apex,
    Subdomain,
    Wildcard,
    Ip,
    Garbage,
}

impl AssetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssetKind::Apex => "apex",
            AssetKind::Subdomain => "subdomain",
            AssetKind::Wildcard => "wildcard",
            AssetKind::Ip => "ip",
            AssetKind::Garbage => "garbage",
        }
    }
}

/// DNS liveness status attached to an asset after validation.
///
/// The enum is finer-grained than puredns's binary resolved/wildcard split:
/// we distinguish IP-only wildcards (`WildcardIp`) from CNAME-target wildcards
/// (`WildcardCname`, common for CDNs), and flag hosts whose answer set
/// partially overlaps a wildcard signature (`MixedWildcard`) because those
/// deserve a second look rather than a blanket filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsStatus {
    #[default]
    Unknown,
    Resolved,
    Unresolved,
    WildcardIp,
    WildcardCname,
    MixedWildcard,
    Shaky,
    Timeout,
    Error,
}

impl DnsStatus {
    pub fn is_wildcard(&self) -> bool {
        matches!(
            self,
            DnsStatus::WildcardIp | DnsStatus::WildcardCname | DnsStatus::MixedWildcard
        )
    }
}

/// Why a DNS result was classified as a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WildcardReason {
    IpOverlap,
    CnameMatch,
    TimeoutInferred,
}

/// Scope match outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScopeStatus {
    #[default]
    Unknown,
    InScope,
    OutOfScope,
}

/// A canonical asset record. Produced by the classify stage from a normalized
/// input; consumed by dedupe/scope/dns and finally emitted by the CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    /// Original input string before any cleaning.
    pub raw: String,

    /// Canonical host form (or hex digest for garbage).
    /// - apex/subdomain/wildcard: ASCII-lowercase IDN form
    /// - ip: IpAddr::to_string()
    pub canonical: String,

    pub kind: AssetKind,

    /// Registrable domain (e.g. `example.com`) for apex/subdomain/wildcard;
    /// None for ip/garbage.
    pub registrable: Option<String>,

    /// Optional explicit port (None means default or unspecified).
    pub port: Option<u16>,

    /// Scheme hint carried from the input (e.g. Some("https")).
    pub scheme: Option<String>,

    /// Explanation when `kind == Garbage`.
    pub reason: Option<String>,

    /// Wildcard assets that semantically cover this host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_by: Vec<String>,

    #[serde(default, skip_serializing_if = "is_unknown_dns")]
    pub dns: DnsStatus,

    /// A/AAAA records found during DNS validation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<IpAddr>,

    /// CNAME resolution chain in order, e.g. `["legacy.target.com",
    /// "s3-bucket.amazonaws.com"]`. Empty when the host resolves directly via
    /// A/AAAA. Preserved in chain order (not sorted) so downstream tools can
    /// trace the full path — needed for dangling-CNAME / takeover detection and
    /// CDN fingerprinting where intermediate hops carry information.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cnames: Vec<String>,

    /// Wildcard root that explained a wildcard DNS status, e.g. `*.example.com`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wildcard_root: Option<String>,

    /// Specific wildcard signal used for the verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wildcard_reason: Option<WildcardReason>,

    /// Evidence counts behind a wildcard verdict. These are intentionally
    /// aggregate counts, not per-resolver payloads, so JSON output stays small
    /// on large runs.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub wildcard_ip_overlap_count: usize,

    #[serde(default, skip_serializing_if = "is_zero")]
    pub wildcard_cname_overlap_count: usize,

    #[serde(default, skip_serializing_if = "is_zero")]
    pub wildcard_host_ip_count: usize,

    #[serde(default, skip_serializing_if = "is_zero")]
    pub wildcard_signature_ip_count: usize,

    #[serde(default, skip_serializing_if = "is_zero")]
    pub wildcard_signature_cname_count: usize,

    /// True when independent resolvers disagreed on answer vs NXDOMAIN.
    #[serde(default, skip_serializing_if = "is_false")]
    pub resolver_disagreement: bool,

    /// Dead ancestor zone that caused DNS validation to short-circuit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_zone: Option<String>,

    /// Runtime flaky parent zone that caused DNS validation to short-circuit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flaky_zone: Option<String>,

    /// CDN provider identified from the resolved IP set (e.g. `"cloudflare"`).
    /// Set when every resolved IP falls in a known CDN range. Also acts as the
    /// signal that downgraded an IP-overlap wildcard verdict to `resolved`,
    /// since CDN IPs legitimately rotate and overlap is uninformative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdn: Option<String>,

    /// Confidence in the DNS verdict on a `[0.0, 1.0]` scale. Derived from the
    /// existing wildcard evidence counts, multi-resolver agreement, and the
    /// CDN tag. `None` when DNS validation didn't run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,

    #[serde(default, skip_serializing_if = "is_unknown_scope")]
    pub scope: ScopeStatus,
}

fn is_unknown_dns(s: &DnsStatus) -> bool {
    matches!(s, DnsStatus::Unknown)
}

fn is_unknown_scope(s: &ScopeStatus) -> bool {
    matches!(s, ScopeStatus::Unknown)
}

fn is_false(v: &bool) -> bool {
    !*v
}

fn is_zero(v: &usize) -> bool {
    *v == 0
}

impl Asset {
    pub fn garbage(raw: impl Into<String>, reason: impl Into<String>) -> Self {
        let raw = raw.into();
        let digest = short_digest(&raw);
        Self {
            raw,
            canonical: digest,
            kind: AssetKind::Garbage,
            registrable: None,
            port: None,
            scheme: None,
            reason: Some(reason.into()),
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

    /// Stable semantic key used for deduplication and cross-phase reference.
    pub fn canonical_key(&self) -> String {
        let kind = self.kind.as_str();
        match self.kind {
            AssetKind::Garbage => format!("garbage:{}", self.canonical),
            _ => match self.port {
                None => format!("{kind}:{}", self.canonical),
                Some(port) if self.kind == AssetKind::Ip && self.canonical.contains(':') => {
                    format!("{kind}:[{}]:{port}", self.canonical)
                }
                Some(port) => format!("{kind}:{}:{port}", self.canonical),
            },
        }
    }

    pub fn is_host(&self) -> bool {
        matches!(
            self.kind,
            AssetKind::Apex | AssetKind::Subdomain | AssetKind::Ip
        )
    }
}

fn short_digest(input: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    input.hash(&mut h);
    format!("{:016x}", h.finish())
}
