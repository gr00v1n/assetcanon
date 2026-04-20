//! DNS validation with an improved wildcard-filtering pipeline.
//!
//! Differences from a plain puredns port:
//!
//! 1. **Dual wildcard signature.** A signature records both the union of
//!    terminal IPs and the set of CNAME targets observed from random probes.
//!    CDN/SaaS wildcards (`*.example.com → dXYZ.cloudfront.net → rotating IPs`)
//!    are caught via the CNAME target even when the IP set churns.
//! 2. **Batch precompute.** All ancestor domains referenced by the input are
//!    collected up front and probed concurrently. Host validation then runs
//!    against a read-only `HashMap<parent, Option<Signature>>` — no further
//!    probe traffic, no per-host tree walk.
//! 3. **Multi-resolver consistency.** Each host is resolved through
//!    `consistency_checks` independent resolvers in parallel. If one says
//!    NXDOMAIN and another returns answers, the host is flagged `Shaky`.
//! 4. **Refined status.** Instead of a binary `Resolved|Wildcard`, we emit
//!    `WildcardIp`, `WildcardCname`, `MixedWildcard`, `Shaky`, `Timeout`, and
//!    `Unresolved`, letting downstream tooling decide how aggressively to filter.
//! 5. **NXDOMAIN short-circuit.** A parent whose random probes all yield
//!    NXDOMAIN is recorded as "no wildcard here" once and reused.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use futures::stream::{self, StreamExt};
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use rand::Rng;
use tokio::sync::{Mutex, RwLock};

use crate::model::{Asset, AssetKind, DnsStatus};

// ---------------------------------------------------------------------------
// Configuration

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub resolvers: Vec<SocketAddr>,
    pub concurrency: usize,
    pub timeout: Duration,
    pub retries: u8,
    pub wildcard_tests: usize,
    pub wildcard_filter: bool,
    /// Number of independent resolvers queried per host for consistency
    /// cross-checking. 1 disables the check.
    pub consistency_checks: usize,
    /// Parallelism cap for the wildcard-signature precompute phase. 0 = auto
    /// (currently `max(concurrency / 4, 16)`). Kept lower than the host-level
    /// `concurrency` because the precompute fires `wildcard_tests` queries per
    /// parent simultaneously; without a separate cap, the initial burst
    /// rate-limits upstream resolvers and produces false "no wildcard" verdicts.
    pub probe_concurrency: usize,
    /// Zone short-circuit: skip subsequent host queries in a parent once the
    /// parent has accumulated enough failures. `flaky_min_samples` is the
    /// minimum number of resolved hosts under the parent before the ratio is
    /// even checked; `flaky_threshold` is the timeout-ratio at or above which
    /// the parent is flagged. Set either to 0 to disable the short-circuit.
    pub flaky_threshold: f32,
    pub flaky_min_samples: usize,
    /// Treat "host query timed out under a confirmed-wildcard parent" as
    /// `WildcardIp` instead of `Timeout`. Rationale: under a wildcard zone,
    /// any label still resolves via the wildcard — so a timeout is almost
    /// always a rate-limit packet drop rather than a genuinely unreachable
    /// host. Disable for strict "observed only" semantics.
    pub infer_wildcard_on_timeout: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            resolvers: default_resolvers(),
            concurrency: 100,
            timeout: Duration::from_secs(5),
            retries: 2,
            wildcard_tests: 8,
            wildcard_filter: true,
            consistency_checks: 2,
            probe_concurrency: 0,
            flaky_threshold: 0.8,
            flaky_min_samples: 10,
            infer_wildcard_on_timeout: true,
        }
    }
}

impl DnsConfig {
    fn effective_probe_concurrency(&self) -> usize {
        if self.probe_concurrency == 0 {
            // Half of host-level concurrency (empirically low enough to avoid
            // hitting 1.1.1.1 / 8.8.8.8 rate limits during the probe burst),
            // floored at 50 so small configs still get real parallelism.
            (self.concurrency / 2).max(50)
        } else {
            self.probe_concurrency
        }
    }

    fn flaky_enabled(&self) -> bool {
        self.flaky_min_samples > 0 && self.flaky_threshold > 0.0 && self.flaky_threshold <= 1.0
    }
}

fn default_resolvers() -> Vec<SocketAddr> {
    [
        "1.1.1.1:53",
        "1.0.0.1:53",
        "8.8.8.8:53",
        "8.8.4.4:53",
        "9.9.9.9:53",
        "149.112.112.112:53",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
}

// ---------------------------------------------------------------------------
// Types

pub struct DnsValidator {
    resolvers: Vec<TokioResolver>,
    config: DnsConfig,
    // Parent domain → ParentState. Populated in one batch before host
    // validation; read-only afterwards.
    signatures: Arc<RwLock<HashMap<String, ParentState>>>,
    // Runtime flaky-zone tracker: accumulates (timeouts, total, flagged) per
    // immediate parent during the validation phase so bursts of timeouts
    // short-circuit remaining hosts in the same zone.
    flaky: Arc<Mutex<HashMap<String, FlakyStats>>>,
}

#[derive(Debug, Clone)]
enum ParentState {
    /// Probes surfaced a wildcard signature.
    Wildcard(WildcardSignature),
    /// Probes returned NXDOMAIN (or NOERROR-no-answer) decisively — no
    /// wildcard at this level.
    Clean,
    /// Two rounds of probes yielded zero decisive responses — the zone's
    /// authoritative NS is unreachable/broken. Host queries under a Dead
    /// ancestor are short-circuited to Timeout.
    Dead,
}

#[derive(Debug, Clone, Default)]
struct WildcardSignature {
    root: String,
    ips: HashSet<IpAddr>,
    cnames: HashSet<String>,
}

#[derive(Debug, Clone, Default)]
struct HostAnswers {
    ips: HashSet<IpAddr>,
    cnames: HashSet<String>,
    any_answer: bool,
    all_nxdomain: bool,
    any_timeout: bool,
    any_error: bool,
    /// Resolvers disagreed: at least one returned answers, at least one NXDOMAIN.
    disagreement: bool,
}

#[derive(Debug, Clone, Default)]
struct FlakyStats {
    timeouts: usize,
    total: usize,
    flagged: bool,
}

pub struct DnsReport {
    pub assets: Vec<Asset>,
    pub wildcard_roots: Vec<String>,
    pub dead_zones: Vec<String>,
    pub flaky_zones: Vec<String>,
}

// ---------------------------------------------------------------------------
// Implementation

impl DnsValidator {
    pub fn new(config: DnsConfig) -> anyhow::Result<Self> {
        if config.resolvers.is_empty() {
            anyhow::bail!("DnsConfig: no resolvers configured");
        }

        let mut resolvers = Vec::with_capacity(config.resolvers.len());
        for addr in &config.resolvers {
            let mut conn = ConnectionConfig::udp();
            conn.port = addr.port();
            let ns = NameServerConfig::new(addr.ip(), true, vec![conn]);
            let rconfig = ResolverConfig::from_parts(None, Vec::new(), vec![ns]);

            let mut opts = ResolverOpts::default();
            opts.timeout = config.timeout;
            opts.attempts = (config.retries as usize).max(1);
            opts.cache_size = 0;
            opts.use_hosts_file = ResolveHosts::Never;

            let provider = TokioRuntimeProvider::default();
            let resolver = TokioResolver::builder_with_config(rconfig, provider)
                .with_options(opts)
                .build()?;
            resolvers.push(resolver);
        }

        Ok(Self {
            resolvers,
            config,
            signatures: Arc::new(RwLock::new(HashMap::new())),
            flaky: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Validate all host-like assets. Non-host assets pass through unchanged.
    pub async fn validate(&self, assets: Vec<Asset>) -> DnsReport {
        if self.config.wildcard_filter {
            let ancestors = collect_ancestors(&assets);
            self.precompute_signatures(ancestors).await;
        }

        let concurrency = self.config.concurrency.max(1);
        let validator = Arc::new(self);
        let futures_iter = assets.into_iter().map(move |asset| {
            let v = Arc::clone(&validator);
            async move { v.validate_one(asset).await }
        });
        let assets: Vec<Asset> = stream::iter(futures_iter)
            .buffer_unordered(concurrency)
            .collect()
            .await;

        let wildcard_roots = self.collect_zone_names(|s| match s {
            ParentState::Wildcard(sig) => Some(format!("*.{}", sig.root)),
            _ => None,
        }).await;
        let dead_zones = self.collect_zone_names(|s| match s {
            ParentState::Dead => Some(String::new()),
            _ => None,
        }).await;
        let dead_zones = self.attach_names(dead_zones, ParentState::Dead).await;
        let flaky_zones = self.collect_flaky_zones().await;

        DnsReport {
            assets,
            wildcard_roots,
            dead_zones,
            flaky_zones,
        }
    }

    async fn precompute_signatures(&self, ancestors: HashSet<String>) {
        if ancestors.is_empty() {
            return;
        }
        let probe_con = self.config.effective_probe_concurrency().max(1);
        let jobs = ancestors.into_iter().map(|parent| async move {
            let state = self.probe_parent(&parent).await;
            (parent, state)
        });
        let results: Vec<_> = stream::iter(jobs)
            .buffer_unordered(probe_con)
            .collect()
            .await;

        let mut cache = self.signatures.write().await;
        for (parent, state) in results {
            cache.insert(parent, state);
        }
    }

    /// Fire `wildcard_tests` random probes against `parent`, spread across
    /// resolvers. Collapses the outcome into a `ParentState`:
    ///
    /// - Two rounds yielding **zero** decisive responses → `Dead`: the zone's
    ///   authoritative NS is unreachable. Hosts under this parent will be
    ///   short-circuited to `Timeout` without a DNS query.
    /// - Any probe resolved → `Wildcard` (signature union across rounds).
    /// - Decisive responses but no resolved probes → `Clean`.
    ///
    /// A retry is triggered when fewer than half of the first round's probes
    /// were decisive, so a rate-limited first wave doesn't produce a false
    /// Clean / Dead verdict.
    async fn probe_parent(&self, parent: &str) -> ParentState {
        let tests = self.config.wildcard_tests.max(1);
        let threshold = (tests / 2).max(1);

        let (sig1, decisive1) = self.probe_parent_round(parent, tests).await;
        if decisive1 >= threshold {
            return sig_to_state(sig1);
        }

        let (sig2, decisive2) = self.probe_parent_round(parent, tests).await;

        if decisive1 + decisive2 == 0 {
            return ParentState::Dead;
        }

        let unioned = match (sig1, sig2) {
            (Some(mut a), Some(b)) => {
                a.ips.extend(b.ips);
                a.cnames.extend(b.cnames);
                Some(a)
            }
            (Some(s), None) | (None, Some(s)) => Some(s),
            (None, None) => None,
        };
        sig_to_state(unioned)
    }

    /// One round of `tests` random probes. Returns the signature (if any
    /// probe resolved) and the count of probes that returned a decisive
    /// response (answer or NXDOMAIN) — used to detect rate-limited rounds.
    async fn probe_parent_round(
        &self,
        parent: &str,
        tests: usize,
    ) -> (Option<WildcardSignature>, usize) {
        let jobs: Vec<_> = (0..tests)
            .map(|i| {
                let sub = format!("{}.{}", random_label(16), parent);
                let resolver = &self.resolvers[i % self.resolvers.len()];
                async move { resolve_host(resolver, &sub).await }
            })
            .collect();
        let results: Vec<HostAnswers> = join_all(jobs).await;

        let mut ips: HashSet<IpAddr> = HashSet::new();
        let mut cnames: HashSet<String> = HashSet::new();
        let mut decisive = 0usize;
        for r in &results {
            ips.extend(&r.ips);
            for c in &r.cnames {
                cnames.insert(c.clone());
            }
            if r.any_answer || r.all_nxdomain {
                decisive += 1;
            }
        }

        let sig = if ips.is_empty() && cnames.is_empty() {
            None
        } else {
            Some(WildcardSignature {
                root: parent.to_string(),
                ips,
                cnames,
            })
        };
        (sig, decisive)
    }

    async fn validate_one(&self, mut asset: Asset) -> Asset {
        let host = match host_for_dns(&asset) {
            Some(h) => h,
            None => {
                asset.dns = DnsStatus::Unknown;
                return asset;
            }
        };

        // IP: trivially resolved.
        if asset.kind == AssetKind::Ip {
            asset.dns = DnsStatus::Resolved;
            if let Ok(ip) = host.parse::<IpAddr>() {
                if !asset.ips.contains(&ip) {
                    asset.ips.push(ip);
                }
            }
            return asset;
        }

        // Wildcard literal: no resolution attempted.
        if asset.kind == AssetKind::Wildcard {
            asset.dns = DnsStatus::Unknown;
            return asset;
        }

        // Zone short-circuits: skip DNS traffic entirely when we've already
        // determined the host's zone is broken or overwhelmingly failing.
        if self.config.wildcard_filter && self.ancestor_is_dead(&host).await {
            asset.dns = DnsStatus::Timeout;
            return asset;
        }
        if self.config.flaky_enabled() && self.parent_flagged_flaky(&host).await {
            asset.dns = DnsStatus::Timeout;
            return asset;
        }

        let checks = self.config.consistency_checks.max(1);
        let answers = self.resolve_with_consistency(&host, checks).await;

        if answers.any_answer {
            asset.ips = {
                let mut v: Vec<IpAddr> = answers.ips.iter().copied().collect();
                v.sort();
                v
            };
            if asset.cname.is_none() {
                let mut ordered: Vec<&String> = answers.cnames.iter().collect();
                ordered.sort();
                asset.cname = ordered.first().map(|s| s.to_string());
            }
        }

        // Record the result in the flaky tracker so bursts of timeouts under
        // the same parent short-circuit remaining siblings.
        if self.config.flaky_enabled() {
            self.record_flaky_sample(&host, &answers).await;
        }

        let sig = if self.config.wildcard_filter {
            self.union_signature_for(&host).await
        } else {
            None
        };
        asset.dns = final_status(
            &answers,
            sig.as_ref(),
            self.config.infer_wildcard_on_timeout,
        );
        asset
    }

    async fn ancestor_is_dead(&self, host: &str) -> bool {
        let sigs = self.signatures.read().await;
        let mut cur = host.to_string();
        while let Some(parent) = parent_of(&cur) {
            if matches!(sigs.get(&parent), Some(ParentState::Dead)) {
                return true;
            }
            cur = parent;
        }
        false
    }

    async fn parent_flagged_flaky(&self, host: &str) -> bool {
        let Some(parent) = parent_of(host) else { return false };
        let stats = self.flaky.lock().await;
        stats.get(&parent).map(|s| s.flagged).unwrap_or(false)
    }

    async fn record_flaky_sample(&self, host: &str, answers: &HostAnswers) {
        let Some(parent) = parent_of(host) else { return };
        let mut stats = self.flaky.lock().await;
        let entry = stats.entry(parent).or_default();
        apply_flaky_sample(
            entry,
            self.config.flaky_threshold,
            self.config.flaky_min_samples,
            answers.any_answer,
            answers.any_timeout,
        );
    }

    async fn resolve_with_consistency(&self, host: &str, checks: usize) -> HostAnswers {
        let n = checks.min(self.resolvers.len()).max(1);
        let queries = (0..n).map(|i| {
            let resolver = &self.resolvers[i];
            async move { resolve_host(resolver, host).await }
        });
        let results: Vec<HostAnswers> = join_all(queries).await;
        merge_answers(results)
    }

    async fn union_signature_for(&self, host: &str) -> Option<WildcardSignature> {
        let sigs = self.signatures.read().await;
        let mut ips: HashSet<IpAddr> = HashSet::new();
        let mut cnames: HashSet<String> = HashSet::new();
        let mut first_root: Option<String> = None;

        let mut cur = host.to_string();
        while let Some(parent) = parent_of(&cur) {
            if let Some(ParentState::Wildcard(sig)) = sigs.get(&parent) {
                ips.extend(&sig.ips);
                for c in &sig.cnames {
                    cnames.insert(c.clone());
                }
                if first_root.is_none() {
                    first_root = Some(sig.root.clone());
                }
            }
            cur = parent;
        }

        if ips.is_empty() && cnames.is_empty() {
            None
        } else {
            Some(WildcardSignature {
                root: first_root.unwrap_or_default(),
                ips,
                cnames,
            })
        }
    }

    /// Generic helper: collect a sorted, deduped list of zone labels from the
    /// signature map that satisfy the caller's predicate.
    async fn collect_zone_names<F>(&self, f: F) -> Vec<String>
    where
        F: Fn(&ParentState) -> Option<String>,
    {
        let sigs = self.signatures.read().await;
        let mut out: HashSet<String> = HashSet::new();
        for state in sigs.values() {
            if let Some(name) = f(state) {
                out.insert(name);
            }
        }
        let mut v: Vec<String> = out.into_iter().collect();
        v.sort();
        v
    }

    /// For the `Dead` case we can't synthesize the name from the value (since
    /// the state carries no root) — we need the map key. `_placeholder` is
    /// the sentinel returned by `collect_zone_names`; we use it only to
    /// trigger the "some zones exist" check, then re-scan to pick the keys.
    async fn attach_names(&self, _placeholder: Vec<String>, want: ParentState) -> Vec<String> {
        let sigs = self.signatures.read().await;
        let mut out: Vec<String> = sigs
            .iter()
            .filter(|(_, v)| std::mem::discriminant(*v) == std::mem::discriminant(&want))
            .map(|(k, _)| k.clone())
            .collect();
        out.sort();
        out
    }

    async fn collect_flaky_zones(&self) -> Vec<String> {
        let stats = self.flaky.lock().await;
        let mut v: Vec<String> = stats
            .iter()
            .filter(|(_, s)| s.flagged)
            .map(|(k, _)| k.clone())
            .collect();
        v.sort();
        v
    }
}

fn sig_to_state(sig: Option<WildcardSignature>) -> ParentState {
    match sig {
        Some(s) => ParentState::Wildcard(s),
        None => ParentState::Clean,
    }
}

/// Pure helper: update a parent's flaky stats with one host's outcome. Flag
/// is raised once enough samples accumulated and the timeout ratio is at
/// or above the threshold. Kept pure (no I/O, no locks) so the precedence
/// is trivially unit-testable.
fn apply_flaky_sample(
    entry: &mut FlakyStats,
    threshold: f32,
    min_samples: usize,
    any_answer: bool,
    any_timeout: bool,
) {
    entry.total += 1;
    // Count "hard timeouts" — no resolver got any answer AND at least one
    // timed out. Plain NXDOMAIN/error is not counted: a zone can legitimately
    // have many non-existent subdomains without being flaky.
    if !any_answer && any_timeout {
        entry.timeouts += 1;
    }
    if !entry.flagged
        && entry.total >= min_samples
        && min_samples > 0
        && (entry.timeouts as f32 / entry.total as f32) >= threshold
    {
        entry.flagged = true;
    }
}

// ---------------------------------------------------------------------------
// Classification helpers

/// Decide the final `DnsStatus` from a host's merged answers and the union
/// of its ancestor wildcard signatures (or `None` if no ancestor was a
/// wildcard). Pure function — keeps the precedence rules in one place and
/// testable without a live resolver.
///
/// Precedence:
/// - Empty answers:
///   - `any_timeout` + wildcard parent + `infer_wildcard_on_timeout` →
///     `WildcardIp` (inferred — a wildcard zone would have answered the
///     label if the query hadn't dropped, so a timeout there is
///     overwhelmingly a rate-limit artifact, not a genuine black hole).
///   - `all_nxdomain` → `Unresolved`
///   - `any_timeout` → `Timeout`
///   - `any_error` → `Error`
/// - Wildcard match → `WildcardCname` / `WildcardIp` / `MixedWildcard`.
///   Wins over `Shaky`: resolver disagreement on a wildcard zone is expected
///   behavior (cache divergence), not a red flag.
/// - Otherwise → `Shaky` (if resolvers disagreed) or `Resolved`.
fn final_status(
    answers: &HostAnswers,
    sig: Option<&WildcardSignature>,
    infer_wildcard_on_timeout: bool,
) -> DnsStatus {
    if !answers.any_answer {
        if infer_wildcard_on_timeout && answers.any_timeout && sig.is_some() {
            return DnsStatus::WildcardIp;
        }
        return if answers.all_nxdomain {
            DnsStatus::Unresolved
        } else if answers.any_timeout {
            DnsStatus::Timeout
        } else if answers.any_error {
            DnsStatus::Error
        } else {
            DnsStatus::Unresolved
        };
    }
    if let Some(sig) = sig {
        let verdict = classify_against_sig(answers, sig);
        if verdict.is_wildcard() {
            return verdict;
        }
    }
    if answers.disagreement {
        DnsStatus::Shaky
    } else {
        DnsStatus::Resolved
    }
}

fn classify_against_sig(answers: &HostAnswers, sig: &WildcardSignature) -> DnsStatus {
    // CNAME chain match is the strongest positive signal: if the host's CNAME
    // target is the same as a wildcard probe's, the host is served by the
    // wildcard regardless of which IPs the CDN happened to return this second.
    let cname_hit = answers.cnames.iter().any(|c| sig.cnames.contains(c));
    if cname_hit {
        return DnsStatus::WildcardCname;
    }

    if answers.ips.is_empty() {
        return DnsStatus::Resolved;
    }

    let host_hits = answers.ips.intersection(&sig.ips).count();
    if host_hits == 0 {
        return DnsStatus::Resolved;
    }
    if host_hits == answers.ips.len() {
        return DnsStatus::WildcardIp;
    }
    DnsStatus::MixedWildcard
}

fn merge_answers(results: Vec<HostAnswers>) -> HostAnswers {
    let mut merged = HostAnswers::default();
    let mut any_ans = false;
    let mut any_nx = false;
    let mut all_nx = true;
    let mut any_to = false;
    let mut any_err = false;

    for r in &results {
        merged.ips.extend(&r.ips);
        for c in &r.cnames {
            merged.cnames.insert(c.clone());
        }
        if r.any_answer {
            any_ans = true;
            all_nx = false;
        } else if r.all_nxdomain {
            any_nx = true;
        } else {
            all_nx = false;
        }
        if r.any_timeout {
            any_to = true;
        }
        if r.any_error {
            any_err = true;
        }
    }

    merged.any_answer = any_ans;
    merged.all_nxdomain = !any_ans && all_nx && any_nx;
    merged.any_timeout = any_to;
    merged.any_error = any_err;
    merged.disagreement = any_ans && any_nx;
    merged
}

/// Single-resolver A/AAAA lookup. The answer section contains both the CNAME
/// chain and the final A/AAAA records, so one query yields both signals.
async fn resolve_host(resolver: &TokioResolver, host: &str) -> HostAnswers {
    match resolver.lookup_ip(host).await {
        Ok(lookup) => {
            let mut ips: HashSet<IpAddr> = HashSet::new();
            let mut cnames: HashSet<String> = HashSet::new();
            for rec in lookup.as_lookup().answers() {
                match &rec.data {
                    RData::A(a) => {
                        ips.insert(IpAddr::V4((*a).into()));
                    }
                    RData::AAAA(aaaa) => {
                        ips.insert(IpAddr::V6((*aaaa).into()));
                    }
                    RData::CNAME(c) => {
                        cnames.insert(normalize_cname(&c.to_string()));
                    }
                    _ => {}
                }
            }
            HostAnswers {
                any_answer: !ips.is_empty() || !cnames.is_empty(),
                ips,
                cnames,
                all_nxdomain: false,
                any_timeout: false,
                any_error: false,
                disagreement: false,
            }
        }
        Err(err) => {
            let (nx, timeout, other) = classify_error(&err);
            HostAnswers {
                ips: HashSet::new(),
                cnames: HashSet::new(),
                any_answer: false,
                all_nxdomain: nx,
                any_timeout: timeout,
                any_error: other,
                disagreement: false,
            }
        }
    }
}

fn classify_error(err: &NetError) -> (bool, bool, bool) {
    match err {
        NetError::Timeout => (false, true, false),
        NetError::Dns(DnsError::NoRecordsFound(_)) => (true, false, false),
        _ => (false, false, true),
    }
}

// ---------------------------------------------------------------------------
// Plain helpers

fn collect_ancestors(assets: &[Asset]) -> HashSet<String> {
    let mut set = HashSet::new();
    for a in assets {
        if !matches!(a.kind, AssetKind::Apex | AssetKind::Subdomain) {
            continue;
        }
        let Some(h) = host_for_dns(a) else { continue };
        let mut cur = h;
        while let Some(p) = parent_of(&cur) {
            set.insert(p.clone());
            cur = p;
        }
    }
    set
}

fn host_for_dns(asset: &Asset) -> Option<String> {
    if asset.kind == AssetKind::Garbage || asset.kind == AssetKind::Wildcard {
        return None;
    }
    let host = if asset.canonical.starts_with('[') {
        asset
            .canonical
            .rsplit_once("]:")
            .map(|(h, _)| h.trim_start_matches('[').to_string())
            .unwrap_or_else(|| asset.canonical.clone())
    } else if let Some((h, _)) = asset
        .canonical
        .rsplit_once(':')
        .filter(|(h, _)| !h.contains(':'))
    {
        h.to_string()
    } else {
        asset.canonical.clone()
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn parent_of(host: &str) -> Option<String> {
    let host = host.trim_matches('.');
    if host.matches('.').count() < 2 {
        // TLD or registrable apex — not useful for wildcard probing.
        return None;
    }
    host.split_once('.').map(|(_, rest)| rest.to_string())
}

fn random_label(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

fn normalize_cname(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_basic() {
        assert_eq!(parent_of("a.b.example.com").as_deref(), Some("b.example.com"));
        assert_eq!(parent_of("b.example.com").as_deref(), Some("example.com"));
        assert_eq!(parent_of("example.com"), None);
        assert_eq!(parent_of("com"), None);
    }

    #[test]
    fn random_label_shape() {
        let s = random_label(16);
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn cname_match_is_decisive() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: HashSet::new(),
            cnames: HashSet::from(["cdn.example.net".into()]),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: HashSet::from(["cdn.example.net".into()]),
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(classify_against_sig(&answers, &sig), DnsStatus::WildcardCname);
    }

    #[test]
    fn full_ip_overlap_is_wildcard_ip() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: HashSet::from(["1.2.3.4".parse().unwrap(), "1.2.3.5".parse().unwrap()]),
            cnames: HashSet::new(),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: HashSet::new(),
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(classify_against_sig(&answers, &sig), DnsStatus::WildcardIp);
    }

    #[test]
    fn partial_overlap_is_mixed() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: HashSet::new(),
        };
        let answers = HostAnswers {
            ips: HashSet::from([
                "1.2.3.4".parse().unwrap(),
                "9.9.9.9".parse().unwrap(),
            ]),
            cnames: HashSet::new(),
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(classify_against_sig(&answers, &sig), DnsStatus::MixedWildcard);
    }

    #[test]
    fn disjoint_ip_is_resolved() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: HashSet::new(),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["8.8.8.8".parse().unwrap()]),
            cnames: HashSet::new(),
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(classify_against_sig(&answers, &sig), DnsStatus::Resolved);
    }

    #[test]
    fn merge_marks_shaky_on_disagreement() {
        let a = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: HashSet::new(),
            any_answer: true,
            ..Default::default()
        };
        let b = HostAnswers {
            ips: HashSet::new(),
            cnames: HashSet::new(),
            any_answer: false,
            all_nxdomain: true,
            ..Default::default()
        };
        let merged = merge_answers(vec![a, b]);
        assert!(merged.disagreement);
        assert!(merged.any_answer);
    }

    #[test]
    fn merge_all_nxdomain_is_unresolved() {
        let a = HostAnswers { all_nxdomain: true, ..Default::default() };
        let b = HostAnswers { all_nxdomain: true, ..Default::default() };
        let merged = merge_answers(vec![a, b]);
        assert!(!merged.any_answer);
        assert!(merged.all_nxdomain);
        assert!(!merged.disagreement);
    }

    #[test]
    fn wildcard_wins_over_shaky() {
        // Regression: a host whose IPs are entirely inside the parent wildcard
        // signature must be reported as WildcardIp even when the resolvers
        // disagreed. Previously `shaky` swallowed the wildcard verdict.
        let sig = WildcardSignature {
            root: "cheaptickets.nl".into(),
            ips: HashSet::from(["104.18.16.5".parse().unwrap(), "104.18.17.5".parse().unwrap()]),
            cnames: HashSet::new(),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["104.18.16.5".parse().unwrap(), "104.18.17.5".parse().unwrap()]),
            cnames: HashSet::new(),
            any_answer: true,
            disagreement: true,
            ..Default::default()
        };
        assert_eq!(
            final_status(&answers, Some(&sig), /*infer*/ true),
            DnsStatus::WildcardIp
        );
    }

    #[test]
    fn wildcard_cname_wins_over_shaky() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: HashSet::new(),
            cnames: HashSet::from(["cdn.example.net".into()]),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: HashSet::from(["cdn.example.net".into()]),
            any_answer: true,
            disagreement: true,
            ..Default::default()
        };
        assert_eq!(
            final_status(&answers, Some(&sig), /*infer*/ true),
            DnsStatus::WildcardCname
        );
    }

    #[test]
    fn shaky_survives_when_no_wildcard_match() {
        // No signature (parent has no wildcard) + resolver disagreement → Shaky.
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: HashSet::new(),
            any_answer: true,
            disagreement: true,
            ..Default::default()
        };
        assert_eq!(final_status(&answers, None, /*infer*/ true), DnsStatus::Shaky);
    }

    #[test]
    fn clean_resolve_is_resolved() {
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: HashSet::new(),
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(final_status(&answers, None, /*infer*/ true), DnsStatus::Resolved);
    }

    #[test]
    fn timeout_when_no_answers_and_some_timed_out() {
        let answers = HostAnswers {
            any_answer: false,
            any_timeout: true,
            ..Default::default()
        };
        assert_eq!(final_status(&answers, None, /*infer*/ true), DnsStatus::Timeout);
    }

    #[test]
    fn unresolved_beats_timeout_when_all_nxdomain() {
        let answers = HostAnswers {
            any_answer: false,
            all_nxdomain: true,
            any_timeout: true,
            ..Default::default()
        };
        assert_eq!(final_status(&answers, None, /*infer*/ true), DnsStatus::Unresolved);
    }

    #[test]
    fn timeout_under_wildcard_parent_is_inferred_wildcard_ip() {
        // Regression: a host that times out but whose parent is a wildcard
        // should be reported as WildcardIp (under the inference flag).
        // Rationale: wildcard zones answer every label; a timeout there is
        // a rate-limit drop, not a real black hole.
        let sig = WildcardSignature {
            root: "cheaptickets.nl".into(),
            ips: HashSet::from(["104.18.16.5".parse().unwrap()]),
            cnames: HashSet::new(),
        };
        let answers = HostAnswers {
            any_answer: false,
            any_timeout: true,
            ..Default::default()
        };
        assert_eq!(
            final_status(&answers, Some(&sig), /*infer*/ true),
            DnsStatus::WildcardIp
        );
    }

    #[test]
    fn inference_disabled_keeps_timeout() {
        // Same scenario as above, but with the inference flag OFF → stays
        // Timeout for strict observed-only semantics.
        let sig = WildcardSignature {
            root: "cheaptickets.nl".into(),
            ips: HashSet::from(["104.18.16.5".parse().unwrap()]),
            cnames: HashSet::new(),
        };
        let answers = HostAnswers {
            any_answer: false,
            any_timeout: true,
            ..Default::default()
        };
        assert_eq!(
            final_status(&answers, Some(&sig), /*infer*/ false),
            DnsStatus::Timeout
        );
    }

    #[test]
    fn inference_does_not_rescue_nxdomain() {
        // A wildcard zone should answer every label; if we got NXDOMAIN
        // from all resolvers, something is weird — don't paper over it.
        let sig = WildcardSignature {
            root: "cheaptickets.nl".into(),
            ips: HashSet::from(["104.18.16.5".parse().unwrap()]),
            cnames: HashSet::new(),
        };
        let answers = HostAnswers {
            any_answer: false,
            all_nxdomain: true,
            ..Default::default()
        };
        assert_eq!(
            final_status(&answers, Some(&sig), /*infer*/ true),
            DnsStatus::Unresolved
        );
    }

    // ---- flaky tracker ----

    fn flak() -> FlakyStats {
        FlakyStats::default()
    }

    #[test]
    fn flaky_flips_after_threshold_and_min_samples() {
        let mut s = flak();
        // 9 timeouts — below min_samples (10), must not flag yet.
        for _ in 0..9 {
            apply_flaky_sample(&mut s, 0.8, 10, false, true);
        }
        assert!(!s.flagged, "below min samples should not flag");
        assert_eq!(s.timeouts, 9);
        // 10th timeout → ratio 10/10 = 1.0 ≥ 0.8 → flag.
        apply_flaky_sample(&mut s, 0.8, 10, false, true);
        assert!(s.flagged);
    }

    #[test]
    fn flaky_does_not_flip_when_mostly_successful() {
        let mut s = flak();
        // 9 successes + 1 timeout = 10% timeout ratio, below 0.8.
        for _ in 0..9 {
            apply_flaky_sample(&mut s, 0.8, 10, true, false);
        }
        apply_flaky_sample(&mut s, 0.8, 10, false, true);
        assert!(!s.flagged);
        assert_eq!(s.timeouts, 1);
        assert_eq!(s.total, 10);
    }

    #[test]
    fn flaky_ignores_nxdomain_only_outcomes() {
        // A zone with many non-existent subs (NXDOMAIN, no timeout) must not
        // be flagged flaky — it's working, just sparse.
        let mut s = flak();
        for _ in 0..20 {
            // any_answer=false, any_timeout=false → NXDOMAIN-only, not counted.
            apply_flaky_sample(&mut s, 0.8, 10, false, false);
        }
        assert!(!s.flagged);
        assert_eq!(s.timeouts, 0);
    }

    #[test]
    fn flaky_min_samples_zero_never_flags() {
        let mut s = flak();
        for _ in 0..50 {
            apply_flaky_sample(&mut s, 0.8, 0, false, true);
        }
        assert!(!s.flagged);
    }

    #[test]
    fn sig_to_state_maps_correctly() {
        assert!(matches!(sig_to_state(None), ParentState::Clean));
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: HashSet::new(),
        };
        assert!(matches!(sig_to_state(Some(sig)), ParentState::Wildcard(_)));
    }
}
