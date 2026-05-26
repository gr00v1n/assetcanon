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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use serde::Serialize;
use tokio::sync::{Mutex, RwLock};

use crate::model::{Asset, AssetKind, DnsStatus, WildcardReason};

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
    /// Adaptive resolver routing: after `resolver_min_samples` queries
    /// against a resolver, if its observed timeout rate exceeds
    /// `resolver_unhealthy_threshold` the resolver is dropped from rotation
    /// for the rest of the run. Sticky — once flagged, stays flagged. If
    /// every resolver gets flagged the validator falls back to using all
    /// resolvers (we'd rather emit shaky results than black-hole the run).
    /// Set the threshold to >= 1.0 to disable the gate.
    pub resolver_unhealthy_threshold: f32,
    pub resolver_min_samples: usize,
    /// Background NXDOMAIN-hijack detection: every
    /// `hijack_probe_interval` seconds the validator fires a
    /// random-`.invalid` probe at each resolver and flags as unhealthy any
    /// that returns an answer (since `.invalid` must NXDOMAIN per RFC
    /// 6761). Set `hijack_probe_interval` to 0 to disable.
    pub hijack_probe_interval_secs: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            resolvers: default_resolvers(),
            concurrency: 50,
            timeout: Duration::from_secs(5),
            retries: 2,
            wildcard_tests: 6,
            wildcard_filter: true,
            consistency_checks: 2,
            probe_concurrency: 25,
            flaky_threshold: 0.8,
            flaky_min_samples: 10,
            infer_wildcard_on_timeout: true,
            resolver_unhealthy_threshold: 0.5,
            resolver_min_samples: 20,
            hijack_probe_interval_secs: 30,
        }
    }
}

impl DnsConfig {
    fn effective_probe_concurrency(&self) -> usize {
        if self.probe_concurrency == 0 {
            // Half of host-level concurrency, floored at 16 so small configs
            // still get useful parallelism without hammering public resolvers.
            (self.concurrency / 2).max(16)
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
    // Per-resolver runtime health state, parallel to `resolvers` by index.
    // Used by `healthy_resolver_indices` to skip resolvers that exceed the
    // configured timeout-rate threshold during a run. Atomic counters so
    // host-validation futures can update them lock-free.
    resolver_health: Vec<ResolverHealthCounters>,
    config: DnsConfig,
    // Parent domain → ParentState. Populated in one batch before host
    // validation; read-only afterwards.
    signatures: Arc<RwLock<HashMap<String, ParentState>>>,
    // Runtime flaky-zone tracker: accumulates (timeouts, total, flagged) per
    // immediate parent during the validation phase so bursts of timeouts
    // short-circuit remaining hosts in the same zone.
    flaky: Arc<Mutex<HashMap<String, FlakyStats>>>,
    // Low-cardinality runtime counters used for production observability.
    // Detailed per-resolver payloads are intentionally not retained here so
    // large DNS runs don't multiply memory by `hosts × resolvers`.
    counters: Arc<DnsRuntimeCounters>,
}

/// Per-resolver health tracker. A resolver crossing
/// `DnsConfig::resolver_unhealthy_threshold` after at least
/// `resolver_min_samples` queries gets `flagged` to true, and subsequent
/// resolver selections skip it. Sticky for the rest of the run — once
/// flagged stays flagged, to avoid oscillation on borderline resolvers.
///
/// Named with the `Counters` suffix to avoid collision with the public
/// `ResolverHealth` report produced by `--check-resolvers`.
#[derive(Debug, Default)]
struct ResolverHealthCounters {
    total: AtomicUsize,
    timeouts: AtomicUsize,
    flagged: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Default)]
struct DnsRuntimeCounters {
    probe_queries: AtomicUsize,
    host_queries: AtomicUsize,
    answer_vs_nxdomain: AtomicUsize,
    answer_vs_timeout: AtomicUsize,
    answer_vs_error: AtomicUsize,
    distinct_ip_sets: AtomicUsize,
    distinct_cname_sets: AtomicUsize,
}

impl DnsRuntimeCounters {
    fn reset(&self) {
        self.probe_queries.store(0, Ordering::Relaxed);
        self.host_queries.store(0, Ordering::Relaxed);
        self.answer_vs_nxdomain.store(0, Ordering::Relaxed);
        self.answer_vs_timeout.store(0, Ordering::Relaxed);
        self.answer_vs_error.store(0, Ordering::Relaxed);
        self.distinct_ip_sets.store(0, Ordering::Relaxed);
        self.distinct_cname_sets.store(0, Ordering::Relaxed);
    }
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

/// A parent's wildcard fingerprint. IP/CNAME sets are `Arc<HashSet>` so the
/// common single-wildcard-ancestor case in `scan_ancestors` can hand the
/// per-host caller a cheap `Arc::clone` instead of copying every IP/string.
#[derive(Debug, Clone, Default)]
struct WildcardSignature {
    root: String,
    ips: Arc<HashSet<IpAddr>>,
    cnames: Arc<HashSet<String>>,
}

#[derive(Debug, Clone, Default)]
struct HostAnswers {
    ips: HashSet<IpAddr>,
    /// CNAME chain in DNS-response order (first alias at index 0, terminal
    /// target at the tail). Kept as `Vec` rather than `HashSet` because chain
    /// order is load-bearing for downstream consumers: dangling-CNAME /
    /// subdomain-takeover detection needs the terminal target, and CDN
    /// fingerprinting benefits from the intermediate hops.
    cnames: Vec<String>,
    any_answer: bool,
    all_nxdomain: bool,
    any_timeout: bool,
    any_error: bool,
    /// Resolvers disagreed: at least one returned answers, at least one NXDOMAIN.
    disagreement: bool,
    answer_count: usize,
    nxdomain_count: usize,
    timeout_count: usize,
    error_count: usize,
    distinct_ip_sets: usize,
    distinct_cname_sets: usize,
}

#[derive(Debug, Clone, Default)]
struct FlakyStats {
    timeouts: usize,
    total: usize,
    flagged: bool,
}

/// Result of a single parent-chain walk over the signature cache: the nearest
/// Dead ancestor (short-circuits DNS) plus the unioned Wildcard signature
/// for post-resolution classification.
#[derive(Debug, Clone, Default)]
struct AncestorScan {
    dead_zone: Option<String>,
    signature: Option<WildcardSignature>,
}

pub struct DnsReport {
    pub assets: Vec<Asset>,
    pub wildcard_roots: Vec<String>,
    pub dead_zones: Vec<String>,
    pub flaky_zones: Vec<String>,
    pub stats: DnsStats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsStats {
    pub input_assets: usize,
    pub dns_eligible_assets: usize,
    pub elapsed_ms: u128,
    pub probe_queries: usize,
    pub host_queries: usize,
    pub signature_parents: SignatureParentStats,
    pub statuses: DnsStatusStats,
    pub wildcard_decisions: WildcardDecisionStats,
    pub resolver_disagreement: ResolverDisagreementStats,
    pub short_circuits: DnsShortCircuitStats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SignatureParentStats {
    pub total: usize,
    pub wildcard: usize,
    pub clean: usize,
    pub dead: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsStatusStats {
    pub unknown: usize,
    pub resolved: usize,
    pub unresolved: usize,
    pub wildcard_ip: usize,
    pub wildcard_cname: usize,
    pub mixed_wildcard: usize,
    pub shaky: usize,
    pub timeout: usize,
    pub error: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WildcardDecisionStats {
    pub ip_overlap: usize,
    pub cname_match: usize,
    pub timeout_inferred: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResolverDisagreementStats {
    pub answer_vs_nxdomain: usize,
    pub answer_vs_timeout: usize,
    pub answer_vs_error: usize,
    pub distinct_ip_sets: usize,
    pub distinct_cname_sets: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsShortCircuitStats {
    pub dead_zone: usize,
    pub flaky_zone: usize,
}

#[derive(Debug, Clone)]
pub struct ResolverCheckConfig {
    pub positive_domains: Vec<String>,
    pub rounds: usize,
    pub concurrency: usize,
}

impl Default for ResolverCheckConfig {
    fn default() -> Self {
        Self {
            positive_domains: vec!["example.com".into(), "iana.org".into()],
            rounds: 5,
            concurrency: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverHealthStatus {
    Ok,
    Warn,
    Bad,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverLatencyStats {
    pub p50_ms: Option<u128>,
    pub max_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_ms: Option<u128>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResolverCheckSummary {
    pub passed: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResolverHealthChecks {
    pub positive: ResolverCheckSummary,
    pub nxdomain: ResolverCheckSummary,
    pub wildcard_pollution: ResolverCheckSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverHealth {
    pub resolver: SocketAddr,
    pub status: ResolverHealthStatus,
    pub score: u8,
    pub latency: ResolverLatencyStats,
    pub timeout_ratio: f32,
    pub checks: ResolverHealthChecks,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolverCheckKind {
    Positive,
    NxdomainInvalid,
    NxdomainRandom,
    WildcardPollution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolverCheckOutcome {
    Answer,
    Nxdomain,
    Timeout,
    Error,
}

#[derive(Debug, Clone)]
struct ResolverCheckSample {
    kind: ResolverCheckKind,
    outcome: ResolverCheckOutcome,
    latency_ms: Option<u128>,
}

#[derive(Debug, Clone)]
struct RawResolverHealth {
    resolver: SocketAddr,
    samples: Vec<ResolverCheckSample>,
    setup_error: Option<String>,
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
            resolvers.push(build_resolver(*addr, &config)?);
        }
        let resolver_health = (0..resolvers.len())
            .map(|_| ResolverHealthCounters::default())
            .collect();

        Ok(Self {
            resolvers,
            resolver_health,
            config,
            signatures: Arc::new(RwLock::new(HashMap::new())),
            flaky: Arc::new(Mutex::new(HashMap::new())),
            counters: Arc::new(DnsRuntimeCounters::default()),
        })
    }

    /// Indices of resolvers currently considered healthy. If every resolver
    /// has been flagged (degenerate pool), falls back to all resolvers — a
    /// black-holed run is worse than emitting `shaky` results.
    fn healthy_resolver_indices(&self) -> Vec<usize> {
        let healthy: Vec<usize> = (0..self.resolvers.len())
            .filter(|&i| !self.resolver_health[i].flagged.load(Ordering::Relaxed))
            .collect();
        if healthy.is_empty() {
            (0..self.resolvers.len()).collect()
        } else {
            healthy
        }
    }

    /// Update per-resolver health counters after a query result. Delegates
    /// the decision logic to `apply_resolver_health_sample` so it can be
    /// unit-tested without a live validator.
    fn record_resolver_outcome(&self, idx: usize, answers: &HostAnswers) {
        apply_resolver_health_sample(
            &self.resolver_health[idx],
            self.config.resolver_unhealthy_threshold,
            self.config.resolver_min_samples,
            answers.any_answer,
            answers.any_timeout,
            answers.all_nxdomain,
        );
    }

    /// Flag a resolver as unhealthy unconditionally — used by the hijack
    /// detector when a `.invalid` probe returns an answer.
    fn flag_resolver_unhealthy(&self, idx: usize) {
        if let Some(h) = self.resolver_health.get(idx) {
            h.flagged.store(true, Ordering::Relaxed);
        }
    }

    /// Validate all host-like assets. Non-host assets pass through unchanged.
    ///
    /// Receiver is `&Arc<Self>` so the hijack-probe background task can
    /// `Arc::clone(self)` and outlive any specific stack frame. Callers
    /// wrap once with `Arc::new(DnsValidator::new(...))` and the call
    /// syntax stays the same.
    pub async fn validate(self: &Arc<Self>, assets: Vec<Asset>) -> DnsReport {
        self.counters.reset();
        let started_at = Instant::now();
        let input_assets = assets.len();

        // Spawn the NXDOMAIN-hijack background probe for the lifetime of
        // this validation. Aborted at the end. Skipped when disabled by
        // config (interval == 0) or when there's only one resolver (no
        // useful comparison anyway).
        let hijack_handle = if self.config.hijack_probe_interval_secs > 0 {
            let validator = Arc::clone(self);
            Some(tokio::spawn(async move {
                validator.run_hijack_probe_loop().await;
            }))
        } else {
            None
        };

        if self.config.wildcard_filter {
            let ancestors = collect_ancestors(&assets);
            self.precompute_signatures(ancestors).await;
        }

        let concurrency = self.config.concurrency.max(1);
        let validator = Arc::clone(self);
        let futures_iter = assets.into_iter().map(move |asset| {
            let v = Arc::clone(&validator);
            async move { v.validate_one(asset).await }
        });
        let assets: Vec<Asset> = stream::iter(futures_iter)
            .buffer_unordered(concurrency)
            .collect()
            .await;

        if let Some(handle) = hijack_handle {
            handle.abort();
            let _ = handle.await;
        }

        let wildcard_roots = self
            .collect_zone_names(|s| match s {
                ParentState::Wildcard(sig) => Some(format!("*.{}", sig.root)),
                _ => None,
            })
            .await;
        let dead_zones = self
            .collect_zone_names(|s| match s {
                ParentState::Dead => Some(String::new()),
                _ => None,
            })
            .await;
        let dead_zones = self.attach_names(dead_zones, ParentState::Dead).await;
        let flaky_zones = self.collect_flaky_zones().await;
        let stats = self
            .build_stats(&assets, input_assets, started_at.elapsed().as_millis())
            .await;

        DnsReport {
            assets,
            wildcard_roots,
            dead_zones,
            flaky_zones,
            stats,
        }
    }

    /// Periodic `.invalid` probe loop. Every `hijack_probe_interval_secs`
    /// we fire a fresh random `<label>.invalid` query at each resolver. Per
    /// RFC 6761 these MUST be answered NXDOMAIN by any well-behaved
    /// resolver — anything else (rewrite to a captive-portal IP, sinkhole,
    /// etc.) means the resolver is polluting answers, and we flag it as
    /// unhealthy for the rest of the run.
    ///
    /// Runs until the task is aborted by `validate()`. First sleep is the
    /// configured interval so we don't compete with the initial precompute
    /// burst — gives the resolver pool a moment to warm up.
    async fn run_hijack_probe_loop(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.hijack_probe_interval_secs);
        loop {
            tokio::time::sleep(interval).await;
            for idx in 0..self.resolvers.len() {
                if self.resolver_health[idx].flagged.load(Ordering::Relaxed) {
                    continue;
                }
                let label = random_label(16);
                let probe = format!("{label}.invalid");
                let outcome = tokio::time::timeout(
                    Duration::from_secs(5),
                    resolve_host(&self.resolvers[idx], &probe),
                )
                .await;
                if is_hijacked_outcome(&outcome) {
                    self.flag_resolver_unhealthy(idx);
                }
            }
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
            (Some(a), Some(b)) => {
                // Union the two rounds' sets. Arc::try_unwrap when possible to
                // avoid a copy; we hold the only references here, so the
                // unwrap should typically succeed.
                let mut ips = Arc::try_unwrap(a.ips).unwrap_or_else(|arc| (*arc).clone());
                ips.extend(b.ips.iter().copied());
                let mut cnames = Arc::try_unwrap(a.cnames).unwrap_or_else(|arc| (*arc).clone());
                for c in b.cnames.iter() {
                    cnames.insert(c.clone());
                }
                Some(WildcardSignature {
                    root: a.root,
                    ips: Arc::new(ips),
                    cnames: Arc::new(cnames),
                })
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
        // Restrict probes to currently-healthy resolvers. If every resolver
        // is flagged we get the full pool back (better to probe noisily than
        // not at all).
        let healthy = self.healthy_resolver_indices();
        let jobs: Vec<_> = (0..tests)
            .map(|i| {
                let sub = format!("{}.{}", random_label(16), parent);
                let resolver_idx = healthy[i % healthy.len()];
                let resolver = &self.resolvers[resolver_idx];
                async move {
                    let answers = resolve_host(resolver, &sub).await;
                    (resolver_idx, answers)
                }
            })
            .collect();
        let results: Vec<(usize, HostAnswers)> = join_all(jobs).await;
        self.counters
            .probe_queries
            .fetch_add(results.len(), Ordering::Relaxed);
        for (idx, ans) in &results {
            self.record_resolver_outcome(*idx, ans);
        }

        let mut ips: HashSet<IpAddr> = HashSet::new();
        let mut cnames: HashSet<String> = HashSet::new();
        let mut decisive = 0usize;
        for (_, r) in &results {
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
                ips: Arc::new(ips),
                cnames: Arc::new(cnames),
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

        // IP: trivially resolved with full confidence (the literal is the answer).
        if asset.kind == AssetKind::Ip {
            asset.dns = DnsStatus::Resolved;
            asset.confidence = Some(1.0);
            if let Ok(ip) = host.parse::<IpAddr>() {
                if !asset.ips.contains(&ip) {
                    asset.ips.push(ip);
                }
                if let Some(provider) = crate::cdn::lookup(ip) {
                    asset.cdn = Some(provider.to_string());
                }
            }
            return asset;
        }

        // Wildcard literal: no resolution attempted, no confidence to report.
        if asset.kind == AssetKind::Wildcard {
            asset.dns = DnsStatus::Unknown;
            return asset;
        }

        // Single read-lock acquisition + single parent walk over the signature
        // cache, combining the dead-zone short-circuit with the wildcard-signature
        // union used in post-resolution classification.
        let scan = if self.config.wildcard_filter {
            self.scan_ancestors(&host).await
        } else {
            AncestorScan::default()
        };
        if let Some(dead_zone) = scan.dead_zone {
            asset.dns = DnsStatus::Timeout;
            asset.dead_zone = Some(dead_zone);
            // Short-circuited without a query — the verdict is "the zone is
            // broken," which is decent confidence that this host won't resolve.
            asset.confidence = Some(0.5);
            return asset;
        }

        // Compute the immediate parent once and reuse it for both the
        // pre-resolve flaky check and the post-resolve sample-record.
        let flaky_parent: Option<String> = if self.config.flaky_enabled() {
            parent_of(&host).map(str::to_string)
        } else {
            None
        };
        if let Some(ref parent) = flaky_parent {
            if self.is_flaky_parent_flagged(parent).await {
                asset.dns = DnsStatus::Timeout;
                asset.flaky_zone = Some(parent.clone());
                // Flaky-zone short-circuits are weaker evidence than dead
                // zones — the zone might just be rate-limiting us.
                asset.confidence = Some(0.3);
                return asset;
            }
        }

        let checks = self.config.consistency_checks.max(1);
        let answers = self.resolve_with_consistency(&host, checks).await;
        asset.resolver_disagreement = answers.disagreement;

        if answers.any_answer {
            asset.ips = {
                let mut v: Vec<IpAddr> = answers.ips.iter().copied().collect();
                v.sort();
                v
            };
            if asset.cnames.is_empty() {
                asset.cnames = answers.cnames.clone();
            }
        }

        // Record the result in the flaky tracker so bursts of timeouts under
        // the same parent short-circuit remaining siblings.
        if let Some(ref parent) = flaky_parent {
            self.record_flaky_sample(parent, &answers).await;
        }

        let mut decision = final_decision(
            &answers,
            scan.signature.as_ref(),
            self.config.infer_wildcard_on_timeout,
        );

        // CDN tag (IP-range then CNAME-suffix) + IP-overlap downgrade. Done
        // as pure helpers so they can be unit-tested without a live resolver.
        let cdn_tag = detect_cdn(&answers);
        apply_cdn_downgrade(&mut decision, cdn_tag);
        if let Some(provider) = cdn_tag {
            asset.cdn = Some(provider.to_string());
        }
        asset.confidence = Some(compute_confidence(&decision, &answers, cdn_tag.is_some()));

        asset.dns = decision.status;
        asset.wildcard_root = decision.wildcard_root;
        asset.wildcard_reason = decision.wildcard_reason;
        asset.wildcard_ip_overlap_count = decision.wildcard_ip_overlap_count;
        asset.wildcard_cname_overlap_count = decision.wildcard_cname_overlap_count;
        asset.wildcard_host_ip_count = decision.wildcard_host_ip_count;
        asset.wildcard_signature_ip_count = decision.wildcard_signature_ip_count;
        asset.wildcard_signature_cname_count = decision.wildcard_signature_cname_count;
        asset
    }

    /// Single-pass scan of the signature cache from `host` up to the apex.
    /// Combines what used to be `dead_ancestor_for` + `union_signature_for`
    /// into one read-lock acquisition + one parent-chain walk. Returns the
    /// nearest Dead ancestor (if any — caller will short-circuit) and the
    /// union of any Wildcard signatures encountered above the host.
    ///
    /// Common case (single wildcard ancestor): returns Arc clones of the
    /// cached signature sets — no per-host HashSet copy. Rare case (multiple
    /// wildcard ancestors): allocates a fresh unioned signature.
    async fn scan_ancestors(&self, host: &str) -> AncestorScan {
        let sigs = self.signatures.read().await;
        let mut hits: Vec<&WildcardSignature> = Vec::new();

        let mut cur = host;
        while let Some(parent) = parent_of(cur) {
            match sigs.get(parent) {
                Some(ParentState::Dead) => {
                    return AncestorScan {
                        dead_zone: Some(parent.to_string()),
                        signature: None,
                    };
                }
                Some(ParentState::Wildcard(sig)) => hits.push(sig),
                _ => {}
            }
            cur = parent;
        }

        let signature = match hits.as_slice() {
            [] => None,
            [only] => Some((*only).clone()),
            many => {
                let mut ips: HashSet<IpAddr> = HashSet::new();
                let mut cnames: HashSet<String> = HashSet::new();
                for sig in many {
                    ips.extend(sig.ips.iter().copied());
                    for c in sig.cnames.iter() {
                        cnames.insert(c.clone());
                    }
                }
                Some(WildcardSignature {
                    root: many[0].root.clone(),
                    ips: Arc::new(ips),
                    cnames: Arc::new(cnames),
                })
            }
        };
        AncestorScan {
            dead_zone: None,
            signature,
        }
    }

    async fn is_flaky_parent_flagged(&self, parent: &str) -> bool {
        let stats = self.flaky.lock().await;
        stats.get(parent).map(|s| s.flagged).unwrap_or(false)
    }

    async fn record_flaky_sample(&self, parent: &str, answers: &HostAnswers) {
        let mut stats = self.flaky.lock().await;
        let entry = stats.entry(parent.to_string()).or_default();
        apply_flaky_sample(
            entry,
            self.config.flaky_threshold,
            self.config.flaky_min_samples,
            answers.any_answer,
            answers.any_timeout,
        );
    }

    async fn resolve_with_consistency(&self, host: &str, checks: usize) -> HostAnswers {
        // Pick the first `n` healthy resolvers; preserves the "distinct
        // resolvers per consistency-check round" property the old code
        // relied on (indexed selection). Falls back to the full pool when
        // every resolver is flagged.
        let healthy = self.healthy_resolver_indices();
        let n = checks.min(healthy.len()).max(1);
        let queries = healthy.iter().take(n).copied().map(|idx| {
            let resolver = &self.resolvers[idx];
            async move {
                let answers = resolve_host(resolver, host).await;
                (idx, answers)
            }
        });
        let results: Vec<(usize, HostAnswers)> = join_all(queries).await;
        self.counters
            .host_queries
            .fetch_add(results.len(), Ordering::Relaxed);
        for (idx, ans) in &results {
            self.record_resolver_outcome(*idx, ans);
        }
        let answers = merge_answers(results.into_iter().map(|(_, a)| a).collect());
        self.record_resolver_disagreement_stats(&answers);
        answers
    }

    fn record_resolver_disagreement_stats(&self, answers: &HostAnswers) {
        if answers.answer_count > 0 && answers.nxdomain_count > 0 {
            self.counters
                .answer_vs_nxdomain
                .fetch_add(1, Ordering::Relaxed);
        }
        if answers.answer_count > 0 && answers.timeout_count > 0 {
            self.counters
                .answer_vs_timeout
                .fetch_add(1, Ordering::Relaxed);
        }
        if answers.answer_count > 0 && answers.error_count > 0 {
            self.counters
                .answer_vs_error
                .fetch_add(1, Ordering::Relaxed);
        }
        if answers.distinct_ip_sets > 1 {
            self.counters
                .distinct_ip_sets
                .fetch_add(1, Ordering::Relaxed);
        }
        if answers.distinct_cname_sets > 1 {
            self.counters
                .distinct_cname_sets
                .fetch_add(1, Ordering::Relaxed);
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

    async fn build_stats(
        &self,
        assets: &[Asset],
        input_assets: usize,
        elapsed_ms: u128,
    ) -> DnsStats {
        let mut stats = DnsStats {
            input_assets,
            elapsed_ms,
            probe_queries: self.counters.probe_queries.load(Ordering::Relaxed),
            host_queries: self.counters.host_queries.load(Ordering::Relaxed),
            resolver_disagreement: ResolverDisagreementStats {
                answer_vs_nxdomain: self.counters.answer_vs_nxdomain.load(Ordering::Relaxed),
                answer_vs_timeout: self.counters.answer_vs_timeout.load(Ordering::Relaxed),
                answer_vs_error: self.counters.answer_vs_error.load(Ordering::Relaxed),
                distinct_ip_sets: self.counters.distinct_ip_sets.load(Ordering::Relaxed),
                distinct_cname_sets: self.counters.distinct_cname_sets.load(Ordering::Relaxed),
            },
            ..DnsStats::default()
        };

        for asset in assets {
            if asset.is_host() {
                stats.dns_eligible_assets += 1;
            }
            add_status_stat(&mut stats.statuses, asset.dns);
            if let Some(reason) = asset.wildcard_reason {
                add_wildcard_reason_stat(&mut stats.wildcard_decisions, reason);
            }
            if asset.dead_zone.is_some() {
                stats.short_circuits.dead_zone += 1;
            }
            if asset.flaky_zone.is_some() {
                stats.short_circuits.flaky_zone += 1;
            }
        }

        let sigs = self.signatures.read().await;
        stats.signature_parents.total = sigs.len();
        for state in sigs.values() {
            match state {
                ParentState::Wildcard(_) => stats.signature_parents.wildcard += 1,
                ParentState::Clean => stats.signature_parents.clean += 1,
                ParentState::Dead => stats.signature_parents.dead += 1,
            }
        }

        stats
    }
}

fn add_status_stat(stats: &mut DnsStatusStats, status: DnsStatus) {
    match status {
        DnsStatus::Unknown => stats.unknown += 1,
        DnsStatus::Resolved => stats.resolved += 1,
        DnsStatus::Unresolved => stats.unresolved += 1,
        DnsStatus::WildcardIp => stats.wildcard_ip += 1,
        DnsStatus::WildcardCname => stats.wildcard_cname += 1,
        DnsStatus::MixedWildcard => stats.mixed_wildcard += 1,
        DnsStatus::Shaky => stats.shaky += 1,
        DnsStatus::Timeout => stats.timeout += 1,
        DnsStatus::Error => stats.error += 1,
    }
}

fn add_wildcard_reason_stat(stats: &mut WildcardDecisionStats, reason: WildcardReason) {
    match reason {
        WildcardReason::IpOverlap => stats.ip_overlap += 1,
        WildcardReason::CnameMatch => stats.cname_match += 1,
        WildcardReason::TimeoutInferred => stats.timeout_inferred += 1,
    }
}

fn build_resolver(addr: SocketAddr, config: &DnsConfig) -> anyhow::Result<TokioResolver> {
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
    Ok(TokioResolver::builder_with_config(rconfig, provider)
        .with_options(opts)
        .build()?)
}

pub async fn check_resolvers(
    config: DnsConfig,
    check_config: ResolverCheckConfig,
) -> Vec<ResolverHealth> {
    let concurrency = if check_config.concurrency == 0 {
        config.resolvers.len().clamp(1, 50)
    } else {
        check_config.concurrency.max(1)
    };
    let jobs = config.resolvers.iter().copied().map(|resolver| {
        let config = config.clone();
        let check_config = check_config.clone();
        async move { check_one_resolver(resolver, &config, &check_config).await }
    });
    stream::iter(jobs)
        .buffer_unordered(concurrency)
        .collect()
        .await
}

async fn check_one_resolver(
    resolver_addr: SocketAddr,
    config: &DnsConfig,
    check_config: &ResolverCheckConfig,
) -> ResolverHealth {
    let resolver = match build_resolver(resolver_addr, config) {
        Ok(r) => r,
        Err(e) => {
            return classify_health(RawResolverHealth {
                resolver: resolver_addr,
                samples: Vec::new(),
                setup_error: Some(e.to_string()),
            });
        }
    };

    let mut samples = Vec::new();
    let domains = if check_config.positive_domains.is_empty() {
        ResolverCheckConfig::default().positive_domains
    } else {
        check_config.positive_domains.clone()
    };
    let rounds = check_config.rounds.max(1);

    for round in 0..rounds {
        for domain in &domains {
            samples.push(query_health(&resolver, ResolverCheckKind::Positive, domain).await);

            let random_domain = format!(
                "{}.{}",
                random_check_label(round, "wild"),
                domain.trim_end_matches('.')
            );
            samples.push(
                query_health(
                    &resolver,
                    ResolverCheckKind::WildcardPollution,
                    &random_domain,
                )
                .await,
            );
        }

        let invalid = format!(
            "{}.assetcanon-check.invalid",
            random_check_label(round, "nx")
        );
        samples.push(query_health(&resolver, ResolverCheckKind::NxdomainInvalid, &invalid).await);

        let example = format!("{}.example.com", random_check_label(round, "ex"));
        samples.push(query_health(&resolver, ResolverCheckKind::NxdomainRandom, &example).await);
    }

    classify_health(RawResolverHealth {
        resolver: resolver_addr,
        samples,
        setup_error: None,
    })
}

async fn query_health(
    resolver: &TokioResolver,
    kind: ResolverCheckKind,
    domain: &str,
) -> ResolverCheckSample {
    let start = Instant::now();
    let answers = resolve_host(resolver, domain).await;
    let latency_ms = Some(start.elapsed().as_millis());
    let outcome = if answers.any_answer {
        ResolverCheckOutcome::Answer
    } else if answers.all_nxdomain {
        ResolverCheckOutcome::Nxdomain
    } else if answers.any_timeout {
        ResolverCheckOutcome::Timeout
    } else {
        ResolverCheckOutcome::Error
    };
    ResolverCheckSample {
        kind,
        outcome,
        latency_ms,
    }
}

fn classify_health(raw: RawResolverHealth) -> ResolverHealth {
    let mut checks = ResolverHealthChecks::default();
    let mut reasons = Vec::new();

    if let Some(e) = raw.setup_error {
        reasons.push(format!("setup-error:{e}"));
        return ResolverHealth {
            resolver: raw.resolver,
            status: ResolverHealthStatus::Error,
            score: 0,
            latency: latency_stats(&[], false),
            timeout_ratio: 0.0,
            checks,
            reasons,
        };
    }

    let total = raw.samples.len();
    if total == 0 {
        reasons.push("no-samples".to_string());
        return ResolverHealth {
            resolver: raw.resolver,
            status: ResolverHealthStatus::Error,
            score: 0,
            latency: latency_stats(&[], false),
            timeout_ratio: 0.0,
            checks,
            reasons,
        };
    }

    let mut timeouts = 0usize;
    let mut errors = 0usize;
    let mut latencies = Vec::new();
    let mut nxdomain_hijack = false;
    let mut wildcard_pollution = false;

    for sample in &raw.samples {
        if let Some(ms) = sample.latency_ms {
            latencies.push(ms);
        }
        if sample.outcome == ResolverCheckOutcome::Timeout {
            timeouts += 1;
        }
        if sample.outcome == ResolverCheckOutcome::Error {
            errors += 1;
        }

        match sample.kind {
            ResolverCheckKind::Positive => {
                checks.positive.total += 1;
                if sample.outcome == ResolverCheckOutcome::Answer {
                    checks.positive.passed += 1;
                }
            }
            ResolverCheckKind::NxdomainInvalid | ResolverCheckKind::NxdomainRandom => {
                checks.nxdomain.total += 1;
                if sample.outcome == ResolverCheckOutcome::Nxdomain {
                    checks.nxdomain.passed += 1;
                }
                if sample.kind == ResolverCheckKind::NxdomainInvalid
                    && sample.outcome == ResolverCheckOutcome::Answer
                {
                    nxdomain_hijack = true;
                }
                if sample.kind == ResolverCheckKind::NxdomainRandom
                    && sample.outcome == ResolverCheckOutcome::Answer
                {
                    wildcard_pollution = true;
                }
            }
            ResolverCheckKind::WildcardPollution => {
                checks.wildcard_pollution.total += 1;
                if sample.outcome == ResolverCheckOutcome::Nxdomain {
                    checks.wildcard_pollution.passed += 1;
                }
                if sample.outcome == ResolverCheckOutcome::Answer {
                    wildcard_pollution = true;
                }
            }
        }
    }

    let timeout_ratio = timeouts as f32 / total as f32;
    let enough_for_p95 = checks.positive.total >= 20;
    let latency = latency_stats(&latencies, enough_for_p95);

    let status = if errors == total {
        reasons.push("all-errors".to_string());
        ResolverHealthStatus::Error
    } else if nxdomain_hijack {
        reasons.push("nxdomain-hijack".to_string());
        ResolverHealthStatus::Bad
    } else if wildcard_pollution {
        reasons.push("wildcard-pollution".to_string());
        ResolverHealthStatus::Bad
    } else if timeout_ratio > 0.5 {
        reasons.push("timeout-ratio>50%".to_string());
        ResolverHealthStatus::Bad
    } else if timeout_ratio >= 0.1 {
        reasons.push("timeout-ratio>=10%".to_string());
        ResolverHealthStatus::Warn
    } else if latency.p95_ms.map(|p95| p95 > 1000).unwrap_or(false) {
        reasons.push("p95>1000ms".to_string());
        ResolverHealthStatus::Warn
    } else {
        ResolverHealthStatus::Ok
    };

    ResolverHealth {
        resolver: raw.resolver,
        status,
        score: if status == ResolverHealthStatus::Ok {
            health_score(&checks, &latency, timeout_ratio)
        } else {
            0
        },
        latency,
        timeout_ratio,
        checks,
        reasons,
    }
}

fn latency_stats(samples: &[u128], include_p95: bool) -> ResolverLatencyStats {
    if samples.is_empty() {
        return ResolverLatencyStats {
            p50_ms: None,
            max_ms: None,
            p95_ms: None,
        };
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let p50 = percentile_nearest_rank(&sorted, 0.50);
    let p95 = include_p95.then(|| percentile_nearest_rank(&sorted, 0.95));
    ResolverLatencyStats {
        p50_ms: Some(p50),
        max_ms: sorted.last().copied(),
        p95_ms: p95,
    }
}

fn percentile_nearest_rank(sorted: &[u128], percentile: f32) -> u128 {
    let idx = ((sorted.len() as f32 * percentile).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

fn health_score(
    checks: &ResolverHealthChecks,
    latency: &ResolverLatencyStats,
    timeout_ratio: f32,
) -> u8 {
    let mut score = 100.0f32;
    score -= timeout_ratio * 100.0;
    score -= failure_ratio(&checks.positive) * 30.0;
    score -= failure_ratio(&checks.nxdomain) * 30.0;
    score -= failure_ratio(&checks.wildcard_pollution) * 20.0;
    if let Some(p50) = latency.p50_ms {
        if p50 > 250 {
            score -= ((p50 - 250) as f32 / 50.0).min(20.0);
        }
    }
    score.clamp(0.0, 100.0).round() as u8
}

fn failure_ratio(summary: &ResolverCheckSummary) -> f32 {
    if summary.total == 0 {
        0.0
    } else {
        (summary.total - summary.passed) as f32 / summary.total as f32
    }
}

fn random_check_label(round: usize, prefix: &str) -> String {
    format!("ac-{}-{}-{}", prefix, round, random_label(10))
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

/// Decide whether a `.invalid` probe outcome indicates an NXDOMAIN-hijacking
/// resolver. We flag only on a positive answer — timeouts and errors are
/// ambiguous (could be network blip, could be a resolver that drops bogon
/// names instead of returning NXDOMAIN). A normal resolver MUST NXDOMAIN
/// `.invalid` per RFC 6761; an A/AAAA answer means it's rewriting.
fn is_hijacked_outcome(outcome: &Result<HostAnswers, tokio::time::error::Elapsed>) -> bool {
    match outcome {
        Ok(ans) => ans.any_answer,
        Err(_) => false,
    }
}

/// Update a resolver's atomic health counters from a single query outcome
/// and flag it as unhealthy if the timeout ratio crosses the threshold.
/// Only "hard timeouts" (no answer, no NXDOMAIN, at least one timeout)
/// count — slow NXDOMAIN replies are not the resolver's fault. Sticky:
/// once flagged stays flagged. Threshold strictly greater than ratio means
/// `0.5` requires > 50%, not >= 50%, matching the docstring's intent.
fn apply_resolver_health_sample(
    h: &ResolverHealthCounters,
    threshold: f32,
    min_samples: usize,
    any_answer: bool,
    any_timeout: bool,
    all_nxdomain: bool,
) {
    h.total.fetch_add(1, Ordering::Relaxed);
    if any_timeout && !any_answer && !all_nxdomain {
        h.timeouts.fetch_add(1, Ordering::Relaxed);
    }
    if h.flagged.load(Ordering::Relaxed) {
        return;
    }
    if min_samples == 0 || threshold >= 1.0 {
        return;
    }
    let total = h.total.load(Ordering::Relaxed);
    if total < min_samples {
        return;
    }
    let timeouts = h.timeouts.load(Ordering::Relaxed);
    let ratio = timeouts as f32 / total as f32;
    if ratio > threshold {
        h.flagged.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Classification helpers

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsDecision {
    status: DnsStatus,
    wildcard_root: Option<String>,
    wildcard_reason: Option<WildcardReason>,
    wildcard_ip_overlap_count: usize,
    wildcard_cname_overlap_count: usize,
    wildcard_host_ip_count: usize,
    wildcard_signature_ip_count: usize,
    wildcard_signature_cname_count: usize,
}

impl DnsDecision {
    fn plain(status: DnsStatus) -> Self {
        Self {
            status,
            wildcard_root: None,
            wildcard_reason: None,
            wildcard_ip_overlap_count: 0,
            wildcard_cname_overlap_count: 0,
            wildcard_host_ip_count: 0,
            wildcard_signature_ip_count: 0,
            wildcard_signature_cname_count: 0,
        }
    }

    fn wildcard(
        status: DnsStatus,
        sig: &WildcardSignature,
        reason: WildcardReason,
        answers: &HostAnswers,
        ip_overlap_count: usize,
        cname_overlap_count: usize,
    ) -> Self {
        Self {
            status,
            wildcard_root: Some(format!("*.{}", sig.root)),
            wildcard_reason: Some(reason),
            wildcard_ip_overlap_count: ip_overlap_count,
            wildcard_cname_overlap_count: cname_overlap_count,
            wildcard_host_ip_count: answers.ips.len(),
            wildcard_signature_ip_count: sig.ips.len(),
            wildcard_signature_cname_count: sig.cnames.len(),
        }
    }
}

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
#[cfg(test)]
fn final_status(
    answers: &HostAnswers,
    sig: Option<&WildcardSignature>,
    infer_wildcard_on_timeout: bool,
) -> DnsStatus {
    final_decision(answers, sig, infer_wildcard_on_timeout).status
}

fn final_decision(
    answers: &HostAnswers,
    sig: Option<&WildcardSignature>,
    infer_wildcard_on_timeout: bool,
) -> DnsDecision {
    if !answers.any_answer {
        if infer_wildcard_on_timeout && answers.any_timeout {
            if let Some(sig) = sig {
                return DnsDecision::wildcard(
                    DnsStatus::WildcardIp,
                    sig,
                    WildcardReason::TimeoutInferred,
                    answers,
                    0,
                    0,
                );
            }
        }
        let status = if answers.all_nxdomain {
            DnsStatus::Unresolved
        } else if answers.any_timeout {
            DnsStatus::Timeout
        } else if answers.any_error {
            DnsStatus::Error
        } else {
            DnsStatus::Unresolved
        };
        return DnsDecision::plain(status);
    }
    if let Some(sig) = sig {
        let decision = classify_against_sig_decision(answers, sig);
        if decision.status.is_wildcard() {
            return decision;
        }
    }
    if answers.disagreement {
        DnsDecision::plain(DnsStatus::Shaky)
    } else {
        DnsDecision::plain(DnsStatus::Resolved)
    }
}

/// Confidence in a DNS verdict on a `[0.0, 1.0]` scale, derived purely from
/// signals the validator already computed. Designed for triaging large result
/// sets ("show me only resolved hosts with confidence >= 0.9"), not for hard
/// classification decisions — those still live in `DnsStatus`.
///
/// Calibration intent:
/// - `Resolved` with multi-resolver agreement and CDN evidence: near 1.0
/// - `WildcardCname`: high (~0.95) — CNAME-target match is a strong signal
/// - `WildcardIp`: scales with how completely the host's IPs lie in the sig
/// - `MixedWildcard`: deliberately middling (0.5) — these are worth reviewing
/// - `Shaky` / `Timeout`: low; `Error` / `Unknown`: zero
fn compute_confidence(decision: &DnsDecision, answers: &HostAnswers, cdn_tagged: bool) -> f32 {
    let c = match decision.status {
        DnsStatus::Resolved => {
            // `Resolved` already implies the resolvers agreed — disagreement
            // would have routed through `Shaky` in `final_decision`. So the
            // boosts here are purely additive: multi-resolver agreement and
            // an identified CDN provider both raise our certainty.
            let mut c = 0.9_f32;
            if answers.answer_count >= 2 {
                c += 0.05;
            }
            if cdn_tagged {
                c += 0.05;
            }
            c
        }
        DnsStatus::Unresolved => {
            // NXDOMAIN — decisive when resolvers agree, less so when they don't.
            if answers.disagreement {
                0.5
            } else {
                0.9
            }
        }
        DnsStatus::WildcardIp => {
            // Timeout-inferred verdicts are weaker than directly-observed ones.
            if matches!(
                decision.wildcard_reason,
                Some(WildcardReason::TimeoutInferred)
            ) {
                0.6
            } else {
                let host_ips = decision.wildcard_host_ip_count.max(1) as f32;
                let overlap = decision.wildcard_ip_overlap_count as f32;
                let coverage = (overlap / host_ips).clamp(0.0, 1.0);
                0.6 + 0.4 * coverage
            }
        }
        DnsStatus::WildcardCname => 0.95,
        DnsStatus::MixedWildcard => 0.5,
        DnsStatus::Shaky => 0.3,
        DnsStatus::Timeout => 0.1,
        DnsStatus::Error => 0.0,
        DnsStatus::Unknown => 0.0,
    };
    c.clamp(0.0, 1.0)
}

/// Detect a CDN from the host's answer set. Tries IP-range matching first
/// (more specific — a CIDR hit is unambiguous), then falls back to the
/// terminal CNAME suffix (catches Akamai/CloudFront/PaaS where IPs aren't
/// in our table). Returns `None` if neither path produces a tag.
fn detect_cdn(answers: &HostAnswers) -> Option<&'static str> {
    crate::cdn::dominant_provider(answers.ips.iter())
        .or_else(|| crate::cdn::lookup_cname_terminal(&answers.cnames))
}

/// Apply the CDN-driven IP-overlap-wildcard downgrade.
///
/// Given a CDN tag (from either IP- or CNAME-based detection), an IP-overlap
/// wildcard verdict is weak evidence: CDN IPs legitimately rotate and overlap
/// with a parent's wildcard signature. We downgrade a pure `WildcardIp` verdict
/// to `MixedWildcard` so it lands in the review bucket instead of being treated
/// as either high-confidence real or high-confidence fake. A CNAME-match
/// wildcard verdict is *not* downgraded — matching CNAME targets is a stronger
/// signal than IPs and stays intact even when the host is CDN-fronted.
fn apply_cdn_downgrade(decision: &mut DnsDecision, cdn: Option<&'static str>) {
    if cdn.is_none() {
        return;
    }
    if matches!(decision.wildcard_reason, Some(WildcardReason::IpOverlap))
        && matches!(decision.status, DnsStatus::WildcardIp)
    {
        decision.status = DnsStatus::MixedWildcard;
    }
}

#[cfg(test)]
fn classify_against_sig(answers: &HostAnswers, sig: &WildcardSignature) -> DnsStatus {
    classify_against_sig_decision(answers, sig).status
}

fn classify_against_sig_decision(answers: &HostAnswers, sig: &WildcardSignature) -> DnsDecision {
    // CNAME chain match is the strongest positive signal: if the host's CNAME
    // target is the same as a wildcard probe's, the host is served by the
    // wildcard regardless of which IPs the CDN happened to return this second.
    let cname_hit = answers.cnames.iter().any(|c| sig.cnames.contains(c));
    if cname_hit {
        let cname_hits = answers
            .cnames
            .iter()
            .filter(|c| sig.cnames.contains(*c))
            .count();
        return DnsDecision::wildcard(
            DnsStatus::WildcardCname,
            sig,
            WildcardReason::CnameMatch,
            answers,
            0,
            cname_hits,
        );
    }

    if answers.ips.is_empty() {
        return DnsDecision::plain(DnsStatus::Resolved);
    }

    let host_hits = answers.ips.intersection(&sig.ips).count();
    if host_hits == 0 {
        return DnsDecision::plain(DnsStatus::Resolved);
    }
    if host_hits == answers.ips.len() {
        return DnsDecision::wildcard(
            DnsStatus::WildcardIp,
            sig,
            WildcardReason::IpOverlap,
            answers,
            host_hits,
            0,
        );
    }
    DnsDecision::wildcard(
        DnsStatus::MixedWildcard,
        sig,
        WildcardReason::IpOverlap,
        answers,
        host_hits,
        0,
    )
}

fn merge_answers(results: Vec<HostAnswers>) -> HostAnswers {
    let mut merged = HostAnswers::default();
    let mut any_ans = false;
    let mut any_nx = false;
    let mut all_nx = true;
    let mut any_to = false;
    let mut any_err = false;
    let mut answer_count = 0usize;
    let mut nxdomain_count = 0usize;
    let mut timeout_count = 0usize;
    let mut error_count = 0usize;
    let mut ip_sets: HashSet<Vec<IpAddr>> = HashSet::new();
    let mut cname_sets: HashSet<Vec<String>> = HashSet::new();

    for r in &results {
        merged.ips.extend(&r.ips);
        for c in &r.cnames {
            if !merged.cnames.contains(c) {
                merged.cnames.push(c.clone());
            }
        }
        if r.any_answer {
            any_ans = true;
            all_nx = false;
            answer_count += 1;
            let mut ips: Vec<IpAddr> = r.ips.iter().copied().collect();
            ips.sort();
            ip_sets.insert(ips);
            let mut cnames = r.cnames.clone();
            cnames.sort();
            cname_sets.insert(cnames);
        } else if r.all_nxdomain {
            any_nx = true;
            nxdomain_count += 1;
        } else {
            all_nx = false;
        }
        if r.any_timeout {
            any_to = true;
            timeout_count += 1;
        }
        if r.any_error {
            any_err = true;
            error_count += 1;
        }
    }

    merged.any_answer = any_ans;
    merged.all_nxdomain = !any_ans && all_nx && any_nx;
    merged.any_timeout = any_to;
    merged.any_error = any_err;
    merged.disagreement = any_ans && any_nx;
    merged.answer_count = answer_count;
    merged.nxdomain_count = nxdomain_count;
    merged.timeout_count = timeout_count;
    merged.error_count = error_count;
    merged.distinct_ip_sets = ip_sets.len();
    merged.distinct_cname_sets = cname_sets.len();
    merged
}

/// Single-resolver A/AAAA lookup. The answer section contains both the CNAME
/// chain and the final A/AAAA records, so one query yields both signals.
async fn resolve_host(resolver: &TokioResolver, host: &str) -> HostAnswers {
    match resolver.lookup_ip(host).await {
        Ok(lookup) => {
            let mut ips: HashSet<IpAddr> = HashSet::new();
            // Vec + linear `contains` dedup: CNAME chains are almost always
            // < 10 hops, so O(n²) is trivial and preserves response order —
            // which is exactly the chain order we want to expose downstream.
            let mut cnames: Vec<String> = Vec::new();
            for rec in lookup.as_lookup().answers() {
                match &rec.data {
                    RData::A(a) => {
                        ips.insert(IpAddr::V4((*a).into()));
                    }
                    RData::AAAA(aaaa) => {
                        ips.insert(IpAddr::V6((*aaaa).into()));
                    }
                    RData::CNAME(c) => {
                        let name = normalize_cname(&c.to_string());
                        if !cnames.contains(&name) {
                            cnames.push(name);
                        }
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
                ..Default::default()
            }
        }
        Err(err) => {
            let (nx, timeout, other) = classify_error(&err);
            HostAnswers {
                ips: HashSet::new(),
                cnames: Vec::new(),
                any_answer: false,
                all_nxdomain: nx,
                any_timeout: timeout,
                any_error: other,
                disagreement: false,
                ..Default::default()
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
        let mut cur: &str = &h;
        while let Some(p) = parent_of(cur) {
            set.insert(p.to_string());
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

fn parent_of(host: &str) -> Option<&str> {
    let host = host.trim_matches('.');
    if host.matches('.').count() < 2 {
        // TLD or registrable apex — not useful for wildcard probing.
        return None;
    }
    host.split_once('.').map(|(_, rest)| rest)
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
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::UdpSocket;

    use hickory_resolver::proto::op::{Message, OpCode, ResponseCode};
    use hickory_resolver::proto::rr::{rdata::A, rdata::CNAME, Name, Record};

    #[test]
    fn parent_basic() {
        assert_eq!(parent_of("a.b.example.com"), Some("b.example.com"));
        assert_eq!(parent_of("b.example.com"), Some("example.com"));
        assert_eq!(parent_of("example.com"), None);
        assert_eq!(parent_of("com"), None);
    }

    #[test]
    fn random_label_shape() {
        let s = random_label(16);
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    fn health_sample(
        kind: ResolverCheckKind,
        outcome: ResolverCheckOutcome,
        latency_ms: u128,
    ) -> ResolverCheckSample {
        ResolverCheckSample {
            kind,
            outcome,
            latency_ms: Some(latency_ms),
        }
    }

    fn raw_health(samples: Vec<ResolverCheckSample>) -> RawResolverHealth {
        RawResolverHealth {
            resolver: "127.0.0.1:53".parse().unwrap(),
            samples,
            setup_error: None,
        }
    }

    #[test]
    fn classify_health_ok_uses_score_without_status_overlap() {
        let health = classify_health(raw_health(vec![
            health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Answer,
                20,
            ),
            health_sample(
                ResolverCheckKind::NxdomainInvalid,
                ResolverCheckOutcome::Nxdomain,
                20,
            ),
            health_sample(
                ResolverCheckKind::NxdomainRandom,
                ResolverCheckOutcome::Nxdomain,
                20,
            ),
            health_sample(
                ResolverCheckKind::WildcardPollution,
                ResolverCheckOutcome::Nxdomain,
                20,
            ),
        ]));
        assert_eq!(health.status, ResolverHealthStatus::Ok);
        assert!(health.score >= 90);
    }

    #[test]
    fn classify_health_hard_rules_bad_for_hijack_and_pollution() {
        let hijack = classify_health(raw_health(vec![
            health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Answer,
                20,
            ),
            health_sample(
                ResolverCheckKind::NxdomainInvalid,
                ResolverCheckOutcome::Answer,
                20,
            ),
        ]));
        assert_eq!(hijack.status, ResolverHealthStatus::Bad);
        assert!(hijack.reasons.contains(&"nxdomain-hijack".to_string()));

        let pollution = classify_health(raw_health(vec![
            health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Answer,
                20,
            ),
            health_sample(
                ResolverCheckKind::NxdomainInvalid,
                ResolverCheckOutcome::Nxdomain,
                20,
            ),
            health_sample(
                ResolverCheckKind::WildcardPollution,
                ResolverCheckOutcome::Answer,
                20,
            ),
        ]));
        assert_eq!(pollution.status, ResolverHealthStatus::Bad);
        assert!(pollution
            .reasons
            .contains(&"wildcard-pollution".to_string()));
    }

    #[test]
    fn classify_health_timeout_ratio_rules() {
        let warn = classify_health(raw_health(vec![
            health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Answer,
                20,
            ),
            health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Answer,
                20,
            ),
            health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Timeout,
                20,
            ),
            health_sample(
                ResolverCheckKind::NxdomainInvalid,
                ResolverCheckOutcome::Nxdomain,
                20,
            ),
        ]));
        assert_eq!(warn.status, ResolverHealthStatus::Warn);

        let bad = classify_health(raw_health(vec![
            health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Timeout,
                20,
            ),
            health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Timeout,
                20,
            ),
            health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Timeout,
                20,
            ),
            health_sample(
                ResolverCheckKind::NxdomainInvalid,
                ResolverCheckOutcome::Nxdomain,
                20,
            ),
        ]));
        assert_eq!(bad.status, ResolverHealthStatus::Bad);
    }

    #[test]
    fn classify_health_p95_warn_requires_enough_positive_samples() {
        let mut few = Vec::new();
        for _ in 0..19 {
            few.push(health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Answer,
                1500,
            ));
        }
        let few = classify_health(raw_health(few));
        assert_eq!(few.status, ResolverHealthStatus::Ok);
        assert_eq!(few.latency.p95_ms, None);

        let mut enough = Vec::new();
        for _ in 0..20 {
            enough.push(health_sample(
                ResolverCheckKind::Positive,
                ResolverCheckOutcome::Answer,
                1500,
            ));
        }
        let enough = classify_health(raw_health(enough));
        assert_eq!(enough.status, ResolverHealthStatus::Warn);
        assert_eq!(enough.latency.p95_ms, Some(1500));
        assert!(enough.reasons.contains(&"p95>1000ms".to_string()));
    }

    #[derive(Clone, Copy)]
    enum MockDnsMode {
        Ok,
        Timeout,
        Hijack,
        WildcardPollution,
        Flaky,
    }

    async fn spawn_mock_dns(mode: MockDnsMode) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                if matches!(mode, MockDnsMode::Timeout) {
                    continue;
                }
                if matches!(mode, MockDnsMode::Flaky)
                    && counter.fetch_add(1, Ordering::SeqCst) % 2 == 0
                {
                    continue;
                }
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let response = mock_response(&request, mode);
                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });
        addr
    }

    #[derive(Clone, Copy)]
    enum MockValidationMode {
        Clean,
        WildcardIp,
        MixedWildcard,
        WildcardCname,
        Nxdomain,
        Timeout,
    }

    async fn spawn_mock_validation_dns(mode: MockValidationMode) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                if matches!(mode, MockValidationMode::Timeout) {
                    continue;
                }
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let response = mock_validation_response(&request, mode);
                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });
        addr
    }

    fn mock_validation_response(request: &Message, mode: MockValidationMode) -> Message {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.add_queries(request.queries.clone());
        let Some(query) = request.queries.first() else {
            response.metadata.response_code = ResponseCode::FormErr;
            return response;
        };
        let query_name = query
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let name = query.name().clone();

        match mode {
            MockValidationMode::Clean => {
                if query_name == "api.example.test" {
                    add_a(&mut response, name, [1, 2, 3, 4]);
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            MockValidationMode::WildcardIp => {
                if query_name.ends_with(".example.test") {
                    add_a(&mut response, name, [1, 2, 3, 4]);
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            MockValidationMode::MixedWildcard => {
                if query_name == "api.example.test" {
                    add_a(&mut response, name.clone(), [1, 2, 3, 4]);
                    add_a(&mut response, name, [9, 9, 9, 9]);
                } else if query_name.ends_with(".example.test") {
                    add_a(&mut response, name, [1, 2, 3, 4]);
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            MockValidationMode::WildcardCname => {
                if query_name.ends_with(".example.test") {
                    let target = Name::from_ascii("wildcard.cdn.test.").unwrap();
                    response.add_answer(Record::from_rdata(
                        name,
                        60,
                        RData::CNAME(CNAME(target.clone())),
                    ));
                    add_a(&mut response, target, [1, 2, 3, 4]);
                } else {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
            }
            MockValidationMode::Nxdomain => {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
            MockValidationMode::Timeout => unreachable!("handled by caller"),
        }
        response
    }

    fn add_a(response: &mut Message, name: Name, octets: [u8; 4]) {
        response.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A(Ipv4Addr::from(octets))),
        ));
    }

    async fn validate_with_mock(mode: MockValidationMode, consistency_checks: usize) -> DnsReport {
        let addr = spawn_mock_validation_dns(mode).await;
        let config = DnsConfig {
            resolvers: vec![addr],
            timeout: Duration::from_millis(60),
            retries: 1,
            wildcard_tests: 2,
            consistency_checks,
            probe_concurrency: 1,
            flaky_min_samples: 0,
            ..DnsConfig::default()
        };
        let validator = Arc::new(DnsValidator::new(config).unwrap());
        validator
            .validate(vec![crate::classify::classify_str("api.example.test")])
            .await
    }

    async fn validate_with_two_mocks(
        first: MockValidationMode,
        second: MockValidationMode,
    ) -> DnsReport {
        let first = spawn_mock_validation_dns(first).await;
        let second = spawn_mock_validation_dns(second).await;
        let config = DnsConfig {
            resolvers: vec![first, second],
            timeout: Duration::from_millis(60),
            retries: 1,
            wildcard_tests: 2,
            consistency_checks: 2,
            probe_concurrency: 1,
            flaky_min_samples: 0,
            ..DnsConfig::default()
        };
        let validator = Arc::new(DnsValidator::new(config).unwrap());
        validator
            .validate(vec![crate::classify::classify_str("api.example.test")])
            .await
    }

    fn mock_response(request: &Message, mode: MockDnsMode) -> Message {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.add_queries(request.queries.clone());
        let query_name = request
            .queries
            .first()
            .map(|q| {
                q.name()
                    .to_ascii()
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();

        let should_answer = match mode {
            MockDnsMode::Ok => query_name == "example.com" || query_name == "iana.org",
            MockDnsMode::Hijack => true,
            MockDnsMode::WildcardPollution => {
                query_name == "example.com"
                    || query_name == "iana.org"
                    || query_name.ends_with(".example.com")
                    || query_name.ends_with(".iana.org")
            }
            MockDnsMode::Flaky => query_name == "example.com" || query_name == "iana.org",
            MockDnsMode::Timeout => false,
        };

        if should_answer {
            let name = request.queries.first().unwrap().name().clone();
            response.add_answer(Record::from_rdata(
                name,
                60,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            ));
        } else {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        response
    }

    async fn run_mock_health(mode: MockDnsMode) -> ResolverHealth {
        let addr = spawn_mock_dns(mode).await;
        let config = DnsConfig {
            resolvers: vec![addr],
            timeout: Duration::from_millis(80),
            retries: 1,
            ..DnsConfig::default()
        };
        let check_config = ResolverCheckConfig {
            rounds: 5,
            concurrency: 1,
            ..ResolverCheckConfig::default()
        };
        check_resolvers(config, check_config).await.remove(0)
    }

    #[tokio::test]
    async fn resolver_health_mock_ok_is_ok() {
        let health = run_mock_health(MockDnsMode::Ok).await;
        assert_eq!(health.status, ResolverHealthStatus::Ok);
    }

    #[tokio::test]
    async fn resolver_health_mock_timeout_is_bad() {
        let health = run_mock_health(MockDnsMode::Timeout).await;
        assert_eq!(health.status, ResolverHealthStatus::Bad);
        assert!(health.reasons.iter().any(|r| r.contains("timeout-ratio")));
    }

    #[tokio::test]
    async fn resolver_health_mock_hijack_is_bad() {
        let health = run_mock_health(MockDnsMode::Hijack).await;
        assert_eq!(health.status, ResolverHealthStatus::Bad);
        assert!(
            health.reasons.contains(&"nxdomain-hijack".to_string())
                || health.reasons.contains(&"wildcard-pollution".to_string())
        );
    }

    #[tokio::test]
    async fn resolver_health_mock_wildcard_pollution_is_bad() {
        let health = run_mock_health(MockDnsMode::WildcardPollution).await;
        assert_eq!(health.status, ResolverHealthStatus::Bad);
        assert!(health.reasons.contains(&"wildcard-pollution".to_string()));
    }

    #[tokio::test]
    async fn resolver_health_mock_flaky_is_warn() {
        let health = run_mock_health(MockDnsMode::Flaky).await;
        assert_eq!(health.status, ResolverHealthStatus::Warn);
    }

    #[tokio::test]
    async fn dns_validation_mock_clean_resolved_records_stats() {
        let report = validate_with_mock(MockValidationMode::Clean, 1).await;
        let asset = &report.assets[0];

        assert_eq!(asset.dns, DnsStatus::Resolved);
        assert_eq!(asset.ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(report.stats.statuses.resolved, 1);
        assert_eq!(report.stats.signature_parents.clean, 1);
        assert_eq!(report.stats.host_queries, 1);
        assert_eq!(report.stats.probe_queries, 2);
    }

    #[tokio::test]
    async fn dns_validation_mock_wildcard_ip_records_evidence() {
        let report = validate_with_mock(MockValidationMode::WildcardIp, 1).await;
        let asset = &report.assets[0];

        assert_eq!(asset.dns, DnsStatus::WildcardIp);
        assert_eq!(asset.wildcard_reason, Some(WildcardReason::IpOverlap));
        assert_eq!(asset.wildcard_root.as_deref(), Some("*.example.test"));
        assert_eq!(asset.wildcard_ip_overlap_count, 1);
        assert_eq!(asset.wildcard_host_ip_count, 1);
        assert_eq!(asset.wildcard_signature_ip_count, 1);
        assert_eq!(report.stats.wildcard_decisions.ip_overlap, 1);
        assert_eq!(report.stats.statuses.wildcard_ip, 1);
    }

    #[tokio::test]
    async fn dns_validation_mock_mixed_wildcard_records_partial_overlap() {
        let report = validate_with_mock(MockValidationMode::MixedWildcard, 1).await;
        let asset = &report.assets[0];

        assert_eq!(asset.dns, DnsStatus::MixedWildcard);
        assert_eq!(asset.wildcard_reason, Some(WildcardReason::IpOverlap));
        assert_eq!(asset.wildcard_ip_overlap_count, 1);
        assert_eq!(asset.wildcard_host_ip_count, 2);
        assert_eq!(report.stats.statuses.mixed_wildcard, 1);
    }

    #[tokio::test]
    async fn dns_validation_mock_wildcard_cname_records_evidence() {
        let report = validate_with_mock(MockValidationMode::WildcardCname, 1).await;
        let asset = &report.assets[0];

        assert_eq!(asset.dns, DnsStatus::WildcardCname);
        assert_eq!(asset.wildcard_reason, Some(WildcardReason::CnameMatch));
        assert_eq!(asset.wildcard_cname_overlap_count, 1);
        assert_eq!(asset.wildcard_signature_cname_count, 1);
        assert!(asset.cnames.contains(&"wildcard.cdn.test".to_string()));
        assert_eq!(report.stats.wildcard_decisions.cname_match, 1);
        assert_eq!(report.stats.statuses.wildcard_cname, 1);
    }

    #[tokio::test]
    async fn dns_validation_mock_dead_zone_short_circuits_host_query() {
        let report = validate_with_mock(MockValidationMode::Timeout, 1).await;
        let asset = &report.assets[0];

        assert_eq!(asset.dns, DnsStatus::Timeout);
        assert_eq!(asset.dead_zone.as_deref(), Some("example.test"));
        assert_eq!(report.stats.signature_parents.dead, 1);
        assert_eq!(report.stats.short_circuits.dead_zone, 1);
        assert_eq!(report.stats.host_queries, 0);
    }

    #[tokio::test]
    async fn dns_validation_mock_resolver_disagreement_is_shaky_and_counted() {
        let report =
            validate_with_two_mocks(MockValidationMode::Clean, MockValidationMode::Nxdomain).await;
        let asset = &report.assets[0];

        assert_eq!(asset.dns, DnsStatus::Shaky);
        assert!(asset.resolver_disagreement);
        assert_eq!(report.stats.resolver_disagreement.answer_vs_nxdomain, 1);
        assert_eq!(report.stats.statuses.shaky, 1);
        assert_eq!(report.stats.host_queries, 2);
    }

    #[tokio::test]
    #[ignore]
    async fn resolver_health_live_public_smoke() {
        let config = DnsConfig {
            resolvers: vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()],
            timeout: Duration::from_secs(2),
            retries: 1,
            ..DnsConfig::default()
        };
        let results = check_resolvers(config, ResolverCheckConfig::default()).await;
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn cname_match_is_decisive() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::new()),
            cnames: Arc::new(HashSet::from(["cdn.example.net".into()])),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: vec!["cdn.example.net".into()],
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(
            classify_against_sig(&answers, &sig),
            DnsStatus::WildcardCname
        );
    }

    #[test]
    fn explain_cname_match_includes_root_and_reason() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::new()),
            cnames: Arc::new(HashSet::from(["cdn.example.net".into()])),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: vec!["cdn.example.net".into()],
            any_answer: true,
            ..Default::default()
        };

        let decision = final_decision(&answers, Some(&sig), /*infer*/ true);

        assert_eq!(decision.status, DnsStatus::WildcardCname);
        assert_eq!(decision.wildcard_root.as_deref(), Some("*.example.com"));
        assert_eq!(decision.wildcard_reason, Some(WildcardReason::CnameMatch));
        assert_eq!(decision.wildcard_cname_overlap_count, 1);
        assert_eq!(decision.wildcard_signature_cname_count, 1);
    }

    #[test]
    fn cname_chain_match_hits_on_any_hop() {
        // Signature records the terminal CDN target; the host's chain is
        // `legacy.example.com → cdn.example.net`. The match must trigger on the
        // tail hop, not just the first one — this is the takeover / CDN path
        // we explicitly want to detect.
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::new()),
            cnames: Arc::new(HashSet::from(["cdn.example.net".into()])),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: vec!["legacy.example.com".into(), "cdn.example.net".into()],
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(
            classify_against_sig(&answers, &sig),
            DnsStatus::WildcardCname
        );
    }

    #[test]
    fn full_ip_overlap_is_wildcard_ip() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from([
                "1.2.3.4".parse().unwrap(),
                "1.2.3.5".parse().unwrap(),
            ])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: Vec::new(),
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(classify_against_sig(&answers, &sig), DnsStatus::WildcardIp);
    }

    #[test]
    fn explain_ip_overlap_includes_root_and_reason() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from(["1.2.3.4".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            any_answer: true,
            ..Default::default()
        };

        let decision = final_decision(&answers, Some(&sig), /*infer*/ true);

        assert_eq!(decision.status, DnsStatus::WildcardIp);
        assert_eq!(decision.wildcard_root.as_deref(), Some("*.example.com"));
        assert_eq!(decision.wildcard_reason, Some(WildcardReason::IpOverlap));
        assert_eq!(decision.wildcard_ip_overlap_count, 1);
        assert_eq!(decision.wildcard_host_ip_count, 1);
        assert_eq!(decision.wildcard_signature_ip_count, 1);
    }

    #[test]
    fn cdn_downgrade_ip_overlap_to_review() {
        // Both sig and answers are entirely on Cloudflare IPs — IP overlap is
        // not strong enough to classify as fake. Downgrade to MixedWildcard so
        // the CLI routes it to the review bucket.
        let cf_a: IpAddr = "104.16.1.1".parse().unwrap();
        let cf_b: IpAddr = "172.64.1.1".parse().unwrap();
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from([cf_a, cf_b])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::from([cf_a]),
            any_answer: true,
            ..Default::default()
        };
        let mut decision = final_decision(&answers, Some(&sig), /*infer*/ true);
        assert_eq!(decision.status, DnsStatus::WildcardIp);

        let cdn = detect_cdn(&answers);
        apply_cdn_downgrade(&mut decision, cdn);
        assert_eq!(cdn, Some("cloudflare"));
        assert_eq!(decision.status, DnsStatus::MixedWildcard);
        assert_eq!(decision.wildcard_root.as_deref(), Some("*.example.com"));
        assert_eq!(decision.wildcard_reason, Some(WildcardReason::IpOverlap));
        assert_eq!(decision.wildcard_ip_overlap_count, 1);
    }

    #[test]
    fn cdn_does_not_downgrade_cname_match() {
        // CNAME-target match is a strong signal even for CDN-fronted hosts.
        let cf: IpAddr = "104.16.1.1".parse().unwrap();
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::new()),
            cnames: Arc::new(HashSet::from(["cdn.example.net".into()])),
        };
        let answers = HostAnswers {
            ips: HashSet::from([cf]),
            cnames: vec!["cdn.example.net".into()],
            any_answer: true,
            ..Default::default()
        };
        let mut decision = final_decision(&answers, Some(&sig), /*infer*/ true);
        assert_eq!(decision.status, DnsStatus::WildcardCname);

        let cdn = detect_cdn(&answers);
        apply_cdn_downgrade(&mut decision, cdn);
        // Still tagged with the CDN provider, but the verdict stays put.
        assert_eq!(cdn, Some("cloudflare"));
        assert_eq!(decision.status, DnsStatus::WildcardCname);
        assert!(decision.wildcard_root.is_some());
        assert_eq!(decision.wildcard_reason, Some(WildcardReason::CnameMatch));
    }

    #[test]
    fn cdn_tags_resolved_host_without_downgrade() {
        // Pure resolved (no wildcard sig) — just stamp the CDN tag.
        let cf: IpAddr = "104.16.1.1".parse().unwrap();
        let answers = HostAnswers {
            ips: HashSet::from([cf]),
            any_answer: true,
            ..Default::default()
        };
        let mut decision = final_decision(&answers, None, /*infer*/ true);
        assert_eq!(decision.status, DnsStatus::Resolved);

        let cdn = detect_cdn(&answers);
        apply_cdn_downgrade(&mut decision, cdn);
        assert_eq!(cdn, Some("cloudflare"));
        assert_eq!(decision.status, DnsStatus::Resolved);
    }

    #[test]
    fn cdn_mixed_cdn_and_non_cdn_does_not_tag() {
        let cf: IpAddr = "104.16.1.1".parse().unwrap();
        let google: IpAddr = "8.8.8.8".parse().unwrap();
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from([cf, google])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::from([cf, google]),
            any_answer: true,
            ..Default::default()
        };
        let mut decision = final_decision(&answers, Some(&sig), /*infer*/ true);
        assert_eq!(decision.status, DnsStatus::WildcardIp);

        let cdn = detect_cdn(&answers);
        apply_cdn_downgrade(&mut decision, cdn);
        // Mixed providers → no tag, no downgrade. The wildcard verdict is real.
        assert_eq!(cdn, None);
        assert_eq!(decision.status, DnsStatus::WildcardIp);
    }

    #[test]
    fn cdn_cname_based_detection_tags_akamai() {
        // No CDN IPs (Akamai doesn't publish a full IP list), but CNAME chain
        // ends at akamaiedge.net — the CNAME path catches it.
        let answers = HostAnswers {
            ips: HashSet::from(["198.51.100.5".parse().unwrap()]),
            cnames: vec!["e1234.dscb.akamaiedge.net".into()],
            any_answer: true,
            ..Default::default()
        };
        let mut decision = final_decision(&answers, None, /*infer*/ true);
        assert_eq!(decision.status, DnsStatus::Resolved);

        let cdn = detect_cdn(&answers);
        apply_cdn_downgrade(&mut decision, cdn);
        assert_eq!(cdn, Some("akamai"));
    }

    #[test]
    fn cdn_cname_based_downgrade_for_cloudfront() {
        // CloudFront IPs aren't in our static table but the CNAME terminal is
        // unmistakable. An IP-overlap wildcard verdict should still be routed
        // to review, not promoted to trusted resolved.
        let ip: IpAddr = "13.224.78.55".parse().unwrap(); // CloudFront-ish but not in our table
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from([ip])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::from([ip]),
            cnames: vec!["d123456abcdef.cloudfront.net".into()],
            any_answer: true,
            ..Default::default()
        };
        let mut decision = final_decision(&answers, Some(&sig), /*infer*/ true);
        assert_eq!(decision.status, DnsStatus::WildcardIp);

        let cdn = detect_cdn(&answers);
        apply_cdn_downgrade(&mut decision, cdn);
        assert_eq!(cdn, Some("cloudfront"));
        assert_eq!(decision.status, DnsStatus::MixedWildcard);
        assert_eq!(decision.wildcard_root.as_deref(), Some("*.example.com"));
    }

    #[test]
    fn cdn_ip_match_takes_precedence_over_cname() {
        // IP says Cloudflare; CNAME says Akamai. IP is more specific.
        let cf: IpAddr = "104.16.1.1".parse().unwrap();
        let answers = HostAnswers {
            ips: HashSet::from([cf]),
            cnames: vec!["e1234.akamaiedge.net".into()],
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(detect_cdn(&answers), Some("cloudflare"));
    }

    #[test]
    fn confidence_resolved_multi_resolver_plus_cdn() {
        let cf: IpAddr = "104.16.1.1".parse().unwrap();
        let answers = HostAnswers {
            ips: HashSet::from([cf]),
            any_answer: true,
            answer_count: 2,
            ..Default::default()
        };
        let decision = final_decision(&answers, None, true);
        let c = compute_confidence(&decision, &answers, /*cdn_tagged*/ true);
        // 0.9 base + 0.05 multi-resolver + 0.05 CDN = 1.0
        assert!((c - 1.0).abs() < 1e-6, "expected ~1.0, got {c}");
    }

    #[test]
    fn confidence_resolved_single_resolver_no_cdn() {
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            any_answer: true,
            answer_count: 1,
            ..Default::default()
        };
        let decision = final_decision(&answers, None, true);
        let c = compute_confidence(&decision, &answers, false);
        // Base 0.9 without multi-resolver/CDN boosts.
        assert!((c - 0.9).abs() < 1e-6, "expected 0.9, got {c}");
    }

    #[test]
    fn confidence_wildcard_cname_is_high() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::new()),
            cnames: Arc::new(HashSet::from(["cdn.example.net".into()])),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: vec!["cdn.example.net".into()],
            any_answer: true,
            ..Default::default()
        };
        let decision = final_decision(&answers, Some(&sig), true);
        let c = compute_confidence(&decision, &answers, false);
        assert!((c - 0.95).abs() < 1e-6);
    }

    #[test]
    fn confidence_wildcard_ip_scales_with_coverage() {
        // Full coverage: 1 host IP in 1 sig IP → coverage 1.0 → 0.6 + 0.4 = 1.0
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from(["1.2.3.4".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            any_answer: true,
            ..Default::default()
        };
        let decision = final_decision(&answers, Some(&sig), true);
        let c = compute_confidence(&decision, &answers, false);
        assert!((c - 1.0).abs() < 1e-6, "expected ~1.0, got {c}");
    }

    #[test]
    fn confidence_timeout_inferred_is_moderate() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from(["1.2.3.4".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::new(),
            any_answer: false,
            any_timeout: true,
            ..Default::default()
        };
        let decision = final_decision(&answers, Some(&sig), /*infer*/ true);
        assert_eq!(decision.status, DnsStatus::WildcardIp);
        assert_eq!(
            decision.wildcard_reason,
            Some(WildcardReason::TimeoutInferred)
        );
        let c = compute_confidence(&decision, &answers, false);
        assert!(
            (c - 0.6).abs() < 1e-6,
            "expected 0.6 for timeout-inferred, got {c}"
        );
    }

    #[test]
    fn confidence_shaky_and_timeout_are_low() {
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            any_answer: true,
            disagreement: true,
            answer_count: 1,
            nxdomain_count: 1,
            ..Default::default()
        };
        // Force Shaky by passing no sig (so final_decision sees disagreement on resolved).
        let mut decision = final_decision(&answers, None, true);
        // The fixture above hits Resolved-with-disagreement. Build a Shaky one manually:
        decision.status = DnsStatus::Shaky;
        assert!((compute_confidence(&decision, &answers, false) - 0.3).abs() < 1e-6);

        decision.status = DnsStatus::Timeout;
        assert!((compute_confidence(&decision, &answers, false) - 0.1).abs() < 1e-6);

        decision.status = DnsStatus::Error;
        assert!((compute_confidence(&decision, &answers, false) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn partial_overlap_is_mixed() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from(["1.2.3.4".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap(), "9.9.9.9".parse().unwrap()]),
            cnames: Vec::new(),
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(
            classify_against_sig(&answers, &sig),
            DnsStatus::MixedWildcard
        );
    }

    #[test]
    fn disjoint_ip_is_resolved() {
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from(["1.2.3.4".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["8.8.8.8".parse().unwrap()]),
            cnames: Vec::new(),
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(classify_against_sig(&answers, &sig), DnsStatus::Resolved);
    }

    #[test]
    fn merge_marks_shaky_on_disagreement() {
        let a = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: Vec::new(),
            any_answer: true,
            ..Default::default()
        };
        let b = HostAnswers {
            ips: HashSet::new(),
            cnames: Vec::new(),
            any_answer: false,
            all_nxdomain: true,
            ..Default::default()
        };
        let merged = merge_answers(vec![a, b]);
        assert!(merged.disagreement);
        assert!(merged.any_answer);
        assert_eq!(merged.answer_count, 1);
        assert_eq!(merged.nxdomain_count, 1);
    }

    #[test]
    fn merge_tracks_low_cardinality_resolver_disagreement_stats() {
        let answer_a = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: vec!["cdn-a.example.net".into()],
            any_answer: true,
            ..Default::default()
        };
        let answer_b = HostAnswers {
            ips: HashSet::from(["5.6.7.8".parse().unwrap()]),
            cnames: vec!["cdn-b.example.net".into()],
            any_answer: true,
            ..Default::default()
        };
        let timeout = HostAnswers {
            any_timeout: true,
            ..Default::default()
        };
        let error = HostAnswers {
            any_error: true,
            ..Default::default()
        };

        let merged = merge_answers(vec![answer_a, answer_b, timeout, error]);

        assert_eq!(merged.answer_count, 2);
        assert_eq!(merged.timeout_count, 1);
        assert_eq!(merged.error_count, 1);
        assert_eq!(merged.distinct_ip_sets, 2);
        assert_eq!(merged.distinct_cname_sets, 2);
    }

    #[test]
    fn merge_preserves_cname_chain_order() {
        // Two resolvers returned the same chain. The merged result must
        // preserve the order `[first-alias, terminal-target]`, not scramble
        // it via set iteration. Subdomain-takeover detection depends on
        // knowing which hop is the tail.
        let chain = vec!["legacy.example.com".into(), "cdn.example.net".into()];
        let a = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: chain.clone(),
            any_answer: true,
            ..Default::default()
        };
        let b = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: chain.clone(),
            any_answer: true,
            ..Default::default()
        };
        let merged = merge_answers(vec![a, b]);
        assert_eq!(merged.cnames, chain);
    }

    #[test]
    fn merge_unions_divergent_chains_first_seen_wins() {
        // R1 returned a 2-hop chain, R2 a shorter 1-hop. Result is the
        // first-seen order with no duplicates — the union still exposes the
        // terminal target R1 saw.
        let a = HostAnswers {
            cnames: vec!["legacy.example.com".into(), "cdn.example.net".into()],
            any_answer: true,
            ..Default::default()
        };
        let b = HostAnswers {
            cnames: vec!["legacy.example.com".into()],
            any_answer: true,
            ..Default::default()
        };
        let merged = merge_answers(vec![a, b]);
        assert_eq!(
            merged.cnames,
            vec![
                "legacy.example.com".to_string(),
                "cdn.example.net".to_string(),
            ]
        );
    }

    #[test]
    fn merge_all_nxdomain_is_unresolved() {
        let a = HostAnswers {
            all_nxdomain: true,
            ..Default::default()
        };
        let b = HostAnswers {
            all_nxdomain: true,
            ..Default::default()
        };
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
            ips: Arc::new(HashSet::from([
                "104.18.16.5".parse().unwrap(),
                "104.18.17.5".parse().unwrap(),
            ])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            ips: HashSet::from([
                "104.18.16.5".parse().unwrap(),
                "104.18.17.5".parse().unwrap(),
            ]),
            cnames: Vec::new(),
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
            ips: Arc::new(HashSet::new()),
            cnames: Arc::new(HashSet::from(["cdn.example.net".into()])),
        };
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: vec!["cdn.example.net".into()],
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
            cnames: Vec::new(),
            any_answer: true,
            disagreement: true,
            ..Default::default()
        };
        assert_eq!(
            final_status(&answers, None, /*infer*/ true),
            DnsStatus::Shaky
        );
    }

    #[test]
    fn clean_resolve_is_resolved() {
        let answers = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            cnames: Vec::new(),
            any_answer: true,
            ..Default::default()
        };
        assert_eq!(
            final_status(&answers, None, /*infer*/ true),
            DnsStatus::Resolved
        );
    }

    #[test]
    fn timeout_when_no_answers_and_some_timed_out() {
        let answers = HostAnswers {
            any_answer: false,
            any_timeout: true,
            ..Default::default()
        };
        assert_eq!(
            final_status(&answers, None, /*infer*/ true),
            DnsStatus::Timeout
        );
    }

    #[test]
    fn unresolved_beats_timeout_when_all_nxdomain() {
        let answers = HostAnswers {
            any_answer: false,
            all_nxdomain: true,
            any_timeout: true,
            ..Default::default()
        };
        assert_eq!(
            final_status(&answers, None, /*infer*/ true),
            DnsStatus::Unresolved
        );
    }

    #[test]
    fn timeout_under_wildcard_parent_is_inferred_wildcard_ip() {
        // Regression: a host that times out but whose parent is a wildcard
        // should be reported as WildcardIp (under the inference flag).
        // Rationale: wildcard zones answer every label; a timeout there is
        // a rate-limit drop, not a real black hole.
        let sig = WildcardSignature {
            root: "cheaptickets.nl".into(),
            ips: Arc::new(HashSet::from(["104.18.16.5".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
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
    fn explain_timeout_inference_includes_root_and_reason() {
        let sig = WildcardSignature {
            root: "cheaptickets.nl".into(),
            ips: Arc::new(HashSet::from(["104.18.16.5".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
        };
        let answers = HostAnswers {
            any_answer: false,
            any_timeout: true,
            ..Default::default()
        };

        let decision = final_decision(&answers, Some(&sig), /*infer*/ true);

        assert_eq!(decision.status, DnsStatus::WildcardIp);
        assert_eq!(decision.wildcard_root.as_deref(), Some("*.cheaptickets.nl"));
        assert_eq!(
            decision.wildcard_reason,
            Some(WildcardReason::TimeoutInferred),
        );
        assert_eq!(decision.wildcard_ip_overlap_count, 0);
        assert_eq!(decision.wildcard_host_ip_count, 0);
        assert_eq!(decision.wildcard_signature_ip_count, 1);
    }

    #[test]
    fn inference_disabled_keeps_timeout() {
        // Same scenario as above, but with the inference flag OFF → stays
        // Timeout for strict observed-only semantics.
        let sig = WildcardSignature {
            root: "cheaptickets.nl".into(),
            ips: Arc::new(HashSet::from(["104.18.16.5".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
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
            ips: Arc::new(HashSet::from(["104.18.16.5".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
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

    #[test]
    fn stats_helpers_count_statuses_and_wildcard_reasons() {
        let mut statuses = DnsStatusStats::default();
        add_status_stat(&mut statuses, DnsStatus::Resolved);
        add_status_stat(&mut statuses, DnsStatus::Resolved);
        add_status_stat(&mut statuses, DnsStatus::WildcardCname);
        add_status_stat(&mut statuses, DnsStatus::Timeout);

        assert_eq!(statuses.resolved, 2);
        assert_eq!(statuses.wildcard_cname, 1);
        assert_eq!(statuses.timeout, 1);
        assert_eq!(statuses.unresolved, 0);

        let mut reasons = WildcardDecisionStats::default();
        add_wildcard_reason_stat(&mut reasons, WildcardReason::IpOverlap);
        add_wildcard_reason_stat(&mut reasons, WildcardReason::CnameMatch);
        add_wildcard_reason_stat(&mut reasons, WildcardReason::CnameMatch);
        add_wildcard_reason_stat(&mut reasons, WildcardReason::TimeoutInferred);

        assert_eq!(reasons.ip_overlap, 1);
        assert_eq!(reasons.cname_match, 2);
        assert_eq!(reasons.timeout_inferred, 1);
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
    fn resolver_health_flags_after_threshold() {
        let h = ResolverHealthCounters::default();
        // 20 samples, all hard timeouts (no answer, no NX, yes timeout) →
        // ratio 1.0 > 0.5 → flagged.
        for _ in 0..20 {
            apply_resolver_health_sample(&h, 0.5, 20, false, true, false);
        }
        assert!(h.flagged.load(Ordering::Relaxed));
    }

    #[test]
    fn resolver_health_below_threshold_stays_healthy() {
        let h = ResolverHealthCounters::default();
        // 1 in 4 timeouts → 25% < 50% → no flag.
        for i in 0..40 {
            let timeout = i % 4 == 0;
            apply_resolver_health_sample(&h, 0.5, 20, !timeout, timeout, false);
        }
        assert!(!h.flagged.load(Ordering::Relaxed));
    }

    #[test]
    fn resolver_health_nxdomain_does_not_count_as_timeout() {
        let h = ResolverHealthCounters::default();
        // 50 NXDOMAIN replies should NOT increment the timeout counter,
        // even if the resolver also surfaced an internal timeout.
        for _ in 0..50 {
            apply_resolver_health_sample(&h, 0.5, 20, false, true, true);
        }
        assert!(!h.flagged.load(Ordering::Relaxed));
        assert_eq!(h.timeouts.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn resolver_health_requires_min_samples() {
        let h = ResolverHealthCounters::default();
        // 19 hard timeouts but min_samples=20 — no flag yet.
        for _ in 0..19 {
            apply_resolver_health_sample(&h, 0.5, 20, false, true, false);
        }
        assert!(!h.flagged.load(Ordering::Relaxed));
        // One more puts it over.
        apply_resolver_health_sample(&h, 0.5, 20, false, true, false);
        assert!(h.flagged.load(Ordering::Relaxed));
    }

    #[test]
    fn resolver_health_threshold_at_one_disables_gate() {
        let h = ResolverHealthCounters::default();
        for _ in 0..100 {
            apply_resolver_health_sample(&h, 1.0, 1, false, true, false);
        }
        assert!(!h.flagged.load(Ordering::Relaxed));
    }

    #[test]
    fn hijack_outcome_answer_means_hijacked() {
        let ans = HostAnswers {
            ips: HashSet::from(["1.2.3.4".parse().unwrap()]),
            any_answer: true,
            ..Default::default()
        };
        assert!(is_hijacked_outcome(&Ok(ans)));
    }

    #[test]
    fn hijack_outcome_nxdomain_is_clean() {
        let ans = HostAnswers {
            all_nxdomain: true,
            ..Default::default()
        };
        assert!(!is_hijacked_outcome(&Ok(ans)));
    }

    #[tokio::test]
    async fn hijack_outcome_timeout_is_ambiguous_not_hijacked() {
        // We deliberately *don't* flag on timeout — could be network blip,
        // could be a strict resolver that just drops bogon names. Build a
        // real Elapsed via tokio::time::timeout because the error type has
        // no public constructor.
        let outcome: Result<HostAnswers, _> =
            tokio::time::timeout(Duration::from_millis(1), async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                HostAnswers::default()
            })
            .await;
        assert!(outcome.is_err());
        assert!(!is_hijacked_outcome(&outcome));
    }

    #[test]
    fn resolver_health_sticky_after_flag() {
        let h = ResolverHealthCounters::default();
        for _ in 0..20 {
            apply_resolver_health_sample(&h, 0.5, 20, false, true, false);
        }
        assert!(h.flagged.load(Ordering::Relaxed));
        // Even if subsequent samples are all successful, the flag stays.
        for _ in 0..1000 {
            apply_resolver_health_sample(&h, 0.5, 20, true, false, false);
        }
        assert!(h.flagged.load(Ordering::Relaxed));
    }

    #[test]
    fn sig_to_state_maps_correctly() {
        assert!(matches!(sig_to_state(None), ParentState::Clean));
        let sig = WildcardSignature {
            root: "example.com".into(),
            ips: Arc::new(HashSet::from(["1.2.3.4".parse().unwrap()])),
            cnames: Arc::new(HashSet::new()),
        };
        assert!(matches!(sig_to_state(Some(sig)), ParentState::Wildcard(_)));
    }
}
