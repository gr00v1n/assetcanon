//! Unix-style CLI wired around the library's pipeline stages.
//!
//! Each subcommand runs: extract → classify → dedupe → (scope) → (dns) →
//! filter → output. Default input is stdin; default output is plain canonical
//! values, one per line. `--json` emits JSON-lines.

use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use assetcanon::{
    classify::classify_str,
    dedupe::dedupe,
    dns::{
        check_resolvers, DnsConfig, DnsStats, DnsValidator, ResolverCheckConfig, ResolverHealth,
        ResolverHealthStatus,
    },
    extract,
    model::{Asset, AssetKind, DnsStatus, ScopeStatus, WildcardReason},
    scope::ScopeMatcher,
};

// ---------------------------------------------------------------------------
// Top-level CLI

#[derive(Parser)]
#[command(
    name = "assetcanon",
    version,
    about = "Domain/asset canonicalization + DNS validation",
    long_about = None,
    propagate_version = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Emit deduplicated canonical forms (apex + subdomain + wildcard + ip).
    /// `hosts` and `extract` are silent aliases kept for script compat.
    #[command(alias = "hosts", alias = "extract")]
    Clean(CleanArgs),
    /// Emit the unique registrable apex domains.
    Apex(SimpleArgs),
    /// Emit fully qualified domain names (apex + subdomain; drops wildcards and IPs).
    Fqdn(SimpleArgs),
    /// Emit only subdomains (excludes apexes, wildcards, IPs).
    Subs(SimpleArgs),
    /// Emit only wildcard entries like `*.example.com`.
    Wildcards(SimpleArgs),
    /// Classify every input and emit JSON (or tab-separated) records.
    Classify(ClassifyArgs),
    /// Filter input against scope rules.
    Scope(ScopeArgs),
    /// DNS-clean hosts into trusted / review / ignored classes.
    Dns(Box<DnsArgs>),
    /// Check resolver health and exit (NXDOMAIN-hijack, latency, accuracy).
    #[command(name = "resolver-check")]
    ResolverCheck(ResolverCheckArgs),
}

// ---------------------------------------------------------------------------
// Shared argument groups

#[derive(Args, Clone)]
struct InputOpts {
    /// Input files. Reads stdin if none are given (or if a single `-` is given).
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Additional input file (repeatable, hidden — positional FILE is preferred).
    #[arg(short = 'i', long = "input", action = ArgAction::Append, value_name = "FILE", hide = true)]
    extra: Vec<PathBuf>,

    /// How to parse the input.
    #[arg(long, value_enum, default_value_t = InputFormat::Text)]
    input_format: InputFormat,

    /// Restrict JSON scanning to these top-level keys (repeatable).
    /// Only applies when --input-format=json.
    #[arg(long = "json-field", action = ArgAction::Append, value_name = "KEY")]
    json_fields: Vec<String>,

    /// Worker threads for classify/extract. 0 = auto (all CPU cores), 1 = single-threaded.
    #[arg(long, default_value_t = 0)]
    threads: usize,

    /// Chunk size (lines) for parallel classification. Larger = less overhead, smaller = better balance.
    #[arg(long, default_value_t = 4096)]
    chunk_size: usize,
}

#[derive(Args, Clone)]
struct OutputOpts {
    /// Emit JSON-lines instead of plain canonical values.
    #[arg(short = 'j', long)]
    json: bool,

    /// Include garbage records (with their `reason`).
    #[arg(long)]
    include_garbage: bool,

    /// Skip semantic dedupe (canonical-key merge and wildcard coverage).
    #[arg(long)]
    no_dedupe: bool,

    /// In plain-text output, print only the host/IP and drop any explicit port.
    /// JSON output keeps the structured `canonical` and `port` fields unchanged.
    #[arg(long)]
    no_port: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum InputFormat {
    /// Dirty free text — URLs, IPs, and domains extracted via regex.
    Text,
    /// One URL / host per line.
    Urls,
    /// JSON or JSON-lines. Use --json-field to narrow scanned keys.
    Json,
    /// Lines of `DNS:foo.com, DNS:bar.com` (SAN extensions).
    San,
}

#[derive(Args)]
struct CleanArgs {
    #[command(flatten)]
    input: InputOpts,
    #[command(flatten)]
    output: OutputOpts,

    /// Restrict to these kinds (repeatable). Default: all host-like kinds.
    #[arg(long = "include", value_enum, action = ArgAction::Append)]
    include: Vec<KindArg>,
}

#[derive(Args)]
struct SimpleArgs {
    #[command(flatten)]
    input: InputOpts,
    #[command(flatten)]
    output: OutputOpts,
}

#[derive(Args)]
struct ClassifyArgs {
    #[command(flatten)]
    input: InputOpts,
    #[command(flatten)]
    output: OutputOpts,
}

#[derive(Args)]
struct ScopeArgs {
    #[command(flatten)]
    input: InputOpts,
    #[command(flatten)]
    output: OutputOpts,

    /// Scope rules file (one rule per line). Use `-` for stdin (mutually exclusive with piped input).
    #[arg(long, value_name = "FILE")]
    rules: PathBuf,

    /// Strict matching: subdomain rules don't cover their descendants.
    #[arg(long)]
    strict: bool,

    /// Match scope rules with explicit ports. By default scope is host-based,
    /// so `api.example.com` matches `api.example.com:8443`.
    #[arg(long)]
    respect_port: bool,

    /// Invert: show out-of-scope records instead of in-scope.
    #[arg(long)]
    invert: bool,

    /// Annotate each emitted line/record with the matched rule(s).
    #[arg(long)]
    show_rule: bool,
}

#[derive(Args)]
struct DnsArgs {
    #[command(flatten)]
    input: InputOpts,
    #[command(flatten)]
    output: OutputOpts,

    // ----- Resolvers -----
    /// Comma-separated `ip:port` resolvers (e.g. `1.1.1.1:53,8.8.8.8:53`).
    #[arg(long, value_name = "LIST", help_heading = "Resolvers")]
    resolvers: Option<String>,

    /// Resolver file, one resolver per line. Empty lines and `#` comments ignored.
    /// Entries may be `ip`, `ip:port`, or `[ipv6]:port`; bare IPs default to port 53.
    #[arg(long = "resolver-file", action = ArgAction::Append, value_name = "FILE", help_heading = "Resolvers")]
    resolver_files: Vec<PathBuf>,

    // ----- Profile -----
    /// Higher parallelism preset for large lists and strong resolver pools.
    #[arg(long, conflicts_with = "safe", help_heading = "Profile")]
    fast: bool,

    /// Strict observed-only mode: disables timeout-under-wildcard inference
    /// and zone short-circuiting. Expect more `timeout` / `shaky` statuses.
    #[arg(long, help_heading = "Profile")]
    strict: bool,

    // ----- Output class -----
    /// Show medium-confidence DNS results that should be manually verified.
    /// Default output shows only high-confidence real assets.
    #[arg(long, conflicts_with_all = ["all", "resolved_only"], help_heading = "Output")]
    review: bool,

    /// Show every DNS result, including likely-fake and failed records.
    #[arg(long, conflicts_with_all = ["review", "resolved_only"], help_heading = "Output")]
    all: bool,

    /// Advanced compatibility: only emit records matching these statuses
    /// (repeatable). Prefer default / --review / --all for normal use.
    #[arg(long = "status", action = ArgAction::Append, value_name = "STATUS", hide = true)]
    statuses: Vec<String>,

    /// Deprecated: default DNS output is already resolved-only/high-confidence.
    #[arg(long, alias = "real", hide = true)]
    resolved_only: bool,

    // ----- Reporting -----
    /// Also print a summary of detected wildcard roots, dead zones, and flaky
    /// zones to stderr.
    #[arg(long, help_heading = "Reporting")]
    report_wildcards: bool,

    /// Print aggregate DNS stats (query counts, status distribution, wildcard
    /// reasons, short-circuit counts) to stderr after validation.
    #[arg(long, help_heading = "Reporting")]
    stats: bool,

    /// Write aggregate DNS stats as JSON to this file.
    #[arg(long = "stats-json", value_name = "FILE", help_heading = "Reporting")]
    stats_json: Option<PathBuf>,

    /// In plain-text DNS output, show class/status plus key=value explanation
    /// fields (wildcard root/reason, matching CNAME, resolver disagreement,
    /// zone short-circuit source). JSON output always includes these fields.
    #[arg(long, help_heading = "Reporting")]
    explain: bool,

    // ----- Tuning -----
    /// Maximum in-flight validations. Default: 50 (`--fast`: 200).
    #[arg(long, help_heading = "Tuning")]
    concurrency: Option<usize>,

    /// Resolvers queried per host for consistency checking (≥ 2 enables
    /// Shaky detection). Default: 2.
    #[arg(long, help_heading = "Tuning")]
    consistency_checks: Option<usize>,

    // ----- Hidden: default-implied or rarely-touched advanced flags -----
    /// Default profile — kept for explicit readability (this is already the default).
    #[arg(long, hide = true)]
    safe: bool,

    /// Per-query timeout in seconds. Default: 5 (`--fast`: 3).
    #[arg(long, hide = true)]
    timeout: Option<u64>,

    /// Retry attempts per query. Default: 2.
    #[arg(long, hide = true)]
    retries: Option<u8>,

    /// Random probes per parent when building a wildcard signature. Default: 6.
    #[arg(long, hide = true)]
    wildcard_tests: Option<usize>,

    /// Disable wildcard filtering entirely.
    #[arg(long, hide = true)]
    no_wildcard_filter: bool,

    /// Parallelism cap for the wildcard-signature precompute phase.
    #[arg(long, hide = true)]
    probe_concurrency: Option<usize>,

    /// Runtime flaky-zone short-circuit ratio. Default: 0.8.
    #[arg(long, hide = true)]
    flaky_threshold: Option<f32>,

    /// Minimum host samples before runtime flaky-zone short-circuiting.
    #[arg(long, hide = true)]
    flaky_min_samples: Option<usize>,

    /// Disable dead-zone + flaky-zone short-circuits. All host queries
    /// always issued.
    #[arg(long, hide = true)]
    no_skip_zones: bool,

    /// Disable the "timeout under a confirmed-wildcard parent → WildcardIp"
    /// inference. Use for strict "observed only" semantics.
    #[arg(long, hide = true)]
    no_infer_wildcard_timeout: bool,

    // ----- Hidden compat shim: `assetcanon resolver-check` replaces these -----
    /// Deprecated: use `assetcanon resolver-check` instead.
    #[arg(long, hide = true)]
    check_resolvers: bool,

    #[arg(long = "check-domain", action = ArgAction::Append, value_name = "DOMAIN", hide = true)]
    check_domains: Vec<String>,

    #[arg(long = "check-rounds", default_value_t = 5, hide = true)]
    check_rounds: usize,

    #[arg(long = "check-concurrency", hide = true)]
    check_concurrency: Option<usize>,
}

/// New dedicated subcommand for resolver health checks. Cleaner than
/// piggy-backing on `dns --check-resolvers` (which still works for script
/// compat but is hidden from `--help`).
#[derive(Args)]
struct ResolverCheckArgs {
    /// Emit JSON-lines instead of the plain summary table.
    #[arg(short = 'j', long)]
    json: bool,

    /// Comma-separated `ip:port` resolvers.
    #[arg(long, value_name = "LIST")]
    resolvers: Option<String>,

    /// Resolver file (one resolver per line).
    #[arg(long = "resolver-file", action = ArgAction::Append, value_name = "FILE")]
    resolver_files: Vec<PathBuf>,

    /// Positive-resolution domains used for the check (repeatable).
    /// Defaults: example.com, iana.org.
    #[arg(long = "domain", alias = "check-domain", action = ArgAction::Append, value_name = "DOMAIN")]
    domains: Vec<String>,

    /// Rounds per resolver. Default: 5.
    #[arg(long, alias = "check-rounds", default_value_t = 5)]
    rounds: usize,

    /// Concurrency for the health check itself. Default: min(resolver_count, 50).
    #[arg(long, alias = "check-concurrency")]
    concurrency: Option<usize>,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum KindArg {
    Apex,
    Subdomain,
    Wildcard,
    Ip,
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Clean(a) => run_clean(a).await,
        Command::Apex(a) => run_apex(a).await,
        Command::Fqdn(a) => run_fqdn(a).await,
        Command::Subs(a) => run_subs(a).await,
        Command::Wildcards(a) => run_wildcards(a).await,
        Command::Classify(a) => run_classify(a).await,
        Command::Scope(a) => run_scope(a).await,
        Command::Dns(a) => run_dns(*a).await,
        Command::ResolverCheck(a) => run_resolver_check(a).await,
    };
    match result {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("assetcanon: {e:#}");
            ExitCode::from(1)
        }
    }
}

// ---------------------------------------------------------------------------
// Commands

async fn run_clean(args: CleanArgs) -> anyhow::Result<()> {
    let assets = pipeline(&args.input, &args.output).await?;
    let include = if args.include.is_empty() {
        vec![
            AssetKind::Apex,
            AssetKind::Subdomain,
            AssetKind::Wildcard,
            AssetKind::Ip,
        ]
    } else {
        args.include
            .iter()
            .map(|k| match k {
                KindArg::Apex => AssetKind::Apex,
                KindArg::Subdomain => AssetKind::Subdomain,
                KindArg::Wildcard => AssetKind::Wildcard,
                KindArg::Ip => AssetKind::Ip,
            })
            .collect()
    };
    let filtered: Vec<Asset> = assets
        .into_iter()
        .filter(|a| include.contains(&a.kind))
        .collect();
    emit(&filtered, &args.output)
}

async fn run_apex(args: SimpleArgs) -> anyhow::Result<()> {
    let assets = pipeline(&args.input, &args.output).await?;
    if args.output.json {
        let filtered: Vec<Asset> = assets
            .into_iter()
            .filter(|a| a.kind == AssetKind::Apex)
            .collect();
        return emit(&filtered, &args.output);
    }
    // Plain mode: unique registrable apex strings, sorted.
    let mut apexes: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for a in assets {
        let apex = match a.kind {
            AssetKind::Apex => a.canonical.split(':').next().unwrap_or("").to_string(),
            AssetKind::Subdomain | AssetKind::Wildcard => a.registrable.clone().unwrap_or_default(),
            _ => continue,
        };
        if apex.is_empty() {
            continue;
        }
        if seen.insert(apex.clone()) {
            apexes.push(apex);
        }
    }
    apexes.sort();
    write_lines(apexes.iter().map(String::as_str))
}

async fn run_fqdn(args: SimpleArgs) -> anyhow::Result<()> {
    let assets = pipeline(&args.input, &args.output).await?;
    let filtered: Vec<Asset> = assets
        .into_iter()
        .filter(|a| matches!(a.kind, AssetKind::Apex | AssetKind::Subdomain))
        .collect();
    emit(&filtered, &args.output)
}

async fn run_subs(args: SimpleArgs) -> anyhow::Result<()> {
    let assets = pipeline(&args.input, &args.output).await?;
    let filtered: Vec<Asset> = assets
        .into_iter()
        .filter(|a| a.kind == AssetKind::Subdomain)
        .collect();
    emit(&filtered, &args.output)
}

async fn run_wildcards(args: SimpleArgs) -> anyhow::Result<()> {
    let assets = pipeline(&args.input, &args.output).await?;
    let filtered: Vec<Asset> = assets
        .into_iter()
        .filter(|a| a.kind == AssetKind::Wildcard)
        .collect();
    emit(&filtered, &args.output)
}

async fn run_classify(args: ClassifyArgs) -> anyhow::Result<()> {
    let assets = pipeline(&args.input, &args.output).await?;
    if args.output.json {
        return emit_json(&assets);
    }
    // Tab-separated: kind, canonical, registrable, reason
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    for a in &assets {
        writeln!(
            w,
            "{}\t{}\t{}\t{}",
            a.kind.as_str(),
            canonical_for_output(a, &args.output),
            a.registrable.as_deref().unwrap_or(""),
            a.reason.as_deref().unwrap_or(""),
        )?;
    }
    w.flush()?;
    Ok(())
}

async fn run_scope(args: ScopeArgs) -> anyhow::Result<()> {
    let rules_raw = read_path_or_stdin(&args.rules)?;
    let matcher = ScopeMatcher::compile_with_options(rules_raw.lines(), args.respect_port);

    let assets = pipeline(&args.input, &args.output).await?;

    // Apply scope matching.
    let mut tagged: Vec<(Asset, Vec<String>)> = assets
        .into_iter()
        .map(|a| {
            let hits = matcher
                .matches(&a, args.strict)
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>();
            let mut a = a;
            a.scope = if hits.is_empty() {
                ScopeStatus::OutOfScope
            } else {
                ScopeStatus::InScope
            };
            (a, hits)
        })
        .collect();

    if !args.invert {
        tagged.retain(|(a, _)| a.scope == ScopeStatus::InScope);
    } else {
        tagged.retain(|(a, _)| a.scope == ScopeStatus::OutOfScope);
    }

    if args.output.json {
        let assets: Vec<_> = tagged.into_iter().map(|(a, _)| a).collect();
        return emit_json(&assets);
    }

    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    for (a, hits) in &tagged {
        let canonical = canonical_for_output(a, &args.output);
        if args.show_rule {
            writeln!(w, "{}\t{}", canonical, hits.join(","))?;
        } else {
            writeln!(w, "{}", canonical)?;
        }
    }
    w.flush()?;
    Ok(())
}

async fn run_dns(args: DnsArgs) -> anyhow::Result<()> {
    if args.check_resolvers {
        let config = build_dns_config(&args)?;
        let check_config = build_resolver_check_config(&args);
        let results = check_resolvers(config, check_config).await;
        let has_bad = results.iter().any(|r| {
            matches!(
                r.status,
                ResolverHealthStatus::Bad | ResolverHealthStatus::Error
            )
        });
        emit_resolver_health(&results, args.output.json)?;
        if has_bad {
            anyhow::bail!("resolver health check found bad/error resolvers");
        }
        return Ok(());
    }

    let assets = pipeline(&args.input, &args.output).await?;
    let config = build_dns_config(&args)?;
    let validator = std::sync::Arc::new(DnsValidator::new(config)?);
    let report = validator.validate(assets).await;

    if args.stats {
        emit_dns_stats(&report.stats)?;
    }
    if let Some(path) = &args.stats_json {
        write_dns_stats_json(path, &report.stats)?;
    }

    let explicit_statuses: Option<Vec<DnsStatus>> = if args.statuses.is_empty() {
        None
    } else {
        if args.review || args.all || args.resolved_only {
            anyhow::bail!("--status cannot be combined with --review/--all/--resolved-only");
        }
        let parsed: anyhow::Result<Vec<_>> =
            args.statuses.iter().map(|s| parse_status(s)).collect();
        Some(parsed?)
    };

    let output_class = if args.all {
        DnsOutputClass::All
    } else if args.review {
        DnsOutputClass::Review
    } else {
        // `--resolved-only/--real` is kept as a hidden compatibility alias;
        // it now matches the default behavior.
        DnsOutputClass::Trusted
    };

    let filtered: Vec<Asset> = if let Some(allowed) = explicit_statuses {
        report
            .assets
            .into_iter()
            .filter(|a| allowed.contains(&a.dns))
            .collect()
    } else {
        report
            .assets
            .into_iter()
            .filter(|a| output_class.includes(a))
            .collect()
    };

    if args.report_wildcards {
        if !report.wildcard_roots.is_empty() {
            eprintln!(
                "# wildcard roots ({} detected):",
                report.wildcard_roots.len()
            );
            for r in &report.wildcard_roots {
                eprintln!("  {r}");
            }
        }
        if !report.dead_zones.is_empty() {
            eprintln!(
                "# dead zones ({} detected — all probes timed out):",
                report.dead_zones.len()
            );
            for z in &report.dead_zones {
                eprintln!("  {z}");
            }
        }
        if !report.flaky_zones.is_empty() {
            eprintln!(
                "# flaky zones ({} detected — short-circuited mid-run after {:.0}% timeout ratio):",
                report.flaky_zones.len(),
                flaky_threshold_for_report(&args) * 100.0,
            );
            for z in &report.flaky_zones {
                eprintln!("  {z}");
            }
        }
    }

    if args.output.json {
        return emit_json(&filtered);
    }

    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    for a in &filtered {
        if args.explain {
            let explanation = dns_explanation(a);
            if explanation.is_empty() {
                writeln!(
                    w,
                    "{}\t{}\t{}",
                    canonical_for_output(a, &args.output),
                    dns_bucket_str(dns_bucket(a)),
                    dns_status_str(&a.dns),
                )?;
            } else {
                writeln!(
                    w,
                    "{}\t{}\t{}\t{}",
                    canonical_for_output(a, &args.output),
                    dns_bucket_str(dns_bucket(a)),
                    dns_status_str(&a.dns),
                    explanation.join(" "),
                )?;
            }
        } else {
            writeln!(w, "{}", canonical_for_output(a, &args.output))?;
        }
    }
    w.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Pipeline glue

async fn pipeline(input: &InputOpts, output: &OutputOpts) -> anyhow::Result<Vec<Asset>> {
    init_rayon_pool(input.threads);
    let raw = read_inputs(input)?;
    let candidates = extract_candidates(input, &raw);
    let assets = classify_parallel(candidates, input.threads, input.chunk_size);
    let assets = if output.include_garbage {
        assets
    } else {
        assets
            .into_iter()
            .filter(|a| a.kind != AssetKind::Garbage)
            .collect()
    };
    let assets = if output.no_dedupe {
        assets
    } else {
        dedupe(assets)
    };
    Ok(assets)
}

/// Initialize rayon's global thread pool. `threads = 0` leaves the default
/// (all logical cores). Calling twice is a no-op — rayon returns an error
/// that we deliberately ignore so repeated CLI invocations in tests don't
/// blow up.
fn init_rayon_pool(threads: usize) {
    if threads == 0 {
        return;
    }
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global();
}

/// Classify candidates in parallel via rayon. Chunking keeps per-item
/// work-steal overhead negligible for the common case (classify_str ≈ 100 µs).
fn classify_parallel(candidates: Vec<String>, threads: usize, chunk_size: usize) -> Vec<Asset> {
    if threads == 1 || candidates.is_empty() {
        return candidates.iter().map(|s| classify_str(s)).collect();
    }
    use rayon::prelude::*;
    let chunk = chunk_size.max(1);
    let chunks: Vec<Vec<Asset>> = candidates
        .par_chunks(chunk)
        .map(|batch| batch.iter().map(|s| classify_str(s)).collect())
        .collect();
    chunks.into_iter().flatten().collect()
}

fn read_inputs(opts: &InputOpts) -> anyhow::Result<Vec<String>> {
    let mut paths: Vec<PathBuf> = Vec::new();
    paths.extend(opts.files.iter().cloned());
    paths.extend(opts.extra.iter().cloned());

    if paths.is_empty() || paths.iter().any(|p| p.as_os_str() == "-") {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        if paths.is_empty() {
            return Ok(vec![s]);
        }
        // Mix of stdin and files.
        let mut chunks = vec![s];
        for p in paths.iter().filter(|p| p.as_os_str() != "-") {
            chunks.push(fs::read_to_string(p)?);
        }
        return Ok(chunks);
    }

    let mut chunks = Vec::with_capacity(paths.len());
    for p in &paths {
        chunks.push(fs::read_to_string(p)?);
    }
    Ok(chunks)
}

fn extract_candidates(opts: &InputOpts, chunks: &[String]) -> Vec<String> {
    let fields_vec: Vec<&str> = opts.json_fields.iter().map(String::as_str).collect();
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for chunk in chunks {
        let part = match opts.input_format {
            InputFormat::Text => extract_text_maybe_parallel(chunk, opts.threads, opts.chunk_size),
            InputFormat::Urls => extract::from_urls(chunk.lines()),
            InputFormat::Json => extract::from_json(chunk, &fields_vec),
            InputFormat::San => extract::from_san(chunk.lines()),
        };
        for s in part {
            if seen.insert(s.clone()) {
                out.push(s);
            }
        }
    }
    out
}

/// Text mode is regex-heavy and scales poorly on large inputs when run on a
/// single string. When `threads != 1` we chunk the input by line boundaries
/// and run `from_text` on each chunk in parallel. URL/domain regexes don't
/// span newlines so the split is lossless.
fn extract_text_maybe_parallel(text: &str, threads: usize, chunk_size: usize) -> Vec<String> {
    // Cheap fallback: short inputs or explicit single-threaded mode.
    if threads == 1 || text.len() < 256 * 1024 {
        return extract::from_text(text);
    }
    use rayon::prelude::*;

    // Collect line byte-ranges so each chunk is a contiguous &str slice (no
    // copying). chunk_size is interpreted as "lines per parallel chunk".
    let mut line_starts: Vec<usize> = vec![0];
    for (i, b) in text.as_bytes().iter().enumerate() {
        if *b == b'\n' {
            line_starts.push(i + 1);
        }
    }
    if *line_starts.last().unwrap() < text.len() {
        line_starts.push(text.len());
    }
    let lines_per_chunk = chunk_size.max(256);
    let chunk_ranges: Vec<(usize, usize)> = line_starts
        .windows(lines_per_chunk + 1)
        .step_by(lines_per_chunk)
        .map(|w| (w[0], *w.last().unwrap()))
        .collect();

    // Edge case: input shorter than one chunk's worth of lines.
    if chunk_ranges.is_empty() {
        return extract::from_text(text);
    }

    let parts: Vec<Vec<String>> = chunk_ranges
        .par_iter()
        .map(|&(s, e)| extract::from_text(&text[s..e]))
        .collect();

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in parts {
        for s in p {
            if seen.insert(s.clone()) {
                out.push(s);
            }
        }
    }
    out
}

fn read_path_or_stdin(path: &PathBuf) -> anyhow::Result<String> {
    if path.as_os_str() == "-" {
        let mut s = String::new();
        io::stdin().lock().read_to_string(&mut s)?;
        return Ok(s);
    }
    Ok(fs::read_to_string(path)?)
}

// ---------------------------------------------------------------------------
// Output

fn emit(assets: &[Asset], opts: &OutputOpts) -> anyhow::Result<()> {
    if opts.json {
        return emit_json(assets);
    }
    let lines = assets.iter().map(|a| canonical_for_output(a, opts));
    write_lines(lines)
}

fn emit_json(assets: &[Asset]) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    for a in assets {
        let line = serde_json::to_string(a)?;
        w.write_all(line.as_bytes())?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

fn emit_resolver_health(results: &[ResolverHealth], json: bool) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    if json {
        for result in results {
            let line = serde_json::to_string(result)?;
            w.write_all(line.as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        return Ok(());
    }

    writeln!(
        w,
        "resolver\tstatus\tscore\tp50_ms\tmax_ms\tp95_ms\ttimeout_ratio\tpositive\tnxdomain\twildcard_pollution\treason"
    )?;
    for result in results {
        writeln!(
            w,
            "{}\t{}\t{}\t{}\t{}\t{}\t{:.2}\t{}/{}\t{}/{}\t{}/{}\t{}",
            result.resolver,
            resolver_health_status_str(result.status),
            result.score,
            opt_ms(result.latency.p50_ms),
            opt_ms(result.latency.max_ms),
            opt_ms(result.latency.p95_ms),
            result.timeout_ratio,
            result.checks.positive.passed,
            result.checks.positive.total,
            result.checks.nxdomain.passed,
            result.checks.nxdomain.total,
            result.checks.wildcard_pollution.passed,
            result.checks.wildcard_pollution.total,
            if result.reasons.is_empty() {
                "-".to_string()
            } else {
                result.reasons.join(",")
            },
        )?;
    }
    w.flush()?;
    Ok(())
}

fn emit_dns_stats(stats: &DnsStats) -> anyhow::Result<()> {
    let stderr = io::stderr();
    let mut w = BufWriter::new(stderr.lock());
    writeln!(w, "# dns stats")?;
    writeln!(w, "input_assets\t{}", stats.input_assets)?;
    writeln!(w, "dns_eligible_assets\t{}", stats.dns_eligible_assets)?;
    writeln!(w, "elapsed_ms\t{}", stats.elapsed_ms)?;
    writeln!(w, "probe_queries\t{}", stats.probe_queries)?;
    writeln!(w, "host_queries\t{}", stats.host_queries)?;
    writeln!(
        w,
        "signature_parents\ttotal={} wildcard={} clean={} dead={}",
        stats.signature_parents.total,
        stats.signature_parents.wildcard,
        stats.signature_parents.clean,
        stats.signature_parents.dead,
    )?;
    writeln!(
        w,
        "statuses\tunknown={} resolved={} unresolved={} wildcard_ip={} wildcard_cname={} mixed_wildcard={} shaky={} timeout={} error={}",
        stats.statuses.unknown,
        stats.statuses.resolved,
        stats.statuses.unresolved,
        stats.statuses.wildcard_ip,
        stats.statuses.wildcard_cname,
        stats.statuses.mixed_wildcard,
        stats.statuses.shaky,
        stats.statuses.timeout,
        stats.statuses.error,
    )?;
    writeln!(
        w,
        "wildcard_decisions\tip_overlap={} cname_match={} timeout_inferred={}",
        stats.wildcard_decisions.ip_overlap,
        stats.wildcard_decisions.cname_match,
        stats.wildcard_decisions.timeout_inferred,
    )?;
    writeln!(
        w,
        "resolver_disagreement\tanswer_vs_nxdomain={} answer_vs_timeout={} answer_vs_error={} distinct_ip_sets={} distinct_cname_sets={}",
        stats.resolver_disagreement.answer_vs_nxdomain,
        stats.resolver_disagreement.answer_vs_timeout,
        stats.resolver_disagreement.answer_vs_error,
        stats.resolver_disagreement.distinct_ip_sets,
        stats.resolver_disagreement.distinct_cname_sets,
    )?;
    writeln!(
        w,
        "short_circuits\tdead_zone={} flaky_zone={}",
        stats.short_circuits.dead_zone, stats.short_circuits.flaky_zone,
    )?;
    w.flush()?;
    Ok(())
}

fn write_dns_stats_json(path: &PathBuf, stats: &DnsStats) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(stats)?;
    fs::write(path, format!("{json}\n"))?;
    Ok(())
}

fn opt_ms(value: Option<u128>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
}

fn write_lines<I, S>(lines: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    for line in lines {
        w.write_all(line.as_ref().as_bytes())?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS helpers

fn build_dns_config(args: &DnsArgs) -> anyhow::Result<DnsConfig> {
    let mut cfg = DnsConfig::default();
    let resolvers = load_resolvers(args)?;
    if let Some(resolvers) = resolvers {
        cfg.resolvers = resolvers;
    }

    if args.fast {
        apply_fast_dns_preset(&mut cfg);
    }
    if args.strict {
        apply_strict_dns_preset(&mut cfg);
    }

    if let Some(concurrency) = args.concurrency {
        cfg.concurrency = concurrency.max(1);
    }
    if let Some(timeout) = args.timeout {
        cfg.timeout = Duration::from_secs(timeout.max(1));
    }
    if let Some(retries) = args.retries {
        cfg.retries = retries.max(1);
    }
    if let Some(wildcard_tests) = args.wildcard_tests {
        cfg.wildcard_tests = wildcard_tests.max(1);
    }
    cfg.wildcard_filter = !args.no_wildcard_filter;
    if let Some(consistency_checks) = args.consistency_checks {
        cfg.consistency_checks = consistency_checks.max(1);
    }
    if let Some(probe_concurrency) = args.probe_concurrency {
        cfg.probe_concurrency = probe_concurrency;
    }
    if args.no_skip_zones {
        cfg.flaky_min_samples = 0;
    } else {
        if let Some(flaky_threshold) = args.flaky_threshold {
            cfg.flaky_threshold = flaky_threshold;
        }
        if let Some(flaky_min_samples) = args.flaky_min_samples {
            cfg.flaky_min_samples = flaky_min_samples;
        }
    }
    if args.no_infer_wildcard_timeout {
        cfg.infer_wildcard_on_timeout = false;
    }
    Ok(cfg)
}

fn build_resolver_check_config(args: &DnsArgs) -> ResolverCheckConfig {
    let mut cfg = ResolverCheckConfig::default();
    if !args.check_domains.is_empty() {
        cfg.positive_domains = args.check_domains.clone();
    }
    cfg.rounds = args.check_rounds.max(1);
    cfg.concurrency = args.check_concurrency.unwrap_or(0);
    cfg
}

/// Build a minimal DnsConfig from the resolver-check subcommand's args.
/// Reuses the same resolver-loading code path so resolver files behave
/// identically across `dns` and `resolver-check`.
fn build_dns_config_for_check(args: &ResolverCheckArgs) -> anyhow::Result<DnsConfig> {
    let mut cfg = DnsConfig::default();
    let resolvers = load_resolver_list(args.resolvers.as_deref(), &args.resolver_files)?;
    if !resolvers.is_empty() {
        cfg.resolvers = resolvers;
    }
    Ok(cfg)
}

fn build_resolver_check_config_from_args(args: &ResolverCheckArgs) -> ResolverCheckConfig {
    let mut cfg = ResolverCheckConfig::default();
    if !args.domains.is_empty() {
        cfg.positive_domains = args.domains.clone();
    }
    cfg.rounds = args.rounds.max(1);
    cfg.concurrency = args.concurrency.unwrap_or(0);
    cfg
}

async fn run_resolver_check(args: ResolverCheckArgs) -> anyhow::Result<()> {
    let config = build_dns_config_for_check(&args)?;
    let check_config = build_resolver_check_config_from_args(&args);
    let results = check_resolvers(config, check_config).await;
    let has_bad = results.iter().any(|r| {
        matches!(
            r.status,
            ResolverHealthStatus::Bad | ResolverHealthStatus::Error
        )
    });
    emit_resolver_health(&results, args.json)?;
    if has_bad {
        anyhow::bail!("resolver health check found bad/error resolvers");
    }
    Ok(())
}

fn apply_fast_dns_preset(cfg: &mut DnsConfig) {
    cfg.concurrency = 200;
    cfg.timeout = Duration::from_secs(3);
    cfg.wildcard_tests = 8;
    cfg.probe_concurrency = 100;
    cfg.flaky_min_samples = 8;
}

fn apply_strict_dns_preset(cfg: &mut DnsConfig) {
    cfg.flaky_min_samples = 0;
    cfg.infer_wildcard_on_timeout = false;
}

fn flaky_threshold_for_report(args: &DnsArgs) -> f32 {
    args.flaky_threshold.unwrap_or_else(|| {
        let mut cfg = DnsConfig::default();
        if args.fast {
            apply_fast_dns_preset(&mut cfg);
        }
        cfg.flaky_threshold
    })
}

fn load_resolvers(args: &DnsArgs) -> anyhow::Result<Option<Vec<SocketAddr>>> {
    if args.resolvers.is_none() && args.resolver_files.is_empty() {
        return Ok(None);
    }
    let list = load_resolver_list(args.resolvers.as_deref(), &args.resolver_files)?;
    if list.is_empty() {
        anyhow::bail!("no resolvers provided after parsing --resolvers / --resolver-file");
    }
    Ok(Some(list))
}

/// Subcommand-agnostic resolver loader. Returns an empty Vec when neither
/// input is provided so callers can fall back to defaults.
fn load_resolver_list(inline: Option<&str>, files: &[PathBuf]) -> anyhow::Result<Vec<SocketAddr>> {
    let mut resolvers = Vec::new();

    if let Some(list) = inline {
        for (idx, raw) in list.split(',').enumerate() {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let resolver = parse_resolver(raw).map_err(|e| {
                anyhow::anyhow!(
                    "invalid resolver in --resolvers item {} ('{}'): {}",
                    idx + 1,
                    raw,
                    e
                )
            })?;
            push_resolver_unique(&mut resolvers, resolver);
        }
    }

    for path in files {
        let raw = fs::read_to_string(path)?;
        for (line_no, line) in raw.lines().enumerate() {
            let Some(line) = clean_resolver_line(line) else {
                continue;
            };
            let resolver = parse_resolver(line).map_err(|e| {
                anyhow::anyhow!(
                    "invalid resolver in {}:{} ('{}'): {}",
                    path.display(),
                    line_no + 1,
                    line,
                    e,
                )
            })?;
            push_resolver_unique(&mut resolvers, resolver);
        }
    }

    Ok(resolvers)
}

fn clean_resolver_line(line: &str) -> Option<&str> {
    let line = line
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(line)
        .trim();
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

fn parse_resolver(raw: &str) -> anyhow::Result<SocketAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        anyhow::bail!("empty resolver");
    }

    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(addr);
    }

    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }

    anyhow::bail!("expected ip, ip:port, or [ipv6]:port")
}

fn push_resolver_unique(resolvers: &mut Vec<SocketAddr>, resolver: SocketAddr) {
    if !resolvers.contains(&resolver) {
        resolvers.push(resolver);
    }
}

fn canonical_for_output(asset: &Asset, opts: &OutputOpts) -> String {
    if opts.no_port {
        host_without_port(asset)
    } else {
        asset.canonical.clone()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DnsBucket {
    /// High-confidence real asset; default DNS output.
    Trusted,
    /// Medium-confidence / ambiguous; should be manually verified.
    Review,
    /// Likely fake, dead, or not useful for a cleaned live-host list.
    Ignore,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DnsOutputClass {
    Trusted,
    Review,
    All,
}

impl DnsOutputClass {
    fn includes(self, asset: &Asset) -> bool {
        match self {
            DnsOutputClass::Trusted => dns_bucket(asset) == DnsBucket::Trusted,
            DnsOutputClass::Review => dns_bucket(asset) == DnsBucket::Review,
            DnsOutputClass::All => true,
        }
    }
}

fn dns_bucket(asset: &Asset) -> DnsBucket {
    match asset.dns {
        DnsStatus::Resolved => {
            if asset.confidence.unwrap_or(0.0) >= 0.8 {
                DnsBucket::Trusted
            } else {
                DnsBucket::Review
            }
        }
        DnsStatus::MixedWildcard | DnsStatus::Shaky => DnsBucket::Review,
        DnsStatus::WildcardIp
            if matches!(asset.wildcard_reason, Some(WildcardReason::TimeoutInferred)) =>
        {
            DnsBucket::Review
        }
        DnsStatus::Unknown
        | DnsStatus::Unresolved
        | DnsStatus::WildcardIp
        | DnsStatus::WildcardCname
        | DnsStatus::Timeout
        | DnsStatus::Error => DnsBucket::Ignore,
    }
}

fn dns_bucket_str(bucket: DnsBucket) -> &'static str {
    match bucket {
        DnsBucket::Trusted => "trusted",
        DnsBucket::Review => "review",
        DnsBucket::Ignore => "ignore",
    }
}

fn dns_explanation(asset: &Asset) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(root) = &asset.wildcard_root {
        out.push(format!("root={root}"));
    }
    if let Some(reason) = asset.wildcard_reason {
        out.push(format!("reason={}", wildcard_reason_str(reason)));
        if matches!(reason, WildcardReason::CnameMatch) {
            if let Some(cname) = asset.cnames.first() {
                out.push(format!("cname={cname}"));
            }
        }
    }
    if asset.wildcard_ip_overlap_count > 0 {
        out.push(format!("ip_overlap={}", asset.wildcard_ip_overlap_count));
    }
    if asset.wildcard_cname_overlap_count > 0 {
        out.push(format!(
            "cname_overlap={}",
            asset.wildcard_cname_overlap_count
        ));
    }
    if asset.wildcard_host_ip_count > 0 {
        out.push(format!("host_ips={}", asset.wildcard_host_ip_count));
    }
    if asset.wildcard_signature_ip_count > 0 {
        out.push(format!(
            "signature_ips={}",
            asset.wildcard_signature_ip_count
        ));
    }
    if asset.wildcard_signature_cname_count > 0 {
        out.push(format!(
            "signature_cnames={}",
            asset.wildcard_signature_cname_count
        ));
    }
    if asset.resolver_disagreement {
        out.push("resolver_disagreement=true".to_string());
    }
    if let Some(zone) = &asset.dead_zone {
        out.push(format!("dead_zone={zone}"));
    }
    if let Some(zone) = &asset.flaky_zone {
        out.push(format!("flaky_zone={zone}"));
    }
    if let Some(cdn) = &asset.cdn {
        out.push(format!("cdn={cdn}"));
    }
    if let Some(c) = asset.confidence {
        out.push(format!("confidence={c:.2}"));
    }
    out
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

fn parse_status(s: &str) -> anyhow::Result<DnsStatus> {
    let s = s.trim().to_ascii_lowercase();
    Ok(match s.as_str() {
        "unknown" => DnsStatus::Unknown,
        "resolved" => DnsStatus::Resolved,
        "unresolved" => DnsStatus::Unresolved,
        "wildcard_ip" | "wildcardip" => DnsStatus::WildcardIp,
        "wildcard_cname" | "wildcardcname" => DnsStatus::WildcardCname,
        "mixed_wildcard" | "mixedwildcard" => DnsStatus::MixedWildcard,
        "shaky" => DnsStatus::Shaky,
        "timeout" => DnsStatus::Timeout,
        "error" => DnsStatus::Error,
        other => anyhow::bail!("unknown dns status: {other}"),
    })
}

fn dns_status_str(s: &DnsStatus) -> &'static str {
    match s {
        DnsStatus::Unknown => "unknown",
        DnsStatus::Resolved => "resolved",
        DnsStatus::Unresolved => "unresolved",
        DnsStatus::WildcardIp => "wildcard_ip",
        DnsStatus::WildcardCname => "wildcard_cname",
        DnsStatus::MixedWildcard => "mixed_wildcard",
        DnsStatus::Shaky => "shaky",
        DnsStatus::Timeout => "timeout",
        DnsStatus::Error => "error",
    }
}

fn resolver_health_status_str(s: ResolverHealthStatus) -> &'static str {
    match s {
        ResolverHealthStatus::Ok => "ok",
        ResolverHealthStatus::Warn => "warn",
        ResolverHealthStatus::Bad => "bad",
        ResolverHealthStatus::Error => "error",
    }
}

fn wildcard_reason_str(reason: WildcardReason) -> &'static str {
    match reason {
        WildcardReason::IpOverlap => "ip_overlap",
        WildcardReason::CnameMatch => "cname_match",
        WildcardReason::TimeoutInferred => "timeout_inferred",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn dns_args_from(argv: &[&str]) -> DnsArgs {
        let cli = Cli::parse_from(argv);
        let Command::Dns(args) = cli.command else {
            panic!("expected dns command")
        };
        *args
    }

    #[test]
    fn resolver_parser_defaults_bare_ips_to_53() {
        assert_eq!(
            parse_resolver("1.1.1.1").unwrap(),
            "1.1.1.1:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_resolver("2606:4700:4700::1111").unwrap(),
            "[2606:4700:4700::1111]:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_resolver("1::1").unwrap(),
            "[1::1]:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn resolver_parser_accepts_explicit_ports() {
        assert_eq!(
            parse_resolver("8.8.8.8:5353").unwrap(),
            "8.8.8.8:5353".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_resolver("[2001:4860:4860::8888]:53").unwrap(),
            "[2001:4860:4860::8888]:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn resolver_file_lines_ignore_comments_and_blanks() {
        assert_eq!(clean_resolver_line("  # comment"), None);
        assert_eq!(clean_resolver_line(""), None);
        assert_eq!(clean_resolver_line("  9.9.9.9  # quad9"), Some("9.9.9.9"));
        assert_eq!(
            clean_resolver_line("\t1.1.1.1\t# cloudflare"),
            Some("1.1.1.1")
        );
        assert_eq!(clean_resolver_line("8.8.8.8:53   "), Some("8.8.8.8:53"));
    }

    #[test]
    fn dns_fast_preset_raises_parallelism() {
        let mut cfg = DnsConfig::default();
        apply_fast_dns_preset(&mut cfg);
        assert_eq!(cfg.concurrency, 200);
        assert_eq!(cfg.probe_concurrency, 100);
        assert_eq!(cfg.wildcard_tests, 8);
    }

    #[test]
    fn dns_strict_preset_disables_inference_and_flaky_short_circuit() {
        let mut cfg = DnsConfig::default();
        apply_strict_dns_preset(&mut cfg);
        assert!(!cfg.infer_wildcard_on_timeout);
        assert_eq!(cfg.flaky_min_samples, 0);
    }

    #[test]
    fn dns_option_overrides_apply_after_presets_independent_of_cli_order() {
        let args_a = dns_args_from(&[
            "assetcanon",
            "dns",
            "--fast",
            "--concurrency",
            "300",
            "--probe-concurrency",
            "120",
        ]);
        let args_b = dns_args_from(&[
            "assetcanon",
            "dns",
            "--concurrency",
            "300",
            "--probe-concurrency",
            "120",
            "--fast",
        ]);

        let cfg_a = build_dns_config(&args_a).unwrap();
        let cfg_b = build_dns_config(&args_b).unwrap();

        assert_eq!(cfg_a.concurrency, 300);
        assert_eq!(cfg_a.probe_concurrency, 120);
        assert_eq!(cfg_a.concurrency, cfg_b.concurrency);
        assert_eq!(cfg_a.probe_concurrency, cfg_b.probe_concurrency);
        assert_eq!(cfg_a.wildcard_tests, cfg_b.wildcard_tests);
    }

    #[test]
    fn real_alias_still_parses_but_is_hidden_from_help() {
        let args = dns_args_from(&["assetcanon", "dns", "--real"]);
        assert!(args.resolved_only);

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("dns")
            .expect("dns subcommand")
            .render_long_help()
            .to_string();
        assert!(!help.contains("--real"));
    }

    #[test]
    fn dns_bucket_routes_default_review_and_ignore_classes() {
        let mut trusted = classify_str("trusted.example.com");
        trusted.dns = DnsStatus::Resolved;
        trusted.confidence = Some(0.95);
        assert_eq!(dns_bucket(&trusted), DnsBucket::Trusted);
        assert!(DnsOutputClass::Trusted.includes(&trusted));

        let mut review = classify_str("review.example.com");
        review.dns = DnsStatus::MixedWildcard;
        review.wildcard_reason = Some(WildcardReason::IpOverlap);
        review.confidence = Some(0.5);
        assert_eq!(dns_bucket(&review), DnsBucket::Review);
        assert!(DnsOutputClass::Review.includes(&review));
        assert!(!DnsOutputClass::Trusted.includes(&review));

        let mut fake = classify_str("fake.example.com");
        fake.dns = DnsStatus::WildcardCname;
        fake.wildcard_reason = Some(WildcardReason::CnameMatch);
        fake.confidence = Some(0.95);
        assert_eq!(dns_bucket(&fake), DnsBucket::Ignore);
        assert!(!DnsOutputClass::Trusted.includes(&fake));
        assert!(!DnsOutputClass::Review.includes(&fake));
        assert!(DnsOutputClass::All.includes(&fake));
    }

    #[test]
    fn dns_explanation_formats_wildcard_and_zone_fields() {
        let mut asset = classify_str("api.example.com");
        asset.dns = DnsStatus::WildcardCname;
        asset.wildcard_root = Some("*.example.com".into());
        asset.wildcard_reason = Some(WildcardReason::CnameMatch);
        asset.cnames = vec!["cdn.example.net".into()];
        asset.wildcard_cname_overlap_count = 1;
        asset.wildcard_signature_cname_count = 2;
        asset.resolver_disagreement = true;
        asset.dead_zone = Some("old.example.com".into());
        asset.flaky_zone = Some("preview.example.com".into());

        assert_eq!(
            dns_explanation(&asset),
            vec![
                "root=*.example.com".to_string(),
                "reason=cname_match".to_string(),
                "cname=cdn.example.net".to_string(),
                "cname_overlap=1".to_string(),
                "signature_cnames=2".to_string(),
                "resolver_disagreement=true".to_string(),
                "dead_zone=old.example.com".to_string(),
                "flaky_zone=preview.example.com".to_string(),
            ]
        );
    }
}
