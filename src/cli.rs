//! Unix-style CLI wired around the library's pipeline stages.
//!
//! Each subcommand runs: extract → classify → dedupe → (scope) → (dns) →
//! filter → output. Default input is stdin; default output is plain canonical
//! values, one per line. `--json` emits JSON-lines.

use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use assetcanon::{
    classify::classify_str,
    dedupe::dedupe,
    dns::{DnsConfig, DnsValidator},
    extract,
    model::{Asset, AssetKind, DnsStatus, ScopeStatus},
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
    Clean(CleanArgs),
    /// Emit the unique registrable apex domains.
    Apex(SimpleArgs),
    /// Emit fully qualified hosts (apex + subdomain; wildcards and IPs included unless filtered).
    Fqdn(SimpleArgs),
    /// Emit only subdomains (excludes apexes, wildcards, IPs).
    Subs(SimpleArgs),
    /// Emit only wildcard entries like `*.example.com`.
    Wildcards(SimpleArgs),
    /// Classify every input and emit JSON (or tab-separated) records.
    Classify(ClassifyArgs),
    /// Filter input against scope rules.
    Scope(ScopeArgs),
    /// Perform DNS validation with wildcard filtering.
    Dns(DnsArgs),
}

// ---------------------------------------------------------------------------
// Shared argument groups

#[derive(Args, Clone)]
struct InputOpts {
    /// Input files. Reads stdin if none are given (or if a single `-` is given).
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Additional input file (repeatable). Same semantics as positional FILE.
    #[arg(short = 'i', long = "input", action = ArgAction::Append, value_name = "FILE")]
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

    /// Comma-separated `ip:port` resolvers (e.g. `1.1.1.1:53,8.8.8.8:53`).
    #[arg(long, value_name = "LIST")]
    resolvers: Option<String>,

    /// Maximum in-flight validations.
    #[arg(long, default_value_t = 100)]
    concurrency: usize,

    /// Per-query timeout in seconds.
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    /// Retry attempts per query.
    #[arg(long, default_value_t = 2)]
    retries: u8,

    /// Random probes per parent when building a wildcard signature.
    #[arg(long, default_value_t = 8)]
    wildcard_tests: usize,

    /// Disable wildcard filtering.
    #[arg(long)]
    no_wildcard_filter: bool,

    /// Resolvers queried per host for consistency checking (≥ 2 enables Shaky detection).
    #[arg(long, default_value_t = 2)]
    consistency_checks: usize,

    /// Parallelism cap for the wildcard-signature precompute phase. 0 = auto
    /// (max(concurrency/4, 16)). Keep this lower than --concurrency to avoid
    /// resolver rate-limiting during the initial probe burst.
    #[arg(long, default_value_t = 0)]
    probe_concurrency: usize,

    /// Runtime zone short-circuit: once a parent accumulates ≥ --flaky-min-samples
    /// hosts and its timeout ratio hits --flaky-threshold, remaining hosts in
    /// the zone are marked `timeout` without issuing a DNS query. Saves time
    /// on graveyards (e.g. `*-fe-server.foo.com` from an old gau dump).
    #[arg(long, default_value_t = 0.8)]
    flaky_threshold: f32,

    #[arg(long, default_value_t = 10)]
    flaky_min_samples: usize,

    /// Disable the zone short-circuits (dead zone + flaky zone). All host
    /// queries are always issued.
    #[arg(long)]
    no_skip_zones: bool,

    /// Disable the "timeout under a confirmed-wildcard parent → WildcardIp"
    /// inference. Default ON — under a wildcard zone, a timeout is almost
    /// always a rate-limit packet drop, not a genuinely unreachable host.
    /// Use this for strict "observed only" semantics.
    #[arg(long)]
    no_infer_wildcard_timeout: bool,

    /// Only emit records matching these statuses (repeatable). Default: all.
    #[arg(long = "status", action = ArgAction::Append, value_name = "STATUS")]
    statuses: Vec<String>,

    /// Also print a summary of detected wildcard roots, dead zones, and flaky
    /// zones to stderr.
    #[arg(long)]
    report_wildcards: bool,
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
        Command::Dns(a) => run_dns(a).await,
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
            a.canonical,
            a.registrable.as_deref().unwrap_or(""),
            a.reason.as_deref().unwrap_or(""),
        )?;
    }
    w.flush()?;
    Ok(())
}

async fn run_scope(args: ScopeArgs) -> anyhow::Result<()> {
    let rules_raw = read_path_or_stdin(&args.rules)?;
    let matcher = ScopeMatcher::compile(rules_raw.lines());

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
        if args.show_rule {
            writeln!(w, "{}\t{}", a.canonical, hits.join(","))?;
        } else {
            writeln!(w, "{}", a.canonical)?;
        }
    }
    w.flush()?;
    Ok(())
}

async fn run_dns(args: DnsArgs) -> anyhow::Result<()> {
    let assets = pipeline(&args.input, &args.output).await?;
    let config = build_dns_config(&args)?;
    let validator = DnsValidator::new(config)?;
    let report = validator.validate(assets).await;

    let statuses: Option<Vec<DnsStatus>> = if args.statuses.is_empty() {
        None
    } else {
        let parsed: anyhow::Result<Vec<_>> =
            args.statuses.iter().map(|s| parse_status(s)).collect();
        Some(parsed?)
    };

    let filtered: Vec<Asset> = match statuses {
        None => report.assets,
        Some(allowed) => report
            .assets
            .into_iter()
            .filter(|a| allowed.contains(&a.dns))
            .collect(),
    };

    if args.report_wildcards {
        if !report.wildcard_roots.is_empty() {
            eprintln!("# wildcard roots ({} detected):", report.wildcard_roots.len());
            for r in &report.wildcard_roots {
                eprintln!("  {r}");
            }
        }
        if !report.dead_zones.is_empty() {
            eprintln!("# dead zones ({} detected — all probes timed out):", report.dead_zones.len());
            for z in &report.dead_zones {
                eprintln!("  {z}");
            }
        }
        if !report.flaky_zones.is_empty() {
            eprintln!(
                "# flaky zones ({} detected — short-circuited mid-run after {:.0}% timeout ratio):",
                report.flaky_zones.len(),
                args.flaky_threshold * 100.0,
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
        writeln!(w, "{}\t{}", a.canonical, dns_status_str(&a.dns))?;
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
    let assets = if output.no_dedupe { assets } else { dedupe(assets) };
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
    write_lines(assets.iter().map(|a| a.canonical.as_str()))
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
    if let Some(list) = &args.resolvers {
        let parsed: anyhow::Result<Vec<SocketAddr>> = list
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                // Allow `ip` without port → default :53
                if s.contains(':') {
                    s.parse::<SocketAddr>().map_err(|e| {
                        anyhow::anyhow!("invalid resolver '{s}': {e}")
                    })
                } else {
                    format!("{s}:53").parse::<SocketAddr>().map_err(|e| {
                        anyhow::anyhow!("invalid resolver '{s}': {e}")
                    })
                }
            })
            .collect();
        cfg.resolvers = parsed?;
    }
    cfg.concurrency = args.concurrency.max(1);
    cfg.timeout = Duration::from_secs(args.timeout.max(1));
    cfg.retries = args.retries.max(1);
    cfg.wildcard_tests = args.wildcard_tests.max(1);
    cfg.wildcard_filter = !args.no_wildcard_filter;
    cfg.consistency_checks = args.consistency_checks.max(1);
    cfg.probe_concurrency = args.probe_concurrency;
    if args.no_skip_zones {
        cfg.flaky_min_samples = 0;
    } else {
        cfg.flaky_threshold = args.flaky_threshold;
        cfg.flaky_min_samples = args.flaky_min_samples;
    }
    cfg.infer_wildcard_on_timeout = !args.no_infer_wildcard_timeout;
    Ok(cfg)
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

