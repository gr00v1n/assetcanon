# assetcanon

Fast, Unix-style toolkit for cleaning and validating domain/asset lists.

`assetcanon` reads dirty input (URLs, hostnames, IPs, JSON, certificate SANs),
normalizes it, classifies each entry (apex / subdomain / wildcard / IP /
garbage), deduplicates, filters against scope rules, and — optionally — runs
DNS validation with a wildcard filter that is noticeably smarter than the
usual puredns port.

## Install

```sh
cargo install --path .
```

The binary embeds a current copy of the [Mozilla Public Suffix List](https://publicsuffix.org/),
so it runs fully offline for everything except the `dns` subcommand.

## Quick start

```sh
# Clean dirty input into canonical hosts.
cat raw.txt | assetcanon clean

# DNS-clean a host list. Default output is only high-confidence real assets.
cat hosts.txt | assetcanon dns

# Review ambiguous assets separately (CDN/IP-overlap, shaky resolver results, etc.).
cat hosts.txt | assetcanon dns --review --explain

# Use your own resolver pool, and check it when needed.
cat hosts.txt | assetcanon dns --resolver-file resolvers.txt
assetcanon resolver-check --resolver-file resolvers.txt
```

All commands accept stdin or file arguments. Default output is one canonical
value per line; `-j / --json` emits JSON-lines records with the full asset
metadata.

Plain-text output preserves explicit non-default ports by default (for example
`api.example.com:8443`). Add `--no-port` when you want only the host/IP portion.
JSON output keeps the structured `canonical` and `port` fields unchanged.

## Subcommands

| Command     | Purpose                                                                 |
|-------------|-------------------------------------------------------------------------|
| `clean`     | Canonicalize + dedupe everything host-like.                             |
| `hosts`     | Friendlier alias for `clean`; `extract` is accepted as an alias too.    |
| `apex`      | Unique registrable apexes.                                              |
| `fqdn`      | Fully-qualified domain names: apex + subdomain, drop wildcards/IPs.     |
| `subs`      | Subdomains only.                                                        |
| `wildcards` | `*.foo.com` entries only.                                               |
| `classify`  | Emit kind/canonical/registrable/reason records (JSON or TSV).           |
| `scope`     | Keep only entries that match a scope ruleset.                           |
| `dns`       | DNS-clean hosts into trusted / review / ignored classes.                |
| `resolver-check` | Diagnose resolver pool health before a large DNS run.              |

Run `assetcanon <cmd> --help` for the full flag set.

## Parallelism

Every subcommand accepts `--threads N` (default `0` = auto / all cores,
`1` = single-threaded). Two stages are parallelized:

- **Text-mode extraction.** The regex pass on dirty free text is split across
  cores by line-chunking. On a 108 MB `gau` dump this brings the extract step
  from ~50 s down to ~0.7 s (11 cores).
- **Classification.** `extract → classify` for each candidate runs in a rayon
  pool, with batching controlled by `--chunk-size` (default 4096 lines).

For structured input (`--input-format urls|json|san`) parallelization gives
a smaller win because the per-item work is trivial — file IO and
deduplication dominate.

## Input formats

The CLI accepts several input shapes via `--input-format`:

- `text` (default) — dirty free text; URLs/IPs/domains are pulled out with
  regex and cleaned.
- `urls` — one URL or host per line; each line is a candidate.
- `json` / JSON-lines — recursively walks every string value; narrow the scan
  with one or more `--json-field KEY` flags.
- `san` — lines of `DNS:foo.com, DNS:bar.com` (TLS certificate SAN format).

## DNS validation highlights

`assetcanon dns` hides the noisy DNS details behind three practical classes:

| Class | How to get it | Meaning |
|-------|---------------|---------|
| trusted | default `assetcanon dns` | High-confidence real assets. Plain output is host-only for easy piping. |
| review | `assetcanon dns --review --explain` | Ambiguous assets worth checking manually: CDN/IP-overlap, mixed wildcard, shaky resolver disagreement, timeout-inferred wildcard. |
| ignored | default hidden; use `--all --explain` for debugging | Likely fake or unusable: strong wildcard, unresolved, timeout/dead/flaky zone, protocol error. |

The internal status enum is still present in JSON and `--explain`, but normal
usage should not require learning every status. Use `--json` if you want the
structured fields (`dns`, `cdn`, `confidence`, wildcard evidence counts, etc.).

Internally, DNS validation layers several corrections on top of the puredns
wildcard-probing idea:

1. **Dual wildcard signature.** A parent domain's wildcard "fingerprint"
   records both the union of terminal IPs and the set of CNAME targets
   seen from random probes. CDN/SaaS wildcards that rotate IPs per query
   are caught via the stable CNAME target.
2. **Batch precompute with probe retry.** Every ancestor of every input
   host is collected up front and probed concurrently under a separate
   `--probe-concurrency` cap. Rounds that get rate-limited automatically
   retry, so a momentary burst doesn't produce false "no wildcard"
   verdicts.
3. **Dead zone detection.** Parents whose probes all time out (broken
   authoritative NS — very common for dead CI subzones in `gau` dumps)
   are marked dead; their descendants are short-circuited to `timeout`
   without issuing a DNS query.
4. **Runtime flaky zone short-circuit.** During host validation, the
   tool tracks timeout ratios per parent. Once a parent crosses the
   configured threshold, remaining hosts under it short-circuit too —
   huge speedup on stale historical host lists.
5. **Multi-resolver consistency.** Each host is queried through
   `--consistency-checks N` independent resolvers in parallel. If they
   disagree on a non-wildcard zone, the record is flagged `shaky`.
6. **Wildcard-timeout inference.** A host that times out under a
   confirmed-wildcard parent is labeled `wildcard_ip` rather than
   `timeout` — on a wildcard zone the timeout is almost always a
   rate-limit drop, not a real black hole. Disable with
   `--no-infer-wildcard-timeout`.
7. **Refined status enum.** `resolved`, `wildcard_ip`, `wildcard_cname`,
   `mixed_wildcard` (partial IP overlap — real host colocated with a
   wildcard zone, usually interesting), `shaky`, `timeout`,
   `unresolved`, `error`.

For advanced/debugging workflows, `--all --explain` prints every result with its
class and internal status:

```sh
assetcanon dns --all --explain < hosts.txt
```

Surface the discovered wildcard roots, dead zones, and flaky zones with
`--report-wildcards` (emitted to stderr).

For benchmarking and tuning, emit aggregate DNS stats without retaining
per-resolver payloads:

```sh
assetcanon dns --stats < hosts.txt
assetcanon dns --stats-json stats.json < hosts.txt
```

Stats include elapsed time, input and DNS-eligible asset counts, wildcard probe
query count, host query count, signature-parent states (`wildcard` / `clean` /
`dead`), DNS status distribution, wildcard decision reasons, resolver
disagreement types (`answer_vs_nxdomain`, `answer_vs_timeout`,
`answer_vs_error`, distinct IP/CNAME answer sets), and dead/flaky-zone
short-circuit counts. `--stats` writes a
compact table to stderr; `--stats-json` writes the same aggregate data as JSON
for benchmark scripts. These are production diagnostics, not hidden test hooks,
and do not change DNS classification.

DNS JSON output includes explanation fields when a verdict has them:
`wildcard_root`, `wildcard_reason` (`ip_overlap`, `cname_match`, or
`timeout_inferred`), wildcard evidence counts (`wildcard_ip_overlap_count`,
`wildcard_cname_overlap_count`, `wildcard_host_ip_count`,
`wildcard_signature_ip_count`, `wildcard_signature_cname_count`),
`resolver_disagreement`, `dead_zone`, and `flaky_zone`.
Plain DNS output is host-only by default for easy piping. Add `--explain` to
show the output class, internal status, and key-value details, for example:

```txt
api.example.com	review	mixed_wildcard	root=*.example.com reason=ip_overlap ip_overlap=1 host_ips=1 signature_ips=3 cdn=cloudflare confidence=0.50
```

Resolver configuration accepts either a comma-separated list or resolver files:

```sh
assetcanon dns --resolvers 1.1.1.1,8.8.8.8:53 --resolver-file resolvers.txt < hosts.txt
```

Resolver files use one resolver per line. Blank lines and `#` comments are
ignored; bare IPv4/IPv6 addresses default to port 53, while `ip:port` and
`[ipv6]:port` are preserved.

Check a resolver pool before using it:

```sh
assetcanon resolver-check --resolver-file resolvers.txt
assetcanon resolver-check --resolver-file resolvers.txt --json
```

The health check is a report-only mode; it does not read host input and does not
drop bad resolvers from later DNS validation. It checks positive resolution for
`example.com` and `iana.org` by default, plus both random `.invalid` and random
`example.com` NXDOMAIN probes. Use repeated `--domain DOMAIN` flags to override
the default positive-domain list, `--rounds N` to control samples (default 5),
and `--concurrency N` to cap concurrent resolver checks.

Health `status` is decided by hard rules, while `score` is only an auxiliary
ranking signal inside otherwise-OK results. They intentionally do not overlap:
NXDOMAIN hijack and wildcard pollution are always `bad`; timeout ratio > 50% is
`bad`; timeout ratio from 10% through 50% is `warn`; P95 latency > 1000 ms is
`warn` when enough samples exist. Latency output always includes P50 and max;
P95 is emitted only when `check_rounds × check_domains >= 20`.

Exit code is script-friendly: any `bad` or `error` resolver returns 1; all
`ok`/`warn` returns 0.

DNS presets reduce the amount of tuning you need to remember:

- `--safe` is the default profile: `--concurrency 50`, `--wildcard-tests 6`,
  `--probe-concurrency 25`, suitable for public resolvers.
- `--fast` uses higher parallelism (`--concurrency 200`,
  `--probe-concurrency 100`) for large lists and stronger resolver pools.
- `--strict` disables timeout-under-wildcard inference and dead/flaky-zone
  short-circuiting for observed-only results. Expect more `timeout` / `shaky`
  statuses than the default profile because ambiguous cases are not inferred.

Preset values are applied first, then explicit single-parameter flags override
them regardless of CLI order. For example, `--fast --concurrency 300` and
`--concurrency 300 --fast` are equivalent.

See `docs/benchmarks.md` for the current benchmark fixture and the measurements
used to choose the preset defaults.

## License

MIT. Bundled Public Suffix List is MPL-2.0 (see `assets/public_suffix_list.dat`).
