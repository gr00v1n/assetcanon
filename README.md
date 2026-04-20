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
# Extract unique registrable apexes from a messy file.
cat urls.txt | assetcanon apex

# Pull only fully-qualified hosts (drops IPs + wildcards).
cat urls.txt | assetcanon fqdn

# Canonicalize + dedupe a subdomain list.
cat subs.txt | assetcanon clean

# Filter against a scope file, show which rule matched.
assetcanon scope --rules scope.txt --show-rule < hosts.txt

# Validate DNS with multi-resolver consistency + CNAME wildcard detection.
cat hosts.txt | assetcanon dns --json --report-wildcards
```

All commands accept stdin or file arguments. Default output is one canonical
value per line; `-j / --json` emits JSON-lines records with the full asset
metadata.

## Subcommands

| Command     | Purpose                                                                 |
|-------------|-------------------------------------------------------------------------|
| `clean`     | Canonicalize + dedupe everything host-like.                             |
| `apex`      | Unique registrable apexes.                                              |
| `fqdn`      | Apex + subdomain, drop wildcards/IPs.                                   |
| `subs`      | Subdomains only.                                                        |
| `wildcards` | `*.foo.com` entries only.                                               |
| `classify`  | Emit kind/canonical/registrable/reason records (JSON or TSV).           |
| `scope`     | Keep only entries that match a scope ruleset.                           |
| `dns`       | Resolve hosts, classify as resolved / wildcard\_ip / wildcard\_cname / …|

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

`assetcanon dns` is not a straight puredns port — it layers several
corrections on top of the same core idea:

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

Filter on status with repeated `--status` flags:

```sh
assetcanon dns --status resolved --status mixed_wildcard < hosts.txt
```

Surface the discovered wildcard roots, dead zones, and flaky zones with
`--report-wildcards` (emitted to stderr).

## License

MIT. Bundled Public Suffix List is MPL-2.0 (see `assets/public_suffix_list.dat`).
