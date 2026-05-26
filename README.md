# assetcanon

Fast, Unix-style toolkit for cleaning and validating domain / asset lists.

`assetcanon` reads dirty input (URLs, hostnames, IPs, JSON, certificate SANs),
normalizes it, classifies each entry, deduplicates, filters against scope rules,
and optionally runs DNS validation with wildcard-aware cleanup.

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

## Input formats

The CLI accepts several input shapes via `--input-format`:

- `text` (default) — dirty free text; URLs/IPs/domains are pulled out with
  regex and cleaned.
- `urls` — one URL or host per line; each line is a candidate.
- `json` / JSON-lines — recursively walks every string value; narrow the scan
  with one or more `--json-field KEY` flags.
- `san` — lines of `DNS:foo.com, DNS:bar.com` (TLS certificate SAN format).

## DNS validation highlights

`assetcanon dns` hides noisy DNS edge cases behind three practical classes:

| Class | How to get it | Meaning |
|-------|---------------|---------|
| trusted | default `assetcanon dns` | High-confidence real assets. |
| review | `assetcanon dns --review --explain` | Ambiguous assets worth checking manually. |
| ignored | hidden by default | Likely fake or unusable results. Use `--all --explain` to inspect them. |

Normal usage does not require learning the internal DNS status enum. Plain
output is host-only by default; JSON and `--explain` expose the detailed reason
when you need to debug a verdict.

The DNS cleaner handles common false-positive sources:

- wildcard domains, including CNAME-based SaaS/CDN wildcards;
- dead or flaky historical zones from old crawl data;
- resolver disagreement and NXDOMAIN hijacking;
- CDN IP overlap that should be reviewed instead of blindly trusted or dropped.

For advanced/debugging workflows, `--all --explain` prints every result with its
class and internal status:

```sh
assetcanon dns --all --explain < hosts.txt
```

Surface the discovered wildcard roots, dead zones, and flaky zones with
`--report-wildcards` (emitted to stderr).

Emit aggregate DNS stats when tuning resolver pools or presets:

```sh
assetcanon dns --stats < hosts.txt
assetcanon dns --stats-json stats.json < hosts.txt
```

Add `--explain` to show the output class, internal status, and key-value
evidence in plain output:

```txt
api.example.com	review	mixed_wildcard	root=*.example.com reason=ip_overlap ip_overlap=1 host_ips=1 signature_ips=3 cdn=cloudflare confidence=0.50
```

Resolver configuration accepts either a comma-separated list or resolver files:

```sh
assetcanon dns --resolvers 1.1.1.1,8.8.8.8:53 --resolver-file resolvers.txt < hosts.txt
```

Resolver files use one resolver per line. Blank lines and `#` comments are
ignored; bare IPv4/IPv6 addresses default to port 53.

Check a resolver pool before using it:

```sh
assetcanon resolver-check --resolver-file resolvers.txt
assetcanon resolver-check --resolver-file resolvers.txt --json
```

The health check reports `ok`, `warn`, `bad`, or `error` and exits non-zero for
bad/error resolvers. It does not automatically drop resolvers from a later DNS
run.

For larger runs, `--fast` raises DNS parallelism. `--strict` keeps only observed
DNS behavior and avoids inference, so expect more timeout/shaky results. See
`docs/benchmarks.md` for the preset benchmark notes.

## License

MIT. Bundled Public Suffix List is MPL-2.0 (see `assets/public_suffix_list.dat`).
