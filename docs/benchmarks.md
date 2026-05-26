# DNS preset benchmark

This note records the fixture and measurements used to sanity-check the current
DNS preset defaults. DNS results depend on the local network and resolver pool;
rerun this benchmark when changing preset numbers or when testing on a different
resolver set.

## Fixture

The benchmark uses 1,000 unique input records and disables semantic dedupe so
every record is validated. Normal domains are made unique with explicit
non-default ports; DNS validation strips the port and queries the host.

Composition:

- 350 known-good public domains, cycling through `example.com`,
  `www.cloudflare.com`, `www.iana.org`, `github.com`, `www.rust-lang.org`,
  `www.wikipedia.org`, `www.google.com`, `openai.com`, `www.npmjs.com`, and
  `crates.io`.
- 250 wildcard-prone PaaS/CDN-style names under `herokuapp.com`,
  `azurewebsites.net`, `cloudfront.net`, `github.io`, `pages.dev`,
  `vercel.app`, `netlify.app`, and `s3.amazonaws.com`.
- 250 nonexistent `.invalid` names.
- 150 nonexistent `assetcanon.invalid` names, representing dead-zone-like
  historical assets in a deterministic reserved namespace.

Fixture generator:

```sh
python3 - <<'PY'
from pathlib import Path

normal = [
    'example.com', 'www.cloudflare.com', 'www.iana.org', 'github.com',
    'www.rust-lang.org', 'www.wikipedia.org', 'www.google.com', 'openai.com',
    'www.npmjs.com', 'crates.io',
]
wild = [
    'herokuapp.com', 'azurewebsites.net', 'cloudfront.net', 'github.io',
    'pages.dev', 'vercel.app', 'netlify.app', 's3.amazonaws.com',
]

lines = []
for i in range(350):
    lines.append(f'{normal[i % len(normal)]}:{10000 + i}')
for i in range(250):
    lines.append(f'acbench{i:04d}.{wild[i % len(wild)]}')
for i in range(250):
    lines.append(f'acbench-nx-{i:04d}.invalid')
for i in range(150):
    lines.append(f'acbench-dead-{i:04d}.assetcanon.invalid')

Path('/tmp/assetcanon-dns-preset-bench-1000.txt').write_text('\n'.join(lines) + '\n')
PY
```

Commands:

```sh
assetcanon dns --json --no-dedupe --input-format urls \
  --stats-json /tmp/assetcanon-dns-default.stats.json \
  /tmp/assetcanon-dns-preset-bench-1000.txt > /tmp/assetcanon-dns-default.jsonl

assetcanon dns --json --no-dedupe --input-format urls --safe \
  --stats-json /tmp/assetcanon-dns-safe.stats.json \
  /tmp/assetcanon-dns-preset-bench-1000.txt > /tmp/assetcanon-dns-safe.jsonl

assetcanon dns --json --no-dedupe --input-format urls --fast \
  --stats-json /tmp/assetcanon-dns-fast.stats.json \
  /tmp/assetcanon-dns-preset-bench-1000.txt > /tmp/assetcanon-dns-fast.jsonl

assetcanon dns --json --no-dedupe --input-format urls --strict \
  --stats-json /tmp/assetcanon-dns-strict.stats.json \
  /tmp/assetcanon-dns-preset-bench-1000.txt > /tmp/assetcanon-dns-strict.jsonl
```

Use the `*.stats.json` files as the source of truth for elapsed time, query
counts, status distribution, wildcard reason distribution, and resolver
disagreement types. This avoids relying on shell-specific `time` output and
makes safe/fast/strict comparisons reproducible by benchmark scripts.

## Result from 2026-05-26

Environment: macOS arm64, default public resolver pool compiled into
`assetcanon`, debug binary (`target/debug/assetcanon`).

| Mode | Effective preset | Elapsed | Probe queries | Host queries | Total | Resolved | Wildcard hits | Timeout rate | Unresolved | Resolver disagreement |
|------|------------------|--------:|--------------:|-------------:|------:|---------:|--------------:|-------------:|-----------:|----------------------:|
| default | safe defaults | 2.24 s | not recorded | not recorded | 1000 | 600 | 0 | 0.0% | 400 | not recorded |
| `--safe` | safe defaults | 2.20 s | not recorded | not recorded | 1000 | 600 | 0 | 0.0% | 400 | not recorded |
| `--fast` | concurrency 200, probe concurrency 100 | 2.33 s | not recorded | not recorded | 1000 | 600 | 0 | 0.0% | 400 | not recorded |

`Wildcard hits` is the sum of `wildcard_ip`, `wildcard_cname`, and
`mixed_wildcard`. `Timeout rate` is `timeout / total`. `Resolver disagreement`
is the sum of the aggregate disagreement counters in stats JSON
(`answer_vs_nxdomain`, `answer_vs_timeout`, `answer_vs_error`,
`distinct_ip_sets`, and `distinct_cname_sets`).

## Interpretation

- Default and `--safe` are intentionally equivalent. This run showed no timeout
  pressure on the default public resolver pool, so the conservative defaults
  (`concurrency=50`, `wildcard_tests=6`, `probe_concurrency=25`) were kept.
- `--fast` did not improve this small fixture because runtime was dominated by
  resolver/network latency and the fixture has a small ancestor set for wildcard
  precompute. It remains useful for much larger lists and stronger resolver
  pools.
- No wildcard statuses were emitted in this network run even though the fixture
  includes wildcard-prone public suffixes. Treat this benchmark as a preset-load
  sanity check, not as a correctness test for wildcard classification. Wildcard
  correctness remains covered by unit tests for the status classifier.

When changing preset values, rerun this benchmark and prefer the lowest default
parallelism that keeps timeout rate near zero on public resolvers.
