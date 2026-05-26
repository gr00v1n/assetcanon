//! Candidate extractors for dirty text / URL lines / JSON / SAN.
//!
//! Extraction returns `Vec<String>` of raw candidate tokens, which are then
//! fed into `normalize` + `classify`. Duplicates are pre-removed here to avoid
//! redundant downstream work.

use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

static URL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)((?:https?://|//)[^\s<>'"]+)"#).unwrap());
// Leading `[^...]` boundary is consumed; trailing boundary is a zero-width
// `\b` so adjacent tokens separated by whitespace or newlines still match.
static BRACKET_IPV6_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:^|[^\w:])(\[[0-9a-fA-F:.]+\](?::\d{1,5})?)").unwrap());
static IPV6_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:^|[^\w:])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})\b").unwrap()
});
static IPV4_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:^|[^\w.])((?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?)\b").unwrap());
static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?:^|[^@\w.-])((?:\*\.)?(?:[A-Za-z0-9\u{0080}-\u{FFFF}-]{1,63}\.)+[A-Za-z0-9\u{0080}-\u{FFFF}-]{2,63}\.?(?::\d{1,5})?)\b",
    )
    .unwrap()
});

const TRIM: &[char] = &['"', '\'', '`', ',', ';', '(', ')', '{', '}', '<', '>'];

fn trim_token(s: &str) -> String {
    s.trim().trim_matches(TRIM).to_string()
}

/// Extract host-like candidates from dirty text. Pre-dedupes by raw value.
pub fn from_text(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // Invariant: `occupied` is kept sorted by start and pairwise disjoint, so
    // `overlaps` can answer in O(log n) via a single predecessor lookup. Each
    // regex pass's matches are themselves scan-ordered and disjoint, so we
    // collect them into `additions` and merge in one O(n) sweep per pass —
    // the original per-match linear scan was O(n²) on dirty dumps.
    let mut occupied: Vec<(usize, usize)> = Vec::new();

    let mut additions: Vec<(usize, usize)> = Vec::new();
    for m in URL_RE.find_iter(text) {
        let token = trim_token(m.as_str());
        if !token.is_empty() && seen.insert(token.clone()) {
            out.push(token);
        }
        additions.push((m.start(), m.end()));
    }
    occupied = merge_sorted_disjoint(occupied, additions);

    for re in [&*BRACKET_IPV6_RE, &*IPV6_RE, &*IPV4_RE, &*DOMAIN_RE] {
        let mut additions: Vec<(usize, usize)> = Vec::new();
        for cap in re.captures_iter(text) {
            let Some(m) = cap.get(1) else { continue };
            if overlaps(m.start(), m.end(), &occupied) {
                continue;
            }
            let token = trim_token(m.as_str());
            if token.is_empty() {
                continue;
            }
            let token = strip_regex_boundary(&token);
            if token.is_empty() {
                continue;
            }
            if seen.insert(token.clone()) {
                out.push(token);
            }
            // Reserve the range so inner regex passes (e.g. bare IPv6 inside a
            // bracketed match) don't re-extract a partial copy.
            additions.push((m.start(), m.end()));
        }
        occupied = merge_sorted_disjoint(occupied, additions);
    }

    out
}

/// Overlap check against a sorted, pairwise-disjoint `occupied` slice. For
/// such a slice the predecessor of `end` is the only range that can overlap
/// `[start, end)` — if its `e <= start` then by disjoint+sorted ordering all
/// earlier ranges have even smaller `e` and cannot overlap either.
fn overlaps(start: usize, end: usize, occupied: &[(usize, usize)]) -> bool {
    let upper = occupied.partition_point(|&(s, _)| s < end);
    upper > 0 && occupied[upper - 1].1 > start
}

/// Merge two sorted, pairwise-disjoint slices of `(start, end)` into one
/// sorted, pairwise-disjoint vec. Assumes the new additions don't overlap
/// existing entries (the caller has already filtered via `overlaps`).
fn merge_sorted_disjoint(a: Vec<(usize, usize)>, b: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if b.is_empty() {
        return a;
    }
    if a.is_empty() {
        return b;
    }
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        if a[i].0 <= b[j].0 {
            out.push(a[i]);
            i += 1;
        } else {
            out.push(b[j]);
            j += 1;
        }
    }
    out.extend_from_slice(&a[i..]);
    out.extend_from_slice(&b[j..]);
    out
}

/// Because Rust regex lacks lookahead/lookbehind we used `(?:^|[^...])`
/// boundaries, so the first/last char of a match may be a boundary character.
/// Strip them.
fn strip_regex_boundary(token: &str) -> String {
    let t = token.trim().trim_matches(TRIM);
    let t =
        t.trim_start_matches(|c: char| !(c.is_alphanumeric() || c == '[' || c == '*' || c == ':'));
    let t =
        t.trim_end_matches(|c: char| !(c.is_alphanumeric() || c == ']' || c == '.' || c == '*'));
    // Strip trailing dot(s) only if there are two (x.com.. -> x.com.); single trailing
    // dot is valid FQDN notation.
    let t = t.trim_end_matches("..");
    t.to_string()
}

/// Each line is a single URL/host candidate.
pub fn from_urls<I, S>(lines: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in lines {
        let value = trim_token(line.as_ref().trim());
        if value.is_empty() {
            continue;
        }
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

/// Parse JSON or JSONL. If `fields` is non-empty, only top-level keys with
/// those names are scanned; otherwise every string value in the object is
/// scanned.
pub fn from_json(stream: &str, fields: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let trimmed = stream.trim();
    if trimmed.is_empty() {
        return out;
    }

    let push_candidates = |s: &str, out: &mut Vec<String>, seen: &mut HashSet<String>| {
        let candidates = if s.trim().starts_with("http://")
            || s.trim().starts_with("https://")
            || s.trim().starts_with("//")
        {
            from_urls([s])
        } else {
            from_text(s)
        };
        for c in candidates {
            if seen.insert(c.clone()) {
                out.push(c);
            }
        }
    };

    // Try parsing the whole stream first.
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        match value {
            Value::Array(items) => {
                for item in items {
                    walk(&item, fields, &mut |s| {
                        push_candidates(s, &mut out, &mut seen);
                    });
                }
            }
            other => {
                walk(&other, fields, &mut |s| {
                    push_candidates(s, &mut out, &mut seen);
                });
            }
        }
        return out;
    }

    // JSONL fallback.
    for line in stream.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            walk(&value, fields, &mut |s| {
                push_candidates(s, &mut out, &mut seen);
            });
        }
    }

    out
}

fn walk(value: &Value, fields: &[&str], out: &mut dyn FnMut(&str)) {
    if !fields.is_empty() {
        if let Value::Object(map) = value {
            for &key in fields {
                if let Some(Value::String(s)) = map.get(key) {
                    out(s);
                }
            }
        }
        return;
    }
    match value {
        Value::String(s) => out(s),
        Value::Array(items) => {
            for item in items {
                walk(item, fields, out);
            }
        }
        Value::Object(map) => {
            for (_, v) in map {
                walk(v, fields, out);
            }
        }
        _ => {}
    }
}

/// Extract DNS names from SAN-style lines like `DNS:foo.com, DNS:bar.com`.
pub fn from_san<I, S>(lines: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let sep = Regex::new(r"[,\s]+").unwrap();
    for line in lines {
        let line = line.as_ref().trim();
        for part in sep.split(line) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let part = part.strip_prefix("DNS:").unwrap_or(part);
            let part = part.strip_prefix("dns:").unwrap_or(part);
            if part.is_empty() {
                continue;
            }
            for c in from_text(part) {
                if seen.insert(c.clone()) {
                    out.push(c);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_avoids_email_domains() {
        let out = from_text("send to foo@example.com and visit http://bar.com");
        assert!(out.iter().any(|v| v.starts_with("http://bar.com")));
        assert!(!out.iter().any(|v| v == "example.com"));
    }

    #[test]
    fn text_picks_up_ipv4_and_ipv6() {
        let out = from_text("server 10.0.0.1 or [2001:db8::1]:8080");
        assert!(out.iter().any(|v| v.contains("10.0.0.1")));
        assert!(out.iter().any(|v| v.contains("2001:db8::1")));
    }

    #[test]
    fn san_parses_dns_prefix() {
        let out = from_san(["DNS:foo.com, DNS:bar.com"]);
        assert!(out.iter().any(|v| v == "foo.com"));
        assert!(out.iter().any(|v| v == "bar.com"));
    }
}
