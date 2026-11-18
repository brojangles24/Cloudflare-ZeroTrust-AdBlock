#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[package]
edition = "2021"

[dependencies]
anyhow = "1.0"
flate2 = "1.0"
idna = "1.0"
ipnet = "2.10"
rayon = "1.10"
regex = "1.11"
reqwest = { version = "0.12", features = ["blocking", "json", "rustls-tls"], default-features = false }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10"
toml = "0.8"
zip = { version = "2.2", default-features = false, features = ["deflate"] }
---

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rayon::prelude::*;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::net::IpAddr;
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zip::ZipArchive;

const UA_STR: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const MIN_RELEVANCE_DOMAINS: usize = 500_000;
const MAX_SAFE_DOMAINS: usize = 299_000;
const MAX_CLOUDFLARE_LISTS: usize = 299;
const MAX_DROP_RATIO: f64 = 0.60;

struct TopListSpec {
    url: &'static str,
    col: usize,
    skip_header: bool,
    compression: &'static str,
}

const DEFAULT_TOP_LISTS: &[TopListSpec] = &[
    TopListSpec { url: "https://tranco-list.eu/top-1m.csv.zip", col: 1, skip_header: false, compression: "zip" },
    TopListSpec { url: "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", col: 0, skip_header: true, compression: "gzip" },
    TopListSpec { url: "https://downloads.majestic.com/majestic_million.csv", col: 2, skip_header: true, compression: "raw" },
    //TopListSpec { url: "https://openpagerank.keywordseverywhere.com/downloads/top10milliondomains.csv.zip", col: 1, skip_header: true, compression: "zip" },
    TopListSpec { url: "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", col: 1, skip_header: false, compression: "zip" },
];

macro_rules! log_info {
    ($($arg:tt)*) => { println!("[INFO] {}", format_args!($($arg)*)) };
}
macro_rules! log_warn {
    ($($arg:tt)*) => { eprintln!("[WARN] {}", format_args!($($arg)*)) };
}
macro_rules! log_err {
    ($($arg:tt)*) => { eprintln!("[ERROR] {}", format_args!($($arg)*)) };
}

fn jitter_ms(max_ms: u64) -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    Duration::from_millis(nanos % max_ms.max(1))
}

fn fast_domain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$").unwrap())
}

fn label_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").unwrap())
}

fn tld_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z]{2,63}$").unwrap())
}

fn invalid_label_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"invalid label ["']?([a-zA-Z0-9_\-\.]+?)["'\s]"#).unwrap())
}

struct AppConfig {
    raw: Value,
    api_token: String,
    account_id: String,
    target_identity: Option<String>,
    max_workers: usize,
    max_list_size: usize,
    total_quota: usize,
    timeout: Duration,
    scrub_targets: Vec<String>,
    auto_enable_rules: bool,
    block_page_enabled: bool,
}

fn load_config() -> Result<AppConfig> {
    let content = fs::read_to_string("config.toml").context("config.toml not found")?;
    let toml_val: toml::Value = toml::from_str(&content).context("Failed to parse config.toml")?;
    let raw: Value = serde_json::to_value(toml_val)?;

    let api_token = env::var("API_TOKEN").unwrap_or_default().trim().to_string();
    let account_id = env::var("ACCOUNT_ID").unwrap_or_default().trim().to_string();
    if api_token.is_empty() || account_id.is_empty() {
        bail!("Missing API_TOKEN or ACCOUNT_ID in environment.");
    }

    let mut excluded = Vec::new();
    for var in ["SECONDARY_EMAIL", "TERTIARY_EMAIL"] {
        if let Ok(val) = env::var(var) {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() && !excluded.contains(&trimmed) {
                excluded.push(trimmed);
            }
        }
    }
    if let Ok(extra) = env::var("EXCLUDED_EMAILS") {
        for email in extra.split(',') {
            let trimmed = email.trim().to_string();
            if !trimmed.is_empty() && !excluded.contains(&trimmed) {
                excluded.push(trimmed);
            }
        }
    }

    let target_identity = if excluded.is_empty() {
        None
    } else {
        let formatted: Vec<String> = excluded.iter().map(|e| format!("\"{}\"", e)).collect();
        Some(format!("not(identity.email in {{{}}})", formatted.join(" ")))
    };

    let settings = raw.get("settings").and_then(Value::as_object);
    let max_workers = settings.and_then(|s| s.get("max_workers")).and_then(Value::as_u64).unwrap_or(8) as usize;
    let max_list_size = settings.and_then(|s| s.get("max_list_size")).and_then(Value::as_u64).unwrap_or(1000) as usize;
    let total_quota = settings
        .and_then(|s| s.get("total_quota"))
        .and_then(Value::as_u64)
        .map(|q| (q as usize).min(MAX_SAFE_DOMAINS))
        .unwrap_or(MAX_SAFE_DOMAINS);

    let timeout_secs = settings
        .and_then(|s| s.get("request_timeout"))
        .and_then(|t| {
            t.as_array()
                .and_then(|arr| arr.last())
                .and_then(Value::as_u64)
                .or_else(|| t.as_u64())
        })
        .unwrap_or(30);

    let scrub_targets = settings
        .and_then(|s| s.get("scrub_targets"))
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default();

    let auto_enable_rules = settings.and_then(|s| s.get("auto_enable_rules")).and_then(Value::as_bool).unwrap_or(true);
    let block_page_enabled = settings.and_then(|s| s.get("block_page_enabled")).and_then(Value::as_bool).unwrap_or(false);

    Ok(AppConfig {
        raw,
        api_token,
        account_id,
        target_identity,
        max_workers,
        max_list_size,
        total_quota,
        timeout: Duration::from_secs(timeout_secs),
        scrub_targets,
        auto_enable_rules,
        block_page_enabled,
    })
}

fn build_http_client(timeout: Duration, auth_token: Option<&str>) -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(UA_STR));
    if let Some(token) = auth_token {
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", token))?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    Ok(Client::builder()
        .default_headers(headers)
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(15))
        .build()?)
}

struct CloudflareAPI {
    client: Client,
    base_url: String,
}

impl CloudflareAPI {
    fn new(cfg: &AppConfig) -> Result<Self> {
        let client = build_http_client(cfg.timeout, Some(&cfg.api_token))?;
        let base_url = format!("https://api.cloudflare.com/client/v4/accounts/{}/gateway", cfg.account_id);
        Ok(Self { client, base_url })
    }

    fn req(&self, method: reqwest::Method, endpoint: &str, body: Option<&Value>) -> Result<Value> {
        let url = format!("{}/{}", self.base_url, endpoint);
        let retries = 5;
        let base_delay = 2u64;

        if method != reqwest::Method::GET {
            thread::sleep(Duration::from_millis(150) + jitter_ms(100));
        }

        for attempt in 0..retries {
            let mut builder = self.client.request(method.clone(), &url);
            if let Some(b) = body {
                builder = builder.json(b);
            }

            let resp = match builder.send() {
                Ok(r) => r,
                Err(e) => {
                    if attempt < retries - 1 {
                        let wait = Duration::from_secs(base_delay * (1 << attempt)) + jitter_ms(1000);
                        log_warn!("Network error on {} {}: {}. Retrying in {:.2}s...", method, endpoint, e, wait.as_secs_f64());
                        thread::sleep(wait);
                        continue;
                    }
                    return Err(e.into());
                }
            };

            let status = resp.status();
            if status.as_u16() == 429 {
                let wait_secs = resp
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or_else(|| base_delay * (1 << attempt));
                let wait = Duration::from_secs(wait_secs) + jitter_ms(1000);
                log_warn!("Rate limited (429) on {} {}. Backing off for {:.2}s.", method, endpoint, wait.as_secs_f64());
                thread::sleep(wait);
                continue;
            }

            if matches!(status.as_u16(), 500 | 502 | 503 | 504) && attempt < retries - 1 {
                let wait = Duration::from_secs(base_delay * (1 << attempt)) + jitter_ms(1000);
                log_warn!("Server error ({}) on {} {}. Retrying in {:.2}s...", status, method, endpoint, wait.as_secs_f64());
                thread::sleep(wait);
                continue;
            }

            let text = resp.text()?;
            if !status.is_success() {
                log_err!("Cloudflare API error [{}] on {} {}: {}", status, method, endpoint, text);
                bail!("HTTP {} on {} {}: {}", status, method, endpoint, text);
            }

            let payload: Value = serde_json::from_str(&text)?;
            if payload.get("success").and_then(Value::as_bool) == Some(false) {
                let errors = payload.get("errors").cloned().unwrap_or(json!([]));
                log_err!("Cloudflare API error payload on {} {}: {}", method, endpoint, errors);
                bail!("Cloudflare API failed on {}: {}", endpoint, errors);
            }

            return Ok(payload);
        }

        bail!("Exceeded max retries on Cloudflare endpoint: {}", endpoint)
    }

    fn paginate(&self, endpoint: &str) -> Result<Vec<Value>> {
        let mut results = Vec::new();
        let mut page = 1u64;
        loop {
            let resp = self.req(reqwest::Method::GET, &format!("{}?page={}&per_page=100", endpoint, page), None)?;
            if let Some(arr) = resp.get("result").and_then(Value::as_array) {
                results.extend(arr.clone());
            }
            let total_pages = resp
                .get("result_info")
                .and_then(|i| i.get("total_pages"))
                .and_then(Value::as_u64)
                .unwrap_or(1);
            if page >= total_pages {
                break;
            }
            page += 1;
        }
        Ok(results)
    }

    fn get_lists(&self) -> Result<Vec<Value>> { self.paginate("lists") }
    fn get_rules(&self) -> Result<Vec<Value>> { self.paginate("rules") }
    fn delete_list(&self, lid: &str) -> Result<Value> { self.req(reqwest::Method::DELETE, &format!("lists/{}", lid), None) }
    fn delete_rule(&self, rid: &str) -> Result<Value> { self.req(reqwest::Method::DELETE, &format!("rules/{}", rid), None) }

    fn create_list(&self, name: &str, items: &[Value], list_type: &str, desc: &str) -> Result<Value> {
        self.req(
            reqwest::Method::POST,
            "lists",
            Some(&json!({ "name": name, "type": list_type, "items": items, "description": desc })),
        )
    }

    fn update_list(&self, lid: &str, name: &str, items: &[Value], desc: &str) -> Result<Value> {
        self.req(
            reqwest::Method::PUT,
            &format!("lists/{}", lid),
            Some(&json!({ "name": name, "items": items, "description": desc })),
        )
    }

    fn create_rule(&self, data: &Value) -> Result<Value> {
        let mut payload = data.clone();
        let settings = payload.as_object_mut().unwrap().entry("rule_settings").or_insert_with(|| json!({}));
        settings.as_object_mut().unwrap().entry("block_page_enabled").or_insert(json!(false));
        self.req(reqwest::Method::POST, "rules", Some(&payload))
    }

    fn update_rule(&self, rid: &str, data: &Value) -> Result<Value> {
        let mut payload = data.clone();
        let settings = payload.as_object_mut().unwrap().entry("rule_settings").or_insert_with(|| json!({}));
        settings.as_object_mut().unwrap().entry("block_page_enabled").or_insert(json!(false));
        self.req(reqwest::Method::PUT, &format!("rules/{}", rid), Some(&payload))
    }
}

fn is_valid_domain(domain: &str) -> Option<String> {
    let mut d = domain.trim().to_lowercase();
    if d.is_empty() {
        return None;
    }

    if let Some((_, rest)) = d.split_once("://") {
        d = rest.to_string();
    }
    if d.contains(['/', '?', ':', '*']) || d.starts_with('.') || d.ends_with('.') {
        d = d.split('?').next().unwrap_or("")
            .split('/').next().unwrap_or("")
            .split(':').next().unwrap_or("")
            .trim_start_matches("*.")
            .trim_matches('.')
            .to_string();
    }

    if d.is_empty() || !d.contains('.') || d.len() > 253 || d.contains("..") {
        return None;
    }

    if d.is_ascii() && !d.contains("--") && fast_domain_re().is_match(&d) {
        return Some(d);
    }

    if !d.is_ascii() {
        d = idna::domain_to_ascii(&d).ok()?;
    }

    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return None;
    }

    let tld = labels.last()?;
    if tld.chars().all(|c| c.is_ascii_digit()) || !tld_re().is_match(tld) {
        return None;
    }

    for label in &labels {
        if !label_re().is_match(label) {
            return None;
        }
        if label.len() >= 4 && &label[2..4] == "--" {
            if !label.starts_with("xn--") {
                return None;
            }
            let (_, res) = idna::domain_to_unicode(label);
            res.ok()?;
        }
    }

    if d.parse::<IpAddr>().is_ok() {
        return None;
    }

    Some(d)
}

fn has_parent_match(host: &str, lookup: &HashSet<String>) -> bool {
    let mut start = 0;
    while let Some(pos) = host[start..].find('.') {
        let dot_idx = start + pos;
        if lookup.contains(&host[dot_idx + 1..]) {
            return true;
        }
        start = dot_idx + 1;
    }
    false
}

fn has_suffix_match(host: &str, lookup: &HashSet<String>) -> bool {
    lookup.contains(host) || has_parent_match(host, lookup)
}

fn parse_csv_stream<R: Read>(reader: R, col: usize, skip_header: bool) -> HashSet<String> {
    let mut domains = HashSet::new();
    let buf = BufReader::new(reader);
    for (idx, line) in buf.lines().map_while(Result::ok).enumerate() {
        if skip_header && idx == 0 {
            continue;
        }
        if let Some(raw_col) = line.split(',').nth(col) {
            let raw = raw_col.trim().trim_matches('"').to_lowercase();
            if raw.is_empty() || domains.contains(&raw) {
                continue;
            }
            if let Some(clean) = is_valid_domain(&raw) {
                domains.insert(clean);
            }
        }
    }
    domains
}

fn fetch_with_retry(client: &Client, url: &str) -> Result<Vec<u8>> {
    for attempt in 0..5 {
        match client.get(url).send().and_then(|r| r.error_for_status()) {
            Ok(resp) => return Ok(resp.bytes()?.to_vec()),
            Err(e) if attempt < 4 => {
                thread::sleep(Duration::from_millis(1500 * (1 << attempt)) + jitter_ms(500));
                if attempt == 3 {
                    log_warn!("Retry failed for {}: {}", url, e);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!()
}

fn build_relevance_dataset(client: &Client) -> Result<HashSet<String>> {
    log_info!("Fetching fresh relevance datasets directly from sources...");
    let sets: Vec<HashSet<String>> = DEFAULT_TOP_LISTS
        .par_iter()
        .map(|item| {
            let bytes = match fetch_with_retry(client, item.url) {
                Ok(b) => b,
                Err(e) => {
                    log_warn!("Failed to fetch top list ({}): {}", item.url, e);
                    return HashSet::new();
                }
            };
            let parsed = match item.compression {
                "zip" => {
                    let cursor = Cursor::new(bytes);
                    let Ok(mut archive) = ZipArchive::new(cursor) else { return HashSet::new() };
                    let mut target_idx = 0;
                    for i in 0..archive.len() {
                        if let Ok(file) = archive.by_index(i) {
                            let lower = file.name().to_lowercase();
                            if (lower.ends_with(".csv") || lower.ends_with(".txt")) && !lower.ends_with('/') {
                                target_idx = i;
                                break;
                            }
                        }
                    }
                    let parsed = if let Ok(file) = archive.by_index(target_idx) {
                        parse_csv_stream(file, item.col, item.skip_header)
                    } else {
                        HashSet::new()
                    };
                    parsed
                }
                "gzip" => parse_csv_stream(GzDecoder::new(Cursor::new(bytes)), item.col, item.skip_header),
                _ => parse_csv_stream(Cursor::new(bytes), item.col, item.skip_header),
            };
            log_info!("Fetched & parsed {} domains from {}", parsed.len(), item.url);
            parsed
        })
        .collect();

    let mut master = HashSet::new();
    for s in sets {
        master.extend(s);
    }

    if master.len() < MIN_RELEVANCE_DOMAINS {
        bail!("Relevance dataset critically low ({} domains). Aborting sync.", master.len());
    }
    log_info!("Relevance dataset compiled: {} root domains.", master.len());
    Ok(master)
}

#[derive(Clone)]
struct SourceSpec {
    name: String,
    urls: Vec<String>,
    enable_relevance: bool,
}

fn parse_sources(table: Option<&Map<String, Value>>, is_ip: bool) -> Vec<SourceSpec> {
    let Some(map) = table else { return Vec::new() };
    let mut out = Vec::new();
    for (name, data) in map {
        match data {
            Value::String(u) => out.push(SourceSpec { name: name.clone(), urls: vec![u.clone()], enable_relevance: !is_ip }),
            Value::Array(arr) => {
                let urls = arr.iter().filter_map(Value::as_str).map(String::from).collect();
                out.push(SourceSpec { name: name.clone(), urls, enable_relevance: !is_ip });
            }
            Value::Object(obj) => {
                let urls = if let Some(arr) = obj.get("urls").and_then(Value::as_array) {
                    arr.iter().filter_map(Value::as_str).map(String::from).collect()
                } else if let Some(u) = obj.get("url").and_then(Value::as_str) {
                    vec![u.to_string()]
                } else {
                    Vec::new()
                };
                let enable_relevance = if is_ip {
                    false
                } else {
                    obj.get("relevance").and_then(Value::as_bool).unwrap_or(true)
                };
                out.push(SourceSpec { name: name.clone(), urls, enable_relevance });
            }
            _ => {}
        }
    }
    out
}

fn fetch_feed_source(client: &Client, spec: &SourceSpec, relevance: Option<&HashSet<String>>) -> Result<HashSet<String>> {
    let mut kept = HashSet::new();
    for u in &spec.urls {
        let bytes = fetch_with_retry(client, u)?;
        let text = String::from_utf8_lossy(&bytes);
        for mut line in text.lines() {
            line = line.trim();
            if line.is_empty() || line.starts_with(['#', '!', '/']) {
                continue;
            }
            for c in ['#', '!', ';'] {
                if let Some((before, _)) = line.split_once(c) {
                    line = before;
                }
            }
            line = line.trim();
            if line.is_empty() {
                continue;
            }
            let last_tok = line.split_whitespace().last().unwrap_or("");
            let token = last_tok
                .split('$').next().unwrap_or("")
                .trim_start_matches("||")
                .split('^').next().unwrap_or("");

            if let Some(clean) = is_valid_domain(token) {
                if !kept.contains(&clean) {
                    let ok = match relevance {
                        Some(rel) => {
                            let check_dom = clean.strip_prefix("www.").unwrap_or(&clean);
                            has_suffix_match(check_dom, rel)
                        }
                        None => true,
                    };
                    if ok {
                        kept.insert(clean);
                    }
                }
            }
        }
    }
    log_info!("Fetched {}: {} kept", spec.name, kept.len());
    Ok(kept)
}

fn is_non_routable_ip(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => {
            let ip = v4.addr();
            ip.is_private() || ip.is_loopback() || ip.is_multicast() || ip.is_link_local() || ip.is_unspecified()
        }
        IpNet::V6(v6) => {
            let ip = v6.addr();
            ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
    }
}

fn fetch_ip_source(client: &Client, spec: &SourceSpec) -> Result<HashSet<IpNet>> {
    let mut networks = HashSet::new();
    for u in &spec.urls {
        let bytes = fetch_with_retry(client, u)?;
        let text = String::from_utf8_lossy(&bytes);
        for mut line in text.lines() {
            line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';', '/']) {
                continue;
            }
            for c in ["#", ";", "//"] {
                if let Some((before, _)) = line.split_once(c) {
                    line = before;
                }
            }
            line = line.trim();
            if line.is_empty() {
                continue;
            }
            let cleaned = line.replace(['"', '\'', ',', '\t'], " ");
            for raw_token in cleaned.split_whitespace() {
                let mut token = raw_token.trim().trim_matches(&['[', ']'][..]);
                if !token.contains('.') && !token.contains(':') {
                    continue;
                }
                if token.contains('.') && token.contains(':') {
                    token = token.split(':').next().unwrap_or("");
                } else if let Some((v6_part, _)) = raw_token.split_once("]:") {
                    token = v6_part.trim_start_matches('[');
                }

                let parsed_net = token
                    .parse::<IpNet>()
                    .map(|n| n.trunc())
                    .or_else(|_| token.parse::<IpAddr>().map(IpNet::from));

                if let Ok(net) = parsed_net {
                    if !is_non_routable_ip(&net) {
                        networks.insert(net);
                    }
                }
            }
        }
    }
    log_info!("Fetched IP feed {}: {} unique subnets/IPs", spec.name, networks.len());
    Ok(networks)
}

fn fetch_spam_tlds(client: &Client, url: &str) -> Result<(String, HashSet<String>)> {
    let bytes = fetch_with_retry(client, url)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut tlds = BTreeSet::new();
    for line in text.lines() {
        let l = line.trim().to_lowercase();
        if !l.is_empty() && !l.starts_with(['#', '!', '/']) {
            let clean = l.split_whitespace().last().unwrap_or("").trim_start_matches("*.").trim_matches('.');
            if !clean.is_empty() && !clean.contains('.') && !clean.contains('*') {
                tlds.insert(clean.to_string());
            }
        }
    }
    if tlds.is_empty() {
        bail!("Zero TLDs parsed from {}", url);
    }
    let joined: Vec<&str> = tlds.iter().map(String::as_str).collect();
    let expr = format!(r#"any(dns.domains[*] matches "(?i)\.({})$")"#, joined.join("|"));
    Ok((expr, tlds.into_iter().collect()))
}

enum FetchedFeed {
    Domain(HashSet<String>),
    Ip(HashSet<IpNet>),
}

fn build_policy_sets(
    policies: &[Value],
    fetched: &HashMap<String, FetchedFeed>,
    spam_tlds: &HashSet<String>,
) -> Vec<(Value, Vec<String>)> {
    let base_set = match fetched.get("HaGeZi Normal") {
        Some(FetchedFeed::Domain(d)) => Some(d),
        _ => None,
    };
    let has_active_spam_tld = policies.iter().any(|p| p.get("use_spam_tld").and_then(Value::as_bool).unwrap_or(false));

    policies
        .iter()
        .map(|p| {
            let prefix = p.get("prefix").and_then(Value::as_str).unwrap_or("unknown");
            let p_type = p.get("type").and_then(Value::as_str).unwrap_or("DOMAIN").to_uppercase();

            if p_type == "IP" {
                let mut ip_set = HashSet::new();
                if let Some(incs) = p.get("include").and_then(Value::as_array) {
                    for inc in incs.iter().filter_map(Value::as_str) {
                        if let Some(FetchedFeed::Ip(nets)) = fetched.get(inc) {
                            ip_set.extend(nets.iter().copied());
                        }
                    }
                }
                if let Some(excs) = p.get("exclude").and_then(Value::as_array) {
                    for exc in excs.iter().filter_map(Value::as_str) {
                        if let Some(FetchedFeed::Ip(nets)) = fetched.get(exc) {
                            for n in nets {
                                ip_set.remove(n);
                            }
                        }
                    }
                }

                let mut v4: Vec<Ipv4Net> = Vec::new();
                let mut v6: Vec<Ipv6Net> = Vec::new();
                for net in ip_set {
                    match net {
                        IpNet::V4(n) => v4.push(n),
                        IpNet::V6(n) => v6.push(n),
                    }
                }
                let mut collapsed: Vec<String> = Ipv4Net::aggregate(&v4).into_iter().map(|n| n.to_string()).collect();
                collapsed.extend(Ipv6Net::aggregate(&v6).into_iter().map(|n| n.to_string()));
                (p.clone(), collapsed)
            } else {
                let mut p_set = HashSet::new();
                let includes: Vec<&str> = p
                    .get("include")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();

                for inc in &includes {
                    if let Some(FetchedFeed::Domain(doms)) = fetched.get(*inc) {
                        p_set.extend(doms.iter().cloned());
                    }
                }
                if let Some(excs) = p.get("exclude").and_then(Value::as_array) {
                    for exc in excs.iter().filter_map(Value::as_str) {
                        if let Some(FetchedFeed::Domain(doms)) = fetched.get(exc) {
                            for d in doms {
                                p_set.remove(d);
                            }
                        }
                    }
                }

                if p.get("action").and_then(Value::as_str) != Some("allow") {
                    if let Some(base) = base_set {
                        if prefix != "L_Normal" && prefix != "L_Relaxed" && !includes.contains(&"HaGeZi Normal") {
                            p_set.retain(|d| !has_suffix_match(d, base));
                        }
                    }
                    let use_spam = p.get("use_spam_tld").and_then(Value::as_bool).unwrap_or(false);
                    if !spam_tlds.is_empty() && (use_spam || has_active_spam_tld) {
                        p_set.retain(|d| {
                            d.rsplit_once('.').map(|(_, tld)| !spam_tlds.contains(tld)).unwrap_or(true)
                        });
                    }
                }

                let mut pruned: Vec<String> = p_set.iter().filter(|d| !has_parent_match(d, &p_set)).cloned().collect();
                pruned.sort();
                (p.clone(), pruned)
            }
        })
        .collect()
}

fn compile_category_expression(p: &Value) -> String {
    let mut parts = Vec::new();
    for (key, field) in [
        ("security_categories", "dns.security_category[*]"),
        ("content_categories", "dns.content_category[*]"),
        ("app_ids", "app.ids[*]"),
    ] {
        if let Some(arr) = p.get(key).and_then(Value::as_array) {
            if !arr.is_empty() {
                let ids: Vec<String> = arr.iter().map(|v| v.to_string().trim_matches('"').to_string()).collect();
                parts.push(format!("any({} in {{{}}})", field, ids.join(" ")));
            }
        }
    }
    if let Some(doms) = p.get("domains").and_then(Value::as_array) {
        if !doms.is_empty() {
            let quoted: Vec<String> = doms.iter().filter_map(Value::as_str).map(|d| format!("\"{}\"", d)).collect();
            parts.push(format!("any(dns.domains[*] in {{{}}})", quoted.join(" ")));
        }
    }
    parts.join(" or ")
}

fn build_rule_update_payload(rule: &Value, enabled: bool, traffic: &str) -> Value {
    let mut payload = json!({
        "name": rule.get("name").and_then(Value::as_str).unwrap_or(""),
        "action": rule.get("action").and_then(Value::as_str).unwrap_or("block"),
        "enabled": enabled,
        "filters": rule.get("filters").cloned().unwrap_or_else(|| json!(["dns"])),
        "traffic": traffic,
    });
    for opt_key in ["identity", "device_posture", "rule_settings", "schedule", "precedence", "description"] {
        if let Some(v) = rule.get(opt_key) {
            if !v.is_null() {
                payload.as_object_mut().unwrap().insert(opt_key.to_string(), v.clone());
            }
        }
    }
    payload
}

fn detach_lists_from_rules(
    cf: &CloudflareAPI,
    list_ids: &[String],
    existing_rules: &mut [Value],
) -> Result<Vec<Value>> {
    if list_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut snapshots = Vec::new();
    let mut detached_any = false;

    for rule in existing_rules.iter_mut() {
        let traffic = rule.get("traffic").and_then(Value::as_str).unwrap_or("");
        if !list_ids.iter().any(|id| traffic.contains(&format!("${}", id))) {
            continue;
        }
        let rname = rule.get("name").and_then(Value::as_str).unwrap_or("");
        let rid = rule.get("id").and_then(Value::as_str).unwrap_or("");
        log_info!("Detaching lists from policy rule '{}'...", rname);

        snapshots.push(rule.clone());

        let dummy_traffic = r#"any(dns.domains[*] in {"invalid.local.blocklist.temp"})"#;
        let payload = build_rule_update_payload(rule, false, dummy_traffic);

        cf.update_rule(rid, &payload)
            .with_context(|| format!("Failed to detach lists from rule {}", rname))?;
        rule.as_object_mut().unwrap().insert("traffic".to_string(), json!(dummy_traffic));
        rule.as_object_mut().unwrap().insert("enabled".to_string(), json!(false));
        detached_any = true;
    }
    if detached_any {
        thread::sleep(Duration::from_secs(2));
    }
    Ok(snapshots)
}

fn restore_detached_rules(cf: &CloudflareAPI, snapshots: &[Value]) {
    if snapshots.is_empty() {
        return;
    }
    log_warn!("Restoring {} detached rule(s) to previous state after sync failure...", snapshots.len());
    for rule in snapshots {
        let rname = rule.get("name").and_then(Value::as_str).unwrap_or("");
        let rid = rule.get("id").and_then(Value::as_str).unwrap_or("");
        let enabled = rule.get("enabled").and_then(Value::as_bool).unwrap_or(true);
        let traffic = rule.get("traffic").and_then(Value::as_str).unwrap_or("");
        let payload = build_rule_update_payload(rule, enabled, traffic);
        if let Err(e) = cf.update_rule(rid, &payload) {
            log_err!("Failed restoring rule '{}': {}", rname, e);
        } else {
            log_info!("Restored rule '{}'", rname);
        }
    }
}

fn safe_delete_list_with_rule_disabling(
    cf: &CloudflareAPI,
    list_item: &Value,
    existing_rules: &mut [Value],
) -> Result<()> {
    let list_name = list_item.get("name").and_then(Value::as_str).unwrap_or("");
    let list_id = list_item.get("id").and_then(Value::as_str).unwrap_or("");

    detach_lists_from_rules(cf, &[list_id.to_string()], existing_rules)?;

    for attempt in 0..3 {
        match cf.delete_list(list_id) {
            Ok(_) => {
                log_info!("Removed list: {} ({})", list_name, list_id);
                return Ok(());
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("400") && err_str.contains("in use at gateway policies") && attempt < 2 {
                    let wait = Duration::from_secs((1 << attempt) + 1) + jitter_ms(500);
                    log_warn!("List {} still locked. Retrying in {:.2}s...", list_id, wait.as_secs_f64());
                    thread::sleep(wait);
                    continue;
                }
                log_err!("Failed deleting list {} ({}) after {} attempts: {}", list_name, list_id, attempt + 1, e);
                return Err(e);
            }
        }
    }
    bail!("Failed deleting list {} ({}) after 3 attempts.", list_name, list_id)
}

fn sync_policy_in_place(
    cf: &CloudflareAPI,
    cfg: &AppConfig,
    existing_lists: &[Value],
    existing_rules: &mut Vec<Value>,
    entries: &[String],
    policy: &Value,
    tld_expr: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let prefix = policy.get("prefix").and_then(Value::as_str).unwrap_or("");
    let policy_name = policy.get("name").and_then(Value::as_str).unwrap_or("");
    let policy_type = policy.get("type").and_then(Value::as_str).unwrap_or("DOMAIN").to_uppercase();
    let write_workers = cfg.max_workers.min(3);

    let mut matched_lists: Vec<&Value> = existing_lists
        .iter()
        .filter(|l| l.get("name").and_then(Value::as_str).unwrap_or("").starts_with(&format!("{} ", prefix)))
        .collect();
    matched_lists.sort_by_key(|l| l.get("name").and_then(Value::as_str).unwrap_or(""));

    let chunks: Vec<&[String]> = if entries.is_empty() {
        Vec::new()
    } else {
        entries.chunks(cfg.max_list_size).collect()
    };

    let pool = rayon::ThreadPoolBuilder::new().num_threads(write_workers).build()?;
    let chunk_results: Result<Vec<Option<String>>> = pool.install(|| {
        chunks
            .par_iter()
            .enumerate()
            .map(|(idx, chunk)| {
                let name = format!("{} {:03}", prefix, idx + 1);
                let mut current_chunk: Vec<String> = chunk.to_vec();

                for attempt in 0..3 {
                    if current_chunk.is_empty() {
                        return Ok(None);
                    }
                    let joined = current_chunk.join(",");
                    let chash = format!("{:x}", Sha256::digest(joined.as_bytes()));
                    let items: Vec<Value> = current_chunk.iter().map(|e| json!({ "value": e })).collect();

                    let res = if idx < matched_lists.len() {
                        let target = matched_lists[idx];
                        let tid = target.get("id").and_then(Value::as_str).unwrap_or("");
                        let tname = target.get("name").and_then(Value::as_str).unwrap_or("");
                        let tdesc = target.get("description").and_then(Value::as_str).unwrap_or("");
                        let tcount = target.get("count").and_then(Value::as_u64);

                        if tname == name && tdesc == chash && tcount.map_or(true, |c| c as usize == current_chunk.len()) {
                            return Ok(Some(tid.to_string()));
                        }
                        cf.update_list(tid, &name, &items, &chash).map(|_| {
                            log_info!("Updated {} ({} {} items)", name, current_chunk.len(), policy_type.to_lowercase());
                            tid.to_string()
                        })
                    } else {
                        cf.create_list(&name, &items, &policy_type, &chash).map(|r| {
                            log_info!("Created {} ({} {} items)", name, current_chunk.len(), policy_type.to_lowercase());
                            r["result"]["id"].as_str().unwrap_or("").to_string()
                        })
                    };

                    match res {
                        Ok(id) => return Ok(Some(id)),
                        Err(e) => {
                            let err_str = e.to_string();
                            if attempt < 2 {
                                if let Some(caps) = invalid_label_re().captures(&err_str) {
                                    let bad_label = caps[1].to_lowercase();
                                    let before_len = current_chunk.len();
                                    current_chunk.retain(|d| {
                                        let dl = d.to_lowercase();
                                        dl != bad_label && !dl.split('.').any(|lbl| lbl == bad_label)
                                    });
                                    if current_chunk.len() < before_len {
                                        log_warn!("Purged Cloudflare-rejected label '{}' from {} and retrying...", bad_label, name);
                                        continue;
                                    }
                                }
                            }
                            log_err!("Error syncing {} (chunk size: {}): {}", name, current_chunk.len(), e);
                            return Err(e);
                        }
                    }
                }
                Ok(None)
            })
            .collect()
    });

    let active_ids: Vec<String> = chunk_results?.into_iter().flatten().collect();
    let surplus_ids: Vec<String> = if matched_lists.len() > chunks.len() {
        matched_lists[chunks.len()..]
            .iter()
            .filter_map(|l| l.get("id").and_then(Value::as_str).map(String::from))
            .collect()
    } else {
        Vec::new()
    };

    let mut list_items: Vec<String> = if policy_type == "IP" {
        active_ids.iter().map(|lid| format!("any(dns.resolved_ips[*] in ${})", lid)).collect()
    } else {
        let mut items: Vec<String> = active_ids.iter().map(|lid| format!("any(dns.domains[*] in ${})", lid)).collect();
        if !tld_expr.is_empty() && policy.get("use_spam_tld").and_then(Value::as_bool).unwrap_or(false) {
            items.push(format!("({})", tld_expr));
        }
        items
    };

    let cat_expr = compile_category_expression(policy);
    if !cat_expr.is_empty() {
        list_items.push(cat_expr);
    }

    let rule_idx = existing_rules
        .iter()
        .position(|r| r.get("name").and_then(Value::as_str) == Some(policy_name));

    if list_items.is_empty() {
        log_warn!("Policy '{}' has no active list items, categories, or expressions.", policy_name);
        if let Some(idx) = rule_idx {
            let rid = existing_rules[idx].get("id").and_then(Value::as_str).unwrap_or("");
            if let Err(e) = cf.delete_rule(rid) {
                log_err!("Failed deleting inactive rule {}: {}", policy_name, e);
            } else {
                log_info!("Removed inactive firewall rule: {}", policy_name);
                existing_rules.remove(idx);
            }
        }
        return Ok((active_ids, surplus_ids, Vec::new()));
    }

    let cond = if policy.get("restrict_users").and_then(Value::as_bool).unwrap_or(false) {
        cfg.target_identity.clone()
    } else {
        policy.get("identity_condition").and_then(Value::as_str).map(String::from)
    };

    let (traffic_expr, identity_expr) = if let Some(c) = cond {
        if !c.contains("dns.") {
            (list_items.join(" or "), c)
        } else {
            let wrapped: Vec<String> = list_items.iter().map(|item| format!("({} and {})", c, item)).collect();
            (wrapped.join(" or "), String::new())
        }
    } else {
        (list_items.join(" or "), String::new())
    };

    let pol_enabled_opt = policy.get("enabled").and_then(Value::as_bool);
    let rule_enabled = if pol_enabled_opt == Some(false) {
        false
    } else if cfg.auto_enable_rules {
        true
    } else {
        match rule_idx.map(|i| &existing_rules[i]) {
            Some(r) => r.get("enabled").and_then(Value::as_bool).unwrap_or(true),
            None => pol_enabled_opt.unwrap_or(false),
        }
    };

    let block_page = policy.get("block_page_enabled").and_then(Value::as_bool).unwrap_or(cfg.block_page_enabled);
    let ip_cat = policy.get("ip_categories").and_then(Value::as_bool).unwrap_or(false);

    let mut existing_settings = rule_idx
        .and_then(|i| existing_rules[i].get("rule_settings"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    existing_settings.insert("block_page_enabled".to_string(), json!(block_page));
    existing_settings.insert("ip_categories".to_string(), json!(ip_cat));

    let action = policy.get("action").and_then(Value::as_str).unwrap_or("block");
    let mut payload = json!({
        "name": policy_name,
        "action": action,
        "enabled": rule_enabled,
        "filters": ["dns"],
        "traffic": traffic_expr,
        "rule_settings": existing_settings,
    });
    if !identity_expr.is_empty() {
        payload.as_object_mut().unwrap().insert("identity".to_string(), json!(identity_expr));
    }

    if let Some(idx) = rule_idx {
        let (needs_update, rid) = {
            let r = &existing_rules[idx];
            for key in ["precedence", "description", "schedule", "device_posture"] {
                if let Some(v) = r.get(key) {
                    if !v.is_null() {
                        payload.as_object_mut().unwrap().insert(key.to_string(), v.clone());
                    }
                }
            }
            let old_settings = r.get("rule_settings").and_then(Value::as_object);
            let settings_changed = old_settings.and_then(|s| s.get("block_page_enabled")).and_then(Value::as_bool) != Some(block_page)
                || old_settings.and_then(|s| s.get("ip_categories")).and_then(Value::as_bool).unwrap_or(false) != ip_cat;
            let existing_identity = r.get("identity").and_then(Value::as_str).unwrap_or("");

            let changed = r.get("traffic").and_then(Value::as_str) != Some(&traffic_expr)
                || existing_identity != identity_expr
                || r.get("enabled").and_then(Value::as_bool) != Some(rule_enabled)
                || r.get("action").and_then(Value::as_str) != Some(action)
                || settings_changed;
            let id_str = r.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            (changed, id_str)
        };

        if needs_update {
            let resp = cf.update_rule(&rid, &payload)?;
            if let Some(updated) = resp.get("result").cloned() {
                existing_rules[idx] = updated;
            } else {
                existing_rules[idx].as_object_mut().unwrap().insert("traffic".to_string(), json!(traffic_expr));
                existing_rules[idx].as_object_mut().unwrap().insert("enabled".to_string(), json!(rule_enabled));
            }
            log_info!("Updated firewall rule: {} (enabled={}, block_page={}, ip_categories={})", policy_name, rule_enabled, block_page, ip_cat);
        }
    } else {
        let resp = cf.create_rule(&payload)?;
        if let Some(created) = resp.get("result").cloned() {
            existing_rules.push(created);
        }
        log_info!("Created firewall rule: {} (enabled={}, block_page={}, ip_categories={})", policy_name, rule_enabled, block_page, ip_cat);
    }

    Ok((active_ids, surplus_ids, vec![policy_name.to_string()]))
}

fn sync_standalone_policies(cf: &CloudflareAPI, cfg: &AppConfig, existing_rules: &mut [Value]) -> Vec<String> {
    let Some(standalone_cfg) = cfg.raw.get("gateway_policies").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut synced = Vec::new();
    for (rule_name, desired_val) in standalone_cfg {
        let Some(desired_enabled) = desired_val.as_bool() else { continue };
        let Some(matched) = existing_rules.iter_mut().find(|r| r.get("name").and_then(Value::as_str) == Some(rule_name)) else {
            continue;
        };
        synced.push(rule_name.clone());
        let currently_enabled = matched.get("enabled").and_then(Value::as_bool).unwrap_or(true);

        if !cfg.auto_enable_rules && !currently_enabled && desired_enabled {
            log_info!("Skipping auto-enable for disabled standalone policy: {}", rule_name);
            continue;
        }
        if currently_enabled != desired_enabled {
            let traffic = matched.get("traffic").and_then(Value::as_str).unwrap_or("");
            let payload = build_rule_update_payload(matched, desired_enabled, traffic);
            let rid = matched.get("id").and_then(Value::as_str).unwrap_or("");
            match cf.update_rule(rid, &payload) {
                Ok(_) => {
                    matched.as_object_mut().unwrap().insert("enabled".to_string(), json!(desired_enabled));
                    log_info!("Updated standalone policy state: {} -> {}", rule_name, if desired_enabled { "enabled" } else { "disabled" });
                }
                Err(e) => log_err!("Failed to update standalone policy {}: {}", rule_name, e),
            }
        }
    }
    synced
}

fn cleanup_orphans(
    cf: &CloudflareAPI,
    cfg: &AppConfig,
    existing_lists: &[Value],
    existing_rules: &mut [Value],
    active_ids: &[String],
    surplus_ids: &[String],
    active_rules: &[String],
) -> Result<()> {
    let mut protected_rules: HashSet<String> = [
        "IoT Bypass", "Custom", "Keywords", "SafeSearch",
        "Global Blocklist", "Global Bypass", "Block IoT Network", "YouTube Restricted",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    if let Some(gp) = cfg.raw.get("gateway_policies").and_then(Value::as_object) {
        protected_rules.extend(gp.keys().cloned());
    }

    let active_rules_set: HashSet<&str> = active_rules.iter().map(String::as_str).collect();
    let mut deleted_any_rule = false;

    for r in existing_rules.iter() {
        let rname = r.get("name").and_then(Value::as_str).unwrap_or("");
        if protected_rules.contains(rname) || protected_rules.iter().any(|k| rname.contains(k)) {
            continue;
        }
        if !active_rules_set.contains(rname) && cfg.scrub_targets.iter().any(|t| rname.contains(t)) {
            let rid = r.get("id").and_then(Value::as_str).unwrap_or("");
            match cf.delete_rule(rid) {
                Ok(_) => {
                    deleted_any_rule = true;
                    log_info!("Removed orphaned rule: {}", rname);
                }
                Err(e) => log_err!("Rule cleanup error ({}): {}", rname, e),
            }
        }
    }

    if deleted_any_rule || !surplus_ids.is_empty() {
        thread::sleep(Duration::from_secs(2));
    }

    let active_set: HashSet<&str> = active_ids.iter().map(String::as_str).collect();
    let surplus_set: HashSet<&str> = surplus_ids.iter().map(String::as_str).collect();

    let mut lists_to_delete: Vec<&Value> = Vec::new();
    for l in existing_lists {
        let lid = l.get("id").and_then(Value::as_str).unwrap_or("");
        let lname = l.get("name").and_then(Value::as_str).unwrap_or("");
        if surplus_set.contains(lid)
            || (!active_set.contains(lid)
                && cfg.scrub_targets.iter().any(|t| lname.contains(t))
                && !lname.contains("IoT Bypass"))
        {
            lists_to_delete.push(l);
        }
    }

    let ids_to_detach: Vec<String> = lists_to_delete
        .iter()
        .filter_map(|l| l.get("id").and_then(Value::as_str).map(String::from))
        .collect();
    detach_lists_from_rules(cf, &ids_to_detach, existing_rules)?;

    for l in lists_to_delete {
        safe_delete_list_with_rule_disabling(cf, l, existing_rules)?;
    }

    Ok(())
}

fn filter_policy_includes<F>(policies: &mut [Value], pred: F)
where
    F: Fn(&str) -> bool,
{
    for p in policies.iter_mut() {
        if let Some(arr) = p.get_mut("include").and_then(Value::as_array_mut) {
            arr.retain(|v| v.as_str().map(&pred).unwrap_or(true));
        }
    }
}

fn main() -> Result<()> {
    let start = Instant::now();
    let cfg = load_config()?;
    let cf = CloudflareAPI::new(&cfg)?;

    rayon::ThreadPoolBuilder::new().num_threads(cfg.max_workers).build_global().ok();

    let mut policies: Vec<Value> = cfg
        .raw
        .get("policies")
        .and_then(Value::as_object)
        .map(|m| m.values().cloned().collect())
        .unwrap_or_default();

    let use_spam_tld_any = policies.iter().any(|p| p.get("use_spam_tld").and_then(Value::as_bool).unwrap_or(false));

    if use_spam_tld_any {
        if let Some(sa) = cfg.raw.get("spam_allow_source").and_then(Value::as_object) {
            if let Some(sa_name) = sa.get("name").and_then(Value::as_str) {
                policies.push(json!({
                    "prefix": "L_AllowSpam",
                    "name": "Allow: Spam Exceptions",
                    "action": "allow",
                    "type": "DOMAIN",
                    "include": [sa_name],
                    "exclude": [],
                    "use_spam_tld": false,
                }));
            }
        }
    }

    let mut domain_sources = parse_sources(cfg.raw.get("sources").and_then(Value::as_object), false);
    let ip_sources = parse_sources(cfg.raw.get("ip_sources").and_then(Value::as_object), true);

    if use_spam_tld_any {
        if let Some(sa) = cfg.raw.get("spam_allow_source").and_then(Value::as_object) {
            if let (Some(name), Some(url)) = (sa.get("name").and_then(Value::as_str), sa.get("url").and_then(Value::as_str)) {
                domain_sources.push(SourceSpec {
                    name: name.to_string(),
                    urls: vec![url.to_string()],
                    enable_relevance: sa.get("relevance").and_then(Value::as_bool).unwrap_or(false),
                });
            }
        }
    }

    let feed_client = build_http_client(Duration::from_secs(90), None)?;
    let relevance_set = if domain_sources.iter().any(|s| s.enable_relevance) {
        Some(build_relevance_dataset(&feed_client)?)
    } else {
        None
    };

    let tld_url = cfg.raw.get("tld").and_then(|t| t.get("url")).and_then(Value::as_str).unwrap_or("");
    let (tld_expr, spam_tlds) = if !tld_url.is_empty() && use_spam_tld_any {
        fetch_spam_tlds(&feed_client, tld_url)
            .with_context(|| format!("Spam TLD feed failure ({}). Aborting.", tld_url))?
    } else {
        (String::new(), HashSet::new())
    };

    let domain_results: Result<Vec<(String, FetchedFeed)>> = domain_sources
        .par_iter()
        .map(|s| {
            let rel = if s.enable_relevance { relevance_set.as_ref() } else { None };
            let kept = fetch_feed_source(&feed_client, s, rel)?;
            if kept.is_empty() {
                bail!("Feed '{}' returned 0 valid domains.", s.name);
            }
            Ok((s.name.clone(), FetchedFeed::Domain(kept)))
        })
        .collect();

    let ip_results: Result<Vec<(String, FetchedFeed)>> = ip_sources
        .par_iter()
        .map(|s| {
            let nets = fetch_ip_source(&feed_client, s)?;
            if nets.is_empty() {
                bail!("IP feed '{}' returned 0 valid subnets.", s.name);
            }
            Ok((s.name.clone(), FetchedFeed::Ip(nets)))
        })
        .collect();

    let mut fetched: HashMap<String, FetchedFeed> = HashMap::new();
    for (k, v) in domain_results? {
        fetched.insert(k, v);
    }
    for (k, v) in ip_results? {
        fetched.insert(k, v);
    }

    let mut existing_lists = cf.get_lists()?;
    let mut existing_rules = cf.get_rules()?;

    let mut unmanaged_lists_count = 0usize;
    let mut current_managed_items = 0usize;
    for l in &existing_lists {
        let lname = l.get("name").and_then(Value::as_str).unwrap_or("");
        let is_managed = cfg.scrub_targets.iter().any(|t| lname.contains(t)) && !lname.contains("IoT Bypass");
        if is_managed {
            current_managed_items += l.get("count").and_then(Value::as_u64).unwrap_or(0) as usize;
        } else {
            unmanaged_lists_count += 1;
        }
    }

    let max_managed_lists = MAX_CLOUDFLARE_LISTS.saturating_sub(unmanaged_lists_count);

    let mut compiled = build_policy_sets(&policies, &fetched, &spam_tlds);
    let mut total_entries: usize = compiled.iter().map(|(_, items)| items.len()).sum();
    let mut estimated_chunks: usize = compiled.iter().map(|(_, items)| items.len().div_ceil(cfg.max_list_size)).sum();

    // Fallback Tier 1: Shed OISD NSFW first to preserve threat-intelligence feeds
    if total_entries > cfg.total_quota || estimated_chunks > max_managed_lists {
        log_warn!(
            "Capacity constraint reached (Entries: {}/{}, Estimated Lists: {}/{}). Shedding OISD NSFW...",
            total_entries,
            cfg.total_quota,
            estimated_chunks,
            max_managed_lists
        );
        filter_policy_includes(&mut policies, |inc| {
            let l = inc.to_lowercase();
            !(l.contains("oisd") && l.contains("nsfw"))
        });
        compiled = build_policy_sets(&policies, &fetched, &spam_tlds);
        total_entries = compiled.iter().map(|(_, items)| items.len()).sum();
        estimated_chunks = compiled.iter().map(|(_, items)| items.len().div_ceil(cfg.max_list_size)).sum();
    }

    // Fallback Tier 2: Shed HaGeZi TIF IPs if still over quota/list limits
    if total_entries > cfg.total_quota || estimated_chunks > max_managed_lists {
        log_warn!(
            "Capacity still exceeded (Entries: {}/{}, Estimated Lists: {}/{}). Shedding HaGeZi TIF IPs...",
            total_entries,
            cfg.total_quota,
            estimated_chunks,
            max_managed_lists
        );
        filter_policy_includes(&mut policies, |inc| {
            let l = inc.to_lowercase();
            !(l.contains("tif") && l.contains("ip"))
        });
        compiled = build_policy_sets(&policies, &fetched, &spam_tlds);
        total_entries = compiled.iter().map(|(_, items)| items.len()).sum();
        estimated_chunks = compiled.iter().map(|(_, items)| items.len().div_ceil(cfg.max_list_size)).sum();
    }

    // Fallback Tier 3: Shed HaGeZi TIF domain feeds if still over quota/list limits
    if total_entries > cfg.total_quota || estimated_chunks > max_managed_lists {
        log_warn!(
            "Capacity still exceeded (Entries: {}/{}, Estimated Lists: {}/{}). Shedding HaGeZi TIF domain feeds...",
            total_entries,
            cfg.total_quota,
            estimated_chunks,
            max_managed_lists
        );
        filter_policy_includes(&mut policies, |inc| !inc.to_lowercase().contains("tif"));
        compiled = build_policy_sets(&policies, &fetched, &spam_tlds);
        total_entries = compiled.iter().map(|(_, items)| items.len()).sum();
    }

    // Truncation / Feed Poisoning Protection Guard
    if current_managed_items > 10_000 {
        let ratio = total_entries as f64 / current_managed_items as f64;
        if ratio < MAX_DROP_RATIO {
            bail!(
                "Upstream feed truncation detected! Compiled entries dropped by {:.1}% ({} vs {} currently active). Aborting to protect live rules.",
                (1.0 - ratio) * 100.0,
                total_entries,
                current_managed_items
            );
        }
    }

    let final_chunks: usize = compiled.iter().map(|(_, items)| items.len().div_ceil(cfg.max_list_size)).sum();
    if total_entries > cfg.total_quota || final_chunks > max_managed_lists {
        bail!(
            "Capacity exceeded after all fallback tiers (Entries: {}/{}, Lists: {}/{}). Aborting.",
            total_entries,
            cfg.total_quota,
            final_chunks,
            max_managed_lists
        );
    }

    log_info!(
        "Current Cloudflare lists count: {} ({} unmanaged, {} live items). Syncing {} lists in place...",
        existing_lists.len(),
        unmanaged_lists_count,
        current_managed_items,
        final_chunks
    );

    let standalone_rules = sync_standalone_policies(&cf, &cfg, &mut existing_rules);

    let mut all_active_ids = Vec::new();
    let mut all_surplus_ids = Vec::new();
    let mut all_active_rules = standalone_rules;

    let run_sync = |compiled_sets: &[(Value, Vec<String>)],
                    elists: &[Value],
                    erules: &mut Vec<Value>,
                    act_ids: &mut Vec<String>,
                    sur_ids: &mut Vec<String>,
                    act_rules: &mut Vec<String>|
     -> Result<()> {
        for (policy, optimized_entries) in compiled_sets {
            let expr = if policy.get("use_spam_tld").and_then(Value::as_bool).unwrap_or(false) {
                tld_expr.as_str()
            } else {
                ""
            };
            let (a_ids, s_ids, r_names) =
                sync_policy_in_place(&cf, &cfg, elists, erules, optimized_entries, policy, expr)?;
            act_ids.extend(a_ids);
            sur_ids.extend(s_ids);
            act_rules.extend(r_names);
        }
        Ok(())
    };

    if let Err(e) = run_sync(&compiled, &existing_lists, &mut existing_rules, &mut all_active_ids, &mut all_surplus_ids, &mut all_active_rules) {
        let err_str = e.to_string();
        if err_str.contains("Maximum number of lists reached") || err_str.contains("2017") {
            log_err!("Cloudflare list limit (300) hit during sync! Forcing emergency OISD NSFW & TIF purge and list reclamation...");
            existing_lists = cf.get_lists()?;
            existing_rules = cf.get_rules()?;

            let managed_lists: Vec<Value> = existing_lists
                .iter()
                .filter(|l| {
                    let lname = l.get("name").and_then(Value::as_str).unwrap_or("");
                    cfg.scrub_targets.iter().any(|t| lname.contains(t)) && !lname.contains("IoT Bypass")
                })
                .cloned()
                .collect();

            let managed_ids: Vec<String> = managed_lists
                .iter()
                .filter_map(|l| l.get("id").and_then(Value::as_str).map(String::from))
                .collect();

            let rule_snapshots = detach_lists_from_rules(&cf, &managed_ids, &mut existing_rules)?;

            let recovery_result: Result<()> = (|| {
                for l_obj in &managed_lists {
                    safe_delete_list_with_rule_disabling(&cf, l_obj, &mut existing_rules)?;
                }
                thread::sleep(Duration::from_secs(3));

                filter_policy_includes(&mut policies, |inc| {
                    let l = inc.to_lowercase();
                    !(l.contains("oisd") && l.contains("nsfw")) && !l.contains("tif")
                });
                compiled = build_policy_sets(&policies, &fetched, &spam_tlds);
                existing_lists = cf.get_lists()?;
                existing_rules = cf.get_rules()?;

                all_active_ids.clear();
                all_surplus_ids.clear();
                run_sync(&compiled, &existing_lists, &mut existing_rules, &mut all_active_ids, &mut all_surplus_ids, &mut all_active_rules)
            })();

            if let Err(rec_err) = recovery_result {
                restore_detached_rules(&cf, &rule_snapshots);
                return Err(rec_err);
            }
        } else {
            return Err(e);
        }
    }

    cleanup_orphans(&cf, &cfg, &existing_lists, &mut existing_rules, &all_active_ids, &all_surplus_ids, &all_active_rules)?;

    log_info!(
        "Sync completed successfully in {:.2}s ({} items across {} lists).",
        start.elapsed().as_secs_f64(),
        total_entries,
        all_active_ids.len()
    );
    Ok(())
}
