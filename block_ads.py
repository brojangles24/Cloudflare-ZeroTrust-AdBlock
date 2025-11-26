#!/usr/bin/env python3
import os
import sys
import gzip
import time
import json
import hashlib
import requests
import concurrent.futures
from datetime import datetime
from collections import Counter

# ---------------- CONFIG ----------------

SOURCES = {
    "OISD_WILD": "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt",
    "HAGEZI_ULTIMATE": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard.txt",
    "STEVENBLACK": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
}

CACHE_DIR = "cache"
OUTPUT = "singularity_final.txt"
EXTRA_ALLOW = {"localhost"}

THREADS = 12

# ----------------------------------------


os.makedirs(CACHE_DIR, exist_ok=True)


def cache_path(name):
    return os.path.join(CACHE_DIR, f"{name}.cache")


def load_cache(name):
    p = cache_path(name)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "rb") as f:
            return json.loads(f.read().decode())
    except:
        return None


def save_cache(name, data):
    with open(cache_path(name), "wb") as f:
        f.write(json.dumps(data).encode())


def fetch(name, url):
    headers = {}
    cached = load_cache(name)
    if cached:
        if "etag" in cached:
            headers["If-None-Match"] = cached["etag"]
        if "last" in cached:
            headers["If-Modified-Since"] = cached["last"]

    try:
        r = requests.get(url, headers=headers, timeout=30)
    except:
        return cached["data"] if cached else ""

    if r.status_code == 304 and cached:
        return cached["data"]

    text = r.text
    etag = r.headers.get("ETag")
    last = r.headers.get("Last-Modified")

    save_cache(name, {"data": text, "etag": etag, "last": last})
    return text


def normalize(line):
    line = line.strip().lower()
    if not line:
        return None
    if line.startswith("#"):
        return None
    if " " in line:
        parts = line.split()
        line = parts[-1]
    if line.count(".") < 1:
        return None
    return line


def dedupe(domains):
    out = set()
    for d in domains:
        if not d:
            continue
        out.add(d)
    return out


def safe_parse(text):
    domains = []
    for ln in text.splitlines():
        d = normalize(ln)
        if d:
            domains.append(d)
    return domains


def process_source(name, url):
    text = fetch(name, url)
    return safe_parse(text)


def strongest_aggregation(raw_lists):
    counter = Counter()
    for src, domains in raw_lists.items():
        for d in domains:
            counter[d] += 1
    final = set()
    for d, score in counter.items():
        if score > 1:  # threshold adjustable
            final.add(d)
    return final


def main():
    start = time.time()
    raw_lists = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(process_source, name, url): name for name, url in SOURCES.items()}
        for f in futures:
            name = futures[f]
            try:
                raw_lists[name] = f.result()
            except:
                raw_lists[name] = []

    merged = strongest_aggregation(raw_lists)
    cleaned = merged.difference(EXTRA_ALLOW)

    cleaned = sorted(cleaned)

    with open(OUTPUT, "w") as f:
        f.write("# Singularity DNS Aggregator Output\n")
        f.write("# Generated: " + datetime.utcnow().isoformat() + "Z\n")
        f.write("# Total: " + str(len(cleaned)) + "\n\n")
        f.write("\n".join(cleaned))

    duration = round(time.time() - start, 2)
    print("Done in", duration, "sec. Domains:", len(cleaned))


if __name__ == "__main__":
    main()
