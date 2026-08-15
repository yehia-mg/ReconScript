#!/usr/bin/env python3
"""
recon.py — Subdomain enumeration, DNS/HTTP filtering, and API-endpoint discovery.

Pipeline:
  1) Collect subdomains  -> subfinder + assetfinder + amass (passive)
  2) DNS resolve/filter  -> dnsx
  3) HTTP probe/classify -> httpx  (200 / 302 / other)
  4) Endpoint discovery  -> katana + waybackurls
  5) API-pattern filter  -> regex over discovered endpoints
  6) Save results        -> collected_subdomains/scan_N*.txt (auto-incrementing)

Cross-platform: works the same on Linux and Windows, as long as the
external tools (subfinder, assetfinder, amass, dnsx, httpx, katana,
waybackurls) are installed and available on PATH.

Usage:
    python recon.py -d example.com
    python recon.py -d example.com -o my_output_dir
    python recon.py -l domains.txt

IMPORTANT: Only run this against domains/assets you are authorized to test
(your own infrastructure, or an in-scope bug bounty program).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_OUTPUT_DIR = "collected_subdomains"

# No per-tool timeouts by default — large scopes (500+ hosts, big Wayback
# archives) can legitimately take a long time, and killing a tool mid-run
# just loses work. Tools are left to finish naturally. If you ever want a
# hard cap again, set a value (in seconds) here instead of None.
TIMEOUTS = {
    "subfinder": None,
    "assetfinder": None,
    "amass": None,
    "dnsx": None,
    "httpx": None,
    "katana": None,
    "waybackurls": None,
}

# Rate limits (requests/queries per second) for tools that hit the target
# directly. This protects the target from being hammered and keeps the scan
# within reasonable bug-bounty program limits. Passive-only tools that query
# third-party sources (subfinder, assetfinder, amass -passive, waybackurls)
# aren't rate-limited here since they don't touch the target's own servers.
RATE_LIMITS = {
    "dnsx": 100,     # DNS queries/sec against the target's resolvers
    "httpx": 50,     # HTTP requests/sec against the target's servers
    "katana": 20,    # HTTP requests/sec while crawling the target
}

# Regex used to flag API-looking endpoints/subdomains
API_PATTERN = re.compile(
    r"(api[0-9]*[.\-]|[.\-]api[0-9]*[.\-]|graphql|/v[0-9]+/|/api/|swagger|openapi)",
    re.IGNORECASE,
)

REQUIRED_TOOLS = ["subfinder", "assetfinder", "amass", "dnsx", "httpx", "katana", "waybackurls"]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def tool_exists(name: str) -> bool:
    """Check if a tool is available on PATH (cross-platform, handles .exe on Windows)."""
    return shutil.which(name) is not None


def check_tools():
    """Warn about any missing tools before starting. Doesn't hard-exit, just informs."""
    missing = [t for t in REQUIRED_TOOLS if not tool_exists(t)]
    if missing:
        print("[!] The following tools are missing from PATH and their steps will be skipped:")
        for m in missing:
            print(f"    - {m}")
        print()
    return missing


def run_cmd(cmd, timeout, input_text=None):
    """Run a command and return its stdout as a list of non-empty lines. Fails soft."""
    tool_name = cmd[0]
    try:
        result = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            print(f"    [!] {tool_name} returned an error (code {result.returncode}): {result.stderr.strip()[:200]}")
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines
    except FileNotFoundError:
        print(f"    [!] {tool_name} is not installed or not found on PATH — skipping")
        return []
    except subprocess.TimeoutExpired as e:
        # subprocess.run() populates e.stdout/e.stderr with whatever output the
        # process had already produced before being killed — use it instead of
        # throwing away partial results.
        partial_stdout = e.stdout or ""
        if isinstance(partial_stdout, bytes):
            partial_stdout = partial_stdout.decode(errors="ignore")
        lines = [l.strip() for l in partial_stdout.splitlines() if l.strip()]
        if lines:
            print(f"    [!] {tool_name} exceeded {timeout}s and was stopped — keeping {len(lines)} partial result(s)")
        else:
            print(f"    [!] {tool_name} exceeded {timeout}s and was stopped with no usable output")
        return lines
    except Exception as e:
        print(f"    [!] Unexpected error while running {tool_name}: {e}")
        return []


def get_next_scan_number(output_dir: Path) -> int:
    """Look at existing scan_N.txt files and return the next available number."""
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = list(output_dir.glob("scan_*.txt"))
    numbers = []
    for f in existing:
        m = re.match(r"scan_(\d+)(?:_.*)?\.txt$", f.name)
        if m:
            numbers.append(int(m.group(1)))
    return (max(numbers) + 1) if numbers else 1


def save_list(path: Path, items):
    with open(path, "w", encoding="utf-8") as f:
        for item in sorted(set(items)):
            f.write(item + "\n")
    print(f"    [+] Saved: {path}  ({len(set(items))} lines)")


# --------------------------------------------------------------------------
# Step 1: Collection
# --------------------------------------------------------------------------

def collect_subdomains(domain: str) -> set:
    print("[1/5] Collecting subdomains (subfinder + assetfinder + amass)...")
    found = set()

    print("    -> subfinder")
    found.update(run_cmd(["subfinder", "-d", domain, "-silent"], TIMEOUTS["subfinder"]))

    print("    -> assetfinder")
    found.update(run_cmd(["assetfinder", "--subs-only", domain], TIMEOUTS["assetfinder"]))

    print("    -> amass (passive)")
    found.update(run_cmd(["amass", "enum", "-passive", "-d", domain, "-silent"], TIMEOUTS["amass"]))

    # keep only lines that actually look like subdomains of the target
    found = {f for f in found if domain in f}
    print(f"    [=] Total after merging and filtering: {len(found)}")
    return found


# --------------------------------------------------------------------------
# Step 2: DNS resolution filter
# --------------------------------------------------------------------------

def resolve_subdomains(subdomains: set) -> set:
    print("[2/5] DNS filtering (dnsx)...")
    if not subdomains:
        return set()
    input_text = "\n".join(sorted(subdomains)) + "\n"
    resolved = run_cmd(
        ["dnsx", "-silent", "-rate-limit", str(RATE_LIMITS["dnsx"])],
        TIMEOUTS["dnsx"],
        input_text=input_text,
    )
    resolved_set = set(resolved)
    print(f"    [=] Resolved: {len(resolved_set)} / {len(subdomains)}")
    return resolved_set if resolved_set else subdomains  # fail-open if dnsx unavailable


# --------------------------------------------------------------------------
# Step 3: HTTP probing / classification
# --------------------------------------------------------------------------

def probe_http(subdomains: set):
    print("[3/5] Probing HTTP status codes (httpx)...")
    result = {"200": [], "302": [], "other": []}
    if not subdomains:
        return result

    input_text = "\n".join(sorted(subdomains)) + "\n"
    # -json : structured output, immune to ANSI color codes / format drift
    #         between httpx versions (unlike parsing "-sc" plain text output)
    # -rate-limit : cap requests/sec against the target to stay respectful
    #         and within typical bug-bounty program limits
    # -retries 0 : skip retrying dead hosts; a single pass is enough here
    lines = run_cmd(
        ["httpx", "-silent", "-json", "-timeout", "10", "-retries", "0",
         "-rate-limit", str(RATE_LIMITS["httpx"])],
        TIMEOUTS["httpx"],
        input_text=input_text,
    )

    parse_failures = 0
    for line in lines:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            parse_failures += 1
            continue

        url = data.get("url") or data.get("input")
        code = data.get("status_code") or data.get("status-code") or data.get("statuscode")
        if url is None or code is None:
            continue

        code = str(code)
        if code == "200":
            result["200"].append(url)
        elif code == "302":
            result["302"].append(url)
        else:
            result["other"].append(url)

    if parse_failures:
        print(f"    [!] {parse_failures} httpx line(s) could not be parsed as JSON and were skipped")

    print(f"    [=] 200: {len(result['200'])} | 302: {len(result['302'])} | other: {len(result['other'])}")
    return result


# --------------------------------------------------------------------------
# Step 4: Endpoint discovery (katana + waybackurls) + API filtering
# --------------------------------------------------------------------------

def discover_endpoints(live_urls, domain: str) -> set:
    print("[4/5] Discovering additional endpoints (katana + waybackurls)...")
    endpoints = set()

    if live_urls:
        print("    -> katana")
        input_text = "\n".join(live_urls) + "\n"
        endpoints.update(
            run_cmd(
                ["katana", "-silent", "-jc", "-d", "2", "-rl", str(RATE_LIMITS["katana"])],
                TIMEOUTS["katana"],
                input_text=input_text,
            )
        )

    print("    -> waybackurls")
    endpoints.update(run_cmd(["waybackurls", domain], TIMEOUTS["waybackurls"]))

    print(f"    [=] Total endpoints discovered: {len(endpoints)}")
    return endpoints


def filter_api_endpoints(endpoints: set) -> set:
    return {e for e in endpoints if API_PATTERN.search(e)}


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Subdomain recon & API discovery pipeline")
    parser.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-l", "--list", help="File containing multiple domains, one per line")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_DIR, help="Output directory for results")
    args = parser.parse_args()

    if not args.domain and not args.list:
        parser.error("You must specify a domain with -d or a domain list file with -l")

    domains = []
    if args.domain:
        domains.append(args.domain.strip())
    if args.list:
        with open(args.list, "r", encoding="utf-8") as f:
            domains.extend([l.strip() for l in f if l.strip()])

    check_tools()

    output_dir = Path(args.output)
    scan_num = get_next_scan_number(output_dir)
    print(f"=== Scan #{scan_num} — Domains: {', '.join(domains)} ===\n")

    all_subdomains = set()
    all_endpoints = set()
    http_results = {"200": [], "302": [], "other": []}

    for domain in domains:
        subs = collect_subdomains(domain)
        resolved = resolve_subdomains(subs)
        classified = probe_http(resolved)
        for k in http_results:
            http_results[k].extend(classified[k])

        live = classified["200"] + classified["302"]
        endpoints = discover_endpoints(live, domain)
        all_endpoints.update(endpoints)
        all_subdomains.update(resolved)
        print()

    print("[5/5] Filtering API endpoints and saving results...")
    api_endpoints = filter_api_endpoints(all_endpoints)

    # Save everything
    save_list(output_dir / f"scan_{scan_num}.txt", all_subdomains)
    save_list(output_dir / f"scan_{scan_num}_200.txt", http_results["200"])
    save_list(output_dir / f"scan_{scan_num}_302.txt", http_results["302"])
    save_list(output_dir / f"scan_{scan_num}_other.txt", http_results["other"])
    save_list(output_dir / f"scan_{scan_num}_api.txt", api_endpoints)

    print(f"\n=== Scan #{scan_num} complete. Results saved in: {output_dir}/ ===")


if __name__ == "__main__":
    main()
