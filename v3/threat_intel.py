#!/usr/bin/env python3
"""
Demon-Pot — Threat Intelligence Sidecar
========================================
Watches credentials.jsonl in real-time.
For every new attacker IP it:
  1. Queries AbuseIPDB  — abuse confidence score + reports
  2. Queries GreyNoise  — internet scanner classification
  3. Writes enriched JSON to intel_output/enriched.jsonl
  4. Prints a colour-coded alert to stdout

Set API keys via environment variables:
  ABUSEIPDB_KEY   — https://www.abuseipdb.com/account/api
  GREYNOISE_KEY   — https://www.greynoise.io (free tier available)

Optional auto-block (Linux iptables, run as root):
  AUTO_BLOCK=true  — drop IPs scoring ≥ BLOCK_THRESHOLD
  BLOCK_THRESHOLD  — default 80 (AbuseIPDB score 0-100)
"""

import os
import sys
import json
import time
import subprocess
import ipaddress
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

# ─────────────────────────── CONFIG ──────────────────────────

LOG_DIR        = Path(os.getenv("LOG_DIR",        "/logs"))
OUTPUT_DIR     = Path(os.getenv("OUTPUT_DIR",     "/output"))
CRED_LOG       = LOG_DIR / "credentials.jsonl"
ENRICHED_LOG   = OUTPUT_DIR / "enriched.jsonl"
BLOCKED_LOG    = OUTPUT_DIR / "blocked_ips.jsonl"
SEEN_CACHE     = OUTPUT_DIR / ".seen_ips.json"

POLL_INTERVAL  = int(os.getenv("POLL_INTERVAL",   "30"))    # seconds
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY",       "")
GREYNOISE_KEY  = os.getenv("GREYNOISE_KEY",        "")
AUTO_BLOCK     = os.getenv("AUTO_BLOCK",           "false").lower() == "true"
BLOCK_THRESHOLD= int(os.getenv("BLOCK_THRESHOLD", "80"))
REQUEST_TIMEOUT= 10  # seconds per API call

# ANSI colours
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─────────────────────────── LOGGING ─────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("threat-intel")


# ─────────────────────────── HELPERS ─────────────────────────

def is_private_ip(ip: str) -> bool:
    """Skip RFC-1918 and loopback addresses."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def load_seen_cache() -> set:
    if SEEN_CACHE.exists():
        try:
            return set(json.loads(SEEN_CACHE.read_text()))
        except Exception:
            pass
    return set()


def save_seen_cache(seen: set):
    SEEN_CACHE.write_text(json.dumps(list(seen)))


def write_jsonl(filepath: Path, record: dict):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a") as f:
        f.write(json.dumps(record, default=str) + "\n")


# ─────────────────────────── API CLIENTS ─────────────────────

def query_abuseipdb(ip: str) -> Optional[dict]:
    """Query AbuseIPDB v2 — returns condensed result or None."""
    if not ABUSEIPDB_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "abuse_score":       d.get("abuseConfidenceScore", 0),
                "total_reports":     d.get("totalReports", 0),
                "country":           d.get("countryCode", "??"),
                "isp":               d.get("isp", ""),
                "domain":            d.get("domain", ""),
                "is_tor":            d.get("isTor", False),
                "usage_type":        d.get("usageType", ""),
                "last_reported_at":  d.get("lastReportedAt", ""),
            }
        elif r.status_code == 429:
            log.warning("AbuseIPDB rate limit hit — sleeping 60s")
            time.sleep(60)
    except requests.RequestException as e:
        log.warning(f"AbuseIPDB query failed for {ip}: {e}")
    return None


def query_greynoise(ip: str) -> Optional[dict]:
    """Query GreyNoise Community API — returns condensed result or None."""
    if not GREYNOISE_KEY:
        # Try unauthenticated community endpoint
        url  = f"https://api.greynoise.io/v3/community/{ip}"
        hdrs = {"Accept": "application/json"}
    else:
        url  = f"https://api.greynoise.io/v2/noise/quick/{ip}"
        hdrs = {"key": GREYNOISE_KEY, "Accept": "application/json"}
    try:
        r = requests.get(url, headers=hdrs, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            return {
                "noise":       d.get("noise", False),
                "riot":        d.get("riot", False),
                "classification": d.get("classification", "unknown"),
                "name":        d.get("name", ""),
                "link":        d.get("link", ""),
                "last_seen":   d.get("last_seen", ""),
                "message":     d.get("message", ""),
            }
        elif r.status_code == 404:
            return {"noise": False, "riot": False,
                    "classification": "not_seen", "message": "Not in GreyNoise"}
    except requests.RequestException as e:
        log.warning(f"GreyNoise query failed for {ip}: {e}")
    return None


# ─────────────────────────── AUTO-BLOCK ──────────────────────

_blocked_ips: set = set()


def block_ip(ip: str, reason: str):
    """Add an iptables DROP rule for the given IP."""
    if ip in _blocked_ips:
        return
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True,
        )
        _blocked_ips.add(ip)
        log.warning(f"{RED}BLOCKED{RESET} {ip} — {reason}")
        write_jsonl(BLOCKED_LOG, {
            "timestamp": str(datetime.now(timezone.utc)),
            "ip":        ip,
            "reason":    reason,
        })
    except FileNotFoundError:
        log.error("iptables not found — auto-block requires Linux with root.")
    except subprocess.CalledProcessError as e:
        log.error(f"iptables failed for {ip}: {e.stderr.decode()}")


# ─────────────────────────── ENRICHMENT ──────────────────────

def enrich_ip(ip: str, username: str, password: str) -> dict:
    """Fetch threat intel for one IP and return enriched record."""
    now      = datetime.now(timezone.utc)
    abuseipdb = query_abuseipdb(ip)
    greynoise = query_greynoise(ip)

    record = {
        "timestamp":   str(now),
        "ip":          ip,
        "username":    username,
        "password":    password,
        "abuseipdb":   abuseipdb,
        "greynoise":   greynoise,
    }

    # ── Colour-coded console alert ────────────────────────────
    score   = abuseipdb["abuse_score"] if abuseipdb else "N/A"
    country = abuseipdb["country"]     if abuseipdb else "??"
    isp     = abuseipdb["isp"]         if abuseipdb else ""
    gn_cls  = greynoise["classification"] if greynoise else "unknown"
    gn_name = greynoise["name"]           if greynoise else ""

    if isinstance(score, int) and score >= 80:
        colour = RED
        risk   = "HIGH RISK"
    elif isinstance(score, int) and score >= 40:
        colour = YELLOW
        risk   = "MEDIUM RISK"
    else:
        colour = GREEN
        risk   = "LOW / UNKNOWN"

    print(
        f"\n{BOLD}{'─'*60}{RESET}\n"
        f"  {BOLD}IP         {RESET}: {colour}{ip}{RESET}   {BOLD}[{risk}]{RESET}\n"
        f"  {BOLD}Creds      {RESET}: {username}:{password}\n"
        f"  {BOLD}Country    {RESET}: {country}   ISP: {isp}\n"
        f"  {BOLD}AbuseScore {RESET}: {colour}{score}/100{RESET}  "
        f"Reports: {abuseipdb['total_reports'] if abuseipdb else 'N/A'}\n"
        f"  {BOLD}GreyNoise  {RESET}: {gn_cls}"
        f"{' — ' + gn_name if gn_name else ''}\n"
        f"{'─'*60}"
    )

    # ── Auto-block decision ───────────────────────────────────
    if AUTO_BLOCK and isinstance(score, int) and score >= BLOCK_THRESHOLD:
        block_ip(ip, f"AbuseIPDB score={score}")

    return record


# ─────────────────────────── TAIL LOOP ───────────────────────

def tail_credentials():
    """
    Continuously tail credentials.jsonl.
    For each new unique IP, run enrichment.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    seen = load_seen_cache()

    log.info(f"Watching: {CRED_LOG}")
    log.info(f"AbuseIPDB: {'✓ configured' if ABUSEIPDB_KEY else '✗ no key (set ABUSEIPDB_KEY)'}")
    log.info(f"GreyNoise: {'✓ configured' if GREYNOISE_KEY else '~ unauthenticated community'}")
    log.info(f"Auto-block: {'ON (threshold={BLOCK_THRESHOLD})' if AUTO_BLOCK else 'OFF'}\n")

    last_size = 0

    while True:
        try:
            if not CRED_LOG.exists():
                time.sleep(POLL_INTERVAL)
                continue

            current_size = CRED_LOG.stat().st_size

            if current_size > last_size:
                with open(CRED_LOG, "r") as f:
                    f.seek(last_size)
                    new_lines = f.readlines()
                last_size = current_size

                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    ip       = entry.get("ip", "")
                    username = entry.get("username", "")
                    password = entry.get("password", "")

                    if not ip or is_private_ip(ip):
                        continue

                    if ip not in seen:
                        seen.add(ip)
                        save_seen_cache(seen)
                        try:
                            record = enrich_ip(ip, username, password)
                            write_jsonl(ENRICHED_LOG, record)
                        except Exception as e:
                            log.error(f"Enrichment error for {ip}: {e}")

        except KeyboardInterrupt:
            log.info("Shutting down threat intel sidecar.")
            sys.exit(0)
        except Exception as e:
            log.error(f"Unexpected error in tail loop: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    tail_credentials()
