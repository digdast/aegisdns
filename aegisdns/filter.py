"""
AegisDNS - High-Performance Domain Filtering & Threat Engine
Provides sub-millisecond in-memory Set/Trie domain lookups, regex evaluation,
threat categorization, SafeSearch enforcement, and automated blocklist feed ingestion.
"""

import os
import re
import time
import asyncio
import logging
import httpx
from typing import Dict, Set, Tuple, List, Optional, Any
from pathlib import Path
from aegisdns.config import BLOCKLIST_CACHE_DIR, SAFESEARCH_MAPPINGS
from aegisdns.database import Database

logger = logging.getLogger("aegisdns.filter")

# Curated baseline offline protection (active immediately even before external blocklists finish downloading)
BASELINE_AD_DOMAINS = {
    "doubleclick.net", "googleads.g.doubleclick.net", "pagead2.googlesyndication.com",
    "adservice.google.com", "ads.youtube.com", "analytics.google.com", "adroll.com",
    "criteo.com", "adnxs.com", "taboola.com", "outbrain.com", "scorecardresearch.com",
    "app-measurement.com", "analytics.tiktok.com", "ads-twitter.com", "fls-na.amazon.com",
    "telemetry.microsoft.com", "v10.events.data.microsoft.com", "ad-delivery.net",
    "popads.net", "popcash.net", "propellerads.com", "inmobi.com", "unity3d.com/ads"
}

BASELINE_MALWARE_DOMAINS = {
    "malware-traffic-analysis.net", "coinhive.com", "miner.pr0gramm.com",
    "crypto-loot.com", "webminepool.com", "jsecoin.com", "authedmine.com",
    "xmr.pool.minergate.com", "monerominer.rocks", "d1z2vus0.xyz",
    "best-prize-giveaway.top", "win-iphone-today.info", "secure-login-update-account.com"
}

class FilterEngine:
    def __init__(self, db: Database):
        self.db = db
        # In-memory fast lookup sets
        self.whitelisted: Set[str] = set()
        self.blocked_ads: Set[str] = set(BASELINE_AD_DOMAINS)
        self.blocked_malware: Set[str] = set(BASELINE_MALWARE_DOMAINS)
        self.regex_rules: List[Tuple[re.Pattern, str]] = []  # (compiled_pattern, rule_type)

        self.safesearch_enabled: bool = True
        self.blocking_mode: str = "ZERO_IP"
        self._is_updating = False

    def load_rules_from_db(self):
        """Load custom whitelist, blacklist, regex rules, and cached blocklists from SQLite."""
        # 1. Custom Rules
        custom = self.db.get_custom_rules()
        new_white = set()
        new_ads = set(BASELINE_AD_DOMAINS)
        new_malware = set(BASELINE_MALWARE_DOMAINS)
        new_regex = []

        for r in custom:
            domain = r["domain"].strip().lower()
            rule_type = r["rule_type"]
            if rule_type == "ALLOW":
                new_white.add(domain)
            elif rule_type == "BLOCK_MALWARE":
                new_malware.add(domain)
            elif rule_type == "BLOCK_AD":
                new_ads.add(domain)
            elif rule_type == "REGEX":
                try:
                    compiled = re.compile(domain, re.IGNORECASE)
                    new_regex.append((compiled, "BLOCK_AD"))
                except re.error as e:
                    logger.warning(f"Invalid regex rule {domain}: {e}")

        # 2. Settings
        settings = self.db.get_all_settings()
        self.safesearch_enabled = settings.get("safesearch_enabled", "true").lower() == "true"
        self.blocking_mode = settings.get("blocking_mode", "ZERO_IP")

        # 3. Load cached blocklist files from disk
        blocklists = self.db.get_blocklists()
        for b in blocklists:
            if not b["enabled"]:
                continue
            cache_file = BLOCKLIST_CACHE_DIR / f"{b['id']}.txt"
            if cache_file.exists():
                try:
                    with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            d = line.strip().lower()
                            if d:
                                if b["category"] == "MALWARE_PHISHING":
                                    new_malware.add(d)
                                else:
                                    new_ads.add(d)
                except Exception as e:
                    logger.error(f"Error reading blocklist cache {cache_file}: {e}")

        self.whitelisted = new_white
        self.blocked_ads = new_ads
        self.blocked_malware = new_malware
        self.regex_rules = new_regex
        logger.info(f"Filter loaded: {len(self.blocked_ads):,} ads/trackers, {len(self.blocked_malware):,} malware, {len(self.whitelisted):,} whitelisted, {len(self.regex_rules)} regex")

    def check_domain(self, domain: str) -> Tuple[str, Optional[str]]:
        """
        Check if a domain is allowed or blocked.
        Returns: (status, block_reason)
        Status values: 'ALLOWED', 'BLOCKED_AD', 'BLOCKED_MALWARE', 'SAFESEARCH'
        """
        clean = domain.strip().lower().rstrip(".")
        if not clean:
            return "ALLOWED", None

        # 1. Custom Whitelist always has highest precedence
        if clean in self.whitelisted:
            return "ALLOWED", None

        # 2. SafeSearch Check
        if self.safesearch_enabled:
            for engine, data in SAFESEARCH_MAPPINGS.items():
                if clean in data["domains"]:
                    return "SAFESEARCH", f"SafeSearch enforced for {engine}"

        # 3. Fast Exact Match in Malware or Ads
        if clean in self.blocked_malware:
            return "BLOCKED_MALWARE", "Threat Feed: Known Malicious Domain / Phishing"
        if clean in self.blocked_ads:
            return "BLOCKED_AD", "Adware & Tracker Blocklist"

        # 4. Suffix / Subdomain Matching
        # Walk up domain hierarchy (e.g. "ad.doubleclick.net" -> "doubleclick.net")
        parts = clean.split(".")
        if len(parts) > 2:
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self.whitelisted:
                    return "ALLOWED", None
                if parent in self.blocked_malware:
                    return "BLOCKED_MALWARE", f"Subdomain of malicious domain: {parent}"
                if parent in self.blocked_ads:
                    return "BLOCKED_AD", f"Subdomain of ad/tracker domain: {parent}"

        # 5. Regex Rules
        for pattern, rule_type in self.regex_rules:
            if pattern.search(clean):
                return rule_type, f"Matched Regex: {pattern.pattern}"

        return "ALLOWED", None

    def get_safesearch_ip(self, domain: str) -> Optional[str]:
        """Return the enforced IPv4 for SafeSearch canonical redirection."""
        clean = domain.strip().lower().rstrip(".")
        for engine, data in SAFESEARCH_MAPPINGS.items():
            if clean in data["domains"]:
                return data["ipv4"]
        return None

    async def update_all_blocklists(self) -> Dict[str, Any]:
        """Download and ingest all enabled blocklists asynchronously."""
        if self._is_updating:
            return {"status": "already_updating", "message": "Blocklist update is already in progress."}

        self._is_updating = True
        updated_count = 0
        total_domains_ingested = 0

        try:
            blocklists = self.db.get_blocklists()
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                for b in blocklists:
                    if not b["enabled"]:
                        continue
                    try:
                        logger.info(f"Downloading blocklist '{b['name']}' from {b['url']}...")
                        resp = await client.get(b["url"])
                        if resp.status_code == 200:
                            parsed_domains = self._parse_blocklist_content(resp.text)
                            cache_file = BLOCKLIST_CACHE_DIR / f"{b['id']}.txt"
                            with open(cache_file, "w", encoding="utf-8") as f:
                                for d in parsed_domains:
                                    f.write(f"{d}\n")
                            
                            self.db.update_blocklist_count(b["id"], len(parsed_domains))
                            total_domains_ingested += len(parsed_domains)
                            updated_count += 1
                            logger.info(f"Blocklist '{b['name']}' ingested: {len(parsed_domains):,} domains.")
                    except Exception as e:
                        logger.error(f"Failed to download blocklist '{b['name']}': {e}")

            # Reload in-memory sets with new data
            self.load_rules_from_db()
            return {
                "status": "success",
                "updated_lists": updated_count,
                "total_domains": total_domains_ingested,
                "active_ads": len(self.blocked_ads),
                "active_malware": len(self.blocked_malware)
            }
        finally:
            self._is_updating = False

    def _parse_blocklist_content(self, text: str) -> Set[str]:
        """Parse hosts file format, Adblock syntax, and plain domain lists."""
        domains = set()
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue

            # Remove inline comments
            line = line.split("#")[0].strip()

            # Adblock syntax: ||example.com^
            if line.startswith("||"):
                match = re.match(r"^\|\|([a-zA-Z0-9.\-_]+)\^?", line)
                if match:
                    d = match.group(1).lower().rstrip(".")
                    if "." in d and len(d) > 3:
                        domains.add(d)
                continue

            # Standard hosts format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                d = parts[1].lower().rstrip(".")
                if d and d not in ("localhost", "local", "broadcasthost") and "." in d:
                    domains.add(d)
                continue

            # Plain domain format: example.com
            if len(parts) == 1:
                d = parts[0].lower().rstrip(".")
                if "." in d and len(d) > 3 and not d.startswith("http"):
                    domains.add(d)

        return domains
