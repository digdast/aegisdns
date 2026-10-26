"""
AegisDNS - Configuration & Default Constants
High-Performance Recursive DNS Sinkhole, DoH Resolver & Threat Defense Engine
"""

import os
from pathlib import Path
from typing import List, Dict

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
BLOCKLIST_CACHE_DIR = DATA_DIR / "blocklists"
BLOCKLIST_CACHE_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "aegisdns.db"

# Server Network Settings
DNS_HOST = os.getenv("AEGIS_DNS_HOST", "0.0.0.0")
DNS_PORT = int(os.getenv("AEGIS_DNS_PORT", 53))
HTTP_HOST = os.getenv("AEGIS_HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("AEGIS_HTTP_PORT", 5380))

# Resolution Modes:
# 1. 'RECURSIVE': Iterative resolution starting at ICANN Root Nameservers [a-m].root-servers.net
# 2. 'DOH_QUAD9': DNS-over-HTTPS via Quad9 (malware blocking built-in)
# 3. 'DOH_CLOUDFLARE': DNS-over-HTTPS via Cloudflare 1.1.1.1
# 4. 'UNBOUND_LOCAL': Local Unbound instance e.g. 127.0.0.1:5335
DEFAULT_RESOLUTION_MODE = os.getenv("AEGIS_RESOLUTION_MODE", "RECURSIVE")

# Root Nameservers (ICANN Root Hints for pure iterative recursive resolution)
ROOT_SERVERS: List[Dict[str, str]] = [
    {"name": "a.root-servers.net", "ipv4": "198.41.0.4", "ipv6": "2001:503:ba3e::2:30"},
    {"name": "b.root-servers.net", "ipv4": "199.9.14.201", "ipv6": "2001:500:200::b"},
    {"name": "c.root-servers.net", "ipv4": "192.33.4.12", "ipv6": "2001:500:2::c"},
    {"name": "d.root-servers.net", "ipv4": "199.7.91.13", "ipv6": "2001:500:2d::d"},
    {"name": "e.root-servers.net", "ipv4": "192.203.230.10", "ipv6": "2001:500:a8::e"},
    {"name": "f.root-servers.net", "ipv4": "192.5.5.241", "ipv6": "2001:500:2f::f"},
    {"name": "g.root-servers.net", "ipv4": "192.112.36.4", "ipv6": "2001:500:12::d0d"},
    {"name": "h.root-servers.net", "ipv4": "198.97.190.53", "ipv6": "2001:500:1::803f:235"},
    {"name": "i.root-servers.net", "ipv4": "192.36.148.17", "ipv6": "2001:7fe::53"},
    {"name": "j.root-servers.net", "ipv4": "192.58.128.30", "ipv6": "2001:503:c27::2:30"},
    {"name": "k.root-servers.net", "ipv4": "193.0.14.129", "ipv6": "2001:7fd::1"},
    {"name": "l.root-servers.net", "ipv4": "199.7.83.42", "ipv6": "2001:500:9f::42"},
    {"name": "m.root-servers.net", "ipv4": "202.12.27.33", "ipv6": "2001:dc3::35"},
]

# Upstream DoH Providers
UPSTREAM_DOH_PROVIDERS = {
    "QUAD9": "https://dns.quad9.net/dns-query",
    "CLOUDFLARE": "https://cloudflare-dns.com/dns-query",
    "GOOGLE": "https://dns.google/dns-query",
    "ADGUARD": "https://dns.adguard-dns.com/dns-query",
}

# Local Unbound Forwarding Address
LOCAL_UNBOUND_ADDR = "127.0.0.1:5335"

# SafeSearch Canonical Targets
SAFESEARCH_MAPPINGS = {
    "google": {
        "domains": [
            "google.com", "www.google.com", "google.co.uk", "google.ca", "google.de",
            "google.fr", "google.it", "google.es", "google.com.au", "google.com.mx"
        ],
        "cname": "forcesafesearch.google.com",
        "ipv4": "216.239.38.120"
    },
    "bing": {
        "domains": ["bing.com", "www.bing.com"],
        "cname": "strict.bing.com",
        "ipv4": "204.79.197.220"
    },
    "duckduckgo": {
        "domains": ["duckduckgo.com", "www.duckduckgo.com"],
        "cname": "safe.duckduckgo.com",
        "ipv4": "52.142.124.215"
    },
    "youtube": {
        "domains": [
            "youtube.com", "www.youtube.com", "m.youtube.com",
            "youtubei.googleapis.com", "youtube.googleapis.com", "www.youtube-nocookie.com"
        ],
        "cname": "restrict.youtube.com",
        "ipv4": "216.239.38.119"
    }
}

# Default Curated Threat & Ad Blocklists
DEFAULT_BLOCKLISTS = [
    {
        "name": "StevenBlack Unified Adware & Malware",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "category": "ADS_TRACKERS",
        "enabled": True,
        "description": "The gold standard community blocklist consolidating malware, ads, and telemetry."
    },
    {
        "name": "URLhaus Malicious Domains (abuse.ch)",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "category": "MALWARE_PHISHING",
        "enabled": True,
        "description": "Active malware C2, phishing, and ransomware distribution hostnames."
    },
    {
        "name": "OISD Big Filter",
        "url": "https://big.oisd.nl/domainswg",
        "category": "ADS_TRACKERS",
        "enabled": True,
        "description": "Comprehensive ad & telemetry filter engineered for zero false-positives."
    },
    {
        "name": "Phishing Army Blocklist",
        "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "category": "MALWARE_PHISHING",
        "enabled": True,
        "description": "High-velocity threat feed of live verified phishing domains."
    }
]

# In-Memory Cache Settings
CACHE_MAX_ENTRIES = 50000
CACHE_MIN_TTL = 30       # Minimum TTL in seconds to enforce
CACHE_MAX_TTL = 86400    # Maximum TTL (24 hours)

# Blocking Response Types:
# 'ZERO_IP' (0.0.0.0 / ::), 'NXDOMAIN', 'REFUSED'
DEFAULT_BLOCKING_MODE = "ZERO_IP"
