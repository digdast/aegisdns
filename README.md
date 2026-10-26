<div align="center">

# 🛡️ AegisDNS
### Next-Gen Recursive Resolver, RFC 8484 DoH Sinkhole & Cyber Defense Command Center

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![DNS](https://img.shields.io/badge/DNS-RFC%201035%20%7C%20RFC%208484%20DoH-06b6d4.svg)](https://datatracker.ietf.org/doc/html/rfc8484)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

<p align="center">
  <b>A modern, high-performance alternative to Pi-hole and AdGuard Home.</b><br>
  Featuring pure iterative root recursion, encrypted DNS-over-HTTPS (DoH), real-time threat intelligence sinkholing, SafeSearch enforcement, and an executive dark glassmorphic cybersecurity command center.
</p>

[Features](#-key-features) • [Comparison Matrix](#-feature-comparison) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Configuration](#-client-setup) • [API Reference](#-rest-api)

---

</div>

## 🌟 Overview

**AegisDNS** was engineered to solve the design and architectural limitations of legacy DNS sinkholes. Rather than relying on rigid upstream forwarders or outdated web interfaces, AegisDNS combines:

1. **Pure Iterative Root Recursion**: Directly queries the 13 ICANN root nameserver clusters (`[a-m].root-servers.net`) and traverses TLDs down to authoritative nameservers—preventing upstream ISP and commercial DNS tracking.
2. **Encrypted DNS-over-HTTPS (DoH)**: Full compliance with RFC 8484 (`/dns-query` binary wire format) and RFC 8427 JSON DoH for secure, encrypted resolution on mobile, browsers, and remote devices.
3. **Multi-Stage Threat Sinkhole**: High-velocity in-memory O(1) domain set lookups, suffix trie matching, regex evaluation, and automated threat feeds (StevenBlack, URLhaus malware C2, OISD, Phishing Army).
4. **Executive Cyber Command Center**: A stunning, real-time glassmorphic dark dashboard with WebSocket telemetry streams, 24-hour traffic analytics, 1-click domain quick-actions, and an interactive domain auditor.

---

## ⚡ Key Features

- **🚀 Recursive Root Resolver Engine**: Direct hierarchical resolution starting at root hints with automatic fallback to upstream DoH (Quad9, Cloudflare) or local Unbound daemon (`127.0.0.1:5335`).
- **🔒 RFC 8484 DNS-over-HTTPS (DoH)**: Native `/dns-query` endpoint supporting both binary wire format and JSON format (`application/dns-json`).
- **🛡️ Active Threat & Ad Blocking**: Pre-loaded baseline protection + multi-feed automated ingestion stopping malware, crypto-miners, phishing, telemetry, and adware.
- **⚡ Blazing Fast In-Memory Cache**: Adaptive TTL-aware memory cache responding to repeated lookups in **< 0.5 ms**.
- **🔍 Domain Threat Intelligence Auditor**: Interactive sandbox allowing you to inspect any domain against security heuristics, verify block status, and trace resolution routes in real time.
- **🌐 Homelab Local DNS Overrides**: Custom `A`, `AAAA`, `CNAME`, and `TXT` record management for local services (`*.home.lab`, `*.local`, etc.).
- **🔐 SafeSearch Enforcement**: 1-click network-wide strict SafeSearch redirection for Google, YouTube, Bing, and DuckDuckGo.
- **📊 Real-Time WebSocket Telemetry**: Streaming live query feed with instant 1-click **Quick Whitelist** and **Quick Block** actions.
- **💾 Asynchronous SQLite WAL Storage**: Zero DNS latency impact—queries are buffered in memory and flushed via background worker tasks.

---

## 📊 Feature Comparison

| Capability | AegisDNS | Pi-hole | AdGuard Home | Technitium |
| :--- | :---: | :---: | :---: | :---: |
| **Built-in Pure Root Recursion** | ✅ Native | ❌ Needs Unbound | ❌ Needs Unbound | ✅ Native |
| **Encrypted DoH Endpoint (RFC 8484)** | ✅ Native | ❌ Plugin Needed | ✅ Native | ✅ Native |
| **Executive Glassmorphism UI** | ✅ Modern Cyber | ❌ Classic Admin | ⚠️ Minimalist | ❌ Classic ASP.NET |
| **Real-Time WebSocket Stream** | ✅ Built-in | ❌ Polling/Tail | ⚠️ Polling | ⚠️ Polling |
| **1-Click Quick Allow/Block in Stream**| ✅ Instant | ⚠️ Multi-step | ⚠️ Multi-step | ❌ Manual |
| **Interactive Domain Threat Auditor** | ✅ Built-in | ❌ CLI Only | ⚠️ Basic Query | ⚠️ Basic Test |
| **SafeSearch Interception** | ✅ Built-in | ❌ Complex Regex | ✅ Built-in | ⚠️ Plugin |
| **Homelab Local DNS Records** | ✅ Built-in | ✅ Built-in | ✅ Built-in | ✅ Built-in |
| **Memory Footprint** | **~45 MB** | ~35 MB | ~60 MB | ~120 MB |

---

## 🚀 Quick Start

### Option 1: Docker & Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/digdast/aegisdns.git
cd aegisdns

# Start AegisDNS with Docker Compose
docker-compose up -d
```

Open your browser to:
- **Cyber Command Dashboard**: [http://localhost:5380](http://localhost:5380)
- **DoH RFC 8484 Endpoint**: `http://localhost:5380/dns-query`

---

### Option 2: Windows 1-Click Launch

1. Clone or download the repository to your Windows machine.
2. Double-click **`run.bat`** (or execute in PowerShell as Administrator):
   ```powershell
   cd C:\scripts\aegisdns
   .\run.bat
   ```
3. AegisDNS will install dependencies and immediately bind to **Port 53 (UDP/TCP)** and launch the web interface on **Port 5380**.

---

### Option 3: Linux / macOS Standalone

```bash
git clone https://github.com/digdast/aegisdns.git
cd aegisdns

# Install dependencies
pip3 install -r requirements.txt

# Run with root privileges to bind Port 53
sudo ./run.sh
```

*(Tip: To run without root, grant Python permission to bind privileged ports: `sudo setcap 'cap_net_bind_service=+ep' $(which python3)`).*

---

## 🏛️ Architecture

```mermaid
graph TD
    Client[LAN Client / Browser / Mobile] -->|UDP / TCP Port 53| UDPListener[AegisDNS Listener]
    Client -->|HTTPS Port 5380 /dns-query| DoHHandler[RFC 8484 DoH Handler]
    
    UDPListener --> CoreResolver[AegisDNS Core Resolver]
    DoHHandler --> CoreResolver
    
    CoreResolver --> LocalDNS[Local DNS Table]
    LocalDNS -->|Match: *.home.lab| Answer[Resolved Answer]
    
    CoreResolver --> FilterEngine[In-Memory Threat & Ad Filter]
    FilterEngine -->|Blocked: Malware / Ad| Sinkhole[0.0.0.0 / NXDOMAIN Sinkhole]
    
    CoreResolver --> MemoryCache[In-Memory TTL Cache]
    MemoryCache -->|Cache Hit| Answer
    
    CoreResolver --> UpstreamRouter{Resolution Mode}
    UpstreamRouter -->|Mode: RECURSIVE| RootHints[ICANN Root Servers [a-m]]
    UpstreamRouter -->|Mode: DOH_QUAD9| Quad9[Quad9 Encrypted DoH]
    UpstreamRouter -->|Mode: UNBOUND| LocalUnbound[Local Unbound 127.0.0.1:5335]
    
    RootHints --> TLD[TLD Nameservers] --> Authoritative[Authoritative NS] --> Answer
    Quad9 --> Answer
    LocalUnbound --> Answer
    
    CoreResolver --> AsyncWorker[Async SQLite WAL Worker]
    AsyncWorker --> Database[(aegisdns.db)]
    AsyncWorker --> WebSocketStream[Live WebSocket Stream]
    WebSocketStream --> WebUI[Glassmorphic Dashboard :5380]
```

---

## 📱 Client Setup Guide

### 1. Router DHCP (Network-Wide Protection)
Set your router's Primary DNS server IP to your AegisDNS host IP (e.g., `192.168.0.x`). All devices on your network will automatically be protected without installing software on clients!

### 2. Windows 11 (Encrypted DNS-over-HTTPS)
1. Open **Settings** > **Network & Internet** > **Ethernet / Wi-Fi**.
2. Click **Edit** next to DNS server assignment.
3. Select **Manual** > Turn on **IPv4**.
4. Set Preferred DNS: `Your-AegisDNS-Host-IP`.
5. Set DNS over HTTPS: **On (automatic template)** or specify `https://your-domain.com:5380/dns-query`.

### 3. Apple iOS / macOS
Deploy a mobile configuration profile pointing to your AegisDNS DoH URL (`https://your-domain.com/dns-query`), or configure via native profiles.

### 4. Google Chrome / Mozilla Firefox / Brave
1. Go to **Settings** > **Privacy and Security** > **Security**.
2. Enable **Use Secure DNS**.
3. Select **Custom** and enter:
   ```text
   http://127.0.0.1:5380/dns-query
   ```

---

## 📡 REST API Reference

AegisDNS features a full REST API for programmatic telemetry, rule orchestration, and monitoring.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/stats` | Real-time overview KPIs, 24h timeline graph, and top lists |
| `GET` | `/api/queries` | Paginated query log with search and status filters (`ALL`, `BLOCKED`, `MALWARE`, `ALLOWED`) |
| `POST`| `/api/quick-action` | 1-click whitelist or blacklist directly from query records |
| `POST`| `/api/audit-domain` | Test any domain against security filters and trace recursive resolution |
| `GET` | `/api/blocklists` | List all configured threat and ad blocklist feeds |
| `POST`| `/api/blocklists/update`| Trigger background re-download and parsing of all feeds |
| `GET` | `/api/local-dns` | Retrieve custom local DNS overrides |
| `POST`| `/api/local-dns` | Add new custom `A`, `AAAA`, `CNAME`, or `TXT` record |
| `GET` | `/api/settings` | Get current resolver and defense configuration |
| `POST`| `/api/settings` | Update resolution mode, SafeSearch, or blocking modes |
| `WS`  | `/ws/live` | Real-time WebSocket stream of inbound DNS queries |

---

## 🛡️ Default Curated Threat Feeds

AegisDNS automatically ingests, deduplicates, and optimizes the following threat feeds:
- **StevenBlack Unified Hosts**: The gold standard community consolidation for adware, malware, and telemetry.
- **URLhaus Malicious Hosts (abuse.ch)**: Real-time malware distribution sites and ransomware command-and-control servers.
- **OISD Big Filter**: High-performance ad and tracker filter engineered for zero false positives.
- **Phishing Army**: Actively verified zero-hour phishing and credential harvesting hosts.

---

## 📄 License

Licensed under the **MIT License**. Free for homelab, personal, and enterprise deployment.
Contributed with ❤️ by [digdast](https://github.com/digdast).
