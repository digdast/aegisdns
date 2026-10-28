<div align="center">

# 🛡️ AegisDNS

### Next-Gen Recursive Resolver, RFC 8484 DoH Sinkhole & Cyber Defense Command Center
**Direct ICANN Root Nameserver Traversal, Encrypted DNS-over-HTTPS (DoH), Real-Time Threat Intelligence Sinkholing, and SafeSearch Enforcement.**

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-Framework-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/DNS-RFC%201035%20%7C%208484%20DoH-06B6D4?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" />
</p>

</div>

---

## 📸 Production Preview

*High-Availability DNS cluster command center: multi-node query telemetry, active sinkhole block rates, and live query stream.*

![AegisDNS Sinkhole](docs/screenshots/pihole-cluster-dns.png)

---

## 🌟 Overview

**AegisDNS** solves the structural limitations of legacy ad-blockers and DNS forwarders:

1. **Pure Iterative Root Recursion**: Directly queries the 13 ICANN root nameserver clusters (`[a-m].root-servers.net`) and traverses down to authoritative TLD nameservers—preventing upstream ISP and commercial DNS tracking.
2. **Encrypted DNS-over-HTTPS (DoH)**: Full compliance with RFC 8484 (`/dns-query` binary wire format) and RFC 8427 JSON DoH for secure, encrypted resolution on mobile, browsers, and remote devices.
3. **Multi-Stage Threat Sinkhole**: High-velocity in-memory O(1) domain set lookups, suffix trie matching, regex evaluation, and automated threat feeds (StevenBlack, URLhaus malware C2, OISD, Phishing Army).
4. **Cyber Command Center**: A real-time glassmorphic dark dashboard with WebSocket telemetry streams, 24-hour traffic analytics, 1-click domain quick-actions, and an interactive domain auditor.

---

## 🏗️ Hierarchical Resolution Flow

```mermaid
flowchart TD
    subgraph Clients ["📱 Client Devices"]
        Dev["Browser / OS / Router"]
    end

    subgraph AegisEngine ["🛡️ AegisDNS Core Engine"]
        Sinkhole["Threat Sinkhole Filter\n(O(1) Set + Suffix Trie)"]
        Cache["TTL-Aware Memory Cache\n(<0.5ms Response)"]
        Resolver["Iterative Root Resolver"]
    end

    subgraph Hierarchy ["🌐 Global DNS Hierarchy"]
        Root["13 ICANN Root Nameservers\n([a-m].root-servers.net)"]
        TLD["TLD Authoritative Nameservers\n(.com, .org, .net, etc.)"]
        Auth["Domain Authoritative Nameserver\n(Cloudflare, Route53, etc.)"]
    end

    Dev -->|Port 53 UDP/TCP or /dns-query DoH| Sinkhole
    Sinkhole -->|Blocked Threat / Ad| Blackhole["0.0.0.0 Sinkhole"]
    Sinkhole -->|Clean Query| Cache
    Cache -->|Cache Hit| Dev
    Cache -->|Cache Miss| Resolver

    Resolver -->|Step 1: Root Hints| Root
    Root -->|Referral| TLD
    TLD -->|Referral| Auth
    Auth -->|Authoritative Answer| Resolver
    Resolver --> Cache
```

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

---

## 📊 Feature Comparison

| Capability | AegisDNS | Pi-hole | AdGuard Home | Technitium |
| :--- | :---: | :---: | :---: | :---: |
| **Built-in Pure Root Recursion** | ✅ Native | ❌ Needs Unbound | ❌ Needs Unbound | ✅ Native |
| **Encrypted DoH Endpoint (RFC 8484)** | ✅ Native | ❌ Plugin Needed | ✅ Native | ✅ Native |
| **Executive Glassmorphism UI** | ✅ Modern Cyber | ❌ Classic Admin | ⚠️ Minimalist | ❌ Classic ASP.NET |
| **Real-Time WebSocket Stream** | ✅ Built-in | ❌ Polling/Tail | ⚠️ Polling | ⚠️ Polling |
| **1-Click Quick Allow/Block** | ✅ Instant | ⚠️ Multi-step | ⚠️ Multi-step | ❌ Manual |
| **Domain Threat Auditor** | ✅ Built-in | ❌ CLI Only | ⚠️ Basic Query | ⚠️ Basic Test |
| **SafeSearch Interception** | ✅ Built-in | ❌ Complex Regex | ✅ Built-in | ⚠️ Plugin |
| **Homelab Local DNS Records** | ✅ Built-in | ✅ Built-in | ✅ Built-in | ✅ Built-in |

---

## 🛠️ Quickstart

### Local Workstation (Windows, Linux, macOS)
```bash
git clone https://github.com/ertechlab/aegisdns.git
cd aegisdns
pip install -r requirements.txt
python -m aegisdns.server --port 53 --http-port 8053
```
Open **http://localhost:8053** in your browser.

### Docker Compose
```yaml
version: "3.8"
services:
  aegisdns:
    image: aegisdns:latest
    container_name: aegisdns
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8053:8053/tcp"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

```bash
docker compose up -d
```

---

## 📄 License
MIT License. Created by ERTech Lab.
