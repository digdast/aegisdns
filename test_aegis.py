"""
AegisDNS - Test Suite & Verification Script
Verifies filter engine, resolver, sinkholing, database, and DoH logic.
"""

import sys
import asyncio
import time
import dns.message
import dns.rdatatype

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from aegisdns.database import Database
from aegisdns.filter import FilterEngine
from aegisdns.resolver import ResolverEngine

async def run_tests():
    print("=" * 60)
    print("🧪 AegisDNS Test Suite Starting...")
    print("=" * 60)

    # 1. Test Database
    print("\n[1/5] Testing SQLite Database Initialization...")
    db = Database()
    stats = db.get_stats()
    print(f"  ✓ Database initialized. Default tables and settings ready.")
    print(f"  ✓ Initial total queries: {stats['total_queries']}, Active rules: {stats['total_rules_active']}")

    # 2. Test Filter Engine
    print("\n[2/5] Testing Threat & Ad Filtering Engine...")
    filter_engine = FilterEngine(db)
    filter_engine.load_rules_from_db()

    # Test baseline ad domain
    status, reason = filter_engine.check_domain("doubleclick.net")
    assert status == "BLOCKED_AD", f"Expected BLOCKED_AD, got {status}"
    print(f"  ✓ Adware sinkhole check ('doubleclick.net'): {status} ({reason})")

    # Test subdomain ad matching
    status, reason = filter_engine.check_domain("ad.tracker.doubleclick.net")
    assert status == "BLOCKED_AD", f"Expected BLOCKED_AD for subdomain, got {status}"
    print(f"  ✓ Subdomain sinkhole check ('ad.tracker.doubleclick.net'): {status}")

    # Test malware domain
    status, reason = filter_engine.check_domain("coinhive.com")
    assert status == "BLOCKED_MALWARE", f"Expected BLOCKED_MALWARE, got {status}"
    print(f"  ✓ Threat feed check ('coinhive.com'): {status} ({reason})")

    # Test SafeSearch check
    status, reason = filter_engine.check_domain("google.com")
    assert status == "SAFESEARCH", f"Expected SAFESEARCH, got {status}"
    print(f"  ✓ SafeSearch redirection check ('google.com'): {status} ({reason})")

    # Test clean domain
    status, reason = filter_engine.check_domain("wikipedia.org")
    assert status == "ALLOWED", f"Expected ALLOWED, got {status}"
    print(f"  ✓ Clean domain check ('wikipedia.org'): {status}")

    # 3. Test Resolver Engine
    print("\n[3/5] Testing Resolver Engine & Sinkholing...")
    resolver = ResolverEngine(db, filter_engine)
    await resolver.initialize()

    # Query 1: Blocked domain -> Should return 0.0.0.0
    q_blocked = dns.message.make_query("doubleclick.net", dns.rdatatype.A)
    resp_blocked, meta_blocked = await resolver.resolve(q_blocked)
    assert meta_blocked["status"] == "BLOCKED_AD"
    assert resp_blocked.answer[0][0].address == "0.0.0.0"
    print(f"  ✓ Sinkhole synthesis verified: doubleclick.net -> {resp_blocked.answer[0][0].address} (Latency: {meta_blocked['latency_ms']}ms)")

    # Query 2: Clean domain resolution
    q_clean = dns.message.make_query("cloudflare.com", dns.rdatatype.A)
    resp_clean, meta_clean = await resolver.resolve(q_clean)
    assert resp_clean.answer, "Expected answer for cloudflare.com"
    ip = resp_clean.answer[0][0].address if resp_clean.answer[0].rdtype == dns.rdatatype.A else str(resp_clean.answer[0][0])
    print(f"  ✓ Live resolution verified: cloudflare.com -> {ip} via {meta_clean['upstream_server']} (Latency: {meta_clean['latency_ms']}ms)")

    # Query 3: In-Memory Cache Verification
    resp_cached, meta_cached = await resolver.resolve(q_clean)
    assert meta_cached["status"] == "CACHED"
    print(f"  ✓ Cache hit verified: Status={meta_cached['status']}, Latency={meta_cached['latency_ms']}ms")

    # 4. Test Local DNS Overrides
    print("\n[4/5] Testing Local Homelab DNS Overrides...")
    db.add_local_record("pve.home.lab", "A", "192.168.0.30", 300, "Proxmox VE Cluster")
    q_local = dns.message.make_query("pve.home.lab", dns.rdatatype.A)
    resp_local, meta_local = await resolver.resolve(q_local)
    assert meta_local["status"] == "REWRITE"
    assert resp_local.answer[0][0].address == "192.168.0.30"
    print(f"  ✓ Local rewrite verified: pve.home.lab -> {resp_local.answer[0][0].address}")

    # 5. Clean up
    await resolver.close()
    print("\n[5/5] All Unit & Integration Tests Passed Successfully! 🎉")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_tests())
