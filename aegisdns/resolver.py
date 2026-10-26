"""
AegisDNS - Recursive Resolver & DoH Engine
Supports pure iterative resolution from ICANN root hints, RFC 8484 DoH upstream forwarding,
Unbound local forwarding, in-memory TTL caching, and sinkhole synthesis.
"""

import time
import asyncio
import logging
import random
import httpx
from typing import Dict, Any, Tuple, Optional, List
import dns.message
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rcode
import dns.asyncquery

from aegisdns.config import (
    ROOT_SERVERS, UPSTREAM_DOH_PROVIDERS, LOCAL_UNBOUND_ADDR,
    CACHE_MAX_ENTRIES, CACHE_MIN_TTL, CACHE_MAX_TTL
)
from aegisdns.database import Database
from aegisdns.filter import FilterEngine

logger = logging.getLogger("aegisdns.resolver")

class DNSCacheEntry:
    def __init__(self, message: dns.message.Message, original_ttl: int):
        self.message = message
        self.created_at = time.time()
        self.original_ttl = max(CACHE_MIN_TTL, min(original_ttl, CACHE_MAX_TTL))

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.original_ttl

    def get_remaining_ttl(self) -> int:
        remaining = int(self.original_ttl - (time.time() - self.created_at))
        return max(1, remaining)

class ResolverEngine:
    def __init__(self, db: Database, filter_engine: FilterEngine):
        self.db = db
        self.filter_engine = filter_engine
        self.cache: Dict[Tuple[str, int, int], DNSCacheEntry] = {}
        self.http_client: Optional[httpx.AsyncClient] = None

    async def initialize(self):
        """Initialize HTTP client for DoH queries."""
        self.http_client = httpx.AsyncClient(
            timeout=5.0,
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=200)
        )

    async def close(self):
        if self.http_client:
            await self.http_client.aclose()

    async def resolve(self, query_msg: dns.message.Message, client_ip: str = "127.0.0.1") -> Tuple[dns.message.Message, Dict[str, Any]]:
        """
        Main DNS resolution entry point.
        Processes question, applies filtering, checks cache, executes resolution,
        and returns response message + audit metadata for telemetry.
        """
        start_time = time.time()
        if not query_msg.question:
            resp = dns.message.make_response(query_msg)
            resp.set_rcode(dns.rcode.FORMERR)
            return resp, {"status": "ERROR", "reason": "Empty question", "latency_ms": 0.0}

        q = query_msg.question[0]
        qname = q.name.to_text().rstrip(".")
        qtype_num = q.rdtype
        qtype_str = dns.rdatatype.to_text(qtype_num)
        qclass_num = q.rdclass

        meta = {
            "timestamp": start_time,
            "client_ip": client_ip,
            "domain": qname,
            "query_type": qtype_str,
            "status": "ALLOWED",
            "block_reason": None,
            "upstream_server": None,
            "response_code": "NOERROR",
            "latency_ms": 0.0
        }

        # 1. Check Local DNS Records (Homelab / Custom LAN rewrites)
        local_resp = self._check_local_records(query_msg, qname, qtype_str)
        if local_resp:
            meta["status"] = "REWRITE"
            meta["block_reason"] = "Local DNS Record Override"
            meta["upstream_server"] = "LOCAL_REWRITE"
            meta["latency_ms"] = round((time.time() - start_time) * 1000, 2)
            meta["response_code"] = dns.rcode.to_text(local_resp.rcode())
            return local_resp, meta

        # 2. Check Ad & Threat Filter
        filter_status, reason = self.filter_engine.check_domain(qname)
        if filter_status in ("BLOCKED_AD", "BLOCKED_MALWARE"):
            sinkhole_resp = self._synthesize_sinkhole(query_msg, qname, qtype_num)
            meta["status"] = filter_status
            meta["block_reason"] = reason
            meta["upstream_server"] = "AEGIS_SINKHOLE"
            meta["latency_ms"] = round((time.time() - start_time) * 1000, 2)
            meta["response_code"] = dns.rcode.to_text(sinkhole_resp.rcode())
            return sinkhole_resp, meta

        if filter_status == "SAFESEARCH":
            safesearch_ip = self.filter_engine.get_safesearch_ip(qname)
            if safesearch_ip and qtype_num == dns.rdatatype.A:
                resp = dns.message.make_response(query_msg)
                resp.answer.append(dns.rrset.from_text(q.name, 300, dns.rdataclass.IN, dns.rdatatype.A, safesearch_ip))
                meta["status"] = "SAFESEARCH"
                meta["block_reason"] = reason
                meta["upstream_server"] = "SAFESEARCH_ENFORCED"
                meta["latency_ms"] = round((time.time() - start_time) * 1000, 2)
                return resp, meta

        # 3. Check In-Memory Cache
        cache_key = (qname.lower(), qtype_num, qclass_num)
        cached = self.cache.get(cache_key)
        if cached and not cached.is_expired():
            cached_resp = dns.message.from_wire(cached.message.to_wire())
            cached_resp.id = query_msg.id
            rem_ttl = cached.get_remaining_ttl()
            for rrset in cached_resp.answer:
                rrset.ttl = rem_ttl
            for rrset in cached_resp.authority:
                rrset.ttl = rem_ttl
            for rrset in cached_resp.additional:
                rrset.ttl = rem_ttl

            meta["status"] = "CACHED"
            meta["upstream_server"] = "IN_MEMORY_CACHE"
            meta["latency_ms"] = round((time.time() - start_time) * 1000, 2)
            meta["response_code"] = dns.rcode.to_text(cached_resp.rcode())
            return cached_resp, meta

        # 4. Perform Upstream Resolution
        settings = self.db.get_all_settings()
        res_mode = settings.get("resolution_mode", "RECURSIVE").upper()

        response = None
        upstream_used = "UNKNOWN"

        try:
            if res_mode == "RECURSIVE":
                upstream_used = "RECURSIVE_ROOT"
                response = await self._resolve_iterative(q.name, qtype_num, query_msg)
            elif res_mode.startswith("DOH"):
                upstream_url = settings.get("upstream_doh", UPSTREAM_DOH_PROVIDERS["QUAD9"])
                upstream_used = f"DoH ({upstream_url.split('/')[2]})"
                response = await self._resolve_doh(query_msg, upstream_url)
            elif res_mode == "UNBOUND_LOCAL":
                unbound_addr = settings.get("unbound_addr", LOCAL_UNBOUND_ADDR)
                upstream_used = f"UNBOUND ({unbound_addr})"
                host, port = unbound_addr.split(":")
                response = await dns.asyncquery.udp(query_msg, host, port=int(port), timeout=3.0)
            else:
                # Default to Quad9 DoH
                upstream_used = "DOH_FALLBACK"
                response = await self._resolve_doh(query_msg, UPSTREAM_DOH_PROVIDERS["QUAD9"])
        except Exception as e:
            logger.warning(f"Resolution failed via {upstream_used}: {e}. Attempting Quad9 DoH fallback...")
            try:
                upstream_used = "DOH_QUAD9_FALLBACK"
                response = await self._resolve_doh(query_msg, UPSTREAM_DOH_PROVIDERS["QUAD9"])
            except Exception as e2:
                logger.error(f"Fallback resolution failed: {e2}")
                resp = dns.message.make_response(query_msg)
                resp.set_rcode(dns.rcode.SERVFAIL)
                meta["status"] = "ERROR"
                meta["block_reason"] = f"SERVFAIL: {e2}"
                meta["upstream_server"] = upstream_used
                meta["response_code"] = "SERVFAIL"
                meta["latency_ms"] = round((time.time() - start_time) * 1000, 2)
                return resp, meta

        if response:
            response.id = query_msg.id
            meta["upstream_server"] = upstream_used
            meta["response_code"] = dns.rcode.to_text(response.rcode())
            meta["latency_ms"] = round((time.time() - start_time) * 1000, 2)

            # Cache successful answers
            if response.rcode() == dns.rcode.NOERROR and response.answer:
                min_ttl = 300
                for rr in response.answer:
                    if rr.ttl > 0:
                        min_ttl = min(min_ttl, rr.ttl)
                self._cache_store(cache_key, response, min_ttl)

            return response, meta

        # Ultimate fallback
        resp = dns.message.make_response(query_msg)
        resp.set_rcode(dns.rcode.SERVFAIL)
        meta["response_code"] = "SERVFAIL"
        meta["latency_ms"] = round((time.time() - start_time) * 1000, 2)
        return resp, meta

    # ------------------ Local DNS Records ------------------

    def _check_local_records(self, query_msg: dns.message.Message, qname: str, qtype: str) -> Optional[dns.message.Message]:
        records = self.db.get_local_records()
        for r in records:
            if r["domain"].lower() == qname.lower() and (r["record_type"] == qtype or r["record_type"] == "CNAME"):
                resp = dns.message.make_response(query_msg)
                rdtype = dns.rdatatype.from_text(r["record_type"])
                val = r["value"]
                if r["record_type"] == "CNAME" and not val.endswith("."):
                    val += "."
                rrset = dns.rrset.from_text(query_msg.question[0].name, r["ttl"], dns.rdataclass.IN, rdtype, val)
                resp.answer.append(rrset)
                return resp
        return None

    # ------------------ Sinkhole Synthesis ------------------

    def _synthesize_sinkhole(self, query_msg: dns.message.Message, qname: str, qtype: int) -> dns.message.Message:
        resp = dns.message.make_response(query_msg)
        blocking_mode = self.filter_engine.blocking_mode

        if blocking_mode == "NXDOMAIN":
            resp.set_rcode(dns.rcode.NXDOMAIN)
            return resp

        # Default: 0.0.0.0 or ::
        if qtype == dns.rdatatype.A:
            rrset = dns.rrset.from_text(query_msg.question[0].name, 60, dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0")
            resp.answer.append(rrset)
        elif qtype == dns.rdatatype.AAAA:
            rrset = dns.rrset.from_text(query_msg.question[0].name, 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "::")
            resp.answer.append(rrset)
        else:
            resp.set_rcode(dns.rcode.NOERROR)
        return resp

    # ------------------ Cache Management ------------------

    def _cache_store(self, key: Tuple[str, int, int], response: dns.message.Message, ttl: int):
        if len(self.cache) >= CACHE_MAX_ENTRIES:
            # Evict a random 10% or expired entries
            expired = [k for k, v in self.cache.items() if v.is_expired()]
            for k in expired:
                del self.cache[k]
            if len(self.cache) >= CACHE_MAX_ENTRIES:
                keys = list(self.cache.keys())[:500]
                for k in keys:
                    del self.cache[k]

        self.cache[key] = DNSCacheEntry(response, ttl)

    # ------------------ Pure Recursive Iterative Resolver ------------------

    async def _resolve_iterative(self, target_name: dns.name.Name, rdtype: int, original_query: dns.message.Message) -> dns.message.Message:
        """
        Pure recursive iterative resolution from ICANN root hints -> TLD -> Authoritative.
        """
        # Choose a random root server IPv4
        root = random.choice(ROOT_SERVERS)
        current_servers = [root["ipv4"]]
        depth = 0
        max_depth = 12

        while depth < max_depth:
            depth += 1
            if not current_servers:
                break

            server_ip = current_servers[0]
            sub_query = dns.message.make_query(target_name, rdtype)
            
            try:
                response = await dns.asyncquery.udp(sub_query, server_ip, timeout=2.5)
            except Exception:
                try:
                    response = await dns.asyncquery.tcp(sub_query, server_ip, timeout=3.0)
                except Exception:
                    # Try next server in referral list
                    current_servers.pop(0)
                    continue

            # Case 1: We got an answer!
            if response.answer:
                # Check for CNAME
                cname_target = None
                for rr in response.answer:
                    if rr.rdtype == dns.rdatatype.CNAME and rdtype != dns.rdatatype.CNAME:
                        cname_target = rr[0].target
                        break
                if cname_target:
                    # Recursively resolve target CNAME
                    return await self._resolve_iterative(cname_target, rdtype, original_query)
                return response

            # Case 2: NXDOMAIN
            if response.rcode() == dns.rcode.NXDOMAIN:
                return response

            # Case 3: Referral / Delegation to child nameservers
            if response.authority:
                ns_names = []
                for rr in response.authority:
                    if rr.rdtype == dns.rdatatype.NS:
                        for item in rr:
                            ns_names.append(item.target)

                # Look for Glue records in Additional section
                next_server_ips = []
                for rr in response.additional:
                    if rr.rdtype == dns.rdatatype.A:
                        for item in rr:
                            next_server_ips.append(item.address)

                if next_server_ips:
                    current_servers = next_server_ips
                    continue

                # No glue records: resolve NS names to IPs
                if ns_names:
                    ns_ip = await self._resolve_ns_ip(ns_names[0])
                    if ns_ip:
                        current_servers = [ns_ip]
                        continue

            break

        # If recursion did not yield an answer, fallback to DoH Quad9
        return await self._resolve_doh(original_query, UPSTREAM_DOH_PROVIDERS["QUAD9"])

    async def _resolve_ns_ip(self, ns_name: dns.name.Name) -> Optional[str]:
        """Resolve nameserver hostname to IPv4 address."""
        try:
            q = dns.message.make_query(ns_name, dns.rdatatype.A)
            resp = await self._resolve_doh(q, UPSTREAM_DOH_PROVIDERS["CLOUDFLARE"])
            for rr in resp.answer:
                if rr.rdtype == dns.rdatatype.A:
                    return rr[0].address
        except Exception:
            pass
        return None

    # ------------------ DNS-over-HTTPS (DoH RFC 8484) Client ------------------

    async def _resolve_doh(self, query_msg: dns.message.Message, doh_url: str) -> dns.message.Message:
        """Query upstream RFC 8484 DoH server."""
        if not self.http_client:
            await self.initialize()

        wire_data = query_msg.to_wire()
        headers = {
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "User-Agent": "AegisDNS-Secure-Resolver/1.0"
        }

        resp = await self.http_client.post(doh_url, content=wire_data, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(f"DoH upstream returned HTTP {resp.status_code}")

        return dns.message.from_wire(resp.content)
