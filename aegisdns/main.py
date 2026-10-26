"""
AegisDNS - Main Application Server
Integrates RFC 8484 DNS-over-HTTPS (DoH), DNS on Port 53, REST APIs,
WebSocket live telemetry stream, and Cyber Command Center Web Interface.
"""

import sys
import os
import base64
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import dns.message
import dns.rdatatype
import dns.rcode

# Ensure stdout uses utf-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from aegisdns.config import (
    DNS_HOST, DNS_PORT, HTTP_HOST, HTTP_PORT,
    BASE_DIR, DEFAULT_RESOLUTION_MODE
)
from aegisdns.database import Database
from aegisdns.filter import FilterEngine
from aegisdns.resolver import ResolverEngine
from aegisdns.server import DNSServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("aegisdns.main")

# State Singletons
db = Database()
filter_engine = FilterEngine(db)
resolver_engine = ResolverEngine(db, filter_engine)
dns_server = DNSServer(DNS_HOST, DNS_PORT, resolver_engine, db)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting AegisDNS System...")
    await db.start_worker()
    filter_engine.load_rules_from_db()
    await resolver_engine.initialize()

    # Launch Port 53 UDP/TCP DNS Server
    try:
        await dns_server.start()
    except Exception as e:
        logger.error(f"Could not bind to port 53: {e}. Note: You may need root/admin privileges if running standalone.")

    # Background initial blocklist download if not yet populated
    async def initial_feed_sync():
        stats = db.get_stats()
        if stats["total_rules_active"] == 0:
            logger.info("Initializing baseline threat and ad feeds in background...")
            await filter_engine.update_all_blocklists()
    asyncio.create_task(initial_feed_sync())

    yield

    # Shutdown
    logger.info("Shutting down AegisDNS...")
    dns_server.stop()
    await resolver_engine.close()
    await db.stop_worker()

app = FastAPI(title="AegisDNS", version="2.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# -------------------------------------------------------------
# RFC 8484 DNS-over-HTTPS (DoH) Endpoint (/dns-query)
# -------------------------------------------------------------

@app.post("/dns-query")
async def doh_post_handler(request: Request):
    """RFC 8484 DoH POST handler accepting application/dns-message wire format."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Missing DNS wire body")

    try:
        query_msg = dns.message.from_wire(body)
        response_msg, meta = await resolver_engine.resolve(query_msg, client_ip)
        db.log_query_async(meta)
        await dns_server.broadcast_query(meta)
        
        return Response(
            content=response_msg.to_wire(),
            media_type="application/dns-message",
            headers={"Cache-Control": "max-age=60"}
        )
    except Exception as e:
        logger.error(f"DoH POST Error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/dns-query")
async def doh_get_handler(
    request: Request,
    dns_wire_param: Optional[str] = Query(None, alias="dns"),
    name: Optional[str] = Query(None),
    type_str: Optional[str] = Query("A", alias="type")
):
    """
    RFC 8484 DoH GET with base64url encoded wire format, OR
    RFC 8427 / Cloudflare / Google style JSON DoH (application/dns-json).
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Case A: RFC 8484 base64url wire format ?dns=...
    if dns_wire_param:
        try:
            # Fix base64url padding
            padded = dns_wire_param + "=" * ((4 - len(dns_wire_param) % 4) % 4)
            wire_data = base64.urlsafe_b64decode(padded)
            query_msg = dns.message.from_wire(wire_data)
            response_msg, meta = await resolver_engine.resolve(query_msg, client_ip)
            db.log_query_async(meta)
            await dns_server.broadcast_query(meta)

            return Response(
                content=response_msg.to_wire(),
                media_type="application/dns-message",
                headers={"Cache-Control": "max-age=60"}
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid DoH wire payload: {e}")

    # Case B: JSON DoH format (e.g. ?name=example.com&type=A)
    if name:
        try:
            rdtype = dns.rdatatype.from_text(type_str.upper())
            query_msg = dns.message.make_query(name, rdtype)
            response_msg, meta = await resolver_engine.resolve(query_msg, client_ip)
            db.log_query_async(meta)
            await dns_server.broadcast_query(meta)

            # Build standard JSON DoH response
            answers = []
            for rrset in response_msg.answer:
                for item in rrset:
                    answers.append({
                        "name": rrset.name.to_text(),
                        "type": rrset.rdtype,
                        "TTL": rrset.ttl,
                        "data": item.to_text()
                    })

            return {
                "Status": response_msg.rcode(),
                "TC": bool(response_msg.flags & dns.flags.TC),
                "RD": bool(response_msg.flags & dns.flags.RD),
                "RA": bool(response_msg.flags & dns.flags.RA),
                "AD": bool(response_msg.flags & dns.flags.AD),
                "CD": bool(response_msg.flags & dns.flags.CD),
                "Question": [{"name": name, "type": rdtype}],
                "Answer": answers,
                "AegisMeta": meta
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"JSON DoH query failed: {e}")

    return {"status": "ok", "service": "AegisDNS RFC 8484 DoH Endpoint", "docs": "/docs"}

# -------------------------------------------------------------
# REST APIs for Web UI & Remote Clients
# -------------------------------------------------------------

@app.get("/api/stats")
async def get_stats():
    """Real-time executive statistics."""
    stats = db.get_stats()
    stats["server_port"] = DNS_PORT
    stats["doh_port"] = HTTP_PORT
    stats["active_mode"] = db.get_all_settings().get("resolution_mode", "RECURSIVE")
    return stats

@app.get("/api/queries")
async def get_queries(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None)
):
    """Retrieve filtered query log."""
    return db.get_queries(limit=limit, offset=offset, status_filter=status, search=search)

class QuickActionPayload(BaseModel):
    domain: str
    action: str # "ALLOW", "BLOCK_AD", "BLOCK_MALWARE"
    comment: Optional[str] = "Quick Action via Dashboard"

@app.post("/api/quick-action")
async def quick_action(payload: QuickActionPayload):
    """1-Click Whitelist or Blacklist directly from query log."""
    db.add_custom_rule(payload.domain, payload.action, payload.comment)
    filter_engine.load_rules_from_db()
    return {"status": "success", "domain": payload.domain, "action": payload.action}

@app.get("/api/blocklists")
async def list_blocklists():
    return db.get_blocklists()

class BlocklistCreatePayload(BaseModel):
    name: str
    url: str
    category: str = "ADS_TRACKERS"
    description: Optional[str] = ""

@app.post("/api/blocklists")
async def create_blocklist(payload: BlocklistCreatePayload):
    new_id = db.add_blocklist(payload.name, payload.url, payload.category, payload.description or "")
    return {"status": "success", "id": new_id}

@app.post("/api/blocklists/toggle/{blocklist_id}")
async def toggle_blocklist(blocklist_id: int, request: Request):
    data = await request.json()
    enabled = data.get("enabled", True)
    db.toggle_blocklist(blocklist_id, enabled)
    filter_engine.load_rules_from_db()
    return {"status": "success"}

@app.delete("/api/blocklists/{blocklist_id}")
async def delete_blocklist(blocklist_id: int):
    db.delete_blocklist(blocklist_id)
    filter_engine.load_rules_from_db()
    return {"status": "success"}

@app.post("/api/blocklists/update")
async def trigger_blocklist_update():
    """Trigger asynchronous download & parsing of all blocklist feeds."""
    result = await filter_engine.update_all_blocklists()
    return result

@app.get("/api/rules")
async def list_custom_rules():
    return db.get_custom_rules()

class RuleCreatePayload(BaseModel):
    domain: str
    rule_type: str # 'ALLOW', 'BLOCK_AD', 'BLOCK_MALWARE', 'REGEX'
    comment: Optional[str] = ""

@app.post("/api/rules")
async def create_custom_rule(payload: RuleCreatePayload):
    new_id = db.add_custom_rule(payload.domain, payload.rule_type, payload.comment or "")
    filter_engine.load_rules_from_db()
    return {"status": "success", "id": new_id}

@app.delete("/api/rules/{rule_id}")
async def delete_custom_rule(rule_id: int):
    db.delete_custom_rule(rule_id)
    filter_engine.load_rules_from_db()
    return {"status": "success"}

@app.get("/api/local-dns")
async def list_local_dns():
    return db.get_local_records()

class LocalDNSCreatePayload(BaseModel):
    domain: str
    record_type: str # 'A', 'AAAA', 'CNAME', 'TXT'
    value: str
    ttl: int = 300
    comment: Optional[str] = ""

@app.post("/api/local-dns")
async def create_local_dns(payload: LocalDNSCreatePayload):
    db.add_local_record(payload.domain, payload.record_type, payload.value, payload.ttl, payload.comment or "")
    return {"status": "success"}

@app.delete("/api/local-dns/{record_id}")
async def delete_local_dns(record_id: int):
    db.delete_local_record(record_id)
    return {"status": "success"}

class DomainAuditPayload(BaseModel):
    domain: str

@app.post("/api/audit-domain")
async def audit_domain(payload: DomainAuditPayload):
    """
    Interactive Domain Threat & DNS Inspector tool.
    Tests filter status, resolves live via resolver, and measures latency.
    """
    clean_domain = payload.domain.strip().lower()
    filter_status, reason = filter_engine.check_domain(clean_domain)

    # Perform resolution test
    q = dns.message.make_query(clean_domain, dns.rdatatype.A)
    resp, meta = await resolver_engine.resolve(q, client_ip="127.0.0.1-audit")

    answers = []
    for rrset in resp.answer:
        for item in rrset:
            answers.append({
                "type": dns.rdatatype.to_text(rrset.rdtype),
                "ttl": rrset.ttl,
                "data": item.to_text()
            })

    return {
        "domain": clean_domain,
        "filter_status": filter_status,
        "block_reason": reason,
        "resolved_answers": answers,
        "upstream_used": meta.get("upstream_server"),
        "latency_ms": meta.get("latency_ms"),
        "rcode": meta.get("response_code")
    }

@app.get("/api/settings")
async def get_settings():
    return db.get_all_settings()

class SettingsUpdatePayload(BaseModel):
    resolution_mode: Optional[str] = None
    safesearch_enabled: Optional[str] = None
    blocking_mode: Optional[str] = None
    upstream_doh: Optional[str] = None
    unbound_addr: Optional[str] = None

@app.post("/api/settings")
async def update_settings(payload: SettingsUpdatePayload):
    if payload.resolution_mode:
        db.set_setting("resolution_mode", payload.resolution_mode)
    if payload.safesearch_enabled is not None:
        db.set_setting("safesearch_enabled", payload.safesearch_enabled)
    if payload.blocking_mode:
        db.set_setting("blocking_mode", payload.blocking_mode)
    if payload.upstream_doh:
        db.set_setting("upstream_doh", payload.upstream_doh)
    if payload.unbound_addr:
        db.set_setting("unbound_addr", payload.unbound_addr)

    filter_engine.load_rules_from_db()
    return {"status": "success"}

# -------------------------------------------------------------
# WebSocket Live Query Stream
# -------------------------------------------------------------

@app.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket):
    await websocket.accept()
    queue = asyncio.Queue(maxsize=100)
    dns_server.register_ws_listener(queue)
    try:
        while True:
            item = await queue.get()
            await websocket.send_json(item)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        dns_server.unregister_ws_listener(queue)

# -------------------------------------------------------------
# Frontend View
# -------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "app_name": "AegisDNS"})

def start():
    """CLI Entry point."""
    import uvicorn
    uvicorn.run("aegisdns.main:app", host=HTTP_HOST, port=HTTP_PORT, reload=False, log_level="info")

if __name__ == "__main__":
    start()
