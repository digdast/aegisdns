"""
AegisDNS - High Performance SQLite Storage & Analytics
Provides asynchronous batch-logging, real-time analytics aggregation, and local DNS record persistence.
"""

import sqlite3
import time
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from aegisdns.config import DB_PATH, DEFAULT_BLOCKLISTS, DEFAULT_RESOLUTION_MODE

class Database:
    def __init__(self, db_path: str = str(DB_PATH)):
        self.db_path = db_path
        self._batch_queue: asyncio.Queue = asyncio.Queue()
        self._flush_task: Optional[asyncio.Task] = None
        self._is_running = False
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self):
        """Create database tables and default entries if not present."""
        with self.get_connection() as conn:
            # Queries table with indexes on timestamp, domain, client_ip, status
            conn.execute("""
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                status TEXT NOT NULL,
                block_reason TEXT,
                upstream_server TEXT,
                response_code TEXT,
                latency_ms REAL NOT NULL
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_status ON queries(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_client ON queries(client_ip);")

            # Blocklists table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS blocklists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                domain_count INTEGER NOT NULL DEFAULT 0,
                last_updated TEXT,
                description TEXT
            );
            """)

            # Custom Rules table (Whitelist, Blacklist, Regex)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS custom_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                rule_type TEXT NOT NULL, -- 'ALLOW', 'BLOCK_AD', 'BLOCK_MALWARE', 'REGEX'
                comment TEXT,
                created_at TEXT NOT NULL
            );
            """)

            # Local DNS Records table (Homelab DNS overrides)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS local_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                record_type TEXT NOT NULL, -- 'A', 'AAAA', 'CNAME', 'TXT'
                value TEXT NOT NULL,
                ttl INTEGER NOT NULL DEFAULT 300,
                comment TEXT,
                UNIQUE(domain, record_type)
            );
            """)

            # Key-value Settings table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """)

            # Seed default blocklists if empty
            cursor = conn.execute("SELECT COUNT(*) FROM blocklists")
            if cursor.fetchone()[0] == 0:
                for b in DEFAULT_BLOCKLISTS:
                    conn.execute("""
                    INSERT INTO blocklists (name, url, category, enabled, domain_count, description)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """, (b["name"], b["url"], b["category"], 1 if b["enabled"] else 0, 0, b["description"]))

            # Seed default settings if empty
            cursor = conn.execute("SELECT COUNT(*) FROM settings")
            if cursor.fetchone()[0] == 0:
                defaults = {
                    "resolution_mode": DEFAULT_RESOLUTION_MODE,
                    "safesearch_enabled": "true",
                    "blocking_mode": "ZERO_IP",
                    "cache_min_ttl": "30",
                    "cache_max_ttl": "86400",
                    "upstream_doh": "https://dns.quad9.net/dns-query",
                    "unbound_addr": "127.0.0.1:5335"
                }
                for k, v in defaults.items():
                    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))

            # Seed a default local record for convenience if empty
            cursor = conn.execute("SELECT COUNT(*) FROM local_records")
            if cursor.fetchone()[0] == 0:
                conn.execute("""
                INSERT OR IGNORE INTO local_records (domain, record_type, value, ttl, comment)
                VALUES ('aegis.local', 'A', '127.0.0.1', 300, 'AegisDNS Local Dashboard')
                """)

            conn.commit()

    async def start_worker(self):
        """Start the background async flush worker for non-blocking query logging."""
        if self._is_running:
            return
        self._is_running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop_worker(self):
        """Stop worker and flush remaining queries."""
        self._is_running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final flush
        await self._flush_batch()

    def log_query_async(self, query_data: Dict[str, Any]):
        """Queue a query for async non-blocking insertion."""
        self._batch_queue.put_nowait(query_data)

    async def _flush_loop(self):
        while self._is_running:
            try:
                await asyncio.sleep(1.0)
                await self._flush_batch()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[DB Worker Error] {e}")

    async def _flush_batch(self):
        batch = []
        while not self._batch_queue.empty() and len(batch) < 200:
            try:
                batch.append(self._batch_queue.get_nowait())
            except asyncio.QueueEmpty:
                break

        if not batch:
            return

        def _insert(records):
            with self.get_connection() as conn:
                conn.executemany("""
                INSERT INTO queries (timestamp, client_ip, domain, query_type, status, block_reason, upstream_server, response_code, latency_ms)
                VALUES (:timestamp, :client_ip, :domain, :query_type, :status, :block_reason, :upstream_server, :response_code, :latency_ms)
                """, records)
                conn.commit()

        await asyncio.to_thread(_insert, batch)

    # ------------------ Statistics & Telemetry ------------------

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate high-level overview metrics."""
        now = time.time()
        one_day_ago = now - 86400

        with self.get_connection() as conn:
            # 24h stats
            cursor = conn.execute("""
            SELECT 
                COUNT(*) as total_queries,
                SUM(CASE WHEN status LIKE 'BLOCKED%' THEN 1 ELSE 0 END) as blocked_queries,
                SUM(CASE WHEN status = 'BLOCKED_MALWARE' THEN 1 ELSE 0 END) as malware_blocked,
                SUM(CASE WHEN status = 'BLOCKED_AD' THEN 1 ELSE 0 END) as ads_blocked,
                SUM(CASE WHEN status = 'CACHED' THEN 1 ELSE 0 END) as cached_queries,
                AVG(latency_ms) as avg_latency
            FROM queries
            WHERE timestamp >= ?
            """, (one_day_ago,))
            row = cursor.fetchone()

            total = row["total_queries"] or 0
            blocked = row["blocked_queries"] or 0
            malware = row["malware_blocked"] or 0
            ads = row["ads_blocked"] or 0
            cached = row["cached_queries"] or 0
            avg_lat = round(row["avg_latency"] or 0.0, 2)
            block_ratio = round((blocked / total * 100), 2) if total > 0 else 0.0
            cache_ratio = round((cached / total * 100), 2) if total > 0 else 0.0

            # Distinct active clients in 24h
            c_cursor = conn.execute("SELECT COUNT(DISTINCT client_ip) FROM queries WHERE timestamp >= ?", (one_day_ago,))
            active_clients = c_cursor.fetchone()[0] or 1

            # Total blocked domains in system
            b_cursor = conn.execute("SELECT SUM(domain_count) FROM blocklists WHERE enabled = 1")
            total_rules_active = b_cursor.fetchone()[0] or 0

            # 24h timeline points (bucketed by hour)
            timeline = []
            t_cursor = conn.execute("""
            SELECT 
                strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour_bucket,
                COUNT(*) as total,
                SUM(CASE WHEN status LIKE 'BLOCKED%' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN status = 'ALLOWED' OR status = 'CACHED' THEN 1 ELSE 0 END) as allowed
            FROM queries
            WHERE timestamp >= ?
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
            """, (one_day_ago,))
            for r in t_cursor.fetchall():
                timeline.append({
                    "hour": r["hour_bucket"],
                    "total": r["total"],
                    "blocked": r["blocked"],
                    "allowed": r["allowed"]
                })

            # Top 5 Blocked Domains
            top_blocked = []
            for r in conn.execute("""
            SELECT domain, COUNT(*) as count 
            FROM queries 
            WHERE status LIKE 'BLOCKED%' AND timestamp >= ? 
            GROUP BY domain 
            ORDER BY count DESC 
            LIMIT 5
            """, (one_day_ago,)).fetchall():
                top_blocked.append({"domain": r["domain"], "count": r["count"]})

            # Top 5 Allowed Domains
            top_allowed = []
            for r in conn.execute("""
            SELECT domain, COUNT(*) as count 
            FROM queries 
            WHERE (status = 'ALLOWED' OR status = 'CACHED') AND timestamp >= ? 
            GROUP BY domain 
            ORDER BY count DESC 
            LIMIT 5
            """, (one_day_ago,)).fetchall():
                top_allowed.append({"domain": r["domain"], "count": r["count"]})

            # Top Clients
            top_clients = []
            for r in conn.execute("""
            SELECT client_ip, COUNT(*) as count 
            FROM queries 
            WHERE timestamp >= ? 
            GROUP BY client_ip 
            ORDER BY count DESC 
            LIMIT 5
            """, (one_day_ago,)).fetchall():
                top_clients.append({"client_ip": r["client_ip"], "count": r["count"]})

        return {
            "total_queries": total,
            "blocked_queries": blocked,
            "malware_blocked": malware,
            "ads_blocked": ads,
            "cached_queries": cached,
            "block_ratio": block_ratio,
            "cache_ratio": cache_ratio,
            "avg_latency_ms": avg_lat,
            "active_clients": active_clients,
            "total_rules_active": total_rules_active,
            "timeline": timeline,
            "top_blocked": top_blocked,
            "top_allowed": top_allowed,
            "top_clients": top_clients
        }

    def get_queries(self, limit: int = 100, offset: int = 0, status_filter: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent query log entries with optional filters."""
        query = "SELECT * FROM queries WHERE 1=1"
        params: List[Any] = []

        if status_filter and status_filter != "ALL":
            if status_filter == "BLOCKED":
                query += " AND status LIKE 'BLOCKED%'"
            elif status_filter == "ALLOWED":
                query += " AND (status = 'ALLOWED' OR status = 'CACHED')"
            elif status_filter == "MALWARE":
                query += " AND status = 'BLOCKED_MALWARE'"
            else:
                query += " AND status = ?"
                params.append(status_filter)

        if search:
            query += " AND (domain LIKE ? OR client_ip LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # ------------------ Blocklists CRUD ------------------

    def get_blocklists(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM blocklists ORDER BY id ASC").fetchall()
            return [dict(r) for r in rows]

    def add_blocklist(self, name: str, url: str, category: str = "ADS_TRACKERS", description: str = "") -> int:
        with self.get_connection() as conn:
            cursor = conn.execute("""
            INSERT INTO blocklists (name, url, category, enabled, domain_count, description)
            VALUES (?, ?, ?, 1, 0, ?)
            """, (name, url, category, description))
            conn.commit()
            return cursor.lastrowid

    def toggle_blocklist(self, blocklist_id: int, enabled: bool):
        with self.get_connection() as conn:
            conn.execute("UPDATE blocklists SET enabled = ? WHERE id = ?", (1 if enabled else 0, blocklist_id))
            conn.commit()

    def update_blocklist_count(self, blocklist_id: int, count: int):
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with self.get_connection() as conn:
            conn.execute("UPDATE blocklists SET domain_count = ?, last_updated = ? WHERE id = ?", (count, now_str, blocklist_id))
            conn.commit()

    def delete_blocklist(self, blocklist_id: int):
        with self.get_connection() as conn:
            conn.execute("DELETE FROM blocklists WHERE id = ?", (blocklist_id,))
            conn.commit()

    # ------------------ Custom Rules CRUD ------------------

    def get_custom_rules(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM custom_rules ORDER BY id DESC").fetchall()
            return [dict(r) for r in rows]

    def add_custom_rule(self, domain: str, rule_type: str, comment: str = "") -> int:
        clean_domain = domain.strip().lower()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with self.get_connection() as conn:
            cursor = conn.execute("""
            INSERT OR REPLACE INTO custom_rules (domain, rule_type, comment, created_at)
            VALUES (?, ?, ?, ?)
            """, (clean_domain, rule_type, comment, now_str))
            conn.commit()
            return cursor.lastrowid

    def delete_custom_rule(self, rule_id: int):
        with self.get_connection() as conn:
            conn.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
            conn.commit()

    # ------------------ Local DNS Records CRUD ------------------

    def get_local_records(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM local_records ORDER BY domain ASC").fetchall()
            return [dict(r) for r in rows]

    def add_local_record(self, domain: str, record_type: str, value: str, ttl: int = 300, comment: str = ""):
        clean_domain = domain.strip().lower().rstrip(".")
        clean_type = record_type.strip().upper()
        with self.get_connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO local_records (domain, record_type, value, ttl, comment)
            VALUES (?, ?, ?, ?, ?)
            """, (clean_domain, clean_type, value.strip(), ttl, comment))
            conn.commit()

    def delete_local_record(self, record_id: int):
        with self.get_connection() as conn:
            conn.execute("DELETE FROM local_records WHERE id = ?", (record_id,))
            conn.commit()

    # ------------------ Settings CRUD ------------------

    def get_all_settings(self) -> Dict[str, str]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
            return {r["key"]: r["value"] for r in rows}

    def set_setting(self, key: str, value: str):
        with self.get_connection() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
            conn.commit()
