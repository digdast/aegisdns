"""
AegisDNS - High-Performance Asyncio UDP & TCP DNS Server
Listens on Port 53, handles RFC 1035 wire protocol, and streams live telemetry to the UI.
"""

import struct
import asyncio
import logging
from typing import Set, Callable, Optional
import dns.message

from aegisdns.resolver import ResolverEngine
from aegisdns.database import Database

logger = logging.getLogger("aegisdns.server")

class DNSUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver: ResolverEngine, db: Database, broadcast_callback: Optional[Callable] = None):
        self.resolver = resolver
        self.db = db
        self.broadcast_callback = broadcast_callback
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.create_task(self.handle_datagram(data, addr))

    async def handle_datagram(self, data: bytes, addr: tuple):
        client_ip = addr[0]
        try:
            query = dns.message.from_wire(data)
            response, meta = await self.resolver.resolve(query, client_ip)
            resp_wire = response.to_wire()
            if self.transport and not self.transport.is_closing():
                self.transport.sendto(resp_wire, addr)

            # Asynchronously log query and broadcast to dashboard
            self.db.log_query_async(meta)
            if self.broadcast_callback:
                await self.broadcast_callback(meta)
        except Exception as e:
            logger.debug(f"UDP Error from {client_ip}: {e}")

class DNSServer:
    def __init__(self, host: str, port: int, resolver: ResolverEngine, db: Database):
        self.host = host
        self.port = port
        self.resolver = resolver
        self.db = db
        self.udp_transport: Optional[asyncio.DatagramTransport] = None
        self.tcp_server: Optional[asyncio.Server] = None
        self.active_websockets: Set[asyncio.Queue] = set()

    def register_ws_listener(self, queue: asyncio.Queue):
        self.active_websockets.add(queue)

    def unregister_ws_listener(self, queue: asyncio.Queue):
        self.active_websockets.discard(queue)

    async def broadcast_query(self, meta: dict):
        if not self.active_websockets:
            return
        dead = set()
        for q in list(self.active_websockets):
            try:
                q.put_nowait(meta)
            except Exception:
                dead.add(q)
        for d in dead:
            self.active_websockets.discard(d)

    async def start(self):
        """Start both UDP and TCP listeners on DNS port 53."""
        loop = asyncio.get_running_loop()

        # 1. UDP Listener
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: DNSUDPProtocol(self.resolver, self.db, self.broadcast_query),
                local_addr=(self.host, self.port)
            )
            self.udp_transport = transport
            logger.info(f"AegisDNS UDP Listener active on {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to bind UDP {self.host}:{self.port}: {e}")
            raise e

        # 2. TCP Listener (RFC 1035 with 2-byte length prefix)
        try:
            self.tcp_server = await asyncio.start_server(
                self.handle_tcp_client,
                host=self.host,
                port=self.port
            )
            logger.info(f"AegisDNS TCP Listener active on {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to bind TCP {self.host}:{self.port}: {e}")
            if self.udp_transport:
                self.udp_transport.close()
            raise e

    async def handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else "127.0.0.1"

        try:
            while True:
                # Read 2-byte prefix
                prefix = await reader.readexactly(2)
                if not prefix:
                    break
                length = struct.unpack("!H", prefix)[0]
                data = await reader.readexactly(length)
                
                query = dns.message.from_wire(data)
                response, meta = await self.resolver.resolve(query, client_ip)
                resp_wire = response.to_wire()

                # Send 2-byte prefix + wire bytes
                writer.write(struct.pack("!H", len(resp_wire)) + resp_wire)
                await writer.drain()

                self.db.log_query_async(meta)
                await self.broadcast_query(meta)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            logger.debug(f"TCP error with {client_ip}: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def stop(self):
        if self.udp_transport:
            self.udp_transport.close()
        if self.tcp_server:
            self.tcp_server.close()
        logger.info("AegisDNS listeners stopped.")
