from __future__ import annotations
import asyncio
import socket
import select
from typing import Optional
from models.request import HTTPRequest
from models.response import HTTPResponse
from scope.validator import ScopeValidator
from session.manager import SessionManager
from .intercept import InterceptManager


class InterceptingProxyServer:
    """
    Browser-facing HTTP/HTTPS Interception Proxy server (Section 2 & 3).
    Listens on 127.0.0.1:<port> for browser traffic.
    """
    def __init__(
        self,
        port: int = 8081,
        intercept_manager: Optional[InterceptManager] = None,
        scope_validator: Optional[ScopeValidator] = None,
        session_manager: Optional[SessionManager] = None
    ):
        self.port = port
        self.intercept_manager = intercept_manager or InterceptManager()
        self.scope_validator = scope_validator
        self.session_manager = session_manager or SessionManager()
        self.is_running = False
        self._server = None

    async def start(self):
        self.is_running = True
        self._server = await asyncio.start_server(self._handle_client, "127.0.0.1", self.port)

    async def stop(self):
        self.is_running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                return

            req_line = line.decode("utf-8", errors="ignore").strip()
            parts = req_line.split()
            if len(parts) < 2:
                writer.close()
                return

            method, target_url = parts[0], parts[1]

            # 1. Handle HTTPS CONNECT Tunnel
            if method.upper() == "CONNECT":
                await self._handle_connect(target_url, reader, writer)
                return

            # 2. Read headers
            headers = {}
            while True:
                h_line = await reader.readline()
                if not h_line or h_line == b"\r\n" or h_line == b"\n":
                    break
                h_str = h_line.decode("utf-8", errors="ignore").strip()
                if ":" in h_str:
                    k, v = h_str.split(":", 1)
                    headers[k.strip()] = v.strip()

            # Read body if present
            body_bytes = b""
            content_length = int(headers.get("Content-Length", 0))
            if content_length > 0:
                body_bytes = await reader.readexactly(min(content_length, 5 * 1024 * 1024))

            # Build HTTPRequest
            url = target_url if target_url.startswith("http") else f"http://{headers.get('Host', '127.0.0.1')}{target_url}"
            req = HTTPRequest(
                method=method,
                url=url,
                headers=headers,
                body=body_bytes.decode("utf-8", errors="ignore")
            )

            # Scope Validation
            if self.scope_validator and not self.scope_validator.validate_url(req.url):
                blocked_resp = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by Agentic-Burp Scope Policy\r\n"
                writer.write(blocked_resp)
                await writer.drain()
                writer.close()
                return

            # Intercept handling (Pass-through / Human / AI)
            action, final_req = await self.intercept_manager.handle_request(req)
            if action == "DROP":
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nRequest dropped by Agentic-Burp\r\n")
                await writer.drain()
                writer.close()
                return

            # Forward to Target
            parsed_host = headers.get("Host", "127.0.0.1")
            dest_port = 80
            if ":" in parsed_host:
                parsed_host, p_str = parsed_host.split(":", 1)
                dest_port = int(p_str)

            dest_reader, dest_writer = await asyncio.open_connection(parsed_host, dest_port)

            # Write request line & headers
            path = final_req.path_with_query
            dest_writer.write(f"{final_req.method} {path} HTTP/1.1\r\n".encode())
            for hk, hv in final_req.headers.items():
                dest_writer.write(f"{hk}: {hv}\r\n".encode())
            dest_writer.write(b"\r\n")
            if final_req.body:
                dest_writer.write(final_req.body.encode())
            await dest_writer.drain()

            # Read response from target
            resp_data = await dest_reader.read(65536)
            writer.write(resp_data)
            await writer.drain()

            dest_writer.close()
            writer.close()
        except Exception:
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_connect(self, target_host: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            host, port_str = target_host.split(":", 1)
            port = int(port_str)

            dest_reader, dest_writer = await asyncio.open_connection(host, port)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            async def pipe(r, w):
                try:
                    while True:
                        data = await r.read(16384)
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:
                    pass

            await asyncio.gather(pipe(reader, dest_writer), pipe(dest_reader, writer))
        except Exception:
            writer.close()
