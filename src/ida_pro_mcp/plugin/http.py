from __future__ import annotations

import http.server
import json
import os
import socketserver
import traceback
from typing import Any, Dict
from urllib.parse import urlparse

from .rpc import JSONRPCError, rpc, get_cached_output


class JSONRPCRequestHandler(http.server.BaseHTTPRequestHandler):
    def send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # Output download endpoint
        if path.startswith("/output/"):
            cache_id = path.split("/output/", 1)[1].rstrip("/")
            if cache_id.endswith(".json"):
                cache_id = cache_id[:-5]
            data = get_cached_output(cache_id)
            if data is None:
                self.send_json({"error": "Output not found or expired"}, status=404)
            else:
                body = data.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            return

        self.send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/mcp":
            return self.send_json({"jsonrpc": "2.0", "error": {"code": -32098, "message": "Invalid endpoint"}})

        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
            req = json.loads(raw)
        except Exception:
            return self.send_json({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}})

        resp: Dict[str, Any] = {"jsonrpc": "2.0", "id": req.get("id")}
        try:
            if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or "method" not in req:
                raise JSONRPCError(-32600, "Invalid Request")
            result = rpc.dispatch(req["method"], req.get("params", {}))
            resp["result"] = result
        except JSONRPCError as e:
            resp["error"] = {"code": e.code, "message": e.message}
            if e.data:
                resp["error"]["data"] = e.data
        except Exception:
            resp["error"] = {"code": -32603, "message": "Internal error", "data": traceback.format_exc()}

        return self.send_json(resp)

    def log_message(self, *_: Any) -> None:
        pass


class UnixJSONRPCServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = False
    daemon_threads = True
    # Default is 5 — too small for parallel MCP call batches.
    # When >5 connections arrive simultaneously, the kernel drops extras
    # with ECONNREFUSED. 128 handles typical agent bursts.
    request_queue_size = 128

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        super().__init__(socket_path, JSONRPCRequestHandler)

    def server_bind(self) -> None:
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        super().server_bind()

    def server_close(self) -> None:
        super().server_close()
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def get_request(self):
        request, _ = super().get_request()
        return request, ("local", 0)
