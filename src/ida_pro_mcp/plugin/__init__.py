"""IDA Pro MCP Plugin Package.

This package implements the IDA-side JSON-RPC server that exposes
reverse engineering tools via Unix sockets. It is loaded by the
mcp-plugin.py shim which IDA's plugin system discovers.
"""
from __future__ import annotations

import logging
import os
import re
import signal
import sys
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Suppress SIGPIPE to prevent IDA crashes on client disconnect
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

# --- IDA imports ---
import idaapi
import ida_funcs
import ida_kernwin

# --- Plugin internals ---
from .rpc import rpc
from .sync import (
    _ensure_heartbeat_timer,
    _stop_heartbeat_timer,
    _refresh_system_meta_base,
    _clear_system_meta,
)
from .utils import _invalidate_caches_for_db, clear_strings_cache
from .http import UnixJSONRPCServer

# --- Import all API modules to register their RPC methods ---
from . import api_core
from . import api_analysis
from . import api_memory
from . import api_types
from . import api_modify
from . import api_script
from . import api_composite
from . import api_stack
from . import api_debug
from . import api_resources
from . import api_discovery

# ============================================================================
# Server Lifecycle
# ============================================================================

RUNTIME_DIR = os.environ.get(
    "IDA_PRO_MCP_RUNTIME_DIR",
    os.path.expanduser("~/.ida-pro-mcp/instances"),
)
_SERVER_SINGLETON: Optional[Dict[str, Any]] = None


def _get_socket_path() -> str:
    """Get unique socket path for this IDA instance."""
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    db_name = idaapi.get_root_filename() or "unknown"
    safe_name = re.sub(r'[^\w\-.]', '_', db_name)
    return os.path.join(RUNTIME_DIR, f"{os.getpid()}_{safe_name}.sock")


def _start_server() -> Optional[Dict[str, Any]]:
    """Start the MCP JSON-RPC server."""
    global _SERVER_SINGLETON

    db_name = idaapi.get_root_filename()
    if not db_name:
        return None

    _ensure_heartbeat_timer()
    _refresh_system_meta_base()
    _invalidate_caches_for_db(db_name)

    if _SERVER_SINGLETON is not None:
        expected_path = _get_socket_path()
        if _SERVER_SINGLETON["socket_path"] == expected_path:
            return _SERVER_SINGLETON
        _stop_server()

    socket_path = _get_socket_path()

    try:
        server = UnixJSONRPCServer(socket_path)
    except Exception as e:
        logger.error("Failed to start server: %s", e)
        return None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    _SERVER_SINGLETON = {
        "server": server,
        "thread": thread,
        "socket_path": socket_path,
    }

    logger.info("MCP server started: %s", socket_path)
    return _SERVER_SINGLETON


def _stop_server() -> None:
    """Stop the MCP server."""
    global _SERVER_SINGLETON

    if _SERVER_SINGLETON is None:
        return

    try:
        _SERVER_SINGLETON["server"].shutdown()
        _SERVER_SINGLETON["server"].server_close()
    except Exception as e:
        logger.error("Error stopping server: %s", e)

    _SERVER_SINGLETON = None
    _clear_system_meta()
    clear_strings_cache()
    logger.info("MCP server stopped")


# ============================================================================
# UI Hooks
# ============================================================================

class MCPUIHooks(idaapi.UI_Hooks):
    """UI hooks to detect database open/close events.

    database_inited is the ONLY safe place to start the server.
    Do NOT use register_timer during plugin init — timer callbacks
    fire inside init_database's internal event-loop pump and deadlock
    on a QReadWriteLock.
    """

    def database_inited(self, is_new_db, idc_script):
        _start_server()
        return 0

    def database_closed(self):
        _stop_server()
        return 0


_ui_hooks: Optional[MCPUIHooks] = None


# ============================================================================
# Plugin Class
# ============================================================================

class MCPPlugin(idaapi.plugin_t):
    """IDA Pro MCP Plugin - Exposes reverse engineering tools via JSON-RPC."""

    flags = idaapi.PLUGIN_FIX
    comment = "MCP Server for LLM-assisted reverse engineering"
    help = "Starts a JSON-RPC server for external tool access"
    wanted_name = "MCP Server"
    wanted_hotkey = "Ctrl-Shift-M"

    def init(self):
        global _ui_hooks
        _ui_hooks = MCPUIHooks()
        _ui_hooks.hook()
        # Do NOT call _start_server() or register_timer() here.
        # Plugin init runs during init_database. Any timer or
        # execute_sync call will deadlock on IDA's QReadWriteLock.
        # The database_inited hook fires once init_database completes
        # and is the only safe place to start.
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        global _SERVER_SINGLETON
        if _SERVER_SINGLETON is None:
            _start_server()
        else:
            _stop_server()

    def term(self):
        global _ui_hooks
        _stop_server()
        _stop_heartbeat_timer()
        if _ui_hooks:
            _ui_hooks.unhook()
            _ui_hooks = None


def PLUGIN_ENTRY():
    return MCPPlugin()
