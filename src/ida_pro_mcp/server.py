# IDA Pro MCP Server - Simplified 12-tool design for LLM reverse engineering
# This server exposes IDA Pro tools via MCP (Model Context Protocol)

import os
import sys
import json
import socket
import http.client
import errno
import argparse
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from contextlib import suppress
from glob import glob
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

# ============================================================================
# Configuration
# ============================================================================

mcp = FastMCP("ida-pro-mcp", log_level="ERROR")

DEFAULT_TIMEOUT = float(os.environ.get("IDA_MCP_REQUEST_TIMEOUT", "15"))
METHOD_TIMEOUTS = {
    "decompile": 30.0,
    "decompile_batch": 120.0,
    "disassemble": 25.0,
    "list_functions": 20.0,
    "search_strings": 30.0,
    "search": 30.0,
    "get_xrefs": 20.0,
    "script_exec": 60.0,
    "survey_binary": 60.0,
    "analyze_function_compact": 30.0,
    "analyze_component": 120.0,
    "diff_before_after": 30.0,
    "trace_data_flow": 60.0,
    "basic_blocks": 20.0,
    "find_insns": 30.0,
    "type_apply_batch": 60.0,
    "infer_types": 30.0,
    "py_eval": 60.0,
    "py_exec_file": 120.0,
    "idb_save": 30.0,
    "imports_list": 20.0,
}

INSTANCE_RUNTIME_ENV = "IDA_PRO_MCP_RUNTIME_DIR"
_runtime_root = os.environ.get(INSTANCE_RUNTIME_ENV)
if _runtime_root:
    INSTANCE_REGISTRY_DIR = Path(os.path.expanduser(_runtime_root))
else:
    INSTANCE_REGISTRY_DIR = Path.home() / ".ida-pro-mcp"

# Also check the 'instances' subdirectory for backwards compatibility
INSTANCE_REGISTRY_DIRS = [INSTANCE_REGISTRY_DIR, INSTANCE_REGISTRY_DIR / "instances"]


# ============================================================================
# Unix Socket Communication
# ============================================================================

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 10):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


_jsonrpc_request_id = 1

# Track timeouts to avoid killing long-running but healthy instances too aggressively
_timeout_marks: Dict[str, float] = {}
KILL_GRACE_SECONDS = float(os.environ.get("IDA_MCP_KILL_GRACE", "120"))
HEARTBEAT_STALE_SECONDS = float(os.environ.get("IDA_MCP_HEARTBEAT_STALE", "10"))


def _send_jsonrpc_request(socket_path: str, method: str, params: Any, timeout: float) -> Any:
    """Send JSON-RPC request to IDA plugin."""
    global _jsonrpc_request_id
    conn = UnixHTTPConnection(socket_path, timeout=timeout)

    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params if params is not None else {},
        "id": _jsonrpc_request_id,
    }
    _jsonrpc_request_id += 1

    try:
        conn.request("POST", "/mcp", json.dumps(request), {"Content-Type": "application/json"})
        response = conn.getresponse()
        payload = response.read().decode()
        data = json.loads(payload)
    finally:
        conn.close()

    if "error" in data:
        error = data["error"]
        message = error.get("message", "unknown error")
        raise Exception(message)

    return data.get("result", "success")


# ============================================================================
# Small helpers (used by callers/tests)
# ============================================================================

def _split_pseudocode_lines(pseudocode: Any) -> List[str]:
    """Normalize pseudocode field into a list of lines."""
    if pseudocode is None:
        return []
    if isinstance(pseudocode, list):
        return [str(x) for x in pseudocode]
    if isinstance(pseudocode, str):
        return pseudocode.splitlines()
    return [str(pseudocode)]


def _format_globals_compact(globals_list: List[Dict[str, Any]]) -> Dict[str, List[List[str]]]:
    """Group globals by kind and compact each entry for display/logging."""
    grouped: Dict[str, List[List[str]]] = {}
    for entry in globals_list or []:
        kind = str(entry.get("kind") or "unknown")
        row: List[str] = []
        at = entry.get("at")
        target = entry.get("target")
        name = entry.get("name")
        if at is not None:
            row.append(str(at))
        if target is not None:
            row.append(str(target))
        if name:
            row.append(str(name))
        grouped.setdefault(kind, []).append(row)
    return grouped


def check_connection() -> Dict[str, Any]:
    """Lightweight sanity-check that at least one IDA instance is reachable."""
    instances = InstanceManager.list()
    if not instances:
        return {"connected": False, "total_instances": 0, "note": "No IDA instances detected. Open IDA and load a database."}

    out: List[Dict[str, Any]] = []
    any_ok = False
    for inst in instances:
        db = inst.get("database") or inst.get("db") or "unknown"
        rec: Dict[str, Any] = dict(inst)
        try:
            meta = make_jsonrpc_request(db, "system.info", {})
            if isinstance(meta, dict):
                rec.update(meta)
                any_ok = True
        except Exception as exc:
            rec["error"] = str(exc)
        out.append(rec)

    return {"connected": any_ok, "total_instances": len(instances), "instances": out}


# ============================================================================
# Instance Management
# ============================================================================

class InstanceLookupError(LookupError):
    pass


class InstanceManager:
    """Manages connections to IDA Pro instances."""
    _instances: Dict[str, Dict[str, Any]] = {}
    _loaded: bool = False

    @staticmethod
    def _probe_socket(path: Path) -> Optional[Dict[str, Any]]:
        """Try to connect to a socket and get instance info."""
        for method in ("system.info", "info", "discover"):
            try:
                meta = _send_jsonrpc_request(str(path), method, {}, DEFAULT_TIMEOUT)
                if isinstance(meta, dict):
                    rec = dict(meta)
                    rec["_socket"] = str(path)
                    rec.setdefault("status", "ready")
                    if not rec.get("database"):
                        stem = path.stem
                        if "_" in stem:
                            rec["database"] = stem.split("_", 1)[1] or stem
                        else:
                            rec["database"] = stem
                    return rec
            except Exception as e:
                # IMPORTANT:
                # Never unlink socket paths aggressively.
                #
                # There is a real race during server startup:
                # - Unix socket path exists right after bind()
                # - but before listen()/accept loop is running
                # If we probe in that window, connect() may raise ECONNREFUSED.
                # Unlinking that pathname will orphan a still-running server
                # (the process keeps listening on an unnamed socket), making it
                # undiscoverable for all future clients.
                #
                # Only remove socket files when we're confident they belong to a
                # dead process.
                if isinstance(e, OSError) and e.errno in (errno.ENOENT, errno.ECONNREFUSED):
                    pid = _pid_from_socket_path(str(path))
                    if pid and not _pid_is_alive(pid):
                        with suppress(Exception):
                            path.unlink()
                continue
        return None

    @classmethod
    def refresh(cls) -> None:
        """Scan for active IDA instances."""
        cls._instances = {}
        cls._loaded = True
        for registry_dir in INSTANCE_REGISTRY_DIRS:
            if not registry_dir.exists():
                continue
            for socket_path in registry_dir.glob("*.sock"):
                record = cls._probe_socket(socket_path)
                if record:
                    key = record.get("database", socket_path.stem)
                    cls._instances[key] = record

    @classmethod
    def list(cls) -> List[Dict[str, Any]]:
        """List all active instances."""
        cls.refresh()
        return list(cls._instances.values())

    @classmethod
    def resolve(cls, database: str) -> str:
        """Resolve database name to instance key."""
        if not cls._loaded:
            cls.refresh()

        # Exact match
        if database in cls._instances:
            return database

        # Case-insensitive match
        lower_query = database.lower()
        for name in cls._instances:
            if name.lower() == lower_query:
                return name

        # Prefix match
        for name in cls._instances:
            if name.lower().startswith(lower_query):
                return name

        # Refresh and try again
        cls.refresh()
        if database in cls._instances:
            return database
        for name in cls._instances:
            if name.lower() == lower_query or name.lower().startswith(lower_query):
                return name

        raise InstanceLookupError(
            f"No IDA instance found for '{database}'. Use list_instances to see active sessions."
        )

    @classmethod
    def get(cls, database: str) -> Dict[str, Any]:
        """Get instance info by database name."""
        key = cls.resolve(database)
        return cls._instances[key]


def _pid_from_socket_path(socket_path: str) -> Optional[int]:
    """Extract PID prefix from socket filename (format: <pid>_<name>.sock)."""

    try:
        stem = Path(socket_path).stem
        pid_part = stem.split("_", 1)[0]
        pid = int(pid_part)
        return pid if pid > 0 else None
    except Exception:
        return None


def _kill_if_ida_process(pid: int) -> bool:
    """Kill the process if it looks like an IDA binary. Returns True if killed.

    Sends SIGTERM first for graceful shutdown, waits up to 5s, then SIGKILL.
    """

    if os.name != "posix":
        return False

    try:
        comm = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="], text=True).strip().lower()
    except Exception:
        return False

    if "ida" not in comm:
        return False

    try:
        os.kill(pid, signal.SIGTERM)
        # Wait up to 5 seconds for graceful shutdown
        for _ in range(50):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True  # Process exited cleanly
            except Exception:
                break
        # Still alive after 5s — force kill
        os.kill(pid, signal.SIGKILL)
        return True
    except Exception:
        return False


def _pid_is_alive(pid: int) -> bool:
    """Return True if a PID appears to still exist (posix only)."""

    if pid <= 0 or os.name != "posix":
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # It exists, but we might not be allowed to signal it.
        return True
    except Exception:
        # Unknown: assume alive to avoid deleting a live instance socket.
        return True


def _quick_health_check(socket_path: str) -> bool:
    """Best-effort ping to see if the MCP socket responds at all."""

    try:
        meta = _send_jsonrpc_request(socket_path, "system.info", {}, timeout=2.0)
    except Exception:
        return False

    # Legacy plugins might return non-dicts here; treat that as "responding".
    if not isinstance(meta, dict):
        return True

    # If the plugin provides a main-thread heartbeat, use it to distinguish
    # "busy" from "actually stuck". The health-check itself is served from the
    # JSON-RPC thread, so it can still succeed while the main thread is busy.
    busy = bool(meta.get("busy"))

    hb_age_raw = meta.get("main_thread_heartbeat_age_s")
    try:
        hb_age = float(hb_age_raw) if hb_age_raw is not None else None
    except Exception:
        hb_age = None

    # If no heartbeat data, we can't infer main-thread liveness; assume healthy.
    if hb_age is None or hb_age != hb_age or hb_age > 1e9:  # NaN/very large
        return True

    # If IDA is busy on the main thread, the heartbeat might not update; treat
    # this as healthy (the process is alive & servicing RPC), and rely on the
    # operator to intervene if a specific action runs too long.
    if busy:
        return True

    # Not busy: heartbeat should be fresh.
    return hb_age < HEARTBEAT_STALE_SECONDS


def make_jsonrpc_request(database: str, method: str, params: Dict[str, Any]) -> Any:
    """Make a JSON-RPC request to an IDA instance."""
    try:
        instance = InstanceManager.get(database)
    except InstanceLookupError as exc:
        raise Exception(str(exc))

    socket_path = instance.get("_socket")
    if not socket_path:
        raise Exception(f"Invalid instance for '{database}' (missing socket)")

    timeout = METHOD_TIMEOUTS.get(method, DEFAULT_TIMEOUT)

    try:
        result = _send_jsonrpc_request(socket_path, method, params, timeout)
        _timeout_marks.pop(socket_path, None)
        return result
    except socket.timeout:
        now = time.monotonic()
        first_timeout = _timeout_marks.get(socket_path, now)

        if not _quick_health_check(socket_path):
            elapsed = now - first_timeout
            if elapsed >= KILL_GRACE_SECONDS:
                pid = _pid_from_socket_path(socket_path)
                killed = _kill_if_ida_process(pid) if pid else False

                # IMPORTANT: Never unlink a socket path for a live IDA process.
                # Unlinking a bound AF_UNIX path makes a still-running server
                # unreachable (the process keeps listening on an unnamed socket).
                # Only unlink when we are confident the instance is dead.
                if killed or (pid and not _pid_is_alive(pid)):
                    with suppress(Exception):
                        Path(socket_path).unlink()
                    InstanceManager.refresh()

                _timeout_marks.pop(socket_path, None)
                if killed:
                    raise Exception(
                        f"Instance '{database}' became unresponsive (IDA likely crashed/froze after the last command). It was force-terminated (pid {pid}). Please reopen the database."
                    )
                raise Exception(
                    f"Instance '{database}' is unresponsive (IDA likely crashed/froze after the last command). "
                    f"Socket cleanup was skipped to avoid breaking a live instance; restart the MCP server in IDA if needed."
                )

            # Not yet past grace period: record and warn
            _timeout_marks[socket_path] = first_timeout
            remaining = int(max(0, KILL_GRACE_SECONDS - elapsed))
            raise Exception(
                f"Request to '{method}' timed out and IDA is unresponsive; it may be busy or frozen. "
                f"Will force-terminate if still unresponsive after {remaining}s. You can retry the command after waiting a bit."
            )

        # Health check succeeded: IDA is still alive (likely busy on the main thread).
        _timeout_marks.pop(socket_path, None)
        raise Exception(
            f"Request to '{method}' timed out after {timeout}s, but IDA is still responding. "
            "The operation may still be running; consider retrying later or increasing the timeout."
        )
    except OSError as e:
        # H-02: On socket death, refresh instances and give actionable error
        # H-12: Single retry for transient ECONNREFUSED
        if e.errno == errno.ECONNREFUSED:
            # One retry after 500ms for transient failures (e.g., IDA startup race)
            try:
                time.sleep(0.5)
                result = _send_jsonrpc_request(socket_path, method, params, timeout)
                _timeout_marks.pop(socket_path, None)
                return result
            except OSError:
                pass  # Fall through to refresh + error

        InstanceManager.refresh()
        available = InstanceManager.list()
        if available:
            names = [inst.get("database", "unknown") for inst in available]
            raise Exception(
                f"IDA instance '{database}' is no longer available (socket error: {e}). "
                f"Available instances: {', '.join(names)}."
            )
        raise Exception(
            f"IDA instance '{database}' is no longer available (socket error: {e}). "
            f"No IDA instances are running. Open IDA and load a database."
        )


def _resolve_database(database: str) -> str:
    """Resolve database parameter — auto-select when single instance exists."""
    if database:
        return database
    instances = InstanceManager.list()
    if len(instances) == 0:
        raise Exception("No IDA instances running. Open IDA Pro and load a binary.")
    if len(instances) == 1:
        return instances[0].get("database", "unknown")
    names = [inst.get("database", "unknown") for inst in instances]
    raise Exception(
        f"Multiple IDA instances running ({len(instances)}): {', '.join(names)}. "
        f"Specify the database parameter to select one."
    )


# ============================================================================
# MCP Tools - The 12 core tools for reverse engineering
# ============================================================================


@mcp.tool()
def job_status(database: str = "", job_id: str = "") -> Dict[str, Any]:
    """Check status of an async job (created after a timeout).

    When to use: After a tool call times out and returns a job_id.
    NOT for: Checking if IDA is running (use list_instances instead).

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        job_id: The job ID returned by a timed-out tool call

    Returns:
        state ("pending", "running", "done", "error"), method, params
    """
    if not job_id:
        raise Exception("job_id is required. You receive a job_id when a tool call times out.")
    return make_jsonrpc_request(_resolve_database(database), "job_status", {"job_id": job_id})


@mcp.tool()
def job_result(database: str = "", job_id: str = "", pop: bool = True) -> Dict[str, Any]:
    """Get result of an async job (optionally remove it from cache).

    When to use: After job_status shows state="done" or state="error".

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        job_id: The job ID returned by a timed-out tool call
        pop: Remove the job from cache after retrieving (default True)

    Returns:
        state, result (if done), error (if error)
    """
    if not job_id:
        raise Exception("job_id is required. You receive a job_id when a tool call times out.")
    return make_jsonrpc_request(_resolve_database(database), "job_result", {"job_id": job_id, "pop": pop})


@mcp.tool()
def list_instances() -> str:
    """List all active IDA Pro instances.

    When to use: To discover which IDA databases are open and available.
    Call this FIRST if you don't know which databases are loaded.

    Do: Use the database name from results as the 'database' parameter for other tools.
    Don't: Call this repeatedly in a loop. Instance list is refreshed automatically.

    Returns:
        Summary of active instances with database names and status.
    """
    instances = InstanceManager.list()
    if not instances:
        return "No IDA instances running. Open IDA Pro and load a binary."
    results = []
    for inst in instances:
        db = inst.get("database", "unknown")
        status = inst.get("status", "unknown")
        results.append(f"{db} ({status})")
    return f"Active instances ({len(instances)}): " + ", ".join(results)


@mcp.tool()
def decompile(
    database: str = "",
    selector: str = "",
    start_line: int = 0,
    end_line: int = 0,
    max_lines: int = 0,
) -> Dict[str, Any]:
    """Get Hex-Rays pseudocode for a function.

    When to use: To understand what a function does. This is the primary analysis tool.
    NOT for: Getting raw assembly (use disassemble), finding functions (use list_functions).

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        selector: Function name or "0xADDRESS" (REQUIRED)
        start_line: Start at this line (1-indexed, 0 = from beginning)
        end_line: End at this line (inclusive, 0 = to end)
        max_lines: Maximum lines to return (0 = no limit, overrides end_line)

    Returns:
        name, addr, proto, code, vars, lines (if filtered)

    Do:
    - Use list_functions() or info() first to find valid function names/addresses.
    - Use max_lines=50 for large functions to avoid overwhelming context.
    - Follow up with get_xrefs() and get_callgraph() to understand call context.

    Don't:
    - Pass an empty selector. Find function names with list_functions() first.
    - Pass arbitrary addresses. The address must be at or within a function.

    Common mistakes:
    - Empty selector: Use list_functions() to find function names first.
    - Address not in a function: The error will suggest nearby functions.
    - Hex-Rays not available: The error will include a disassembly preview.

    Examples:
        decompile(selector="main")
        decompile(selector="0x401000")
        decompile(selector="sub_401000", max_lines=30)
        decompile(selector="main", start_line=10, end_line=30)
    """
    if not selector:
        raise Exception(
            "selector is required. Pass a function name or address like '0x401000'. "
            "Use list_functions() to find available function names, or info() to see the entry point."
        )
    result = make_jsonrpc_request(_resolve_database(database), "decompile", {
        "selector": selector,
        "start_line": start_line,
        "end_line": end_line,
        "max_lines": max_lines,
    })
    if isinstance(result, dict):
        name = result.get("name", selector)
        result["next_actions"] = [
            f"Use get_xrefs(target='{name}', direction='to') to find callers of this function",
            f"Use get_callgraph(target='{name}') to see the full call tree",
            f"Use rename(target='{name}', new_name='...') to give it a meaningful name",
            f"Use set_comment(address='{result.get('addr', '')}', comment='...') to annotate it",
        ]
    return result


@mcp.tool()
def decompile_batch(
    database: str = "",
    selectors: List[str] = [],
    max_lines_per_function: int = 50,
) -> Dict[str, Any]:
    """Decompile multiple functions in a single call. Reduces round-trips for call-chain analysis.

    When to use: When you need to read 2+ functions at once (e.g., analyzing a call chain).
    NOT for: Single functions (use decompile), finding functions (use list_functions).

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        selectors: List of function names or "0xADDRESS" strings (max 50, REQUIRED)
        max_lines_per_function: Max pseudocode lines per function (default 50)

    Returns:
        results: [{name, addr, proto, code, error?, truncated?}], count, errors

    Do:
    - Use this after get_callgraph() to decompile an entire call chain at once.
    - Check the 'error' field on each result. Partial failures are expected.

    Don't:
    - Pass more than 50 selectors. Split into multiple calls if needed.
    - Pass an empty list.

    Examples:
        decompile_batch(selectors=["main", "init_config", "parse_input"])
        decompile_batch(selectors=["0x401000", "0x401200"], max_lines_per_function=30)
    """
    if not selectors:
        raise Exception(
            "selectors list is required. Pass a list of function names or addresses. "
            "Use list_functions() to find available function names."
        )
    return make_jsonrpc_request(_resolve_database(database), "decompile_batch", {
        "selectors": selectors,
        "max_lines_per_function": max_lines_per_function,
    })


@mcp.tool()
def disassemble(
    database: str = "",
    selector: str = "",
    max_instructions: int = 200,
) -> str:
    """Get assembly instructions for a function or address range.

    When to use: When you need raw assembly (instruction encodings, exact addresses, opcodes).
    NOT for: Understanding function logic (use decompile first, fall back to this if decompile fails).

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        selector: Function name, "0xADDRESS", or "0xSTART-0xEND" (REQUIRED)
        max_instructions: Maximum instructions to return (default 200)

    Returns:
        Plaintext disassembly (newline separated). First line has absolute address, rest are relative offsets.

    Do:
    - Try decompile() first. Use disassemble only when you need exact instruction-level detail.
    - Use address ranges ("0x401000-0x401100") to inspect specific code regions.

    Don't:
    - Pass an empty selector.
    - Use this as your primary analysis tool. Pseudocode from decompile() is faster to read.

    Examples:
        disassemble(selector="main")
        disassemble(selector="0x401000")
        disassemble(selector="0x401000-0x401100")
        disassemble(selector="main", max_instructions=50)
    """
    if not selector:
        raise Exception(
            "selector is required. Pass a function name, address, or range like '0xSTART-0xEND'. "
            "Use list_functions() to find available function names."
        )
    return make_jsonrpc_request(_resolve_database(database), "disassemble", {
        "selector": selector,
        "max_instructions": max_instructions,
    })


@mcp.tool()
def list_functions(
    database: str = "",
    filter: str = "",
    offset: int = 0,
    limit: int = 100,
) -> Dict[str, Any]:
    """List all functions with basic info. Supports regex filtering and pagination.

    When to use: To discover function names before calling decompile() or get_xrefs().
    This is how you find what to analyze.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        filter: Optional regex to filter by name (case-insensitive). Empty string = all functions.
        offset: Start index for pagination (default 0)
        limit: Number of functions to return (default 100)

    Returns:
        funcs: [{addr, name, size}], total, more

    Do:
    - Use empty filter first to see what naming conventions the binary uses.
    - Use regex patterns like "main|init|start" to find entry points.
    - Use "crypt|encrypt|hash" to find crypto functions, "net|socket|send|recv" for networking.
    - Paginate with offset if there are many functions.

    Don't:
    - Pass "*" or ".*" as filter expecting all functions. Use empty string instead.

    Common mistakes:
    - Using glob syntax ("main*") instead of regex ("main.*"). Filter uses regex, not glob.

    Examples:
        list_functions()
        list_functions(filter="main")
        list_functions(filter="crypt|encrypt|decrypt|hash")
        list_functions(filter="^sub_", offset=100, limit=50)
    """
    result = make_jsonrpc_request(_resolve_database(database), "list_functions", {
        "filter": filter,
        "offset": offset,
        "limit": limit,
    })
    if isinstance(result, dict):
        result["next_actions"] = [
            "Use decompile(selector='function_name') to read a function's code",
            "Use get_xrefs(target='function_name', direction='to') to find who calls a function",
        ]
    return result


@mcp.tool()
def get_xrefs(
    database: str = "",
    target: str = "",
    direction: str = "to",
    limit: int = 100,
) -> Dict[str, Any]:
    """Get cross-references to/from an address or function.

    When to use: To find who calls a function ("to") or what a function calls ("from").
    Essential for understanding code flow and finding attack surface.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        target: Address or function name (REQUIRED)
        direction: "to" (callers/references TO this), "from" (what this references), or "both"
        limit: Maximum xrefs to return (default 100)

    Returns:
        xrefs: [{from, to, dir, func, line}], count, more

    Do:
    - Use direction="to" to find all callers of a function (most common use).
    - Use direction="from" to see what a function calls.
    - Follow up with decompile() on interesting callers/callees.

    Don't:
    - Pass an empty target.
    - Confuse direction: "to" = who references THIS target, "from" = what THIS target references.

    Examples:
        get_xrefs(target="malloc", direction="to")
        get_xrefs(target="main", direction="from")
        get_xrefs(target="0x401000", direction="both")
    """
    if not target:
        raise Exception(
            "target is required. Pass a function name or address. "
            "Use list_functions() to find function names."
        )
    return make_jsonrpc_request(_resolve_database(database), "get_xrefs", {
        "target": target,
        "direction": direction,
        "limit": limit,
    })


@mcp.tool()
def search_strings(
    database: str = "",
    pattern: str = "",
    min_length: int = 4,
    offset: int = 0,
    limit: int = 100,
    include_xrefs: bool = False,
) -> Dict[str, Any]:
    """Find strings in the binary. Useful for finding error messages, URLs, keys, config paths.

    When to use: To find interesting strings like passwords, URLs, error messages, config values.
    NOT for: Searching for byte patterns or assembly instructions (use search() instead).

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        pattern: Optional regex to filter strings (case-insensitive). Empty = all strings.
        min_length: Minimum string length (default 4)
        offset: Start index for pagination (default 0)
        limit: Maximum strings to return (default 100)
        include_xrefs: Include xref count per string (default False, slower when True)

    Returns:
        strings: [{addr, val, len, xrefs?}], total, offset, limit, more

    Do:
    - Use regex patterns like "password|secret|key|token" for security analysis.
    - Use "http|https|ftp" to find network URLs.
    - Use "error|fail|invalid" to find error handling paths.
    - Use include_xrefs=True to find which strings are actually referenced in code.

    Don't:
    - Set include_xrefs=True on first call. It's slow. Browse strings first, then check xrefs.

    Examples:
        search_strings(pattern="password|secret|key")
        search_strings(pattern="http", include_xrefs=True)
        search_strings(min_length=20, limit=50)
    """
    result = make_jsonrpc_request(_resolve_database(database), "search_strings", {
        "pattern": pattern,
        "min_length": min_length,
        "offset": offset,
        "limit": limit,
        "include_xrefs": include_xrefs,
    })
    if isinstance(result, dict):
        result["next_actions"] = [
            "Use get_xrefs(target='0xADDRESS', direction='to') to find code that uses a string",
            "Use decompile() on the referencing function to understand how the string is used",
        ]
    return result


@mcp.tool()
def read_bytes(
    database: str = "",
    address: str = "",
    size: int = 64,
) -> Dict[str, Any]:
    """Read raw bytes at an address. Returns hex dump, raw hex, and ASCII representation.

    When to use: To inspect raw data at a specific address (embedded keys, structs, tables).
    NOT for: Reading code (use disassemble), reading strings (use search_strings).

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        address: Hex address to read from (REQUIRED), e.g. "0x401000"
        size: Number of bytes to read (default 64)

    Returns:
        addr, size, hex, ascii, dump (formatted hex dump lines)

    Examples:
        read_bytes(address="0x401000")
        read_bytes(address="0x401000", size=256)
    """
    if not address:
        raise Exception(
            "address is required. Pass a hex address like '0x401000'. "
            "Use search() or search_strings() to find addresses of interest."
        )
    return make_jsonrpc_request(_resolve_database(database), "read_bytes", {
        "address": address,
        "size": size,
    })


@mcp.tool()
def search(
    database: str = "",
    query: str = "",
    search_type: str = "auto",
    start_address: str = "",
    limit: int = 100,
) -> Dict[str, Any]:
    """Search for bytes, immediates, or text patterns in the binary.

    When to use: To find specific patterns, constants, byte sequences, or names in the binary.
    NOT for: Finding string literals specifically (use search_strings, it's faster and paginated).

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        query: What to search for (REQUIRED):
            - Hex bytes: "48 89 E5" or "488BE5" (spaces optional)
            - Immediate value: "0x1000" or "4096"
            - Text: "BOOTLOADER_MODE" (searches names, strings, raw bytes)
            - Disassembly regex: "call.*malloc" (slow, searches every instruction)
        search_type: "bytes", "immediate", "text", "disasm", or "auto" (default, auto-detects)
        start_address: Address to start searching from (default: start of binary)
        limit: Maximum results to return (default 100)

    Returns:
        results: [{addr, ctx, func?, kind?}], type, count, more

    Do:
    - Use "auto" search_type (default) unless you know the query type.
    - Use "text" for finding function names, symbol names, or string content.
    - Use "bytes" for finding specific instruction patterns or data.
    - Use "immediate" for finding references to specific constants or addresses.

    Don't:
    - Use search_type="disasm" for simple string lookups. It scans every instruction and is slow.
    - Pass an empty query.

    Common mistakes:
    - Using "disasm" when "text" would work. "text" searches names+strings+bytes and is fast.
      "disasm" checks every disassembly line and can timeout on large binaries.

    Examples:
        search(query="malloc")
        search(query="48 89 E5", search_type="bytes")
        search(query="0xDEADBEEF", search_type="immediate")
        search(query="call.*malloc", search_type="disasm")
    """
    if not query:
        raise Exception(
            "query is required. Pass a search string, hex bytes, or pattern. "
            "For string search, try search_strings() which supports regex and pagination."
        )
    result = make_jsonrpc_request(_resolve_database(database), "search", {
        "query": query,
        "search_type": search_type,
        "start_address": start_address,
        "limit": limit,
    })
    if isinstance(result, dict):
        result["next_actions"] = [
            "Use decompile(selector='function_name') to analyze functions containing matches",
            "Use get_xrefs(target='0xADDRESS') to find references to a match address",
        ]
    return result


@mcp.tool()
def rename(
    database: str = "",
    target: str = "",
    new_name: str = "",
    batch: Optional[List[Dict[str, str]]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Rename a function, global, or struct field. Supports batch mode.

    When to use: After analyzing a function with decompile() and understanding its purpose.
    This is a key part of documenting reverse engineering findings.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        target: Address ("0xADDRESS"), function name, or "StructName.field" (REQUIRED for single)
        new_name: New name to assign (REQUIRED for single). Must be a valid C identifier.
        batch: List of {target, new_name} for batch rename (overrides target/new_name)
        dry_run: If True, return what would change without applying

    Returns:
        old, new, kind ("func", "global", or "field"), addr

    Do:
    - Use descriptive names that reflect the function's purpose (e.g., "parse_config", "decrypt_payload").
    - Rename struct fields with "StructName.old_field" as target.

    Don't:
    - Pass empty target or new_name.
    - Use names with spaces or special characters. Names must be valid C identifiers.

    Examples:
        rename(target="sub_401000", new_name="parse_config")
        rename(target="0x401000", new_name="decrypt_payload")
        rename(target="MyStruct.field_0", new_name="buffer_size")
    """
    if not target:
        raise Exception(
            "target is required. Pass a function name, address, or 'StructName.field'. "
            "Use list_functions() to find function names."
        )
    if not new_name:
        raise Exception("new_name is required. Provide a valid C identifier as the new name.")
    return make_jsonrpc_request(_resolve_database(database), "rename", {
        "target": target,
        "new_name": new_name,
        "batch": batch,
        "dry_run": dry_run,
    })


@mcp.tool()
def set_type(
    database: str = "",
    target: str = "",
    type_str: str = "",
) -> Dict[str, Any]:
    """Set the type of a function, variable, or global.

    When to use: After analyzing a function and understanding its signature or data types.
    Especially useful for correcting wrong function prototypes that mislead decompilation.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        target: Address or name (REQUIRED)
        type_str: C type declaration (REQUIRED), e.g. "int (*handler)(void *ctx, char *data)"

    Returns:
        ok, addr, type

    Do:
    - Set function prototypes to improve decompiled output. Re-decompile after setting type.
    - Use standard C syntax. Semicolons are added automatically if missing.

    Don't:
    - Pass empty target or type_str.

    Examples:
        set_type(target="sub_401000", type_str="int parse_config(char *filename, int flags)")
        set_type(target="0x402000", type_str="char key_buffer[256]")
    """
    if not target:
        raise Exception(
            "target is required. Pass a function name or address. "
            "Use list_functions() to find function names."
        )
    if not type_str:
        raise Exception("type_str is required. Provide a C type declaration.")
    return make_jsonrpc_request(_resolve_database(database), "set_type", {
        "target": target,
        "type_str": type_str,
    })


@mcp.tool()
def create_struct(
    database: str = "",
    name: str = "",
    definition: str = "",
) -> Dict[str, Any]:
    """Create a new struct type from C definition.

    When to use: After identifying a data structure passed between functions.
    Apply the struct to addresses with set_type() after creation.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        name: Struct name (REQUIRED)
        definition: C-style struct definition (REQUIRED)

    Returns:
        name, size, members: [{name, type, off, size}]

    Do:
    - Include the full struct definition with "struct Name { ... }".
    - After creating, use set_type() to apply it to variables and function parameters.

    Don't:
    - Pass empty name or definition.

    Examples:
        create_struct(name="ConnectionState", definition="struct ConnectionState { int socket; char buffer[1024]; int state; }")
        create_struct(name="PacketHeader", definition="struct PacketHeader { unsigned short magic; unsigned short length; unsigned int type; }")
    """
    if not name:
        raise Exception("name is required. Provide a name for the struct.")
    if not definition:
        raise Exception(
            "definition is required. Provide a C-style struct definition like: "
            "\"struct MyStruct { int field1; char buffer[64]; }\""
        )
    return make_jsonrpc_request(_resolve_database(database), "create_struct", {
        "name": name,
        "definition": definition,
    })


@mcp.tool()
def set_comment(
    database: str = "",
    address: str = "",
    comment: str = "",
    comment_type: str = "line",
    view: str = "disasm",
) -> Dict[str, Any]:
    """Add a comment at an address. Use to document analysis findings in the IDA database.

    When to use: After analyzing code, to record what you found for future reference.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        address: Hex address (REQUIRED), e.g. "0x401000"
        comment: Comment text (REQUIRED)
        comment_type: "line" (default, at specific address), "function" (function header), or "repeatable" (shown at all xrefs)
        view: "disasm" (default) or "decompiler" (set comment in Hex-Rays pseudocode view)

    Returns:
        ok, addr, type

    Do:
    - Use "function" comment_type for high-level function descriptions.
    - Use "repeatable" for comments that should appear everywhere this address is referenced.
    - Use "line" (default) for specific instruction-level notes.

    Examples:
        set_comment(address="0x401000", comment="Decrypts config file using XOR key at 0x402000")
        set_comment(address="0x401000", comment="Main packet handler - dispatches by type field", comment_type="function")
    """
    if not address:
        raise Exception(
            "address is required. Pass a hex address like '0x401000'. "
            "Get addresses from decompile(), disassemble(), or search() results."
        )
    if not comment:
        raise Exception("comment is required. Provide the comment text.")
    return make_jsonrpc_request(_resolve_database(database), "set_comment", {
        "address": address,
        "comment": comment,
        "comment_type": comment_type,
        "view": view,
    })


@mcp.tool()
def info(
    database: str = "",
) -> Dict[str, Any]:
    """Get current database info and cursor position.

    When to use: As one of your FIRST calls when starting analysis. Gives you the binary overview:
    architecture, file type, function count, entry point, and segment/string/import counts.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)

    Returns:
        db, cursor, cursor_func, arch, bits, funcs, hexrays, entry, file_type,
        segments, strings, imports, exports

    Do:
    - Call this first to understand what kind of binary you're working with.
    - Note the 'entry' field for the binary's entry point address.
    - Check 'hexrays' to know if decompilation is available.

    Examples:
        info()
    """
    result = make_jsonrpc_request(_resolve_database(database), "info", {})
    if isinstance(result, dict):
        result["next_actions"] = [
            "Use list_functions() to browse available functions",
            "Use search_strings() to find interesting strings",
            "Use get_segments() to see memory layout",
            f"Use decompile(selector='{result.get('entry', '0x0')}') to start from the entry point" if result.get("entry") else "Use list_functions(filter='main') to find the entry point",
        ]
    return result


@mcp.tool()
def get_callgraph(
    database: str = "",
    target: str = "",
    max_depth: int = 3,
    direction: str = "both",
) -> Dict[str, Any]:
    """Get call graph for a function. Shows callers and/or callees as a nested tree.

    When to use: To understand a function's position in the program, map execution flow,
    or find all functions in a call chain before batch-decompiling them.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        target: Function name or address (REQUIRED)
        max_depth: Maximum depth to traverse (default 3, keep low for large binaries)
        direction: "callers" (who calls this), "callees" (what this calls), or "both"

    Returns:
        root: {addr, name}, callers: [{addr, name, site, callers?}], callees: [{addr, name, site, callees?}]

    Do:
    - Use direction="callees" to trace what a function does.
    - Use direction="callers" to find all paths that reach a function (attack surface analysis).
    - Feed the resulting function names into decompile_batch() for efficient bulk analysis.
    - Keep max_depth at 2-3. Depth 4+ can return very large trees.

    Don't:
    - Pass an empty target.
    - Use max_depth > 4. The result grows exponentially.

    Examples:
        get_callgraph(target="main", direction="callees", max_depth=2)
        get_callgraph(target="vulnerable_function", direction="callers")
    """
    if not target:
        raise Exception(
            "target is required. Pass a function name or address. "
            "Use list_functions() to find function names."
        )
    result = make_jsonrpc_request(_resolve_database(database), "get_callgraph", {
        "target": target,
        "max_depth": max_depth,
        "direction": direction,
    })
    if isinstance(result, dict):
        result["next_actions"] = [
            "Use decompile_batch() with the function names from this call graph to analyze the chain",
        ]
    return result


@mcp.tool()
def get_segments(
    database: str = "",
) -> Dict[str, Any]:
    """Get memory segments/sections of the binary.

    When to use: To understand the binary's memory layout (code vs data, permissions, sections).
    Useful early in analysis alongside info().

    Args:
        database: Database filename of the IDA instance (optional if only one instance)

    Returns:
        segs: [{name, start, end, size, perm, class}], count

    Examples:
        get_segments()
    """
    return make_jsonrpc_request(_resolve_database(database), "get_segments", {})


@mcp.tool()
def overview(
    database: str = "",
) -> Dict[str, Any]:
    """Get a complete overview of a binary in one call. Combines info, segments, top functions, and sample strings.

    When to use: As your FIRST call when starting analysis of a binary. Gives you everything
    you need to orient yourself without multiple round-trips.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)

    Returns:
        info: {db, arch, bits, funcs, entry, file_type, ...},
        segments: {segs, count},
        functions: {funcs (first 20), total, more},
        strings_sample: {strings (first 20), total, more},
        next_actions: [suggested follow-up actions]

    Examples:
        overview()
        overview(database="firmware.bin")
    """
    db = _resolve_database(database)
    result: Dict[str, Any] = {}

    result["info"] = make_jsonrpc_request(db, "info", {})
    result["segments"] = make_jsonrpc_request(db, "get_segments", {})
    result["functions"] = make_jsonrpc_request(db, "list_functions", {
        "filter": "", "offset": 0, "limit": 20,
    })
    result["strings_sample"] = make_jsonrpc_request(db, "search_strings", {
        "pattern": "", "min_length": 6, "offset": 0, "limit": 20,
    })

    # Build context-aware next_actions
    actions = []
    info_data = result.get("info", {})
    entry = info_data.get("entry")
    if entry:
        actions.append(f"Use decompile(selector='{entry}') to analyze the entry point")
    actions.extend([
        "Use list_functions(filter='main|init|start') to find key entry points",
        "Use search_strings(pattern='password|secret|key|token') for security-relevant strings",
        "Use search_strings(pattern='http|url|socket') for network indicators",
        "Use list_functions(filter='crypt|encrypt|decrypt|hash') to find crypto functions",
        "Use decompile(selector='function_name') to analyze specific functions",
    ])
    result["next_actions"] = actions

    return result


@mcp.tool()
def script_exec(
    database: str = "",
    script: str = "",
) -> Dict[str, Any]:
    """Execute arbitrary Python code in IDA. Escape hatch for operations not covered by other tools.

    When to use: ONLY when no other tool can do what you need. This runs arbitrary code in IDA's
    Python environment with full access to the IDA API.

    NOT for: Decompiling (use decompile), searching (use search), renaming (use rename),
    or any operation that has a dedicated tool.

    Args:
        database: Database filename of the IDA instance (optional if only one instance)
        script: Python code to execute (REQUIRED). Use print() to return data.

    Returns:
        ok, out (stdout), err (stderr), error (if failed)

    Do:
    - Use print() to output data you need returned.
    - Keep scripts short and focused.
    - Use for: listing enums, creating enums, bulk operations, accessing IDA APIs not exposed as tools.

    Don't:
    - Pass an empty script.
    - Use this when a dedicated tool exists (decompile, search, rename, etc.).
    - Run destructive operations without understanding what they do.

    Examples:
        script_exec(script="for i in range(ida_typeinf.get_enum_qty()): print(ida_typeinf.get_enum_name(ida_typeinf.getn_enum(i)))")
        script_exec(script="print(hex(idaapi.get_screen_ea()))")
    """
    if not script:
        raise Exception(
            "script is required. Provide Python code to execute. "
            "Consider using a dedicated tool instead: decompile, search, rename, set_type, etc."
        )
    return make_jsonrpc_request(_resolve_database(database), "script_exec", {
        "script": script,
    })


# ============================================================================
# New Tools - Survey & Core
# ============================================================================


@mcp.tool()
def survey_binary(
    database: str = "",
    detail_level: str = "standard",
) -> Dict[str, Any]:
    """One-call binary triage. Returns metadata, top strings/functions by xref count,
    imports by category, and function classifications.

    When to use: As your FIRST call for a quick but comprehensive binary overview.
    More detailed than overview() - ranks strings and functions by importance.

    Args:
        database: Database filename (optional if only one instance)
        detail_level: "quick", "standard", or "full"

    Returns:
        metadata, statistics, interesting_strings, interesting_functions, imports_by_category
    """
    return make_jsonrpc_request(_resolve_database(database), "survey_binary", {
        "detail_level": detail_level,
    })


@mcp.tool()
def func_query(
    database: str = "",
    selector: str = "",
) -> Dict[str, Any]:
    """Get detailed information about a single function.

    Returns name, address, size, prototype, basic block count, xref counts.
    More detailed than list_functions for a specific function.

    Args:
        database: Database filename (optional if only one instance)
        selector: Function name or address (REQUIRED)
    """
    if not selector:
        raise Exception("selector is required.")
    return make_jsonrpc_request(_resolve_database(database), "func_query", {
        "selector": selector,
    })


@mcp.tool()
def list_globals(
    database: str = "",
    filter: str = "",
    offset: int = 0,
    limit: int = 100,
) -> Dict[str, Any]:
    """List global variables (named data items not in functions).

    Args:
        database: Database filename (optional if only one instance)
        filter: Regex filter for names
        offset: Pagination start
        limit: Max results
    """
    return make_jsonrpc_request(_resolve_database(database), "list_globals", {
        "filter": filter, "offset": offset, "limit": limit,
    })


@mcp.tool()
def entity_query(
    database: str = "",
    name: str = "",
) -> Dict[str, Any]:
    """Look up any named entity (function, global, import, string).

    Args:
        database: Database filename (optional if only one instance)
        name: Entity name to look up (REQUIRED)
    """
    if not name:
        raise Exception("name is required.")
    return make_jsonrpc_request(_resolve_database(database), "entity_query", {
        "name": name,
    })


@mcp.tool()
def imports_list(
    database: str = "",
) -> Dict[str, Any]:
    """List all imports grouped by module.

    Args:
        database: Database filename (optional if only one instance)

    Returns:
        modules: [{name, imports: [{addr, name, ordinal}]}], total
    """
    return make_jsonrpc_request(_resolve_database(database), "imports_list", {})


@mcp.tool()
def imports_query(
    database: str = "",
    filter: str = "",
    module: str = "",
) -> Dict[str, Any]:
    """Search imports by name pattern and optional module filter.

    Args:
        database: Database filename (optional if only one instance)
        filter: Regex to filter import names
        module: Filter to specific module
    """
    return make_jsonrpc_request(_resolve_database(database), "imports_query", {
        "filter": filter, "module": module,
    })


@mcp.tool()
def idb_save(
    database: str = "",
) -> Dict[str, Any]:
    """Save the IDA database.

    Args:
        database: Database filename (optional if only one instance)
    """
    return make_jsonrpc_request(_resolve_database(database), "idb_save", {})


@mcp.tool()
def int_convert(
    value: str = "",
) -> Dict[str, Any]:
    """Convert a number between formats (hex, decimal, octal, binary, ASCII).

    Args:
        value: Number in any format (e.g. "0xFF", "255", "0b11111111")
    """
    if not value:
        raise Exception("value is required.")
    # This runs locally, no IDA needed
    from plugin.rpc import rpc as _rpc
    return _rpc.dispatch("int_convert", {"value": value})


# ============================================================================
# New Tools - Composite Analysis
# ============================================================================


@mcp.tool()
def analyze_function_compact(
    database: str = "",
    selector: str = "",
) -> Dict[str, Any]:
    """Deep single-function analysis in one call. Returns decompilation, string refs,
    constants, callers, callees, and basic block count.

    Args:
        database: Database filename (optional if only one instance)
        selector: Function name or address (REQUIRED)
    """
    if not selector:
        raise Exception("selector is required.")
    return make_jsonrpc_request(_resolve_database(database), "analyze_function_compact", {
        "selector": selector,
    })


@mcp.tool()
def analyze_component(
    database: str = "",
    selectors: List[str] = [],
    max_depth: int = 1,
) -> Dict[str, Any]:
    """Multi-function group analysis with internal call graph and shared globals.

    Args:
        database: Database filename (optional if only one instance)
        selectors: List of function names/addresses to analyze together
        max_depth: Depth for internal call graph (default 1)
    """
    if not selectors:
        raise Exception("selectors list is required.")
    return make_jsonrpc_request(_resolve_database(database), "analyze_component", {
        "selectors": selectors, "max_depth": max_depth,
    })


@mcp.tool()
def diff_before_after(
    database: str = "",
    selector: str = "",
    rename_to: str = "",
    type_str: str = "",
    comment: str = "",
    comment_addr: str = "",
) -> Dict[str, Any]:
    """Apply rename/type/comment modifications and show before/after decompilation.

    Args:
        database: Database filename (optional if only one instance)
        selector: Function to modify (REQUIRED)
        rename_to: New name for the function
        type_str: New type declaration
        comment: Comment to add
        comment_addr: Address for comment (defaults to function start)
    """
    if not selector:
        raise Exception("selector is required.")
    return make_jsonrpc_request(_resolve_database(database), "diff_before_after", {
        "selector": selector, "rename_to": rename_to,
        "type_str": type_str, "comment": comment, "comment_addr": comment_addr,
    })


@mcp.tool()
def trace_data_flow(
    database: str = "",
    start: str = "",
    direction: str = "forward",
    max_depth: int = 3,
    max_nodes: int = 50,
) -> Dict[str, Any]:
    """BFS xref traversal to trace data flow forward or backward from an address.

    Args:
        database: Database filename (optional if only one instance)
        start: Starting address or function name (REQUIRED)
        direction: "forward" (follow xrefs FROM) or "backward" (follow xrefs TO)
        max_depth: Maximum BFS depth
        max_nodes: Maximum nodes to collect
    """
    if not start:
        raise Exception("start is required.")
    return make_jsonrpc_request(_resolve_database(database), "trace_data_flow", {
        "start": start, "direction": direction,
        "max_depth": max_depth, "max_nodes": max_nodes,
    })


# ============================================================================
# New Tools - Enhanced Analysis
# ============================================================================


@mcp.tool()
def basic_blocks(
    database: str = "",
    selector: str = "",
) -> Dict[str, Any]:
    """Get basic block boundaries for a function (CFG analysis).

    Args:
        database: Database filename (optional if only one instance)
        selector: Function name or address (REQUIRED)

    Returns:
        blocks: [{start, end, size, succs, preds, instructions}], count
    """
    if not selector:
        raise Exception("selector is required.")
    return make_jsonrpc_request(_resolve_database(database), "basic_blocks", {
        "selector": selector,
    })


@mcp.tool()
def find_insns(
    database: str = "",
    selector: str = "",
    mnemonic: str = "",
    operand: str = "",
    limit: int = 100,
) -> Dict[str, Any]:
    """Find instructions matching a pattern within a function.

    Args:
        database: Database filename (optional if only one instance)
        selector: Function name or address (REQUIRED)
        mnemonic: Regex to match instruction mnemonic (e.g. "call", "mov")
        operand: Text to match in operands
        limit: Max results
    """
    if not selector:
        raise Exception("selector is required.")
    return make_jsonrpc_request(_resolve_database(database), "find_insns", {
        "selector": selector, "mnemonic": mnemonic,
        "operand": operand, "limit": limit,
    })


# ============================================================================
# New Tools - Enhanced Memory
# ============================================================================


@mcp.tool()
def get_int(
    database: str = "",
    address: str = "",
    type: str = "u32",
) -> Dict[str, Any]:
    """Read a typed integer at an address.

    Args:
        database: Database filename (optional if only one instance)
        address: Hex address (REQUIRED)
        type: Integer type: u8, i8, u16, i16, u32, i32, u64, i64 (add 'be' suffix for big-endian)
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "get_int", {
        "address": address, "type": type,
    })


@mcp.tool()
def get_string(
    database: str = "",
    address: str = "",
    encoding: str = "utf-8",
    max_length: int = 1024,
) -> Dict[str, Any]:
    """Read a null-terminated string at an address.

    Args:
        database: Database filename (optional if only one instance)
        address: Hex address (REQUIRED)
        encoding: String encoding (default utf-8)
        max_length: Max bytes to read
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "get_string", {
        "address": address, "encoding": encoding, "max_length": max_length,
    })


@mcp.tool()
def get_global_value(
    database: str = "",
    name: str = "",
) -> Dict[str, Any]:
    """Read the value of a named global variable.

    Args:
        database: Database filename (optional if only one instance)
        name: Global variable name (REQUIRED)
    """
    if not name:
        raise Exception("name is required.")
    return make_jsonrpc_request(_resolve_database(database), "get_global_value", {
        "name": name,
    })


@mcp.tool()
def patch_bytes(
    database: str = "",
    address: str = "",
    hex_bytes: str = "",
) -> Dict[str, Any]:
    """Write raw bytes to the IDA database at an address.

    Args:
        database: Database filename (optional if only one instance)
        address: Hex address (REQUIRED)
        hex_bytes: Hex string of bytes to write (REQUIRED), e.g. "90909090"
    """
    if not address or not hex_bytes:
        raise Exception("address and hex_bytes are required.")
    return make_jsonrpc_request(_resolve_database(database), "patch_bytes", {
        "address": address, "hex_bytes": hex_bytes,
    })


@mcp.tool()
def put_int(
    database: str = "",
    address: str = "",
    value: int = 0,
    type: str = "u32",
) -> Dict[str, Any]:
    """Write a typed integer at an address in the IDA database.

    Args:
        database: Database filename (optional if only one instance)
        address: Hex address (REQUIRED)
        value: Integer value to write
        type: Integer type: u8, i8, u16, i16, u32, i32, u64, i64
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "put_int", {
        "address": address, "value": value, "type": type,
    })


# ============================================================================
# New Tools - Enhanced Types
# ============================================================================


@mcp.tool()
def declare_type(
    database: str = "",
    declaration: str = "",
) -> Dict[str, Any]:
    """Parse and register a C type declaration in the local type library.

    Args:
        database: Database filename (optional if only one instance)
        declaration: C type declaration (REQUIRED), e.g. "typedef int BOOL;"
    """
    if not declaration:
        raise Exception("declaration is required.")
    return make_jsonrpc_request(_resolve_database(database), "declare_type", {
        "declaration": declaration,
    })


@mcp.tool()
def enum_upsert(
    database: str = "",
    name: str = "",
    members: Dict[str, int] = {},
    width: int = 4,
) -> Dict[str, Any]:
    """Create or update an enum type.

    Args:
        database: Database filename (optional if only one instance)
        name: Enum name (REQUIRED)
        members: Dict of member_name -> value (REQUIRED)
        width: Enum width in bytes (default 4)
    """
    if not name or not members:
        raise Exception("name and members are required.")
    return make_jsonrpc_request(_resolve_database(database), "enum_upsert", {
        "name": name, "members": members, "width": width,
    })


@mcp.tool()
def read_struct(
    database: str = "",
    address: str = "",
    struct_name: str = "",
) -> Dict[str, Any]:
    """Read memory at an address interpreted as a struct.

    Args:
        database: Database filename (optional if only one instance)
        address: Hex address (REQUIRED)
        struct_name: Struct type name (REQUIRED)
    """
    if not address or not struct_name:
        raise Exception("address and struct_name are required.")
    return make_jsonrpc_request(_resolve_database(database), "read_struct", {
        "address": address, "struct_name": struct_name,
    })


@mcp.tool()
def search_structs(
    database: str = "",
    filter: str = "",
    offset: int = 0,
    limit: int = 50,
) -> Dict[str, Any]:
    """Search struct/union definitions by name pattern.

    Args:
        database: Database filename (optional if only one instance)
        filter: Regex to filter struct names
        offset: Pagination start
        limit: Max results
    """
    return make_jsonrpc_request(_resolve_database(database), "search_structs", {
        "filter": filter, "offset": offset, "limit": limit,
    })


@mcp.tool()
def type_query(
    database: str = "",
    filter: str = "",
    kind: str = "",
    offset: int = 0,
    limit: int = 50,
) -> Dict[str, Any]:
    """Query types in the local type library.

    Args:
        database: Database filename (optional if only one instance)
        filter: Regex to filter type names
        kind: Filter by kind: "struct", "union", "enum", "typedef", or "" (all)
        offset: Pagination start
        limit: Max results
    """
    return make_jsonrpc_request(_resolve_database(database), "type_query", {
        "filter": filter, "kind": kind, "offset": offset, "limit": limit,
    })


@mcp.tool()
def type_inspect(
    database: str = "",
    name: str = "",
) -> Dict[str, Any]:
    """Get full details of a named type (struct members, enum values, etc).

    Args:
        database: Database filename (optional if only one instance)
        name: Type name (REQUIRED)
    """
    if not name:
        raise Exception("name is required.")
    return make_jsonrpc_request(_resolve_database(database), "type_inspect", {
        "name": name,
    })


@mcp.tool()
def type_apply_batch(
    database: str = "",
    items: List[Dict[str, str]] = [],
) -> Dict[str, Any]:
    """Batch apply types to multiple addresses.

    Args:
        database: Database filename (optional if only one instance)
        items: List of {target, type_str} to apply
    """
    if not items:
        raise Exception("items list is required.")
    return make_jsonrpc_request(_resolve_database(database), "type_apply_batch", {
        "items": items,
    })


@mcp.tool()
def infer_types(
    database: str = "",
    selector: str = "",
) -> Dict[str, Any]:
    """Auto-infer types for a function using the Hex-Rays decompiler.

    Args:
        database: Database filename (optional if only one instance)
        selector: Function name or address (REQUIRED)
    """
    if not selector:
        raise Exception("selector is required.")
    return make_jsonrpc_request(_resolve_database(database), "infer_types", {
        "selector": selector,
    })


# ============================================================================
# New Tools - Stack Frame
# ============================================================================


@mcp.tool()
def stack_frame(
    database: str = "",
    selector: str = "",
) -> Dict[str, Any]:
    """Get the stack frame layout for a function.

    Args:
        database: Database filename (optional if only one instance)
        selector: Function name or address (REQUIRED)

    Returns:
        name, addr, frame_size, members: [{name, offset, size, type}]
    """
    if not selector:
        raise Exception("selector is required.")
    return make_jsonrpc_request(_resolve_database(database), "stack_frame", {
        "selector": selector,
    })


@mcp.tool()
def declare_stack(
    database: str = "",
    selector: str = "",
    offset: int = 0,
    name: str = "",
    type_str: str = "",
    size: int = 0,
) -> Dict[str, Any]:
    """Add or modify a stack variable in a function's frame.

    Args:
        database: Database filename (optional if only one instance)
        selector: Function name or address (REQUIRED)
        offset: Stack offset (REQUIRED)
        name: Variable name (REQUIRED)
        type_str: C type for the variable
        size: Size in bytes (auto-detected from type if not given)
    """
    if not selector or not name:
        raise Exception("selector and name are required.")
    return make_jsonrpc_request(_resolve_database(database), "declare_stack", {
        "selector": selector, "offset": offset,
        "name": name, "type_str": type_str, "size": size,
    })


@mcp.tool()
def delete_stack(
    database: str = "",
    selector: str = "",
    offset: int = 0,
) -> Dict[str, Any]:
    """Remove a stack variable from a function's frame.

    Args:
        database: Database filename (optional if only one instance)
        selector: Function name or address (REQUIRED)
        offset: Stack offset of the variable to remove
    """
    if not selector:
        raise Exception("selector is required.")
    return make_jsonrpc_request(_resolve_database(database), "delete_stack", {
        "selector": selector, "offset": offset,
    })


# ============================================================================
# New Tools - Enhanced Modifications
# ============================================================================


@mcp.tool()
def append_comments(
    database: str = "",
    address: str = "",
    comment: str = "",
    comment_type: str = "line",
) -> Dict[str, Any]:
    """Append to an existing comment (with deduplication).

    Args:
        database: Database filename (optional if only one instance)
        address: Hex address (REQUIRED)
        comment: Comment text to append (REQUIRED)
        comment_type: "line", "function", or "repeatable"
    """
    if not address or not comment:
        raise Exception("address and comment are required.")
    return make_jsonrpc_request(_resolve_database(database), "append_comments", {
        "address": address, "comment": comment, "comment_type": comment_type,
    })


@mcp.tool()
def patch_asm(
    database: str = "",
    address: str = "",
    assembly: str = "",
) -> Dict[str, Any]:
    """Assemble an instruction and patch it at the given address.

    Args:
        database: Database filename (optional if only one instance)
        address: Hex address (REQUIRED)
        assembly: Assembly instruction text (REQUIRED), e.g. "nop" or "mov eax, 0"
    """
    if not address or not assembly:
        raise Exception("address and assembly are required.")
    return make_jsonrpc_request(_resolve_database(database), "patch_asm", {
        "address": address, "assembly": assembly,
    })


@mcp.tool()
def define_func(
    database: str = "",
    address: str = "",
    end_address: str = "",
) -> Dict[str, Any]:
    """Create a function at the given address.

    Args:
        database: Database filename (optional if only one instance)
        address: Start address (REQUIRED)
        end_address: Optional end address (IDA auto-detects if not given)
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "define_func", {
        "address": address, "end_address": end_address,
    })


@mcp.tool()
def define_code(
    database: str = "",
    address: str = "",
    size: int = 0,
) -> Dict[str, Any]:
    """Convert bytes to code (instructions) at the given address.

    Args:
        database: Database filename (optional if only one instance)
        address: Hex address (REQUIRED)
        size: Number of bytes to convert (0 = auto-detect single instruction)
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "define_code", {
        "address": address, "size": size,
    })


@mcp.tool()
def undefine(
    database: str = "",
    address: str = "",
    size: int = 1,
) -> Dict[str, Any]:
    """Undefine bytes at an address (revert to raw data).

    Args:
        database: Database filename (optional if only one instance)
        address: Hex address (REQUIRED)
        size: Number of bytes to undefine
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "undefine", {
        "address": address, "size": size,
    })


# ============================================================================
# New Tools - Debugger
# ============================================================================


@mcp.tool()
def dbg_start(database: str = "", path: str = "", args: str = "") -> Dict[str, Any]:
    """Start a debugger session.

    Args:
        database: Database filename (optional if only one instance)
        path: Path to executable (defaults to current IDB's input)
        args: Command line arguments
    """
    return make_jsonrpc_request(_resolve_database(database), "dbg_start", {
        "path": path, "args": args,
    })


@mcp.tool()
def dbg_exit(database: str = "") -> Dict[str, Any]:
    """Terminate the debugger session."""
    return make_jsonrpc_request(_resolve_database(database), "dbg_exit", {})


@mcp.tool()
def dbg_continue(database: str = "") -> Dict[str, Any]:
    """Continue execution in the debugger."""
    return make_jsonrpc_request(_resolve_database(database), "dbg_continue", {})


@mcp.tool()
def dbg_run_to(database: str = "", address: str = "") -> Dict[str, Any]:
    """Run to a specific address.

    Args:
        database: Database filename (optional if only one instance)
        address: Target address (REQUIRED)
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "dbg_run_to", {
        "address": address,
    })


@mcp.tool()
def dbg_step_into(database: str = "") -> Dict[str, Any]:
    """Step into the next instruction."""
    return make_jsonrpc_request(_resolve_database(database), "dbg_step_into", {})


@mcp.tool()
def dbg_step_over(database: str = "") -> Dict[str, Any]:
    """Step over the next instruction."""
    return make_jsonrpc_request(_resolve_database(database), "dbg_step_over", {})


@mcp.tool()
def dbg_bps(database: str = "") -> Dict[str, Any]:
    """List all breakpoints."""
    return make_jsonrpc_request(_resolve_database(database), "dbg_bps", {})


@mcp.tool()
def dbg_add_bp(database: str = "", address: str = "") -> Dict[str, Any]:
    """Add a breakpoint.

    Args:
        database: Database filename (optional if only one instance)
        address: Address for breakpoint (REQUIRED)
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "dbg_add_bp", {
        "address": address,
    })


@mcp.tool()
def dbg_delete_bp(database: str = "", address: str = "") -> Dict[str, Any]:
    """Delete a breakpoint.

    Args:
        database: Database filename (optional if only one instance)
        address: Address of breakpoint to delete (REQUIRED)
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "dbg_delete_bp", {
        "address": address,
    })


@mcp.tool()
def dbg_toggle_bp(database: str = "", address: str = "") -> Dict[str, Any]:
    """Toggle a breakpoint enable/disable.

    Args:
        database: Database filename (optional if only one instance)
        address: Address of breakpoint to toggle (REQUIRED)
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "dbg_toggle_bp", {
        "address": address,
    })


@mcp.tool()
def dbg_regs(database: str = "") -> Dict[str, Any]:
    """Read general purpose registers."""
    return make_jsonrpc_request(_resolve_database(database), "dbg_regs", {})


@mcp.tool()
def dbg_regs_all(database: str = "") -> Dict[str, Any]:
    """Read all register groups."""
    return make_jsonrpc_request(_resolve_database(database), "dbg_regs_all", {})


@mcp.tool()
def dbg_stacktrace(database: str = "") -> Dict[str, Any]:
    """Get the current call stack from the debugger."""
    return make_jsonrpc_request(_resolve_database(database), "dbg_stacktrace", {})


@mcp.tool()
def dbg_read(database: str = "", address: str = "", size: int = 64) -> Dict[str, Any]:
    """Read memory from the debuggee process.

    Args:
        database: Database filename (optional if only one instance)
        address: Address to read from (REQUIRED)
        size: Number of bytes to read
    """
    if not address:
        raise Exception("address is required.")
    return make_jsonrpc_request(_resolve_database(database), "dbg_read", {
        "address": address, "size": size,
    })


@mcp.tool()
def dbg_write(database: str = "", address: str = "", hex_bytes: str = "") -> Dict[str, Any]:
    """Write memory to the debuggee process.

    Args:
        database: Database filename (optional if only one instance)
        address: Address to write to (REQUIRED)
        hex_bytes: Hex string of bytes to write (REQUIRED)
    """
    if not address or not hex_bytes:
        raise Exception("address and hex_bytes are required.")
    return make_jsonrpc_request(_resolve_database(database), "dbg_write", {
        "address": address, "hex_bytes": hex_bytes,
    })


# ============================================================================
# New Tools - Enhanced Python Execution
# ============================================================================


@mcp.tool()
def py_eval(
    database: str = "",
    code: str = "",
) -> Dict[str, Any]:
    """Jupyter-style Python execution with smart result handling.

    Single expressions return their value. Statements with a trailing expression
    execute the statements then return the expression's value. All IDA modules
    are pre-imported.

    Args:
        database: Database filename (optional if only one instance)
        code: Python code to evaluate (REQUIRED)
    """
    if not code:
        raise Exception("code is required.")
    return make_jsonrpc_request(_resolve_database(database), "py_eval", {
        "code": code,
    })


@mcp.tool()
def py_exec_file(
    database: str = "",
    path: str = "",
) -> Dict[str, Any]:
    """Execute a Python script file in IDA's environment.

    Args:
        database: Database filename (optional if only one instance)
        path: Path to the Python script (REQUIRED)
    """
    if not path:
        raise Exception("path is required.")
    return make_jsonrpc_request(_resolve_database(database), "py_exec_file", {
        "path": path,
    })


# ============================================================================
# New Tools - Instance Management
# ============================================================================


@mcp.tool()
def open_file(
    database: str = "",
    path: str = "",
    args: str = "",
) -> Dict[str, Any]:
    """Launch a new IDA instance with a binary file.

    Args:
        database: Database filename (optional if only one instance, used for routing)
        path: Path to the binary file to open (REQUIRED)
        args: Additional IDA command line arguments
    """
    if not path:
        raise Exception("path is required.")
    # If we have any running instance, send through it
    db = _resolve_database(database) if database else None
    if db:
        return make_jsonrpc_request(db, "open_file", {"path": path, "args": args})
    # No instance running - launch IDA directly
    import subprocess
    ida_path = shutil.which("ida64") or shutil.which("ida") or shutil.which("idat64") or shutil.which("idat")
    if not ida_path:
        raise Exception("Cannot find IDA executable in PATH. Set IDA path manually.")
    cmd = [ida_path]
    if args:
        cmd.extend(args.split())
    cmd.append(path)
    proc = subprocess.Popen(cmd, start_new_session=True)
    return {"ok": True, "path": path, "pid": proc.pid}


# ============================================================================
# MCP Resources - ida:// URIs
# ============================================================================


@mcp.resource("ida://idb/metadata")
def resource_idb_metadata() -> str:
    """IDA database metadata: file path, architecture, bitness, hashes."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_idb_metadata", {})
    return json.dumps(result, indent=2)


@mcp.resource("ida://idb/segments")
def resource_idb_segments() -> str:
    """Memory segments of the loaded binary."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_idb_segments", {})
    return json.dumps(result, indent=2)


@mcp.resource("ida://idb/entrypoints")
def resource_idb_entrypoints() -> str:
    """Entry points of the binary."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_idb_entrypoints", {})
    return json.dumps(result, indent=2)


@mcp.resource("ida://cursor")
def resource_cursor() -> str:
    """Current cursor position and containing function."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_cursor", {})
    return json.dumps(result, indent=2)


@mcp.resource("ida://selection")
def resource_selection() -> str:
    """Active selection range in IDA."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_selection", {})
    return json.dumps(result, indent=2)


@mcp.resource("ida://types")
def resource_types() -> str:
    """Local type library listing."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_types", {})
    return json.dumps(result, indent=2)


@mcp.resource("ida://structs")
def resource_structs() -> str:
    """All struct definitions."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_structs", {})
    return json.dumps(result, indent=2)


@mcp.resource("ida://struct/{name}")
def resource_struct_detail(name: str) -> str:
    """Details of a specific struct."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_struct_detail", {"name": name})
    return json.dumps(result, indent=2)


@mcp.resource("ida://import/{name}")
def resource_import_detail(name: str) -> str:
    """Look up an import by name."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_import_detail", {"name": name})
    return json.dumps(result, indent=2)


@mcp.resource("ida://export/{name}")
def resource_export_detail(name: str) -> str:
    """Look up an export by name."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_export_detail", {"name": name})
    return json.dumps(result, indent=2)


@mcp.resource("ida://xrefs/from/{addr}")
def resource_xrefs_from(addr: str) -> str:
    """Outgoing cross-references from an address."""
    db = _resolve_database("")
    result = make_jsonrpc_request(db, "resource_xrefs_from", {"address": addr})
    return json.dumps(result, indent=2)


# ============================================================================
# MCP Prompts - Guided analysis workflows
# ============================================================================

@mcp.prompt()
def analyze_function(database: str, function: str) -> str:
    """Systematic function analysis guide.

    Args:
        database: Database filename of the IDA instance
        function: Function name or address to analyze
    """
    return f"""Analyze the function '{function}' in database '{database}' systematically:

1. First, get the function's pseudocode:
   decompile(database="{database}", selector="{function}")

2. Get the assembly for low-level details:
   disassemble(database="{database}", selector="{function}")

3. Understand the call context:
   get_xrefs(database="{database}", target="{function}", direction="to")
   get_callgraph(database="{database}", target="{function}", max_depth=2)

After gathering this information, provide:
- **Purpose**: What does this function do?
- **Parameters**: What are the inputs and how are they used?
- **Return value**: What does it return and what does that mean?
- **Side effects**: Does it modify global state, write to files, make network calls?
- **Algorithm**: Describe the logic step by step
- **Security concerns**: Any potential vulnerabilities or dangerous patterns?

Once you understand the function, use rename() and set_comment() to document your findings in IDA."""


@mcp.prompt()
def identify_vulnerabilities(database: str, function: str) -> str:
    """Security-focused vulnerability analysis.

    Args:
        database: Database filename of the IDA instance
        function: Function name or address to analyze
    """
    return f"""Perform security analysis on '{function}' in database '{database}':

1. Get the decompiled code:
   decompile(database="{database}", selector="{function}")

2. Get assembly for precise understanding:
   disassemble(database="{database}", selector="{function}")

3. Check what calls this function (attack surface):
   get_xrefs(database="{database}", target="{function}", direction="to")

Analyze for these vulnerability classes:

**Memory Safety**
- Buffer overflow/underflow (fixed-size buffers, missing bounds checks)
- Integer overflow leading to small allocations
- Use-after-free / double-free
- Uninitialized memory use

**Input Validation**
- Format string vulnerabilities (user input to printf-family)
- Command injection (user input to system/exec)
- Path traversal (user input in file paths)
- SQL/NoSQL injection patterns

**Logic Issues**
- Race conditions (TOCTOU)
- Missing authentication/authorization checks
- Cryptographic weaknesses (weak algorithms, hardcoded keys)
- Information disclosure

For each potential vulnerability found:
1. **Location**: Exact address/line
2. **Description**: What the bug is
3. **Impact**: What an attacker could achieve
4. **Exploitation**: How it might be triggered
5. **Remediation**: How to fix it

Use set_comment() to annotate vulnerable code locations."""


@mcp.prompt()
def reverse_engineer_binary(database: str) -> str:
    """Comprehensive binary reverse engineering guide.

    Args:
        database: Database filename of the IDA instance
    """
    return f"""Systematically reverse engineer the binary '{database}':

## Phase 1: Reconnaissance

1. Get binary overview:
   info(database="{database}")
   get_segments(database="{database}")

2. Find interesting strings:
   search_strings(database="{database}", pattern="password|key|secret|token|api", limit=50)
   search_strings(database="{database}", pattern="http|https|ftp|ssh", limit=50)
   search_strings(database="{database}", pattern="error|fail|invalid", limit=50)

3. List functions and identify patterns:
   list_functions(database="{database}", filter="main", limit=20)
   list_functions(database="{database}", filter="init|setup|start", limit=20)
   list_functions(database="{database}", filter="crypt|encrypt|decrypt|hash", limit=20)
   list_functions(database="{database}", filter="net|socket|connect|send|recv", limit=20)

## Phase 2: Entry Point Analysis

4. Start from main/entry and trace execution:
   - Decompile entry points
   - Follow the call graph to understand program flow
   - Identify initialization routines

## Phase 3: Functional Mapping

5. Categorize functions by purpose:
   - Network communication
   - File I/O
   - Cryptography
   - String manipulation
   - Configuration/settings

6. For each important function:
   - Decompile and understand
   - Rename with descriptive names
   - Add comments explaining purpose
   - Set proper types for parameters

## Phase 4: Data Structure Recovery

7. Identify and document data structures:
   - Look for structs passed between functions
   - Use create_struct() to define them
   - Apply types with set_type()

## Phase 5: Documentation

8. Build a complete picture:
   - Document the program's purpose
   - Map out the architecture
   - Note any malicious/interesting behavior
   - Identify C2, persistence, evasion techniques if malware

Use rename(), set_type(), create_struct(), and set_comment() throughout to document findings."""


@mcp.prompt()
def analyze_malware(database: str) -> str:
    """Malware-specific analysis guide.

    Args:
        database: Database filename of the IDA instance
    """
    return f"""Analyze potential malware in '{database}':

## Phase 1: Triage

1. Basic info and structure:
   info(database="{database}")
   get_segments(database="{database}")

2. Look for malware indicators in strings:
   search_strings(database="{database}", pattern="cmd|powershell|bash|sh", limit=30)
   search_strings(database="{database}", pattern="RegSetValue|CreateService|schtasks", limit=30)
   search_strings(database="{database}", pattern="VirtualAlloc|VirtualProtect|NtUnmap", limit=30)
   search_strings(database="{database}", pattern="http|https|socket|connect|recv|send", limit=30)
   search_strings(database="{database}", pattern="password|credential|token|key", limit=30)

## Phase 2: Capability Analysis

3. Find functions related to:

   **Persistence**:
   list_functions(database="{database}", filter="registry|service|schedule|startup", limit=20)

   **C2 Communication**:
   list_functions(database="{database}", filter="http|socket|connect|beacon|command", limit=20)

   **Data Exfiltration**:
   list_functions(database="{database}", filter="upload|send|post|exfil", limit=20)

   **Evasion**:
   list_functions(database="{database}", filter="anti|debug|vm|sandbox|detect", limit=20)

   **Payload**:
   list_functions(database="{database}", filter="inject|hollow|load|exec|shell", limit=20)

## Phase 3: Deep Dive

4. For each capability identified:
   - Decompile the relevant functions
   - Trace the call graph
   - Document the technique used
   - Note IOCs (IPs, domains, file paths, registry keys)

## Phase 4: Report

Produce a malware analysis report covering:
- **Family/Type**: What kind of malware is this?
- **Capabilities**: What can it do?
- **C2 Protocol**: How does it communicate?
- **Persistence**: How does it survive reboot?
- **Evasion**: What anti-analysis techniques does it use?
- **IOCs**: Network indicators, file paths, registry keys
- **MITRE ATT&CK**: Map techniques to ATT&CK framework"""


# ============================================================================
# Installation and Setup
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PY = os.path.join(SCRIPT_DIR, "mcp-plugin.py")
# The plugin package directory that must be symlinked alongside the shim
IDA_PLUGIN_PKG = SCRIPT_DIR  # The entire src/ida_pro_mcp/ directory


def get_python_executable():
    """Get the path to the Python executable."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python
    return sys.executable


def install_ida_plugin(*, uninstall: bool = False, quiet: bool = False):
    """Install or uninstall the IDA plugin.

    Symlinks the entire ida_pro_mcp package directory into IDA's plugins folder
    so that the modular plugin package is accessible alongside the shim.
    """
    if sys.platform == "win32":
        ida_folder = os.path.join(os.getenv("APPDATA"), "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")

    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    # Symlink the package directory
    pkg_destination = os.path.join(ida_plugin_folder, "ida_pro_mcp")
    # Also symlink the shim entry point at the top level
    shim_destination = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        for path in (pkg_destination, shim_destination):
            if os.path.lexists(path):
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                if not quiet:
                    print(f"Uninstalled: {path}")
        return

    os.makedirs(ida_plugin_folder, exist_ok=True)

    # Create symlink for the package directory
    if os.path.lexists(pkg_destination):
        if os.path.isdir(pkg_destination) and not os.path.islink(pkg_destination):
            shutil.rmtree(pkg_destination)
        else:
            os.remove(pkg_destination)

    try:
        os.symlink(IDA_PLUGIN_PKG, pkg_destination)
    except OSError:
        shutil.copytree(IDA_PLUGIN_PKG, pkg_destination)

    # Create symlink for the shim entry point
    if os.path.lexists(shim_destination):
        os.remove(shim_destination)

    try:
        os.symlink(IDA_PLUGIN_PY, shim_destination)
    except OSError:
        shutil.copy(IDA_PLUGIN_PY, shim_destination)

    if not quiet:
        print(f"Installed IDA plugin package: {pkg_destination}")
        print(f"Installed IDA plugin shim: {shim_destination}")


def install_mcp_servers(*, uninstall: bool = False, quiet: bool = False):
    """Install MCP server configuration for various clients."""
    if sys.platform == "darwin":
        configs = {
            "Claude": (os.path.expanduser("~/Library/Application Support/Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.expanduser("~/.cursor"), "mcp.json"),
            "Claude Code": (os.path.expanduser("~"), ".claude.json"),
        }
    elif sys.platform == "win32":
        configs = {
            "Claude": (os.path.join(os.path.expanduser("~"), "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Claude Code": (os.path.expanduser("~"), ".claude.json"),
        }
    else:  # Linux
        configs = {
            "Cursor": (os.path.expanduser("~/.cursor"), "mcp.json"),
            "Claude Code": (os.path.expanduser("~"), ".claude.json"),
        }

    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)

        if not os.path.exists(config_dir):
            if not quiet:
                print(f"Skipping {name} (directory not found)")
            continue

        # Load existing config
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
            except:
                config = {}
        else:
            config = {}

        if "mcpServers" not in config:
            config["mcpServers"] = {}

        if uninstall:
            if mcp.name in config["mcpServers"]:
                del config["mcpServers"][mcp.name]
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                if not quiet:
                    print(f"Uninstalled from {name}")
        else:
            config["mcpServers"][mcp.name] = {
                "command": get_python_executable(),
                "args": [__file__],
                "timeout": 1800,
            }
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
            if not quiet:
                print(f"Installed to {name}: {config_path}")


def main():
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="Install MCP server and IDA plugin")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall MCP server and IDA plugin")
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport (stdio or http)")
    args = parser.parse_args()

    if args.install:
        install_ida_plugin()
        install_mcp_servers()
        print("\nInstallation complete. Restart IDA Pro to load the plugin.")
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True)
        install_mcp_servers(uninstall=True)
        return

    # Run the MCP server
    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            from urllib.parse import urlparse
            url = urlparse(args.transport)
            if url.hostname and url.port:
                mcp.settings.host = url.hostname
                mcp.settings.port = url.port
                mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
