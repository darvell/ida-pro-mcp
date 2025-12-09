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
    "disassemble": 25.0,
    "list_functions": 20.0,
    "search_strings": 30.0,
    "search": 30.0,
    "get_xrefs": 20.0,
    "script_exec": 60.0,
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
                if isinstance(e, OSError) and e.errno in (errno.ENOENT, errno.ECONNREFUSED):
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
    """Kill the process if it looks like an IDA binary. Returns True if killed."""

    if os.name != "posix":
        return False

    try:
        comm = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="], text=True).strip().lower()
    except Exception:
        return False

    if "ida" not in comm:
        return False

    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except Exception:
        return False


def _quick_health_check(socket_path: str) -> bool:
    """Best-effort ping to see if the MCP socket responds at all."""

    try:
        _send_jsonrpc_request(socket_path, "system.info", {}, timeout=2.0)
        return True
    except Exception:
        return False


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
                with suppress(Exception):
                    Path(socket_path).unlink()
                InstanceManager.refresh()
                _timeout_marks.pop(socket_path, None)
                if killed:
                    raise Exception(
                        f"Instance '{database}' became unresponsive (IDA likely crashed/froze after the last command). It was force-terminated (pid {pid}). Please reopen the database."
                    )
                raise Exception(
                    f"Instance '{database}' is unresponsive (IDA likely crashed/froze after the last command). Its socket was removed; please restart IDA for this database."
                )

            # Not yet past grace period: record and warn
            _timeout_marks[socket_path] = first_timeout
            remaining = int(max(0, KILL_GRACE_SECONDS - elapsed))
            raise Exception(
                f"Request to '{method}' timed out and IDA is unresponsive; it may be busy or frozen. "
                f"Will force-terminate if still unresponsive after {remaining}s. You can retry the command after waiting a bit."
            )

        # Health check succeeded: spin off async job and return job_id so caller can poll result
        try:
            job_resp = _send_jsonrpc_request(socket_path, "start_job", {"method": method, "params": params}, 5.0)
            job_id = job_resp.get("job_id") if isinstance(job_resp, dict) else None
        except Exception:
            job_id = None

        _timeout_marks.pop(socket_path, None)
        if job_id:
            raise Exception(
                f"Request to '{method}' timed out after {timeout}s, but IDA is still responding. "
                f"The operation was re-submitted as async job '{job_id}'. Poll job_status/job_result to retrieve the output (results kept ~5 minutes)."
            )
        raise Exception(
            f"Request to '{method}' timed out after {timeout}s, but IDA is still responding. "
            "The operation may still be running; consider retrying or increasing the timeout."
        )
    except OSError as e:
        raise Exception(f"Failed to communicate with IDA: {e}")


# ============================================================================
# MCP Tools - The 12 core tools for reverse engineering
# ============================================================================


@mcp.tool()
def job_status(database: str, job_id: str) -> Dict[str, Any]:
    """Check status of an async job (created after a timeout)."""
    return make_jsonrpc_request(database, "job_status", {"job_id": job_id})


@mcp.tool()
def job_result(database: str, job_id: str, pop: bool = True) -> Dict[str, Any]:
    """Get result of an async job (optionally remove it from cache)."""
    return make_jsonrpc_request(database, "job_result", {"job_id": job_id, "pop": pop})


@mcp.tool()
def list_instances() -> str:
    """List all active IDA Pro instances."""
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
    database: str,
    selector: str,
    start_line: int = 0,
    end_line: int = 0,
    max_lines: int = 0,
) -> Dict[str, Any]:
    """Get Hex-Rays pseudocode for a function.

    Args:
        database: Database filename of the IDA instance
        selector: Function name or "0xADDRESS"
        start_line: Start at this line (1-indexed, 0 = from beginning)
        end_line: End at this line (inclusive, 0 = to end)
        max_lines: Maximum lines to return (0 = no limit, overrides end_line)

    Returns:
        name, address, prototype, pseudocode, variables, line_info (if filtered)

    Examples:
        - Get first 20 lines: max_lines=20
        - Get lines 10-30: start_line=10, end_line=30
        - Get 15 lines from line 25: start_line=25, max_lines=15
    """
    return make_jsonrpc_request(database, "decompile", {
        "selector": selector,
        "start_line": start_line,
        "end_line": end_line,
        "max_lines": max_lines,
    })


@mcp.tool()
def disassemble(
    database: str,
    selector: str,
    max_instructions: int = 200,
) -> str:
    """Get assembly instructions for a function or address range.

    Args:
        database: Database filename of the IDA instance
        selector: Function name, "0xADDRESS", or "0xSTART-0xEND"
        max_instructions: Maximum instructions to return (default 200)

    Returns:
        Plaintext disassembly (newline separated)
    """
    return make_jsonrpc_request(database, "disassemble", {
        "selector": selector,
        "max_instructions": max_instructions,
    })


@mcp.tool()
def list_functions(
    database: str,
    filter: str = "",
    offset: int = 0,
    limit: int = 100,
) -> Dict[str, Any]:
    """List all functions with basic info.

    Args:
        database: Database filename of the IDA instance
        filter: Optional regex to filter by name
        offset: Start index for pagination
        limit: Number of functions to return

    Returns:
        functions[], total, offset, limit, has_more
    """
    return make_jsonrpc_request(database, "list_functions", {
        "filter": filter,
        "offset": offset,
        "limit": limit,
    })


@mcp.tool()
def get_xrefs(
    database: str,
    target: str,
    direction: str = "to",
    limit: int = 100,
) -> Dict[str, Any]:
    """Get cross-references to/from an address or function.

    Args:
        database: Database filename of the IDA instance
        target: Address or function name
        direction: "to" (callers), "from" (callees), or "both"
        limit: Maximum xrefs to return

    Returns:
        xrefs[] (includes source disassembly line), count, limit, has_more
    """
    return make_jsonrpc_request(database, "get_xrefs", {
        "target": target,
        "direction": direction,
        "limit": limit,
    })


@mcp.tool()
def search_strings(
    database: str,
    pattern: str = "",
    min_length: int = 4,
    offset: int = 0,
    limit: int = 100,
) -> Dict[str, Any]:
    """Find strings in the binary.

    Args:
        database: Database filename of the IDA instance
        pattern: Optional regex to filter strings
        min_length: Minimum string length (default 4)
        offset: Start index for pagination
        limit: Maximum strings to return

    Returns:
        strings[], total, offset, limit, has_more
    """
    return make_jsonrpc_request(database, "search_strings", {
        "pattern": pattern,
        "min_length": min_length,
        "offset": offset,
        "limit": limit,
    })


@mcp.tool()
def read_bytes(
    database: str,
    address: str,
    size: int = 64,
) -> Dict[str, Any]:
    """Read raw bytes at an address.

    Args:
        database: Database filename of the IDA instance
        address: Hex address to read from
        size: Number of bytes to read (default 64)

    Returns:
        hex, ascii, dump[]
    """
    return make_jsonrpc_request(database, "read_bytes", {
        "address": address,
        "size": size,
    })


@mcp.tool()
def search(
    database: str,
    query: str,
    search_type: str = "auto",
    start_address: str = "",
    limit: int = 100,
) -> Dict[str, Any]:
    """Search for bytes, immediates, or text patterns in the binary.

    Args:
        database: Database filename of the IDA instance
        query: What to search for:
            - Hex bytes: "48 89 E5" or "488BE5" (spaces optional)
            - Immediate value: "0x1000" or "4096"
            - Text/regex: "encrypt" or "call.*malloc"
        search_type: "bytes", "immediate", "text", or "auto" (default, auto-detects)
        start_address: Address to start searching from (default: start of binary)
        limit: Maximum results to return (default 100)

    Returns:
        results[], search_type, count, limit, has_more
    """
    return make_jsonrpc_request(database, "search", {
        "query": query,
        "search_type": search_type,
        "start_address": start_address,
        "limit": limit,
    })


@mcp.tool()
def rename(
    database: str,
    target: str,
    new_name: str,
) -> Dict[str, Any]:
    """Rename a function, global, or struct field.

    Args:
        database: Database filename of the IDA instance
        target: Address ("0xADDRESS"), function name, or "StructName.field"
        new_name: New name to assign

    Returns:
        old_name, new_name, type
    """
    return make_jsonrpc_request(database, "rename", {
        "target": target,
        "new_name": new_name,
    })


@mcp.tool()
def set_type(
    database: str,
    target: str,
    type_str: str,
) -> Dict[str, Any]:
    """Set the type of a function, variable, or global.

    Args:
        database: Database filename of the IDA instance
        target: Address or name
        type_str: C type declaration (e.g., "int (*handler)(void *ctx, char *data)")

    Returns:
        success, applied_type
    """
    return make_jsonrpc_request(database, "set_type", {
        "target": target,
        "type_str": type_str,
    })


@mcp.tool()
def create_struct(
    database: str,
    name: str,
    definition: str,
) -> Dict[str, Any]:
    """Create a new struct type from C definition.

    Args:
        database: Database filename of the IDA instance
        name: Struct name
        definition: C-style struct definition (e.g., "struct Foo { int x; char buf[64]; }")

    Returns:
        name, size, members[]
    """
    return make_jsonrpc_request(database, "create_struct", {
        "name": name,
        "definition": definition,
    })


@mcp.tool()
def set_comment(
    database: str,
    address: str,
    comment: str,
    comment_type: str = "line",
) -> Dict[str, Any]:
    """Add a comment at an address.

    Args:
        database: Database filename of the IDA instance
        address: Hex address
        comment: Comment text
        comment_type: "line" (default), "function", or "repeatable"

    Returns:
        success
    """
    return make_jsonrpc_request(database, "set_comment", {
        "address": address,
        "comment": comment,
        "comment_type": comment_type,
    })


@mcp.tool()
def info(
    database: str,
) -> Dict[str, Any]:
    """Get current database info and cursor position.

    Args:
        database: Database filename of the IDA instance

    Returns:
        database, cursor_address, cursor_function, arch, total_functions
    """
    return make_jsonrpc_request(database, "info", {})


@mcp.tool()
def get_callgraph(
    database: str,
    target: str,
    max_depth: int = 3,
    direction: str = "both",
) -> Dict[str, Any]:
    """Get call graph for a function.

    Args:
        database: Database filename of the IDA instance
        target: Function name or address
        max_depth: Maximum depth to traverse (default 3)
        direction: "callers" (who calls this), "callees" (what this calls), or "both"

    Returns:
        root function info with nested callers/callees tree
    """
    return make_jsonrpc_request(database, "get_callgraph", {
        "target": target,
        "max_depth": max_depth,
        "direction": direction,
    })


@mcp.tool()
def get_segments(
    database: str,
) -> Dict[str, Any]:
    """Get memory segments/sections of the binary.

    Args:
        database: Database filename of the IDA instance

    Returns:
        segments[] with name, start, end, size, permissions, class
    """
    return make_jsonrpc_request(database, "get_segments", {})


@mcp.tool()
def script_exec(
    database: str,
    script: str,
) -> Dict[str, Any]:
    """Execute arbitrary Python code in IDA.

    Args:
        database: Database filename of the IDA instance
        script: Python code to execute

    Returns:
        success, stdout, stderr, error
    """
    return make_jsonrpc_request(database, "script_exec", {
        "script": script,
    })


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
    """Install or uninstall the IDA plugin."""
    if sys.platform == "win32":
        ida_folder = os.path.join(os.getenv("APPDATA"), "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")

    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    plugin_destination = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        if os.path.exists(plugin_destination):
            os.remove(plugin_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin: {plugin_destination}")
        return

    os.makedirs(ida_plugin_folder, exist_ok=True)

    # Create symlink or copy
    if os.path.lexists(plugin_destination):
        os.remove(plugin_destination)

    try:
        os.symlink(IDA_PLUGIN_PY, plugin_destination)
    except OSError:
        shutil.copy(IDA_PLUGIN_PY, plugin_destination)

    if not quiet:
        print(f"Installed IDA plugin: {plugin_destination}")


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
