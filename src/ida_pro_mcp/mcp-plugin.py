# IDA Pro MCP Plugin - Simplified 12-tool design for LLM reverse engineering
# Requires: Python >= 3.11, IDA Professional >= 9.2

import os
import sys
import json
import time
import re
import threading
import uuid
import traceback
import http.server
import socketserver
from urllib.parse import urlparse
from typing import Any, Optional, Callable, Dict, List
from contextlib import contextmanager

if sys.version_info < (3, 11):
    raise RuntimeError("Python 3.11+ required")

# --- IDA imports ---
try:
    import idaapi
    import idautils
    import ida_bytes
    import ida_funcs
    import ida_lines
    import ida_name
    import ida_nalt
    import ida_xref
    import ida_typeinf
    import ida_ua
    import ida_ida
    import ida_strlist
    import idc
    from ida_pro import IDA_SDK_VERSION
except ImportError as e:
    print(f"[mcp-plugin] IDA imports failed: {e}")
    raise

# Hex-Rays decompiler (optional but recommended)
try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

# IDA 9.2 new type parser
try:
    import ida_srclang
    SRCLANG_AVAILABLE = True
except Exception:
    SRCLANG_AVAILABLE = False


# ============================================================================
# JSON-RPC Infrastructure
# ============================================================================

class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class IDAError(JSONRPCError):
    def __init__(self, message: str, data: Any = None):
        super().__init__(-32000, message, data)


class RPCRegistry:
    def __init__(self):
        self.methods: Dict[str, Callable] = {}
        self.meta: Dict[str, Dict[str, Any]] = {}

    def register(self, name: str, func: Callable, *, doc: str = ""):
        self.methods[name] = func
        self.meta[name] = {"doc": doc or (func.__doc__ or "").strip()}

    def dispatch(self, method: str, params: Any) -> Any:
        if method not in self.methods:
            raise JSONRPCError(-32601, f"Method '{method}' not found")

        func = self.methods[method]
        import inspect
        sig = inspect.signature(func)

        if isinstance(params, dict):
            # Filter to known parameters and bind
            filtered = {k: v for k, v in params.items() if k in sig.parameters}
            try:
                bound = sig.bind_partial(**filtered)
            except TypeError as e:
                raise JSONRPCError(-32602, f"Invalid params: {e}")
            # Apply defaults
            for pname, p in sig.parameters.items():
                if pname not in bound.arguments and p.default is not inspect._empty:
                    bound.arguments[pname] = p.default
            return func(*bound.args, **bound.kwargs)
        elif isinstance(params, list):
            return func(*params)
        else:
            return func()


rpc = RPCRegistry()


# ----------------------------------------------------------------------------
# Async job runner (used when front-end times out but IDA is still healthy)
# ----------------------------------------------------------------------------

_jobs_lock = threading.Lock()
_jobs: Dict[str, Dict[str, Any]] = {}
_JOB_LIMIT = 200
_JOB_TTL = 300  # seconds


def _prune_jobs():
    now = time.time()
    with _jobs_lock:
        # Drop expired jobs (older than TTL) regardless of state
        expired = [jid for jid, j in _jobs.items() if now - j.get("created", now) > _JOB_TTL]
        for jid in expired:
            _jobs.pop(jid, None)

        if len(_jobs) <= _JOB_LIMIT:
            return

        # Drop oldest finished jobs to enforce limit
        finished = sorted(
            ((j.get("finished", j.get("created", 0)), jid) for jid, j in _jobs.items() if j.get("state") in {"done", "error"}),
            key=lambda x: x[0],
        )
        excess = max(0, len(_jobs) - _JOB_LIMIT)
        for _, jid in finished[:excess]:
            _jobs.pop(jid, None)


def _run_job(job_id: str, method: str, params: Any):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job["state"] = "running"
        job["started"] = time.time()

    try:
        result = rpc.dispatch(method, params)
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job["state"] = "done"
                job["result"] = result
                job["finished"] = time.time()
    except Exception as exc:
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job["state"] = "error"
                job["error"] = str(exc)
                job["finished"] = time.time()


def start_job(method: str, params: Any) -> Dict[str, Any]:
    """Start an asynchronous job; returns a job_id immediately."""

    if method in {"start_job", "job_status", "job_result"}:
        raise JSONRPCError(-32601, "Method not allowed for job runner")
    if method not in rpc.methods:
        raise JSONRPCError(-32601, f"Method '{method}' not found")

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            "state": "pending",
            "method": method,
            "params": params,
            "created": time.time(),
        }
    _prune_jobs()

    t = threading.Thread(target=_run_job, args=(job_id, method, params), daemon=True)
    t.start()

    return {"job_id": job_id, "state": "pending"}


def job_status(job_id: str) -> Dict[str, Any]:
    _prune_jobs()
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise JSONRPCError(-32001, f"Job '{job_id}' not found")
        if time.time() - job.get("created", time.time()) > _JOB_TTL and job.get("state") in {"done", "error"}:
            _jobs.pop(job_id, None)
            raise JSONRPCError(-32001, f"Job '{job_id}' expired")
        return dict(job)


def job_result(job_id: str, *, pop: bool = True) -> Dict[str, Any]:
    _prune_jobs()
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise JSONRPCError(-32001, f"Job '{job_id}' not found")
        state = job.get("state")
        if state in {"pending", "running"}:
            return {"state": state}
        payload = {
            "state": state,
            "result": job.get("result"),
            "error": job.get("error"),
        }
        if pop:
            _jobs.pop(job_id, None)
        return payload


rpc.register("start_job", start_job, doc="Start an asynchronous job; returns job_id")
rpc.register("job_status", job_status, doc="Check status of an async job")
rpc.register("job_result", job_result, doc="Get result of an async job (optionally pop)")


class JSONRPCRequestHandler(http.server.BaseHTTPRequestHandler):
    def send_json(self, payload: Dict[str, Any], status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlparse(self.path).path != "/mcp":
            return self.send_json({"jsonrpc": "2.0", "error": {"code": -32098, "message": "Invalid endpoint"}})

        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
            req = json.loads(raw)
        except Exception:
            return self.send_json({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}})

        resp = {"jsonrpc": "2.0", "id": req.get("id")}
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

    def log_message(self, *_):
        pass


class UnixJSONRPCServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        super().__init__(socket_path, JSONRPCRequestHandler)

    def server_bind(self):
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        super().server_bind()

    def server_close(self):
        super().server_close()
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def get_request(self):
        request, _ = super().get_request()
        return request, ("local", 0)


# ============================================================================
# Utilities
# ============================================================================

def _hex(ea: int) -> str:
    """Format address as hex string."""
    return f"0x{ea:X}"


AUTO_NAME_SUFFIX_RE = re.compile(r"^(?:loc|off|word|byte|dword|qword|unk|asc|stru|dbl|flt|sub)_(?:0x)?([0-9A-Fa-f]+)$")


def _disasm_line(ea: int) -> str:
    """Return one disassembly line without color tags for an address."""
    try:
        text = idc.generate_disasm_line(ea, 0) or ""
    except Exception:
        return ""
    try:
        return ida_lines.tag_remove(text)
    except Exception:
        return text


def parse_ea(text: str) -> int:
    """Parse hex or decimal address string."""
    if text.lower() == "current":
        return idaapi.get_screen_ea()
    try:
        return int(text, 0)
    except Exception:
        # Accept common IDA auto-generated names like word_800A80A2
        match = AUTO_NAME_SUFFIX_RE.match(text)
        if match:
            try:
                return int(match.group(1), 16)
            except ValueError:
                pass
        raise IDAError(f"Invalid address: {text}")


def resolve_function(selector: str) -> ida_funcs.func_t:
    """Resolve function by name or address."""
    # Try as address first
    try:
        ea = parse_ea(selector)
        fn = idaapi.get_func(ea)
        if fn:
            return fn
    except IDAError:
        pass

    # Try as name
    ea = idaapi.get_name_ea(idaapi.BADADDR, selector)
    if ea != idaapi.BADADDR:
        fn = idaapi.get_func(ea)
        if fn:
            return fn

    # Search all functions by name
    for fea in idautils.Functions():
        name = ida_funcs.get_func_name(fea)
        if name == selector:
            fn = idaapi.get_func(fea)
            if fn:
                return fn

    raise IDAError(f"Cannot find function '{selector}'. Use list_functions to see available functions.")


# Thread-safe wrappers
def idaread(f):
    """Decorator for read-only IDA operations (thread-safe)."""
    import functools
    @functools.wraps(f)
    def wrap(*a, **k):
        out = []
        def inner():
            try:
                out.append(f(*a, **k))
            except Exception as e:
                out.append(e)
        idaapi.execute_sync(inner, idaapi.MFF_READ)
        if isinstance(out[0], Exception):
            raise out[0]
        return out[0]
    return wrap


def idawrite(f):
    """Decorator for write IDA operations (thread-safe)."""
    import functools
    @functools.wraps(f)
    def wrap(*a, **k):
        out = []
        def inner():
            try:
                out.append(f(*a, **k))
            except Exception as e:
                out.append(e)
        idaapi.execute_sync(inner, idaapi.MFF_WRITE)
        if isinstance(out[0], Exception):
            raise out[0]
        return out[0]
    return wrap


@contextmanager
def batch_mode():
    """Context manager to suppress IDA dialogs."""
    old = idc.batch(1)
    try:
        yield
    finally:
        idc.batch(old)


# ============================================================================
# Tool Implementations
# ============================================================================

# --- 1. decompile ---

@idaread
def decompile(
    selector: str,
    start_line: int = 0,
    end_line: int = 0,
    max_lines: int = 0,
) -> Dict[str, Any]:
    """Get Hex-Rays pseudocode for a function.

    Parameters:
        selector: Function name or "0xADDRESS"
        start_line: Start at this line (1-indexed, 0 = from beginning)
        end_line: End at this line (inclusive, 0 = to end)
        max_lines: Maximum lines to return (0 = no limit, overrides end_line)

    Returns:
        name, address, prototype, pseudocode, variables, line_info (if filtered)

    Examples:
        - Get first 20 lines: max_lines=20
        - Get lines 10-30: start_line=10, end_line=30
        - Get 15 lines starting from line 25: start_line=25, max_lines=15
    """
    # Check dynamically - Hex-Rays may not be ready at plugin load time
    if not ida_hexrays or not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler not available. Use disassemble instead.")

    fn = resolve_function(selector)
    cfunc = ida_hexrays.decompile(fn.start_ea)
    if not cfunc:
        raise IDAError(f"Decompilation failed for {selector}")

    # Get local variables
    vars = []
    for lvar in cfunc.get_lvars():
        v = {"name": lvar.name, "type": str(lvar.type())}
        if lvar.is_stk_var():
            v["loc"] = "stack"
        elif lvar.is_reg_var():
            v["loc"] = "reg"
        elif lvar.is_arg_var:
            v["loc"] = "arg"
        vars.append(v)

    # Get full pseudocode
    full_code = str(cfunc)
    all_lines = full_code.split('\n')
    total = len(all_lines)

    # Apply line filtering if requested
    result = {
        "name": ida_funcs.get_func_name(fn.start_ea),
        "addr": _hex(fn.start_ea),
        "proto": str(cfunc.type),
        "vars": vars,
    }

    if start_line > 0 or end_line > 0 or max_lines > 0:
        start_idx = max(0, start_line - 1) if start_line > 0 else 0
        if max_lines > 0:
            end_idx = start_idx + max_lines
        elif end_line > 0:
            end_idx = end_line
        else:
            end_idx = total
        filtered = all_lines[start_idx:end_idx]
        result["code"] = '\n'.join(filtered)
        result["lines"] = {"total": total, "start": start_idx + 1, "end": min(end_idx, total), "more": end_idx < total}
    else:
        result["code"] = full_code

    return result

rpc.register("decompile", decompile, doc="Get Hex-Rays pseudocode for a function.")


# --- 2. disassemble ---

@idaread
def disassemble(selector: str, max_instructions: int = 200) -> str:
    """Get assembly for a function or address range as plain text.

    Parameters:
        selector: Function name, "0xADDRESS", or "0xSTART-0xEND"
        max_instructions: Maximum instructions to return (default 200)

    Returns:
        Newline-joined disassembly lines. First line uses absolute address;
        subsequent lines are relative offsets (e.g., "+0x4:") to reduce noise.
    """
    # Check for range syntax
    if "-" in selector and selector.count("-") == 1:
        parts = selector.split("-")
        try:
            start_ea = parse_ea(parts[0])
            end_ea = parse_ea(parts[1])
        except:
            raise IDAError(f"Invalid range: {selector}. Use format '0xSTART-0xEND'")
    else:
        fn = resolve_function(selector)
        start_ea = fn.start_ea
        end_ea = fn.end_ea

    lines: List[str] = []
    ea = start_ea
    count = 0

    base = start_ea

    while ea < end_ea and count < max_instructions:
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            ea += 1
            continue

        # Get disassembly text
        disasm = idc.generate_disasm_line(ea, 0)
        if ea == base:
            prefix = _hex(ea)
        else:
            prefix = f"+0x{ea - base:X}"

        line = f"{prefix}: {disasm}" if disasm else prefix
        lines.append(line)

        ea += length
        count += 1

    return "\n".join(lines)

rpc.register("disassemble", disassemble, doc="Get assembly instructions for a function or address range.")


# --- 3. list_functions ---

@idaread
def list_functions(filter: str = "", offset: int = 0, limit: int = 100) -> Dict[str, Any]:
    """List all functions with basic info.

    Parameters:
        filter: Optional regex to filter by name
        offset: Start index for pagination (default 0)
        limit: Maximum functions to return (default 100)

    Returns:
        functions: [{address, name, size}], total, offset, limit, has_more
    """
    pattern = re.compile(filter, re.IGNORECASE) if filter else None

    all_functions = []
    for ea in idautils.Functions():
        fn = idaapi.get_func(ea)
        if not fn:
            continue
        name = ida_funcs.get_func_name(ea)

        # Apply filter
        if pattern and not pattern.search(name):
            continue

        all_functions.append({
            "addr": _hex(ea),
            "name": name,
            "size": fn.end_ea - fn.start_ea,
        })

    total = len(all_functions)
    end_idx = offset + limit

    return {
        "funcs": all_functions[offset:end_idx],
        "total": total,
        "more": end_idx < total,
    }

rpc.register("list_functions", list_functions, doc="List all functions with basic info. Use filter for regex matching.")


# --- 4. get_xrefs ---

@idaread
def get_xrefs(target: str, direction: str = "to", limit: int = 100) -> Dict[str, Any]:
    """Get cross-references to/from an address or symbol.

    Parameters:
        target: Address or function name
        direction: "to" (who references this), "from" (what this references), or "both"
        limit: Maximum xrefs to return (default 100)

    Returns:
        xrefs: [{from_addr, to_addr, type, from_func/to_func, line}], count, has_more
    """
    # Resolve target
    try:
        ea = parse_ea(target)
    except IDAError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, target)
        if ea == idaapi.BADADDR:
            # Preserve existing error path for function-only lookups
            fn = resolve_function(target)
            ea = fn.start_ea

    xrefs = []
    truncated = False

    # Xrefs TO this address (callers/references)
    if direction in ("to", "both") and len(xrefs) < limit:
        xb = ida_xref.xrefblk_t()
        if xb.first_to(ea, ida_xref.XREF_ALL):
            while True:
                if len(xrefs) >= limit:
                    truncated = True
                    break
                from_func = ida_funcs.get_func(xb.frm)
                xrefs.append({
                    "from": _hex(xb.frm),
                    "to": _hex(ea),
                    "dir": "to",
                    "func": ida_funcs.get_func_name(xb.frm) if from_func else None,
                    "line": _disasm_line(xb.frm),
                })
                if not xb.next_to():
                    break

    # Xrefs FROM this address (callees/referenced)
    if direction in ("from", "both") and len(xrefs) < limit:
        # If target is a function, iterate through all its addresses
        fn = idaapi.get_func(ea)
        if fn:
            addr = fn.start_ea
            while addr < fn.end_ea and len(xrefs) < limit:
                xb = ida_xref.xrefblk_t()
                if xb.first_from(addr, ida_xref.XREF_ALL):
                    while True:
                        if len(xrefs) >= limit:
                            truncated = True
                            break
                        to_func = ida_funcs.get_func(xb.to)
                        xrefs.append({
                            "from": _hex(addr),
                            "to": _hex(xb.to),
                            "dir": "from",
                            "func": ida_funcs.get_func_name(xb.to) if to_func else None,
                            "line": _disasm_line(addr),
                        })
                        if not xb.next_from():
                            break
                addr = idc.next_head(addr, fn.end_ea)
        else:
            # Single address
            xb = ida_xref.xrefblk_t()
            if xb.first_from(ea, ida_xref.XREF_ALL):
                while True:
                    if len(xrefs) >= limit:
                        truncated = True
                        break
                    to_func = ida_funcs.get_func(xb.to)
                    xrefs.append({
                        "from": _hex(ea),
                        "to": _hex(xb.to),
                        "dir": "from",
                        "func": ida_funcs.get_func_name(xb.to) if to_func else None,
                        "line": _disasm_line(ea),
                    })
                    if not xb.next_from():
                        break

    return {
        "xrefs": xrefs,
        "count": len(xrefs),
        "more": truncated,
    }

rpc.register("get_xrefs", get_xrefs, doc="Get cross-references to/from an address.")


# --- 5. search_strings ---

@idaread
def search_strings(pattern: str = "", min_length: int = 4, offset: int = 0, limit: int = 100) -> Dict[str, Any]:
    """Find strings in the binary.

    Parameters:
        pattern: Optional regex to filter strings
        min_length: Minimum string length (default 4)
        offset: Start index for pagination (default 0)
        limit: Maximum strings to return (default 100)

    Returns:
        strings: [{address, value, length, xref_count}], total, offset, limit, has_more
    """
    ida_strlist.build_strlist()

    regex = re.compile(pattern, re.IGNORECASE) if pattern else None

    all_strings = []
    total_count = ida_strlist.get_strlist_qty()

    for i in range(total_count):
        si = ida_strlist.string_info_t()
        if not ida_strlist.get_strlist_item(si, i):
            continue

        if si.length < min_length:
            continue

        # Get string content
        s = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
        if not s:
            continue

        try:
            s_str = s.decode('utf-8', errors='replace')
        except:
            s_str = str(s)

        # Apply filter
        if regex and not regex.search(s_str):
            continue

        # Count xrefs
        xref_count = 0
        xb = ida_xref.xrefblk_t()
        if xb.first_to(si.ea, ida_xref.XREF_ALL):
            while True:
                xref_count += 1
                if not xb.next_to():
                    break

        all_strings.append({
            "addr": _hex(si.ea),
            "val": s_str,
            "len": si.length,
            "xrefs": xref_count,
        })

    total = len(all_strings)
    end_idx = offset + limit

    return {
        "strings": all_strings[offset:end_idx],
        "total": total,
        "more": end_idx < total,
    }

rpc.register("search_strings", search_strings, doc="Find strings in the binary.")


# --- 6. read_bytes ---

@idaread
def read_bytes(address: str, size: int = 64) -> Dict[str, Any]:
    """Read raw bytes at an address.

    Parameters:
        address: Hex address to read from
        size: Number of bytes to read (default 64)

    Returns:
        hex: Hex string of bytes, ascii: Printable representation
    """
    ea = parse_ea(address)
    data = ida_bytes.get_bytes(ea, size)

    if not data:
        raise IDAError(f"Cannot read {size} bytes at {address}")

    hex_str = data.hex()
    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)

    # Also format as hex dump
    hex_dump = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        hex_dump.append(f"{_hex(ea+i)}: {hex_part:48s} {ascii_part}")

    return {
        "addr": _hex(ea),
        "size": len(data),
        "hex": hex_str,
        "ascii": ascii_str,
        "dump": hex_dump,
    }

rpc.register("read_bytes", read_bytes, doc="Read raw bytes at an address. Useful for understanding data structures.")


# --- 7. search ---

@idaread
def search(
    query: str,
    search_type: str = "auto",
    start_address: str = "",
    limit: int = 100,
) -> Dict[str, Any]:
    """Search for bytes, immediates, or text in the binary.

    Parameters:
        query: What to search for:
            - Hex bytes: "48 89 E5" or "488BE5" (spaces optional)
            - Immediate value: "0x1000" or "4096"
            - Text/regex: "encrypt" or "call.*malloc"
        search_type: "bytes", "immediate", "text", or "auto" (default, guesses from query)
        start_address: Address to start searching from (default: start of binary)
        limit: Maximum results to return (default 100)

    Returns:
        results: [{address, context, function?}], search_type, count, limit, has_more
    """
    import ida_search

    # Determine search range
    if start_address:
        min_ea = parse_ea(start_address)
    else:
        min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()

    # Auto-detect search type
    if search_type == "auto":
        query_stripped = query.replace(" ", "")
        # Check if it looks like hex bytes (all hex chars, even length)
        if all(c in "0123456789abcdefABCDEF" for c in query_stripped) and len(query_stripped) >= 4 and len(query_stripped) % 2 == 0:
            search_type = "bytes"
        # Check if it looks like an immediate value
        elif query.startswith("0x") or query.isdigit():
            search_type = "immediate"
        else:
            search_type = "text"

    results = []
    has_more = False

    if search_type == "bytes":
        # Normalize hex pattern (ensure spaces between bytes for IDA)
        hex_clean = query.replace(" ", "")
        pattern = " ".join(hex_clean[i:i+2] for i in range(0, len(hex_clean), 2))

        compiled = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(compiled, min_ea, pattern, 16)
        if err:
            raise IDAError(f"Invalid byte pattern: {err}")

        ea = min_ea
        while len(results) < limit:
            result = ida_bytes.bin_search(ea, max_ea, compiled, ida_bytes.BIN_SEARCH_FORWARD)
            if isinstance(result, tuple):
                ea = result[0]
            else:
                ea = result

            if ea == idc.BADADDR:
                break

            fn = idaapi.get_func(ea)
            results.append({
                "addr": _hex(ea),
                "ctx": idc.generate_disasm_line(ea, 0),
                "func": ida_funcs.get_func_name(ea) if fn else None,
            })
            ea += 1
        else:
            result = ida_bytes.bin_search(ea, max_ea, compiled, ida_bytes.BIN_SEARCH_FORWARD)
            check_ea = result[0] if isinstance(result, tuple) else result
            has_more = check_ea != idc.BADADDR

    elif search_type == "immediate":
        try:
            imm_value = int(query, 0)
        except ValueError:
            raise IDAError(f"Invalid immediate value: {query}")

        ea = min_ea
        while len(results) < limit:
            ea, _ = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, imm_value)
            if ea == idc.BADADDR:
                break
            fn = idaapi.get_func(ea)
            results.append({
                "addr": _hex(ea),
                "ctx": idc.generate_disasm_line(ea, 0),
                "func": ida_funcs.get_func_name(ea) if fn else None,
            })
            ea = idc.next_head(ea, max_ea)
        else:
            check_ea, _ = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, imm_value)
            has_more = check_ea != idc.BADADDR

    elif search_type == "text":
        ea = min_ea
        while len(results) < limit:
            ea = ida_search.find_text(ea, 0, 0, query, ida_search.SEARCH_DOWN | ida_search.SEARCH_REGEX)
            if ea == idc.BADADDR:
                break
            fn = idaapi.get_func(ea)
            results.append({
                "addr": _hex(ea),
                "ctx": idc.generate_disasm_line(ea, 0),
                "func": ida_funcs.get_func_name(ea) if fn else None,
            })
            ea = idc.next_head(ea, max_ea)
        else:
            check_ea = ida_search.find_text(ea, 0, 0, query, ida_search.SEARCH_DOWN | ida_search.SEARCH_REGEX)
            has_more = check_ea != idc.BADADDR

    else:
        raise IDAError(f"Unknown search type: {search_type}. Use 'bytes', 'immediate', 'text', or 'auto'.")

    return {
        "type": search_type,
        "results": results,
        "count": len(results),
        "more": has_more,
    }

rpc.register("search", search, doc="Search for bytes, immediates, or text patterns in the binary.")


# --- 8. rename ---

@idawrite
def rename(target: str, new_name: str) -> Dict[str, Any]:
    """Rename a function, global, or struct field.

    Parameters:
        target: Address ("0xADDRESS"), function name, or "StructName.field"
        new_name: New name to assign

    Returns:
        old_name, new_name, type
    """
    with batch_mode():
        # Check for struct field rename (StructName.field)
        if "." in target and not target.startswith("0x"):
            parts = target.split(".", 1)
            struct_name = parts[0]
            field_name = parts[1]

            til = ida_typeinf.get_idati()
            tif = ida_typeinf.tinfo_t()

            if not tif.get_named_type(til, struct_name):
                raise IDAError(f"Struct '{struct_name}' not found")

            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                raise IDAError(f"Cannot get details for struct '{struct_name}'")

            # Find and rename the field
            found = False
            for member in udt:
                if member.name == field_name:
                    member.name = new_name
                    found = True
                    break

            if not found:
                raise IDAError(f"Field '{field_name}' not found in struct '{struct_name}'")

            # Rebuild and save
            tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
            result = tif.set_named_type(til, struct_name, ida_typeinf.NTF_REPLACE)

            if result != 0:
                raise IDAError(f"Failed to rename field (error code {result})")

            return {
                "old": f"{struct_name}.{field_name}",
                "new": f"{struct_name}.{new_name}",
                "kind": "field",
            }

        # Function or global rename
        try:
            ea = parse_ea(target)
        except IDAError:
            # Try to resolve as function name
            ea = idaapi.get_name_ea(idaapi.BADADDR, target)
            if ea == idaapi.BADADDR:
                fn = resolve_function(target)
                ea = fn.start_ea

        old_name = ida_name.get_name(ea) or f"sub_{ea:X}"

        fn = idaapi.get_func(ea)
        kind = "func" if fn else "global"

        result = ida_name.set_name(ea, new_name, ida_name.SN_CHECK)
        if not result:
            raise IDAError(f"Cannot rename '{old_name}' to '{new_name}'. Name may be invalid or already in use.")

        if fn and ida_hexrays and ida_hexrays.init_hexrays_plugin():
            ida_hexrays.mark_cfunc_dirty(fn.start_ea)

        return {"old": old_name, "new": new_name, "kind": kind, "addr": _hex(ea)}

rpc.register("rename", rename, doc="Rename a function, global, or struct field.")


# --- 8. set_type ---

@idawrite
def set_type(target: str, type_str: str) -> Dict[str, Any]:
    """Set the type of a function, variable, or global.

    Parameters:
        target: Address or name
        type_str: C type declaration (e.g., "int (*handler)(void *ctx, char *data)")

    Returns:
        success, applied_type
    """
    with batch_mode():
        # Resolve target address
        try:
            ea = parse_ea(target)
        except IDAError:
            ea = idaapi.get_name_ea(idaapi.BADADDR, target)
            if ea == idaapi.BADADDR:
                fn = resolve_function(target)
                ea = fn.start_ea

        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()

        # Ensure type string ends with semicolon
        decl = type_str.strip()
        if not decl.endswith(";"):
            decl += ";"

        # Parse the type declaration
        result = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
        if result is None:
            raise IDAError(f"Cannot parse type: '{type_str}'. Ensure valid C syntax with semicolon.")

        # Apply the type
        apply_result = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
        if not apply_result:
            raise IDAError(f"Cannot apply type to {_hex(ea)}. Type may be incompatible.")

        fn = idaapi.get_func(ea)
        if fn and ida_hexrays and ida_hexrays.init_hexrays_plugin():
            ida_hexrays.mark_cfunc_dirty(fn.start_ea)

        return {"ok": True, "addr": _hex(ea), "type": str(tif)}

rpc.register("set_type", set_type, doc="Set the type of a function, variable, or global.")


# --- 9. create_struct ---

@idawrite
def create_struct(name: str, definition: str) -> Dict[str, Any]:
    """Create a new struct type from C definition.

    Parameters:
        name: Struct name
        definition: C-style struct definition
            Example: "struct ConnectionState { int socket; char buffer[1024]; int state; }"

    Returns:
        name, size, members
    """
    with batch_mode():
        # Parse the struct definition
        result = ida_typeinf.idc_parse_types(definition, 0)
        if result != 0:
            raise IDAError(f"Cannot parse struct definition. Error code: {result}")

        # Verify it was created
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()

        if not tif.get_named_type(til, name):
            raise IDAError(f"Struct '{name}' was not created. Check the definition syntax.")

        # Get struct details
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            raise IDAError(f"Cannot get details for struct '{name}'")

        members = []
        for m in udt:
            members.append({
                "name": m.name,
                "type": str(m.type),
                "off": m.offset // 8,
                "size": m.size // 8 if m.size >= 8 else 1,
            })

        return {"name": name, "size": tif.get_size(), "members": members}

rpc.register("create_struct", create_struct, doc="Create a new struct type from C definition.")


# --- 10. set_comment ---

@idawrite
def set_comment(address: str, comment: str, comment_type: str = "line") -> Dict[str, Any]:
    """Add a comment at an address.

    Parameters:
        address: Hex address
        comment: Comment text
        comment_type: "line" (default), "function", or "repeatable"

    Returns:
        success
    """
    ea = parse_ea(address)

    with batch_mode():
        if comment_type == "function":
            fn = idaapi.get_func(ea)
            if not fn:
                raise IDAError(f"No function at {address}")
            ida_funcs.set_func_cmt(fn, comment, 0)
        elif comment_type == "repeatable":
            idc.set_cmt(ea, comment, 1)
        else:  # line
            idc.set_cmt(ea, comment, 0)

        return {"ok": True, "addr": _hex(ea), "type": comment_type}

rpc.register("set_comment", set_comment, doc="Add a comment at an address.")


# --- 11. info ---

@idaread
def info() -> Dict[str, Any]:
    """Get current database info and cursor position.

    Returns:
        database, cursor_address, cursor_function, arch, total_functions
    """
    cursor_ea = idaapi.get_screen_ea()
    cursor_fn = idaapi.get_func(cursor_ea)
    bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)

    return {
        "db": idaapi.get_root_filename(),
        "cursor": _hex(cursor_ea),
        "cursor_func": ida_funcs.get_func_name(cursor_ea) if cursor_fn else None,
        "arch": ida_ida.inf_get_procname(),
        "bits": bits,
        "funcs": ida_funcs.get_func_qty(),
        "hexrays": bool(ida_hexrays and ida_hexrays.init_hexrays_plugin()),
    }

rpc.register("info", info, doc="Get database info and cursor position.")


# --- System/discovery tools ---

def system_info() -> Dict[str, Any]:
    """Get IDA instance info (for MCP server connection)."""
    return info()

rpc.register("system.info", system_info, doc="Get IDA instance info.")


def discover() -> Dict[str, Any]:
    """List available tools."""
    # Hide internal job helpers from discover
    hidden = {"start_job", "job_status", "job_result"}
    return {"tools": {k: v for k, v in rpc.meta.items() if k not in hidden}}

rpc.register("discover", discover, doc="List available tools and their descriptions.")


# --- get_callgraph ---

@idaread
def get_callgraph(target: str, max_depth: int = 3, direction: str = "both") -> Dict[str, Any]:
    """Get call graph for a function.

    Parameters:
        target: Function name or address
        max_depth: Maximum depth to traverse (default 3)
        direction: "callers" (who calls this), "callees" (what this calls), or "both"

    Returns:
        root function info and nested callers/callees tree
    """
    fn = resolve_function(target)
    root_ea = fn.start_ea
    root_name = ida_funcs.get_func_name(root_ea)

    visited_callers = set()
    visited_callees = set()

    def get_callers(ea: int, depth: int) -> List[Dict[str, Any]]:
        if depth <= 0 or ea in visited_callers:
            return []
        visited_callers.add(ea)
        callers = []
        xb = ida_xref.xrefblk_t()
        if xb.first_to(ea, ida_xref.XREF_ALL):
            while True:
                caller_fn = ida_funcs.get_func(xb.frm)
                if caller_fn and caller_fn.start_ea != ea:
                    caller_ea = caller_fn.start_ea
                    if caller_ea not in [c.get("addr") for c in callers]:
                        c = {"addr": _hex(caller_ea), "name": ida_funcs.get_func_name(caller_ea), "site": _hex(xb.frm)}
                        if depth > 1:
                            c["callers"] = get_callers(caller_ea, depth - 1)
                        callers.append(c)
                if not xb.next_to():
                    break
        return callers

    def get_callees(ea: int, depth: int) -> List[Dict[str, Any]]:
        if depth <= 0 or ea in visited_callees:
            return []
        visited_callees.add(ea)
        callees = []
        fn = idaapi.get_func(ea)
        if not fn:
            return callees
        addr = fn.start_ea
        while addr < fn.end_ea:
            xb = ida_xref.xrefblk_t()
            if xb.first_from(addr, ida_xref.XREF_ALL):
                while True:
                    callee_fn = ida_funcs.get_func(xb.to)
                    if callee_fn and callee_fn.start_ea != ea:
                        callee_ea = callee_fn.start_ea
                        if callee_ea not in [c.get("addr") for c in callees]:
                            c = {"addr": _hex(callee_ea), "name": ida_funcs.get_func_name(callee_ea), "site": _hex(addr)}
                            if depth > 1:
                                c["callees"] = get_callees(callee_ea, depth - 1)
                            callees.append(c)
                    if not xb.next_from():
                        break
            addr = idc.next_head(addr, fn.end_ea)
        return callees

    result = {"root": {"addr": _hex(root_ea), "name": root_name}}

    if direction in ("callers", "both"):
        result["callers"] = get_callers(root_ea, max_depth)

    if direction in ("callees", "both"):
        result["callees"] = get_callees(root_ea, max_depth)

    return result

rpc.register("get_callgraph", get_callgraph, doc="Get call graph showing callers and callees of a function.")


# --- get_segments ---

@idaread
def get_segments() -> Dict[str, Any]:
    """Get memory segments/sections of the binary.

    Returns:
        List of segments with name, start, end, permissions, type
    """
    import ida_segment

    segments = []
    seg = ida_segment.get_first_seg()

    while seg:
        perm = ""
        if seg.perm & ida_segment.SEGPERM_READ:
            perm += "R"
        if seg.perm & ida_segment.SEGPERM_WRITE:
            perm += "W"
        if seg.perm & ida_segment.SEGPERM_EXEC:
            perm += "X"

        seg_class = ida_segment.get_segm_class(seg) or ""

        segments.append({
            "name": ida_segment.get_segm_name(seg) or "",
            "start": _hex(seg.start_ea),
            "end": _hex(seg.end_ea),
            "size": seg.end_ea - seg.start_ea,
            "perm": perm or "---",
            "class": seg_class,
        })
        seg = ida_segment.get_next_seg(seg.start_ea)

    return {"segs": segments, "count": len(segments)}

rpc.register("get_segments", get_segments, doc="Get memory segments/sections.")


# --- script_exec ---

@idawrite
def script_exec(script: str) -> Dict[str, Any]:
    """Execute arbitrary Python code in IDA.

    Parameters:
        script: Python code to execute

    Returns:
        success, stdout, stderr, error
    """
    import io
    import contextlib

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    with batch_mode():
        try:
            with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                exec(script, globals())
            return {"ok": True, "out": stdout_capture.getvalue(), "err": stderr_capture.getvalue()}
        except Exception as e:
            return {"ok": False, "out": stdout_capture.getvalue(), "err": stderr_capture.getvalue(), "error": str(e)}

rpc.register("script_exec", script_exec, doc="Execute Python code in IDA.")


# ============================================================================
# Plugin Infrastructure
# ============================================================================

RUNTIME_DIR = os.environ.get("IDA_PRO_MCP_RUNTIME_DIR", os.path.expanduser("~/.ida-pro-mcp/instances"))
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

    # Don't start if no database is loaded
    db_name = idaapi.get_root_filename()
    if not db_name:
        return None

    # Already running with correct socket? Keep it
    if _SERVER_SINGLETON is not None:
        expected_path = _get_socket_path()
        if _SERVER_SINGLETON["socket_path"] == expected_path:
            return _SERVER_SINGLETON
        # Database changed - restart with new socket
        _stop_server()

    socket_path = _get_socket_path()

    try:
        server = UnixJSONRPCServer(socket_path)
    except Exception as e:
        print(f"[MCP] Failed to start server: {e}")
        return None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    _SERVER_SINGLETON = {
        "server": server,
        "thread": thread,
        "socket_path": socket_path,
    }

    print(f"[MCP] Server started: {socket_path}")
    return _SERVER_SINGLETON


def _stop_server():
    """Stop the MCP server."""
    global _SERVER_SINGLETON

    if _SERVER_SINGLETON is None:
        return

    try:
        _SERVER_SINGLETON["server"].shutdown()
        _SERVER_SINGLETON["server"].server_close()
    except Exception as e:
        print(f"[MCP] Error stopping server: {e}")

    _SERVER_SINGLETON = None
    print("[MCP] Server stopped")


class MCPUIHooks(idaapi.UI_Hooks):
    """UI hooks to detect database open/close events."""

    def database_inited(self, is_new_db, idc_script):
        """Called when a database is fully loaded."""
        _start_server()
        return 0

    def database_closed(self):
        """Called when database is about to close."""
        _stop_server()
        return 0


_ui_hooks: Optional[MCPUIHooks] = None


class MCPPlugin(idaapi.plugin_t):
    """IDA Pro MCP Plugin - Exposes reverse engineering tools via JSON-RPC."""

    flags = idaapi.PLUGIN_FIX
    comment = "MCP Server for LLM-assisted reverse engineering"
    help = "Starts a JSON-RPC server for external tool access"
    wanted_name = "MCP Server"
    wanted_hotkey = "Ctrl-Shift-M"

    def init(self):
        """Initialize plugin - install hooks and start server if DB already loaded."""
        global _ui_hooks
        _ui_hooks = MCPUIHooks()
        _ui_hooks.hook()
        # Try to start now in case DB is already loaded
        _start_server()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Toggle server on hotkey press."""
        global _SERVER_SINGLETON
        if _SERVER_SINGLETON is None:
            _start_server()
        else:
            _stop_server()

    def term(self):
        """Clean up on plugin unload."""
        global _ui_hooks
        _stop_server()
        if _ui_hooks:
            _ui_hooks.unhook()
            _ui_hooks = None


def PLUGIN_ENTRY():
    return MCPPlugin()
