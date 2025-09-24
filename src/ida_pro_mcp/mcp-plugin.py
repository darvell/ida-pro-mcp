import os
import sys

if sys.version_info < (3, 11):
    raise RuntimeError("Python 3.11 or higher is required for the MCP plugin")

import io
import json
import socket
import socketserver
import struct
import threading
import http.server
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Callable, get_type_hints, TypedDict, Optional, Annotated, TypeVar, Generic, NotRequired

from contextlib import suppress, redirect_stdout, redirect_stderr
import traceback


class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data

class RPCRegistry:
    def __init__(self):
        self.methods: dict[str, Callable] = {}
        self.unsafe: set[str] = set()

    def register(self, func: Callable) -> Callable:
        self.methods[func.__name__] = func
        return func

    def mark_unsafe(self, func: Callable) -> Callable:
        self.unsafe.add(func.__name__)
        return func

    def dispatch(self, method: str, params: Any) -> Any:
        if method not in self.methods:
            raise JSONRPCError(-32601, f"Method '{method}' not found")

        func = self.methods[method]
        hints = get_type_hints(func)

        # Remove return annotation if present
        hints.pop("return", None)

        if isinstance(params, list):
            if len(params) != len(hints):
                raise JSONRPCError(-32602, f"Invalid params: expected {len(hints)} arguments, got {len(params)}")

            # Validate and convert parameters
            converted_params = []
            for value, (param_name, expected_type) in zip(params, hints.items()):
                try:
                    if not isinstance(value, expected_type):
                        value = expected_type(value)
                    converted_params.append(value)
                except (ValueError, TypeError):
                    raise JSONRPCError(-32602, f"Invalid type for parameter '{param_name}': expected {expected_type.__name__}")

            return func(*converted_params)
        elif isinstance(params, dict):
            if set(params.keys()) != set(hints.keys()):
                raise JSONRPCError(-32602, f"Invalid params: expected {list(hints.keys())}")

            # Validate and convert parameters
            converted_params = {}
            for param_name, expected_type in hints.items():
                value = params.get(param_name)
                try:
                    if not isinstance(value, expected_type):
                        value = expected_type(value)
                    converted_params[param_name] = value
                except (ValueError, TypeError):
                    raise JSONRPCError(-32602, f"Invalid type for parameter '{param_name}': expected {expected_type.__name__}")

            return func(**converted_params)
        else:
            raise JSONRPCError(-32600, "Invalid Request: params must be array or object")

rpc_registry = RPCRegistry()

def jsonrpc(func: Callable) -> Callable:
    """Decorator to register a function as a JSON-RPC method"""
    global rpc_registry
    return rpc_registry.register(func)

def unsafe(func: Callable) -> Callable:
    """Decorator to register mark a function as unsafe"""
    return rpc_registry.mark_unsafe(func)

class JSONRPCRequestHandler(http.server.BaseHTTPRequestHandler):
    def send_jsonrpc_error(self, code: int, message: str, id: Any = None):
        response = {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message
            }
        }
        if id is not None:
            response["id"] = id
        response_body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def do_POST(self):
        global rpc_registry

        parsed_path = urlparse(self.path)
        if parsed_path.path != "/mcp":
            self.send_jsonrpc_error(-32098, "Invalid endpoint", None)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_jsonrpc_error(-32700, "Parse error: missing request body", None)
            return

        request_body = self.rfile.read(content_length)
        try:
            request = json.loads(request_body)
        except json.JSONDecodeError:
            self.send_jsonrpc_error(-32700, "Parse error: invalid JSON", None)
            return

        # Prepare the response
        response = {
            "jsonrpc": "2.0"
        }
        if request.get("id") is not None:
            response["id"] = request.get("id")

        try:
            # Basic JSON-RPC validation
            if not isinstance(request, dict):
                raise JSONRPCError(-32600, "Invalid Request")
            if request.get("jsonrpc") != "2.0":
                raise JSONRPCError(-32600, "Invalid JSON-RPC version")
            if "method" not in request:
                raise JSONRPCError(-32600, "Method not specified")

            # Dispatch the method
            result = rpc_registry.dispatch(request["method"], request.get("params", []))
            response["result"] = result

        except JSONRPCError as e:
            response["error"] = {
                "code": e.code,
                "message": e.message
            }
            if e.data is not None:
                response["error"]["data"] = e.data
        except IDAError as e:
            response["error"] = {
                "code": -32000,
                "message": e.message,
            }
        except Exception as e:
            traceback.print_exc()
            response["error"] = {
                "code": -32603,
                "message": "Internal error (please report a bug)",
                "data": traceback.format_exc(),
            }

        try:
            response_body = json.dumps(response).encode("utf-8")
        except Exception as e:
            traceback.print_exc()
            response_body = json.dumps({
                "error": {
                    "code": -32603,
                    "message": "Internal error (please report a bug)",
                    "data": traceback.format_exc(),
                }
            }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        # Suppress logging
        pass

class UnixJSONRPCServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, socket_path: str, request_handler: type[http.server.BaseHTTPRequestHandler]):
        self.socket_path = socket_path
        self.RequestHandlerClass = request_handler
        socketserver.UnixStreamServer.__init__(self, socket_path, request_handler)
        self.server_name = "unix"
        self.server_port = 0

    def server_bind(self):
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        super().server_bind()

    def server_close(self):
        super().server_close()
        with suppress(FileNotFoundError):
            os.unlink(self.socket_path)

    def get_request(self):
        request, _ = super().get_request()
        return request, ("local", 0)


INSTANCE_RUNTIME_ENV = "IDA_PRO_MCP_RUNTIME_DIR"


def _get_runtime_directory() -> Path:
    base_dir = os.environ.get(INSTANCE_RUNTIME_ENV)
    if base_dir:
        root = Path(base_dir)
    else:
        root = Path(os.path.expanduser("~")) / ".ida-pro-mcp"
    instances_dir = root / "instances"
    instances_dir.mkdir(parents=True, exist_ok=True)
    return instances_dir


def _sanitize_filename(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in (".", "-", "_") else "_" for ch in name)


def _get_idb_path() -> str:
    try:
        import ida_nalt

        return ida_nalt.get_path(ida_nalt.PATH_TYPE_IDB)
    except Exception:
        try:
            return idaapi.get_path(idaapi.PATH_TYPE_IDB)
        except Exception:
            return ""


def _build_instance_metadata(status: str, loaded_at: float) -> dict[str, Any]:
    idb_path = _get_idb_path()
    database_filename = os.path.basename(idb_path) if idb_path else idaapi.get_root_filename()
    loaded_at_iso = datetime.fromtimestamp(loaded_at, tz=timezone.utc).isoformat()
    return {
        "database": database_filename,
        "status": status,
        "loaded_at": loaded_at_iso,
        "module": idaapi.get_root_filename(),
        "input_path": idaapi.get_input_file_path(),
        "idb_path": idb_path,
        "pid": os.getpid(),
    }


ACTIVE_SERVER: Optional["Server"] = None


class Server:
    def __init__(self):
        global ACTIVE_SERVER
        self.server: Optional["UnixJSONRPCServer"] = None
        self.server_thread: Optional[threading.Thread] = None
        self.running = False
        self.loaded_at: Optional[float] = None
        self.socket_path: Optional[Path] = None
        self.status: str = "stopped"
        ACTIVE_SERVER = self

    def start(self):
        if self.running:
            print("[MCP] Server is already running")
            return

        try:
            runtime_dir = _get_runtime_directory()
            self.loaded_at = time.time()
            metadata = _build_instance_metadata("starting", self.loaded_at)
            safe_name = _sanitize_filename(metadata["database"] or "ida")
            socket_path = runtime_dir / f"{os.getpid()}_{safe_name}.sock"
            self.socket_path = socket_path
            self.server = UnixJSONRPCServer(str(socket_path), JSONRPCRequestHandler)
        except OSError as e:
            print(f"[MCP] Server error: {e}")
            self.loaded_at = None
            self.socket_path = None
            return

        self.running = True
        self.status = "starting"
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

    def stop(self):
        if not self.running:
            return

        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.server_thread:
            self.server_thread.join()
            self.server = None
        self.status = "stopped"
        self.loaded_at = None
        self.socket_path = None
        print("[MCP] Server stopped")

    def _run_server(self):
        try:
            assert self.server is not None
            assert self.socket_path is not None
            print(f"[MCP] Server started at unix://{self.socket_path}")
            self.status = "ready"
            self.server.serve_forever()
        except OSError as e:
            print(f"[MCP] Server error: {e}")
            self.running = False
        except Exception as e:
            print(f"[MCP] Server error: {e}")
        finally:
            self.running = False
            if self.status != "stopped":
                self.status = "stopped"
            self.loaded_at = None

    def describe_instance(self) -> dict[str, Any]:
        if self.loaded_at is None:
            raise IDAError("MCP server is not ready")
        return _build_instance_metadata(self.status, self.loaded_at)

# A module that helps with writing thread safe ida code.
# Based on:
# https://web.archive.org/web/20160305190440/http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator/
import logging
import queue
import traceback
import functools

import ida_hexrays
import ida_kernwin
import ida_funcs
import ida_gdl
import ida_lines
import ida_idaapi
import idc
import idaapi
import idautils
import ida_nalt
import ida_bytes
import ida_typeinf
import ida_xref
import ida_entry
import idautils
import ida_idd
import ida_dbg
import ida_name
import ida_ida
import ida_frame
try:
    import ida_enum
    IDA_ENUM_AVAILABLE = True
except ImportError:
    IDA_ENUM_AVAILABLE = False
import ida_segment

class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]

class IDASyncError(Exception):
    pass

class DecompilerLicenseError(IDAError):
    pass

# Important note: Always make sure the return value from your function f is a
# copy of the data you have gotten from IDA, and not the original data.
#
# Example:
# --------
#
# Do this:
#
#   @idaread
#   def ts_Functions():
#       return list(idautils.Functions())
#
# Don't do this:
#
#   @idaread
#   def ts_Functions():
#       return idautils.Functions()
#

logger = logging.getLogger(__name__)

# Enum for safety modes. Higher means safer:
class IDASafety:
    ida_kernwin.MFF_READ
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE

call_stack = queue.LifoQueue()
SCRIPT_EXECUTION_GLOBALS: dict[str, Any] = {}

def sync_wrapper(ff, safety_mode: IDASafety):
    """
    Call a function ff with a specific IDA safety_mode.
    """
    #logger.debug('sync_wrapper: {}, {}'.format(ff.__name__, safety_mode))

    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = 'Invalid safety mode {} over function {}'\
                .format(safety_mode, ff.__name__)
        logger.error(error_str)
        raise IDASyncError(error_str)

    # No safety level is set up:
    res_container = queue.Queue()

    def runned():
        #logger.debug('Inside runned')

        # Make sure that we are not already inside a sync_wrapper:
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = ('Call stack is not empty while calling the '
                'function {} from {}').format(ff.__name__, last_func_name)
            #logger.error(error_str)
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            call_stack.get()
            #logger.debug('Finished runned')

    ret_val = idaapi.execute_sync(runned, safety_mode)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res

def idawrite(f):
    """
    decorator for marking a function as modifying the IDB.
    schedules a request to be made in the main IDA loop to avoid IDB corruption.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)
    return wrapper

def idaread(f):
    """
    decorator for marking a function as reading from the IDB.
    schedules a request to be made in the main IDA loop to avoid
      inconsistent results.
    MFF_READ constant via: http://www.openrce.org/forums/posts/1827
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_READ)
    return wrapper

def is_window_active():
    """Returns whether IDA is currently active"""
    try:
        import PySide6
        import PySide6.QtWidgets
        from PySide6.QtGui import QApplication 
    except ImportError:
        try:
            from PyQt5.QtWidgets import QApplication
        except ImportError:
            return False

    app = QApplication.instance()
    if app is None:
        return False

    for widget in app.topLevelWidgets():
        if widget.isActiveWindow():
            return True
    return False

class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str


class InstanceDescription(TypedDict):
    database: str
    status: str
    loaded_at: str
    module: str
    input_path: str
    idb_path: str
    pid: int


class PythonScriptResult(TypedDict):
    stdout: str
    stderr: str
    success: bool
    error: Optional[str]


@idaread
def describe_instance() -> InstanceDescription:
    """Describe the current MCP instance (internal use)."""
    if ACTIVE_SERVER is None:
        raise IDAError("MCP server is not initialized")
    data = ACTIVE_SERVER.describe_instance()
    return InstanceDescription(
        database=str(data.get("database", "")),
        status=str(data.get("status", "unknown")),
        loaded_at=str(data.get("loaded_at", "")),
        module=str(data.get("module", "")),
        input_path=str(data.get("input_path", "")),
        idb_path=str(data.get("idb_path", "")),
        pid=int(data.get("pid", os.getpid())),
    )


rpc_registry.register(describe_instance)


def get_image_size() -> int:
    try:
        # https://www.hex-rays.com/products/ida/support/sdkdoc/structidainfo.html
        info = idaapi.get_inf_structure()
        omin_ea = info.omin_ea
        omax_ea = info.omax_ea
    except AttributeError:
        import ida_ida
        omin_ea = ida_ida.inf_get_omin_ea()
        omax_ea = ida_ida.inf_get_omax_ea()
    # Bad heuristic for image size (bad if the relocations are the last section)
    image_size = omax_ea - omin_ea
    # Try to extract it from the PE header
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size

@jsonrpc
@idaread
def get_metadata() -> Metadata:
    """Get metadata about the current IDB"""
    # Fat Mach-O binaries can return a None hash:
    # https://github.com/mrexodia/ida-pro-mcp/issues/26
    def hash(f):
        try:
            return f().hex()
        except:
            return None

    return Metadata(path=idaapi.get_input_file_path(),
                    module=idaapi.get_root_filename(),
                    base=hex(idaapi.get_imagebase()),
                    size=hex(get_image_size()),
                    md5=hash(ida_nalt.retrieve_input_file_md5),
                    sha256=hash(ida_nalt.retrieve_input_file_sha256),
                    crc32=hex(ida_nalt.retrieve_input_file_crc32()),
                    filesize=hex(ida_nalt.retrieve_input_file_size()))

def get_prototype(fn: ida_funcs.func_t) -> Optional[str]:
    try:
        prototype: ida_typeinf.tinfo_t = fn.get_prototype()
        if prototype is not None:
            return str(prototype)
        else:
            return None
    except AttributeError:
        try:
            return idc.get_type(fn.start_ea)
        except:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn.start_ea):
                return str(tif)
            return None
    except Exception as e:
        print(f"Error getting function prototype: {e}")
        return None

class Function(TypedDict):
    address: str
    name: str
    size: str


class Link(TypedDict, total=False):
    rel: str
    method: str
    description: NotRequired[str]
    params: NotRequired[dict]


class FunctionGraphNode(TypedDict, total=False):
    function: Function
    callers: list
    callees: list
    depth: int
    prototype: NotRequired[Optional[str]]
    links: NotRequired[list]


class FunctionGraph(TypedDict, total=False):
    root: Function
    direction: str
    max_depth: int
    total_nodes: int
    nodes: list
    links: NotRequired[list]


class DataFlowReference(TypedDict, total=False):
    name: NotRequired[str]
    kind: str
    address: NotRequired[str]
    target: NotRequired[str]
    type: NotRequired[str]
    line: NotRequired[int]
    text: NotRequired[str]
    function: NotRequired[Function]


class DataFlowVariable(TypedDict, total=False):
    name: str
    type: NotRequired[str]
    storage: str
    references: list


class DataFlowSummary(TypedDict, total=False):
    function: Function
    locals: list
    arguments: list
    globals: list
    call_sites: list
    pseudocode: list
    links: NotRequired[list]
    notes: NotRequired[dict]


class ProgramStructureMap(TypedDict, total=False):
    summary: dict
    segments: NotRequired[list]
    structures: NotRequired[list]
    enums: NotRequired[list]
    functions: NotRequired[list]
    links: NotRequired[list]

def parse_address(address: str) -> int:
    try:
        return int(address, 0)
    except ValueError:
        for ch in address:
            if ch not in "0123456789abcdefABCDEF":
                raise IDAError(f"Failed to parse address: {address}")
        raise IDAError(f"Failed to parse address (missing 0x prefix): {address}")

def get_function(address: int, *, raise_error=True) -> Function:
    fn = idaapi.get_func(address)
    if fn is None:
        if raise_error:
            raise IDAError(f"No function found at address {hex(address)}")
        return None

    try:
        name = fn.get_name()
    except AttributeError:
        name = ida_funcs.get_func_name(fn.start_ea)

    return Function(address=hex(address), name=name, size=hex(fn.end_ea - fn.start_ea))


def _build_function_links(address: int) -> list[Link]:
    addr_hex = hex(address)
    return [
        Link(rel="self", method="decompile_function", params={"address": addr_hex}),
        Link(rel="graph", method="analyze_call_graph", params={"address": addr_hex}),
        Link(rel="data-flow", method="analyze_data_flow", params={"address": addr_hex}),
        Link(rel="disassembly", method="disassemble_function", params={"start_address": addr_hex}),
    ]


def _collect_callers(func: ida_funcs.func_t, limit: int | None = None) -> list[Function]:
    callers: list[Function] = []
    seen: set[int] = set()
    for xref_ea in idautils.CodeRefsTo(func.start_ea, 0):
        caller_func = idaapi.get_func(xref_ea)
        if not caller_func:
            continue
        if caller_func.start_ea in seen:
            continue
        seen.add(caller_func.start_ea)
        callers.append(get_function(caller_func.start_ea))
        if limit is not None and len(callers) >= limit:
            break
    return callers


def _collect_callees(func: ida_funcs.func_t, limit: int | None = None) -> list[Function]:
    callees: list[Function] = []
    seen: set[int] = set()
    for item_ea in ida_funcs.func_item_iterator_t(func):
        for xref_ea in idautils.CodeRefsFrom(item_ea, 0):
            callee_func = idaapi.get_func(xref_ea)
            if not callee_func:
                continue
            if callee_func.start_ea == func.start_ea:
                continue
            if callee_func.start_ea in seen:
                continue
            seen.add(callee_func.start_ea)
            callees.append(get_function(callee_func.start_ea))
            if limit is not None and len(callees) >= limit:
                return callees
    return callees


def _parse_section_filter(section_text: str, include_xrefs: bool) -> list[str]:
    available = [
        "summary",
        "callers",
        "callees",
        "globals",
        "xrefs",
        "decompilation",
        "assembly",
    ]
    if section_text:
        requested = []
        for part in section_text.split(","):
            part = part.strip().lower()
            if not part:
                continue
            if part not in available:
                raise IDAError(f"Unknown section '{part}'. Available sections: {', '.join(available)}")
            requested.append(part)
    else:
        requested = [sec for sec in available if sec != "xrefs"]
        if include_xrefs:
            requested.append("xrefs")
    if include_xrefs and "xrefs" not in requested:
        requested.append("xrefs")
    return requested


def _identifier_in_line(line: str, identifier: str) -> bool:
    line_lower = line.lower()
    ident_lower = identifier.lower()
    start = 0
    length = len(ident_lower)
    if length == 0:
        return False
    while True:
        idx = line_lower.find(ident_lower, start)
        if idx == -1:
            return False
        before_ok = idx == 0 or not (line_lower[idx - 1].isalnum() or line_lower[idx - 1] == "_")
        after_idx = idx + length
        after_ok = after_idx >= len(line_lower) or not (
            line_lower[after_idx].isalnum() or line_lower[after_idx] == "_"
        )
        if before_ok and after_ok:
            return True
        start = idx + length

DEMANGLED_TO_EA = {}

def create_demangled_to_ea_map():
    for ea in idautils.Functions():
        # Get the function name and demangle it
        # MNG_NODEFINIT inhibits everything except the main name
        # where default demangling adds the function signature
        # and decorators (if any)
        demangled = idaapi.demangle_name(
            idc.get_name(ea, 0), idaapi.MNG_NODEFINIT)
        if demangled:
            DEMANGLED_TO_EA[demangled] = ea


def get_type_by_name(type_name: str) -> ida_typeinf.tinfo_t:
    # 8-bit integers
    if type_name in ('int8', '__int8', 'int8_t', 'char', 'signed char'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT8)
    elif type_name in ('uint8', '__uint8', 'uint8_t', 'unsigned char', 'byte', 'BYTE'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT8)

    # 16-bit integers
    elif type_name in ('int16', '__int16', 'int16_t', 'short', 'short int', 'signed short', 'signed short int'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT16)
    elif type_name in ('uint16', '__uint16', 'uint16_t', 'unsigned short', 'unsigned short int', 'word', 'WORD'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT16)

    # 32-bit integers
    elif type_name in ('int32', '__int32', 'int32_t', 'int', 'signed int', 'long', 'long int', 'signed long', 'signed long int'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
    elif type_name in ('uint32', '__uint32', 'uint32_t', 'unsigned int', 'unsigned long', 'unsigned long int', 'dword', 'DWORD'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT32)

    # 64-bit integers
    elif type_name in ('int64', '__int64', 'int64_t', 'long long', 'long long int', 'signed long long', 'signed long long int'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT64)
    elif type_name in ('uint64', '__uint64', 'uint64_t', 'unsigned int64', 'unsigned long long', 'unsigned long long int', 'qword', 'QWORD'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT64)

    # 128-bit integers
    elif type_name in ('int128', '__int128', 'int128_t', '__int128_t'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT128)
    elif type_name in ('uint128', '__uint128', 'uint128_t', '__uint128_t', 'unsigned int128'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT128)

    # Floating point types
    elif type_name in ('float', ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_FLOAT)
    elif type_name in ('double', ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_DOUBLE)
    elif type_name in ('long double', 'ldouble'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_LDOUBLE)

    # Boolean type
    elif type_name in ('bool', '_Bool', 'boolean'):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_BOOL)

    # Void type
    elif type_name in ('void', ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)

    # If not a standard type, try to get a named type
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_STRUCT):
        return tif

    if tif.get_named_type(None, type_name, ida_typeinf.BTF_TYPEDEF):
        return tif

    if tif.get_named_type(None, type_name, ida_typeinf.BTF_ENUM):
        return tif

    if tif.get_named_type(None, type_name, ida_typeinf.BTF_UNION):
        return tif

    if tif := ida_typeinf.tinfo_t(type_name):
        return tif

    raise IDAError(f"Unable to retrieve {type_name} type info object")

@jsonrpc
@idaread
def get_function_by_name(
    name: Annotated[str, "Name of the function to get"]
) -> Function:
    """Get a function by its name"""
    function_address = idaapi.get_name_ea(idaapi.BADADDR, name)
    if function_address == idaapi.BADADDR:
        # If map has not been created yet, create it
        if len(DEMANGLED_TO_EA) == 0:
            create_demangled_to_ea_map()
        # Try to find the function in the map, else raise an error
        if name in DEMANGLED_TO_EA:
            function_address = DEMANGLED_TO_EA[name]
        else:
            raise IDAError(f"No function found with name {name}")
    return get_function(function_address)

@jsonrpc
@idaread
def get_function_by_address(
    address: Annotated[str, "Address of the function to get"],
) -> Function:
    """Get a function by its address"""
    return get_function(parse_address(address))

@jsonrpc
@idaread
def get_current_address() -> str:
    """Get the address currently selected by the user"""
    return hex(idaapi.get_screen_ea())

@jsonrpc
@idaread
def get_current_function() -> Optional[Function]:
    """Get the function currently selected by the user"""
    return get_function(idaapi.get_screen_ea())

class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str

@jsonrpc
def convert_number(
    text: Annotated[str, "Textual representation of the number to convert"],
    size: Annotated[Optional[int], "Size of the variable in bytes"],
) -> ConvertedNumber:
    """Convert a number (decimal, hexadecimal) to different representations"""
    try:
        value = int(text, 0)
    except ValueError:
        raise IDAError(f"Invalid number: {text}")

    # Estimate the size of the number
    if not size:
        size = 0
        n = abs(value)
        while n:
            size += 1
            n >>= 1
        size += 7
        size //= 8

    # Convert the number to bytes
    try:
        bytes = value.to_bytes(size, "little", signed=True)
    except OverflowError:
        raise IDAError(f"Number {text} is too big for {size} bytes")

    # Convert the bytes to ASCII
    ascii = ""
    for byte in bytes.rstrip(b"\x00"):
        if byte >= 32 and byte <= 126:
            ascii += chr(byte)
        else:
            ascii = None
            break

    return ConvertedNumber(
        decimal=str(value),
        hexadecimal=hex(value),
        bytes=bytes.hex(" "),
        ascii=ascii,
        binary=bin(value),
    )

T = TypeVar("T")

class Page(TypedDict, Generic[T]):
    data: list[T]
    next_offset: Optional[int]

def paginate(data: list[T], offset: int, count: int) -> Page[T]:
    if count == 0:
        count = len(data)
    next_offset = offset + count
    if next_offset >= len(data):
        next_offset = None
    return {
        "data": data[offset:offset + count],
        "next_offset": next_offset,
    }

def pattern_filter(data: list[T], pattern: str, key: str) -> list[T]:
    if not pattern:
        return data

    # TODO: implement /regex/ matching

    def matches(item: T) -> bool:
        return pattern.lower() in item[key].lower()
    return list(filter(matches, data))

@jsonrpc
@idaread
def list_functions(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of functions to list (100 is a good default, 0 means remainder)"],
) -> Page[Function]:
    """List all functions in the database (paginated)"""
    functions = [get_function(address) for address in idautils.Functions()]
    return paginate(functions, offset, count)

class Global(TypedDict):
    address: str
    name: str


@jsonrpc
@idaread
def list_globals(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of globals to list (100 is a good default, 0 means remainder)"],
    filter: Annotated[str, "Filter to apply to the list (empty string for no filter). Case-insensitive contains or /regex/ syntax"] = ""
) -> Page[Global]:
    """List globals in the database (paginated, optionally filtered)"""
    globals = []
    for addr, name in idautils.Names():
        # Skip functions
        if not idaapi.get_func(addr):
            globals += [Global(address=hex(addr), name=name)]

    globals = pattern_filter(globals, filter, "name")
    return paginate(globals, offset, count)

class Import(TypedDict):
    address: str
    imported_name: str
    module: str

@jsonrpc
@idaread
def list_imports(
        offset: Annotated[int, "Offset to start listing from (start at 0)"],
        count: Annotated[int, "Number of imports to list (100 is a good default, 0 means remainder)"],
) -> Page[Import]:
    """ List all imported symbols with their name and module (paginated) """
    nimps = ida_nalt.get_import_module_qty()

    rv = []
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"

            acc += [Import(address=hex(ea), imported_name=symbol_name, module=module_name)]

            return True

        imp_cb_w_context = lambda ea, symbol_name, ordinal: imp_cb(ea, symbol_name, ordinal, rv)
        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)

class String(TypedDict):
    address: str
    length: int
    string: str


@jsonrpc
@idaread
def list_strings(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of strings to list (100 is a good default, 0 means remainder)"],
    filter: Annotated[str, "Filter to apply to the list (empty string for no filter). Case-insensitive contains or /regex/ syntax"] = ""
) -> Page[String]:
    """List strings in the database (paginated, optionally filtered)"""
    strings = []
    for item in idautils.Strings():
        try:
            string = str(item)
            if string:
                strings += [
                    String(address=hex(item.ea), length=item.length, string=string),
                ]
        except:
            continue

    strings = pattern_filter(strings, filter, "string")
    return paginate(strings, offset, count)

@jsonrpc
@idaread
def list_local_types():
    """List all Local types in the database"""
    error = ida_hexrays.hexrays_failure_t()
    locals = []
    idati = ida_typeinf.get_idati()
    type_count = ida_typeinf.get_ordinal_limit(idati)
    for ordinal in range(1, type_count):
        try:
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(idati, ordinal):
                type_name = tif.get_type_name()
                if not type_name:
                    type_name = f"<Anonymous Type #{ordinal}>"
                locals.append(f"\nType #{ordinal}: {type_name}")
                if tif.is_udt():
                    c_decl_flags = (ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_SEMI | ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_METHODS | ida_typeinf.PRTYPE_OFFSETS)
                    c_decl_output = tif._print(None, c_decl_flags)
                    if c_decl_output:
                        locals.append(f"  C declaration:\n{c_decl_output}")
                else:
                    simple_decl = tif._print(None, ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_SEMI)
                    if simple_decl:
                        locals.append(f"  Simple declaration:\n{simple_decl}")  
            else:
                message = f"\nType #{ordinal}: Failed to retrieve information."
                if error.str:
                    message += f": {error.str}"
                if error.errea != idaapi.BADADDR:
                    message += f"from (address: {hex(error.errea)})"
                raise IDAError(message)
        except:
            continue
    return locals

def decompile_checked(address: int) -> ida_hexrays.cfunc_t:
    if not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler is not available")
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(address, error, ida_hexrays.DECOMP_WARNINGS)
    if not cfunc:
        if error.code == ida_hexrays.MERR_LICENSE:
            raise DecompilerLicenseError("Decompiler licence is not available. Use `disassemble_function` to get the assembly code instead.")

        message = f"Decompilation failed at {hex(address)}"
        if error.str:
            message += f": {error.str}"
        if error.errea != idaapi.BADADDR:
            message += f" (address: {hex(error.errea)})"
        raise IDAError(message)
    return cfunc

@jsonrpc
@idaread
def decompile_function(
    address: Annotated[str, "Address of the function to decompile"],
    output_format: Annotated[str, "Output format: text (default), markdown, or json"] = "text",
    sections: Annotated[
        str,
        "Comma-separated sections to include (summary, callers, callees, globals, xrefs, decompilation, assembly).",
    ] = "",
    max_callers: Annotated[int, "Maximum number of callers to include"] = 5,
    max_callees: Annotated[int, "Maximum number of callees to include"] = 5,
    max_globals: Annotated[int, "Maximum number of globals to include"] = 5,
    include_xrefs: Annotated[bool, "Include cross references section"] = False,
    max_xrefs: Annotated[int, "Maximum number of cross references to include"] = 20,
) -> str | dict:
    """Decompile a function with customizable output formats and sections."""

    addr = parse_address(address)
    func = idaapi.get_func(addr)
    if not func:
        raise IDAError(f"No function found at address {hex(addr)}")

    output_kind = output_format.lower().strip() or "text"
    if output_kind not in {"text", "markdown", "json"}:
        raise IDAError("output_format must be 'text', 'markdown', or 'json'")

    selected_sections = _parse_section_filter(sections, include_xrefs)

    func_name = func.get_name() if hasattr(func, "get_name") else ida_funcs.get_func_name(func.start_ea)
    func_size = func.end_ea - func.start_ea
    function_info = get_function(func.start_ea)

    callers = _collect_callers(func, max_callers if max_callers > 0 else None)
    callees = _collect_callees(func, max_callees if max_callees > 0 else None)

    globals_found: list[dict] = []
    seen_globals: set[int] = set()
    for ea in ida_funcs.func_item_iterator_t(func):
        if max_globals > 0 and len(globals_found) >= max_globals:
            break
        for dref_ea in idautils.DataRefsFrom(ea):
            if dref_ea in seen_globals:
                continue
            if idaapi.get_func(dref_ea):
                continue
            name = ida_name.get_name(dref_ea)
            seen_globals.add(dref_ea)
            entry = {"address": hex(dref_ea)}
            if name:
                entry["name"] = name
            globals_found.append(entry)
            if max_globals > 0 and len(globals_found) >= max_globals:
                break

    pseudocode_lines: list[str] = []
    decompilation_error: Optional[str] = None
    if "decompilation" in selected_sections or output_kind == "json":
        try:
            cfunc = decompile_checked(addr)
            if is_window_active():
                ida_hexrays.open_pseudocode(addr, ida_hexrays.OPF_REUSE)
            sv = cfunc.get_pseudocode()
            for sl in sv:
                line = ida_lines.tag_remove(sl.line)
                pseudocode_lines.append(line)
        except Exception as exc:  # noqa: BLE001
            decompilation_error = str(exc)

    assembly_lines: list[str] = []
    if "assembly" in selected_sections or output_kind == "json":
        for ea in ida_funcs.func_item_iterator_t(func):
            disasm = ida_lines.tag_remove(idaapi.generate_disasm_line(ea, 0))
            comment = idaapi.get_cmt(ea, False) or idaapi.get_cmt(ea, True)
            line = f"{hex(ea)}: {disasm}"
            if comment:
                line += f" ;{comment}"
            assembly_lines.append(line)

    xrefs: list[dict] = []
    if (include_xrefs or "xrefs" in selected_sections) and max_xrefs != 0:
        for xref in idautils.XrefsTo(func.start_ea):
            entry: dict[str, Any] = {
                "address": hex(xref.frm),
                "type": ida_xref.get_xref_type_name(xref.type),
            }
            caller_func = idaapi.get_func(xref.frm)
            if caller_func:
                entry["function"] = get_function(caller_func.start_ea)
            xrefs.append(entry)
            if len(xrefs) >= max_xrefs > 0:
                break

    if output_kind == "json":
        result: dict[str, Any] = {
            "function": function_info,
            "metadata": {
                "size_bytes": func_size,
                "start_ea": function_info["address"],
            },
            "links": _build_function_links(func.start_ea),
        }
        if "callers" in selected_sections:
            result["callers"] = callers
        if "callees" in selected_sections:
            result["callees"] = callees
        if "globals" in selected_sections:
            result["globals"] = globals_found
        if "xrefs" in selected_sections and xrefs:
            result["xrefs"] = xrefs
        if "decompilation" in selected_sections:
            if decompilation_error:
                result["decompilation_error"] = decompilation_error
            else:
                result["decompilation"] = pseudocode_lines
        if "assembly" in selected_sections:
            result["assembly"] = assembly_lines
        if "summary" in selected_sections:
            result["summary"] = {
                "label": func_name,
                "size_bytes": func_size,
                "address": function_info["address"],
            }
        return result

    lines: list[str] = []
    if output_kind == "markdown":
        if "summary" in selected_sections:
            lines.append(f"### {func_name} @ {function_info['address']}")
            lines.append(f"- Size: {func_size} bytes")
    else:
        if "summary" in selected_sections:
            lines.append(f"=== {func_name} @ {function_info['address']} | Size: {func_size}b ===")

    if "callers" in selected_sections:
        if output_kind == "markdown":
            lines.append("**Callers:**")
            if callers:
                for item in callers:
                    lines.append(f"- {item['name']} ({item['address']})")
            else:
                lines.append("- None")
        else:
            caller_text = ", ".join(f"{item['name']}@{item['address']}" for item in callers) if callers else "None"
            lines.append(f"Callers: {caller_text}")

    if "callees" in selected_sections:
        if output_kind == "markdown":
            lines.append("**Callees:**")
            if callees:
                for item in callees:
                    lines.append(f"- {item['name']} ({item['address']})")
            else:
                lines.append("- None")
        else:
            callee_text = ", ".join(f"{item['name']}@{item['address']}" for item in callees) if callees else "None"
            lines.append(f"Callees: {callee_text}")

    if "globals" in selected_sections:
        if output_kind == "markdown":
            lines.append("**Global references:**")
            if globals_found:
                for item in globals_found:
                    label = item.get("name", "<anonymous>")
                    lines.append(f"- {label} ({item['address']})")
            else:
                lines.append("- None")
        else:
            if globals_found:
                formatted = ", ".join(
                    f"{item.get('name', '<anonymous>')}@{item['address']}" for item in globals_found
                )
            else:
                formatted = "None"
            lines.append(f"Globals: {formatted}")

    if "xrefs" in selected_sections and xrefs:
        if output_kind == "markdown":
            lines.append("**Cross-references:**")
            for entry in xrefs:
                func_entry = entry.get("function")
                if func_entry:
                    lines.append(
                        f"- {entry['type']} from {func_entry['name']} ({func_entry['address']})"
                    )
                else:
                    lines.append(f"- {entry['type']} from {entry['address']}")
        else:
            formatted = []
            for entry in xrefs:
                if entry.get("function"):
                    formatted.append(
                        f"{entry['function']['name']}@{entry['function']['address']} ({entry['type']})"
                    )
                else:
                    formatted.append(f"{entry['address']} ({entry['type']})")
            if formatted:
                lines.append(f"Xrefs: {', '.join(formatted)}")

    if "decompilation" in selected_sections:
        if output_kind == "markdown":
            lines.append("**Pseudocode:**")
            if decompilation_error:
                lines.append(f"> Decompilation failed: {decompilation_error}")
            else:
                lines.append("```c")
                lines.extend(pseudocode_lines)
                lines.append("```")
        else:
            lines.append("DECOMPILED:")
            if decompilation_error:
                lines.append(f"Decompilation failed: {decompilation_error}")
            else:
                lines.extend(pseudocode_lines)

    if "assembly" in selected_sections:
        if output_kind == "markdown":
            lines.append("**Assembly:**")
            lines.append("```asm")
            lines.extend(assembly_lines)
            lines.append("```")
        else:
            lines.append("ASSEMBLY:")
            lines.extend(assembly_lines)

    return "\n".join(lines)


@jsonrpc
@idaread
def analyze_call_graph(
    address: Annotated[str, "Address of the root function"],
    max_depth: Annotated[int, "Maximum traversal depth from the root (0 for root only)"] = 1,
    direction: Annotated[str, "Traversal direction: forward, backward, or both"] = "both",
    include_external: Annotated[bool, "Include call edges without a defined function"] = False,
    max_functions: Annotated[int, "Maximum number of functions to explore (0 for unlimited)"] = 128,
) -> FunctionGraph:
    """Generate a call graph rooted at the specified function."""

    root_ea = parse_address(address)
    root_func = idaapi.get_func(root_ea)
    if not root_func:
        raise IDAError(f"No function found at address {address}")

    if max_depth < 0:
        raise IDAError("max_depth must be zero or greater")
    if max_functions < 0:
        raise IDAError("max_functions must be zero or greater")

    traversal = direction.lower().strip() or "both"
    if traversal not in {"forward", "backward", "both"}:
        raise IDAError("direction must be 'forward', 'backward', or 'both'")

    node_limit: Optional[int]
    node_limit = max_functions if max_functions > 0 else None

    visited: dict[int, FunctionGraphNode] = {}
    queue: deque[tuple[int, int]] = deque([(root_func.start_ea, 0)])
    enqueued: set[int] = {root_func.start_ea}

    while queue:
        current_ea, depth = queue.popleft()
        enqueued.discard(current_ea)
        if current_ea in visited:
            continue

        current_func = idaapi.get_func(current_ea)
        if not current_func:
            if include_external:
                placeholder = Function(address=hex(current_ea), name=f"<external {hex(current_ea)}>", size="0x0")
                visited[current_ea] = FunctionGraphNode(
                    function=placeholder,
                    callers=[],
                    callees=[],
                    depth=depth,
                )
            continue

        node = FunctionGraphNode(
            function=get_function(current_func.start_ea),
            callers=[],
            callees=[],
            depth=depth,
        )
        prototype = get_prototype(current_func)
        if prototype:
            node["prototype"] = prototype
        node["links"] = _build_function_links(current_func.start_ea)
        visited[current_func.start_ea] = node

        if node_limit is not None and len(visited) >= node_limit:
            continue

        explore_forward = traversal in {"forward", "both"}
        explore_backward = traversal in {"backward", "both"}

        if explore_backward:
            callers_seen: set[int] = set()
            for xref_ea in idautils.CodeRefsTo(current_func.start_ea, 0):
                caller_func = idaapi.get_func(xref_ea)
                if caller_func:
                    if caller_func.start_ea not in callers_seen:
                        callers_seen.add(caller_func.start_ea)
                        node["callers"].append(get_function(caller_func.start_ea))
                    if depth < max_depth and (
                        node_limit is None or len(visited) + len(enqueued) < node_limit
                    ) and caller_func.start_ea not in visited and caller_func.start_ea not in enqueued:
                        queue.append((caller_func.start_ea, depth + 1))
                        enqueued.add(caller_func.start_ea)
                elif include_external:
                    node["callers"].append(
                        Function(address=hex(xref_ea), name=f"<external {hex(xref_ea)}>", size="0x0")
                    )

        if explore_forward:
            callees_seen: set[int] = set()
            for item_ea in ida_funcs.func_item_iterator_t(current_func):
                for xref_ea in idautils.CodeRefsFrom(item_ea, 0):
                    callee_func = idaapi.get_func(xref_ea)
                    if callee_func:
                        if callee_func.start_ea == current_func.start_ea:
                            continue
                        if callee_func.start_ea not in callees_seen:
                            callees_seen.add(callee_func.start_ea)
                            node["callees"].append(get_function(callee_func.start_ea))
                        if depth < max_depth and (
                            node_limit is None or len(visited) + len(enqueued) < node_limit
                        ) and callee_func.start_ea not in visited and callee_func.start_ea not in enqueued:
                            queue.append((callee_func.start_ea, depth + 1))
                            enqueued.add(callee_func.start_ea)
                    elif include_external:
                        node["callees"].append(
                            Function(address=hex(xref_ea), name=f"<external {hex(xref_ea)}>", size="0x0")
                        )

    ordered_nodes = [visited[key] for key in visited]
    function_info = get_function(root_func.start_ea)
    return FunctionGraph(
        root=function_info,
        direction=traversal,
        max_depth=max_depth,
        total_nodes=len(ordered_nodes),
        nodes=ordered_nodes,
        links=[
            Link(rel="self", method="analyze_call_graph", params={
                 "address": function_info["address"],
                 "max_depth": max_depth,
                 "direction": traversal,
                 "include_external": include_external,
                 "max_functions": max_functions,
            }),
            Link(rel="decompile", method="decompile_function", params={"address": function_info["address"]}),
            Link(rel="data-flow", method="analyze_data_flow", params={"address": function_info["address"]}),
        ],
    )


@jsonrpc
@idaread
def analyze_data_flow(
    address: Annotated[str, "Address of the function to analyze"],
    variable_filter: Annotated[str, "Case-insensitive filter for variable names"] = "",
    include_globals: Annotated[bool, "Include referenced global data"] = True,
    include_locals: Annotated[bool, "Include local stack variables"] = True,
    include_arguments: Annotated[bool, "Include function arguments"] = True,
    max_references: Annotated[int, "Maximum references per variable (0 for unlimited)"] = 40,
    max_data_references: Annotated[int, "Maximum data references to record (0 for unlimited)"] = 128,
) -> DataFlowSummary:
    """Summarize variable usage, data references, and call sites for a function."""

    ea = parse_address(address)
    func = idaapi.get_func(ea)
    if not func:
        raise IDAError(f"No function found at address {address}")

    if max_references < 0:
        raise IDAError("max_references must be zero or greater")
    if max_data_references < 0:
        raise IDAError("max_data_references must be zero or greater")

    filter_text = variable_filter.lower().strip()
    variables: dict[str, DataFlowVariable] = {}
    pseudocode_lines: list[str] = []
    decompiler_error: Optional[str] = None
    cfunc: Optional[ida_hexrays.cfunc_t] = None

    try:
        cfunc = decompile_checked(func.start_ea)
    except (DecompilerLicenseError, IDAError) as exc:
        decompiler_error = str(exc)
    else:
        for sl in cfunc.get_pseudocode():
            pseudocode_lines.append(ida_lines.tag_remove(sl.line))

    if cfunc and (include_locals or include_arguments):
        for lvar in cfunc.get_lvars():
            storage = "argument" if getattr(lvar, "is_arg_var", False) else "local"
            if storage == "argument" and not include_arguments:
                continue
            if storage == "local" and not include_locals:
                continue

            base_name = getattr(lvar, "name", "") or f"var_{len(variables)}"
            name = base_name
            suffix = 1
            while name in variables:
                name = f"{base_name}_{suffix}"
                suffix += 1

            var_entry: DataFlowVariable = DataFlowVariable(name=name, storage=storage, references=[])
            try:
                var_type = str(lvar.type())
            except Exception:
                var_type = None
            if var_type:
                var_entry["type"] = var_type
            variables[name] = var_entry

    if not pseudocode_lines:
        for idx, item_ea in enumerate(ida_funcs.func_item_iterator_t(func)):
            if idx >= 64:
                break
            disasm = ida_lines.tag_remove(idaapi.generate_disasm_line(item_ea, 0))
            pseudocode_lines.append(f"{hex(item_ea)}: {disasm}")

    if pseudocode_lines:
        for line_idx, line in enumerate(pseudocode_lines, start=1):
            for name, entry in variables.items():
                if filter_text and filter_text not in name.lower():
                    continue
                if not _identifier_in_line(line, name):
                    continue
                refs = entry["references"]
                if max_references > 0 and len(refs) >= max_references:
                    continue
                refs.append(
                    DataFlowReference(
                        kind="usage",
                        line=line_idx,
                        text=line.strip(),
                        name=name,
                    )
                )

    data_refs: list[DataFlowReference] = []
    if include_globals:
        seen_refs: set[tuple[int, int, int]] = set()
        for item_ea in ida_funcs.func_item_iterator_t(func):
            for xref in idautils.XrefsFrom(item_ea):
                if xref.iscode:
                    continue
                key = (item_ea, xref.to, xref.type)
                if key in seen_refs:
                    continue
                seen_refs.add(key)
                ref_entry: DataFlowReference = DataFlowReference(
                    kind=ida_xref.get_xref_type_name(xref.type),
                    address=hex(item_ea),
                    target=hex(xref.to),
                )
                name = ida_name.get_name(xref.to)
                if name:
                    ref_entry["name"] = name
                data_refs.append(ref_entry)
                if max_data_references > 0 and len(data_refs) >= max_data_references:
                    break
            if max_data_references > 0 and len(data_refs) >= max_data_references:
                break

    call_sites: list[DataFlowReference] = []
    seen_calls: set[tuple[int, int]] = set()
    for item_ea in ida_funcs.func_item_iterator_t(func):
        for cref in idautils.CodeRefsFrom(item_ea, 0):
            key = (item_ea, cref)
            if key in seen_calls:
                continue
            seen_calls.add(key)
            entry = DataFlowReference(kind="call", address=hex(item_ea), target=hex(cref))
            callee_func = idaapi.get_func(cref)
            if callee_func:
                entry["function"] = get_function(callee_func.start_ea)
            call_sites.append(entry)

    locals_list: list[DataFlowVariable] = []
    arguments_list: list[DataFlowVariable] = []
    for entry in variables.values():
        if filter_text and filter_text not in entry["name"].lower():
            continue
        if max_references > 0 and len(entry["references"]) > max_references:
            entry["references"] = entry["references"][:max_references]
        if entry["storage"] == "argument":
            arguments_list.append(entry)
        else:
            locals_list.append(entry)

    result: DataFlowSummary = DataFlowSummary(
        function=get_function(func.start_ea),
        locals=locals_list if include_locals else [],
        arguments=arguments_list if include_arguments else [],
        globals=data_refs if include_globals else [],
        call_sites=call_sites,
        pseudocode=pseudocode_lines,
        links=[
            Link(rel="self", method="analyze_data_flow", params={
                 "address": hex(func.start_ea),
                 "variable_filter": variable_filter,
                 "include_globals": include_globals,
                 "include_locals": include_locals,
                 "include_arguments": include_arguments,
                 "max_references": max_references,
                 "max_data_references": max_data_references,
            }),
            Link(rel="decompile", method="decompile_function", params={"address": hex(func.start_ea)}),
            Link(rel="call-graph", method="analyze_call_graph", params={"address": hex(func.start_ea)}),
        ],
    )
    if decompiler_error:
        result["notes"] = {"decompiler_error": decompiler_error}
    return result


@jsonrpc
@idaread
def map_program_structures(
    limit: Annotated[int, "Maximum number of entries per category (0 for unlimited)"] = 50,
    include_segments: Annotated[bool, "Include memory segments in the result"] = True,
    include_structures: Annotated[bool, "Include structure summaries"] = True,
    include_enums: Annotated[bool, "Include enumeration summaries"] = True,
    include_functions: Annotated[bool, "Include sample function relationships"] = True,
) -> ProgramStructureMap:
    """Map program structures, types, and high-level relationships."""

    if limit < 0:
        raise IDAError("limit must be zero or greater")

    limit_value: Optional[int] = limit if limit > 0 else None

    structure_count = 0
    structures_sample: list[dict] = []
    if include_structures:
        for ordinal in range(1, ida_typeinf.get_ordinal_limit()):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(None, ordinal):
                continue
            if not tif.is_udt():
                continue
            structure_count += 1
            collect = limit_value is None or len(structures_sample) < limit_value
            if collect:
                udt = ida_typeinf.udt_type_data_t()
                member_count = 0
                if tif.get_udt_details(udt):
                    member_count = sum(1 for m in udt if not m.is_gap())
                name = tif.get_type_name() or f"<anonymous_{ordinal}>"
                structures_sample.append(
                    {
                        "name": name,
                        "size": tif.get_size(),
                        "member_count": member_count,
                    }
                )
            if limit_value is not None and len(structures_sample) >= limit_value and structure_count >= limit_value:
                continue
        if structure_count == 0:
            structure_count = len(structures_sample)
    else:
        for ordinal in range(1, ida_typeinf.get_ordinal_limit()):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(None, ordinal) and tif.is_udt():
                structure_count += 1

    enum_count = 0
    enums_sample: list[dict] = []
    if include_enums and IDA_ENUM_AVAILABLE:
        # IDA 8.x style enum iteration
        enum_count = ida_enum.get_enum_qty()
        for idx in range(enum_count):
            enum_id = ida_enum.getn_enum(idx)
            if enum_id == idaapi.BADNODE:
                continue
            name = ida_enum.get_enum_name(enum_id) or f"<enum_{idx}>"
            enum_info = {
                "name": name,
                "size": ida_enum.get_enum_size(enum_id),
            }
            member_qty = None
            if hasattr(ida_enum, "get_enum_member_qty"):
                try:
                    member_qty = ida_enum.get_enum_member_qty(enum_id)
                except Exception:
                    member_qty = None
            if member_qty is not None:
                enum_info["member_count"] = member_qty
            enums_sample.append(enum_info)
            if limit_value is not None and len(enums_sample) >= limit_value:
                break
    elif include_enums:
        # IDA 9.x style enum iteration using type system
        try:
            # Iterate through all named types to find enums
            for ordinal in range(1, ida_typeinf.get_ordinal_limit()):
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(None, ordinal) and tif.is_enum():
                    enum_count += 1
                    if limit_value is not None and len(enums_sample) >= limit_value:
                        continue
                    name = tif.get_type_name() or f"<enum_{ordinal}>"
                    # Get enum member count using IDA 9.x API
                    try:
                        member_count = tif.get_enum_nmembers()
                    except Exception:
                        member_count = 0
                    enum_info = {
                        "name": name,
                        "size": member_count,
                    }
                    enums_sample.append(enum_info)
        except Exception as e:
            # If type system iteration fails, skip enums
            pass

    segments: list[dict] = []
    if include_segments:
        perm_map = [
            (ida_segment.SEGPERM_READ, "R"),
            (ida_segment.SEGPERM_WRITE, "W"),
            (ida_segment.SEGPERM_EXEC, "X"),
        ]
        seg_limit = limit_value
        for idx in range(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(idx)
            if not seg:
                continue
            perms = "".join(flag for perm, flag in perm_map if seg.perm & perm) or "-"
            segments.append(
                {
                    "name": idaapi.get_segm_name(seg) or f"seg_{idx}",
                    "start": hex(seg.start_ea),
                    "end": hex(seg.end_ea),
                    "size": seg.end_ea - seg.start_ea,
                    "perms": perms,
                }
            )
            if seg_limit is not None and len(segments) >= seg_limit:
                break

    functions_sample: list[dict] = []
    if include_functions:
        func_limit = limit_value
        for fn_ea in idautils.Functions():
            if func_limit is not None and len(functions_sample) >= func_limit:
                break
            fn = idaapi.get_func(fn_ea)
            if not fn:
                continue
            info = dict(get_function(fn.start_ea))
            info["callers"] = len(_collect_callers(fn, None))
            info["callees"] = len(_collect_callees(fn, None))
            prototype = get_prototype(fn)
            if prototype:
                info["prototype"] = prototype
            info["links"] = _build_function_links(fn.start_ea)
            functions_sample.append(info)

    summary = {
        "functions": ida_funcs.get_func_qty(),
        "segments": idaapi.get_segm_qty(),
        "structures": structure_count,
        "enums": enum_count,
    }

    result: ProgramStructureMap = ProgramStructureMap(summary=summary)
    if include_segments:
        result["segments"] = segments
    if include_structures:
        result["structures"] = structures_sample
    if include_enums:
        result["enums"] = enums_sample
    if include_functions:
        result["functions"] = functions_sample

    result["links"] = [
        Link(rel="self", method="map_program_structures", params={
             "limit": limit,
             "include_segments": include_segments,
             "include_structures": include_structures,
             "include_enums": include_enums,
             "include_functions": include_functions,
        }),
        Link(rel="discover", method="discover_resources", params={"context": "root"}),
        Link(rel="structures-detailed", method="get_defined_structures", params={}),
    ]
    return result


class DisassemblyLine(TypedDict):
    segment: NotRequired[str]
    address: str
    label: NotRequired[str]
    instruction: str
    comments: NotRequired[list[str]]

class Argument(TypedDict):
    name: str
    type: str

class DisassemblyFunction(TypedDict):
    name: str
    start_ea: str
    return_type: NotRequired[str]
    arguments: NotRequired[list[Argument]]
    stack_frame: list[dict]
    lines: list[DisassemblyLine]

@jsonrpc
@idaread
def disassemble_function(
    start_address: Annotated[str, "Address of the function to disassemble"],
) -> DisassemblyFunction:
    """Get assembly code for a function"""
    start = parse_address(start_address)
    func: ida_funcs.func_t = idaapi.get_func(start)
    if not func:
        raise IDAError(f"No function found containing address {start_address}")
    if is_window_active():
        ida_kernwin.jumpto(start)

    lines = []
    for address in ida_funcs.func_item_iterator_t(func):
        seg = idaapi.getseg(address)
        segment = idaapi.get_segm_name(seg) if seg else None

        label = idc.get_name(address, 0)
        if label and label == func.name and address == func.start_ea:
            label = None
        if label == "":
            label = None

        comments = []
        if comment := idaapi.get_cmt(address, False):
            comments += [comment]
        if comment := idaapi.get_cmt(address, True):
            comments += [comment]

        raw_instruction = idaapi.generate_disasm_line(address, 0)
        tls = ida_kernwin.tagged_line_sections_t()
        ida_kernwin.parse_tagged_line_sections(tls, raw_instruction)
        insn_section = tls.first(ida_lines.COLOR_INSN)

        operands = []
        for op_tag in range(ida_lines.COLOR_OPND1, ida_lines.COLOR_OPND8 + 1):
            op_n = tls.first(op_tag)
            if not op_n:
                break

            op: str = op_n.substr(raw_instruction)
            op_str = ida_lines.tag_remove(op)

            # Do a lot of work to add address comments for symbols
            for idx in range(len(op) - 2):
                if op[idx] != idaapi.COLOR_ON:
                    continue

                idx += 1
                if ord(op[idx]) != idaapi.COLOR_ADDR:
                    continue

                idx += 1
                addr_string = op[idx:idx + idaapi.COLOR_ADDR_SIZE]
                idx += idaapi.COLOR_ADDR_SIZE

                addr = int(addr_string, 16)

                # Find the next color and slice until there
                symbol = op[idx:op.find(idaapi.COLOR_OFF, idx)]

                if symbol == '':
                    # We couldn't figure out the symbol, so use the whole op_str
                    symbol = op_str

                comments += [f"{symbol}={addr:#x}"]

                # print its value if its type is available
                try:
                    value = get_global_variable_value_internal(addr)
                except:
                    continue

                comments += [f"*{symbol}={value}"]

            operands += [op_str]

        mnem = ida_lines.tag_remove(insn_section.substr(raw_instruction))
        instruction = f"{mnem} {', '.join(operands)}"

        line = DisassemblyLine(
            address=f"{address:#x}",
            instruction=instruction,
        )

        if len(comments) > 0:
            line.update(comments=comments)

        if segment:
            line.update(segment=segment)

        if label:
            line.update(label=label)

        lines += [line]

    prototype = func.get_prototype()
    arguments: list[Argument] = [Argument(name=arg.name, type=f"{arg.type}") for arg in prototype.iter_func()] if prototype else None

    disassembly_function = DisassemblyFunction(
        name=func.name,
        start_ea=f"{func.start_ea:#x}",
        stack_frame=get_stack_frame_variables_internal(func.start_ea),
        lines=lines
    )

    if prototype:
        disassembly_function.update(return_type=f"{prototype.get_rettype()}")

    if arguments:
        disassembly_function.update(arguments=arguments)

    return disassembly_function

class Xref(TypedDict):
    address: str
    type: str
    function: Optional[Function]

@jsonrpc
@idaread
def get_xrefs_to(
    address: Annotated[str, "Address to get cross references to"],
) -> list[Xref]:
    """Get all cross references to the given address"""
    xrefs = []
    xref: ida_xref.xrefblk_t
    for xref in idautils.XrefsTo(parse_address(address)):
        xrefs += [
            Xref(address=hex(xref.frm),
                 type="code" if xref.iscode else "data",
                 function=get_function(xref.frm, raise_error=False))
        ]
    return xrefs

@jsonrpc
@idaread
def get_xrefs_to_field(
    struct_name: Annotated[str, "Name of the struct (type) containing the field"],
    field_name: Annotated[str, "Name of the field (member) to get xrefs to"],
) -> list[Xref]:
    """Get all cross references to a named struct field (member)"""

    # Get the type library
    til = ida_typeinf.get_idati()
    if not til:
        raise IDAError("Failed to retrieve type library.")

    # Get the structure type info
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, struct_name, ida_typeinf.BTF_STRUCT, True, False):
        print(f"Structure '{struct_name}' not found.")
        return []

    # Get The field index
    idx = ida_typeinf.get_udm_by_fullname(None, struct_name + '.' + field_name)
    if idx == -1:
        print(f"Field '{field_name}' not found in structure '{struct_name}'.")
        return []

    # Get the type identifier
    tid = tif.get_udm_tid(idx)
    if tid == ida_idaapi.BADADDR:
        raise IDAError(f"Unable to get tid for structure '{struct_name}' and field '{field_name}'.")

    # Get xrefs to the tid
    xrefs = []
    xref: ida_xref.xrefblk_t
    for xref in idautils.XrefsTo(tid):

        xrefs += [
            Xref(address=hex(xref.frm),
                 type="code" if xref.iscode else "data",
                 function=get_function(xref.frm, raise_error=False))
        ]
    return xrefs

@jsonrpc
@idaread
def get_callees(
    function_address: Annotated[str, "Address of the function to get callee functions"],
) -> list[dict[str, str]]:
    """Get all the functions called (callees) by the function at function_address"""
    func_start = parse_address(function_address)
    func = idaapi.get_func(func_start)
    if not func:
        raise IDAError(f"No function found containing address {function_address}")
    func_end = idc.find_func_end(func_start)
    callees: list[dict[str, str]] = []
    current_ea = func_start
    while current_ea < func_end:
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, current_ea)
        if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
            target = idc.get_operand_value(current_ea, 0)
            target_type = idc.get_operand_type(current_ea, 0)
            # check if it's a direct call - avoid getting the indirect call offset
            if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                # in here, we do not use get_function because the target can be external function.
                # but, we should mark the target as internal/external function.
                func_type = (
                    "internal" if idaapi.get_func(target) is not None else "external"
                )
                func_name = idc.get_name(target)
                if func_name is not None:
                    callees.append(
                        {"address": hex(target), "name": func_name, "type": func_type}
                    )
        current_ea = idc.next_head(current_ea, func_end)

    # deduplicate callees
    unique_callee_tuples = {tuple(callee.items()) for callee in callees}
    unique_callees = [dict(callee) for callee in unique_callee_tuples]
    return unique_callees  # type: ignore

@jsonrpc
@idaread
def get_callers(
    function_address: Annotated[str, "Address of the function to get callers"],
) -> list[Function]:
    """Get all callers of the given address"""
    callers = {}
    for caller_address in idautils.CodeRefsTo(parse_address(function_address), 0):
        # validate the xref address is a function
        func = get_function(caller_address, raise_error=False)
        if not func:
            continue
        # load the instruction at the xref address
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, caller_address)
        # check the instruction is a call
        if insn.itype not in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
            continue
        # deduplicate callers by address
        callers[func["address"]] = func

    return list(callers.values())

@jsonrpc
@idaread
def get_entry_points() -> list[Function]:
    """Get all entry points in the database"""
    result = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        address = ida_entry.get_entry(ordinal)
        func = get_function(address, raise_error=False)
        if func is not None:
            result.append(func)
    return result

@jsonrpc
@idawrite
def set_comment(
    address: Annotated[str, "Address in the function to set the comment for"],
    comment: Annotated[str, "Comment text"],
):
    """Set a comment for a given address in the function disassembly and pseudocode"""
    address = parse_address(address)

    if not idaapi.set_cmt(address, comment, False):
        raise IDAError(f"Failed to set disassembly comment at {hex(address)}")

    if not ida_hexrays.init_hexrays_plugin():
        return

    # Reference: https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/
    # Check if the address corresponds to a line
    try:
        cfunc = decompile_checked(address)
    except DecompilerLicenseError:
        # We failed to decompile the function due to a decompiler license error
        return

    # Special case for function entry comments
    if address == cfunc.entry_ea:
        idc.set_func_cmt(address, comment, True)
        cfunc.refresh_func_ctext()
        return

    eamap = cfunc.get_eamap()
    if address not in eamap:
        print(f"Failed to set decompiler comment at {hex(address)}")
        return
    nearest_ea = eamap[address][0].ea

    # Remove existing orphan comments
    if cfunc.has_orphan_cmts():
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()

    # Set the comment by trying all possible item types
    tl = idaapi.treeloc_t()
    tl.ea = nearest_ea
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()
        if not cfunc.has_orphan_cmts():
            return
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()
    print(f"Failed to set decompiler comment at {hex(address)}")

def refresh_decompiler_widget():
    widget = ida_kernwin.get_current_widget()
    if widget is not None:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu is not None:
            vu.refresh_ctext()

def refresh_decompiler_ctext(function_address: int):
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(function_address, error, ida_hexrays.DECOMP_WARNINGS)
    if cfunc:
        cfunc.refresh_func_ctext()

@jsonrpc
@idawrite
def rename_local_variable(
    function_address: Annotated[str, "Address of the function containing the variable"],
    old_name: Annotated[str, "Current name of the variable"],
    new_name: Annotated[str, "New name for the variable (empty for a default name)"],
):
    """Rename a local variable in a function"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
        raise IDAError(f"Failed to rename local variable {old_name} in function {hex(func.start_ea)}")
    refresh_decompiler_ctext(func.start_ea)

@jsonrpc
@idawrite
def rename_global_variable(
    old_name: Annotated[str, "Current name of the global variable"],
    new_name: Annotated[str, "New name for the global variable (empty for a default name)"],
):
    """Rename a global variable"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, old_name)
    if not idaapi.set_name(ea, new_name):
        raise IDAError(f"Failed to rename global variable {old_name} to {new_name}")
    refresh_decompiler_ctext(ea)

@jsonrpc
@idawrite
def set_global_variable_type(
    variable_name: Annotated[str, "Name of the global variable"],
    new_type: Annotated[str, "New type for the variable"],
):
    """Set a global variable's type"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    tif = get_type_by_name(new_type)
    if not tif:
        raise IDAError(f"Parsed declaration is not a variable type")
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL):
        raise IDAError(f"Failed to apply type")

def patch_address_assemble(
    ea: int,
    assemble: str,
) -> int:
    """Patch Address Assemble"""
    (check_assemble, bytes_to_patch) = idautils.Assemble(ea, assemble)
    if check_assemble == False:
        raise IDAError(f"Failed to assemble instruction: {assemble}")
    try:
        ida_bytes.patch_bytes(ea, bytes_to_patch)
    except:
        raise IDAError(f"Failed to patch bytes at address {hex(ea)}")
    
    return len(bytes_to_patch)

@jsonrpc
@idawrite
def patch_address_assembles(
    address: Annotated[str, "Starting Address to apply patch"],
    assembles: Annotated[str, "Assembly instructions separated by ';'"],
) -> str:
    ea = parse_address(address)
    assembles = assembles.split(";")
    for assemble in assembles:
        assemble = assemble.strip()
        try:
            patch_bytes_len = patch_address_assemble(ea, assemble)
        except IDAError as e:
            raise IDAError(f"Failed to patch bytes at address {hex(address)}: {e}")
        ea += patch_bytes_len
    return f"Patched {len(assembles)} instructions"

@jsonrpc
@idaread
def get_global_variable_value_by_name(variable_name: Annotated[str, "Name of the global variable"]) -> str:
    """
    Read a global variable's value (if known at compile-time)

    Prefer this function over the `data_read_*` functions.
    """
    ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    if ea == idaapi.BADADDR:
        raise IDAError(f"Global variable {variable_name} not found")

    return get_global_variable_value_internal(ea)

@jsonrpc
@idaread
def get_global_variable_value_at_address(ea: Annotated[str, "Address of the global variable"]) -> str:
    """
    Read a global variable's value by its address (if known at compile-time)

    Prefer this function over the `data_read_*` functions.
    """
    ea = parse_address(ea)
    return get_global_variable_value_internal(ea)

def get_global_variable_value_internal(ea: int) -> str:
     # Get the type information for the variable
     tif = ida_typeinf.tinfo_t()
     if not ida_nalt.get_tinfo(tif, ea):
         # No type info, maybe we can figure out its size by its name
         if not ida_bytes.has_any_name(ea):
             raise IDAError(f"Failed to get type information for variable at {ea:#x}")

         size = ida_bytes.get_item_size(ea)
         if size == 0:
             raise IDAError(f"Failed to get type information for variable at {ea:#x}")
     else:
         # Determine the size of the variable
         size = tif.get_size()

     # Read the value based on the size
     if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
         return_string = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8").strip()
         return f"\"{return_string}\""
     elif size == 1:
         return hex(ida_bytes.get_byte(ea))
     elif size == 2:
         return hex(ida_bytes.get_word(ea))
     elif size == 4:
         return hex(ida_bytes.get_dword(ea))
     elif size == 8:
         return hex(ida_bytes.get_qword(ea))
     else:
         # For other sizes, return the raw bytes
         return ' '.join(hex(x) for x in ida_bytes.get_bytes(ea, size))


@jsonrpc
@idawrite
def rename_function(
    function_address: Annotated[str, "Address of the function to rename"],
    new_name: Annotated[str, "New name for the function (empty for a default name)"],
):
    """Rename a function"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not idaapi.set_name(func.start_ea, new_name):
        raise IDAError(f"Failed to rename function {hex(func.start_ea)} to {new_name}")
    refresh_decompiler_ctext(func.start_ea)

@jsonrpc
@idawrite
def set_function_prototype(
    function_address: Annotated[str, "Address of the function"],
    prototype: Annotated[str, "New function prototype"],
):
    """Set a function's prototype"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    try:
        tif = ida_typeinf.tinfo_t(prototype, None, ida_typeinf.PT_SIL)
        if not tif.is_func():
            raise IDAError(f"Parsed declaration is not a function type")
        if not ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.PT_SIL):
            raise IDAError(f"Failed to apply type")
        refresh_decompiler_ctext(func.start_ea)
    except Exception as e:
        raise IDAError(f"Failed to parse prototype string: {prototype}")

class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvars):
        for lvar_saved in lvars.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False

# NOTE: This is extremely hacky, but necessary to get errors out of IDA
def parse_decls_ctypes(decls: str, hti_flags: int) -> tuple[int, str]:
    if sys.platform == "win32":
        import ctypes

        assert isinstance(decls, str), "decls must be a string"
        assert isinstance(hti_flags, int), "hti_flags must be an int"
        c_decls = decls.encode("utf-8")
        c_til = None
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        ida_dll.parse_decls.restype = ctypes.c_int

        messages = []

        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes):
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                messages.append(formatted.decode("utf-8"))
                return len(formatted) + 1
            else:
                messages.append(f"unsupported magic_printer fmt: {repr(fmt)}")
                return 0

        errors = ida_dll.parse_decls(c_til, c_decls, magic_printer, hti_flags)
    else:
        # NOTE: The approach above could also work on other platforms, but it's
        # not been tested and there are differences in the vararg ABIs.
        errors = ida_typeinf.parse_decls(None, decls, False, hti_flags)
        messages = []
    return errors, messages

@jsonrpc
@idawrite
def declare_c_type(
    c_declaration: Annotated[str, "C declaration of the type. Examples include: typedef int foo_t; struct bar { int a; bool b; };"],
):
    """Create or update a local type from a C declaration"""
    # PT_SIL: Suppress warning dialogs (although it seems unnecessary here)
    # PT_EMPTY: Allow empty types (also unnecessary?)
    # PT_TYP: Print back status messages with struct tags
    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
    errors, messages = parse_decls_ctypes(c_declaration, flags)

    pretty_messages = "\n".join(messages)
    if errors > 0:
        raise IDAError(f"Failed to parse type:\n{c_declaration}\n\nErrors:\n{pretty_messages}")
    return f"success\n\nInfo:\n{pretty_messages}"

@jsonrpc
@idawrite
def set_local_variable_type(
    function_address: Annotated[str, "Address of the decompiled function containing the variable"],
    variable_name: Annotated[str, "Name of the variable"],
    new_type: Annotated[str, "New type for the variable"],
):
    """Set a local variable's type"""
    try:
        # Some versions of IDA don't support this constructor
        new_tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)
    except Exception:
        try:
            new_tif = ida_typeinf.tinfo_t()
            # parse_decl requires semicolon for the type
            ida_typeinf.parse_decl(new_tif, None, new_type + ";", ida_typeinf.PT_SIL)
        except Exception:
            raise IDAError(f"Failed to parse type: {new_type}")
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not ida_hexrays.rename_lvar(func.start_ea, variable_name, variable_name):
        raise IDAError(f"Failed to find local variable: {variable_name}")
    modifier = my_modifier_t(variable_name, new_tif)
    if not ida_hexrays.modify_user_lvars(func.start_ea, modifier):
        raise IDAError(f"Failed to modify local variable: {variable_name}")
    refresh_decompiler_ctext(func.start_ea)

class StackFrameVariable(TypedDict):
    name: str
    offset: str
    size: str
    type: str

@jsonrpc
@idaread
def get_stack_frame_variables(
        function_address: Annotated[str, "Address of the disassembled function to retrieve the stack frame variables"]
) -> list[StackFrameVariable]:
    """ Retrieve the stack frame variables for a given function """
    return get_stack_frame_variables_internal(parse_address(function_address))

def get_stack_frame_variables_internal(function_address: int) -> list[dict]:
    func = idaapi.get_func(function_address)
    if not func:
        raise IDAError(f"No function found at address {function_address}")

    members = []
    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(func.frame) or not tif.is_udt():
        return []

    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    for udm in udt:
        if not udm.is_gap():
            name = udm.name
            offset = udm.offset // 8
            size = udm.size // 8
            type = str(udm.type)

            members += [StackFrameVariable(name=name,
                                           offset=hex(offset),
                                           size=hex(size),
                                           type=type)
            ]

    return members


class StructureMember(TypedDict):
    name: str
    offset: str
    size: str
    type: str

class StructureDefinition(TypedDict):
    name: str
    size: str
    members: list[StructureMember]

@jsonrpc
@idaread
def get_defined_structures() -> list[StructureDefinition]:
    """ Returns a list of all defined structures """

    rv = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        tif.get_numbered_type(None, ordinal)
        if tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            members = []
            if tif.get_udt_details(udt):
                members = [
                    StructureMember(name=x.name,
                                    offset=hex(x.offset // 8),
                                    size=hex(x.size // 8),
                                    type=str(x.type))
                    for _, x in enumerate(udt)
                ]

            rv += [StructureDefinition(name=tif.get_type_name(),
                                       size=hex(tif.get_size()),
                                       members=members)]

    return rv

def get_structure_detailed_analysis(name: str) -> dict:
    """Get detailed analysis of a structure with all fields (internal function)"""
    # Get tinfo object
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        raise IDAError(f"Structure '{name}' not found!")
    
    result = {
        "name": name,
        "type": str(tif._print()),
        "size": tif.get_size(),
        "is_udt": tif.is_udt()
    }
    
    if not tif.is_udt():
        result["error"] = "This is not a user-defined type!"
        return result
    
    # Get UDT (User Defined Type) details
    udt_data = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        result["error"] = "Failed to get structure details!"
        return result
    
    result["member_count"] = udt_data.size()
    result["is_union"] = udt_data.is_union
    result["udt_type"] = "Union" if udt_data.is_union else "Struct"
    
    # Output information about each field
    members = []
    for i, member in enumerate(udt_data):
        offset = member.begin() // 8  # Convert bits to bytes
        size = member.size // 8 if member.size > 0 else member.type.get_size()
        member_type = member.type._print()
        member_name = member.name
        
        member_info = {
            "index": i,
            "offset": f"0x{offset:08X}",
            "size": size,
            "type": member_type,
            "name": member_name,
            "is_nested_udt": member.type.is_udt()
        }
        
        # If this is a nested structure, show additional information
        if member.type.is_udt():
            member_info["nested_size"] = member.type.get_size()
        
        members.append(member_info)
    
    result["members"] = members
    result["total_size"] = tif.get_size()
    
    return result

@jsonrpc
@idaread
def get_struct_at_address(address: Annotated[str, "Address to analyze structure at"], 
                         struct_name: Annotated[str, "Name of the structure"]) -> dict:
    """Get structure field values at a specific address"""
    addr = parse_address(address)
    
    # Get structure tinfo
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, struct_name):
        raise IDAError(f"Structure '{struct_name}' not found!")
    
    # Get structure details
    udt_data = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        raise IDAError("Failed to get structure details!")
    
    result = {
        "struct_name": struct_name,
        "address": f"0x{addr:X}",
        "members": []
    }
    
    for member in udt_data:
        offset = member.begin() // 8
        member_addr = addr + offset
        member_type = member.type._print()
        member_name = member.name
        member_size = member.type.get_size()
        
        # Try to get value based on size
        try:
            if member.type.is_ptr():
                # Pointer
                if idaapi.get_inf_structure().is_64bit():
                    value = idaapi.get_qword(member_addr)
                    value_str = f"0x{value:016X}"
                else:
                    value = idaapi.get_dword(member_addr)
                    value_str = f"0x{value:08X}"
            elif member_size == 1:
                value = idaapi.get_byte(member_addr)
                value_str = f"0x{value:02X} ({value})"
            elif member_size == 2:
                value = idaapi.get_word(member_addr)
                value_str = f"0x{value:04X} ({value})"
            elif member_size == 4:
                value = idaapi.get_dword(member_addr)
                value_str = f"0x{value:08X} ({value})"
            elif member_size == 8:
                value = idaapi.get_qword(member_addr)
                value_str = f"0x{value:016X} ({value})"
            else:
                # For large structures, read first few bytes
                bytes_data = []
                for i in range(min(member_size, 16)):
                    try:
                        byte_val = idaapi.get_byte(member_addr + i)
                        bytes_data.append(f"{byte_val:02X}")
                    except:
                        break
                value_str = f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
        except:
            value_str = "<failed to read>"
        
        member_info = {
            "offset": f"0x{offset:08X}",
            "type": member_type,
            "name": member_name,
            "value": value_str
        }
        
        result["members"].append(member_info)
    
    return result

@jsonrpc
@idaread
def get_structure_info(name: Annotated[str, "Name of the structure"], detailed: Annotated[bool, "Get detailed analysis if True, basic info if False"] = False) -> dict:
    """Get structure information (basic or detailed)"""
    if detailed:
        return get_structure_detailed_analysis(name)

    # Basic info
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        raise IDAError(f"Structure '{name}' not found!")

    info = {
        'name': name,
        'type': tif._print(),
        'size': tif.get_size(),
        'is_udt': tif.is_udt()
    }

    if tif.is_udt():
        udt_data = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt_data):
            info['member_count'] = udt_data.size()
            info['is_union'] = udt_data.is_union

            members = []
            for member in udt_data:
                members.append({
                    'name': member.name,
                    'type': member.type._print(),
                    'offset': member.begin() // 8,
                    'size': member.type.get_size()
                })
            info['members'] = members

    return info

@jsonrpc
@idaread
def search_structures(filter: Annotated[str, "Filter pattern to search for structures (case-insensitive)"]) -> list[dict]:
    """Search for structures by name pattern"""
    results = []
    limit = ida_typeinf.get_ordinal_limit()
    
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name = tif.get_type_name()
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    member_count = 0
                    if tif.get_udt_details(udt_data):
                        member_count = udt_data.size()
                    
                    results.append({
                        "name": type_name,
                        "size": tif.get_size(),
                        "member_count": member_count,
                        "is_union": udt_data.is_union if tif.get_udt_details(udt_data) else False,
                        "ordinal": ordinal
                    })
    
    return results

@jsonrpc
@idawrite
def manage_stack_variable(
    function_address: Annotated[str, "Address of the function containing the stack variable"],
    action: Annotated[str, "Action to perform: 'create', 'delete', 'rename', or 'set_type'"],
    variable_name: Annotated[str, "Name of the stack variable"],
    offset: Annotated[str, "Offset for create action (required for create)"] = None,
    new_name: Annotated[str, "New name for rename action (required for rename)"] = None,
    type_name: Annotated[str, "Type name for create/set_type actions (required for create and set_type)"] = None
):
    """Manage stack frame variables: create, delete, rename, or set type"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        raise IDAError("No frame returned.")

    if action == "create":
        if not offset or not type_name:
            raise IDAError("create action requires 'offset' and 'type_name' parameters")

        offset_addr = parse_address(offset)
        tif = get_type_by_name(type_name)
        if not ida_frame.define_stkvar(func, variable_name, offset_addr, tif):
            raise IDAError("failed to define stack frame variable")

    elif action == "delete":
        idx, udm = frame_tif.get_udm(variable_name)
        if not udm:
            raise IDAError(f"{variable_name} not found.")

        tid = frame_tif.get_udm_tid(idx)
        if ida_frame.is_special_frame_member(tid):
            raise IDAError(f"{variable_name} is a special frame member. Will not delete.")

        udm = ida_typeinf.udm_t()
        frame_tif.get_udm_by_tid(udm, tid)
        offset_val = udm.offset // 8
        size = udm.size // 8
        if ida_frame.is_funcarg_off(func, offset_val):
            raise IDAError(f"{variable_name} is an argument member. Will not delete.")

        if not ida_frame.delete_frame_members(func, offset_val, offset_val+size):
            raise IDAError("failed to delete stack frame variable")

    elif action == "rename":
        if not new_name:
            raise IDAError("rename action requires 'new_name' parameter")

        idx, udm = frame_tif.get_udm(variable_name)
        if not udm:
            raise IDAError(f"{variable_name} not found.")

        tid = frame_tif.get_udm_tid(idx)
        if ida_frame.is_special_frame_member(tid):
            raise IDAError(f"{variable_name} is a special frame member. Will not change the name.")

        udm = ida_typeinf.udm_t()
        frame_tif.get_udm_by_tid(udm, tid)
        offset_val = udm.offset // 8
        if ida_frame.is_funcarg_off(func, offset_val):
            raise IDAError(f"{variable_name} is an argument member. Will not change the name.")

        sval = ida_frame.soff_to_fpoff(func, offset_val)
        if not ida_frame.define_stkvar(func, new_name, sval, udm.type):
            raise IDAError("failed to rename stack frame variable")

    elif action == "set_type":
        if not type_name:
            raise IDAError("set_type action requires 'type_name' parameter")

        idx, udm = frame_tif.get_udm(variable_name)
        if not udm:
            raise IDAError(f"{variable_name} not found.")

        tid = frame_tif.get_udm_tid(idx)
        udm = ida_typeinf.udm_t()
        frame_tif.get_udm_by_tid(udm, tid)
        offset_val = udm.offset // 8

        tif = get_type_by_name(type_name)
        if not ida_frame.set_frame_member_type(func, offset_val, tif):
            raise IDAError("failed to set stack frame variable type")

    else:
        raise IDAError(f"Invalid action '{action}'. Must be 'create', 'delete', 'rename', or 'set_type'.")

@jsonrpc
@idaread
def read_memory_bytes(
        memory_address: Annotated[str, "Address of the memory value to be read"],
        size: Annotated[int, "size of memory to read"]
) -> str:
    """
    Read bytes at a given address.

    Only use this function if `get_global_variable_at` and `get_global_variable_by_name`
    both failed.
    """
    return ' '.join(f'{x:#02x}' for x in ida_bytes.get_bytes(parse_address(memory_address), size))


@jsonrpc
@idawrite
def write_memory_bytes(
        address: Annotated[str, "Address where bytes should be patched"],
        data: Annotated[str, "Hex-encoded byte string (spaces and newlines ignored)"]
) -> str:
    """Patch raw bytes at the specified address."""

    ea = parse_address(address)
    cleaned = "".join(ch for ch in data.split())
    if len(cleaned) == 0:
        raise IDAError("No data provided to write")
    if len(cleaned) % 2 != 0:
        raise IDAError("Hex data must contain an even number of characters")

    try:
        payload = bytes.fromhex(cleaned)
    except ValueError:
        raise IDAError("Data must be a valid hex string")

    ida_bytes.patch_bytes(ea, payload)

    func = idaapi.get_func(ea)
    if func:
        refresh_decompiler_ctext(func.start_ea)

    return f"Wrote {len(payload)} bytes to {hex(ea)}"

@jsonrpc
@idaread
def data_read_byte(
        address: Annotated[str, "Address to get 1 byte value from"],
) -> int:
    """
    Read the 1 byte value at the specified address.

    Only use this function if `get_global_variable_at` failed.
    """
    ea = parse_address(address)
    return ida_bytes.get_wide_byte(ea)

@jsonrpc
@idaread
def read_integer(
    address: Annotated[str, "Address to read integer from"],
    size: Annotated[int, "Size in bytes: 1 (byte), 2 (word), 4 (dword), or 8 (qword)"]
) -> int:
    """
    Read an integer value at the specified address with given size.

    Only use this function if `get_global_variable_at` failed.
    """
    ea = parse_address(address)
    if size == 1:
        return ida_bytes.get_wide_byte(ea)
    elif size == 2:
        return ida_bytes.get_wide_word(ea)
    elif size == 4:
        return ida_bytes.get_wide_dword(ea)
    elif size == 8:
        return ida_bytes.get_qword(ea)
    else:
        raise IDAError(f"Invalid size {size}. Must be 1, 2, 4, or 8 bytes.")

@jsonrpc
@idaread
def data_read_string(
        address: Annotated[str, "Address to get string from"]
) -> str:
    """
    Read the string at the specified address.

    Only use this function if `get_global_variable_at` failed.
    """
    try:
        return idaapi.get_strlit_contents(parse_address(address),-1,0).decode("utf-8")
    except Exception as e:
        return "Error:" + str(e)


@jsonrpc
@idawrite
def execute_python_script(
    script: Annotated[str, "Python script to execute"],
) -> PythonScriptResult:
    """Execute a Python script inside IDA and capture its output."""

    global SCRIPT_EXECUTION_GLOBALS

    if not SCRIPT_EXECUTION_GLOBALS:
        SCRIPT_EXECUTION_GLOBALS = {
            "__name__": "__mcp_script__",
            "__builtins__": __builtins__,
        }
        SCRIPT_EXECUTION_GLOBALS.update(globals())

    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    success = True
    error: Optional[str] = None

    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
        try:
            exec(compile(script, "<mcp-script>", "exec"), SCRIPT_EXECUTION_GLOBALS)
        except Exception as exc:
            success = False
            error = str(exc)
            traceback.print_exc(file=stderr_buffer)

    return PythonScriptResult(
        stdout=stdout_buffer.getvalue(),
        stderr=stderr_buffer.getvalue(),
        success=success,
        error=error,
    )


@jsonrpc
@idaread
@unsafe
def get_debug_state(
    query_type: Annotated[str, "Type of debug state to query: 'registers', 'callstack', or 'breakpoints'"]
):
    """Get debugger state information: registers, call stack, or breakpoints"""
    if query_type == "registers":
        result = []
        dbg = ida_idd.get_dbg()
        # TODO: raise an exception when not debugging?
        for thread_index in range(ida_dbg.get_thread_qty()):
            tid = ida_dbg.getn_thread(thread_index)
            regs = []
            regvals = ida_dbg.get_reg_vals(tid)
            for reg_index, rv in enumerate(regvals):
                reg_info = dbg.regs(reg_index)
                reg_value = rv.pyval(reg_info.dtype)
                if isinstance(reg_value, int):
                    reg_value = hex(reg_value)
                if isinstance(reg_value, bytes):
                    reg_value = reg_value.hex(" ")
                regs.append({
                    "name": reg_info.name,
                    "value": reg_value,
                })
            result.append({
                "thread_id": tid,
                "registers": regs,
            })
        return result

    elif query_type == "callstack":
        callstack = []
        try:
            tid = ida_dbg.get_current_thread()
            trace = ida_idd.call_stack_t()

            if not ida_dbg.collect_stack_trace(tid, trace):
                return []
            for frame in trace:
                frame_info = {
                    "address": hex(frame.callea),
                }
                try:
                    module_info = ida_idd.modinfo_t()
                    if ida_dbg.get_module_info(frame.callea, module_info):
                        frame_info["module"] = os.path.basename(module_info.name)
                    else:
                        frame_info["module"] = "<unknown>"

                    name = (
                        ida_name.get_nice_colored_name(
                            frame.callea,
                            ida_name.GNCN_NOCOLOR
                            | ida_name.GNCN_NOLABEL
                            | ida_name.GNCN_NOSEG
                            | ida_name.GNCN_PREFDBG,
                        )
                        or "<unnamed>"
                    )
                    frame_info["symbol"] = name

                except Exception as e:
                    frame_info["module"] = "<error>"
                    frame_info["symbol"] = str(e)

                callstack.append(frame_info)

        except Exception as e:
            pass
        return callstack

    elif query_type == "breakpoints":
        ea = ida_ida.inf_get_min_ea()
        end_ea = ida_ida.inf_get_max_ea()
        breakpoints = []
        while ea <= end_ea:
            bpt = ida_dbg.bpt_t()
            if ida_dbg.get_bpt(ea, bpt):
                breakpoints.append(
                    {
                        "ea": hex(bpt.ea),
                        "type": bpt.type,
                        "enabled": bpt.flags & ida_dbg.BPT_ENABLED,
                        "condition": bpt.condition if bpt.condition else None,
                    }
                )
            ea = ida_bytes.next_head(ea, end_ea)
        return breakpoints

    else:
        raise IDAError(f"Invalid query_type '{query_type}'. Must be 'registers', 'callstack', or 'breakpoints'.")

@jsonrpc
@idaread
@unsafe
def control_debugger(
    action: Annotated[str, "Debugger action: 'start', 'exit', 'continue', or 'run_to'"],
    address: Annotated[str, "Address for 'run_to' action (required only for run_to)"] = None
) -> str:
    """Control debugger execution: start, exit, continue, or run to address"""
    if action == "start":
        if idaapi.start_process("", "", ""):
            return "Debugger started"
        return "Failed to start debugger"

    elif action == "exit":
        if idaapi.exit_process():
            return "Debugger exited"
        return "Failed to exit debugger"

    elif action == "continue":
        if idaapi.continue_process():
            return "Debugger continued"
        return "Failed to continue debugger"

    elif action == "run_to":
        if not address:
            raise IDAError("run_to action requires 'address' parameter")
        ea = parse_address(address)
        if idaapi.run_to(ea):
            return f"Debugger run to {hex(ea)}"
        return f"Failed to run to address {hex(ea)}"

    else:
        raise IDAError(f"Invalid action '{action}'. Must be 'start', 'exit', 'continue', or 'run_to'.")

@jsonrpc
@idaread
@unsafe
def manage_breakpoint(
    action: Annotated[str, "Breakpoint action: 'set', 'delete', or 'toggle'"],
    address: Annotated[str, "Address of the breakpoint"],
    enabled: Annotated[bool, "Enable state for 'toggle' action (required only for toggle)"] = None
) -> str:
    """Manage breakpoints: set, delete, or toggle enable state"""
    ea = parse_address(address)

    if action == "set":
        if idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT):
            return f"Breakpoint set at {hex(ea)}"
        # Check if breakpoint already exists
        bpt = ida_dbg.bpt_t()
        if ida_dbg.get_bpt(ea, bpt):
            return f"Breakpoint already exists at {hex(ea)}"
        return f"Failed to set breakpoint at address {hex(ea)}"

    elif action == "delete":
        if idaapi.del_bpt(ea):
            return f"Breakpoint deleted at {hex(ea)}"
        return f"Failed to delete breakpoint at address {hex(ea)}"

    elif action == "toggle":
        if enabled is None:
            raise IDAError("toggle action requires 'enabled' parameter")
        if idaapi.enable_bpt(ea, enabled):
            return f"Breakpoint {'enabled' if enabled else 'disabled'} at {hex(ea)}"
        return f"Failed to {'enable' if enabled else 'disable'} breakpoint at address {hex(ea)}"

    else:
        raise IDAError(f"Invalid action '{action}'. Must be 'set', 'delete', or 'toggle'.")


@jsonrpc
@idaread
def discover_resources(
    context: Annotated[str, "Optional navigation context such as 'function:0x401000'"] = "",
) -> dict:
    """Expose discoverable links to MCP functionality (HATEOAS-style navigation)."""

    ctx = context.strip()
    result: dict[str, Any] = {
        "context": ctx or "root",
        "counts": {
            "available_methods": len(rpc_registry.methods),
            "unsafe_methods": len(rpc_registry.unsafe),
        },
    }

    links: list[Link] = [Link(rel="self", method="discover_resources", params={"context": ctx})]

    base_links: list[Link] = [
        Link(
            rel="functions",
            method="list_functions",
            description="List functions (provide offset/count)",
            params={"offset": 0, "count": 100},
        ),
        Link(
            rel="globals",
            method="list_globals",
            description="List globals (provide offset/count)",
            params={"offset": 0, "count": 100, "filter": ""},
        ),
        Link(
            rel="strings",
            method="list_strings",
            description="List strings (provide offset/count)",
            params={"offset": 0, "count": 100, "filter": ""},
        ),
        Link(
            rel="structures",
            method="map_program_structures",
            description="Summarize program structures and relationships",
            params={"limit": 50},
        ),
        Link(
            rel="decompile",
            method="decompile_function",
            description="Decompile a function (provide an address)",
            params={"address": "<function_address>"},
        ),
        Link(
            rel="call-graph",
            method="analyze_call_graph",
            description="Generate a call graph (provide an address)",
            params={"address": "<function_address>"},
        ),
        Link(
            rel="data-flow",
            method="analyze_data_flow",
            description="Analyze data flow (provide an address)",
            params={"address": "<function_address>"},
        ),
        Link(
            rel="memory-read",
            method="read_memory_bytes",
            description="Read raw memory bytes",
            params={"memory_address": "<address>", "size": 16},
        ),
        Link(
            rel="memory-write",
            method="write_memory_bytes",
            description="Patch raw bytes at an address",
            params={"address": "<address>", "data": "<hex_bytes>"},
        ),
        Link(
            rel="batch",
            method="batch_tool_calls",
            description="Execute multiple MCP tools in a single request",
            params={"requests": []},
        ),
    ]

    if not ctx or ctx.lower() == "root":
        links.extend(base_links)
    elif ctx.lower().startswith("function:"):
        addr_text = ctx.split(":", 1)[1]
        try:
            fn_ea = parse_address(addr_text)
            fn = idaapi.get_func(fn_ea)
            if not fn:
                raise IDAError("invalid function context")
        except Exception as exc:  # noqa: BLE001
            result["warning"] = f"Unable to resolve context '{context}': {exc}"
        else:
            result["function"] = get_function(fn.start_ea)
            links.extend(_build_function_links(fn.start_ea))
    else:
        result["warning"] = f"Unknown context '{context}'"

    result["links"] = links
    return result

class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    def init(self):
        self.server = Server()
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if sys.platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")
        print(f"[MCP] Plugin loaded, auto-starting server... (Use Edit -> Plugins -> MCP ({hotkey}) to restart if needed)")

        # Auto-start the server
        try:
            self.server.start()
            print("[MCP] Server started automatically")
        except Exception as e:
            print(f"[MCP] Failed to auto-start server: {e}")
            print(f"[MCP] You can manually start it with Edit -> Plugins -> MCP ({hotkey})")

        return idaapi.PLUGIN_KEEP

    def run(self, args):
        self.server.start()

    def term(self):
        self.server.stop()

def PLUGIN_ENTRY():
    return MCP()
