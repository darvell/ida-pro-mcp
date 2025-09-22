import os
import sys
import ast
import json
import shutil
import argparse
import http.client
import socket
import errno
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Any, Callable, Dict, List, Optional, TypedDict
from urllib.parse import urlparse
from glob import glob

from mcp.server.fastmcp import FastMCP

# The log_level is necessary for Cline to work: https://github.com/jlowin/fastmcp/issues/81
mcp = FastMCP("ida-pro-mcp", log_level="ERROR")

BATCH_TOOL_NAME = "batch_tool_calls"

jsonrpc_request_id = 1

INSTANCE_RUNTIME_ENV = "IDA_PRO_MCP_RUNTIME_DIR"
_runtime_root = os.environ.get(INSTANCE_RUNTIME_ENV)
if _runtime_root:
    INSTANCE_REGISTRY_DIR = Path(_runtime_root) / "instances"
else:
    INSTANCE_REGISTRY_DIR = Path.home() / ".ida-pro-mcp" / "instances"


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


def _send_jsonrpc_request(socket_path: str, method: str, params: List[Any]) -> Any:
    global jsonrpc_request_id

    conn = UnixHTTPConnection(socket_path, timeout=10)
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": jsonrpc_request_id,
    }
    jsonrpc_request_id += 1

    try:
        conn.request("POST", "/mcp", json.dumps(request), {
            "Content-Type": "application/json"
        })
        response = conn.getresponse()
        payload = response.read().decode()
        data = json.loads(payload)
    finally:
        conn.close()

    if "error" in data:
        error = data["error"]
        code = error.get("code")
        message = error.get("message", "unknown error")
        pretty = f"JSON-RPC error {code}: {message}"
        if "data" in error:
            pretty += "\n" + str(error["data"])
        raise Exception(pretty)

    result = data.get("result")
    if result is None:
        result = "success"
    return result


class InstanceManager:
    _instances: Dict[str, Dict[str, Any]] = {}
    _loaded: bool = False

    @staticmethod
    def _probe_socket(path: Path) -> Optional[Dict[str, Any]]:
        try:
            metadata = _send_jsonrpc_request(str(path), "describe_instance", [])
        except FileNotFoundError:
            with suppress(FileNotFoundError):
                path.unlink()
            return None
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ECONNREFUSED):
                with suppress(FileNotFoundError):
                    path.unlink()
            return None
        except Exception:
            return None

        if not isinstance(metadata, dict):
            return None

        database = metadata.get("database")
        if not isinstance(database, str) or not database:
            return None

        metadata = dict(metadata)
        metadata["_socket"] = str(path)
        return metadata

    @classmethod
    def refresh(cls) -> None:
        cls._instances = {}
        cls._loaded = True
        if not INSTANCE_REGISTRY_DIR.exists():
            return

        for socket_path in INSTANCE_REGISTRY_DIR.glob("*.sock"):
            record = cls._probe_socket(socket_path)
            if record is None:
                continue
            cls._instances[record["database"]] = record

    @classmethod
    def _ensure_loaded(cls) -> None:
        if not cls._loaded:
            cls.refresh()

    @classmethod
    def list(cls) -> List[Dict[str, Any]]:
        cls.refresh()
        records = list(cls._instances.values())
        records.sort(key=lambda item: item.get("loaded_at", ""))
        return records

    @classmethod
    def get(cls, database: str) -> Dict[str, Any]:
        cls._ensure_loaded()
        record = cls._instances.get(database)
        if record is None:
            cls.refresh()
            record = cls._instances.get(database)
        if record is None:
            raise KeyError(database)
        return record

    @classmethod
    def invalidate(cls, database: str) -> None:
        cls._instances.pop(database, None)

def make_jsonrpc_request(database: str, method: str, *params):
    """Make a JSON-RPC request to a specific IDA plugin instance"""
    try:
        instance = InstanceManager.get(database)
    except KeyError:
        raise Exception(
            f"No IDA instance registered for database '{database}'. "
            "Use the list_instances tool to see active sessions.",
        )

    socket_path = instance.get("_socket")
    if not isinstance(socket_path, str) or not socket_path:
        raise Exception(
            f"Invalid registration for '{database}' (missing socket). "
            "Try restarting the MCP plugin inside IDA.",
        )

    try:
        return _send_jsonrpc_request(socket_path, method, list(params))
    except OSError as e:
        InstanceManager.invalidate(database)
        raise Exception(
            f"Failed to communicate with IDA instance '{database}': {e}. "
            "Use the list_instances tool to verify that the instance is still running.",
        ) from e
    except Exception:
        raise

@mcp.tool()
def check_connection(database: Annotated[str, "Database filename of the IDA instance to query"]) -> str:
    """Check if a specific IDA plugin instance is running"""
    try:
        metadata = make_jsonrpc_request(database, "get_metadata")
        return (
            f"Successfully connected to '{database}' (open module: {metadata['module']})"
        )
    except Exception as e:
        if sys.platform == "darwin":
            shortcut = "Ctrl+Option+M"
        else:
            shortcut = "Ctrl+Alt+M"
        return (
            f"Failed to connect to IDA instance '{database}': {e} "
            f"Use the list_instances tool to verify running sessions or start the plugin via Edit -> Plugins -> MCP ({shortcut})."
        )


class InstanceSummary(TypedDict, total=False):
    database: str
    status: str
    loaded_at: str
    module: Optional[str]
    input_path: Optional[str]
    idb_path: Optional[str]
    pid: Optional[int]
    runtime_socket: str


class BatchToolRequest(TypedDict, total=False):
    tool: str
    arguments: Dict[str, Any]


class BatchToolResult(TypedDict, total=False):
    index: int
    tool: str
    status: str
    arguments: Dict[str, Any]
    output: Any
    error: str
    chunk_index: int
    total_chunks: int
    output_format: str


def _coerce_to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _coerce_to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_coerce_to_jsonable(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return repr(value)


def _serialized_length(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False))
    except TypeError:
        return len(json.dumps(_coerce_to_jsonable(value), ensure_ascii=False))


def _chunk_text(text: str, size: int) -> List[str]:
    if size <= 0:
        size = 1
    if not text:
        return [""]
    return [text[i : i + size] for i in range(0, len(text), size)]


def _chunk_batch_result(entry: Dict[str, Any], char_limit: int) -> List[Dict[str, Any]]:
    base_entry = dict(entry)
    output = base_entry.pop("output", "")
    base_entry.pop("chunk_index", None)
    base_entry.pop("total_chunks", None)
    base_entry.pop("output_format", None)
    metadata_len = _serialized_length({**base_entry, "output": ""})
    available_chars = max(1, char_limit - metadata_len - 2)
    if isinstance(output, str):
        raw_output = output
        output_format = "text"
    else:
        raw_output = json.dumps(_coerce_to_jsonable(output), ensure_ascii=False)
        output_format = "json-string"
    chunks = _chunk_text(raw_output, available_chars)
    total_chunks = len(chunks)
    chunk_entries: List[Dict[str, Any]] = []
    for idx, chunk in enumerate(chunks, start=1):
        chunk_entry = dict(base_entry)
        chunk_entry["output"] = chunk
        chunk_entry["chunk_index"] = idx
        chunk_entry["total_chunks"] = total_chunks
        chunk_entry["output_format"] = output_format
        chunk_entries.append(chunk_entry)
    return chunk_entries


@mcp.tool()
def list_instances() -> List[InstanceSummary]:
    """List all currently registered IDA MCP plugin instances"""
    instances = InstanceManager.list()
    summaries: List[InstanceSummary] = []
    for instance in instances:
        summaries.append(
            InstanceSummary(
                database=instance.get("database", "<unknown>"),
                status=instance.get("status", "unknown"),
                loaded_at=instance.get("loaded_at", ""),
                module=instance.get("module"),
                input_path=instance.get("input_path"),
                idb_path=instance.get("idb_path"),
                pid=instance.get("pid"),
                runtime_socket=instance.get("_socket", ""),
            )
        )
    return summaries


@mcp.tool()
def batch_tool_calls(
    requests: Annotated[List[BatchToolRequest], "List of tool invocations to execute in order."],
    page: Annotated[int, "1-based page number of the aggregated results to return."] = 1,
    page_size_tokens: Annotated[
        int,
        "Approximate token budget per page (defaults to 25k tokens).",
    ] = 25000,
    allow_unsafe: Annotated[
        bool,
        "Allow execution of tools marked as unsafe by also passing this flag as True.",
    ] = False,
) -> Dict[str, Any]:
    """Execute multiple MCP tools sequentially and return paginated results."""

    if page <= 0:
        raise ValueError("page must be a positive integer")
    if page_size_tokens <= 0:
        raise ValueError("page_size_tokens must be a positive integer")
    if not isinstance(requests, list):
        raise ValueError("requests must be provided as a list")

    approx_char_limit = max(1, page_size_tokens) * 4
    available_functions: Dict[str, Callable[..., Any]] = {}
    for name in MCP_FUNCTIONS:
        func = globals().get(name)
        if callable(func):
            available_functions[name] = func

    results: List[BatchToolResult] = []
    for idx, request in enumerate(requests, start=1):
        if not isinstance(request, dict):
            raise ValueError(f"Request #{idx} must be an object with tool information")

        tool_name = request.get("tool")
        if not isinstance(tool_name, str) or not tool_name:
            raise ValueError(f"Request #{idx} is missing a valid tool name")
        if tool_name == BATCH_TOOL_NAME:
            raise ValueError("batch_tool_calls cannot invoke itself")
        if tool_name not in available_functions:
            raise ValueError(f"Unknown tool '{tool_name}' in request #{idx}")
        if not allow_unsafe and tool_name in UNSAFE_FUNCTIONS:
            raise ValueError(
                f"Tool '{tool_name}' is marked as unsafe. Set allow_unsafe=True to execute it."
            )

        raw_arguments = request.get("arguments") or {}
        if not isinstance(raw_arguments, dict):
            raise ValueError(f"Request #{idx} arguments must be an object")

        normalized_arguments = {str(key): value for key, value in raw_arguments.items()}
        entry: BatchToolResult = BatchToolResult(
            index=idx,
            tool=tool_name,
            status="success",
            arguments=_coerce_to_jsonable(normalized_arguments),
        )

        func = available_functions[tool_name]
        try:
            output = func(**raw_arguments)
        except Exception as exc:  # noqa: BLE001
            entry["status"] = "error"
            entry["error"] = str(exc)
        else:
            entry["output"] = _coerce_to_jsonable(output)

        results.append(entry)

    if not results:
        if page != 1:
            raise ValueError("No results available")
        return {
            "page": 1,
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
            "page_size_tokens": page_size_tokens,
            "approx_char_limit": approx_char_limit,
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "results": [],
        }

    pages: List[List[BatchToolResult]] = []
    current_page: List[BatchToolResult] = []
    current_length = 0

    for entry in results:
        entry_length = _serialized_length(entry)
        if entry_length > approx_char_limit:
            chunked_entries = _chunk_batch_result(entry, approx_char_limit)
            for chunk in chunked_entries:
                chunk_length = _serialized_length(chunk)
                if current_page and current_length + chunk_length > approx_char_limit:
                    pages.append(current_page)
                    current_page = []
                    current_length = 0
                current_page.append(chunk)
                current_length += chunk_length
            continue

        if current_page and current_length + entry_length > approx_char_limit:
            pages.append(current_page)
            current_page = []
            current_length = 0

        current_page.append(entry)
        current_length += entry_length

    if current_page:
        pages.append(current_page)
    if not pages:
        pages.append([])

    total_pages = len(pages)
    if page > total_pages:
        raise ValueError(f"Requested page {page} is out of range (max {total_pages})")

    success_count = sum(1 for entry in results if entry["status"] == "success")
    failure_count = len(results) - success_count

    page_results = pages[page - 1]

    return {
        "page": page,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
        "page_size_tokens": page_size_tokens,
        "approx_char_limit": approx_char_limit,
        "total_requests": len(results),
        "successful_requests": success_count,
        "failed_requests": failure_count,
        "results": page_results,
    }


# Code taken from https://github.com/mrexodia/ida-pro-mcp (MIT License)
class MCPVisitor(ast.NodeVisitor):
    def __init__(self):
        self.types: dict[str, ast.ClassDef] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.descriptions: dict[str, str] = {}
        self.unsafe: list[str] = []

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id == "jsonrpc":
                    database_arg = ast.arg(
                        arg="database",
                        annotation=ast.Subscript(
                            value=ast.Name(id="Annotated", ctx=ast.Load()),
                            slice=ast.Tuple(
                                elts=[
                                    ast.Name(id="str", ctx=ast.Load()),
                                    ast.Constant(
                                        value="Database filename of the IDA instance to query",
                                    ),
                                ],
                                ctx=ast.Load(),
                            ),
                            ctx=ast.Load(),
                        ),
                        type_comment=None,
                    )
                    for i, arg in enumerate(node.args.args):
                        arg_name = arg.arg
                        arg_type = arg.annotation
                        if arg_type is None:
                            raise Exception(f"Missing argument type for {node.name}.{arg_name}")
                        if isinstance(arg_type, ast.Subscript):
                            assert isinstance(arg_type.value, ast.Name)
                            assert arg_type.value.id == "Annotated"
                            assert isinstance(arg_type.slice, ast.Tuple)
                            assert len(arg_type.slice.elts) == 2
                            annot_type = arg_type.slice.elts[0]
                            annot_description = arg_type.slice.elts[1]
                            assert isinstance(annot_description, ast.Constant)
                            node.args.args[i].annotation = ast.Subscript(
                                value=ast.Name(id="Annotated", ctx=ast.Load()),
                                slice=ast.Tuple(
                                    elts=[
                                    annot_type,
                                    ast.Call(
                                        func=ast.Name(id="Field", ctx=ast.Load()),
                                        args=[],
                                        keywords=[
                                        ast.keyword(
                                            arg="description",
                                            value=annot_description)])],
                                    ctx=ast.Load()),
                                ctx=ast.Load())
                        elif isinstance(arg_type, ast.Name):
                            pass
                        else:
                            raise Exception(f"Unexpected type annotation for {node.name}.{arg_name} -> {type(arg_type)}")

                    body_comment = node.body[0]
                    if isinstance(body_comment, ast.Expr) and isinstance(body_comment.value, ast.Constant):
                        new_body = [body_comment]
                        self.descriptions[node.name] = body_comment.value.value
                    else:
                        new_body = []

                    call_args = [ast.Name(id="database", ctx=ast.Load()), ast.Constant(value=node.name)]
                    for arg in node.args.args:
                        call_args.append(ast.Name(id=arg.arg, ctx=ast.Load()))
                    new_body.append(ast.Return(
                        value=ast.Call(
                            func=ast.Name(id="make_jsonrpc_request", ctx=ast.Load()),
                            args=call_args,
                            keywords=[])))
                    decorator_list = [
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id="mcp", ctx=ast.Load()),
                                attr="tool",
                                ctx=ast.Load()),
                            args=[],
                            keywords=[]
                        )
                    ]
                    new_args = ast.arguments(
                        posonlyargs=list(node.args.posonlyargs),
                        args=[database_arg] + list(node.args.args),
                        vararg=node.args.vararg,
                        kwonlyargs=list(node.args.kwonlyargs),
                        kw_defaults=list(node.args.kw_defaults),
                        kwarg=node.args.kwarg,
                        defaults=list(node.args.defaults),
                    )
                    node_nobody = ast.FunctionDef(
                        node.name,
                        new_args,
                        new_body,
                        decorator_list,
                        node.returns,
                        node.type_comment,
                        lineno=node.lineno,
                        col_offset=node.col_offset,
                    )
                    assert node.name not in self.functions, f"Duplicate function: {node.name}"
                    self.functions[node.name] = node_nobody
                elif decorator.id == "unsafe":
                    self.unsafe.append(node.name)

    def visit_ClassDef(self, node):
        for base in node.bases:
            if isinstance(base, ast.Name):
                if base.id == "TypedDict":
                    self.types[node.name] = node


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PY = os.path.join(SCRIPT_DIR, "mcp-plugin.py")
GENERATED_PY = os.path.join(SCRIPT_DIR, "server_generated.py")

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PY):
    raise RuntimeError(f"IDA plugin not found at {IDA_PLUGIN_PY} (did you move it?)")
with open(IDA_PLUGIN_PY, "r", encoding="utf-8") as f:
    code = f.read()
module = ast.parse(code, IDA_PLUGIN_PY)
visitor = MCPVisitor()
visitor.visit(module)
code = """# NOTE: This file has been automatically generated, do not modify!
# Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)
import sys
if sys.version_info >= (3, 12):
    from typing import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
else:
    from typing_extensions import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
from pydantic import Field

T = TypeVar("T")

"""
for type in visitor.types.values():
    code += ast.unparse(type)
    code += "\n\n"
for function in visitor.functions.values():
    code += ast.unparse(function)
    code += "\n\n"

try:
    if os.path.exists(GENERATED_PY):
        with open(GENERATED_PY, "rb") as f:
            existing_code_bytes = f.read()
    else:
        existing_code_bytes = b""
    code_bytes = code.encode("utf-8").replace(b"\r", b"")
    if code_bytes != existing_code_bytes:
        with open(GENERATED_PY, "wb") as f:
            f.write(code_bytes)
except:
    print(f"Failed to generate code: {GENERATED_PY}", file=sys.stderr, flush=True)

exec(compile(code, GENERATED_PY, "exec"))

MCP_FUNCTIONS = ["check_connection", "list_instances"] + list(visitor.functions.keys())
UNSAFE_FUNCTIONS = visitor.unsafe
SAFE_FUNCTIONS = [f for f in MCP_FUNCTIONS if f not in UNSAFE_FUNCTIONS]

if BATCH_TOOL_NAME not in MCP_FUNCTIONS:
    MCP_FUNCTIONS.append(BATCH_TOOL_NAME)
    if BATCH_TOOL_NAME not in UNSAFE_FUNCTIONS:
        SAFE_FUNCTIONS.append(BATCH_TOOL_NAME)

def generate_readme():
    print("README:")
    print(
        "- `check_connection(database)`: Check if the IDA plugin instance for"
        " the given database filename is reachable."
    )
    print("- `list_instances()`: List all currently registered IDA databases.")
    print(
        "- `batch_tool_calls(requests, page=1, page_size_tokens=25000, allow_unsafe=False)`: "
        "Execute multiple MCP tools sequentially and retrieve paginated results."
    )
    def get_description(name: str):
        function = visitor.functions.get(name)
        if function is None:
            return None
        signature = function.name + "("
        for i, arg in enumerate(function.args.args):
            if i > 0:
                signature += ", "
            signature += arg.arg
        signature += ")"
        description = visitor.descriptions.get(function.name, "<no description>").strip()
        if description[-1] != ".":
            description += "."
        return f"- `{signature}`: {description}"
    for safe_function in SAFE_FUNCTIONS:
        description = get_description(safe_function)
        if description is not None:
            print(description)
    print("\nUnsafe functions (`--unsafe` flag required):\n")
    for unsafe_function in UNSAFE_FUNCTIONS:
        description = get_description(unsafe_function)
        if description is not None:
            print(description)
    print("\nMCP Config:")
    mcp_config = {
        "mcpServers": {
            "github.com/mrexodia/ida-pro-mcp": {
            "command": "uv",
            "args": [
                "--directory",
                "c:\\MCP\\ida-pro-mcp",
                "run",
                "server.py",
                "--install-plugin"
            ],
            "timeout": 1800,
            "disabled": False,
            }
        }
    }
    print(json.dumps(mcp_config, indent=2))

def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable

def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result

def print_mcp_config():
    mcp_config = {
        "command": get_python_executable(),
        "args": [
            __file__,
        ],
        "timeout": 1800,
        "disabled": False,
    }
    env = {}
    if copy_python_env(env):
        print(f"[WARNING] Custom Python environment variables detected")
        mcp_config["env"] = env
    print(json.dumps({
            "mcpServers": {
                mcp.name: mcp_config
            }
        }, indent=2)
    )

def install_mcp_servers(*, uninstall=False, quiet=False, env={}):
    if sys.platform == "win32":
        configs = {
            "Cline": (os.path.join(os.getenv("APPDATA"), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.getenv("APPDATA"), "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.getenv("APPDATA"), "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.getenv("APPDATA"), "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(config_path, "r", encoding="utf-8") as f:
                data = f.read().strip()
                if len(data) == 0:
                    config = {}
                else:
                    try:
                        config = json.loads(data)
                    except json.decoder.JSONDecodeError:
                        if not quiet:
                            print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)")
                        continue
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        mcp_servers = config["mcpServers"]
        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]
        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                continue
            del mcp_servers[mcp.name]
        else:
            # Copy environment variables from the existing server if present
            if mcp.name in mcp_servers:
                for key, value in mcp_servers[mcp.name].get("env", {}):
                    env[key] = value
            if copy_python_env(env):
                print(f"[WARNING] Custom Python environment variables detected")
            mcp_servers[mcp.name] = {
                "command": get_python_executable(),
                "args": [
                    __file__,
                ],
                "timeout": 1800,
                "disabled": False,
                "autoApprove": SAFE_FUNCTIONS,
                "alwaysAllow": SAFE_FUNCTIONS,
            }
            if env:
                mcp_servers[mcp.name]["env"] = env
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(f"{action} {name} MCP server (restart required)\n  Config: {config_path}")
        installed += 1
    if not uninstall and installed == 0:
        print("No MCP servers installed. For unsupported MCP clients, use the following config:\n")
        print_mcp_config()

def install_ida_plugin(*, uninstall: bool = False, quiet: bool = False):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.getenv("APPDATA"), "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    free_licenses = glob(os.path.join(ida_folder, "idafree_*.hexlic"))
    if len(free_licenses) > 0:
        print(f"IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead.")
        sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    plugin_destination = os.path.join(ida_plugin_folder, "mcp-plugin.py")
    if uninstall:
        if not os.path.exists(plugin_destination):
            print(f"Skipping IDA plugin uninstall\n  Path: {plugin_destination} (not found)")
            return
        os.remove(plugin_destination)
        if not quiet:
            print(f"Uninstalled IDA plugin\n  Path: {plugin_destination}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Skip if symlink already up to date
        realpath = os.path.realpath(plugin_destination)
        if realpath == IDA_PLUGIN_PY:
            if not quiet:
                print(f"Skipping IDA plugin installation (symlink up to date)\n  Plugin: {realpath}")
        else:
            # Remove existing plugin
            if os.path.lexists(plugin_destination):
                os.remove(plugin_destination)

            # Symlink or copy the plugin
            try:
                os.symlink(IDA_PLUGIN_PY, plugin_destination)
            except OSError:
                shutil.copy(IDA_PLUGIN_PY, plugin_destination)

            if not quiet:
                print(f"Installed IDA Pro plugin (IDA restart required)\n  Plugin: {plugin_destination}")

def main():
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="Install the MCP Server and IDA plugin")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall the MCP Server and IDA plugin")
    parser.add_argument("--generate-docs", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--install-plugin", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)")
    parser.add_argument("--config", action="store_true", help="Generate MCP config JSON")
    args = parser.parse_args()

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin()
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True)
        install_mcp_servers(uninstall=True)
        return

    # NOTE: Developers can use this to generate the README
    if args.generate_docs:
        generate_readme()
        return

    # NOTE: This is silent for automated Cline installations
    if args.install_plugin:
        install_ida_plugin(quiet=True)

    if args.config:
        print_mcp_config()
        return

    # Remove unsafe tools
    if not args.unsafe:
        mcp_tools = mcp._tool_manager._tools
        for unsafe in UNSAFE_FUNCTIONS:
            if unsafe in mcp_tools:
                del mcp_tools[unsafe]

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            mcp.settings.host = url.hostname
            mcp.settings.port = url.port
            # NOTE: npx @modelcontextprotocol/inspector for debugging
            print(f"MCP Server availabile at http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.settings.log_level = "INFO"
            mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
