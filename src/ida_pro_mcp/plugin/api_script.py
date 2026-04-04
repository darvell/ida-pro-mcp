from __future__ import annotations

import ast
import contextlib
import io
import logging
from typing import Any

from .rpc import rpc, IDAError
from .sync import idawrite, batch_mode

logger = logging.getLogger(__name__)

# All standard IDA modules to pre-populate in eval/exec globals
_IDA_MODULE_NAMES = [
    "idaapi", "idc", "idautils",
    "ida_bytes", "ida_funcs", "ida_hexrays", "ida_typeinf",
    "ida_ua", "ida_xref", "ida_name", "ida_lines",
    "ida_ida", "ida_strlist", "ida_nalt", "ida_segment",
    "ida_entry", "ida_search", "ida_kernwin",
]


def _build_ida_globals() -> dict[str, Any]:
    """Import all standard IDA modules and return a globals dict."""
    g: dict[str, Any] = {"__builtins__": __builtins__}
    for mod_name in _IDA_MODULE_NAMES:
        try:
            import importlib
            g[mod_name] = importlib.import_module(mod_name)
        except ImportError:
            pass
    return g


# ============================================================================
# script_exec
# ============================================================================

@idawrite
def script_exec(script: str) -> dict[str, Any]:
    """Execute arbitrary Python code in IDA.

    Use print() to return data. Has access to all IDA modules.

    Parameters:
        script: Python code to execute

    Returns:
        ok, out (stdout), err (stderr), error (if failed)
    """
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    with batch_mode():
        try:
            with (
                contextlib.redirect_stdout(stdout_capture),
                contextlib.redirect_stderr(stderr_capture),
            ):
                exec(script, _build_ida_globals())
            return {
                "ok": True,
                "out": stdout_capture.getvalue(),
                "err": stderr_capture.getvalue(),
            }
        except Exception as exc:
            return {
                "ok": False,
                "out": stdout_capture.getvalue(),
                "err": stderr_capture.getvalue(),
                "error": str(exc),
            }


rpc.register("script_exec", script_exec,
             doc="Execute Python code in IDA.")


# ============================================================================
# py_eval
# ============================================================================

@idawrite
def py_eval(code: str) -> dict[str, Any]:
    """Jupyter-style Python execution with expression result capture.

    If the code is a single expression, its value is returned as 'result'.
    If the code ends with an expression after statements, the statements
    are executed and the trailing expression is evaluated and returned.
    If the code is pure statements, only stdout/stderr are captured.

    Parameters:
        code: Python code to execute

    Returns:
        ok, result (if expression), out (stdout), err (stderr), error (if failed)
    """
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    g = _build_ida_globals()

    with batch_mode():
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return {
                "ok": False,
                "out": "",
                "err": "",
                "error": f"SyntaxError: {exc}",
            }

        try:
            with (
                contextlib.redirect_stdout(stdout_capture),
                contextlib.redirect_stderr(stderr_capture),
            ):
                result = None
                has_result = False

                if not tree.body:
                    pass
                elif (
                    len(tree.body) == 1
                    and isinstance(tree.body[0], ast.Expr)
                ):
                    # Single expression
                    compiled = compile(
                        ast.Expression(body=tree.body[0].value),
                        "<py_eval>", "eval",
                    )
                    result = eval(compiled, g)
                    has_result = True
                elif isinstance(tree.body[-1], ast.Expr):
                    # Statements followed by a trailing expression
                    stmts = ast.Module(
                        body=tree.body[:-1], type_ignores=[]
                    )
                    compiled_stmts = compile(
                        stmts, "<py_eval>", "exec"
                    )
                    exec(compiled_stmts, g)

                    expr_node = tree.body[-1]
                    compiled_expr = compile(
                        ast.Expression(body=expr_node.value),
                        "<py_eval>", "eval",
                    )
                    result = eval(compiled_expr, g)
                    has_result = True
                else:
                    # Pure statements
                    compiled = compile(tree, "<py_eval>", "exec")
                    exec(compiled, g)

            response: dict[str, Any] = {
                "ok": True,
                "out": stdout_capture.getvalue(),
                "err": stderr_capture.getvalue(),
            }
            if has_result:
                # Convert to JSON-safe representation
                try:
                    response["result"] = _safe_repr(result)
                except Exception:
                    response["result"] = repr(result)
            return response

        except Exception as exc:
            return {
                "ok": False,
                "out": stdout_capture.getvalue(),
                "err": stderr_capture.getvalue(),
                "error": str(exc),
            }


def _safe_repr(value: Any) -> Any:
    """Convert a Python value to a JSON-safe representation."""
    if value is None:
        return None
    if isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [_safe_repr(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _safe_repr(v) for k, v in value.items()}
    return repr(value)


rpc.register("py_eval", py_eval,
             doc="Jupyter-style Python execution with expression result capture.")


# ============================================================================
# py_exec_file
# ============================================================================

@idawrite
def py_exec_file(path: str) -> dict[str, Any]:
    """Read and execute a Python file in IDA.

    Parameters:
        path: Path to the Python file

    Returns:
        ok, out (stdout), err (stderr), error (if failed)
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            script = f.read()
    except FileNotFoundError:
        return {
            "ok": False,
            "out": "",
            "err": "",
            "error": f"File not found: {path}",
        }
    except OSError as exc:
        return {
            "ok": False,
            "out": "",
            "err": "",
            "error": f"Cannot read file: {exc}",
        }

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    g = _build_ida_globals()
    g["__file__"] = path

    with batch_mode():
        try:
            with (
                contextlib.redirect_stdout(stdout_capture),
                contextlib.redirect_stderr(stderr_capture),
            ):
                exec(compile(script, path, "exec"), g)
            return {
                "ok": True,
                "out": stdout_capture.getvalue(),
                "err": stderr_capture.getvalue(),
            }
        except Exception as exc:
            return {
                "ok": False,
                "out": stdout_capture.getvalue(),
                "err": stderr_capture.getvalue(),
                "error": str(exc),
            }


rpc.register("py_exec_file", py_exec_file,
             doc="Read and execute a Python file in IDA.")
