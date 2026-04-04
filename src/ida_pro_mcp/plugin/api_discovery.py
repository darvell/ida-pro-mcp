from __future__ import annotations

import logging
import subprocess
import sys
from typing import Any

from .rpc import rpc, IDAError
from .sync import idawrite
from .utils import _hex

logger = logging.getLogger(__name__)


# ============================================================================
# 1. open_file
# ============================================================================

@idawrite
def open_file(path: str, args: str = "") -> dict[str, Any]:
    """Launch a new IDA instance to analyze a file.

    Starts IDA in the background with the given file path.
    The new instance will register itself with the MCP server
    once analysis completes.

    Parameters:
        path: Path to the file to open in IDA
        args: Additional IDA command-line arguments (optional)

    Returns:
        ok, path, pid
    """
    import idaapi

    # Determine IDA executable path from the running instance
    ida_dir = idaapi.idadir("")
    ida_exe = sys.executable  # This is the IDA process

    cmd: list[str] = [ida_exe]
    if args:
        cmd.extend(args.split())
    cmd.append(path)

    try:
        proc = subprocess.Popen(
            cmd,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise IDAError(f"Cannot find IDA executable: {ida_exe}")
    except OSError as exc:
        raise IDAError(f"Failed to launch IDA: {exc}")

    logger.info("Launched IDA for %s (PID %d)", path, proc.pid)

    return {"ok": True, "path": path, "pid": proc.pid}


rpc.register("open_file", open_file,
             doc="Launch a new IDA instance to analyze a file.")


# ============================================================================
# 2. select_instance
# ============================================================================

def select_instance(database: str = "") -> dict[str, Any]:
    """Instance selection stub.

    Instance selection is handled by the MCP server, not the plugin.
    This method exists for API completeness.

    Parameters:
        database: Database name (handled server-side)

    Returns:
        message explaining that instance selection is a server-side operation
    """
    return {
        "ok": True,
        "message": (
            "Instance selection is managed by the MCP server. "
            "Use the server's select_instance or pass 'database' to any tool call."
        ),
    }


rpc.register("select_instance", select_instance,
             doc="Instance selection (server-side operation; this is an informational stub).")
