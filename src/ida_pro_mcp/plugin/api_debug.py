from __future__ import annotations

import logging
from typing import Any

import idaapi
import idc

try:
    import ida_dbg
except ImportError:
    ida_dbg = None

try:
    import ida_idd
except ImportError:
    ida_idd = None

from .rpc import rpc, IDAError
from .sync import idaread, idawrite
from .utils import parse_ea, _hex

logger = logging.getLogger(__name__)


# ============================================================================
# Helper
# ============================================================================

def _check_debugger() -> None:
    """Raise IDAError if the debugger module is unavailable or not active."""
    if ida_dbg is None:
        raise IDAError("Debugger module (ida_dbg) is not available in this IDA build")
    if not ida_dbg.is_debugger_on():
        raise IDAError("Debugger is not active. Start the debugger first with dbg_start.")


# ============================================================================
# 1. dbg_start
# ============================================================================

@idawrite
def dbg_start(path: str = "", args: str = "") -> dict[str, Any]:
    """Start the debugger.

    If no path is provided, uses the current IDB's input file.

    Parameters:
        path: Executable path (optional)
        args: Command-line arguments (optional)

    Returns:
        ok, path, pid
    """
    if ida_dbg is None:
        raise IDAError("Debugger module (ida_dbg) is not available")

    if not path:
        path = idaapi.get_input_file_path() or ""
    if not path:
        raise IDAError("No executable path specified and no input file in IDB")

    if args:
        idc.set_process_options("", args, "")

    pid = ida_dbg.start_process(path, args, "")
    if pid <= 0:
        raise IDAError(f"Failed to start debugger for '{path}'")

    return {"ok": True, "path": path, "pid": pid}


rpc.register("dbg_start", dbg_start,
             doc="Start the debugger session.")


# ============================================================================
# 2. dbg_exit
# ============================================================================

@idawrite
def dbg_exit() -> dict[str, Any]:
    """Terminate the debugger session.

    Returns:
        ok
    """
    _check_debugger()
    ida_dbg.exit_process()
    return {"ok": True}


rpc.register("dbg_exit", dbg_exit,
             doc="Terminate the debugger session.")


# ============================================================================
# 3. dbg_continue
# ============================================================================

@idawrite
def dbg_continue() -> dict[str, Any]:
    """Continue execution.

    Returns:
        ok
    """
    _check_debugger()
    ida_dbg.continue_process()
    return {"ok": True}


rpc.register("dbg_continue", dbg_continue,
             doc="Continue debugger execution.")


# ============================================================================
# 4. dbg_run_to
# ============================================================================

@idawrite
def dbg_run_to(address: str) -> dict[str, Any]:
    """Run execution to a specific address.

    Parameters:
        address: Target address (hex)

    Returns:
        ok, addr
    """
    _check_debugger()
    ea = parse_ea(address)
    ida_dbg.run_to(ea)
    return {"ok": True, "addr": _hex(ea)}


rpc.register("dbg_run_to", dbg_run_to,
             doc="Run debugger execution to a specific address.")


# ============================================================================
# 5. dbg_step_into
# ============================================================================

@idawrite
def dbg_step_into() -> dict[str, Any]:
    """Step into the next instruction.

    Returns:
        ok
    """
    _check_debugger()
    ida_dbg.step_into()
    return {"ok": True}


rpc.register("dbg_step_into", dbg_step_into,
             doc="Step into the next instruction.")


# ============================================================================
# 6. dbg_step_over
# ============================================================================

@idawrite
def dbg_step_over() -> dict[str, Any]:
    """Step over the next instruction.

    Returns:
        ok
    """
    _check_debugger()
    ida_dbg.step_over()
    return {"ok": True}


rpc.register("dbg_step_over", dbg_step_over,
             doc="Step over the next instruction.")


# ============================================================================
# 7. dbg_bps
# ============================================================================

@idaread
def dbg_bps() -> dict[str, Any]:
    """List all breakpoints.

    Returns:
        breakpoints: [{addr, size, type, enabled}], count
    """
    if ida_dbg is None:
        raise IDAError("Debugger module (ida_dbg) is not available")

    bps: list[dict[str, Any]] = []
    count = ida_dbg.get_bpt_qty()
    for i in range(count):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            bps.append({
                "addr": _hex(bpt.ea),
                "size": bpt.size,
                "type": bpt.type,
                "enabled": bool(bpt.flags & ida_dbg.BPT_ENABLED) if hasattr(ida_dbg, "BPT_ENABLED") else True,
            })

    return {"breakpoints": bps, "count": len(bps)}


rpc.register("dbg_bps", dbg_bps,
             doc="List all breakpoints.")


# ============================================================================
# 8. dbg_add_bp
# ============================================================================

@idawrite
def dbg_add_bp(address: str) -> dict[str, Any]:
    """Add a breakpoint at an address.

    Parameters:
        address: Breakpoint address (hex)

    Returns:
        ok, addr
    """
    if ida_dbg is None:
        raise IDAError("Debugger module (ida_dbg) is not available")

    ea = parse_ea(address)
    if not ida_dbg.add_bpt(ea):
        raise IDAError(f"Cannot add breakpoint at {_hex(ea)}")

    return {"ok": True, "addr": _hex(ea)}


rpc.register("dbg_add_bp", dbg_add_bp,
             doc="Add a breakpoint at an address.")


# ============================================================================
# 9. dbg_delete_bp
# ============================================================================

@idawrite
def dbg_delete_bp(address: str) -> dict[str, Any]:
    """Delete a breakpoint at an address.

    Parameters:
        address: Breakpoint address (hex)

    Returns:
        ok, addr
    """
    if ida_dbg is None:
        raise IDAError("Debugger module (ida_dbg) is not available")

    ea = parse_ea(address)
    if not ida_dbg.del_bpt(ea):
        raise IDAError(f"No breakpoint to delete at {_hex(ea)}")

    return {"ok": True, "addr": _hex(ea)}


rpc.register("dbg_delete_bp", dbg_delete_bp,
             doc="Delete a breakpoint at an address.")


# ============================================================================
# 10. dbg_toggle_bp
# ============================================================================

@idawrite
def dbg_toggle_bp(address: str) -> dict[str, Any]:
    """Toggle a breakpoint's enabled/disabled state.

    Parameters:
        address: Breakpoint address (hex)

    Returns:
        ok, addr, enabled
    """
    if ida_dbg is None:
        raise IDAError("Debugger module (ida_dbg) is not available")

    ea = parse_ea(address)
    bpt = ida_dbg.bpt_t()
    if not ida_dbg.get_bpt(ea, bpt):
        raise IDAError(f"No breakpoint at {_hex(ea)}")

    new_state = not bool(bpt.flags & ida_dbg.BPT_ENABLED) if hasattr(ida_dbg, "BPT_ENABLED") else True
    if not ida_dbg.enable_bpt(ea, new_state):
        raise IDAError(f"Cannot toggle breakpoint at {_hex(ea)}")

    return {"ok": True, "addr": _hex(ea), "enabled": new_state}


rpc.register("dbg_toggle_bp", dbg_toggle_bp,
             doc="Toggle a breakpoint's enabled/disabled state.")


# ============================================================================
# 11. dbg_regs
# ============================================================================

@idaread
def dbg_regs() -> dict[str, Any]:
    """Read general purpose registers.

    Returns:
        registers: {name: value}, count
    """
    _check_debugger()

    regs: dict[str, Any] = {}
    rv = ida_dbg.regval_t()

    # Get the first register group (general purpose)
    if ida_idd is not None:
        reg_info_list = ida_idd.dbg_get_registers()
        if reg_info_list:
            for ri in reg_info_list:
                name = ri.name
                if ida_dbg.get_reg_val(name, rv):
                    regs[name] = _hex(rv.ival)
    else:
        # Fallback: try common register names
        for name in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
                      "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
            if ida_dbg.get_reg_val(name, rv):
                regs[name] = _hex(rv.ival)

    return {"registers": regs, "count": len(regs)}


rpc.register("dbg_regs", dbg_regs,
             doc="Read general purpose registers.")


# ============================================================================
# 12. dbg_regs_all
# ============================================================================

@idaread
def dbg_regs_all() -> dict[str, Any]:
    """Read all register groups.

    Returns:
        groups: [{name, registers: {name: value}}], count
    """
    _check_debugger()

    groups: list[dict[str, Any]] = []
    rv = ida_dbg.regval_t()

    if ida_idd is not None:
        reg_info_list = ida_idd.dbg_get_registers()
        if reg_info_list:
            # Group registers - IDA doesn't expose groups directly via ida_idd,
            # so we return them all in one group
            group_regs: dict[str, Any] = {}
            for ri in reg_info_list:
                name = ri.name
                if ida_dbg.get_reg_val(name, rv):
                    group_regs[name] = _hex(rv.ival)
            if group_regs:
                groups.append({"name": "all", "registers": group_regs})

    return {"groups": groups, "count": len(groups)}


rpc.register("dbg_regs_all", dbg_regs_all,
             doc="Read all register groups.")


# ============================================================================
# 13. dbg_stacktrace
# ============================================================================

@idaread
def dbg_stacktrace() -> dict[str, Any]:
    """Get the current call stack.

    Returns:
        frames: [{index, addr, func_name, return_addr}], count
    """
    _check_debugger()

    trace = ida_dbg.call_stack_t()
    if not ida_dbg.get_call_stack(trace):
        raise IDAError("Cannot retrieve call stack")

    frames: list[dict[str, Any]] = []
    for i in range(trace.size()):
        entry = trace[i]
        ea = entry.callea
        func_name = idaapi.get_func_name(ea) or ""
        frames.append({
            "index": i,
            "addr": _hex(ea),
            "func_name": func_name,
            "return_addr": _hex(entry.caller) if hasattr(entry, "caller") else "",
        })

    return {"frames": frames, "count": len(frames)}


rpc.register("dbg_stacktrace", dbg_stacktrace,
             doc="Get the current call stack.")


# ============================================================================
# 14. dbg_read
# ============================================================================

@idaread
def dbg_read(address: str, size: int = 64) -> dict[str, Any]:
    """Read memory from the debuggee process.

    Parameters:
        address: Memory address (hex)
        size: Number of bytes to read (default 64)

    Returns:
        addr, size, hex, ascii, dump
    """
    _check_debugger()

    ea = parse_ea(address)
    data = ida_dbg.dbg_read_memory(ea, size)
    if not data:
        raise IDAError(f"Cannot read {size} bytes from debuggee at {_hex(ea)}")

    hex_str = data.hex()
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)

    hex_dump: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_dump.append(f"{_hex(ea + i)}: {hex_part:48s} {ascii_part}")

    return {
        "addr": _hex(ea),
        "size": len(data),
        "hex": hex_str,
        "ascii": ascii_str,
        "dump": hex_dump,
    }


rpc.register("dbg_read", dbg_read,
             doc="Read memory from the debuggee process.")


# ============================================================================
# 15. dbg_write
# ============================================================================

@idawrite
def dbg_write(address: str, hex_bytes: str) -> dict[str, Any]:
    """Write memory to the debuggee process.

    Parameters:
        address: Memory address (hex)
        hex_bytes: Hex string of bytes to write (e.g. "90909090")

    Returns:
        ok, addr, size
    """
    _check_debugger()

    ea = parse_ea(address)

    cleaned = hex_bytes.replace(" ", "").replace("-", "")
    if len(cleaned) % 2 != 0:
        raise IDAError("Hex string must have an even number of characters")

    try:
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise IDAError(f"Invalid hex string: {exc}")

    if not data:
        raise IDAError("Empty byte string")

    written = ida_dbg.dbg_write_memory(ea, data)
    if written != len(data):
        raise IDAError(
            f"Partial write at {_hex(ea)}: wrote {written} of {len(data)} bytes"
        )

    return {"ok": True, "addr": _hex(ea), "size": len(data)}


rpc.register("dbg_write", dbg_write,
             doc="Write memory to the debuggee process.")
