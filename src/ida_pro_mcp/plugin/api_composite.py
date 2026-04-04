from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any

import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_name
import ida_typeinf
import ida_xref
import idc

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

from .rpc import rpc, IDAError
from .sync import idaread, idawrite, batch_mode
from .utils import parse_ea, resolve_function, _hex, _disasm_line, count_xrefs_to

logger = logging.getLogger(__name__)


# ============================================================================
# Helpers
# ============================================================================

_TRIVIAL_CONSTANTS = frozenset({0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})


def _extract_strings_from_func(fn: ida_funcs.func_t) -> list[str]:
    """Scan function body for data xrefs that point to string addresses."""
    strings: list[str] = []
    seen: set[int] = set()
    ea = fn.start_ea
    while ea < fn.end_ea:
        xb = ida_xref.xrefblk_t()
        if xb.first_from(ea, ida_xref.XREF_DATA):
            while True:
                target = xb.to
                if target not in seen:
                    seen.add(target)
                    s = ida_bytes.get_strlit_contents(target, -1, 0)
                    if s:
                        try:
                            strings.append(s.decode("utf-8", errors="replace"))
                        except Exception:
                            strings.append(str(s))
                if not xb.next_from():
                    break
        ea = idc.next_head(ea, fn.end_ea)
    return strings


def _extract_constants_from_code(code: str) -> list[int]:
    """Extract integer constants from decompiled pseudocode, filtering trivials."""
    constants: set[int] = set()
    for match in re.finditer(r'\b0x([0-9A-Fa-f]+)\b', code):
        try:
            val = int(match.group(1), 16)
            if val not in _TRIVIAL_CONSTANTS:
                constants.add(val)
        except ValueError:
            pass
    for match in re.finditer(r'(?<![0-9A-Fa-fxX])(\d{2,})\b', code):
        try:
            val = int(match.group(1))
            if val not in _TRIVIAL_CONSTANTS:
                constants.add(val)
        except ValueError:
            pass
    return sorted(constants)


def _get_callees(fn: ida_funcs.func_t) -> list[dict[str, Any]]:
    """Get unique functions called by fn."""
    callees: list[dict[str, Any]] = []
    seen: set[int] = set()
    ea = fn.start_ea
    while ea < fn.end_ea:
        xb = ida_xref.xrefblk_t()
        if xb.first_from(ea, ida_xref.XREF_ALL):
            while True:
                callee_fn = ida_funcs.get_func(xb.to)
                if callee_fn and callee_fn.start_ea != fn.start_ea:
                    callee_ea = callee_fn.start_ea
                    if callee_ea not in seen:
                        seen.add(callee_ea)
                        callees.append({
                            "addr": _hex(callee_ea),
                            "name": ida_funcs.get_func_name(callee_ea),
                        })
                if not xb.next_from():
                    break
        ea = idc.next_head(ea, fn.end_ea)
    return callees


def _decompile_func(ea: int, max_lines: int = 0) -> tuple[str, str, str]:
    """Decompile a function, returning (code, proto, name). Raises on failure."""
    if not ida_hexrays or not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler not available")

    cfunc = None
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception:
        pass
    if not cfunc:
        raise IDAError(f"Decompilation failed for {_hex(ea)}")

    code = str(cfunc)
    if max_lines > 0:
        lines = code.split("\n")
        if len(lines) > max_lines:
            code = "\n".join(lines[:max_lines])

    name = ida_funcs.get_func_name(ea)
    proto = str(cfunc.type)
    return code, proto, name


# ============================================================================
# 1. analyze_function_compact
# ============================================================================

@idaread
def analyze_function_compact(selector: str) -> dict[str, Any]:
    """Deep single-function analysis in one call.

    Decompiles the function, extracts referenced strings and constants,
    counts callers, lists callees, and counts basic blocks.

    Parameters:
        selector: Function name or "0xADDRESS"

    Returns:
        name, addr, size, proto, code, strings, constants, callers,
        callees: [{addr, name}], basic_blocks
    """
    fn = resolve_function(selector)
    ea = fn.start_ea
    func_name = ida_funcs.get_func_name(ea)

    code, proto, _ = _decompile_func(ea, max_lines=100)

    strings = _extract_strings_from_func(fn)
    constants = _extract_constants_from_code(code)
    callers = count_xrefs_to(ea)
    callees = _get_callees(fn)

    flowchart = idaapi.FlowChart(fn)
    bb_count = sum(1 for _ in flowchart)

    return {
        "name": func_name,
        "addr": _hex(ea),
        "size": fn.end_ea - fn.start_ea,
        "proto": proto,
        "code": code,
        "strings": strings,
        "constants": constants,
        "callers": callers,
        "callees": callees,
        "basic_blocks": bb_count,
    }


rpc.register("analyze_function_compact", analyze_function_compact,
             doc="Deep single-function analysis: decompile, strings, constants, callers, callees, basic blocks.")


# ============================================================================
# 2. analyze_component
# ============================================================================

@idaread
def analyze_component(
    selectors: list[str],
    max_depth: int = 1,
) -> dict[str, Any]:
    """Multi-function group analysis.

    Decompiles each function, builds an internal call graph between them,
    finds shared globals, and collects unique strings across the set.

    Parameters:
        selectors: List of function names or addresses
        max_depth: Expansion depth for call graph (default 1, currently used for future expansion)

    Returns:
        functions: [{name, addr, code}], internal_calls: [{from, to}],
        shared_globals: [{addr, name, used_by}], strings, total_size
    """
    if not selectors:
        raise IDAError("selectors list must not be empty")

    # Resolve all functions first
    func_map: dict[int, ida_funcs.func_t] = {}
    func_names: dict[int, str] = {}
    for sel in selectors:
        fn = resolve_function(sel)
        ea = fn.start_ea
        func_map[ea] = fn
        func_names[ea] = ida_funcs.get_func_name(ea)

    member_eas = set(func_map.keys())

    functions: list[dict[str, Any]] = []
    internal_calls: list[dict[str, str]] = []
    all_strings: list[str] = []
    seen_strings: set[str] = set()
    total_size = 0

    # Track globals referenced by each function: global_ea -> set of func names
    global_usage: dict[int, set[str]] = defaultdict(set)

    for ea, fn in func_map.items():
        total_size += fn.end_ea - fn.start_ea

        # Decompile
        try:
            code, _, _ = _decompile_func(ea, max_lines=50)
        except IDAError:
            code = f"/* decompilation failed for {_hex(ea)} */"

        functions.append({
            "name": func_names[ea],
            "addr": _hex(ea),
            "code": code,
        })

        # Strings
        for s in _extract_strings_from_func(fn):
            if s not in seen_strings:
                seen_strings.add(s)
                all_strings.append(s)

        # Build internal call edges and track global references
        addr = fn.start_ea
        while addr < fn.end_ea:
            xb = ida_xref.xrefblk_t()
            if xb.first_from(addr, ida_xref.XREF_ALL):
                while True:
                    target_fn = ida_funcs.get_func(xb.to)
                    if target_fn and target_fn.start_ea in member_eas and target_fn.start_ea != ea:
                        edge = {"from": func_names[ea], "to": func_names[target_fn.start_ea]}
                        if edge not in internal_calls:
                            internal_calls.append(edge)
                    elif not target_fn:
                        # Could be a global reference
                        name = ida_name.get_name(xb.to)
                        if name and not name.startswith(("loc_", "off_", "unk_")):
                            global_usage[xb.to].add(func_names[ea])
                    if not xb.next_from():
                        break
            addr = idc.next_head(addr, fn.end_ea)

    # Filter to globals used by 2+ functions
    shared_globals: list[dict[str, Any]] = []
    for g_ea, users in global_usage.items():
        if len(users) >= 2:
            shared_globals.append({
                "addr": _hex(g_ea),
                "name": ida_name.get_name(g_ea) or _hex(g_ea),
                "used_by": sorted(users),
            })

    return {
        "functions": functions,
        "internal_calls": internal_calls,
        "shared_globals": shared_globals,
        "strings": all_strings,
        "total_size": total_size,
    }


rpc.register("analyze_component", analyze_component,
             doc="Multi-function group analysis: decompile, call graph, shared globals, strings.")


# ============================================================================
# 3. diff_before_after
# ============================================================================

@idawrite
def diff_before_after(
    selector: str,
    rename_to: str = "",
    type_str: str = "",
    comment: str = "",
    comment_addr: str = "",
) -> dict[str, Any]:
    """Apply modifications and show before/after decompilation.

    Decompiles the function before and after applying rename, type,
    and/or comment changes so the caller can see the effect.

    Parameters:
        selector: Function name or "0xADDRESS"
        rename_to: New name for the function (optional)
        type_str: C type declaration to apply (optional)
        comment: Comment text to set (optional)
        comment_addr: Address for the comment; defaults to function start (optional)

    Returns:
        name, addr, before, after, changes
    """
    fn = resolve_function(selector)
    ea = fn.start_ea
    func_name = ida_funcs.get_func_name(ea)

    # Decompile "before"
    before_code, _, _ = _decompile_func(ea)

    changes: list[str] = []

    with batch_mode():
        # Apply rename
        if rename_to:
            old_name = ida_name.get_name(ea) or f"sub_{ea:X}"
            ok = ida_name.set_name(ea, rename_to, ida_name.SN_CHECK)
            if not ok:
                raise IDAError(f"Cannot rename '{old_name}' to '{rename_to}'")
            changes.append(f"Renamed {old_name} -> {rename_to}")
            if ida_hexrays and ida_hexrays.init_hexrays_plugin():
                ida_hexrays.mark_cfunc_dirty(ea)

        # Apply type
        if type_str:
            til = ida_typeinf.get_idati()
            tif = ida_typeinf.tinfo_t()
            decl = type_str.strip()
            if not decl.endswith(";"):
                decl += ";"
            result = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
            if result is None:
                raise IDAError(f"Cannot parse type: '{type_str}'")
            if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                raise IDAError(f"Cannot apply type to {_hex(ea)}")
            changes.append(f"Applied type: {tif}")
            if ida_hexrays and ida_hexrays.init_hexrays_plugin():
                ida_hexrays.mark_cfunc_dirty(ea)

        # Apply comment
        if comment:
            cmt_ea = parse_ea(comment_addr) if comment_addr else ea
            idc.set_cmt(cmt_ea, comment, 0)
            changes.append(f"Set comment at {_hex(cmt_ea)}")

    # Decompile "after"
    after_code, _, _ = _decompile_func(ea)

    return {
        "name": rename_to or func_name,
        "addr": _hex(ea),
        "before": before_code,
        "after": after_code,
        "changes": changes,
    }


rpc.register("diff_before_after", diff_before_after,
             doc="Apply modifications and show before/after decompilation diff.")


# ============================================================================
# 4. trace_data_flow
# ============================================================================

@idaread
def trace_data_flow(
    start: str,
    direction: str = "forward",
    max_depth: int = 3,
    max_nodes: int = 50,
) -> dict[str, Any]:
    """BFS xref traversal from an address.

    Follows cross-references forward (FROM) or backward (TO) to trace
    data/code flow through the binary.

    Parameters:
        start: Starting address (hex)
        direction: "forward" follows xrefs FROM, "backward" follows xrefs TO
        max_depth: Maximum BFS depth (default 3)
        max_nodes: Maximum nodes to collect (default 50)

    Returns:
        start, direction, nodes: [{addr, name, depth}],
        edges: [{from, to}], depth_reached
    """
    if direction not in ("forward", "backward"):
        raise IDAError(f"direction must be 'forward' or 'backward', got '{direction}'")

    start_ea = parse_ea(start)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    visited: set[int] = set()
    depth_reached = 0

    # BFS queue: (ea, depth)
    queue: list[tuple[int, int]] = [(start_ea, 0)]
    visited.add(start_ea)

    start_name = ida_name.get_name(start_ea) or _hex(start_ea)
    nodes.append({"addr": _hex(start_ea), "name": start_name, "depth": 0})

    while queue and len(nodes) < max_nodes:
        current_ea, depth = queue.pop(0)
        if depth > depth_reached:
            depth_reached = depth
        if depth >= max_depth:
            continue

        xb = ida_xref.xrefblk_t()
        if direction == "forward":
            has_xref = xb.first_from(current_ea, ida_xref.XREF_ALL)
        else:
            has_xref = xb.first_to(current_ea, ida_xref.XREF_ALL)

        if has_xref:
            while True:
                target_ea = xb.to if direction == "forward" else xb.frm

                if direction == "forward":
                    edges.append({"from": _hex(current_ea), "to": _hex(target_ea)})
                else:
                    edges.append({"from": _hex(target_ea), "to": _hex(current_ea)})

                if target_ea not in visited and len(nodes) < max_nodes:
                    visited.add(target_ea)
                    target_name = ida_name.get_name(target_ea) or _hex(target_ea)
                    nodes.append({
                        "addr": _hex(target_ea),
                        "name": target_name,
                        "depth": depth + 1,
                    })
                    queue.append((target_ea, depth + 1))

                if direction == "forward":
                    if not xb.next_from():
                        break
                else:
                    if not xb.next_to():
                        break

    return {
        "start": _hex(start_ea),
        "direction": direction,
        "nodes": nodes,
        "edges": edges,
        "depth_reached": depth_reached,
    }


rpc.register("trace_data_flow", trace_data_flow,
             doc="BFS xref traversal: trace data/code flow forward or backward from an address.")
