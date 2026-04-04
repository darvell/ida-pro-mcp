from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_lines
import ida_name
import ida_ua
import ida_xref
import idc

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

from .rpc import rpc, IDAError
from .sync import idaread, batch_mode
from .utils import parse_ea, resolve_function, _hex, _disasm_line

logger = logging.getLogger(__name__)


# ============================================================================
# 1. decompile
# ============================================================================

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
    """
    # Check dynamically - Hex-Rays may not be ready at plugin load time
    if not ida_hexrays or not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler not available. Use disassemble instead.")

    fn = resolve_function(selector)
    cfunc = None
    try:
        cfunc = ida_hexrays.decompile(fn.start_ea)
    except Exception:
        pass
    if not cfunc:
        # Fall back to disassembly preview so the caller doesn't have to retry
        func_size = fn.end_ea - fn.start_ea
        preview_lines: List[str] = []
        ea = fn.start_ea
        preview_limit = 30
        while ea < fn.end_ea and len(preview_lines) < preview_limit:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length <= 0:
                ea += 1
                continue
            line = _disasm_line(ea)
            if ea == fn.start_ea:
                preview_lines.append(f"{_hex(ea)}: {line}")
            else:
                preview_lines.append(f"+0x{ea - fn.start_ea:X}: {line}")
            ea += length
        func_name = ida_funcs.get_func_name(fn.start_ea)
        raise IDAError(
            f"Decompilation failed for {func_name} (Hex-Rays could not produce pseudocode). "
            f"Function size: 0x{func_size:X} bytes. "
            f"Disassembly preview ({len(preview_lines)} lines):\n" + "\n".join(preview_lines)
        )

    # Get local variables
    vars_list: List[Dict[str, Any]] = []
    for lvar in cfunc.get_lvars():
        v: Dict[str, Any] = {"name": lvar.name, "type": str(lvar.type())}
        if lvar.is_stk_var():
            v["loc"] = "stack"
        elif lvar.is_reg_var():
            v["loc"] = "reg"
        elif lvar.is_arg_var:
            v["loc"] = "arg"
        vars_list.append(v)

    # Get full pseudocode
    full_code = str(cfunc)
    all_lines = full_code.split("\n")
    total = len(all_lines)

    # Apply line filtering if requested
    result: Dict[str, Any] = {
        "name": ida_funcs.get_func_name(fn.start_ea),
        "addr": _hex(fn.start_ea),
        "proto": str(cfunc.type),
        "vars": vars_list,
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
        result["code"] = "\n".join(filtered)
        result["lines"] = {
            "total": total,
            "start": start_idx + 1,
            "end": min(end_idx, total),
            "more": end_idx < total,
        }
    else:
        result["code"] = full_code

    return result


rpc.register("decompile", decompile, doc="Get Hex-Rays pseudocode for a function.")


# ============================================================================
# 2. decompile_batch
# ============================================================================

@idaread
def decompile_batch(
    selectors: List[str],
    max_lines_per_function: int = 50,
) -> Dict[str, Any]:
    """Decompile multiple functions in a single call.

    Parameters:
        selectors: List of function names or "0xADDRESS" strings
        max_lines_per_function: Max pseudocode lines per function (default 50)

    Returns:
        results: [{selector, name, addr, proto, code, error?, truncated?}], count, errors
    """
    if not ida_hexrays or not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler not available. Use disassemble instead.")

    if len(selectors) > 50:
        raise IDAError("Maximum 50 functions per batch call.")

    results: List[Dict[str, Any]] = []
    error_count = 0

    for selector in selectors:
        entry: Dict[str, Any] = {"selector": selector}
        try:
            fn = resolve_function(selector)
            cfunc = None
            try:
                cfunc = ida_hexrays.decompile(fn.start_ea)
            except Exception:
                pass
            if not cfunc:
                entry["name"] = ida_funcs.get_func_name(fn.start_ea)
                entry["addr"] = _hex(fn.start_ea)
                entry["error"] = "Decompilation failed"
                error_count += 1
            else:
                full_code = str(cfunc)
                lines = full_code.split("\n")
                if max_lines_per_function > 0 and len(lines) > max_lines_per_function:
                    lines = lines[:max_lines_per_function]
                    entry["truncated"] = True
                entry["name"] = ida_funcs.get_func_name(fn.start_ea)
                entry["addr"] = _hex(fn.start_ea)
                entry["proto"] = str(cfunc.type)
                entry["code"] = "\n".join(lines)
        except (IDAError, Exception) as e:
            entry["error"] = str(e)
            error_count += 1
        results.append(entry)

    return {"results": results, "count": len(results), "errors": error_count}


rpc.register("decompile_batch", decompile_batch, doc="Decompile multiple functions in one call.")


# ============================================================================
# 3. disassemble
# ============================================================================

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
        except Exception:
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


rpc.register(
    "disassemble",
    disassemble,
    doc="Get assembly instructions for a function or address range.",
)


# ============================================================================
# 4. get_xrefs
# ============================================================================

@idaread
def get_xrefs(target: str, direction: str = "to", limit: int = 100) -> Dict[str, Any]:
    """Get cross-references to/from an address or symbol.

    Parameters:
        target: Address or function name
        direction: "to" (who references this), "from" (what this references), or "both"
        limit: Maximum xrefs to return (default 100)

    Returns:
        xrefs: [{from, to, dir, func, line}], count, more
    """
    # Resolve target
    try:
        ea = parse_ea(target)
    except IDAError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, target)
        if ea == idaapi.BADADDR:
            raise IDAError(
                f"Target '{target}' not found as an address or name. "
                "If you meant a string literal, use search() to find its address first."
            )

    xrefs: List[Dict[str, Any]] = []
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


# ============================================================================
# 5. get_callgraph
# ============================================================================

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

    visited_callers: set[int] = set()
    visited_callees: set[int] = set()

    def _get_callers(ea: int, depth: int) -> List[Dict[str, Any]]:
        if depth <= 0 or ea in visited_callers:
            return []
        visited_callers.add(ea)
        callers: List[Dict[str, Any]] = []
        xb = ida_xref.xrefblk_t()
        if xb.first_to(ea, ida_xref.XREF_ALL):
            while True:
                caller_fn = ida_funcs.get_func(xb.frm)
                if caller_fn and caller_fn.start_ea != ea:
                    caller_ea = caller_fn.start_ea
                    # Deduplicate by checking existing entries
                    if caller_ea not in [c.get("addr") for c in callers]:
                        c: Dict[str, Any] = {
                            "addr": _hex(caller_ea),
                            "name": ida_funcs.get_func_name(caller_ea),
                            "site": _hex(xb.frm),
                        }
                        if depth > 1:
                            c["callers"] = _get_callers(caller_ea, depth - 1)
                        callers.append(c)
                if not xb.next_to():
                    break
        return callers

    def _get_callees(ea: int, depth: int) -> List[Dict[str, Any]]:
        if depth <= 0 or ea in visited_callees:
            return []
        visited_callees.add(ea)
        callees: List[Dict[str, Any]] = []
        callee_fn_obj = idaapi.get_func(ea)
        if not callee_fn_obj:
            return callees
        addr = callee_fn_obj.start_ea
        while addr < callee_fn_obj.end_ea:
            xb = ida_xref.xrefblk_t()
            if xb.first_from(addr, ida_xref.XREF_ALL):
                while True:
                    callee_fn = ida_funcs.get_func(xb.to)
                    if callee_fn and callee_fn.start_ea != ea:
                        callee_ea = callee_fn.start_ea
                        # Deduplicate by checking existing entries
                        if callee_ea not in [c.get("addr") for c in callees]:
                            c: Dict[str, Any] = {
                                "addr": _hex(callee_ea),
                                "name": ida_funcs.get_func_name(callee_ea),
                                "site": _hex(addr),
                            }
                            if depth > 1:
                                c["callees"] = _get_callees(callee_ea, depth - 1)
                            callees.append(c)
                    if not xb.next_from():
                        break
            addr = idc.next_head(addr, callee_fn_obj.end_ea)
        return callees

    result: Dict[str, Any] = {"root": {"addr": _hex(root_ea), "name": root_name}}

    if direction in ("callers", "both"):
        result["callers"] = _get_callers(root_ea, max_depth)

    if direction in ("callees", "both"):
        result["callees"] = _get_callees(root_ea, max_depth)

    return result


rpc.register(
    "get_callgraph",
    get_callgraph,
    doc="Get call graph showing callers and callees of a function.",
)


# ============================================================================
# 6. basic_blocks
# ============================================================================

@idaread
def basic_blocks(selector: str) -> Dict[str, Any]:
    """Get basic block boundaries for a function.

    Parameters:
        selector: Function name or "0xADDRESS"

    Returns:
        name, addr, blocks: [{start, end, size, succs, preds, instructions}], count
    """
    fn = resolve_function(selector)
    func_name = ida_funcs.get_func_name(fn.start_ea)

    flowchart = idaapi.FlowChart(fn)
    blocks: List[Dict[str, Any]] = []

    for block in flowchart:
        # Count instructions in the block
        insn_count = 0
        ea = block.start_ea
        while ea < block.end_ea:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length <= 0:
                ea += 1
                continue
            insn_count += 1
            ea += length

        succs = [_hex(succ.start_ea) for succ in block.succs()]
        preds = [_hex(pred.start_ea) for pred in block.preds()]

        blocks.append({
            "start": _hex(block.start_ea),
            "end": _hex(block.end_ea),
            "size": block.end_ea - block.start_ea,
            "succs": succs,
            "preds": preds,
            "instructions": insn_count,
        })

    return {
        "name": func_name,
        "addr": _hex(fn.start_ea),
        "blocks": blocks,
        "count": len(blocks),
    }


rpc.register(
    "basic_blocks",
    basic_blocks,
    doc="Get basic block boundaries for a function.",
)


# ============================================================================
# 7. find_insns
# ============================================================================

@idaread
def find_insns(
    selector: str,
    mnemonic: str = "",
    operand: str = "",
    limit: int = 100,
) -> Dict[str, Any]:
    """Find instructions matching a pattern within a function.

    Parameters:
        selector: Function name or "0xADDRESS"
        mnemonic: Regex pattern to match instruction mnemonic (case-insensitive)
        operand: Text to match anywhere in the operand string
        limit: Maximum matches to return (default 100)

    Returns:
        name, addr, matches: [{addr, offset, mnemonic, disasm}], count, more
    """
    fn = resolve_function(selector)
    func_name = ida_funcs.get_func_name(fn.start_ea)

    try:
        mnem_re = re.compile(mnemonic, re.IGNORECASE) if mnemonic else None
    except re.error as exc:
        raise IDAError(f"Invalid mnemonic regex: {exc}")

    matches: List[Dict[str, Any]] = []
    truncated = False
    ea = fn.start_ea

    while ea < fn.end_ea:
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, ea)
        if length <= 0:
            ea += 1
            continue

        mnem = insn.get_canon_mnem()
        disasm = _disasm_line(ea)

        mnem_ok = (not mnem_re) or mnem_re.search(mnem)
        operand_ok = (not operand) or (operand.lower() in disasm.lower())

        if mnem_ok and operand_ok:
            if len(matches) >= limit:
                truncated = True
                break
            matches.append({
                "addr": _hex(ea),
                "offset": ea - fn.start_ea,
                "mnemonic": mnem,
                "disasm": disasm,
            })

        ea += length

    return {
        "name": func_name,
        "addr": _hex(fn.start_ea),
        "matches": matches,
        "count": len(matches),
        "more": truncated,
    }


rpc.register(
    "find_insns",
    find_insns,
    doc="Find instructions matching a pattern within a function.",
)
