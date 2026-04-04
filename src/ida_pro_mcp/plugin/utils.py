from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Dict, List, Optional

import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_lines
import ida_name
import ida_strlist
import ida_xref
import idc

from .rpc import IDAError


# ============================================================================
# Address Formatting
# ============================================================================

def _hex(ea: int) -> str:
    """Format address as hex string."""
    return f"0x{ea:X}"


AUTO_NAME_SUFFIX_RE = re.compile(r"^(?:loc|off|word|byte|dword|qword|unk|asc|stru|dbl|flt|sub)_(?:0x)?([0-9A-Fa-f]+)$")


# ============================================================================
# Address Parsing
# ============================================================================

def parse_ea(text: str) -> int:
    """Parse hex or decimal address string."""
    if text.lower() == "current":
        return idaapi.get_screen_ea()
    try:
        return int(text, 0)
    except Exception:
        match = AUTO_NAME_SUFFIX_RE.match(text)
        if match:
            try:
                return int(match.group(1), 16)
            except ValueError:
                pass
        raise IDAError(f"Invalid address: {text}")


# ============================================================================
# Disassembly Helpers
# ============================================================================

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


# ============================================================================
# Function Resolution
# ============================================================================

def resolve_function(selector: str) -> ida_funcs.func_t:
    """Resolve function by name or address."""
    parsed_ea = None
    try:
        parsed_ea = parse_ea(selector)
        fn = idaapi.get_func(parsed_ea)
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

    # Search all functions by exact name
    for fea in idautils.Functions():
        name = ida_funcs.get_func_name(fea)
        if name == selector:
            fn = idaapi.get_func(fea)
            if fn:
                return fn

    # Try demangled C++ name matching
    demangled_matches: List[tuple] = []
    for fea in idautils.Functions():
        demangled = ida_name.get_demangled_name(fea, ida_name.GN_DEMANGLED | ida_name.GN_SHORT, 0)
        if demangled and selector in demangled:
            demangled_matches.append((fea, demangled))
    if len(demangled_matches) == 1:
        fn = idaapi.get_func(demangled_matches[0][0])
        if fn:
            return fn
    elif len(demangled_matches) > 1:
        suggestions = [f"  {_hex(ea)}: {name}" for ea, name in demangled_matches[:10]]
        raise IDAError(
            f"Ambiguous demangled name '{selector}' matches {len(demangled_matches)} functions:\n"
            + "\n".join(suggestions)
            + ("\n  ..." if len(demangled_matches) > 10 else "")
            + "\nUse the address (0xADDRESS) to select a specific function."
        )

    # If we parsed an address that exists but isn't at a function start
    if parsed_ea is not None:
        if ida_bytes.is_mapped(parsed_ea):
            fn = idaapi.get_func(parsed_ea)
            if fn:
                return fn
            prev_func_ea = idc.get_prev_func(parsed_ea)
            next_func_ea = idc.get_next_func(parsed_ea)
            suggestions = []
            if prev_func_ea != idaapi.BADADDR:
                prev_name = ida_funcs.get_func_name(prev_func_ea)
                offset = parsed_ea - prev_func_ea
                suggestions.append(f"{prev_name} at {_hex(prev_func_ea)} (offset +0x{offset:X})")
            if next_func_ea != idaapi.BADADDR:
                next_name = ida_funcs.get_func_name(next_func_ea)
                suggestions.append(f"{next_name} at {_hex(next_func_ea)}")
            if suggestions:
                raise IDAError(
                    f"Address {_hex(parsed_ea)} exists but is not at a function start. "
                    f"Nearest functions: {'; '.join(suggestions)}. "
                    f"Try decompiling one of those instead."
                )

    raise IDAError(f"Cannot find function '{selector}'. Use list_functions to see available functions.")


# ============================================================================
# Segment Helpers
# ============================================================================

def _iter_segments_in_range(min_ea: int, max_ea: int):
    """Yield (start_ea, end_ea) for segments overlapping [min_ea, max_ea)."""
    import ida_segment
    seg = ida_segment.get_first_seg()
    while seg:
        start = int(max(seg.start_ea, min_ea))
        end = int(min(seg.end_ea, max_ea))
        if start < end:
            yield start, end
        seg = ida_segment.get_next_seg(seg.start_ea)


# ============================================================================
# Strings Cache
# ============================================================================

_STRINGS_CACHE_LOCK = threading.Lock()
_STRINGS_CACHE_DB: Optional[str] = None
_STRINGS_CACHE: Optional[List[Dict[str, Any]]] = None
_STRINGS_CACHE_BUILT_MONO: float = 0.0


def _invalidate_caches_for_db(db_name: str) -> None:
    global _STRINGS_CACHE_DB, _STRINGS_CACHE, _STRINGS_CACHE_BUILT_MONO
    with _STRINGS_CACHE_LOCK:
        if _STRINGS_CACHE_DB != db_name:
            _STRINGS_CACHE_DB = db_name
            _STRINGS_CACHE = None
            _STRINGS_CACHE_BUILT_MONO = 0.0


def clear_strings_cache() -> None:
    global _STRINGS_CACHE_DB, _STRINGS_CACHE, _STRINGS_CACHE_BUILT_MONO
    with _STRINGS_CACHE_LOCK:
        _STRINGS_CACHE_DB = None
        _STRINGS_CACHE = None
        _STRINGS_CACHE_BUILT_MONO = 0.0


def _get_strings_cache() -> List[Dict[str, Any]]:
    """Return cached strings list (builds lazily)."""
    global _STRINGS_CACHE, _STRINGS_CACHE_BUILT_MONO, _STRINGS_CACHE_DB
    db_name = idaapi.get_root_filename() or "unknown"
    with _STRINGS_CACHE_LOCK:
        if _STRINGS_CACHE is not None and _STRINGS_CACHE_DB == db_name:
            return _STRINGS_CACHE

    ida_strlist.build_strlist()
    total_count = ida_strlist.get_strlist_qty()
    items: List[Dict[str, Any]] = []
    for i in range(total_count):
        si = ida_strlist.string_info_t()
        if not ida_strlist.get_strlist_item(si, i):
            continue
        s = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
        if not s:
            continue
        try:
            s_str = s.decode("utf-8", errors="replace")
        except Exception:
            s_str = str(s)
        items.append({"ea": int(si.ea), "val": s_str, "len": int(si.length), "typ": int(si.type)})

    with _STRINGS_CACHE_LOCK:
        _STRINGS_CACHE_DB = db_name
        _STRINGS_CACHE = items
        _STRINGS_CACHE_BUILT_MONO = time.monotonic()
        return _STRINGS_CACHE


# ============================================================================
# Xref Helpers
# ============================================================================

def count_xrefs_to(ea: int) -> int:
    """Count xrefs to an address."""
    count = 0
    xb = ida_xref.xrefblk_t()
    if xb.first_to(ea, ida_xref.XREF_ALL):
        while True:
            count += 1
            if not xb.next_to():
                break
    return count
