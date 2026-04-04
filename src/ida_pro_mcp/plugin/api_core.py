from __future__ import annotations

import logging
import re
import time
from typing import Any

import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_ida
import ida_name
import ida_strlist
import ida_ua
import ida_typeinf
import ida_xref
import idc

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

from .rpc import rpc, IDAError
from .sync import idaread, idawrite, batch_mode, _get_busy_snapshot, _get_heartbeat_snapshot, _get_system_meta_base
from .utils import parse_ea, _hex, _disasm_line, _get_strings_cache, _iter_segments_in_range, count_xrefs_to

logger = logging.getLogger(__name__)


# ============================================================================
# 1. info
# ============================================================================

@idaread
def info() -> dict[str, Any]:
    """Get current database info: architecture, function count, entry point, segments, strings, imports, exports."""
    import ida_segment
    import ida_entry
    import ida_nalt

    db_name = idaapi.get_root_filename() or "unknown"
    bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
    arch = ida_ida.inf_get_procname()

    func_count = 0
    for _ in idautils.Functions():
        func_count += 1

    cursor = idaapi.get_screen_ea()
    cursor_func_name = None
    fn = idaapi.get_func(cursor)
    if fn:
        cursor_func_name = ida_funcs.get_func_name(fn.start_ea)

    hexrays_available = False
    if ida_hexrays:
        try:
            hexrays_available = ida_hexrays.init_hexrays_plugin()
        except Exception:
            pass

    entry = ida_entry.get_entry(ida_entry.get_entry_ordinal(0)) if ida_entry.get_entry_qty() > 0 else None

    file_type_id = ida_ida.inf_get_filetype()
    file_type_names = {
        0: "unknown", 1: "ELF", 2: "PE", 3: "MachO", 4: "BIN",
        5: "OMF", 6: "SREC", 7: "COFF", 8: "WIN", 9: "LX",
    }
    file_type = file_type_names.get(file_type_id, f"type_{file_type_id}")

    seg_count = 0
    seg = ida_segment.get_first_seg()
    while seg:
        seg_count += 1
        seg = ida_segment.get_next_seg(seg.start_ea)

    ida_strlist.build_strlist()
    string_count = ida_strlist.get_strlist_qty()

    import_count = 0
    def _import_counter(ea, name, ordinal):
        nonlocal import_count
        import_count += 1
        return True
    for i in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(i, _import_counter)

    export_count = ida_entry.get_entry_qty()

    return {
        "db": db_name,
        "cursor": _hex(cursor),
        "cursor_func": cursor_func_name,
        "arch": arch,
        "bits": bits,
        "funcs": func_count,
        "hexrays": hexrays_available,
        "entry": _hex(entry) if entry is not None else None,
        "file_type": file_type,
        "segments": seg_count,
        "strings": string_count,
        "imports": import_count,
        "exports": export_count,
    }


rpc.register("info", info, doc="Get current database info and cursor position.")


# ============================================================================
# 2. list_functions
# ============================================================================

@idaread
def list_functions(filter: str = "", offset: int = 0, limit: int = 100) -> dict[str, Any]:
    """List functions with optional regex filtering and pagination."""
    try:
        pat = re.compile(filter, re.IGNORECASE) if filter else None
    except re.error as exc:
        raise IDAError(f"Invalid regex filter: {exc}")

    all_funcs: list[dict[str, Any]] = []
    for fea in idautils.Functions():
        name = ida_funcs.get_func_name(fea)
        if pat and not pat.search(name):
            continue
        fn = idaapi.get_func(fea)
        size = fn.size() if fn else 0
        all_funcs.append({"addr": _hex(fea), "name": name, "size": size})

    total = len(all_funcs)
    page = all_funcs[offset:offset + limit]
    return {"funcs": page, "total": total, "more": offset + limit < total}


rpc.register("list_functions", list_functions, doc="List functions with regex filter and pagination.")


# ============================================================================
# 3. search_strings
# ============================================================================

@idaread
def search_strings(
    pattern: str = "",
    min_length: int = 4,
    offset: int = 0,
    limit: int = 100,
    include_xrefs: bool = False,
) -> dict[str, Any]:
    """Find strings in the binary with optional regex filtering."""
    try:
        pat = re.compile(pattern, re.IGNORECASE) if pattern else None
    except re.error as exc:
        raise IDAError(f"Invalid regex pattern: {exc}")

    cache = _get_strings_cache()
    filtered: list[dict[str, Any]] = []
    for item in cache:
        if item["len"] < min_length:
            continue
        if pat and not pat.search(item["val"]):
            continue
        entry: dict[str, Any] = {
            "addr": _hex(item["ea"]),
            "val": item["val"],
            "len": item["len"],
        }
        if include_xrefs:
            entry["xrefs"] = count_xrefs_to(item["ea"])
        filtered.append(entry)

    total = len(filtered)
    page = filtered[offset:offset + limit]
    return {
        "strings": page,
        "total": total,
        "offset": offset,
        "limit": limit,
        "more": offset + limit < total,
    }


rpc.register("search_strings", search_strings, doc="Find strings in the binary with regex filter.")


# ============================================================================
# 4. search (multi-type)
# ============================================================================

def _looks_like_bin_bytes(q: str) -> bool:
    stripped = q.replace(" ", "")
    return bool(re.fullmatch(r'[0-9A-Fa-f]{2,}', stripped)) and len(stripped) >= 4

def _looks_like_imm(q: str) -> bool:
    return bool(re.fullmatch(r'0x[0-9A-Fa-f]+|\d+', q.strip()))

def _looks_like_regex(q: str) -> bool:
    return bool(re.search(r'[.+*?\[\](){}|\\^$]', q))


@idaread
def search(
    query: str,
    search_type: str = "auto",
    start_address: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """Search for bytes, immediates, text, or disassembly patterns."""
    if not query:
        raise IDAError("Empty search query")

    if search_type == "auto":
        if _looks_like_bin_bytes(query) and not _looks_like_imm(query):
            search_type = "bytes"
        elif _looks_like_imm(query):
            search_type = "immediate"
        elif _looks_like_regex(query):
            search_type = "disasm"
        else:
            search_type = "text"

    start_ea = parse_ea(start_address) if start_address else ida_ida.inf_get_min_ea()
    results: list[dict[str, Any]] = []
    truncated = False

    def _func_at(ea: int) -> str | None:
        fn = idaapi.get_func(ea)
        return ida_funcs.get_func_name(fn.start_ea) if fn else None

    if search_type == "bytes":
        hex_str = query.replace(" ", "")
        if len(hex_str) % 2 != 0:
            raise IDAError(f"Hex byte string must have even length, got {len(hex_str)}")
        pattern = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        compiled = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(compiled, start_ea, pattern, 16)
        if err:
            raise IDAError(f"Invalid byte pattern: {err}")
        flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
        max_ea = ida_ida.inf_get_max_ea()
        for seg_start, seg_end in _iter_segments_in_range(start_ea, max_ea):
            ea = seg_start
            while len(results) < limit:
                result = ida_bytes.bin_search(ea, seg_end, compiled, flags)
                ea = result[0] if isinstance(result, tuple) else result
                if ea == idc.BADADDR:
                    break
                results.append({
                    "addr": _hex(ea),
                    "ctx": _disasm_line(ea),
                    "func": _func_at(ea),
                    "kind": "bytes",
                })
                ea += 1
            if len(results) >= limit:
                truncated = True
                break

    elif search_type == "immediate":
        try:
            import ida_search
        except ImportError:
            raise IDAError("Immediate search not available in this IDA version")
        val = int(query, 0)
        ea = start_ea
        for _ in range(limit + 1):
            ea, _ = ida_search.find_imm(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NOSHOW, val)
            if ea == idaapi.BADADDR or ea == idc.BADADDR:
                break
            if len(results) >= limit:
                truncated = True
                break
            results.append({
                "addr": _hex(ea),
                "ctx": _disasm_line(ea),
                "func": _func_at(ea),
                "kind": "immediate",
            })
            ea = idc.next_head(ea, ida_ida.inf_get_max_ea())
            if ea == idaapi.BADADDR:
                break

    elif search_type == "text":
        # Layer 1: exact name lookup
        ea = idaapi.get_name_ea(idaapi.BADADDR, query)
        if ea != idaapi.BADADDR:
            results.append({
                "addr": _hex(ea),
                "ctx": _disasm_line(ea),
                "func": _func_at(ea),
                "kind": "name_exact",
            })

        # Layer 2: raw bytes (UTF-8)
        encoded = query.encode("utf-8")
        ea = start_ea
        for _ in range(limit + 1):
            ea = ida_bytes.bin_search(
                ea, ida_ida.inf_get_max_ea(),
                encoded, None,
                1, ida_bytes.BIN_SEARCH_FORWARD,
            )
            if ea == idaapi.BADADDR:
                break
            if len(results) >= limit:
                truncated = True
                break
            results.append({
                "addr": _hex(ea),
                "ctx": _disasm_line(ea),
                "func": _func_at(ea),
                "kind": "bytes_utf8",
            })
            ea += 1

        # Layer 3: raw bytes (UTF-16LE)
        if not truncated:
            encoded_16 = query.encode("utf-16-le")
            ea = start_ea
            for _ in range(limit + 1):
                ea = ida_bytes.bin_search(
                    ea, ida_ida.inf_get_max_ea(),
                    encoded_16, None,
                    1, ida_bytes.BIN_SEARCH_FORWARD,
                )
                if ea == idaapi.BADADDR:
                    break
                if len(results) >= limit:
                    truncated = True
                    break
                results.append({
                    "addr": _hex(ea),
                    "ctx": _disasm_line(ea),
                    "func": _func_at(ea),
                    "kind": "bytes_utf16",
                })
                ea += 1

        # Layer 4: Names() iteration
        if not truncated:
            try:
                name_pat = re.compile(query, re.IGNORECASE)
            except re.error:
                name_pat = None
            if name_pat:
                for ea_n, name_n in idautils.Names():
                    if len(results) >= limit:
                        truncated = True
                        break
                    if name_pat.search(name_n):
                        if not any(r["addr"] == _hex(ea_n) for r in results):
                            results.append({
                                "addr": _hex(ea_n),
                                "ctx": name_n,
                                "func": _func_at(ea_n),
                                "kind": "name_match",
                            })

        # Layer 5: strings cache
        if not truncated:
            try:
                str_pat = re.compile(query, re.IGNORECASE)
            except re.error:
                str_pat = None
            if str_pat:
                for s_item in _get_strings_cache():
                    if len(results) >= limit:
                        truncated = True
                        break
                    if str_pat.search(s_item["val"]):
                        s_ea = s_item["ea"]
                        if not any(r["addr"] == _hex(s_ea) for r in results):
                            results.append({
                                "addr": _hex(s_ea),
                                "ctx": s_item["val"][:80],
                                "func": _func_at(s_ea),
                                "kind": "string",
                            })

    elif search_type == "disasm":
        try:
            disasm_pat = re.compile(query, re.IGNORECASE)
        except re.error as exc:
            raise IDAError(f"Invalid disasm regex: {exc}")

        max_scan = min(max(200_000, limit * 2_000), 2_000_000)
        deadline = time.monotonic() + 5.0
        scanned = 0
        ea = start_ea

        with batch_mode():
            while ea < ida_ida.inf_get_max_ea() and scanned < max_scan:
                if time.monotonic() > deadline:
                    truncated = True
                    break
                insn = ida_ua.insn_t()
                length = ida_ua.decode_insn(insn, ea)
                if length <= 0:
                    ea += 1
                    scanned += 1
                    continue
                line = _disasm_line(ea)
                if disasm_pat.search(line):
                    if len(results) >= limit:
                        truncated = True
                        break
                    results.append({
                        "addr": _hex(ea),
                        "ctx": line,
                        "func": _func_at(ea),
                        "kind": "disasm",
                    })
                ea += length
                scanned += 1
    else:
        raise IDAError(f"Unknown search_type: {search_type}. Use bytes/immediate/text/disasm/auto.")

    return {
        "type": search_type,
        "results": results,
        "count": len(results),
        "more": truncated,
    }


rpc.register("search", search, doc="Search for bytes, immediates, text, or disassembly patterns.")


# ============================================================================
# 5. get_segments
# ============================================================================

@idaread
def get_segments() -> dict[str, Any]:
    """Get memory segments/sections of the binary."""
    import ida_segment

    segs: list[dict[str, Any]] = []
    seg = ida_segment.get_first_seg()
    while seg:
        perm_str = ""
        if seg.perm & ida_segment.SFL_COMORG:
            pass
        perm_str += "R" if seg.perm & 4 else "-"
        perm_str += "W" if seg.perm & 2 else "-"
        perm_str += "X" if seg.perm & 1 else "-"

        segs.append({
            "name": ida_segment.get_segm_name(seg) or "",
            "start": _hex(seg.start_ea),
            "end": _hex(seg.end_ea),
            "size": seg.end_ea - seg.start_ea,
            "perm": perm_str,
            "class": ida_segment.get_segm_class(seg) or "",
        })
        seg = ida_segment.get_next_seg(seg.start_ea)

    return {"segs": segs, "count": len(segs)}


rpc.register("get_segments", get_segments, doc="Get memory segments/sections of the binary.")


# ============================================================================
# 6. system_info (no decorator - non-blocking)
# ============================================================================

def system_info() -> dict[str, Any]:
    """Get system/instance status without blocking the main thread."""
    result = _get_system_meta_base()
    result.update(_get_busy_snapshot())
    result.update(_get_heartbeat_snapshot())
    return result


rpc.register("system_info", system_info, doc="Get system/instance status (non-blocking).")


# ============================================================================
# 7. discover (no decorator)
# ============================================================================

def discover() -> dict[str, Any]:
    """List all available RPC tools and their documentation."""
    excluded = {"start_job", "job_status", "job_result"}
    tools: dict[str, dict[str, str]] = {}
    for name, meta in rpc.meta.items():
        if name in excluded:
            continue
        tools[name] = {"doc": meta.get("doc", "")}
    return {"tools": tools}


rpc.register("discover", discover, doc="List all available RPC tools.")


# ============================================================================
# 8. survey_binary
# ============================================================================

@idaread
def survey_binary(detail_level: str = "standard") -> dict[str, Any]:
    """One-call binary triage: metadata, statistics, interesting strings/functions, categorized imports."""
    import ida_segment
    import ida_entry
    import ida_nalt

    # --- metadata (inline version of info() since we're already on main thread) ---
    db_name = idaapi.get_root_filename() or "unknown"
    bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
    arch = ida_ida.inf_get_procname()
    hexrays_available = False
    if ida_hexrays:
        try:
            hexrays_available = ida_hexrays.init_hexrays_plugin()
        except Exception:
            pass
    entry_ea = ida_entry.get_entry(ida_entry.get_entry_ordinal(0)) if ida_entry.get_entry_qty() > 0 else None
    file_type_id = ida_ida.inf_get_filetype()

    metadata = {
        "db": db_name,
        "arch": arch,
        "bits": bits,
        "hexrays": hexrays_available,
        "entry": _hex(entry_ea) if entry_ea is not None else None,
        "file_type_id": file_type_id,
    }

    # --- statistics ---
    func_count = 0
    for _ in idautils.Functions():
        func_count += 1

    all_strings = _get_strings_cache()
    string_count = len(all_strings)

    statistics = {"functions": func_count, "strings": string_count}

    # --- interesting_strings: top 15 by xref count ---
    scored_strings: list[tuple[int, dict[str, Any]]] = []
    for s in all_strings:
        xc = count_xrefs_to(s["ea"])
        scored_strings.append((xc, s))
    scored_strings.sort(key=lambda x: x[0], reverse=True)
    interesting_strings = [
        {"addr": _hex(s["ea"]), "val": s["val"][:120], "xrefs": xc}
        for xc, s in scored_strings[:15]
    ]

    # --- interesting_functions: top 15 by incoming xref count ---
    func_entries: list[dict[str, Any]] = []
    for fea in idautils.Functions():
        fn = idaapi.get_func(fea)
        if not fn:
            continue
        name = ida_funcs.get_func_name(fea)
        xc = count_xrefs_to(fea)

        # classify
        insn_count = 0
        call_count = 0
        is_jump_thunk = False
        ea = fn.start_ea
        while ea < fn.end_ea:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length <= 0:
                ea += 1
                continue
            insn_count += 1
            mnem = insn.get_canon_mnem().lower()
            if mnem in ("call", "bl", "blx", "jal", "jalr", "bsr"):
                call_count += 1
            if insn_count == 1 and mnem in ("jmp", "b", "br", "j"):
                is_jump_thunk = True
            ea += length

        if is_jump_thunk and insn_count == 1:
            kind = "thunk"
        elif insn_count <= 20 and 1 <= call_count <= 2:
            kind = "wrapper"
        elif call_count == 0:
            kind = "leaf"
        else:
            kind = "complex"

        func_entries.append({
            "addr": _hex(fea),
            "name": name,
            "size": fn.size(),
            "xrefs": xc,
            "kind": kind,
        })

    func_entries.sort(key=lambda x: x["xrefs"], reverse=True)
    interesting_functions = func_entries[:15]

    # --- imports_by_category ---
    category_patterns = {
        "crypto": re.compile(r"crypt|aes|des|sha|md5|hash|hmac|rsa|cipher|ssl|tls", re.IGNORECASE),
        "network": re.compile(r"socket|connect|send|recv|accept|listen|bind|http|url|inet|dns|tcp|udp", re.IGNORECASE),
        "process": re.compile(r"exec|spawn|fork|process|shell|system|popen|dlopen|loadlib", re.IGNORECASE),
        "file_io": re.compile(r"file|fopen|fread|fwrite|fclose|read|write|open|close|mkdir|unlink|remove", re.IGNORECASE),
    }
    imports_by_category: dict[str, list[str]] = {cat: [] for cat in category_patterns}

    def _categorize_import(ea, name, ordinal):
        if not name:
            return True
        for cat, pat in category_patterns.items():
            if pat.search(name):
                imports_by_category[cat].append(name)
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(i, _categorize_import)

    return {
        "metadata": metadata,
        "statistics": statistics,
        "interesting_strings": interesting_strings,
        "interesting_functions": interesting_functions,
        "imports_by_category": imports_by_category,
    }


rpc.register("survey_binary", survey_binary, doc="One-call binary triage with metadata, stats, and highlights.")


# ============================================================================
# 9. func_query
# ============================================================================

@idaread
def func_query(selector: str) -> dict[str, Any]:
    """Get detailed info about a single function."""
    from .utils import resolve_function

    fn = resolve_function(selector)
    fea = fn.start_ea
    name = ida_funcs.get_func_name(fea)

    flowchart = idaapi.FlowChart(fn)
    bb_count = 0
    for _ in flowchart:
        bb_count += 1

    xrefs_to = count_xrefs_to(fea)

    calls_out = 0
    ea = fn.start_ea
    while ea < fn.end_ea:
        xb = ida_xref.xrefblk_t()
        if xb.first_from(ea, ida_xref.XREF_ALL):
            while True:
                callee_fn = ida_funcs.get_func(xb.to)
                if callee_fn and callee_fn.start_ea != fea:
                    calls_out += 1
                if not xb.next_from():
                    break
        ea = idc.next_head(ea, fn.end_ea)
        if ea == idaapi.BADADDR:
            break

    proto = ""
    if ida_hexrays:
        try:
            if ida_hexrays.init_hexrays_plugin():
                cfunc = ida_hexrays.decompile(fea)
                if cfunc:
                    proto = str(cfunc.type)
        except Exception:
            pass
    if not proto:
        tif = ida_typeinf.tinfo_t()
        if idaapi.get_func_type(fea, tif):
            proto = str(tif)

    return {
        "name": name,
        "addr": _hex(fea),
        "end": _hex(fn.end_ea),
        "size": fn.size(),
        "flags": fn.flags,
        "proto": proto,
        "basic_blocks": bb_count,
        "xrefs_to": xrefs_to,
        "calls_out": calls_out,
    }


rpc.register("func_query", func_query, doc="Get detailed info about a function.")


# ============================================================================
# 10. list_globals
# ============================================================================

@idaread
def list_globals(filter: str = "", offset: int = 0, limit: int = 100) -> dict[str, Any]:
    """List named globals (items not inside a function)."""
    try:
        pat = re.compile(filter, re.IGNORECASE) if filter else None
    except re.error as exc:
        raise IDAError(f"Invalid regex filter: {exc}")

    all_globals: list[dict[str, Any]] = []
    for ea, name in idautils.Names():
        if idaapi.get_func(ea):
            continue
        if pat and not pat.search(name):
            continue
        size = idc.get_item_size(ea)
        all_globals.append({"addr": _hex(ea), "name": name, "size": size})

    total = len(all_globals)
    page = all_globals[offset:offset + limit]
    return {"globals": page, "total": total, "more": offset + limit < total}


rpc.register("list_globals", list_globals, doc="List named globals not inside a function.")


# ============================================================================
# 11. entity_query
# ============================================================================

@idaread
def entity_query(name: str) -> dict[str, Any]:
    """Look up any named entity (function, data, string) by name."""
    ea = idaapi.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
        raise IDAError(f"Name '{name}' not found")

    fn = idaapi.get_func(ea)
    if fn and fn.start_ea == ea:
        kind = "function"
        details: dict[str, Any] = {
            "size": fn.size(),
            "end": _hex(fn.end_ea),
        }
    else:
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_strlit(flags):
            kind = "string"
            raw = ida_bytes.get_strlit_contents(ea, -1, idc.get_str_type(ea))
            val = raw.decode("utf-8", errors="replace") if raw else ""
            details = {"value": val, "size": idc.get_item_size(ea)}
        else:
            kind = "data"
            details = {"size": idc.get_item_size(ea)}

    return {
        "name": name,
        "addr": _hex(ea),
        "kind": kind,
        "details": details,
    }


rpc.register("entity_query", entity_query, doc="Look up a named entity by name.")


# ============================================================================
# 12. imports_list
# ============================================================================

@idaread
def imports_list() -> dict[str, Any]:
    """List all imports grouped by module."""
    import ida_nalt

    modules: list[dict[str, Any]] = []
    total = 0

    for i in range(ida_nalt.get_import_module_qty()):
        mod_name = ida_nalt.get_import_module_name(i) or f"module_{i}"
        entries: list[dict[str, Any]] = []

        def _collector(ea, imp_name, ordinal):
            entries.append({
                "addr": _hex(ea),
                "name": imp_name or "",
                "ordinal": ordinal,
            })
            return True

        ida_nalt.enum_import_names(i, _collector)
        total += len(entries)
        modules.append({"name": mod_name, "imports": entries})

    return {"modules": modules, "total": total}


rpc.register("imports_list", imports_list, doc="List all imports grouped by module.")


# ============================================================================
# 13. imports_query
# ============================================================================

@idaread
def imports_query(filter: str = "", module: str = "") -> dict[str, Any]:
    """Search imports with regex name and module filters."""
    import ida_nalt

    try:
        name_pat = re.compile(filter, re.IGNORECASE) if filter else None
    except re.error as exc:
        raise IDAError(f"Invalid regex filter: {exc}")

    try:
        mod_pat = re.compile(module, re.IGNORECASE) if module else None
    except re.error as exc:
        raise IDAError(f"Invalid module regex: {exc}")

    imports: list[dict[str, Any]] = []

    for i in range(ida_nalt.get_import_module_qty()):
        mod_name = ida_nalt.get_import_module_name(i) or f"module_{i}"
        if mod_pat and not mod_pat.search(mod_name):
            continue

        def _collector(ea, imp_name, ordinal, _mod=mod_name):
            if name_pat and (not imp_name or not name_pat.search(imp_name)):
                return True
            imports.append({
                "addr": _hex(ea),
                "name": imp_name or "",
                "module": _mod,
                "ordinal": ordinal,
            })
            return True

        ida_nalt.enum_import_names(i, _collector)

    total = len(imports)
    return {"imports": imports, "total": total, "more": False}


rpc.register("imports_query", imports_query, doc="Search imports with regex filters.")


# ============================================================================
# 14. idb_save
# ============================================================================

@idawrite
def idb_save() -> dict[str, Any]:
    """Save the current IDB database."""
    import ida_loader

    db_path = idc.get_idb_path()
    with batch_mode():
        result = ida_loader.save_database(db_path, 0)
    if not result:
        raise IDAError(f"Failed to save database to {db_path}")
    return {"ok": True, "path": db_path}


rpc.register("idb_save", idb_save, doc="Save the current IDB database.")


# ============================================================================
# 15. int_convert
# ============================================================================

def int_convert(value: str) -> dict[str, Any]:
    """Parse a number and return decimal, hex, octal, binary, and ASCII representations."""
    try:
        n = int(value, 0)
    except (ValueError, TypeError) as exc:
        raise IDAError(f"Cannot parse '{value}' as integer: {exc}")

    ascii_repr = ""
    if 0 <= n <= 0x10FFFF:
        try:
            ch = chr(n)
            if ch.isprintable():
                ascii_repr = ch
        except (ValueError, OverflowError):
            pass

    return {
        "decimal": n,
        "hex": hex(n),
        "octal": oct(n),
        "binary": bin(n),
        "ascii": ascii_repr,
    }


rpc.register("int_convert", int_convert, doc="Convert a number between decimal, hex, octal, binary, and ASCII.")
