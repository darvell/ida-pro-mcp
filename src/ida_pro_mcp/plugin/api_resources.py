from __future__ import annotations

import logging
from typing import Any

import idaapi
import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_nalt
import ida_segment
import ida_typeinf
import ida_xref
import idautils
import idc

try:
    import ida_kernwin
except ImportError:
    ida_kernwin = None

from .rpc import rpc, IDAError
from .sync import idaread
from .utils import _hex

logger = logging.getLogger(__name__)


# ============================================================================
# 1. resource_idb_metadata
# ============================================================================

@idaread
def resource_idb_metadata() -> dict[str, Any]:
    """Get IDB metadata: file path, architecture, bits, base address, input MD5.

    Returns:
        file_path, arch, bits, base_addr, input_md5
    """
    file_path = idaapi.get_input_file_path() or ""
    arch = ida_ida.inf_get_procname() or ""
    bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
    base_addr = ida_ida.inf_get_min_ea()

    md5_bytes = ida_nalt.retrieve_input_file_md5()
    if md5_bytes and len(md5_bytes) >= 16:
        # ida_nalt returns raw bytes; convert to hex string
        if isinstance(md5_bytes, bytes):
            input_md5 = md5_bytes[:16].hex()
        else:
            input_md5 = str(md5_bytes)
    else:
        input_md5 = ""

    return {
        "file_path": file_path,
        "arch": arch,
        "bits": bits,
        "base_addr": _hex(base_addr),
        "input_md5": input_md5,
    }


rpc.register("resource_idb_metadata", resource_idb_metadata,
             doc="Get IDB metadata for MCP resource.")


# ============================================================================
# 2. resource_idb_segments
# ============================================================================

@idaread
def resource_idb_segments() -> dict[str, Any]:
    """List all segments with details.

    Returns:
        segments: [{name, start, end, size, perm, class, bitness}], count
    """
    segments: list[dict[str, Any]] = []
    seg = ida_segment.get_first_seg()
    while seg:
        perm_str = ""
        if seg.perm & ida_segment.SFL_COMORG:
            pass
        perm_str += "R" if seg.perm & 4 else "-"
        perm_str += "W" if seg.perm & 2 else "-"
        perm_str += "X" if seg.perm & 1 else "-"

        seg_class = ida_segment.get_segm_class(seg) or ""

        segments.append({
            "name": ida_segment.get_segm_name(seg) or "",
            "start": _hex(seg.start_ea),
            "end": _hex(seg.end_ea),
            "size": seg.end_ea - seg.start_ea,
            "perm": perm_str,
            "class": seg_class,
            "bitness": seg.bitness,
        })
        seg = ida_segment.get_next_seg(seg.start_ea)

    return {"segments": segments, "count": len(segments)}


rpc.register("resource_idb_segments", resource_idb_segments,
             doc="List all segments for MCP resource.")


# ============================================================================
# 3. resource_idb_entrypoints
# ============================================================================

@idaread
def resource_idb_entrypoints() -> dict[str, Any]:
    """List entry points with names.

    Returns:
        entries: [{index, ordinal, addr, name}], count
    """
    entries: list[dict[str, Any]] = []
    qty = ida_entry.get_entry_qty()
    for i in range(qty):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal) or ""
        entries.append({
            "index": i,
            "ordinal": ordinal,
            "addr": _hex(ea),
            "name": name,
        })

    return {"entries": entries, "count": len(entries)}


rpc.register("resource_idb_entrypoints", resource_idb_entrypoints,
             doc="List entry points for MCP resource.")


# ============================================================================
# 4. resource_cursor
# ============================================================================

@idaread
def resource_cursor() -> dict[str, Any]:
    """Get current cursor position and containing function.

    Returns:
        addr, func_name, func_addr
    """
    ea = idaapi.get_screen_ea()
    fn = idaapi.get_func(ea)

    result: dict[str, Any] = {"addr": _hex(ea)}
    if fn:
        result["func_name"] = ida_funcs.get_func_name(fn.start_ea)
        result["func_addr"] = _hex(fn.start_ea)
    else:
        result["func_name"] = ""
        result["func_addr"] = ""

    return result


rpc.register("resource_cursor", resource_cursor,
             doc="Get current cursor position for MCP resource.")


# ============================================================================
# 5. resource_selection
# ============================================================================

@idaread
def resource_selection() -> dict[str, Any]:
    """Get the active selection range in the disassembly view.

    Returns:
        has_selection, start, end, size
    """
    if ida_kernwin is None:
        return {"has_selection": False, "start": "", "end": "", "size": 0}

    viewer = ida_kernwin.get_current_viewer()
    if not viewer:
        return {"has_selection": False, "start": "", "end": "", "size": 0}

    start = idaapi.BADADDR
    end = idaapi.BADADDR
    ok = ida_kernwin.read_range_selection(viewer, start, end)

    if ok and start != idaapi.BADADDR and end != idaapi.BADADDR:
        return {
            "has_selection": True,
            "start": _hex(start),
            "end": _hex(end),
            "size": end - start,
        }

    return {"has_selection": False, "start": "", "end": "", "size": 0}


rpc.register("resource_selection", resource_selection,
             doc="Get active selection range for MCP resource.")


# ============================================================================
# 6. resource_types
# ============================================================================

@idaread
def resource_types() -> dict[str, Any]:
    """List local type names and their kinds.

    Returns:
        types: [{name, kind}], count
    """
    til = ida_typeinf.get_idati()
    qty = ida_typeinf.get_ordinal_qty(til)

    types: list[dict[str, str]] = []
    for ordinal in range(1, qty):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue

        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue

        if tif.is_struct():
            kind = "struct"
        elif tif.is_union():
            kind = "union"
        elif tif.is_enum():
            kind = "enum"
        elif tif.is_typeref():
            kind = "typedef"
        else:
            kind = "other"

        types.append({"name": name, "kind": kind})

    return {"types": types, "count": len(types)}


rpc.register("resource_types", resource_types,
             doc="List local types for MCP resource.")


# ============================================================================
# 7. resource_structs
# ============================================================================

@idaread
def resource_structs() -> dict[str, Any]:
    """List all struct names.

    Returns:
        structs: [{name, size}], count
    """
    til = ida_typeinf.get_idati()
    qty = ida_typeinf.get_ordinal_qty(til)

    structs: list[dict[str, Any]] = []
    for ordinal in range(1, qty):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue

        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue

        if not tif.is_struct():
            continue

        structs.append({"name": name, "size": tif.get_size()})

    return {"structs": structs, "count": len(structs)}


rpc.register("resource_structs", resource_structs,
             doc="List all struct names for MCP resource.")


# ============================================================================
# 8. resource_struct_detail
# ============================================================================

@idaread
def resource_struct_detail(name: str) -> dict[str, Any]:
    """Get detailed members of a specific struct.

    Parameters:
        name: Struct type name

    Returns:
        name, size, members: [{name, type, offset, size}]
    """
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()

    if not tif.get_named_type(til, name):
        raise IDAError(f"Struct '{name}' not found")

    if not tif.is_struct():
        raise IDAError(f"Type '{name}' is not a struct")

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        raise IDAError(f"Cannot get details for struct '{name}'")

    members: list[dict[str, Any]] = []
    for m in udt:
        members.append({
            "name": m.name,
            "type": str(m.type),
            "offset": m.offset // 8,
            "size": m.size // 8 if m.size >= 8 else 1,
        })

    return {"name": name, "size": tif.get_size(), "members": members}


rpc.register("resource_struct_detail", resource_struct_detail,
             doc="Get struct member details for MCP resource.")


# ============================================================================
# 9. resource_import_detail
# ============================================================================

@idaread
def resource_import_detail(name: str) -> dict[str, Any]:
    """Look up an import by name.

    Parameters:
        name: Import name to search for

    Returns:
        name, addr, module
    """
    results: list[dict[str, Any]] = []

    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        mod_name = idaapi.get_import_module_name(i)

        def _import_cb(ea: int, imp_name: str, ordinal: int) -> bool:
            if imp_name and name.lower() in imp_name.lower():
                results.append({
                    "name": imp_name,
                    "addr": _hex(ea),
                    "module": mod_name or "",
                    "ordinal": ordinal,
                })
            return True  # continue enumeration

        idaapi.enum_import_names(i, _import_cb)

    if not results:
        raise IDAError(f"Import '{name}' not found")

    if len(results) == 1:
        return results[0]

    return {"matches": results, "count": len(results)}


rpc.register("resource_import_detail", resource_import_detail,
             doc="Look up import by name for MCP resource.")


# ============================================================================
# 10. resource_export_detail
# ============================================================================

@idaread
def resource_export_detail(name: str) -> dict[str, Any]:
    """Look up an export by name.

    Parameters:
        name: Export name to search for

    Returns:
        name, addr, ordinal
    """
    results: list[dict[str, Any]] = []

    qty = ida_entry.get_entry_qty()
    for i in range(qty):
        ordinal = ida_entry.get_entry_ordinal(i)
        entry_name = ida_entry.get_entry_name(ordinal) or ""
        if name.lower() in entry_name.lower():
            ea = ida_entry.get_entry(ordinal)
            results.append({
                "name": entry_name,
                "addr": _hex(ea),
                "ordinal": ordinal,
            })

    if not results:
        raise IDAError(f"Export '{name}' not found")

    if len(results) == 1:
        return results[0]

    return {"matches": results, "count": len(results)}


rpc.register("resource_export_detail", resource_export_detail,
             doc="Look up export by name for MCP resource.")


# ============================================================================
# 11. resource_xrefs_from
# ============================================================================

@idaread
def resource_xrefs_from(address: str) -> dict[str, Any]:
    """Get outgoing cross-references from an address.

    Parameters:
        address: Source address (hex)

    Returns:
        addr, xrefs: [{to, type, func}], count
    """
    from .utils import parse_ea, _hex

    ea = parse_ea(address)
    xrefs: list[dict[str, Any]] = []

    xb = ida_xref.xrefblk_t()
    if xb.first_from(ea, ida_xref.XREF_ALL):
        while True:
            target_fn = ida_funcs.get_func(xb.to)
            xref_type = "code" if xb.type < ida_xref.fl_CF else "data"
            xrefs.append({
                "to": _hex(xb.to),
                "type": xref_type,
                "func": ida_funcs.get_func_name(xb.to) if target_fn else "",
            })
            if not xb.next_from():
                break

    return {"addr": _hex(ea), "xrefs": xrefs, "count": len(xrefs)}


rpc.register("resource_xrefs_from", resource_xrefs_from,
             doc="Get outgoing xrefs from an address for MCP resource.")
