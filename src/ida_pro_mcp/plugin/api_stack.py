from __future__ import annotations

import logging
from typing import Any

import idaapi
import ida_frame
import ida_funcs
import ida_typeinf
import idc

from .rpc import rpc, IDAError
from .sync import idaread, idawrite, batch_mode
from .utils import parse_ea, resolve_function, _hex

logger = logging.getLogger(__name__)


# ============================================================================
# 1. stack_frame
# ============================================================================

@idaread
def stack_frame(selector: str) -> dict[str, Any]:
    """Dump stack frame layout for a function.

    Parameters:
        selector: Function name or "0xADDRESS"

    Returns:
        name, addr, frame_size, members: [{name, offset, size, type}]
    """
    fn = resolve_function(selector)
    ea = fn.start_ea
    func_name = ida_funcs.get_func_name(ea)

    frame = ida_frame.get_frame(fn)
    if not frame:
        raise IDAError(f"No stack frame for function {func_name} at {_hex(ea)}")

    # Use tinfo_t to read the frame struct via ida_typeinf
    frame_size = idc.get_struc_size(frame.id)
    members: list[dict[str, Any]] = []

    offset = 0
    while offset < frame_size:
        mid = idc.get_member_id(frame.id, offset)
        if mid == -1:
            offset += 1
            continue

        m_name = idc.get_member_name(frame.id, offset)
        m_size = idc.get_member_size(frame.id, offset)
        m_flag = idc.get_member_flag(frame.id, offset)

        # Get type string via tinfo
        m_type = ""
        tif = ida_typeinf.tinfo_t()
        # Try to get member type info
        try:
            member = ida_frame.get_stkvar(fn, offset)
            if member:
                # Different approach: get type from the member
                pass
        except Exception:
            pass

        # Fall back to flag-based type name
        if not m_type:
            if m_flag is not None:
                if m_flag & idaapi.byte_flag():
                    m_type = "byte"
                elif m_flag & idaapi.word_flag():
                    m_type = "word"
                elif m_flag & idaapi.dword_flag():
                    m_type = "dword"
                elif m_flag & idaapi.qword_flag():
                    m_type = "qword"

        members.append({
            "name": m_name or f"var_{offset:X}",
            "offset": offset,
            "size": m_size if m_size and m_size > 0 else 1,
            "type": m_type,
        })

        # Advance by member size
        step = m_size if m_size and m_size > 0 else 1
        offset += step

    return {
        "name": func_name,
        "addr": _hex(ea),
        "frame_size": frame_size,
        "members": members,
    }


rpc.register("stack_frame", stack_frame,
             doc="Dump stack frame layout for a function.")


# ============================================================================
# 2. declare_stack
# ============================================================================

@idawrite
def declare_stack(
    selector: str,
    offset: int,
    name: str,
    type_str: str = "",
    size: int = 0,
) -> dict[str, Any]:
    """Add or modify a stack variable in a function's frame.

    Parameters:
        selector: Function name or "0xADDRESS"
        offset: Stack frame offset
        name: Name for the stack variable
        type_str: C type declaration (optional)
        size: Size in bytes (optional, inferred from type if given)

    Returns:
        ok, func_name, offset, name
    """
    fn = resolve_function(selector)
    ea = fn.start_ea
    func_name = ida_funcs.get_func_name(ea)

    frame = ida_frame.get_frame(fn)
    if not frame:
        raise IDAError(f"No stack frame for function {func_name}")

    sid = frame.id

    with batch_mode():
        mid = idc.get_member_id(sid, offset)
        if mid != -1:
            # Rename existing member
            if not idc.set_member_name(sid, offset, name):
                raise IDAError(
                    f"Cannot rename stack member at offset {offset} to '{name}'"
                )
        else:
            # Add a new member
            member_size = size if size > 0 else 1
            result = idc.add_struc_member(
                sid, name, offset, idaapi.byte_flag(), -1, member_size,
            )
            if result != 0:
                raise IDAError(
                    f"Cannot add stack member '{name}' at offset {offset} "
                    f"(error code {result})"
                )

        # Apply type if provided
        if type_str:
            til = ida_typeinf.get_idati()
            tif = ida_typeinf.tinfo_t()
            decl = type_str.strip()
            if not decl.endswith(";"):
                decl += ";"
            parse_result = ida_typeinf.parse_decl(
                tif, til, decl, ida_typeinf.PT_SIL,
            )
            if parse_result is not None:
                # Apply type to the stack member
                idc.SetType(idc.get_member_id(sid, offset), str(tif))

    return {
        "ok": True,
        "func_name": func_name,
        "offset": offset,
        "name": name,
    }


rpc.register("declare_stack", declare_stack,
             doc="Add or modify a stack variable in a function's frame.")


# ============================================================================
# 3. delete_stack
# ============================================================================

@idawrite
def delete_stack(selector: str, offset: int) -> dict[str, Any]:
    """Remove a stack variable from a function's frame.

    Parameters:
        selector: Function name or "0xADDRESS"
        offset: Stack frame offset of the member to delete

    Returns:
        ok, func_name, offset
    """
    fn = resolve_function(selector)
    ea = fn.start_ea
    func_name = ida_funcs.get_func_name(ea)

    frame = ida_frame.get_frame(fn)
    if not frame:
        raise IDAError(f"No stack frame for function {func_name}")

    with batch_mode():
        if not idc.del_struc_member(frame.id, offset):
            raise IDAError(
                f"Cannot delete stack member at offset {offset} in {func_name}"
            )

    return {
        "ok": True,
        "func_name": func_name,
        "offset": offset,
    }


rpc.register("delete_stack", delete_stack,
             doc="Remove a stack variable from a function's frame.")
