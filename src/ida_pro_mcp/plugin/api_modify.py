from __future__ import annotations

import logging
from typing import Any

import ida_bytes
import ida_funcs
import ida_name
import ida_typeinf
import idaapi
import idc

from .rpc import rpc, IDAError
from .sync import idaread, idawrite, batch_mode
from .utils import parse_ea, resolve_function, _hex

logger = logging.getLogger(__name__)

# Optional Hex-Rays
try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None


# ============================================================================
# rename
# ============================================================================

@idawrite
def rename(target: str, new_name: str, batch: list[dict[str, str]] | None = None,
           dry_run: bool = False) -> dict[str, Any]:
    """Rename a function, global, or struct field.

    Supports single renames and batch mode. In batch mode, supply a list of
    {target, new_name} dicts via the batch parameter (target and new_name
    args are ignored when batch is provided).

    Parameters:
        target: Address, function name, or "StructName.field"
        new_name: New name to assign
        batch: Optional list of {target, new_name} for batch renames
        dry_run: If True, resolve names but do not apply changes

    Returns:
        Single: {old, new, kind, addr}
        Batch: {results: [...], total, errors}
    """
    if batch is not None:
        return _rename_batch(batch, dry_run)
    return _rename_single(target, new_name, dry_run)


def _rename_single(target: str, new_name: str,
                   dry_run: bool) -> dict[str, Any]:
    """Apply a single rename operation."""
    with batch_mode():
        # Struct field rename
        if "." in target and not target.startswith("0x"):
            parts = target.split(".", 1)
            struct_name, field_name = parts[0], parts[1]

            til = ida_typeinf.get_idati()
            tif = ida_typeinf.tinfo_t()

            if not tif.get_named_type(til, struct_name):
                raise IDAError(f"Struct '{struct_name}' not found")

            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                raise IDAError(
                    f"Cannot get details for struct '{struct_name}'"
                )

            found = False
            for member in udt:
                if member.name == field_name:
                    if not dry_run:
                        member.name = new_name
                    found = True
                    break

            if not found:
                raise IDAError(
                    f"Field '{field_name}' not found in struct "
                    f"'{struct_name}'"
                )

            if not dry_run:
                tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
                result = tif.set_named_type(
                    til, struct_name, ida_typeinf.NTF_REPLACE
                )
                if result != 0:
                    raise IDAError(
                        f"Failed to rename field (error code {result})"
                    )

            return {
                "old": f"{struct_name}.{field_name}",
                "new": f"{struct_name}.{new_name}",
                "kind": "field",
            }

        # Function or global rename
        try:
            ea = parse_ea(target)
        except IDAError:
            ea = idaapi.get_name_ea(idaapi.BADADDR, target)
            if ea == idaapi.BADADDR:
                fn = resolve_function(target)
                ea = fn.start_ea

        old_name = ida_name.get_name(ea) or f"sub_{ea:X}"
        fn = idaapi.get_func(ea)
        kind = "func" if fn else "global"

        if not dry_run:
            result = ida_name.set_name(ea, new_name, ida_name.SN_CHECK)
            if not result:
                raise IDAError(
                    f"Cannot rename '{old_name}' to '{new_name}'. "
                    "Name may be invalid or already in use."
                )

            if fn and ida_hexrays and ida_hexrays.init_hexrays_plugin():
                ida_hexrays.mark_cfunc_dirty(fn.start_ea)

        return {
            "old": old_name,
            "new": new_name,
            "kind": kind,
            "addr": _hex(ea),
        }


def _rename_batch(items: list[dict[str, str]],
                  dry_run: bool) -> dict[str, Any]:
    """Process a batch of rename operations."""
    results = []
    error_count = 0

    for item in items:
        t = item.get("target", "")
        n = item.get("new_name", "")
        if not t or not n:
            results.append({
                "target": t,
                "ok": False,
                "error": "Missing target or new_name",
            })
            error_count += 1
            continue
        try:
            r = _rename_single(t, n, dry_run)
            r["ok"] = True
            r["target"] = t
            results.append(r)
        except Exception as exc:
            results.append({
                "target": t,
                "ok": False,
                "error": str(exc),
            })
            error_count += 1

    return {
        "results": results,
        "total": len(results),
        "errors": error_count,
    }


rpc.register("rename", rename,
             doc="Rename a function, global, or struct field. "
                 "Supports batch and dry_run modes.")


# ============================================================================
# set_comment
# ============================================================================

@idawrite
def set_comment(address: str, comment: str, comment_type: str = "line",
                view: str = "disasm") -> dict[str, Any]:
    """Add a comment at an address.

    Parameters:
        address: Hex address
        comment: Comment text
        comment_type: "line" (default), "function", or "repeatable"
        view: "disasm" (default) or "decompiler"

    Returns:
        ok, addr, type, view
    """
    ea = parse_ea(address)

    with batch_mode():
        if view == "decompiler" and ida_hexrays and ida_hexrays.init_hexrays_plugin():
            fn = idaapi.get_func(ea)
            if not fn:
                raise IDAError(
                    f"No function at {address} for decompiler comment"
                )
            try:
                cfunc = ida_hexrays.decompile(fn.start_ea)
                if cfunc is None:
                    raise IDAError(
                        f"Decompilation failed for {address}"
                    )
                treeloc = ida_hexrays.treeloc_t()
                treeloc.ea = ea
                treeloc.itp = ida_hexrays.ITP_SEMI
                cfunc.set_user_cmt(treeloc, comment)
                cfunc.save_user_cmts()
            except Exception as exc:
                if "DecompilationFailure" in type(exc).__name__:
                    raise IDAError(
                        f"Decompilation failed for {address}: {exc}"
                    )
                raise
        else:
            if comment_type == "function":
                fn = idaapi.get_func(ea)
                if not fn:
                    raise IDAError(f"No function at {address}")
                ida_funcs.set_func_cmt(fn, comment, 0)
            elif comment_type == "repeatable":
                idc.set_cmt(ea, comment, 1)
            else:
                idc.set_cmt(ea, comment, 0)

    return {
        "ok": True,
        "addr": _hex(ea),
        "type": comment_type,
        "view": view,
    }


rpc.register("set_comment", set_comment,
             doc="Add a comment at an address.")


# ============================================================================
# append_comments
# ============================================================================

@idawrite
def append_comments(address: str, comment: str,
                    comment_type: str = "line") -> dict[str, Any]:
    """Append text to an existing comment, deduplicating.

    If the text is already present in the existing comment, no change is made.

    Parameters:
        address: Hex address
        comment: Text to append
        comment_type: "line" (default), "function", or "repeatable"

    Returns:
        ok, addr, type, appended
    """
    ea = parse_ea(address)

    with batch_mode():
        if comment_type == "function":
            fn = idaapi.get_func(ea)
            if not fn:
                raise IDAError(f"No function at {address}")
            existing = ida_funcs.get_func_cmt(fn, 0) or ""
        elif comment_type == "repeatable":
            existing = idc.get_cmt(ea, 1) or ""
        else:
            existing = idc.get_cmt(ea, 0) or ""

        if comment in existing:
            return {
                "ok": True,
                "addr": _hex(ea),
                "type": comment_type,
                "appended": False,
            }

        if existing:
            new_comment = existing + "\n" + comment
        else:
            new_comment = comment

        if comment_type == "function":
            fn = idaapi.get_func(ea)
            ida_funcs.set_func_cmt(fn, new_comment, 0)
        elif comment_type == "repeatable":
            idc.set_cmt(ea, new_comment, 1)
        else:
            idc.set_cmt(ea, new_comment, 0)

    return {
        "ok": True,
        "addr": _hex(ea),
        "type": comment_type,
        "appended": True,
    }


rpc.register("append_comments", append_comments,
             doc="Append text to an existing comment (dedup).")


# ============================================================================
# patch_asm
# ============================================================================

@idawrite
def patch_asm(address: str, assembly: str) -> dict[str, Any]:
    """Assemble an instruction and patch it at an address.

    Parameters:
        address: Hex address to patch
        assembly: Assembly instruction text

    Returns:
        ok, addr, assembly, size
    """
    ea = parse_ea(address)

    with batch_mode():
        result = idc.assemble(ea, 0, ea, True, assembly)
        if isinstance(result, int) and result == 0:
            raise IDAError(
                f"Assembly failed for '{assembly}' at {_hex(ea)}"
            )
        if isinstance(result, str):
            raise IDAError(
                f"Assembly error at {_hex(ea)}: {result}"
            )

        if isinstance(result, bytes):
            size = len(result)
        else:
            size = idc.get_item_size(ea)

    return {
        "ok": True,
        "addr": _hex(ea),
        "assembly": assembly,
        "size": size,
    }


rpc.register("patch_asm", patch_asm,
             doc="Assemble an instruction and patch at an address.")


# ============================================================================
# define_func
# ============================================================================

@idawrite
def define_func(address: str, end_address: str = "") -> dict[str, Any]:
    """Create a function at an address.

    Parameters:
        address: Start address of the function
        end_address: Optional end address (auto-detected if empty)

    Returns:
        ok, addr, name, size
    """
    ea = parse_ea(address)

    end_ea = idaapi.BADADDR
    if end_address:
        end_ea = parse_ea(end_address)

    with batch_mode():
        if not ida_funcs.add_func(ea, end_ea):
            # Maybe a function already exists here
            fn = idaapi.get_func(ea)
            if fn:
                raise IDAError(
                    f"Function already exists at {_hex(ea)} "
                    f"({ida_funcs.get_func_name(ea)})"
                )
            raise IDAError(f"Cannot create function at {_hex(ea)}")

    fn = idaapi.get_func(ea)
    name = ida_funcs.get_func_name(ea) if fn else f"sub_{ea:X}"
    size = fn.size() if fn else 0

    return {
        "ok": True,
        "addr": _hex(ea),
        "name": name,
        "size": size,
    }


rpc.register("define_func", define_func,
             doc="Create a function at an address.")


# ============================================================================
# define_code
# ============================================================================

@idawrite
def define_code(address: str, size: int = 0) -> dict[str, Any]:
    """Make code (instructions) at an address.

    Parameters:
        address: Address to define as code
        size: Number of bytes to undefine first (0 = just the item)

    Returns:
        ok, addr, size
    """
    ea = parse_ea(address)

    with batch_mode():
        if size > 0:
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)

        insn_len = idc.create_insn(ea)
        if insn_len == 0:
            raise IDAError(f"Cannot create instruction at {_hex(ea)}")

    return {
        "ok": True,
        "addr": _hex(ea),
        "size": insn_len,
    }


rpc.register("define_code", define_code,
             doc="Make code (instructions) at an address.")


# ============================================================================
# undefine
# ============================================================================

@idawrite
def undefine(address: str, size: int = 1) -> dict[str, Any]:
    """Undefine bytes at an address.

    Parameters:
        address: Address to undefine
        size: Number of bytes to undefine (default 1)

    Returns:
        ok, addr, size
    """
    ea = parse_ea(address)

    with batch_mode():
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)

    return {
        "ok": True,
        "addr": _hex(ea),
        "size": size,
    }


rpc.register("undefine", undefine,
             doc="Undefine bytes at an address.")
