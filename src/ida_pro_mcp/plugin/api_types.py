from __future__ import annotations

import logging
from typing import Any

import ida_bytes
import ida_typeinf
import idaapi

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
# set_type
# ============================================================================

@idawrite
def set_type(target: str, type_str: str) -> dict[str, Any]:
    """Set the type of a function, variable, or global.

    Parameters:
        target: Address or name
        type_str: C type declaration

    Returns:
        ok, addr, type
    """
    try:
        ea = parse_ea(target)
    except IDAError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, target)
        if ea == idaapi.BADADDR:
            fn = resolve_function(target)
            ea = fn.start_ea

    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()

    decl = type_str.strip()
    if not decl.endswith(";"):
        decl += ";"

    with batch_mode():
        result = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
        if result is None:
            raise IDAError(
                f"Cannot parse type: '{type_str}'. "
                "Ensure valid C syntax with semicolon."
            )

        apply_result = ida_typeinf.apply_tinfo(
            ea, tif, ida_typeinf.TINFO_DEFINITE
        )
        if not apply_result:
            raise IDAError(
                f"Cannot apply type to {_hex(ea)}. "
                "Type may be incompatible."
            )

        fn = idaapi.get_func(ea)
        if fn and ida_hexrays and ida_hexrays.init_hexrays_plugin():
            ida_hexrays.mark_cfunc_dirty(fn.start_ea)

    return {"ok": True, "addr": _hex(ea), "type": str(tif)}


rpc.register("set_type", set_type,
             doc="Set the type of a function, variable, or global.")


# ============================================================================
# create_struct
# ============================================================================

@idawrite
def create_struct(name: str, definition: str) -> dict[str, Any]:
    """Create a new struct type from C definition.

    Parameters:
        name: Struct name
        definition: C-style struct definition

    Returns:
        name, size, members: [{name, type, off, size}]
    """
    with batch_mode():
        result = ida_typeinf.idc_parse_types(definition, 0)
        if result != 0:
            raise IDAError(
                f"Cannot parse struct definition. Error code: {result}"
            )

        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()

        if not tif.get_named_type(til, name):
            raise IDAError(
                f"Struct '{name}' was not created. "
                "Check the definition syntax."
            )

        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            raise IDAError(f"Cannot get details for struct '{name}'")

        members = []
        for m in udt:
            members.append({
                "name": m.name,
                "type": str(m.type),
                "off": m.offset // 8,
                "size": m.size // 8 if m.size >= 8 else 1,
            })

    return {"name": name, "size": tif.get_size(), "members": members}


rpc.register("create_struct", create_struct,
             doc="Create a new struct type from C definition.")


# ============================================================================
# declare_type
# ============================================================================

@idawrite
def declare_type(declaration: str) -> dict[str, Any]:
    """Parse and register a type declaration string.

    Accepts any valid C type declaration: structs, unions, enums, typedefs.

    Parameters:
        declaration: C type declaration string

    Returns:
        ok, types_added
    """
    with batch_mode():
        result = ida_typeinf.idc_parse_types(declaration, 0)
        if result < 0:
            raise IDAError(
                f"Cannot parse type declaration. Error code: {result}"
            )

    return {"ok": True, "types_added": result}


rpc.register("declare_type", declare_type,
             doc="Parse and register a C type declaration.")


# ============================================================================
# enum_upsert
# ============================================================================

@idawrite
def enum_upsert(name: str, members: list[dict[str, Any]],
                width: int = 4) -> dict[str, Any]:
    """Create or update an enum type.

    If the enum already exists, missing members are added.

    Parameters:
        name: Enum name
        members: List of {name, value} dicts
        width: Byte width (1, 2, 4, or 8; default 4)

    Returns:
        name, id, members: [{name, value}], created
    """
    if not members:
        raise IDAError("Members list must not be empty")

    with batch_mode():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()

        # Check if enum already exists
        created = False
        if tif.get_named_type(til, name):
            # Enum exists -- collect existing member names
            ei = ida_typeinf.enum_type_data_t()
            if not tif.get_enum_details(ei):
                raise IDAError(
                    f"Type '{name}' exists but is not an enum"
                )
            existing_names = {m.name for m in ei}
        else:
            # Build a new enum
            created = True
            ei = ida_typeinf.enum_type_data_t()
            existing_names = set()

        # Add missing members
        for m in members:
            m_name = m.get("name")
            m_value = m.get("value")
            if m_name is None or m_value is None:
                raise IDAError(
                    "Each member must have 'name' and 'value' fields"
                )
            if m_name in existing_names:
                continue
            em = ida_typeinf.enum_member_t()
            em.name = m_name
            em.value = m_value
            ei.push_back(em)
            existing_names.add(m_name)

        # Set byte width via calc_nbytes or bte
        if width in (1, 2, 4, 8):
            ei.calc_nbytes()

        # Build and register the enum type
        tif2 = ida_typeinf.tinfo_t()
        tif2.create_enum(ei)
        tif2.set_named_type(til, name, ida_typeinf.NTF_REPLACE)

        # Read back final state
        tif3 = ida_typeinf.tinfo_t()
        tif3.get_named_type(til, name)
        ei_out = ida_typeinf.enum_type_data_t()
        tif3.get_enum_details(ei_out)

        result_members = []
        for m in ei_out:
            result_members.append({"name": m.name, "value": m.value})

    return {
        "name": name,
        "id": _hex(0),
        "members": result_members,
        "created": created,
    }


rpc.register("enum_upsert", enum_upsert,
             doc="Create or update an enum type.")


# ============================================================================
# read_struct
# ============================================================================

@idaread
def read_struct(address: str, struct_name: str) -> dict[str, Any]:
    """Read memory at an address interpreted as a struct.

    Parameters:
        address: Hex address to read from
        struct_name: Name of a previously defined struct type

    Returns:
        addr, struct_name, fields: [{name, offset, type, size, value}]
    """
    ea = parse_ea(address)

    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()

    if not tif.get_named_type(til, struct_name):
        raise IDAError(f"Struct '{struct_name}' not found")

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        raise IDAError(f"Cannot get details for struct '{struct_name}'")

    struct_size = tif.get_size()
    data = ida_bytes.get_bytes(ea, struct_size) if struct_size > 0 else None

    fields = []
    for m in udt:
        byte_off = m.offset // 8
        byte_size = m.size // 8 if m.size >= 8 else 1

        value = None
        if data and byte_off + byte_size <= len(data):
            field_bytes = data[byte_off:byte_off + byte_size]
            if byte_size <= 8:
                value = int.from_bytes(field_bytes, byteorder="little")
            else:
                value = field_bytes.hex()

        fields.append({
            "name": m.name,
            "offset": byte_off,
            "type": str(m.type),
            "size": byte_size,
            "value": value,
        })

    return {
        "addr": _hex(ea),
        "struct_name": struct_name,
        "fields": fields,
    }


rpc.register("read_struct", read_struct,
             doc="Read memory interpreted as a struct.")


# ============================================================================
# search_structs
# ============================================================================

@idaread
def search_structs(filter: str = "", offset: int = 0,
                   limit: int = 50) -> dict[str, Any]:
    """Search struct/union definitions by name pattern.

    Parameters:
        filter: Regex pattern for name matching (case-insensitive)
        offset: Pagination start index
        limit: Maximum results to return

    Returns:
        structs: [{name, size, member_count}], total, more
    """
    import re
    pattern = re.compile(filter, re.IGNORECASE) if filter else None

    til = ida_typeinf.get_idati()
    qty = ida_typeinf.get_ordinal_qty(til)

    matches = []
    for ordinal in range(1, qty):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue

        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue

        if not tif.is_struct() and not tif.is_union():
            continue

        if pattern and not pattern.search(name):
            continue

        udt = ida_typeinf.udt_type_data_t()
        member_count = 0
        if tif.get_udt_details(udt):
            member_count = udt.size()

        matches.append({
            "name": name,
            "size": tif.get_size(),
            "member_count": member_count,
        })

    total = len(matches)
    page = matches[offset:offset + limit]

    return {
        "structs": page,
        "total": total,
        "more": offset + limit < total,
    }


rpc.register("search_structs", search_structs,
             doc="Search struct/union definitions by name pattern.")


# ============================================================================
# type_query
# ============================================================================

@idaread
def type_query(filter: str = "", kind: str = "", offset: int = 0,
               limit: int = 50) -> dict[str, Any]:
    """Query types in the local type library.

    Parameters:
        filter: Regex pattern for name matching (case-insensitive)
        kind: Filter by kind - "struct", "union", "enum", "typedef", "" (all)
        offset: Pagination start index
        limit: Maximum results to return

    Returns:
        types: [{name, kind, size}], total, more
    """
    import re
    pattern = re.compile(filter, re.IGNORECASE) if filter else None
    valid_kinds = {"struct", "union", "enum", "typedef", ""}
    if kind not in valid_kinds:
        raise IDAError(
            f"Invalid kind '{kind}'. Valid: {', '.join(sorted(valid_kinds))}"
        )

    til = ida_typeinf.get_idati()
    qty = ida_typeinf.get_ordinal_qty(til)

    matches = []
    for ordinal in range(1, qty):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue

        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue

        if tif.is_struct():
            t_kind = "struct"
        elif tif.is_union():
            t_kind = "union"
        elif tif.is_enum():
            t_kind = "enum"
        elif tif.is_typeref():
            t_kind = "typedef"
        else:
            t_kind = "other"

        if kind and t_kind != kind:
            continue

        if pattern and not pattern.search(name):
            continue

        matches.append({
            "name": name,
            "kind": t_kind,
            "size": tif.get_size(),
        })

    total = len(matches)
    page = matches[offset:offset + limit]

    return {
        "types": page,
        "total": total,
        "more": offset + limit < total,
    }


rpc.register("type_query", type_query,
             doc="Query types in the local type library.")


# ============================================================================
# type_inspect
# ============================================================================

@idaread
def type_inspect(name: str) -> dict[str, Any]:
    """Get full details of a named type.

    Parameters:
        name: Type name to inspect

    Returns:
        name, kind, size, details (struct members / enum values / typedef target)
    """
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()

    if not tif.get_named_type(til, name):
        raise IDAError(f"Type '{name}' not found")

    size = tif.get_size()

    if tif.is_struct() or tif.is_union():
        t_kind = "struct" if tif.is_struct() else "union"
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            raise IDAError(f"Cannot get details for {t_kind} '{name}'")

        members = []
        for m in udt:
            members.append({
                "name": m.name,
                "type": str(m.type),
                "offset": m.offset // 8,
                "size": m.size // 8 if m.size >= 8 else 1,
            })
        details = {"members": members}

    elif tif.is_enum():
        t_kind = "enum"
        ei = ida_typeinf.enum_type_data_t()
        if not tif.get_enum_details(ei):
            raise IDAError(f"Cannot get enum details for '{name}'")

        values = []
        for m in ei:
            values.append({"name": m.name, "value": m.value})
        details = {"values": values}

    elif tif.is_typeref():
        t_kind = "typedef"
        target = tif.get_final_type_name()
        details = {"target": target or str(tif)}

    else:
        t_kind = "other"
        details = {"declaration": str(tif)}

    return {
        "name": name,
        "kind": t_kind,
        "size": size,
        "details": details,
    }


rpc.register("type_inspect", type_inspect,
             doc="Get full details of a named type.")


# ============================================================================
# type_apply_batch
# ============================================================================

@idawrite
def type_apply_batch(items: list[dict[str, str]]) -> dict[str, Any]:
    """Batch apply types to multiple targets.

    Parameters:
        items: List of {target, type_str} dicts

    Returns:
        results: [{target, ok, error?}], total, errors
    """
    if not items:
        raise IDAError("Items list must not be empty")

    til = ida_typeinf.get_idati()
    results = []
    error_count = 0

    with batch_mode():
        for item in items:
            target = item.get("target", "")
            type_str_val = item.get("type_str", "")
            if not target or not type_str_val:
                results.append({
                    "target": target,
                    "ok": False,
                    "error": "Missing target or type_str",
                })
                error_count += 1
                continue

            try:
                try:
                    ea = parse_ea(target)
                except IDAError:
                    ea = idaapi.get_name_ea(idaapi.BADADDR, target)
                    if ea == idaapi.BADADDR:
                        fn = resolve_function(target)
                        ea = fn.start_ea

                tif = ida_typeinf.tinfo_t()
                decl = type_str_val.strip()
                if not decl.endswith(";"):
                    decl += ";"

                parse_result = ida_typeinf.parse_decl(
                    tif, til, decl, ida_typeinf.PT_SIL
                )
                if parse_result is None:
                    raise IDAError(f"Cannot parse type: '{type_str_val}'")

                apply_result = ida_typeinf.apply_tinfo(
                    ea, tif, ida_typeinf.TINFO_DEFINITE
                )
                if not apply_result:
                    raise IDAError(
                        f"Cannot apply type to {_hex(ea)}"
                    )

                fn = idaapi.get_func(ea)
                if fn and ida_hexrays and ida_hexrays.init_hexrays_plugin():
                    ida_hexrays.mark_cfunc_dirty(fn.start_ea)

                results.append({"target": target, "ok": True})

            except Exception as exc:
                results.append({
                    "target": target,
                    "ok": False,
                    "error": str(exc),
                })
                error_count += 1

    return {
        "results": results,
        "total": len(results),
        "errors": error_count,
    }


rpc.register("type_apply_batch", type_apply_batch,
             doc="Batch apply types to multiple targets.")


# ============================================================================
# infer_types
# ============================================================================

@idawrite
def infer_types(selector: str) -> dict[str, Any]:
    """Auto-infer types for a function using Hex-Rays.

    Decompiles the function to trigger type inference and returns the
    inferred prototype and local variable types.

    Parameters:
        selector: Function name or address

    Returns:
        name, addr, proto, vars: [{name, type}]
    """
    if not ida_hexrays or not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler is not available")

    fn = resolve_function(selector)
    ea = fn.start_ea

    try:
        cfunc = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure as exc:
        raise IDAError(f"Decompilation failed for {_hex(ea)}: {exc}")

    if cfunc is None:
        raise IDAError(f"Decompilation returned no result for {_hex(ea)}")

    proto = str(cfunc.type)
    func_name = idaapi.get_func_name(ea) or f"sub_{ea:X}"

    lvars = []
    for lvar in cfunc.get_lvars():
        lvars.append({
            "name": lvar.name,
            "type": str(lvar.type()),
        })

    return {
        "name": func_name,
        "addr": _hex(ea),
        "proto": proto,
        "vars": lvars,
    }


rpc.register("infer_types", infer_types,
             doc="Auto-infer types for a function via Hex-Rays.")
