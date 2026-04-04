"""IDA version compatibility layer.

Abstracts API differences across IDA 8.3 through 9.2+.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    import idaapi
    import ida_entry
    import ida_funcs
    import ida_ida
    import ida_typeinf
    from ida_pro import IDA_SDK_VERSION

    _SDK = int(IDA_SDK_VERSION)
except ImportError:
    _SDK = 0

IDA_GE_92 = _SDK >= 920
IDA_GE_90 = _SDK >= 900
IDA_GE_85 = _SDK >= 850
IDA_GE_84 = _SDK >= 840
IDA_GE_83 = _SDK >= 830


# ============================================================================
# Entry Points
# ============================================================================

def get_entry_qty() -> int:
    return ida_entry.get_entry_qty()


def get_entry_ordinal(idx: int) -> int:
    return ida_entry.get_entry_ordinal(idx)


def get_entry(ordinal: int) -> int:
    return ida_entry.get_entry(ordinal)


def get_entry_name(ordinal: int) -> str | None:
    return ida_entry.get_entry_name(ordinal)


# ============================================================================
# Function Info
# ============================================================================

def get_func_name(ea: int) -> str:
    return ida_funcs.get_func_name(ea)


def get_func_prototype(ea: int) -> str:
    """Get function prototype string."""
    tif = ida_typeinf.tinfo_t()
    if ida_funcs.get_func(ea):
        if IDA_GE_92:
            try:
                import ida_srclang
                # Try new API first
            except ImportError:
                pass
        if idaapi.get_tinfo(tif, ea):
            return str(tif)
    return ""


# ============================================================================
# Address Space
# ============================================================================

def inf_get_min_ea() -> int:
    return ida_ida.inf_get_min_ea()


def inf_get_max_ea() -> int:
    return ida_ida.inf_get_max_ea()


def inf_is_64bit() -> bool:
    return ida_ida.inf_is_64bit()


def inf_is_32bit() -> bool:
    return ida_ida.inf_is_32bit_exactly()


# ============================================================================
# Type Parsing
# ============================================================================

def parse_type_declaration(til, decl: str, flags: int = 0):
    """Parse a C type declaration, handling IDA version differences."""
    tif = ida_typeinf.tinfo_t()

    if IDA_GE_92:
        try:
            import ida_srclang
            # IDA 9.2 uses source language aware parser
            result = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
            return tif if result is not None else None
        except ImportError:
            pass

    result = ida_typeinf.parse_decl(tif, til, decl, ida_typeinf.PT_SIL)
    return tif if result is not None else None


# ============================================================================
# Binary Search
# ============================================================================

def bin_search(start_ea: int, end_ea: int, compiled, flags: int) -> int:
    """Wrapper for ida_bytes.bin_search handling version differences."""
    import ida_bytes
    result = ida_bytes.bin_search(start_ea, end_ea, compiled, flags)
    if isinstance(result, tuple):
        return result[0]
    return result
