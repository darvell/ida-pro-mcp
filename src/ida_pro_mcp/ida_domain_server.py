"""
IDA Domain API based MCP server for headless IDA Pro analysis.

This server uses the modern ida-domain package instead of raw IDA Python SDK.
It provides a cleaner, more maintainable implementation for headless analysis.
"""

import sys
import logging
import argparse
from pathlib import Path
from typing import Annotated, Optional, List, Dict, Any

from mcp.server.fastmcp import FastMCP

# Import ida-domain API
from ida_domain import Database

logger = logging.getLogger(__name__)

# Create MCP server
mcp = FastMCP("ida-domain-mcp", log_level="INFO")

# Global database handle
db: Optional[Database] = None


# ============================================================================
# System & Discovery Tools
# ============================================================================

@mcp.tool()
def check_connection() -> Dict[str, Any]:
    """Check if the IDA domain server is running and responsive."""
    global db
    return {
        "status": "ready" if db and db.is_open() else "not_ready",
        "api": "ida-domain",
        "database": str(db.metadata.input_file) if db and db.is_open() else None
    }


@mcp.tool()
def get_metadata() -> Dict[str, Any]:
    """Get metadata about the current database."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    meta = db.metadata
    return {
        "input_file": str(meta.input_file),
        "database_file": str(meta.database_file),
        "min_ea": hex(meta.min_ea),
        "max_ea": hex(meta.max_ea),
        "is_64bit": meta.is_64bit,
        "entry_point": hex(meta.entry_point) if meta.entry_point else None,
        "imagebase": hex(meta.imagebase),
        "file_type": meta.file_type,
        "processor": meta.processor,
    }


# ============================================================================
# Cursor & Navigation Tools
# ============================================================================

@mcp.tool()
def cursor_address() -> str:
    """Get the current screen address (always entry point in headless mode)."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    # In headless mode, we don't have a cursor, so return entry point
    entry = db.metadata.entry_point
    return hex(entry) if entry else hex(db.metadata.min_ea)


# ============================================================================
# Function Analysis Tools
# ============================================================================

@mcp.tool()
def function_list(
    offset: Annotated[int, "Starting offset for pagination"] = 0,
    count: Annotated[int, "Number of functions to return"] = 100
) -> Dict[str, Any]:
    """List all functions in the database with pagination."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    functions = list(db.functions)
    total = len(functions)

    # Apply pagination
    page_funcs = functions[offset:offset + count]

    items = []
    for func in page_funcs:
        items.append({
            "address": hex(func.start_ea),
            "name": func.name,
            "size": func.size,
            "flags": hex(func.flags) if hasattr(func, 'flags') else None
        })

    return {
        "items": items,
        "total": total,
        "offset": offset,
        "count": len(items),
        "next_offset": offset + len(items) if offset + len(items) < total else None
    }


@mcp.tool()
def function_resolve(
    selector: Annotated[str, "Function name or address (hex with 0x prefix)"]
) -> Dict[str, Any]:
    """Resolve a function by name or address."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    # Try to parse as address
    func = None
    if selector.startswith("0x") or selector.startswith("0X"):
        try:
            addr = int(selector, 16)
            func = db.functions.get(addr)
        except ValueError:
            pass

    # Try to find by name
    if func is None:
        for f in db.functions:
            if f.name == selector:
                func = f
                break

    if func is None:
        raise ValueError(f"Function not found: {selector}")

    return {
        "address": hex(func.start_ea),
        "name": func.name,
        "size": func.size,
        "flags": hex(func.flags) if hasattr(func, 'flags') else None
    }


@mcp.tool()
def function_decompile(
    selector: Annotated[str, "Function name or address (hex with 0x prefix)"],
    compact: Annotated[bool, "Return compact pseudocode"] = False
) -> Dict[str, Any]:
    """Decompile a function and return pseudocode."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    # Resolve function
    func_info = function_resolve(selector)
    addr = int(func_info["address"], 16)
    func = db.functions.get(addr)

    if func is None:
        raise ValueError(f"Function not found: {selector}")

    # Get pseudocode
    try:
        pseudocode = func.pseudocode
        if pseudocode:
            lines = str(pseudocode).split('\n')
            if compact:
                lines = [line for line in lines if line.strip()]

            return {
                "address": hex(func.start_ea),
                "name": func.name,
                "pseudocode": '\n'.join(lines),
                "pseudocode_lines": len(lines)
            }
        else:
            return {
                "address": hex(func.start_ea),
                "name": func.name,
                "error": "Decompilation failed or not available"
            }
    except Exception as e:
        return {
            "address": hex(func.start_ea),
            "name": func.name,
            "error": str(e)
        }


@mcp.tool()
def function_disassemble(
    selector: Annotated[str, "Function name or address (hex with 0x prefix)"],
    compact: Annotated[bool, "Return compact disassembly"] = True,
    include_comments: Annotated[bool, "Include comments"] = True
) -> Dict[str, Any]:
    """Disassemble a function and return assembly code."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    # Resolve function
    func_info = function_resolve(selector)
    addr = int(func_info["address"], 16)
    func = db.functions.get(addr)

    if func is None:
        raise ValueError(f"Function not found: {selector}")

    # Get disassembly
    disasm_lines = []
    for insn in db.instructions(func.start_ea, func.end_ea):
        line = f"{hex(insn.ea)}: {insn.mnemonic}"
        if hasattr(insn, 'op_str') and insn.op_str:
            line += f" {insn.op_str}"

        if include_comments:
            # Get comment if available
            comment = db.comments.get(insn.ea)
            if comment:
                line += f"  ; {comment}"

        if not compact or line.strip():
            disasm_lines.append(line)

    return {
        "address": hex(func.start_ea),
        "name": func.name,
        "disassembly": '\n'.join(disasm_lines),
        "instruction_count": len(disasm_lines)
    }


# ============================================================================
# Cross-Reference Tools
# ============================================================================

@mcp.tool()
def xref_to(
    address: Annotated[str, "Address to get xrefs to (hex with 0x prefix)"]
) -> List[Dict[str, Any]]:
    """Get all cross-references to the given address."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    addr = int(address, 16)
    xrefs = []

    for xref in db.xrefs.to(addr):
        xrefs.append({
            "from": hex(xref.frm),
            "to": hex(xref.to),
            "type": xref.type.name if hasattr(xref.type, 'name') else str(xref.type),
            "is_code": xref.is_code if hasattr(xref, 'is_code') else None
        })

    return xrefs


@mcp.tool()
def xref_from(
    address: Annotated[str, "Address to get xrefs from (hex with 0x prefix)"]
) -> List[Dict[str, Any]]:
    """Get all cross-references from the given address."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    addr = int(address, 16)
    xrefs = []

    for xref in db.xrefs.frm(addr):
        xrefs.append({
            "from": hex(xref.frm),
            "to": hex(xref.to),
            "type": xref.type.name if hasattr(xref.type, 'name') else str(xref.type),
            "is_code": xref.is_code if hasattr(xref, 'is_code') else None
        })

    return xrefs


# ============================================================================
# String Analysis Tools
# ============================================================================

@mcp.tool()
def list_strings(
    offset: Annotated[int, "Starting offset for pagination"] = 0,
    count: Annotated[int, "Number of strings to return"] = 100,
    filter: Annotated[str, "Filter strings by pattern"] = ""
) -> Dict[str, Any]:
    """List all strings in the database with optional filtering."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    all_strings = list(db.strings)

    # Apply filter if provided
    if filter:
        filtered = []
        for s in all_strings:
            if filter.lower() in str(s.value).lower():
                filtered.append(s)
        all_strings = filtered

    total = len(all_strings)

    # Apply pagination
    page_strings = all_strings[offset:offset + count]

    items = []
    for s in page_strings:
        items.append({
            "address": hex(s.ea),
            "value": str(s.value),
            "length": len(s.value) if hasattr(s, 'value') else 0,
            "type": s.strtype.name if hasattr(s, 'strtype') and hasattr(s.strtype, 'name') else None
        })

    return {
        "items": items,
        "total": total,
        "offset": offset,
        "count": len(items),
        "next_offset": offset + len(items) if offset + len(items) < total else None
    }


# ============================================================================
# Name & Comment Tools
# ============================================================================

@mcp.tool()
def rename_function(
    selector: Annotated[str, "Function name or address (hex with 0x prefix)"],
    new_name: Annotated[str, "New name for the function"]
) -> str:
    """Rename a function."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    # Resolve function
    func_info = function_resolve(selector)
    addr = int(func_info["address"], 16)

    # Set new name
    db.names.set(addr, new_name)

    return f"Renamed function at {hex(addr)} to '{new_name}'"


@mcp.tool()
def set_comment(
    address: Annotated[str, "Address to set comment (hex with 0x prefix)"],
    comment: Annotated[str, "Comment text"]
) -> str:
    """Set a comment at the given address."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    addr = int(address, 16)
    db.comments.set(addr, comment)

    return f"Set comment at {hex(addr)}"


@mcp.tool()
def get_comment(
    address: Annotated[str, "Address to get comment (hex with 0x prefix)"]
) -> Optional[str]:
    """Get comment at the given address."""
    global db
    if not db or not db.is_open():
        raise RuntimeError("Database not open")

    addr = int(address, 16)
    return db.comments.get(addr)


# ============================================================================
# Entry Point
# ============================================================================

def main():
    global db

    parser = argparse.ArgumentParser(description="MCP server for IDA Pro using ida-domain API")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug messages")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to listen on, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8746, help="Port to listen on, default: 8746")
    parser.add_argument("--save-on-close", action="store_true", help="Save database on close")
    parser.add_argument("input_path", type=Path, help="Path to the input file to analyze.")
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    mcp.settings.log_level = logging.getLevelName(log_level)
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    logging.basicConfig(level=log_level)

    if not args.input_path.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_path}")

    # Open database using ida-domain API
    logger.info("Opening database: %s", args.input_path)
    db = Database.open(str(args.input_path), save_on_close=args.save_on_close)

    if not db.is_open():
        raise RuntimeError("Failed to open database")

    logger.info("Database opened successfully")
    logger.info("Metadata: %s", db.metadata)

    # Start MCP server
    logger.info("MCP Server available at: http://%s:%d/sse", args.host, args.port)
    try:
        mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass
    finally:
        if db and db.is_open():
            logger.info("Closing database...")
            db.close()


if __name__ == "__main__":
    main()
