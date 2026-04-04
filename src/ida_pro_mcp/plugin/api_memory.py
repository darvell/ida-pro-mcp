from __future__ import annotations

import logging
import struct
from typing import Any

import ida_bytes
import ida_name
import ida_typeinf
import idaapi

from .rpc import rpc, IDAError
from .sync import idaread, idawrite, batch_mode
from .utils import parse_ea, _hex

logger = logging.getLogger(__name__)

# ============================================================================
# Integer type specifications
# ============================================================================

_INT_TYPES: dict[str, tuple[int, str, bool]] = {
    # name: (byte_width, struct_format, big_endian)
    "u8":    (1, "B",  False),
    "i8":    (1, "b",  False),
    "u16":   (2, "<H", False),
    "i16":   (2, "<h", False),
    "u16be": (2, ">H", True),
    "i16be": (2, ">h", True),
    "u32":   (4, "<I", False),
    "i32":   (4, "<i", False),
    "u32be": (4, ">I", True),
    "i32be": (4, ">i", True),
    "u64":   (8, "<Q", False),
    "i64":   (8, "<q", False),
    "u64be": (8, ">Q", True),
    "i64be": (8, ">q", True),
}


# ============================================================================
# read_bytes
# ============================================================================

@idaread
def read_bytes(address: str, size: int = 64) -> dict[str, Any]:
    """Read raw bytes at an address.

    Parameters:
        address: Hex address to read from
        size: Number of bytes to read (default 64)

    Returns:
        addr, size, hex, ascii, dump (hex dump lines)
    """
    ea = parse_ea(address)
    data = ida_bytes.get_bytes(ea, size)

    if not data:
        raise IDAError(f"Cannot read {size} bytes at {address}")

    hex_str = data.hex()
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)

    hex_dump = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_dump.append(f"{_hex(ea + i)}: {hex_part:48s} {ascii_part}")

    return {
        "addr": _hex(ea),
        "size": len(data),
        "hex": hex_str,
        "ascii": ascii_str,
        "dump": hex_dump,
    }


rpc.register("read_bytes", read_bytes,
             doc="Read raw bytes at an address. Returns hex dump.")


# ============================================================================
# get_int
# ============================================================================

@idaread
def get_int(address: str, type: str = "u32") -> dict[str, Any]:
    """Read a typed integer at an address.

    Parameters:
        address: Hex address to read from
        type: Integer type - u8, i8, u16, i16, u16be, i16be,
              u32, i32, u32be, i32be, u64, i64, u64be, i64be

    Returns:
        addr, type, value, hex
    """
    spec = _INT_TYPES.get(type)
    if spec is None:
        raise IDAError(
            f"Unknown integer type '{type}'. "
            f"Valid types: {', '.join(sorted(_INT_TYPES))}"
        )

    byte_width, fmt, is_big = spec
    ea = parse_ea(address)

    if byte_width == 1:
        raw = ida_bytes.get_byte(ea)
        value = struct.unpack(fmt, bytes([raw]))[0]
    else:
        data = ida_bytes.get_bytes(ea, byte_width)
        if not data or len(data) < byte_width:
            raise IDAError(
                f"Cannot read {byte_width} bytes at {address}"
            )
        value = struct.unpack(fmt, data)[0]

    return {
        "addr": _hex(ea),
        "type": type,
        "value": value,
        "hex": f"0x{value & ((1 << (byte_width * 8)) - 1):X}",
    }


rpc.register("get_int", get_int,
             doc="Read a typed integer value at an address.")


# ============================================================================
# get_string
# ============================================================================

@idaread
def get_string(address: str, encoding: str = "utf-8",
               max_length: int = 1024) -> dict[str, Any]:
    """Read a null-terminated string at an address.

    Parameters:
        address: Hex address to read from
        encoding: String encoding (default utf-8)
        max_length: Maximum bytes to read (default 1024)

    Returns:
        addr, value, length, encoding
    """
    ea = parse_ea(address)
    data = ida_bytes.get_bytes(ea, max_length)

    if not data:
        raise IDAError(f"Cannot read bytes at {address}")

    null_pos = data.find(b"\x00")
    if null_pos >= 0:
        data = data[:null_pos]

    try:
        value = data.decode(encoding, errors="replace")
    except LookupError:
        raise IDAError(f"Unknown encoding '{encoding}'")

    return {
        "addr": _hex(ea),
        "value": value,
        "length": len(data),
        "encoding": encoding,
    }


rpc.register("get_string", get_string,
             doc="Read a null-terminated string at an address.")


# ============================================================================
# get_global_value
# ============================================================================

@idaread
def get_global_value(name: str) -> dict[str, Any]:
    """Resolve a global name to its address and read its value.

    Parameters:
        name: Global symbol name

    Returns:
        name, addr, type, size, value
    """
    ea = ida_name.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
        raise IDAError(f"Global '{name}' not found")

    # Try to get type information for size
    tif = ida_typeinf.tinfo_t()
    has_type = idaapi.get_tinfo(tif, ea)

    if has_type:
        type_str = str(tif)
        size = tif.get_size()
        if size <= 0:
            size = 1
    else:
        type_str = "unknown"
        # Guess size from item
        size = ida_bytes.get_item_size(ea)
        if size <= 0:
            size = 1

    # Cap reads at 8 bytes for integer display; return hex for larger
    if size <= 8:
        data = ida_bytes.get_bytes(ea, size)
        if data and len(data) == size:
            value = int.from_bytes(data, byteorder="little")
        else:
            value = None
    else:
        data = ida_bytes.get_bytes(ea, min(size, 256))
        value = data.hex() if data else None

    return {
        "name": name,
        "addr": _hex(ea),
        "type": type_str,
        "size": size,
        "value": value,
    }


rpc.register("get_global_value", get_global_value,
             doc="Resolve a global name and read its value.")


# ============================================================================
# patch_bytes
# ============================================================================

@idawrite
def patch_bytes(address: str, hex_bytes: str) -> dict[str, Any]:
    """Write raw bytes to the IDB at an address.

    Parameters:
        address: Hex address to write to
        hex_bytes: Hex string of bytes to write (e.g. "90909090")

    Returns:
        addr, size, patched
    """
    ea = parse_ea(address)

    cleaned = hex_bytes.replace(" ", "").replace("-", "")
    if len(cleaned) % 2 != 0:
        raise IDAError("Hex string must have an even number of characters")

    try:
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise IDAError(f"Invalid hex string: {exc}")

    if not data:
        raise IDAError("Empty byte string")

    with batch_mode():
        ida_bytes.patch_bytes(ea, data)

    return {
        "addr": _hex(ea),
        "size": len(data),
        "patched": True,
    }


rpc.register("patch_bytes", patch_bytes,
             doc="Write raw bytes to the IDB.")


# ============================================================================
# put_int
# ============================================================================

@idawrite
def put_int(address: str, value: int, type: str = "u32") -> dict[str, Any]:
    """Write a typed integer at an address.

    Parameters:
        address: Hex address to write to
        value: Integer value to write
        type: Integer type (same options as get_int)

    Returns:
        addr, type, value, ok
    """
    spec = _INT_TYPES.get(type)
    if spec is None:
        raise IDAError(
            f"Unknown integer type '{type}'. "
            f"Valid types: {', '.join(sorted(_INT_TYPES))}"
        )

    byte_width, fmt, is_big = spec
    ea = parse_ea(address)

    with batch_mode():
        if byte_width == 1:
            ida_bytes.patch_byte(ea, value & 0xFF)
        elif byte_width == 2:
            if is_big:
                data = struct.pack(fmt, value)
                ida_bytes.patch_bytes(ea, data)
            else:
                ida_bytes.patch_word(ea, value & 0xFFFF)
        elif byte_width == 4:
            if is_big:
                data = struct.pack(fmt, value)
                ida_bytes.patch_bytes(ea, data)
            else:
                ida_bytes.patch_dword(ea, value & 0xFFFFFFFF)
        elif byte_width == 8:
            if is_big:
                data = struct.pack(fmt, value)
                ida_bytes.patch_bytes(ea, data)
            else:
                ida_bytes.patch_qword(ea, value & 0xFFFFFFFFFFFFFFFF)

    return {
        "addr": _hex(ea),
        "type": type,
        "value": value,
        "ok": True,
    }


rpc.register("put_int", put_int,
             doc="Write a typed integer at an address.")
