from __future__ import annotations

import functools
import os
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Optional

import idaapi
import ida_ida
import ida_funcs
import ida_kernwin
import idc
from ida_pro import IDA_SDK_VERSION


# ============================================================================
# Busy Tracking
# ============================================================================

_BUSY_LOCK = threading.Lock()
_BUSY_COUNT = 0
_BUSY_SINCE_MONO: Optional[float] = None


def _now_mono() -> float:
    return time.monotonic()


def _busy_enter() -> None:
    global _BUSY_COUNT, _BUSY_SINCE_MONO
    with _BUSY_LOCK:
        if _BUSY_COUNT <= 0:
            _BUSY_SINCE_MONO = _now_mono()
            _BUSY_COUNT = 1
            return
        _BUSY_COUNT += 1


def _busy_exit() -> None:
    global _BUSY_COUNT, _BUSY_SINCE_MONO
    with _BUSY_LOCK:
        if _BUSY_COUNT <= 1:
            _BUSY_COUNT = 0
            _BUSY_SINCE_MONO = None
            return
        _BUSY_COUNT -= 1


def _get_busy_snapshot() -> Dict[str, Any]:
    with _BUSY_LOCK:
        busy = _BUSY_COUNT > 0
        busy_for = (_now_mono() - _BUSY_SINCE_MONO) if (busy and _BUSY_SINCE_MONO is not None) else 0.0
        return {
            "busy": busy,
            "busy_count": int(_BUSY_COUNT),
            "busy_for_s": float(busy_for),
        }


# ============================================================================
# Heartbeat Timer
# ============================================================================

_HEARTBEAT_LOCK = threading.Lock()
_MAIN_THREAD_HEARTBEAT_MONO: float = 0.0
_HEARTBEAT_TIMER: Any = None
_HEARTBEAT_INTERVAL_MS = int(os.environ.get("IDA_PRO_MCP_HEARTBEAT_MS", "500"))


def _heartbeat_cb() -> int:
    global _MAIN_THREAD_HEARTBEAT_MONO
    with _HEARTBEAT_LOCK:
        _MAIN_THREAD_HEARTBEAT_MONO = _now_mono()
    return _HEARTBEAT_INTERVAL_MS


def _ensure_heartbeat_timer() -> None:
    global _HEARTBEAT_TIMER
    if _HEARTBEAT_TIMER is not None:
        return
    try:
        _HEARTBEAT_TIMER = ida_kernwin.register_timer(_HEARTBEAT_INTERVAL_MS, _heartbeat_cb)
    except Exception:
        _HEARTBEAT_TIMER = None


def _stop_heartbeat_timer() -> None:
    global _HEARTBEAT_TIMER
    if _HEARTBEAT_TIMER is None:
        return
    try:
        ida_kernwin.unregister_timer(_HEARTBEAT_TIMER)
    except Exception:
        pass
    _HEARTBEAT_TIMER = None


def _get_heartbeat_snapshot() -> Dict[str, Any]:
    with _HEARTBEAT_LOCK:
        last = float(_MAIN_THREAD_HEARTBEAT_MONO)
    age = (_now_mono() - last) if last > 0 else float("inf")
    return {"main_thread_heartbeat_mono": last, "main_thread_heartbeat_age_s": float(age)}


# ============================================================================
# System Metadata Cache
# ============================================================================

_SYSTEM_META_LOCK = threading.Lock()
_SYSTEM_META_BASE: Dict[str, Any] = {}


def _refresh_system_meta_base() -> None:
    """Refresh cached metadata used by system.info (must run on main thread)."""
    db_name = idaapi.get_root_filename() or "unknown"
    bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
    base = {
        "pid": os.getpid(),
        "database": db_name,
        "processor": ida_ida.inf_get_procname(),
        "bitness": bits,
        "ida_sdk": int(IDA_SDK_VERSION),
        "ida_version": str(getattr(ida_kernwin, "get_kernel_version", lambda: "unknown")()),
        "api_style": "ida_* modules",
    }
    with _SYSTEM_META_LOCK:
        _SYSTEM_META_BASE.clear()
        _SYSTEM_META_BASE.update(base)


def _get_system_meta_base() -> Dict[str, Any]:
    with _SYSTEM_META_LOCK:
        return dict(_SYSTEM_META_BASE)


def _clear_system_meta() -> None:
    with _SYSTEM_META_LOCK:
        _SYSTEM_META_BASE.clear()


# ============================================================================
# Thread-Safe Decorators
# ============================================================================

# Execution gate: serialize ALL execute_sync calls (both read and write)
# so only one hits IDA's main thread at a time.
#
# Why reads too: execute_sync posts a callback to IDA's main-thread queue
# and blocks the calling thread on a semaphore. The callback needs the
# Python GIL to run. If N request-handler threads all call execute_sync
# concurrently, they pile up holding/waiting-for the GIL while also
# waiting on the main-thread semaphore. The main thread needs the GIL
# to execute the callbacks but can't get it -> deadlock.
# Observed: parallel decompile_batch -> permanent hang, all threads in
# qsem_wait, main thread idle.
_EXEC_GATE = threading.Semaphore(1)


def idaread(f):
    """Decorator for read-only IDA operations (thread-safe, serialized)."""
    @functools.wraps(f)
    def wrap(*a, **k):
        _EXEC_GATE.acquire()
        try:
            _busy_enter()
            out = []
            def inner():
                try:
                    out.append(f(*a, **k))
                except Exception as e:
                    out.append(e)
            try:
                idaapi.execute_sync(inner, idaapi.MFF_READ)
            finally:
                _busy_exit()
            if not out:
                from .rpc import IDAError
                raise IDAError("IDA execute_sync failed (no result)")
            if isinstance(out[0], Exception):
                raise out[0]
            return out[0]
        finally:
            _EXEC_GATE.release()
    return wrap


def idawrite(f):
    """Decorator for write IDA operations (thread-safe, serialized)."""
    @functools.wraps(f)
    def wrap(*a, **k):
        _EXEC_GATE.acquire()
        try:
            _busy_enter()
            out = []
            def inner():
                try:
                    out.append(f(*a, **k))
                except Exception as e:
                    out.append(e)
            try:
                idaapi.execute_sync(inner, idaapi.MFF_WRITE)
            finally:
                _busy_exit()
            if not out:
                from .rpc import IDAError
                raise IDAError("IDA execute_sync failed (no result)")
            if isinstance(out[0], Exception):
                raise out[0]
            return out[0]
        finally:
            _EXEC_GATE.release()
    return wrap


@contextmanager
def batch_mode():
    """Context manager to suppress IDA dialogs."""
    old = idc.batch(1)
    try:
        yield
    finally:
        idc.batch(old)
