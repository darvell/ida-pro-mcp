from __future__ import annotations

import json
import threading
import time
import traceback
import uuid
from typing import Any, Callable, Dict, List, Optional


# ============================================================================
# Exceptions
# ============================================================================

class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class IDAError(JSONRPCError):
    def __init__(self, message: str, data: Any = None):
        super().__init__(-32000, message, data)


# ============================================================================
# Output Size Limiting
# ============================================================================

OUTPUT_LIMIT = 50_000  # chars
_OUTPUT_CACHE_LIMIT = 100

_output_cache_lock = threading.Lock()
_output_cache: Dict[str, str] = {}
_output_cache_order: List[str] = []


def _cache_output(cache_id: str, full_json: str) -> None:
    with _output_cache_lock:
        if cache_id in _output_cache:
            return
        _output_cache[cache_id] = full_json
        _output_cache_order.append(cache_id)
        while len(_output_cache_order) > _OUTPUT_CACHE_LIMIT:
            evict = _output_cache_order.pop(0)
            _output_cache.pop(evict, None)


def get_cached_output(cache_id: str) -> str | None:
    with _output_cache_lock:
        return _output_cache.get(cache_id)


def _truncate_value(value: Any, limit: int = OUTPUT_LIMIT) -> tuple[Any, bool]:
    """Truncate a JSON-serializable value if its serialized form exceeds limit.

    Returns (value, was_truncated).
    """
    serialized = json.dumps(value, default=str)
    if len(serialized) <= limit:
        return value, False

    cache_id = str(uuid.uuid4())
    _cache_output(cache_id, serialized)

    if isinstance(value, dict):
        # Try truncating large string fields first
        result = dict(value)
        for key in list(result.keys()):
            v = result[key]
            if isinstance(v, str) and len(v) > 1000:
                result[key] = v[:1000] + f"... [truncated, {len(v)} chars total]"
            elif isinstance(v, list) and len(v) > 50:
                result[key] = v[:50]
                result[f"_{key}_truncated"] = True
                result[f"_{key}_total"] = len(v)
        result["_truncated"] = True
        result["_truncated_total_chars"] = len(serialized)
        result["_download_id"] = cache_id
        return result, True

    if isinstance(value, str) and len(value) > limit:
        return {
            "value": value[:limit],
            "_truncated": True,
            "_truncated_total_chars": len(value),
            "_download_id": cache_id,
        }, True

    if isinstance(value, list) and len(value) > 50:
        return {
            "items": value[:50],
            "_truncated": True,
            "_total": len(value),
            "_download_id": cache_id,
        }, True

    return value, False


# ============================================================================
# RPC Registry
# ============================================================================

class RPCRegistry:
    def __init__(self) -> None:
        self.methods: Dict[str, Callable] = {}
        self.meta: Dict[str, Dict[str, Any]] = {}

    def register(self, name: str, func: Callable, *, doc: str = "") -> None:
        self.methods[name] = func
        self.meta[name] = {"doc": doc or (func.__doc__ or "").strip()}

    def _suggest_method(self, method: str) -> str:
        from difflib import get_close_matches
        matches = get_close_matches(method, self.methods.keys(), n=3, cutoff=0.4)
        if matches:
            return f" Did you mean: {', '.join(matches)}?"
        available = sorted(self.methods.keys())
        return f" Available methods: {', '.join(m for m in available if not m.startswith('system.'))}"

    def dispatch(self, method: str, params: Any) -> Any:
        if method not in self.methods:
            suggestion = self._suggest_method(method)
            raise JSONRPCError(-32601, f"Method '{method}' not found.{suggestion}")

        func = self.methods[method]
        import inspect
        sig = inspect.signature(func)

        if isinstance(params, dict):
            filtered = {k: v for k, v in params.items() if k in sig.parameters}
            try:
                bound = sig.bind_partial(**filtered)
            except TypeError as e:
                raise JSONRPCError(-32602, f"Invalid params: {e}")
            for pname, p in sig.parameters.items():
                if pname not in bound.arguments and p.default is not inspect._empty:
                    bound.arguments[pname] = p.default
            result = func(*bound.args, **bound.kwargs)
        elif isinstance(params, list):
            result = func(*params)
        else:
            result = func()

        # Apply output size limiting
        result, _ = _truncate_value(result)
        return result


# Shared instance
rpc = RPCRegistry()


# ============================================================================
# Async Job Queue
# ============================================================================

_jobs_lock = threading.Lock()
_jobs: Dict[str, Dict[str, Any]] = {}
_JOB_LIMIT = 200
_JOB_TTL = 300  # seconds


def _prune_jobs() -> None:
    now = time.time()
    with _jobs_lock:
        expired = [jid for jid, j in _jobs.items() if now - j.get("created", now) > _JOB_TTL]
        for jid in expired:
            _jobs.pop(jid, None)

        if len(_jobs) <= _JOB_LIMIT:
            return

        finished = sorted(
            ((j.get("finished", j.get("created", 0)), jid) for jid, j in _jobs.items() if j.get("state") in {"done", "error"}),
            key=lambda x: x[0],
        )
        excess = max(0, len(_jobs) - _JOB_LIMIT)
        for _, jid in finished[:excess]:
            _jobs.pop(jid, None)


def _run_job(job_id: str, method: str, params: Any) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job["state"] = "running"
        job["started"] = time.time()

    try:
        result = rpc.dispatch(method, params)
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job["state"] = "done"
                job["result"] = result
                job["finished"] = time.time()
    except Exception as exc:
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is not None:
                job["state"] = "error"
                job["error"] = str(exc)
                job["finished"] = time.time()


def start_job(method: str, params: Any) -> Dict[str, Any]:
    """Start an asynchronous job; returns a job_id immediately."""
    if method in {"start_job", "job_status", "job_result"}:
        raise JSONRPCError(-32601, "Method not allowed for job runner")
    if method not in rpc.methods:
        raise JSONRPCError(-32601, f"Method '{method}' not found")

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            "state": "pending",
            "method": method,
            "params": params,
            "created": time.time(),
        }
    _prune_jobs()

    t = threading.Thread(target=_run_job, args=(job_id, method, params), daemon=True)
    t.start()

    return {"job_id": job_id, "state": "pending"}


def job_status(job_id: str) -> Dict[str, Any]:
    _prune_jobs()
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise JSONRPCError(-32001, f"Job '{job_id}' not found")
        if time.time() - job.get("created", time.time()) > _JOB_TTL and job.get("state") in {"done", "error"}:
            _jobs.pop(job_id, None)
            raise JSONRPCError(-32001, f"Job '{job_id}' expired")
        return dict(job)


def job_result(job_id: str, *, pop: bool = True) -> Dict[str, Any]:
    _prune_jobs()
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise JSONRPCError(-32001, f"Job '{job_id}' not found")
        state = job.get("state")
        if state in {"pending", "running"}:
            return {"state": state}
        payload = {
            "state": state,
            "result": job.get("result"),
            "error": job.get("error"),
        }
        if pop:
            _jobs.pop(job_id, None)
        return payload


# Register job management methods
rpc.register("start_job", start_job, doc="Start an asynchronous job; returns job_id")
rpc.register("job_status", job_status, doc="Check status of an async job")
rpc.register("job_result", job_result, doc="Get result of an async job (optionally pop)")
