"""Thread-local progress channel.

Collectors run concurrently, one per thread (see `pipeline.collect`). Each
worker thread registers a reporter; the collection primitives in
`collectors._common` (download, extract, scan) call `report(...)` as they work,
and the live renderer picks the latest detail line up per collector.

This is best-effort telemetry only: when no reporter is registered (e.g. a unit
test, or the plain non-TTY path) `report` is a no-op, so instrumentation never
changes behavior.
"""
from __future__ import annotations
import threading
from typing import Callable

_local = threading.local()


def set_reporter(fn: Callable[[str], None]) -> None:
    _local.fn = fn


def clear_reporter() -> None:
    _local.fn = None


def report(detail: str) -> None:
    """Report the current sub-step for this thread's collector (best-effort)."""
    fn = getattr(_local, "fn", None)
    if fn is not None:
        try:
            fn(detail)
        except Exception:
            pass  # telemetry must never break collection
