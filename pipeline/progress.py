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


def set_count_reporter(fn: Callable[[int], None]) -> None:
    """Register this thread's running-total reporter (drivers stored so far)."""
    _local.count_fn = fn


def clear_reporter() -> None:
    _local.fn = None
    _local.count_fn = None


def current_reporters() -> tuple:
    """Return this thread's (reporter, count_reporter) pair.

    A collector that fans its work out across its own worker threads captures
    these on its main thread and re-registers them inside each worker (the
    channel is thread-local), so sub-steps and the running driver total still
    reach the live renderer from the workers."""
    return getattr(_local, "fn", None), getattr(_local, "count_fn", None)


def report(detail: str) -> None:
    """Report the current sub-step for this thread's collector (best-effort)."""
    fn = getattr(_local, "fn", None)
    if fn is not None:
        try:
            fn(detail)
        except Exception:
            pass  # telemetry must never break collection


def add_count(n: int) -> None:
    """Add `n` to this collector's running driver total (best-effort).

    Lets a long-running catalog collector surface drivers as they are stored,
    instead of only at the end — the live renderer shows the cumulative total,
    which is the meaningful number when a run is never expected to "complete"."""
    if not n:
        return
    fn = getattr(_local, "count_fn", None)
    if fn is not None:
        try:
            fn(n)
        except Exception:
            pass
