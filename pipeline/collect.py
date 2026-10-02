"""Entry point: `python -m pipeline.collect <name> [<name> ...]` or `--all`.

Collectors run concurrently (thread pool): each is independent I/O-bound work
(download + extract) that writes to its own `run_id` directory, and the shared
`drivers_dir` store is content-addressed, so parallel runs do not conflict.

On a TTY the progress is drawn in place, docker-compose style: one line per
collector whose spinner turns into a green check (success), yellow mark (nothing
extracted) or red cross (failed) as it finishes. When stdout is not a TTY
(piped, CI, `-T`) it falls back to one summary line per collector as each ends.
Exits non-zero if any collector failed.
"""
from __future__ import annotations
import argparse
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import collectors
from . import progress

# ── ANSI ────────────────────────────────────────────────────────────────────
_RESET = "\033[0m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_HIDE = "\033[?25l"
_SHOW = "\033[?25h"
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_NAME_W = 18


# ── shared progress state ─────────────────────────────────────────────────────
class _Progress:
    def __init__(self, names: list[str]) -> None:
        self._lock = threading.Lock()
        self.order = list(names)
        self.rows = {
            n: {"phase": "pending", "status": None, "drivers": 0,
                "error": "", "detail": "", "start": None, "end": None}
            for n in names
        }

    def running(self, name: str) -> None:
        with self._lock:
            r = self.rows[name]
            r["phase"] = "running"
            r["start"] = time.monotonic()

    def detail(self, name: str, text: str) -> None:
        with self._lock:
            self.rows[name]["detail"] = text

    def done(self, name: str, *, status: str, drivers: int = 0, error: str = "") -> None:
        with self._lock:
            r = self.rows[name]
            now = time.monotonic()
            r.update(phase="done", status=status, drivers=drivers,
                     error=error, end=now)
            if r["start"] is None:
                r["start"] = now

    def snapshot(self) -> dict:
        with self._lock:
            return {n: dict(v) for n, v in self.rows.items()}


def _elapsed(r: dict) -> str:
    if r["start"] is None:
        return ""
    end = r["end"] if r["end"] is not None else time.monotonic()
    return f"{end - r['start']:.1f}s"


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: max(1, n - 1)] + "…"


def _render(prog: _Progress, frame: int, started: float) -> list[str]:
    rows = prog.snapshot()
    done = sum(1 for r in rows.values() if r["phase"] == "done")
    total = len(prog.order)
    spin = _SPINNER[frame % len(_SPINNER)]
    # leave room for " <glyph> <name padded> " prefix and " <elapsed>" suffix
    width = shutil.get_terminal_size((100, 40)).columns
    detail_w = max(16, width - _NAME_W - 14)
    head = f"{_CYAN}[+] Collecting {done}/{total}{_RESET}  {_DIM}{time.monotonic()-started:.1f}s{_RESET}"
    lines = [head]
    for name in prog.order:
        r = rows[name]
        phase = r["phase"]
        if phase == "pending":
            glyph, text = f"{_DIM}⠿{_RESET}", f"{_DIM}pending{_RESET}"
        elif phase == "running":
            detail = r["detail"] or "collecting…"
            glyph, text = f"{_CYAN}{spin}{_RESET}", f"{_DIM}{_clip(detail, detail_w)}{_RESET}"
        elif r["status"] == "success":
            glyph, text = f"{_GREEN}✔{_RESET}", f"{_GREEN}success{_RESET} drivers={r['drivers']}"
        elif r["status"] == "failed":
            glyph, text = f"{_RED}✖{_RESET}", f"{_RED}failed{_RESET} {_DIM}{r['error'][:48]}{_RESET}"
        else:  # no_driver_extracted and any other non-failure terminal status
            glyph, text = f"{_YELLOW}⚠{_RESET}", f"{_YELLOW}{r['status']}{_RESET}"
        lines.append(f" {glyph} {name:<{_NAME_W}} {text}  {_DIM}{_elapsed(r):>6}{_RESET}")
    return lines


def _worker(name: str, prog: _Progress) -> bool:
    """Run one collector, updating `prog`. Returns True on failure."""
    prog.running(name)
    progress.set_reporter(lambda detail: prog.detail(name, detail))
    try:
        c = collectors.get(name)
    except KeyError as e:
        prog.done(name, status="failed", error=str(e))
        return True
    try:
        m = c.run()
    finally:
        progress.clear_reporter()
    status = m["status"]
    err = (m.get("error") or {}).get("message", "") if status == "failed" else ""
    prog.done(name, status=status, drivers=len(m.get("drivers") or []), error=err)
    return status == "failed"


def _run_live(targets: list[str], jobs: int, prog: _Progress) -> int:
    """TTY path: concurrent run with an in-place redrawn progress block."""
    n_lines = len(targets) + 1
    started = time.monotonic()
    stop = threading.Event()

    def emit(lines: list[str], move_up: int) -> None:
        buf = f"\033[{move_up}A" if move_up else ""
        for ln in lines:
            buf += "\r\033[K" + ln + "\n"
        sys.stdout.write(buf)
        sys.stdout.flush()

    def loop() -> None:
        frame = 0
        sys.stdout.write(_HIDE)
        emit(_render(prog, frame, started), 0)
        while not stop.is_set():
            time.sleep(0.1)
            frame += 1
            emit(_render(prog, frame, started), n_lines)
        emit(_render(prog, frame, started), n_lines)  # final, settled frame
        sys.stdout.write(_SHOW)
        sys.stdout.flush()

    renderer = threading.Thread(target=loop, daemon=True)
    renderer.start()
    rc = 0
    try:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            for failed in [f.result() for f in
                           [pool.submit(_worker, n, prog) for n in targets]]:
                rc |= int(failed)
    finally:
        stop.set()
        renderer.join()
        sys.stdout.write(_SHOW)
        sys.stdout.flush()
    return rc


def _run_plain(targets: list[str], jobs: int, prog: _Progress) -> int:
    """Non-TTY path: one summary line per collector as each finishes."""
    from concurrent.futures import as_completed
    rc = 0
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futs = {pool.submit(_worker, n, prog): n for n in targets}
        for fut in as_completed(futs):
            name = futs[fut]
            failed = fut.result()
            r = prog.snapshot()[name]
            print(f"[{name}] {r['status']} drivers={r['drivers']}")
            if failed:
                print(f"[{name}] ERROR: {r['error']}", file=sys.stderr)
            rc |= int(failed)
    return rc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline.collect")
    ap.add_argument("names", nargs="*", help="collector name(s)")
    ap.add_argument("--all", action="store_true", help="run every registered collector")
    ap.add_argument("--list", action="store_true", help="list registered collectors and exit")
    ap.add_argument("-j", "--jobs", type=int, default=4,
                    help="max collectors to run concurrently (default: 4; 1 = serial)")
    ap.add_argument("--no-progress", action="store_true",
                    help="force plain line output even on a TTY")
    args = ap.parse_args(argv)

    if args.list:
        for n in collectors.available():
            print(n)
        return 0

    targets = collectors.available() if args.all else args.names
    if not targets:
        ap.error("specify a collector name or --all (see --list)")

    jobs = max(1, min(args.jobs, len(targets)))
    prog = _Progress(targets)
    live = sys.stdout.isatty() and not args.no_progress
    return _run_live(targets, jobs, prog) if live else _run_plain(targets, jobs, prog)


if __name__ == "__main__":
    raise SystemExit(main())
