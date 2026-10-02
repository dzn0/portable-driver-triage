"""Entry point: `python -m pipeline.collect <name> [<name> ...]` or `--all`.

Prints a one-line summary per collector and exits non-zero if any failed.
"""
from __future__ import annotations
import argparse
import sys

from . import collectors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline.collect")
    ap.add_argument("names", nargs="*", help="collector name(s)")
    ap.add_argument("--all", action="store_true", help="run every registered collector")
    ap.add_argument("--list", action="store_true", help="list registered collectors and exit")
    args = ap.parse_args(argv)

    if args.list:
        for n in collectors.available():
            print(n)
        return 0

    targets = collectors.available() if args.all else args.names
    if not targets:
        ap.error("specify a collector name or --all (see --list)")

    rc = 0
    for name in targets:
        try:
            c = collectors.get(name)
        except KeyError as e:
            print(f"[{name}] {e}", file=sys.stderr)
            rc = 1
            continue
        m = c.run()
        drivers = len(m.get("drivers") or [])
        print(f"[{name}] {m['status']} drivers={drivers} run_id={m['run_id']}")
        if m["status"] == "failed":
            err = (m.get("error") or {}).get("message", "")
            print(f"[{name}] ERROR: {err}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
