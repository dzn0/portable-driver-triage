"""Stage 1/2 CLI — the cheap L1 fingerprint over the whole corpus, and the
shortlist it produces for the expensive deep stage.

Two modes:

  # compute: fingerprint every driver in the content-addressed store
  python -m pipeline.fingerprint --all [--rebuild]

  # select: print the sha256 of drivers worth deep analysis for a scope
  python -m pipeline.fingerprint --select arbitrary-physical-memory [--min-rank N]

Normally Stage 1 happens *inside* collection (collect_sys_files fingerprints
each driver as it lands), so `--all` is for backfilling a corpus gathered before
that hook existed, or re-running after the reference files changed. `--select`
emits one sha256 per line, ready to pipe into the deep stage:

  python -m pipeline.fingerprint --select msr-access > shas.txt
  python -m pipeline.analyze --all --scope msr-access --sha-list shas.txt
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from . import config
from .adapter import l1


def _existing_shas(path: Path) -> set[str]:
    out: set[str] = set()
    if not path.is_file():
        return out
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.add(json.loads(line)["sha256"])
            except (json.JSONDecodeError, KeyError):
                continue
    return out


def _read_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _dedup_latest(rows: list[dict]) -> dict[str, dict]:
    """Keep the most recent fingerprint per sha256 (by detected_at)."""
    best: dict[str, dict] = {}
    for r in rows:
        sha = r.get("sha256")
        if not sha:
            continue
        cur = best.get(sha)
        if cur is None or (r.get("detected_at", "") >= cur.get("detected_at", "")):
            best[sha] = r
    return best


def _compute_all(rebuild: bool) -> int:
    drivers_dir = config.drivers_dir()
    drivers = sorted(drivers_dir.glob("*.sys"))
    if not drivers:
        print("error: no drivers under pipeline_out/drivers/ (run pipeline.collect first)",
              file=sys.stderr)
        return 2

    if rebuild and l1.FINGERPRINTS.exists():
        l1.FINGERPRINTS.unlink()
    done = set() if rebuild else _existing_shas(l1.FINGERPRINTS)

    computed = skipped = failed = qualified = 0
    for i, p in enumerate(drivers, 1):
        sha = p.stem
        if sha in done:
            skipped += 1
            continue
        row = l1.fingerprint_driver(p, sha)
        if row is None:
            failed += 1
        else:
            computed += 1
            if row["triage"]["qualifies"]:
                qualified += 1
        if i % 200 == 0:
            print(f"[fingerprint] {i}/{len(drivers)} "
                  f"(computed={computed} skipped={skipped} failed={failed})",
                  file=sys.stderr)

    print(f"[fingerprint] done: {len(drivers)} drivers, computed={computed}, "
          f"skipped={skipped}, unparseable={failed}, qualifying={qualified}")
    print(f"[fingerprint] -> {l1.FINGERPRINTS}")
    return 0


def qualifying_shas(scope: str, min_rank: int = 1,
                    path: Path | None = None) -> dict[str, int]:
    """sha256 -> rank for every fingerprinted driver that qualifies for `scope`
    at rank >= `min_rank`. The shortlist the deep stage should analyze. Shared
    by `--select` here and `pipeline.analyze --from-fingerprints`."""
    rows = _dedup_latest(_read_rows(path or l1.FINGERPRINTS))
    out: dict[str, int] = {}
    for sha, r in rows.items():
        for m in (r.get("signals") or {}).get("scope_matches") or []:
            if m.get("scope") == scope and int(m.get("rank", 0)) >= min_rank:
                out[sha] = int(m.get("rank", 0))
                break
    return out


def _select(scope: str, min_rank: int) -> int:
    if not l1.FINGERPRINTS.is_file():
        print(f"error: no fingerprints at {l1.FINGERPRINTS} "
              f"(run --all or collect first)", file=sys.stderr)
        return 2
    picks = sorted(qualifying_shas(scope, min_rank).items(),
                   key=lambda t: (-t[1], t[0]))  # strongest candidates first
    for sha, _ in picks:
        print(sha)
    print(f"[fingerprint] {len(picks)} driver(s) qualify for '{scope}' "
          f"(min-rank={min_rank})", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline.fingerprint")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true",
                   help="fingerprint every driver in the corpus")
    g.add_argument("--select", metavar="SCOPE",
                   help="print sha256 of drivers that qualify for SCOPE "
                        "(one per line, strongest first)")
    ap.add_argument("--rebuild", action="store_true",
                    help="with --all: discard and recompute the whole file")
    ap.add_argument("--min-rank", type=int, default=1,
                    help="with --select: minimum scope rank to include (default 1)")
    args = ap.parse_args(argv)

    if args.all:
        return _compute_all(args.rebuild)
    return _select(args.select, args.min_rank)


if __name__ == "__main__":
    raise SystemExit(main())
