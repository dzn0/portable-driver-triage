"""One-off backfill: recompute `scope_matches` for every row in
`reports/index.jsonl` using the cross-profile logic in
`pipeline.adapter.bundle.compute_scope_matches`.

Why this exists
---------------
Before the cross-profile fix, `scope_matches` only ever recorded the single
*active run scope*, and only when it qualified. Rows produced by a run whose
scope did not fire (e.g. a `hid-input-control` sweep that harvested generic
physical-memory / port-IO drivers) therefore carry an empty `scope_matches`,
and cross-scope triage (AGENTS.md §11) has nothing to read. This script
rebuilds the field for already-analyzed rows **without re-running DrvEye**.

How ranks are reconstructed
---------------------------
`compute_rank` needs only a small `drveye`-shaped view, and every input it uses
for the import-driven terms is already stored on the index row:

  - `findings`      <- synthesized from signals.scope_independent.dangerous_imports
  - `device_names`  <- signals.scope_independent.device_names

That covers `must_have_one`, `dangerous_imports` (weight_each) and
`device_match`. The `ioctl_match` / `method_match` terms are **not**
reconstructable from the index row (the IOCTL table is not stored), so a
backfilled rank is a *lower bound*. That is fine for this script's purpose —
surfacing which scopes a driver qualifies for — because qualification is driven
entirely by `must_have_one`, which is import-based. Rows written by fresh
analysis runs after the fix are unaffected; they rank from full DrvEye output.

Run under the pipeline's interpreter (the one that has PyYAML / produces
bundles), from the repo root:

    python -m scripts.backfill_scope_matches [--dry-run]
    python scripts/backfill_scope_matches.py [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

# Allow both `python -m scripts.backfill_scope_matches` and direct invocation.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline.adapter.bundle import compute_scope_matches  # noqa: E402

INDEX = REPO_ROOT / "reports" / "index.jsonl"


def _synth_drveye(row: dict) -> dict:
    """Minimal drveye-shaped view compute_rank/compute_scope_matches need,
    reconstructed from the fields the index row already carries."""
    si = (row.get("signals") or {}).get("scope_independent") or {}
    imports = si.get("dangerous_imports") or []
    return {
        "findings": [
            {"title": f"Dangerous import: {fn}", "details": {"function": fn}}
            for fn in imports
        ],
        "device_names": si.get("device_names") or [],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="backfill_scope_matches")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change; do not rewrite index.jsonl")
    ap.add_argument("--index", type=Path, default=INDEX,
                    help=f"index file to backfill (default: {INDEX})")
    args = ap.parse_args(argv)

    if not args.index.is_file():
        print(f"error: index not found: {args.index}", file=sys.stderr)
        return 2

    out_lines: list[str] = []
    rows_total = rows_changed = rows_bad = 0
    added_per_scope: Counter[str] = Counter()
    rows_with_any_match = 0

    with args.index.open(encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                out_lines.append(raw.rstrip("\n"))  # preserve blank lines as-is
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                rows_bad += 1
                print(f"warning: line {lineno} is not valid JSON "
                      f"(truncated/corrupt?), left untouched: {line[:60]!r}",
                      file=sys.stderr)
                out_lines.append(raw.rstrip("\n"))  # never drop data
                continue

            rows_total += 1
            si = (row.setdefault("signals", {})
                     .setdefault("scope_independent", {}))
            before = si.get("scope_matches") or []
            after = compute_scope_matches(_synth_drveye(row))

            if after:
                rows_with_any_match += 1
            if after != before:
                rows_changed += 1
                before_scopes = {m["scope"] for m in before}
                for m in after:
                    if m["scope"] not in before_scopes:
                        added_per_scope[m["scope"]] += 1
            si["scope_matches"] = after
            out_lines.append(json.dumps(row, ensure_ascii=False))

    print(f"rows scanned:           {rows_total}")
    print(f"rows with any match:    {rows_with_any_match}")
    print(f"rows changed:           {rows_changed}")
    if rows_bad:
        print(f"non-JSON lines skipped: {rows_bad} (preserved verbatim)")
    if added_per_scope:
        print("newly-added matches per scope:")
        for scope, n in added_per_scope.most_common():
            print(f"  {n:4d}  {scope}")

    if args.dry_run:
        print("\n[dry-run] index.jsonl not modified.")
        return 0

    # Atomic replace: write a sibling temp file, fsync, then os.replace.
    data = ("\n".join(out_lines) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(
        dir=str(args.index.parent), prefix=".index_backfill_", suffix=".jsonl")
    try:
        with os.fdopen(fd, "wb") as tf:
            tf.write(data)
            tf.flush()
            os.fsync(tf.fileno())
        os.replace(tmp_name, args.index)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    print(f"\nrewrote {args.index}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
