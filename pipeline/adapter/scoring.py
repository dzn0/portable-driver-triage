"""Scope ranking — the additive rank formula and cross-profile matching.

Factored out of `bundle.py` so the cheap collection-time L1 pass
(`pipeline.adapter.l1`) can reuse it without pulling in Jinja2 / the whole
bundle writer. `bundle.py` re-imports these names, so its public API is
unchanged.

The rank formula and its rationale are documented in `docs/ranking.md`. The
only input these functions need is a `drveye`-shaped view with two keys:

    {"findings": [{"title": "Dangerous import: X", "details": {"function": X}}, ...],
     "device_names": [...]}

Both the full DrvEye report (deep analysis) and the L1 fingerprint (imports
only, synthesized) satisfy that shape, which is what lets one profile fire the
same way at both stages.
"""
from __future__ import annotations
import functools
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCOPE_PROFILES = REPO_ROOT / "scope_profiles"


def compute_rank(drveye: dict, scope: dict) -> dict:
    weights = scope.get("rank_weights") or {}
    imports = {
        d.get("details", {}).get("function")
        for d in drveye.get("findings", [])
        if (d.get("title") or "").startswith("Dangerous import:")
    }
    must_have_one = set(
        (scope.get("imports_of_interest") or {}).get("must_have_one", []) or []
    )
    weight_each = set(
        (scope.get("imports_of_interest") or {}).get("weight_each", []) or []
    )
    hits = {
        "must_have_one": len(imports & must_have_one),
        "dangerous_imports": len(imports & weight_each),
        "device_match": 0,
        "string_match": 0,
        "ioctl_match": 0,
        "method_match": 0,
        "clone_hit": 0,
    }
    for p in (scope.get("device_name_patterns") or []):
        if any(re.search(p, n) for n in (drveye.get("device_names") or [])):
            hits["device_match"] += 1
    rank = sum(hits[k] * int(weights.get(k, 0)) for k in hits)
    return {
        "rank": rank,
        "hits": hits,
        "qualifies": hits["must_have_one"] > 0,
    }


@functools.lru_cache(maxsize=1)
def _all_profiles() -> tuple[tuple[str, dict], ...]:
    """Every scope profile, as (scope_name, profile_dict), loaded once.

    The scope name is the file stem — the same token `--scope` takes and
    `load_scope` resolves. Cached because compute_scope_matches runs per driver.
    """
    out: list[tuple[str, dict]] = []
    if not SCOPE_PROFILES.is_dir():
        return tuple(out)
    for f in sorted(SCOPE_PROFILES.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        out.append((f.stem, data))
    return tuple(out)


def compute_scope_matches(drveye: dict) -> list[dict]:
    """Cross-profile baseline match: one {scope, rank} entry per profile whose
    `must_have_one` gate fires for this driver, regardless of the run's scope.

    This is what makes cross-scope triage possible (index_row.schema.json /
    AGENTS.md §11): a driver analyzed under one scope still advertises every
    other scope it qualifies for. Sorted by rank desc, then scope asc, so the
    row is deterministic given the same driver + reference files.
    """
    matches = []
    for scope_name, profile in _all_profiles():
        info = compute_rank(drveye, profile)
        if info["qualifies"]:
            matches.append({"scope": scope_name, "rank": info["rank"]})
    matches.sort(key=lambda m: (-m["rank"], m["scope"]))
    return matches


def synth_drveye_view(dangerous_imports: list[str],
                      device_names: list[str] | None = None) -> dict:
    """Build the minimal drveye-shaped view compute_rank/compute_scope_matches
    need from a plain list of imported symbols (+ optional device names).

    Used by the L1 fingerprint and the backfill script, which have the import
    list but not a full DrvEye report."""
    return {
        "findings": [
            {"title": f"Dangerous import: {fn}", "details": {"function": fn}}
            for fn in (dangerous_imports or [])
        ],
        "device_names": list(device_names or []),
    }
