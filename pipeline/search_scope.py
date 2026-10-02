"""Resolve a `--scope` value into a *search* scope for the collectors.

This is the collection-time half of the single scope vocabulary. The same scope
names that `pipeline.analyze --scope <name>` uses to filter *analysis* are reused
here to filter *collection*: a scope profile may carry a `search:` block
(`queries` + catalog-`categories`) that tells a collector what to look for.

`resolve(name)` accepts either:

  - a scope-profile name or its `short_name` (e.g. `hid-input-control`,
    `hidctrl`) → returns that profile's `search:` block, or a sensible fallback
    derived from the profile if it has no `search:` block yet; or
  - any other free-text term (e.g. `mouse`, `network`) → treated as an ad-hoc
    catalog query, so a quick targeted collection needs no profile at all.

yaml is imported lazily so `pipeline.collect --list` keeps working on a box
without PyYAML; only an actual `--scope` call needs it.
"""
from __future__ import annotations
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE_PROFILES = REPO_ROOT / "scope_profiles"


def _load_profiles() -> list[tuple[str, dict]]:
    import yaml
    out: list[tuple[str, dict]] = []
    if not SCOPE_PROFILES.is_dir():
        return out
    for f in sorted(SCOPE_PROFILES.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        out.append((f.stem, data))
    return out


def _derive_search(profile: dict) -> dict:
    """Fallback when a profile has no explicit `search:` block: build queries
    from its device classes / name so --scope still does *something* useful."""
    queries = list(profile.get("device_classes_of_interest") or [])
    if profile.get("name"):
        queries.append(str(profile["name"]).replace("-", " "))
    return {"queries": queries or None, "categories": []}


def resolve(name: str) -> dict:
    """Return {'queries': [...], 'categories': [...], 'label': str, 'source': str}."""
    name = name.strip()
    for stem, profile in _load_profiles():
        if name in (stem, profile.get("name"), profile.get("short_name")):
            search = profile.get("search") or _derive_search(profile)
            return {
                "queries": list(search.get("queries") or []) or None,
                "categories": list(search.get("categories") or []),
                "label": profile.get("name") or stem,
                "source": "profile",
            }
    # No matching profile → treat the term itself as a catalog query.
    return {"queries": [name], "categories": [], "label": name, "source": "adhoc"}
