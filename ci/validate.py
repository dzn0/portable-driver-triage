#!/usr/bin/env python3
"""Validate the project's YAML and JSON assets against their schemas.

Checks:
  - refs/*.yaml                 — YAML-parseable, has `version:` and expected top-level block.
  - scope_profiles/*.yaml       — validates against schemas/scope_profile.schema.json.
                                  Warns if `name:` field diverges from filename stem.
  - schemas/examples/*          — each example validates against its matching schema.

Exit 0 on success, non-zero on any failure. Intended for CI (GitHub Actions,
pre-commit) or local pre-flight. Requires: PyYAML, jsonschema.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("ERROR: PyYAML not installed. Run: pip install PyYAML")

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    sys.exit("ERROR: jsonschema not installed. Run: pip install jsonschema")

ROOT = Path(__file__).resolve().parent.parent

SCHEMAS = {
    "index_row":     ROOT / "schemas" / "index_row.schema.json",
    "rejected_row":  ROOT / "schemas" / "rejected_row.schema.json",
    "findings":      ROOT / "schemas" / "findings.schema.json",
    "scope_profile": ROOT / "schemas" / "scope_profile.schema.json",
    "triage":        ROOT / "schemas" / "triage.schema.json",
}

REFS_EXPECTED = {
    "dangerous_imports.yaml":   "categories",
    "interesting_strings.yaml": "categories",
    "device_classes.yaml":      "classes",
}

EXAMPLE_MAP = {
    "index_row.example.json":     "index_row",
    "rejected_row.example.json":  "rejected_row",
    "findings.example.json":      "findings",
    "scope_profile.example.yaml": "scope_profile",
    "triage.example.json":        "triage",
}


def load_json(path: Path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: Path):
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def validator_for(schema_path: Path) -> Draft202012Validator:
    return Draft202012Validator(load_json(schema_path), format_checker=FormatChecker())


def validation_errors(validator: Draft202012Validator, data) -> list[str]:
    out = []
    for e in sorted(validator.iter_errors(data), key=lambda err: list(err.absolute_path)):
        where = "/".join(str(p) for p in e.absolute_path) or "<root>"
        out.append(f"  {where}: {e.message}")
    return out


def report(label: str, errors: list[str]) -> bool:
    if errors:
        print(f"FAIL {label}")
        for err in errors:
            print(err)
        return False
    print(f"OK   {label}")
    return True


def main() -> int:
    ok = True

    # 1. refs/*.yaml — light sanity (parseable + version + expected top key)
    refs_dir = ROOT / "refs"
    for name, expected_key in REFS_EXPECTED.items():
        path = refs_dir / name
        label = f"refs/{name}"
        if not path.exists():
            ok &= report(label, [f"  file not found: {path}"])
            continue
        try:
            data = load_yaml(path)
        except yaml.YAMLError as e:
            ok &= report(label, [f"  YAML parse error: {e}"])
            continue
        errs = []
        if not isinstance(data, dict):
            errs.append("  top-level is not a mapping")
        else:
            if "version" not in data:
                errs.append("  missing top-level `version:`")
            if expected_key not in data:
                errs.append(f"  missing top-level `{expected_key}:`")
        ok &= report(label, errs)

    # 2. scope_profiles/*.yaml — formal schema
    sp_validator = validator_for(SCHEMAS["scope_profile"])
    sp_dir = ROOT / "scope_profiles"
    for path in sorted(sp_dir.glob("*.yaml")):
        label = f"scope_profiles/{path.name}"
        try:
            data = load_yaml(path)
        except yaml.YAMLError as e:
            ok &= report(label, [f"  YAML parse error: {e}"])
            continue
        if isinstance(data, dict) and data.get("name") and data["name"] != path.stem:
            print(f"WARN {label}: name field ({data['name']!r}) does not match filename stem ({path.stem!r})")
        ok &= report(label, validation_errors(sp_validator, data))

    # 3. schemas/examples/* — validate against matching schema
    examples_dir = ROOT / "schemas" / "examples"
    cached: dict[str, Draft202012Validator] = {}
    for fname, schema_name in EXAMPLE_MAP.items():
        path = examples_dir / fname
        label = f"schemas/examples/{fname}"
        if not path.exists():
            ok &= report(label, [f"  file not found: {path}"])
            continue
        if schema_name not in cached:
            cached[schema_name] = validator_for(SCHEMAS[schema_name])
        try:
            data = load_yaml(path) if path.suffix in (".yaml", ".yml") else load_json(path)
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            ok &= report(label, [f"  parse error: {e}"])
            continue
        ok &= report(label, validation_errors(cached[schema_name], data))

    print()
    print("All checks passed." if ok else "Validation failed.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
