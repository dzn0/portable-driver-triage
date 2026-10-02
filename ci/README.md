# CI validation

Lightweight validator for the project's YAML and JSON assets. Runs in any Python 3.9+ environment with two dependencies.

## What it checks

- `refs/*.yaml` — YAML-parseable, has `version:` and the expected top-level block (`categories` or `classes`).
- `scope_profiles/*.yaml` — validates against `schemas/scope_profile.schema.json`; warns if the `name:` field diverges from the filename stem.
- `schemas/examples/*` — each example validates against its matching schema (`index_row`, `rejected_row`, `findings`, `scope_profile`, `triage`).

## Run locally

```bash
pip install PyYAML jsonschema
python ci/validate.py
```

Each file prints `OK`, `FAIL`, or `WARN`. Exit code is 0 on success, non-zero on any failure.

## Run in CI

```yaml
- name: Validate schemas and profiles
  run: |
    pip install PyYAML jsonschema
    python ci/validate.py
```

## What it does NOT check

- Pipeline output files (`reports/<sha256>/<run_id>/findings.json`, lines of `index.jsonl` / `rejected.jsonl`). Those are validated by the pipeline itself at write time.
- Semantic coherence across files (e.g. does a `scope_matches[].scope` on an index row refer to a profile that actually exists?). Schemas enforce shape; cross-file coherence is a separate pass.
- Content quality of refs/*.yaml beyond basic structure. The `dangerous_imports`, `interesting_strings` and `device_classes` lists are reviewed by hand against the sources credited in each file's header comment.
