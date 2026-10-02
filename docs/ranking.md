# Scope-profile ranking formula

Every scope profile under `scope_profiles/` is applied to a driver's L1 signals to produce a single integer **rank**. The rank appears in two places inside `reports/index.jsonl`:

- `signals.scope_independent.scope_matches[].rank` — one entry per profile whose `must_have_one` gate fires for this driver, computed regardless of which scope the run was for.
- `signals.scope_dependent.rank` — the rank of the profile the run was actually conducted under. Equal to the matching `scope_matches[].rank` entry.

## The formula

The formula is **purely additive, no normalization**:

```
rank =
    must_have_one_hits         * weights.must_have_one
  + weight_each_hits           * weights.dangerous_imports
  + ioctl_pattern_matches      * weights.ioctl_match
  + device_pattern_matches     * weights.device_match
  + string_match_hits          * weights.string_match
  + method_of_interest_matches * weights.method_match
  + clone_cve_hits             * weights.clone_hit
```

Where:

- `*_hits` and `*_matches` are **counts**, not booleans. A driver that imports four symbols from `weight_each` contributes `4 * dangerous_imports` to the rank, not `1 * dangerous_imports`.
- Each term is `0` when the corresponding count is `0`.
- Negative weights are disallowed by the schema (`schemas/scope_profile.schema.json`). A profile cannot "penalize" a signal.

## Why additive, not weighted-average or percentile

- **Transparency.** `rank = 23` can be decomposed into exact contributions ("18 from a clone hit, 5 from an IOCTL match"). Any triage AI consuming the index can show its work.
- **No calibration drift.** Normalized or percentile scores look prettier but need re-calibration every time a profile's `weight_each` list grows. Additive raw counts just grow with the signal density; no recalibration required.
- **Cross-profile comparability is deliberately NOT a goal.** The weight constants are per-profile. A rank of 20 in `arbitrary-physical-memory` is **not** comparable to a rank of 20 in `hid-input-control`. The Mode-C triage reader must dedup by `(sha256, scope)` and compare only within the same scope.

## What `rank` is NOT

- Not a probability.
- Not a severity. Severity lives in `severity_prior` on the profile (fixed per class) and `severity_in_scope` on each AI finding (per-case).
- Not a ground truth. A rank-30 driver is a strong candidate for human attention, not a confirmed vulnerability.

## Required pipeline behavior

- **Emit `rank: 0`** for profiles whose `must_have_one` gate did not fire. Still include the profile in `scope_matches` so operators can see what was considered and did not match.
- **Round nothing.** Ranks are integers by construction; non-integer weights are not allowed by the schema.
- **Determinism.** Rank calculation is deterministic given the same driver and the same reference files (`refs/*.yaml`). The reference files carry a `version:` field; a bump there forces a reanalysis for ranks to remain comparable.
