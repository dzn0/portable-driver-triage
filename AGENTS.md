# Agent Briefing — Portable Driver Triage

You are an AI assistant working with the output of this project's static driver-analysis pipeline. You may be invoked in one of two modes:

- **Deep analysis** of one pre-analyzed Windows kernel driver bundle. Sections 1 through 10 apply.
- **Mass triage** across the whole corpus of analyzed drivers via `reports/index.jsonl`. Section 11 applies and replaces Sections 2 through 10 for that mode (the hard rules in Sections 1 and 8 still apply).

This file is your contract for both modes. Read the section that matches your invocation.

> Broader project context — what the pipeline is, why these artifacts exist,
> how they were produced — lives in `README.md` at the repository root. This
> file (AGENTS.md) is the operational contract for the per-driver analysis task
> and is self-sufficient; the README is background reading, not required input.

---

## 1. What this project is

Defensive security research tooling for Bring-Your-Own-Vulnerable-Driver (BYOVD)
awareness and detection engineering. Every driver you see here was obtained from
a legitimate vendor source and processed statically — **nothing was executed**.

Your job is **correlation and judgment on top of pre-computed facts**, not raw
reverse engineering from bytes. The hard work of parsing the PE, disassembling,
reconstructing dispatch tables, decompiling, running taint, and matching clones
has already been done. You read the artifacts, cross-check them, and produce a
findings report that cites those artifacts line by line.

## 2. What you must produce

Exactly two files, written to the same `reports/<sha256>/<run_id>/` directory you are
reading from:

- `findings.json` — machine-readable, must validate against `schemas/findings.schema.json`
  at the repo root.
- `findings.md` — human-readable prose, one section per finding, with the same
  citations as the JSON.

Plus any `l3_decomp/<addr>.c` you materialize with `pipeline.decompile` (§3) —
that is the one sanctioned way to add to the bundle. Nothing else: no scratch
notes, and no modifications to any file the pipeline already produced.

## 3. What is in the bundle

The bundle layout has two levels. Facts that depend only on the binary are **shared** at the driver level (`reports/<sha256>/`), while facts that depend on the active scope live inside this analysis's own subdirectory (`reports/<sha256>/<run_id>/`). You are reading from the latter.

Paths below are relative to the current directory. Shared artifacts are reached via `../`.

### Sequential reading order (read front-to-back)

1. **`scope_<name>.md`** — the question being asked for *this* execution. Defines
   which vulnerability class matters, which imports / IOCTLs / device names /
   strings are considered interesting, and the ranking weights the pipeline
   already applied to filter the driver into your lap.
2. **`ai_bundle.md`** — the top-level pre-chewed summary: identity, dangerous
   imports, IOCTL dispatch table, scope matches, and pointers to the specific
   handler files you should open next.
3. **`../identity.json`** — authoritative identity, signing status, PE metadata,
   imports/exports, section entropy, provenance (installer URL + SHA256 at
   download time). Shared across every analysis of this driver.
4. **`ioctls_scoped.json`** — the IOCTL → handler dispatch map, with
   buffering method (`METHOD_BUFFERED` / `METHOD_IN_DIRECT` / `METHOD_OUT_DIRECT`
   / `METHOD_NEITHER`) resolved per IOCTL, filtered by the active scope.
5. **`l3_decomp/<func_addr>.c`** — pseudo-C for a promoted function. These are
   **materialized on demand**, not pre-generated: a bundle ships with only the
   ones the pipeline already needed (often none), and you create any others you
   intend to cite with `pipeline.decompile` (see "Materializing pseudo-C on
   demand" below). One file per function; addresses are absolute (`0x140...`),
   matching the disassembly.
6. **`l3_decomp/taint.json`** — taint **hints** mapped from DrvEye's behavior
   analysis. A wrapper object `{"status", "source", "note", "items"}`. Each item
   names a user-controlled source (`IRP->AssociatedIrp.SystemBuffer`,
   `Type3InputBuffer`, `UserBuffer`, inferred from the IOCTL method) and the
   sensitive sink(s) reachable from it (`MmMapIoSpace`, `MmMapLockedPages*`,
   `__writecr*`, `__wrmsr`, …). Reachability hints, **not** fully traced
   dataflow — confirm in the pseudo-C before upgrading to CONFIRMED.
7. **`l3_decomp/validation_gaps.json`** — same wrapper shape. Each item is an
   IOCTL handler where an expected check (`ProbeForRead` / `ProbeForWrite`,
   `input_length_check`, `caller_privilege_check`, …) was **not** observed
   before a dangerous use, given the handler's buffering method.
8. **`l3_decomp/clones.json`** — same wrapper shape. Each item is a hit against
   the local LOLDrivers snapshot: `match_type` (`sha256-exact` | `imphash`),
   `similarity`, `ref_id`, `cve`, `category`, and the matched sample.
9. **`l3_decomp/summary.md`** — a pre-written sketch of what the L3+ layer
   already noticed. Treat it as hints, not as truth; verify everything.

For items 6–8, read `status` before `items`: **`status: "computed"` with an
empty `items` means "analyzed, found none"** (a real negative you may rely on),
while **`status: "not_computed"` means the input needed to compute it was absent**
(e.g. no LOLDrivers snapshot) — that is an `unknowns` entry, not a clean result.

### Random-access artifacts (open on demand, not front-to-back)

- **`../disasm_full.txt`** — full assembly, one instruction per line, format:
  `0xADDR\t<bytes>\t<mnemonic>\t<operands>`. Function starts are marked with
  inline `FUNC_START: <name>` tags. **Open a ±40-line window around any address
  you need to verify.** Do not read it top-to-bottom; it is routinely tens of
  megabytes. Shared across every analysis of this driver.
- **`../functions.json`** — function boundaries, inferred signatures.
  Use to find where a function begins in `../disasm_full.txt`. Shared.

### Reference material (shared across all reports)

- **`../../../schemas/findings.schema.json`** — the schema your output must
  validate against.
- **`../../../scope_profiles/<name>.yaml`** — the raw scope profile definition if
  you need the full ranking rules.

### Materializing pseudo-C on demand (`pipeline.decompile`)

Full-driver decompilation is expensive and mostly wasted, so the pipeline does
**not** pre-decompile every function. When you need readable pseudo-C for a
function you are about to cite — typically an IOCTL handler or a taint sink you
located in `../disasm_full.txt` / `../functions.json` — generate it yourself:

```
python -m pipeline.decompile <driver_sha256> <func_addr> [--window 0xN] [--backend angr|asm-only]
```

- It writes `l3_decomp/<func_addr>.c` into **this** bundle and prints the path.
- You are authorized to run it **freely**, as many times as you need, without
  asking for approval.
- The generated file is a first-class citation target: it is what satisfies the
  `l3_decomp/*.c` requirement for a `CONFIRMED` finding (§6).
- `<func_addr>` is an address from `../functions.json`. If it is not listed,
  pass `--window 0xN` to decompile a fixed byte range starting at that address.
- The default `angr` backend falls back to an `asm-only` carve-out of
  `../disasm_full.txt` if decompilation fails — still a valid citation target.
- This is **not** a violation of the hard rules in §8: the command is part of
  this pipeline, runs locally, and only reads the `.sys` the pipeline already
  has. You never fetch, see, or decode the raw bytes yourself.

## 4. Reading the scope profile

The scope profile narrows what counts as a finding. Signals *inside* the scope
go into the main `findings` array. Signals *outside* it that you still consider
worth surfacing go into the `out_of_scope` array — never into `findings`.

Ranking weights in the profile are informative, not prescriptive. The pipeline
already used them to pick which functions to decompile. You do not need to
re-score; focus on validating or refuting what the pipeline flagged.

## 5. Output contract

### `findings.json` shape (abbreviated — authoritative schema is linked above)

```json
{
  "driver_sha256": "<hex>",
  "scope": "<scope profile name>",
  "agent": "<model id>",
  "generated_at": "<ISO-8601 UTC>",
  "findings": [
    {
      "id": "F-001",
      "title": "<short, imperative, no clickbait>",
      "class": "<vulnerability class, e.g. arbitrary-physical-memory-read-write>",
      "confidence": "CONFIRMED | PLAUSIBLE",
      "severity_in_scope": "critical | high | medium | low",
      "ioctl": "0x<hex> | null",
      "handler": "0x<hex> | null",
      "method": "METHOD_BUFFERED | METHOD_IN_DIRECT | METHOD_OUT_DIRECT | METHOD_NEITHER | null",
      "call_chain": [
        {"file": "<path inside bundle>", "line": <int>, "note": "<what this line shows>"}
      ],
      "primitive": "<one sentence describing the capability granted>",
      "clone_evidence": {"ref": "<CVE-id or null>", "similarity": <float 0..1>, "source": "<path#anchor>"},
      "detection_ideas": ["<string>", "..."],
      "notes_for_human": "<optional>"
    }
  ],
  "out_of_scope": [ /* same shape, items outside the scope profile */ ],
  "unknowns": ["<things the bundle does not let you resolve>"]
}
```

### `findings.md` shape

One `## F-001 — <title>` section per finding, in the same order as the JSON.
Each section states: the primitive, the call chain in prose (with the same
file+line citations as the JSON, rendered as Markdown links), the clone
evidence if any, detection ideas, and open questions. Keep it tight.

## 6. Citation rules — enforced

Every claim in a finding must be anchored to the bundle.

- Every entry in `call_chain` **must** cite a file inside the bundle and a line
  that actually contains the referenced construct.
- A `CONFIRMED` finding **must** cite at least one line in `l3_decomp/*.c`
  **and**, when the claim concerns a specific instruction, at least one line in
  `../disasm_full.txt`. If the relevant `l3_decomp/<addr>.c` does not exist yet,
  materialize it with `pipeline.decompile` (§3) before citing — a finding is
  never blocked from `CONFIRMED` merely because the file had not been generated.
- A finding of class `asm-pseudo-c-mismatch` **must** cite one line in the
  pseudo-C and one line in `../disasm_full.txt`, and the two must disagree.
- A `PLAUSIBLE` finding may cite only pattern/heuristic evidence (clone,
  validation gap, taint hint) but must still cite the exact entry in the `items`
  array of `l3_decomp/taint.json`, `validation_gaps.json`, or `clones.json` that
  produced the signal.

If a claim cannot be cited, it does not go into `findings`. It goes into
`unknowns` with a one-line description of what is missing.

## 7. Confidence levels — how to pick

- **CONFIRMED** — you traced the capability yourself through the pseudo-C and
  (where applicable) verified the instruction is present in `../disasm_full.txt`. You
  can describe the primitive in operational terms (what the caller controls,
  what the driver does with it, what the result is).
- **PLAUSIBLE** — a pattern or heuristic matched (clone hit, missing probe,
  dangerous import reachable from a user-dispatched IOCTL) and the evidence is
  consistent, but you could not fully trace the path end to end in the bundle.
  State explicitly what verification is still missing.

Never emit `confidence` values outside these two.

## 8. Hard rules — do not negotiate

1. **No invented facts.** If an address, function name, IOCTL code, or string
   is not in the bundle, it does not exist for you. Say "not available in
   bundle" instead of guessing.
2. **No exploit code. No weaponized PoC.** Describe the *primitive* granted
   (e.g. "arbitrary physical memory map into caller address space, R/W"). Never
   provide a working chain, shellcode, or ready-to-run exploit for the specific
   driver. Detection ideas are welcome; weaponization is not.
3. **No fetching, reconstructing, or decoding the raw `.sys` yourself.** You do
   not handle the binary. The one exception is `pipeline.decompile` (§3), which
   reads the pipeline's own local copy and returns pseudo-C — you still never
   fetch, see, or decode the raw bytes.
4. **No modification of pipeline artifacts.** Read everything in the bundle as
   read-only. Write only `findings.json`, `findings.md`, and the
   `l3_decomp/<addr>.c` files produced for you by `pipeline.decompile` (§3).
5. **No external tool calls** — no network, no package install, no container
   escape, no shelling out to third-party disassemblers. The **sole** permitted
   command is this pipeline's own `pipeline.decompile` (§3); anything missing
   beyond what it can produce is an `unknowns` entry, not a reason to go hunting.
6. **Stay inside the scope.** Interesting-but-off-scope observations go into
   `out_of_scope`, never into `findings`.
7. **No speculation about intent.** Report capability, not motive. "Driver
   exposes arbitrary MSR write" is a finding; "driver author intended backdoor"
   is not.

## 9. Handling incomplete or inconsistent bundles

- Missing optional artifact (e.g. `clones.json` absent): proceed, note the gap
  under `unknowns`.
- Missing required artifact (`../identity.json`, `ai_bundle.md`, `scope_*.md`,
  `ioctls_scoped.json`): stop. Emit a minimal `findings.json` with empty `findings`,
  empty `out_of_scope`, and an `unknowns` entry explaining the missing input.
  Do not try to reconstruct it.
- Pipeline hint in `l3_decomp/summary.md` conflicts with what you see: trust
  the primary artifact (pseudo-C + disasm), note the disagreement in
  `notes_for_human`.
- Decompiler output looks suspiciously clean around a sensitive sink: open the
  disasm window for that address range before concluding the sink is safe.
  Decompilers routinely elide validation that is not actually there, and also
  elide dangerous ops that *are* there. Both failure modes happen.

## 10. One tiny example (abbreviated)

Scope: `arbitrary-physical-memory`. Driver exposes IOCTL `0x22e000`, method
`METHOD_NEITHER`, handler at `0x14000b1c0`. `taint.json` traces
`IRP->SystemBuffer` into `MmMapIoSpace(arg1, arg2, …)` and
`validation_gaps.json` reports no `ProbeForRead` on the input.

You open `l3_decomp/0x14000b1c0.c`, confirm the mapping call at line 34 with
attacker-controlled physical address and length, open a window around
`0x14000b1c0+N` in `../disasm_full.txt` to verify the `call MmMapIoSpace` is present,
and emit:

```json
{
  "id": "F-001",
  "title": "Unvalidated MmMapIoSpace reachable via IOCTL 0x22e000",
  "class": "arbitrary-physical-memory-read-write",
  "confidence": "CONFIRMED",
  "severity_in_scope": "high",
  "ioctl": "0x22e000",
  "handler": "0x14000b1c0",
  "method": "METHOD_NEITHER",
  "call_chain": [
    {"file": "l3_decomp/0x14000a200.c", "line": 17, "note": "dispatch to 0x14000b1c0"},
    {"file": "l3_decomp/0x14000b1c0.c", "line": 22, "note": "no ProbeForRead on SystemBuffer"},
    {"file": "l3_decomp/0x14000b1c0.c", "line": 34, "note": "MmMapIoSpace with attacker-controlled PhysicalAddress and Length"},
    {"file": "../disasm_full.txt",       "line": 8422, "note": "call MmMapIoSpace confirmed in raw asm"}
  ],
  "primitive": "Arbitrary physical memory mapped into caller address space, read and write.",
  "clone_evidence": {"ref": "CVE-2020-14979", "similarity": 0.83, "source": "l3_decomp/clones.json#ene_sys"},
  "detection_ideas": [
    "YARA: imports MmMapIoSpace + METHOD_NEITHER dispatch for 0x22e000",
    "EDR: driver load event where ServiceName is not on the allowlist"
  ],
  "notes_for_human": "Pseudo-C elides a length check that is also absent in the asm; the gap is real, not a decompiler artifact."
}
```

That is the standard. Match it.

---

## 11. Mass triage mode

You are in mass triage mode when you are invoked from the project root (not from inside a specific bundle) and the question is a capability-level search across the whole corpus: *"which drivers allow arbitrary physical I/O?"*, *"which touch HID input?"*, *"which are similar to CVE-X?"*. The hard rules in Sections 1 and 8 still apply. Everything else below replaces Sections 2 through 10 for this mode.

### Inputs you read

- **`reports/index.jsonl`** — one JSON per line, one line per analysis. Schema: `schemas/index_row.schema.json`.
- **`reports/rejected.jsonl`** — read only if the question explicitly asks what was considered and rejected. Usually ignored.
- **`scope_profiles/*.yaml`** — read only if you need to understand what a `scope_matches` entry on a row means.

You do **not** open any bundle in this mode. The index is complete for triage; opening bundles is the operator's next step, not yours.

### Reading procedure

1. Load `reports/index.jsonl` once.
2. Deduplicate rows by `(identity.sha256, run.scope_profile)`, keeping the row with the most recent `run.generated_at`.
3. Translate the researcher's question into a predicate over `signals.scope_independent`. Examples of common translations:
   - *"arbitrary physical I/O"* → `dangerous_imports` contains any of {`MmMapIoSpace`, `MmMapLockedPages*`, `ZwMapViewOfSection`, `__writecr*`} **OR** `scope_matches` contains `arbitrary-physical-memory`.
   - *"HID / mouse / keyboard input"* → `device_classes` intersects {`hid`, `input`} **OR** `interesting_strings` contains any of {`Mouclass`, `Kbdclass`, `HidP`} **OR** `scope_matches` contains `hid-input-control`.
   - *"similar to known CVE X"* → `clone_hits[].cve == "X"`.
4. Rank the matches. More matched signals, higher `scope_matches.rank` for the queried capability, and any `clone_hits` with a CVE push a candidate up.
5. Produce the triage report. Do **not** open bundles for deep analysis in this mode.

### Deliverable

Write to `reports/triage/<generated_at_compact>_<query_slug>/triage.json` plus a companion `triage.md`. Create the directories if they do not exist. Nothing else.

### `triage.json` shape

```json
{
  "schema_version": 1,
  "query":            "<researcher's question verbatim>",
  "query_slug":       "<kebab-case short tag used in the dirname>",
  "agent":            "<model id>",
  "generated_at":     "<ISO-8601 UTC>",
  "rows_scanned":     <int>,
  "rows_after_dedup": <int>,
  "predicate_used":   "<human-readable predicate you applied, one sentence>",
  "candidates": [
    {
      "sha256":        "<hex>",
      "scope_profile": "<name>",
      "run_id":        "<id>",
      "rank":          <int>,
      "one_liner":     "<short, factual, cites which signals matched>",
      "matched_signals": {
        "scope_matches":           [{"scope": "...", "rank": <int>}],
        "dangerous_imports_hit":   ["..."],
        "device_classes_hit":      ["..."],
        "interesting_strings_hit": ["..."],
        "clone_hits":              [{"ref_id": "...", "cve": "...", "similarity": <float>}]
      },
      "status":      "already_analyzed_deep | needs_deep_rerun",
      "bundle_path": "<path from the row's evidence_pointers>"
    }
  ],
  "no_matches_but_closely_related": [],
  "unknowns": ["..."]
}
```

### `status` values

- **`already_analyzed_deep`** — the matched row has `top_findings_preview` populated. A Mode A invocation on `bundle_path` can go straight to the AI's prior deep findings.
- **`needs_deep_rerun`** — the matched row was analyzed under a different scope than the capability asked about. Operator should re-run the pipeline on that driver with the matching scope before deep analysis is meaningful.

### `triage.md` shape

A ranked list, one `###` section per candidate, in the same order as the JSON. Each section states the `one_liner`, the matched signals in prose, the `status`, and a Markdown link to `bundle_path`. No findings prose here — this is a navigator, not an analyzer.

### Hard rules specific to this mode

- Do **not** open any bundle. If a candidate warrants deep work, say so via `status`.
- `one_liner` must cite values that actually appear in `matched_signals`. No paraphrases that introduce facts the row does not carry.
- A candidate with empty `matched_signals` is not a candidate — drop it, do not emit it.
- If the predicate finds nothing but the researcher's wording hints at a near-miss (e.g. asked about MSR, found only CR-register-write candidates), put those under `no_matches_but_closely_related` with a short note. Never let them pollute `candidates`.
- When the index is empty or absent, emit a `triage.json` with `rows_scanned: 0`, empty `candidates`, and an `unknowns` entry naming the missing file. Do not improvise.
