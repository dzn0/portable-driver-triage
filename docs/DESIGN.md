# Design & architecture

> This is the design document: the rationale, the layered methodology, the engine-reuse pivot, and the implementation status. For a short "clone and use" guide, see the [README](../README.md). The two are complementary — the README teaches usage, this file explains *why the pipeline is shaped the way it is*.

> **Clone the repo, connect your AI, start triaging.** A self-contained, stateless pipeline that collects real-world Windows drivers from legitimate sources, extracts the ones nested inside installers, and pre-computes a deep static analysis so that AI-assisted vulnerability research starts from structured facts instead of raw bytes.

---

## Why this exists

The hardest first mile of defensive driver research is simply **finding and extracting drivers that actually shipped in real products**. The drivers that matter for Bring-Your-Own-Vulnerable-Driver (BYOVD) work rarely sit in a tidy index — they are buried inside installers, OEM bundles, and update packages scattered across vendor sites.

This project closes that gap. It locates candidate drivers via public indexes, downloads them from their original vendors, extracts them from their parent binaries, and pre-computes a layered static analysis so that the hand-off to an AI model (or a human analyst) is as pre-digested as possible.

## Design principles

- **Stateless & portable** — clone, run, get results. No persistent server, no hidden state.
- **Zero-config static core** — the full pipeline runs inside a sandboxed container with every tool bundled. No "install these 14 libraries first."
- **Metadata over binaries** — the repo stores analysis output and references, not a re-hosted archive of potentially malicious drivers. Binaries are fetched on demand from legitimate sources.
- **Discovery is separate from distribution** — indexes are used to *find* installers; the actual download always goes to the vendor's original URL.
- **Defensive by construction** — cross-references known-vulnerable driver datasets and reports attack-surface indicators, so the output serves triage and detection engineering.
- **Cheap triage before expensive analysis** — the signals that decide *whether a driver is worth the deep engine* (dangerous imports, imphash clone family, and therefore which scope profiles it qualifies for) all come from the PE import table, which is nearly free to read. So the pipeline computes them first, on everything (**L0 gate + L1 fingerprint**, fused into collection → `reports/fingerprints.jsonl`), and only runs the expensive engine on the shortlist. This resolves the chicken-and-egg of "you need details to filter, but extracting details is the expensive thing": the *filtering* details are cheap; only the *confirming* details (IOCTL dispatch, taint) are expensive. See [docs/ranking.md](ranking.md#l1-vs-deep-rank).
- **Reuse the engine, own the layers above and below** — the heavy static-analysis engine (disassembly, IOCTL discovery, taint, exploit-primitive classification) is **not** reinvented here. The project vendors [DrvEye](https://github.com/0xDbgMan/DrvEye) (MIT) as its deep L2→L3+ engine and focuses its own effort on the layers DrvEye does not provide: **(a)** real-world vendor-driver collection and static extraction from installers, **(b)** the cheap L0/L1 pre-triage above, and **(c)** the AI-handoff contract (per-bundle `AGENTS.md`, scope profiles, `fingerprints.jsonl` + `index.jsonl` for mass triage, `findings.json` with citation rules). This is the pivot that keeps the project tractable; see [Design pivot — engine reuse](#design-pivot--engine-reuse) below.

## Workflow

```
  ┌──────────┐   ┌───────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────┐   ┌────────┐
  │ Download │ → │  Extract  │ → │ Fingerprint  │ → │ Select       │ → │ Analyze  │ → │ Report │
  │ (vendor) │   │ (unpack   │   │ (L0 + L1,    │   │ (shortlist   │   │ deep     │   │ (per-  │
  │          │   │ installer)│   │ cheap, ALL)  │   │ by scope)    │   │ (L2→L3+) │   │ binary)│
  └──────────┘   └───────────┘   └──────────────┘   └──────────────┘   └──────────┘   └────────┘
       └──────── fused: fingerprint runs AS each driver lands ────────┘        └─ only the shortlist ─┘
```

The cheap stages (L0 viability + L1 fingerprint) run on **every** driver, fused into
collection so the whole corpus is triaged by the time the download finishes. The
expensive deep engine (L2→L3+, DrvEye) runs only on the drivers the fingerprint
flagged for the scope being hunted. See [Analysis pipeline](#analysis-pipeline-gated-four-levels).

## Collection

The corpus is sourced from a **single scalable source: the Microsoft Update
Catalog** (`catalog.update.microsoft.com`). It is official, legal, and — crucially
— the download host *is* the vendor (Microsoft), so it satisfies the "download
always comes from the vendor's original URL" principle without a separate
discovery/distribution split. The `msupdate-catalog` collector drives a headless
Chromium (Playwright) to search, paginate, resolve each update's real download URL
from the JS dialog, pull the CAB, and extract the drivers inside with 7-Zip.

This replaces the project's earlier approach — ~14 per-vendor collectors (Dell, HP,
Intel, GIGABYTE, …) that each pinned a single installer. Together they recovered
only a few hundred drivers ("real products, buried in installers"), which did not
scale. Those collectors, and the standalone LOLDrivers reference-set collector,
were removed in favor of the catalog enumerator. Their installer-extraction
machinery (MSI / NSIS / WiX-CAB / SFX / PE-resource) still lives in
`pipeline/collectors/_common.py` and `base.py` for any future collector. The
earlier per-vendor research is preserved in [`SOURCES.md`](SOURCES.md) as history.

### Search scope vs. analysis scope

A **scope** is one vocabulary applied at three points:

- **Search scope** (`pipeline.collect --scope <name>`) narrows what the collector
  looks for. A scope profile carries a `search:` block (catalog `queries` +
  classification `categories`); `--scope` also accepts a free-text term used
  directly as a catalog query (`--scope network`). With no scope, collection is a
  broad sweep across device classes. Resolution lives in
  [`pipeline/search_scope.py`](../pipeline/search_scope.py).
- **Triage scope / L1** (`pipeline.fingerprint`) — the cheap fingerprint scores
  *every* driver against *every* profile at once (import-only), writing
  `scope_matches` to `reports/fingerprints.jsonl`. `pipeline.fingerprint --select
  <name>` lists the drivers that qualify for a scope — the shortlist for the deep
  stage. Scored during collection, so no separate wait.
- **Analysis scope / deep** (`pipeline.analyze --scope <name>`) runs the expensive
  engine on the drivers that scope selected (pair with `--from-fingerprints`) and
  enriches the AI handoff.

**In scope**
- Drivers that shipped in **real products** — WHQL / catalog-signed updates.
- The full breadth of the catalog by default; a search scope narrows it on demand.

**Out of scope**
- Re-hosting large archives of unvetted driver binaries.
- Executing drivers inside this pipeline. Dynamic analysis is explicitly a separate, isolated, opt-in step (see Safety model).
- Aggregator catalogs that re-host binaries off the vendor's own hosts.

## Design pivot — engine reuse

The static analysis engine the layers below describe is **not implemented in this repo**. It is delegated to [**DrvEye**](https://github.com/0xDbgMan/DrvEye) (MIT), which already covers end-to-end:

- PE parsing + Authenticode verification + Windows load-verdict matrix (Default / Secure Boot / HVCI / S Mode / Test-signing).
- IOCTL discovery via **three independent paths** (dispatch-table walk, WDF emulation, brute-force) with hash-dispatch reversal (FNV / djb2 / CRC32 / sdbm).
- Interprocedural forward/backward taint with constant propagation and bounds inference.
- Classification into **13 exploit primitives** and **11 bug classes** (`arbitrary-rw`, `double-fetch`, `toctou-attach`, `callback-tamper`, …).
- Device-name recovery with Unicorn CPU emulation fallback for hardened drivers.
- LOLDrivers + Microsoft `authroot.stl` / `disallowedcert.stl` + WDAC `SiPolicy_Enforced.p7b` live sync for signing policy.
- Batch mode, JSON output, PoC harness generation.

Trying to reimplement any of that layer here would duplicate research-grade work that is already published and maintained. What the DrvEye output *does not* cover, and what this project owns end to end:

1. **Where the drivers come from.** DrvEye assumes `*.sys` files are already on disk. This project's Microsoft Update Catalog collector — enumerating the catalog and extracting the CAB payloads static-only — is the input layer DrvEye lacks. (An earlier 34-source, 451-driver per-vendor corpus was retired in favor of this one scalable source; see [Collection](#collection) and the historical [`SOURCES.md`](SOURCES.md).)
2. **The AI-handoff contract.** DrvEye emits a terminal report and an optional JSON for a human analyst. This project emits a **per-driver bundle** structured for an AI to walk: a per-bundle `AGENTS.md` entry point, scope-filtered views, a `findings.json` with mandatory per-claim citations, and a corpus-wide `index.jsonl` so Mode C (mass triage) answers capability-level questions over the whole corpus without ever opening a bundle tree.
3. **Scope profiles.** DrvEye reports *every* primitive and bug class it finds. This project narrows the universe up front via a declared scope (`arbitrary-physical-memory`, `msr-access`, `hid-input-control`, …) that both filters the output and enriches the AI prompt vocabulary.
4. **Corpus-level dedup and provenance.** `(installer URL, installer SHA-256 at download time, extraction path)` is recorded for every binary, so a finding can always be traced back to the exact vendor source — not an input DrvEye tracks on its own.

The practical consequence: the "Analysis pipeline" section below describes **what the engine delivers**, not what this repo implements. This repo implements the **collectors, the DrvEye adapter, and the AI-bundle writer** on either side of that engine. The gated-level vocabulary (L0 / L1 / L2 / L3+) is preserved because the output buckets in `reports/<sha256>/` are still carved along those lines — just populated from DrvEye's JSON rather than from code that lives here.

### Vendoring and resilience

DrvEye is pinned as a vendored dependency at a specific commit SHA (`vendor/drveye/`) so an upstream break never silently destabilizes this pipeline. The MIT license permits this and the project can carry forward even if upstream goes dormant.

### When to reach outside DrvEye

Two orthogonal engines may be added as **optional second-opinion** steps when DrvEye marks a path as plausible but not confirmed:

- [**IOCTLance**](https://michaelbommarito.com/wiki/infosec/ioctlance-windows-driver-security/) — angr-based symbolic execution of IOCTL handlers; 13 kernel-vuln classes.
- [**POPKORN**](https://sites.cs.ucsb.edu/~chris/research/doc/acsac22_popkorn.pdf) — angr + Windows-kernel `SimProcedure` library on top of symbolic execution of `DeviceEntry` / dispatch.

Neither is on the V1 critical path; both become relevant once the AI starts producing high-volume `PLAUSIBLE` findings that would benefit from automated reachability proofs.

---

## Analysis pipeline (gated, four levels)

The pipeline is layered. The cheap levels — **L0** (viability gate) and **L1** (fingerprint) — are first-party pefile-only passes that run on every driver during collection. The expensive levels — **L2** (disassembly + dispatch) and **L3+** (taint, primitives, bug classes) — are delivered by DrvEye and run only on the fingerprint shortlist; this project maps DrvEye's output into the same vocabulary so the bundle layout and the AI contract stay stable regardless of which engine the adapter is pointed at. This also keeps the door open for a future second engine (IOCTLance / POPKORN) to populate the same buckets.

### L0 — Viability gate (cheap, runs on everything)

Discards binaries that could not realistically load as drivers, so later levels do not waste CPU.

- Valid PE with `IMAGE_SUBSYSTEM_NATIVE` and a plausible driver layout.
- Imports resolve against kernel modules (`ntoskrnl.exe`, `hal.dll`, `wdfldr.sys`, …).
- Signature policy is **user-selectable** (presence only / was-valid-ever / valid-now).
- Not packed, or packed with a packer the pipeline knows how to unpack.
- No structural corruption or truncation.

Rejections land in `rejected.jsonl` with the reason — never silently dropped.

### L1 — Fingerprint (cheap, first-party, runs on every driver)

Unlike L2→L3+, L1 is **not** DrvEye — it is a first-party pefile-only pass
([`pipeline/adapter/l1.py`](../pipeline/adapter/l1.py)) that runs *inside collection*
as each driver lands, so the whole corpus is triaged by capability before any deep
analysis. One PE parse yields everything it needs:

| Facet | Content | Cost |
|---|---|---|
| Integrity | SHA256 (from content-addressing), imphash | free |
| Dangerous imports | Imported symbols present in `refs/dangerous_imports.yaml` | import table |
| Clone cross-ref | sha256-exact + imphash-family match vs the local LOLDrivers snapshot | import table |
| Cross-profile scope_matches | *Every* profile whose `must_have_one` gate fires, with its import-only rank (`compute_rank` in `scoring.py`) | import table |
| Triage verdict | `qualifies` = matched any scope OR any clone hit; `best_scope` / `best_rank` | derived |

Each driver gets one row in `reports/fingerprints.jsonl`
(`schemas/fingerprint_row.schema.json`). Deferred to the deep stage (they need
disassembly, not the import table): IOCTL/method rank terms, TLSH, YARA,
per-section entropy, signer-chain verification. The L1 rank is therefore a **lower
bound** — see [docs/ranking.md](ranking.md#l1-vs-deep-rank).

### Scope gate — only the fingerprint shortlist proceeds

The researcher declares a **scope profile** (see below). `pipeline.analyze
--from-fingerprints --scope <name>` reads `fingerprints.jsonl` and runs the deep
engine only on drivers whose L1 `scope_matches` qualify for that scope (at or above
`--min-rank`). `--deep-all` overrides to analyze everything (the pre-L1 behavior).
This is the gate that keeps the expensive engine off the thousands of drivers that
carry no relevant capability.

### L2 — Disassembly & dispatch map

- Full disassembly via Capstone (saved as a grep-friendly text file).
- Reconstructed control-flow graph per function.
- Resolution of `IRP_MJ_DEVICE_CONTROL` dispatch — which handler services which IOCTL, including table/switch-driven cases.
- Enumerated IOCTL codes with inferred buffer method (`METHOD_BUFFERED`, `METHOD_IN/OUT_DIRECT`, `METHOD_NEITHER`).
- Resolved device names and symbolic links.

### Function gate — only interesting handlers proceed

Within an L2-processed driver, only functions flagged by the scope profile (or reached by the dispatch map from a flagged IOCTL) advance to L3+. No full-driver decompilation unless the scope asks for it.

### L3+ — Taint, exploit primitives, bug classes

Delivered by DrvEye's internal analyzers. The adapter maps DrvEye's output into the per-bundle artifacts described in [Report layout](#report-layout):

| Technique | Delivered by |
|---|---|
| Interprocedural taint (forward + backward, constant propagation, bounds inference) | DrvEye taint analyzer → `l3_decomp/taint.json` |
| Validation-gap detection (missing `ProbeForRead/Write`, unchecked `OutputBufferLength`, `METHOD_NEITHER` without validation) | DrvEye bug-class detector → `l3_decomp/validation_gaps.json` |
| Exploit-primitive classification (13 primitives: `arb-write`, `arb-read`, `process-kill`, `token-steal`, `ppl-bypass`, …) | DrvEye → merged into `findings.json` candidates for the AI |
| Bug-class detection (11 classes: `arbitrary-rw`, `double-fetch`, `toctou-attach`, `callback-tamper`, …) | DrvEye → same |
| Clone detection against LOLDrivers / Microsoft / MalwareBazaar / HEVD | DrvEye `--loldrivers` → `l3_decomp/clones.json` |
| On-demand pseudo-C for a function the AI is about to cite | `pipeline.decompile` (angr), materialized lazily into `l3_decomp/<addr>.c` |
| asm ↔ pseudo-C cross-check (optional second-opinion for `CONFIRMED` upgrades) | IOCTLance / POPKORN (opt-in, V2+) |

The adapter does **not** re-run these analyses — it reshapes DrvEye's JSON into the scope-aware bundle layout and emits the `ai_bundle.md` that the per-bundle `AGENTS.md` tells the AI to read first.

## Scope profiles

A scope profile is a small declarative file that tells the pipeline **what the researcher is actually hunting for**. It shapes both the filtering (which binaries move forward) and the AI handoff (what vocabulary the prompt is enriched with).

```yaml
# example: hid-input-control
name: hid-input-control
imports_of_interest: [HidRegisterMinidriver, IoCreateDevice, KeInsertQueueApc]
device_name_patterns: ["\\\\Device\\\\Hid*", "\\\\Device\\\\Kbd*"]
ioctl_patterns: ["0x22....", "HID_*"]
strings_of_interest: [Hid, Mouclass, Kbdclass]
rank_weights:
  dangerous_imports: 3
  ioctl_match: 5
  device_match: 4
```

Initial profiles to ship: `arbitrary-physical-memory`, `msr-access`, `hid-input-control`, `process-token-manipulation`, `smm-smi`, `disk-raw-io`.

## Report layout

The same driver can be analyzed multiple times — different scope profiles, different pipeline versions, different flag combinations. The layout reflects that: facts that depend only on the binary (identity, raw disassembly) are **shared** across all analyses of a given driver, while facts that depend on the scope (which handlers were decompiled, which taint paths matter) live inside a **per-analysis** subdirectory.

```
reports/
├── fingerprints.jsonl                       # L1 cheap pass — one line per driver, append-only
├── index.jsonl                              # deep-analysis index — one line per (driver, scope), append-only
├── rejected.jsonl                           # L0 rejections, separate stream
└── <sha256>/                                # one directory per unique driver (deep stage only)
    ├── identity.json                        # L1 — shared across analyses
    ├── pe_metadata.json                     # L1 — shared
    ├── disasm_full.txt                      # L2 raw — shared (grep-friendly)
    ├── functions.json                       # L2 raw — shared
    └── <run_id>/                            # one subdirectory per analysis
        ├── AGENTS.md                        # per-bundle entry point (points to ../../../AGENTS.md)
        ├── scope_<name>.md                  # the scope profile view
        ├── ai_bundle.md                     # pre-chewed summary for AI
        ├── ioctls_scoped.json               # L2 dispatch, scope-filtered
        ├── l3_decomp/
        │   ├── <func_addr>.c                # one pseudo-C file per flagged function
        │   ├── taint.json
        │   ├── validation_gaps.json
        │   ├── clones.json
        │   └── summary.md
        ├── findings.json                    # written by the AI
        └── findings.md                      # written by the AI
```

### `run_id` format

`<ISO8601-compact>Z-<scope-short>` — for example `20261001T191244Z-hidctrl`. Sorts chronologically, carries the scope in the name, remains readable by a human. Collisions across parallel runs are prevented by the second-level timestamp.

### Rejected binaries

Binaries that fail the L0 viability gate never get a `<sha256>/` directory. They are appended as a single line to `reports/rejected.jsonl` with their rejection reason, so the main index stays clean of noise:

```json
{"sha256":"...","driver_file":"xpto.sys","reason":"not NATIVE subsystem","detected_at":"..."}
```

## Mass triage index

The primary way researchers interact with this project is **mass triage**: point an AI at the whole corpus and ask "which drivers match this capability?". For that to scale, the AI must never walk the bundle tree directory by directory — it reads flat index files, filters, ranks, and only then opens the handful of bundles worth looking at.

There are **two** such files, by stage:

- **`reports/fingerprints.jsonl`** — the L1 cheap pass, **one line per driver**, written for every collected driver. This is the complete candidate universe for a capability question, including drivers that were never deep-analyzed. Import-only ranks (lower bounds). Schema: `schemas/fingerprint_row.schema.json`.
- **`reports/index.jsonl`** — the deep pass, **one line per analysis** (not per driver — a driver re-analyzed under a new scope appends a new line), append-only, never mutated. Authoritative ranks + `top_findings_preview` for drivers that were actually deep-analyzed. Schema: `schemas/index_row.schema.json`.

A triage reader uses fingerprints to find *all* candidates and the index to see which of them already have deep bundles (see [Mode C](#mode-c--mass-triage-from-the-project-root-dominant-use-case)).

### Row shape

Every row has four blocks:

| Block | Purpose |
|---|---|
| `identity` | Facts that depend only on the binary — sha256, imphash, tlsh, product/vendor from PE version info, arch, size, signature status. Repeated across all analyses of the same driver (self-contained rows beat normalization here). |
| `run` | Metadata of this specific analysis — `run_id`, `scope_profile`, `pipeline_version`, `generated_at`, flags that affected interpretation, `bundle_path`. |
| `signals` | Divided into `scope_independent` (always computed in L1 — dangerous imports, IOCTL methods, device names, device-class classification, clone hits, interesting strings) and `scope_dependent` (only populated when the matching scope was actually run — rank, validation gaps, taint sinks, top handler). |
| `evidence_pointers` | Relative paths to the key artifacts in the bundle — `ai_bundle`, `scope_view`, `ioctls_json`, `findings_json`. The AI jumps straight to these when it decides to go deep. |

Plus `schema_version` at the top level, so multiple schema generations can coexist in the same stream during a migration.

### Why scope-independent signals matter

The L1 baseline is computed on **every** driver (in `fingerprints.jsonl`), and mirrored into each deep row's `signals.scope_independent` (in `index.jsonl`), regardless of which scope was active. This is what lets the AI answer "which drivers allow arbitrary I/O?" even when most drivers were collected or analyzed under a different scope — the `dangerous_imports` and cross-profile `scope_matches` fields are always there to filter on.

Crucially, the cross-profile `scope_matches` is computed at L1 from imports alone — so a driver collected while hunting HID still advertises that it qualifies for `arbitrary-physical-memory`, *before* any deep analysis spends a second on it. The scope only governs how deep L2 and L3 go (which handlers get decompiled). A triage question that goes beyond what any run touched can still identify candidates from the fingerprint, and the researcher can then deep-analyze exactly those with `pipeline.analyze --from-fingerprints --scope <matching>`.

### Re-analysis semantics

Running the same driver + same scope twice (bug fix, pipeline upgrade) appends a new row. Nothing is overwritten. Readers deduplicate by `(sha256, scope)` and pick the most recent `generated_at` — older rows remain as history, not current truth.

## Using this with an AI assistant

The pipeline is designed to hand its output to an AI model as the final analysis step. The contract that governs that handoff is `AGENTS.md` at the repository root. There are three valid ways to point an AI at this project, and the dominant one is Mode C.

### Mode A — Deep analysis of one known bundle, from the project root

The researcher opens the AI with the project root as the working directory and names the specific analysis to look at:

```
<path>/portable-driver-triage/
> analyze reports/aabbccdd.../20261001T191244Z-hidctrl/
```

The AI finds `AGENTS.md` at the root (most modern agents — Claude Code, OpenAI Codex, Cursor, Devin — auto-discover it), reads the contract, then walks into the named bundle.

### Mode B — Deep analysis of one bundle, from inside the bundle

The researcher goes straight into a specific analysis:

```
<path>/portable-driver-triage/reports/aabbccdd.../20261001T191244Z-hidctrl/
> analyze this
```

For this to work, the pipeline drops a short per-bundle `AGENTS.md` inside every `reports/<sha256>/<run_id>/` on generation. That file names the driver, states the active scope profile, and redirects to the full contract at `../../../AGENTS.md`. The AI finds a local `AGENTS.md` first, follows the pointer up, and ends up on the same contract — no matter which directory the researcher pointed it at.

### Mode C — Mass triage from the project root (dominant use case)

The researcher opens the AI at the project root and asks a capability-level question across the whole corpus:

```
<path>/portable-driver-triage/
> find drivers that allow arbitrary physical I/O or inject mouse / keyboard input
```

The AI loads the root `AGENTS.md`, follows its mass-triage instructions:

1. Reads `reports/fingerprints.jsonl` (the complete candidate universe, one line per driver) and `reports/index.jsonl` (which drivers already have deep bundles).
2. Filters by the fingerprint `signals` (dangerous imports, `scope_matches`, clone hits) against the capability the researcher asked about.
3. Deduplicates — fingerprints by `sha256`, index by `(sha256, scope)` — keeping the most recent per key.
4. Produces a ranked triage report with per-driver one-liners, marking each candidate `already_analyzed_deep` (has an index bundle for the scope) or `needs_deep_rerun` (fingerprint-only, or analyzed under another scope).
5. Only then opens the top handful of already-analyzed candidates' `ai_bundle.md` and L3 artifacts to produce detailed findings on those; for `needs_deep_rerun` candidates it recommends `pipeline.analyze --from-fingerprints`.

This path never walks the bundle tree directory by directory — it reads two flat files, then jumps straight to the few bundles that matter via the `evidence_pointers` in each matching index row.

### Tool-agnostic by design

The project ships a single `AGENTS.md` and no vendor-specific overlays (`CLAUDE.md`, `.cursor/`, `.github/copilot-instructions.md`, …). The contract is written to be executable by any capable AI, and splitting it across tool-specific files is a drift risk at this stage of the project. Vendor-specific overlays will only be added when a concrete need appears that genuinely does not fit the universal contract.

## Running the pipeline (Docker, zero-config)

The static pipeline ships as a single self-contained image — Python, the analysis
deps (pefile, capstone, cryptography, angr), 7-Zip, and the vendored DrvEye
engine are all bundled. No host-side "install these 14 libraries first".

```bash
# build once
docker compose build

# 1. collect — networked: pull the LOLDrivers reference set + a vendor driver.
#     Each driver is L1-fingerprinted as it lands → reports/fingerprints.jsonl.
docker compose run --rm collect pipeline.collect loldrivers windivert

# 2. fingerprint — offline: the cheap L1 pass. Usually already done by collect;
#     --all backfills a corpus gathered earlier. --select lists the shortlist.
docker compose run --rm analyze pipeline.fingerprint --all
docker compose run --rm analyze pipeline.fingerprint --select arbitrary-physical-memory

# 3. analyze — offline (network cut): the EXPENSIVE deep stage, only on the
#     fingerprint shortlist for the scope. --deep-all overrides to the whole
#     corpus; --jobs N parallelizes across worker processes (appends to
#     index.jsonl / rejected.jsonl are concurrency-safe via O_APPEND).
docker compose run --rm analyze pipeline.analyze --all --scope arbitrary-physical-memory --from-fingerprints --skip-existing --jobs 8
#     ...or one driver by hash:
docker compose run --rm analyze pipeline.analyze <sha256> --scope arbitrary-physical-memory

# 4. decompile — offline: materialize pseudo-C for a cited function, on demand
docker compose run --rm analyze pipeline.decompile <sha256> 0x401478
```

`pipeline_out/` (collected drivers + the LOLDrivers snapshot) and `reports/`
(bundles + `index.jsonl`) are bind-mounted, so results persist on the host. The
`analyze` service runs with `network_mode: none`, enforcing the Safety-model
promise below that L0–L3+ is offline-after-pull. Plain `docker build`/`docker run`
work too — see the header of [`Dockerfile`](Dockerfile).

Nothing in the image executes a driver; the `.sys` files are parsed as bytes.

## Safety model

| Stage | Isolation |
|---|---|
| Download / extract / static analysis (L0–L3+) | Fully containerized, unprivileged, offline-capable after image pull, **zero-config**. Nothing is executed — binaries are only parsed. |
| Dynamic analysis | Explicitly **not** part of this project's static pipeline. Loading or executing a driver touches the kernel and cannot be zero-config or containerized. It belongs in a disposable, isolated VM and is a separate, opt-in effort. |

The "download-and-use, no-questions-asked" experience applies to the static pipeline. Anything that actually executes a driver is, by necessity, a deliberate and isolated step kept out of this repository's scope.

## Reproducibility

The pipeline does not pin installer hashes — it always fetches the current version of a source. However, the SHA256 of the installer at download time is **recorded inside every report**, so any run is traceable after the fact.

## Status

Early implementation stage. The methodology above is settled; after the pivot to [vendoring DrvEye](#design-pivot--engine-reuse) as the L0→L3+ engine, the remaining work is scoped to **two first-party layers**: the collectors (porting the 34-source prototypes under `E:\temp\*` into `pipeline/collectors/`) and the DrvEye-to-bundle adapter (which emits the AI contract on top of DrvEye's JSON). The static-analysis engine itself is no longer on the critical path. See **Pending** for the ordered item list.

The zero-config container (see [Running the pipeline](#running-the-pipeline-docker-zero-config)), the L0 viability gate + `rejected.jsonl` stream, the L1 fingerprint stage (`pipeline/adapter/l1.py` + `pipeline/fingerprint.py`, fused into collection → `reports/fingerprints.jsonl`, with `pipeline.analyze --from-fingerprints` gating the deep stage on it), and the adapter's bundle output — disasm + `functions.json`, on-demand decompilation, the L3 hint files, and conforming `index.jsonl` rows — are in place. Batch analysis is wired too — `python -m pipeline.analyze --all --scope <name> [--skip-existing] [--jobs N]` gates + analyzes every collected driver with per-driver isolation, optionally fanning the work across `N` worker processes inside the same container. 14 collectors are ported (see Pending §1); a `collect --all` populates a real corpus (hundreds of drivers), and `analyze --all` builds their bundles. The remaining first-party gaps are the two hard-tier collectors (`corsair`, `lenovo`) and TLSH/`detections/` ingestion.

---

## Pending

The items below block implementation. They are listed in the order they need to be resolved.

### 0. L1 fingerprint stage — cheap triage before the deep engine

**Done.** The signals that decide whether a driver is worth DrvEye (dangerous imports, imphash clone family, cross-profile `scope_matches`) are import-table-only, so they are computed first on every driver and the expensive engine runs only on the shortlist.

- **Done** — [`pipeline/adapter/scoring.py`](../pipeline/adapter/scoring.py): the additive rank formula + cross-profile `compute_scope_matches`, factored out of the bundle writer so the collector can reuse them without the Jinja2 dependency.
- **Done** — [`pipeline/adapter/l1.py`](../pipeline/adapter/l1.py): one pefile parse → imports/imphash → dangerous imports, offline clone hits (reusing `l3.build_clones`), cross-profile `scope_matches`, and a triage verdict; one row per driver to `reports/fingerprints.jsonl`. Schema at [`schemas/fingerprint_row.schema.json`](../schemas/fingerprint_row.schema.json) + example, wired into `ci/validate.py`.
- **Done** — Fused into collection: [`collect_sys_files`](../pipeline/collectors/_common.py) fingerprints each new driver as it is stored (best-effort; `PDT_NO_FINGERPRINT=1` opts out, a missing dep never breaks collection).
- **Done** — [`pipeline/fingerprint.py`](../pipeline/fingerprint.py) CLI: `--all` (backfill the corpus) and `--select <scope>` (emit the deep-stage shortlist). `pipeline.analyze --from-fingerprints [--min-rank N]` gates the deep stage on it; `--deep-all` restores the whole-corpus behavior.
- **Open** — Promote the one-off [`scripts/backfill_scope_matches.py`](../scripts/backfill_scope_matches.py) learnings into a periodic re-fingerprint when `refs/*.yaml` versions bump (ranks stay comparable).

### 1. Collection and reference sources — research and validation

**Substantially done.** Thirty-four sources tested empirically on 2026-10-01 across two research passes, documented in [`SOURCES.md`](SOURCES.md).

Headline outcomes:

- **451 unique drivers** recovered across the 34 sources (within-source dedup; 387 from the first pass, 64 from a follow-up pass).
- Three BYOVD-relevant specimens already in hand: `RTCore64.sys` (CVE-2019-16098), `amdtools.sys` (GIGABYTE lineage), `iobios64.sys` (LOLDrivers reference).
- One confirmed source for the LOLDrivers reference set (feeds L3 clone detection), separate from vendor collection.
- Confirmed the design decision to use TousLesDrivers for **discovery only** and download from the vendor host it points to.
- New coverage from the second pass: audio-peripheral (Focusrite), virtualization (VirtualBox alongside VirtIO), userland-FS filter drivers (Dokany, WinFsp), in-kernel filesystem (WinBtrfs), modern network tunnels (Npcap, OpenVPN, Wintun), USB stack (UsbDk, USBPcap, libusb-win32), USB-serial (Prolific), storage vendor (Samsung NVMe), virtual-disk/mount drivers (ImDisk, OSFMount legacy), full-disk encryption (VeraCrypt), virtual HID (vJoy), and a first-party WHQL baseline from Microsoft Sysinternals.

Still open:

- **Mostly done** — Promoting the `E:\temp\*` prototypes into first-class `pipeline/collectors/<source>.py` modules on a shared interface. Ported and working: `windivert`, `loldrivers`, `intel`, `gigabyte`, `msi-afterburner`, `touslesdrivers`, `virtio`, `surface`, `cpuz`, `hwmonitor`, `hwinfo`, `hp`, `dell`, `msupdate-catalog`. A `SimpleArchiveCollector` base covers four extraction mechanisms uniformly — plain archive, nested installer (NSIS/self-extractor, up to 3 levels), MSI/content-detection (drivers recovered by native-PE subsystem, no Windows-only MSI API), and PE-resource (`7z -tPE` on the app EXE). Still open: `corsair` (registered but needs WiX-Burn CAB carving + manifest mapping — currently recovers nothing) and `lenovo` (needs the `innoextract` tool for its Inno Setup installer). Both are the only two sources that resisted the generalized machinery.
- Per-source refresh cadence / TTL policies.
- Deferred sources listed in `SOURCES.md` under "Attempted but not yet successful" (AMD, ASRock, FTDI, HidHide, PassMark OSFMount current build, Silicon Labs, SoftPerfect, ViGEmBus, WireGuard, Yamaha/Steinberg) — each needs installer-specific tooling rather than a generic retry.
- Per-model Dell/HP/Lenovo Driver Packs (end-user EXEs, often InstallShield SFX) and HWiNFO compressed x64/x86 payloads — expansions, not blockers for V1.

### 2. Per-bundle `AGENTS.md` template

The root `AGENTS.md` is the universal contract. To make Mode B above work (AI pointed directly at a bundle), the pipeline must drop a short, generated `AGENTS.md` inside every `reports/<sha256>/<run_id>/` that names the driver, states the active scope profile, and points up to `../../../AGENTS.md` for the full contract.

- **Done** — Template written as [`pipeline/templates/per_bundle_agents.md.j2`](pipeline/templates/per_bundle_agents.md.j2), with the frame-setting preamble that establishes the defensive-research context so AI assistants invoked cold on a bundle do not refuse or stall before following the pointer up.
- **Open** — Pipeline step that renders the template with the actual placeholders (`sha256`, `scope_name`, `pipeline_version`, flags, …) and writes it inside each new bundle.

Also materialized while closing this item: [`schemas/findings.schema.json`](schemas/findings.schema.json) + [`schemas/examples/findings.example.json`](schemas/examples/findings.example.json). The charter already referenced this file; it now exists and uses the same `schema_version: const 1` convention as the other row schemas.

### 3. `index.jsonl` and `rejected.jsonl` generation

The mass-triage index described above is the backbone of Mode C and is not yet fully implemented. Progress:

- **Done** — Row schema for `index.jsonl` formalized as [`schemas/index_row.schema.json`](schemas/index_row.schema.json), with a validating example in [`schemas/examples/index_row.example.json`](schemas/examples/index_row.example.json).
- **Done** — Row schema for `rejected.jsonl` formalized as [`schemas/rejected_row.schema.json`](schemas/rejected_row.schema.json), with an example in [`schemas/examples/rejected_row.example.json`](schemas/examples/rejected_row.example.json).
- **Done** — Concurrent-safe append for both files via a direct `O_APPEND` write (`bundle.append_index`, `l0.append_rejected`): crash-safe, no partial lines, and POSIX-atomic across processes for writes under `PIPE_BUF` (every row we emit sits well under the 4 KiB limit; an assertion turns a future oversized row into a loud failure instead of a silent interleave). This closes the earlier read-rewrite-rename race without needing a lock, unblocking `--jobs N` in `pipeline.analyze` and any shard-parallel operator orchestration.
- **Done** — Baseline reference files consumed during L1: [`refs/dangerous_imports.yaml`](refs/dangerous_imports.yaml) (13 categories, ~160 symbols), [`refs/interesting_strings.yaml`](refs/interesting_strings.yaml) (11 categories including a `known_vulnerable_driver_signatures` set), [`refs/device_classes.yaml`](refs/device_classes.yaml) (election rules for the 11-class vocabulary that `index_row.schema.json` requires).
- **Done** — Pipeline code produces conforming rows: `index_row` from `pipeline/adapter/bundle.py` (validated 7/7 against `index_row.schema.json`) and `rejected_row` from the L0 gate `pipeline/adapter/l0.py` (validated against `rejected_row.schema.json`).
- **Done** — L0 viability gate (`pipeline/adapter/l0.py`), wired into `analyze.py` ahead of DrvEye. Cheap pefile-only checks (valid PE, `IMAGE_SUBSYSTEM_NATIVE`, sections within file, imports resolve against a kernel module, conservative packing-entropy heuristic, optional `refs/hash_blacklist.txt`), emitting the closed-vocabulary reasons (`not-pe`, `wrong-subsystem`, `kernel-imports-unresolved`, `corrupted`, `packed-unknown`, `signature-policy-mismatch`, `blacklisted`). A rejected binary is logged to `reports/rejected.jsonl` and never gets a bundle. Signature policy is `any` (default) or `present`; `valid-ever`/`valid-now` are deferred to DrvEye's downstream Authenticode.

### 4. Mass triage section in the charter (`AGENTS.md`)

**Done.** Section 11 of [`AGENTS.md`](AGENTS.md) now covers Mode C end to end: reading procedure (`index.jsonl` → dedup → predicate), common query translations, deliverable layout (`reports/triage/<generated_at>_<query_slug>/triage.{json,md}`), the `status` field semantics (`already_analyzed_deep` vs `needs_deep_rerun`), and the hard rules specific to triage (no bundle opens, no uncited claims, no polluting `candidates` with near-misses). The opening of the charter was also updated to signal that two modes exist and point the AI at the right section.

### 5. DrvEye vendoring and adapter

The design pivot described in [Design pivot — engine reuse](#design-pivot--engine-reuse) replaces the "write L0–L3+ from scratch" track with a thinner adapter layer. Concrete work items:

- **Open** — Vendor DrvEye at a pinned commit SHA under `vendor/drveye/`, with a lockfile and a `make vendor-update` target that regenerates the lock and re-runs the test suite against the current corpus.
- **Mostly done** — The adapter (`pipeline/adapter/drveye.py` + `pipeline/adapter/bundle.py`, plus `pipeline/analyze.py` as the entry point) consumes `DrvEye.py --json` per driver, applies the active scope profile (filter in / out), writes the per-bundle layout (`identity.json`, `pe_metadata.json`, `ioctls_scoped.json`, `ai_bundle.md`, per-bundle `AGENTS.md`), and appends one conforming `index_row`. The L0 gate (`pipeline/adapter/l0.py`) runs ahead of it and emits `rejected_row`s for non-viable binaries. Still open: `index` rows carry `tlsh: null` (python-tlsh needs a C toolchain).
- **Done** — L3 hint mapping (`pipeline/adapter/l3.py`): `l3_decomp/{taint,validation_gaps,clones}.json` are no longer empty placeholders. `taint.json` and `validation_gaps.json` are mapped from DrvEye's `ioctls[].behavior` + `findings` (sink-reachability hints and missing-check gaps against `docs/validation_checks.md`); `clones.json` is matched **offline** (sha256-exact + imphash-family) against the local LOLDrivers snapshot. Each file is a `{status, source, note, items}` wrapper, so "computed, found none" is distinguishable from "not computed". Clone hits + taint/gap counts flow into the `index_row`. Backfillable via `python -m pipeline.adapter.l3 <sha256>`.
- **Done** — Shared L2-raw emission: `pipeline/adapter/disasm.py` writes `reports/<sha256>/disasm_full.txt` (a resyncing Capstone linear sweep in the `0xADDR\t<bytes>\t<mnemonic>\t<operands>` format, with inline `FUNC_START` markers seeded from DrvEye's already-resolved handler / hidden-function addresses so every citable address lands on a real instruction boundary) and `functions.json` (boundaries, inferred signatures, per-function `disasm_line`). Wired into the bundle writer; backfillable standalone via `python -m pipeline.adapter.disasm <sha256>`.
- **Done** — On-demand decompilation ("lazy decompilation on citation"): `pipeline/decompile.py` materializes `l3_decomp/<addr>.c` for a single cited function via angr (with an `asm-only` carve-out fallback), so `CONFIRMED` findings get a pseudo-C citation target without paying to decompile the whole driver. The AI is authorized to invoke it freely during analysis — see `AGENTS.md` §3. Dependency declared in `pipeline/requirements.txt`.
- **Open** — Scope-aware filtering layer in the adapter: DrvEye reports every primitive/bug class it finds; the adapter maps each DrvEye finding to **inside-scope** vs **out-of-scope** based on the active `scope_profile.yaml`, then writes `findings` and `out_of_scope` arrays accordingly.
- **Open** — Interoperability test harness: run both DrvEye and this adapter on a fixed 10-driver reference set (including `RTCore64.sys`, `amdtools.sys`, `iobios64.sys`) and assert the adapter output passes `ci/validate.py` for every schema it touches.
- **Deferred to V2** — Optional second-opinion engines ([IOCTLance](https://michaelbommarito.com/wiki/infosec/ioctlance-windows-driver-security/), [POPKORN](https://sites.cs.ucsb.edu/~chris/research/doc/acsac22_popkorn.pdf)) that upgrade `PLAUSIBLE` findings to `CONFIRMED` by symbolically proving reachability. Not on the V1 critical path.
- **Deferred to V2** — Fuzzing harness generation (DrvEye already emits C/Python harnesses; a runtime VM layer that executes them is out of scope — see Safety model).

### 6. Reference-set ingestion (LOLDrivers + WDAC)

Independent of DrvEye's internal LOLDrivers integration, the pipeline keeps its own reference-set snapshot so bundles are self-contained and reproducible. Must pull **both** halves of the LOLDrivers repository: `api/drivers.json` (hashes + metadata for `clone_hits` via TLSH / imphash matching) **and** the `detections/` subtree (`yara/`, `sigma-per-driver/`, `wdac/`, …).

**Partially done:** the `loldrivers` collector already fetches the `api/drivers.json` snapshot (699 entries) under `pipeline_out/collectors/loldrivers/`, and `pipeline/adapter/l3.py` consumes it **offline** for `clone_hits` via sha256-exact + imphash-family matching. Still open: TLSH fuzzy matching (needs python-tlsh + a C toolchain) and ingesting the `detections/` subtree (YARA pre-scanner, `sigma-per-driver/` ground truth, WDAC XML). The YARA rules are usable as an L1 pre-scanner — faster and more specific than fuzzy-hash similarity. The `sigma-per-driver/` rules are the ground-truth reference against which the AI's `detection_ideas` output can be compared. WDAC XML is a candidate for a derived output stage ("render findings into a blocklist policy"). See `SOURCES.md` → LOLDrivers for the full note.

**Resolved while closing earlier items:**

- Scope profile schema at [`schemas/scope_profile.schema.json`](schemas/scope_profile.schema.json) + example at [`schemas/examples/scope_profile.example.yaml`](schemas/examples/scope_profile.example.yaml).
- Ranking formula documented at [`docs/ranking.md`](docs/ranking.md).
- Mode-C triage output schema at [`schemas/triage.schema.json`](schemas/triage.schema.json) + example at [`schemas/examples/triage.example.json`](schemas/examples/triage.example.json).
- `validation_expected` naming consolidation: `input_buffer_length_check` dropped in favor of `input_length_check`; `caller_privilege_check` hierarchy formalized with an implication rule in [`docs/validation_checks.md`](docs/validation_checks.md).
- CI validation script at [`ci/validate.py`](ci/validate.py) covering all `refs/*.yaml`, `scope_profiles/*.yaml`, and `schemas/examples/*`.
