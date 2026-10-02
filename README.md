# Portable Driver Triage

**Static BYOVD triage pipeline for Windows kernel drivers — collect, analyze, and hand
off to an AI, offline in one Docker image. Nothing is ever executed.**

It collects real Windows kernel drivers from their original vendors, extracts the ones
buried inside installers, and pre-computes a layered static analysis so an LLM starts
from structured facts instead of raw bytes — then drives the rest of the pipeline
itself, as a CLI.

> **Built on [DrvEye](https://github.com/0xDbgMan/DrvEye)** (MIT, by 0xDbgMan). DrvEye
> does the hard static-analysis work — PE parsing, Authenticode, IOCTL discovery,
> taint, exploit-primitive classification. This project vendors it as the L0→L3+
> engine and adds the two layers it doesn't cover: real-world **vendor-driver
> collection** and an **AI-handoff contract**. See [Credits](#credits).

Every `.sys` is parsed as bytes — the pipeline is static-only and runs fully offline
after the image is pulled.

---

## Designed for an LLM to drive as a CLI

This is the core idea. The pipeline doesn't just dump a report for a human to read —
it's shaped so an AI agent **operates it from the command line** and produces cited
findings on its own:

- It reads a single contract ([`AGENTS.md`](AGENTS.md)) that modern agents (Claude
  Code, Codex, Cursor) auto-discover, and that tells it exactly which artifacts to open
  and in what order.
- Every collected driver is **fingerprinted as it lands** — a cheap, import-only L1 pass
  (written to `reports/fingerprints.jsonl`) that runs *during* collection, so the moment a
  download finishes the whole corpus is already triaged by capability. The expensive engine
  then runs only on the drivers that fingerprint flagged.
- It triages the whole corpus from **flat index files** (`reports/fingerprints.jsonl` for the
  cheap pass, `reports/index.jsonl` for deep analyses) — no walking the bundle tree — then
  opens only the handful of bundles worth deep analysis.
- It **runs the pipeline itself**: when it needs pseudo-C for a function it's about to
  cite, it invokes `pipeline.decompile <sha256> <addr>` on demand, materializing the
  decompilation lazily instead of paying to decompile every driver up front.
- Every claim it writes into `findings.json` must cite a real line in the bundle
  ([`AGENTS.md`](AGENTS.md) §6) — the contract makes uncited analysis fail.

The [Quick start](#quick-start) below is the human entry point; the
[Point an AI at the results](#point-an-ai-at-the-results) section is the agent one.

---

## Quick start

You need Docker. Nothing else — Python, the analysis deps (pefile, capstone,
cryptography, angr), 7-Zip, and the vendored [DrvEye](https://github.com/0xDbgMan/DrvEye)
engine are all baked into the image.

```bash
# build the image once (includes headless Chromium for the catalog collector)
docker compose build

# 1. collect — run every registered source (needs network).
#    No --scope → a broad sweep across device classes ("collect anything").
docker compose run --rm collect pipeline.collect --all
#    ...or pick one source by name (see --list):
docker compose run --rm collect pipeline.collect samlab
#    ...or narrow the SEARCH with a scope (profile name/short_name, or a free
#    term) — the collection-time half of the scope vocabulary, honored by the
#    scope-aware catalog source:
docker compose run --rm collect pipeline.collect msupdate-catalog --scope hid-input-control
docker compose run --rm collect pipeline.collect msupdate-catalog --scope network

# 2. fingerprint — the cheap L1 pass. Normally it already ran inside `collect`
#    as each driver landed; this backfills a corpus gathered earlier, or
#    recomputes after a reference-file change. Seconds-to-minutes, not hours.
docker compose run --rm analyze pipeline.fingerprint --all
#    ...then see what is worth the expensive engine, per scope:
docker compose run --rm analyze pipeline.fingerprint --select arbitrary-physical-memory

# 3. analyze — the EXPENSIVE deep stage (DrvEye). Run it only on the drivers
#    the L1 fingerprint flagged for this scope — not the whole corpus:
docker compose run --rm analyze pipeline.analyze --all --scope arbitrary-physical-memory --from-fingerprints --skip-existing
#    ...one driver by hash:
docker compose run --rm analyze pipeline.analyze <sha256> --scope arbitrary-physical-memory
#    ...--deep-all forces the whole corpus (the pre-L1 behavior); --jobs N fans
#    the batch across N worker processes (default 1). Appends to index.jsonl /
#    rejected.jsonl are concurrency-safe via O_APPEND.
docker compose run --rm analyze pipeline.analyze --all --scope arbitrary-physical-memory --deep-all --jobs 8

# 4. decompile — materialize pseudo-C for one function, on demand
docker compose run --rm analyze pipeline.decompile <sha256> 0x401478
```

Results land on your host: collected drivers in `pipeline_out/`, analysis bundles and
the triage index in `reports/`. Both are bind-mounted volumes, so they survive
rebuilds — the image carries only code, never data. See
[docs/DESIGN.md](docs/DESIGN.md#reproducibility) for the reproducibility contract.

> `docker compose run --rm collect pipeline.collect --list` prints every collector.
> Plain `docker build` / `docker run` work too — see the header of the [Dockerfile](Dockerfile).

---

## Point an AI at the results

Open an AI agent at the repo root; it finds [`AGENTS.md`](AGENTS.md) and follows the
contract. Three ways to invoke it:

- **Mass triage** (the common case) — ask a capability question: *"which drivers allow
  arbitrary physical I/O?"* The agent reads the flat index files (`reports/fingerprints.jsonl`
  for every collected driver, `reports/index.jsonl` for ones already deep-analyzed), filters,
  ranks, and only then opens the handful of bundles that matter.
- **Deep analysis** — point it at one bundle (`reports/<sha256>/<run_id>/`). It reads
  the facts, runs `pipeline.decompile` for any function it needs pseudo-C on, and writes
  a cited `findings.json` + `findings.md`.
- **Operator-assisted** — you drive `collect` / `analyze` from the shell (the
  [Quick start](#quick-start)); the agent takes over at the findings step.

---

## Scopes

A scope profile tells the pipeline what you're hunting for. The same scope name is
applied at **three points**:

- **Search scope** — `pipeline.collect --scope <name>` narrows what the collector
  *looks for*. A profile carries a `search:` block (catalog queries + category
  tokens); `--scope` also accepts a free-text term (`--scope network`, `--scope
  mouse`) used directly as a catalog query, so quick targeted collection needs no
  profile. With no `--scope`, collection is a broad "anything" sweep.
- **Triage scope (L1)** — the cheap fingerprint computes, for *every* driver and
  *every* profile, whether that driver qualifies and at what import-only rank
  (`reports/fingerprints.jsonl`). `pipeline.fingerprint --select <name>` reads this
  to list the drivers worth the deep engine. This stage is scope-*independent* in
  that it scores all profiles at once, regardless of the search scope used.
- **Analysis scope (deep)** — `pipeline.analyze --scope <name>` runs the expensive
  engine (filtered by that profile) and enriches the AI's vocabulary. Pair it with
  `--from-fingerprints` to analyze only the L1 shortlist for that scope.

Shipped profiles (in [`scope_profiles/`](scope_profiles/)):

| scope | capability |
|---|---|
| `arbitrary-physical-memory` | map/read/write physical memory (`MmMapIoSpace`, …) |
| `msr-access` | model-specific register read/write (`__rdmsr` / `__wrmsr`) |
| `hid-input-control` | inject or intercept mouse / keyboard / HID input |
| `process-token-manipulation` | steal / elevate process tokens |
| `disk-raw-io` | raw block-device read/write |
| `smm-smi` | System Management Mode / SMI triggering |

---

## What you get

Corpus-level, flat files the AI triages from without walking the tree:

```
reports/
├── fingerprints.jsonl       # cheap L1 pass — one line per driver, written during collection
├── index.jsonl              # deep analyses — one line per (driver, scope) bundle
└── rejected.jsonl           # L0 rejections, separate stream
```

Per driver (deep stage only):

```
reports/<sha256>/
├── identity.json            # PE metadata, signing, imports, provenance (shared)
├── disasm_full.txt          # full Capstone disassembly, grep-friendly (shared)
├── functions.json           # function boundaries + signatures (shared)
└── <run_id>/                # one per analysis (scope + timestamp)
    ├── ai_bundle.md         # pre-chewed summary — the AI reads this first
    ├── ioctls_scoped.json   # IOCTL → handler dispatch map, scope-filtered
    ├── l3_decomp/           # taint / validation-gap / clone hints + pseudo-C
    ├── findings.json        # written by the AI, schema-validated
    └── findings.md          # written by the AI, human-readable
```

Drivers that can't load (not a native-subsystem PE, unresolved kernel imports,
corrupted, packed) are rejected at the L0 gate and logged to
`reports/rejected.jsonl` — never silently dropped.

---

## Safety

This is a **static** pipeline. Download, extraction, and all analysis (L0–L3+) run
containerized, unprivileged, and offline-after-pull; binaries are only parsed, never
run. The `analyze` service enforces this with `network_mode: none`.

Dynamic analysis — actually loading a driver — touches the kernel, can't be
zero-config, and is deliberately **out of scope** for this repo. It belongs in a
disposable isolated VM.

---

## How it works

DrvEye is the deep L2→L3+ engine (see the note at the top); this project owns the
Microsoft Update Catalog collector that feeds it, the cheap **L0 gate + L1 fingerprint**
that run before it (import-only triage over the whole corpus, fused into collection), and
the adapter that reshapes DrvEye's JSON into the AI-handoff bundle (scope profiles,
per-bundle `AGENTS.md`, the `fingerprints.jsonl` / `index.jsonl` triage indexes, cited
`findings.json`).

The full rationale, the layered L0→L3+ methodology, the collection design, and the
implementation status live in **[docs/DESIGN.md](docs/DESIGN.md)**. The earlier
per-vendor source research (now superseded by the catalog collector) is kept for
reference in **[SOURCES.md](SOURCES.md)**.

## Credits

- Static engine: [DrvEye](https://github.com/0xDbgMan/DrvEye) by 0xDbgMan (MIT),
  vendored under [`vendor/drveye/`](vendor/drveye/) — provenance in
  [`VENDORED_FROM.txt`](vendor/drveye/VENDORED_FROM.txt).
- Clone-detection reference: [LOLDrivers](https://www.loldrivers.io/). The local
  reference-set collector was removed with the vendor collectors, so offline
  `clone_hits` currently report `not_computed` until a snapshot is wired back in
  (see [docs/DESIGN.md](docs/DESIGN.md#collection)).
