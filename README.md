# Portable Driver Triage

Static-analysis pipeline for Bring-Your-Own-Vulnerable-Driver (BYOVD) research. It
collects real Windows kernel drivers from their original vendors, extracts the ones
buried inside installers, and pre-computes a layered static analysis so an AI (or a
human) starts from structured facts instead of raw bytes.

Runs fully offline in a single zero-config Docker image. **No driver is ever
executed** — every `.sys` is parsed as bytes.

---

## Quick start

You need Docker. Nothing else — Python, the analysis deps (pefile, capstone,
cryptography, angr), 7-Zip, and the vendored [DrvEye](https://github.com/0xDbgMan/DrvEye)
engine are all baked into the image.

```bash
# build the image once
docker compose build

# 1. collect — downloads drivers from vendor sites (needs network)
docker compose run --rm collect pipeline.collect loldrivers windivert
#    ...or grab everything the registered collectors can reach:
docker compose run --rm collect pipeline.collect --all

# 2. analyze — static triage of one driver under a scope (network is cut)
docker compose run --rm analyze pipeline.analyze <sha256> --scope arbitrary-physical-memory
#    ...or batch the whole collected corpus (one crash never aborts the run):
docker compose run --rm analyze pipeline.analyze --all --scope arbitrary-physical-memory --skip-existing

# 3. decompile — materialize pseudo-C for one function, on demand
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

The pipeline's whole purpose is to hand pre-digested facts to an AI. The contract
lives in [`AGENTS.md`](AGENTS.md); modern agents (Claude Code, Codex, Cursor) discover
it automatically. Three ways to use it:

- **Mass triage** (the common case) — from the repo root, ask a capability question:
  *"which drivers allow arbitrary physical I/O?"* The AI reads one index file
  (`reports/index.jsonl`), filters, ranks, and only then opens the handful of bundles
  that matter.
- **Deep analysis** — point the AI at one bundle
  (`reports/<sha256>/<run_id>/`) and ask it to analyze. It produces a cited
  `findings.json` + `findings.md`.
- **On demand** — during analysis the AI runs `pipeline.decompile` itself to get
  pseudo-C for any function it's about to cite.

Every claim in a finding must cite a real line in the bundle — see
[`AGENTS.md`](AGENTS.md) §6.

---

## Scopes

A scope profile tells the pipeline what you're hunting for; it filters which drivers
go deep and enriches the AI's vocabulary. Shipped profiles (in
[`scope_profiles/`](scope_profiles/)):

| scope | capability |
|---|---|
| `arbitrary-physical-memory` | map/read/write physical memory (`MmMapIoSpace`, …) |
| `msr-access` | model-specific register read/write (`__rdmsr` / `__wrmsr`) |
| `hid-input-control` | inject or intercept mouse / keyboard / HID input |
| `process-token-manipulation` | steal / elevate process tokens |
| `disk-raw-io` | raw block-device read/write |
| `smm-smi` | System Management Mode / SMI triggering |

---

## What you get per driver

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

The heavy static-analysis engine (PE parsing, Authenticode, IOCTL discovery, taint,
exploit-primitive classification) is **not reinvented** here — the project vendors
[DrvEye](https://github.com/0xDbgMan/DrvEye) (MIT) as its L0→L3+ engine and owns the
two layers DrvEye doesn't provide: **real-world vendor-driver collection** and the
**AI-handoff contract** (scope profiles, per-bundle `AGENTS.md`, the `index.jsonl`
triage index, cited `findings.json`).

The full rationale, the layered L0→L3+ methodology, the collector catalog, and the
implementation status all live in **[docs/DESIGN.md](docs/DESIGN.md)**.
Vendor source catalog: **[SOURCES.md](SOURCES.md)**.

## Credits

- Static engine: [DrvEye](https://github.com/0xDbgMan/DrvEye) by 0xDbgMan (MIT),
  vendored under [`vendor/drveye/`](vendor/drveye/) — provenance in
  [`VENDORED_FROM.txt`](vendor/drveye/VENDORED_FROM.txt).
- Clone reference set: [LOLDrivers](https://www.loldrivers.io/).
