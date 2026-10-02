"""Lazy decompilation on citation — materialize pseudo-C for one function.

Full-driver decompilation is expensive and almost always wasted: a BYOVD
researcher (human or AI) discards most drivers at the disassembly stage and only
needs readable pseudo-C for the handful of functions they are about to cite.
This CLI produces exactly that, one function at a time, into an existing bundle.

    python -m pipeline.decompile <sha256> <func_addr> [options]

      <sha256>        driver already under pipeline_out/drivers/ (or a .sys path)
      <func_addr>     hex address of the function, e.g. 0x401478 or 0x14000b1c0

    options:
      --run-id ID     bundle to extend (default: most recent run for this sha)
      --window BYTES  decompile only func_start .. func_start+BYTES
                      (default: the function's size from functions.json)
      --backend NAME  angr (default) | asm-only
      --force         overwrite an existing <func_addr>.c

    stdout: absolute path to the generated .c file.
    exit:   0 ok | 1 function not found | 2 decompile failed

The generated `l3_decomp/<func_addr>.c` is a legitimate citation target for a
CONFIRMED finding (AGENTS.md §6). The AI is authorized to call this freely
during analysis — it does not count as "fetching or reconstructing the raw
.sys" (hard rule §8.3): the .sys is already local to the pipeline and the engine
only reads it, exactly as DrvEye already did when the bundle was built.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from . import __version__ as PIPELINE_VERSION
from . import config
from .collectors import _common as C

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS = REPO_ROOT / "reports"


# --- resolution helpers -------------------------------------------------------

def _resolve_sys(spec: str) -> tuple[str, Path]:
    p = Path(spec)
    if p.is_file():
        return C.sha256_file(p), p
    candidate = config.drivers_dir() / f"{spec}.sys"
    if candidate.is_file():
        return spec, candidate
    raise FileNotFoundError(f"driver not found: {spec}")


def _latest_run(sha256: str) -> Path | None:
    base = REPORTS / sha256
    if not base.is_dir():
        return None
    runs = sorted((d for d in base.iterdir() if d.is_dir()), reverse=True)
    return runs[0] if runs else None


def _parse_addr(s: str) -> int:
    return int(s, 16) if s.lower().startswith("0x") else int(s, 16)


def _load_functions(sha256: str) -> dict:
    fp = REPORTS / sha256 / "functions.json"
    if not fp.exists():
        raise FileNotFoundError(
            f"functions.json missing for {sha256[:16]}… — run "
            f"`python -m pipeline.adapter.disasm {sha256}` first")
    return json.loads(fp.read_text(encoding="utf-8"))


def _find_function(functions: dict, addr: int) -> dict | None:
    for f in functions.get("functions", []):
        try:
            if int(f["addr"], 16) == addr:
                return f
        except (KeyError, ValueError):
            continue
    return None


# --- backends -----------------------------------------------------------------

def _decompile_angr(sys_path: Path, pe_image_base: int, func_va: int,
                    end_va: int) -> str:
    """Decompile one function with angr. Raises on failure."""
    import logging
    for noisy in ("angr", "cle", "pyvex", "claripy", "ailment"):
        logging.getLogger(noisy).setLevel(logging.ERROR)
    import angr

    proj = angr.Project(str(sys_path), auto_load_libs=False)
    # Translate analysis-time VA (ImageBase + RVA) to angr's mapped address,
    # in case angr chose a different load base.
    mapped_base = proj.loader.main_object.mapped_base
    delta = mapped_base - pe_image_base
    a_start = func_va + delta
    a_end = end_va + delta

    cfg = proj.analyses.CFGFast(
        normalize=True,
        function_starts=[a_start],
        regions=[(a_start, a_end)],
        force_complete_scan=False,
    )
    try:
        proj.analyses.CompleteCallingConventions(recover_variables=True)
    except Exception:
        pass  # best-effort; decompiler still runs without it

    func = cfg.functions.get_by_addr(a_start) if a_start in cfg.functions else None
    if func is None:
        func = proj.kb.functions.get(a_start)
    if func is None:
        raise RuntimeError(f"angr did not recover a function at 0x{func_va:x}")

    dec = proj.analyses.Decompiler(func, cfg=cfg.model)
    if not getattr(dec, "codegen", None) or not dec.codegen.text:
        raise RuntimeError("angr decompiler produced no output")
    return dec.codegen.text


def _decompile_asm_only(sha256: str, func_va: int, end_va: int) -> str:
    """Fallback: carve the disasm window into a /* asm */ block.

    Not real pseudo-C, but a valid, honest citation target when angr fails or is
    unavailable — the lines come straight from disasm_full.txt.
    """
    disasm = (REPORTS / sha256 / "disasm_full.txt").read_text(encoding="utf-8")
    picked = []
    for line in disasm.splitlines():
        if not line.startswith("0x"):
            continue
        try:
            addr = int(line.split("\t", 1)[0], 16)
        except ValueError:
            continue
        if func_va <= addr < end_va:
            picked.append(line)
    body = "\n".join(f"    {l}" for l in picked) or "    (no instructions in range)"
    return (f"/* asm-only fallback — raw instructions from disasm_full.txt.\n"
            f"   Not decompiled; cite these lines directly. */\n"
            f"void sub_{func_va:x}(void) {{\n/*\n{body}\n*/\n}}\n")


# --- orchestration ------------------------------------------------------------

def decompile(sha256: str, sys_path: Path, func_addr: int, *,
              run_id: str | None = None, window: int | None = None,
              backend: str = "angr", force: bool = False) -> tuple[int, str]:
    """Returns (exit_code, message_or_path)."""
    functions = _load_functions(sha256)
    pe_image_base = int(functions.get("image_base", "0x0"), 16)

    fn = _find_function(functions, func_addr)
    if fn is None and window is None:
        return 1, (f"function 0x{func_addr:x} not in functions.json; pass "
                   f"--window BYTES to decompile a fixed range anyway")

    if window is not None:
        end_va = func_addr + window
        fn_name = fn["name"] if fn else f"sub_{func_addr:x}"
    else:
        size = fn.get("size") or 0x200  # defensive default if size was null
        end_va = func_addr + size
        fn_name = fn["name"]

    # resolve target bundle
    if run_id:
        run_dir = REPORTS / sha256 / run_id
        if not run_dir.is_dir():
            return 1, f"run-id not found: {run_dir}"
    else:
        run_dir = _latest_run(sha256)
        if run_dir is None:
            return 1, f"no analysis bundle exists under reports/{sha256}/"

    l3 = run_dir / "l3_decomp"
    l3.mkdir(parents=True, exist_ok=True)
    out_c = l3 / f"0x{func_addr:x}.c"
    if out_c.exists() and not force:
        print(str(out_c.resolve()))
        return 0, "exists (use --force to overwrite)"

    # run the chosen backend, falling back to asm-only on angr failure
    used_backend = backend
    try:
        if backend == "angr":
            code = _decompile_angr(sys_path, pe_image_base, func_addr, end_va)
        elif backend == "asm-only":
            code = _decompile_asm_only(sha256, func_addr, end_va)
        elif backend == "ghidra":
            return 2, "ghidra backend not implemented (use angr or asm-only)"
        else:
            return 2, f"unknown backend: {backend}"
    except Exception as e:
        if backend == "angr":
            used_backend = "asm-only (angr failed)"
            try:
                code = _decompile_asm_only(sha256, func_addr, end_va)
            except Exception as e2:
                return 2, f"angr failed ({e}); asm-only fallback failed ({e2})"
        else:
            return 2, f"{backend} backend failed: {e}"

    header = (
        f"/* ────────────────────────────────────────────────────────────\n"
        f" * Machine-generated pseudo-C — materialized on demand.\n"
        f" * driver   : {sha256}\n"
        f" * function : {fn_name} @ 0x{func_addr:x}  (range 0x{func_addr:x}"
        f"..0x{end_va:x})\n"
        f" * backend  : {used_backend}\n"
        f" * pipeline : {PIPELINE_VERSION}   generated: {C.utc_now()}\n"
        f" *\n"
        f" * Verify every sink against ../disasm_full.txt before quoting it in\n"
        f" * findings.json — decompilers elide both validation and dangerous ops.\n"
        f" * ──────────────────────────────────────────────────────────── */\n\n"
    )
    out_c.write_text(header + code, encoding="utf-8")
    print(str(out_c.resolve()))
    return 0, used_backend


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline.decompile")
    ap.add_argument("spec", help="sha256 under pipeline_out/drivers/ or a .sys path")
    ap.add_argument("func_addr", help="hex function address, e.g. 0x401478")
    ap.add_argument("--run-id", help="bundle to extend (default: most recent)")
    ap.add_argument("--window", type=lambda s: int(s, 0),
                    help="decompile func_start..func_start+BYTES")
    ap.add_argument("--backend", default="angr",
                    choices=["angr", "asm-only", "ghidra"])
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    try:
        sha, path = _resolve_sys(args.spec)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        addr = _parse_addr(args.func_addr)
    except ValueError:
        print(f"error: bad func_addr: {args.func_addr}", file=sys.stderr)
        return 2

    try:
        rc, msg = decompile(sha, path, addr, run_id=args.run_id,
                            window=args.window, backend=args.backend,
                            force=args.force)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if rc != 0:
        print(f"error: {msg}", file=sys.stderr)
    else:
        print(f"[decompile] 0x{addr:x} via {msg}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
