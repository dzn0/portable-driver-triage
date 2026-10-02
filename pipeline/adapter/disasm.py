"""Layer 2 (raw) — emit the shared, driver-level disassembly artifacts.

Two files, written once per unique driver under `reports/<sha256>/` and shared
across every scoped analysis of that binary (they depend only on the bytes):

  * `disasm_full.txt`  — full, grep-friendly listing, one instruction per line
                         `0xADDR\\t<bytes>\\t<mnemonic>\\t<operands>`, with inline
                         `FUNC_START: <name> @ 0xADDR` markers before each
                         discovered function entry. This is the citation target
                         AGENTS.md §6 requires for any claim about a specific
                         instruction.
  * `functions.json`   — function boundaries + inferred signatures + the line in
                         `disasm_full.txt` where each function begins.

This reuses DrvEye's vendored PE parser and (optionally) its DriverEntry walker
rather than reimplementing them — the "reuse the engine" principle from the
README. The only thing owned here is the linear sweep with resync + the file
layout the AI contract expects.

A plain linear sweep desyncs the moment it hits data-in-code. To keep every
address the AI might cite (DrvEye handler / hidden-function addresses) on a real
instruction boundary, those addresses are used as *forced resync points*: the
sweep never decodes across one, so decoding always restarts aligned at it.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

import capstone

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VENDOR_DRVEYE = REPO_ROOT / "vendor" / "drveye"
REPORTS = REPO_ROOT / "reports"

if str(VENDOR_DRVEYE) not in sys.path:
    sys.path.insert(0, str(VENDOR_DRVEYE))


def _pe_analyzer(sys_path: Path):
    from drivertool.pe_analyzer import PEAnalyzer  # vendored engine
    pe = PEAnalyzer(str(sys_path))
    pe.parse()
    return pe


# --- symbol harvesting from DrvEye JSON (scope-independent) --------------------

_HIDDEN_RE = re.compile(r"^Hidden function.*\bat\b", re.I)


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", (text or "").strip()).strip("_").lower()
    return s or "fn"


def harvest_symbols(drveye: dict | None) -> dict[int, str]:
    """Pull function-entry addresses + names out of a DrvEye report.

    Only genuine function entries are harvested — MajorFunction slot handlers
    (``details.handler`` + ``slot_name``) and DrvEye's recovered "hidden
    functions". ROP-gadget / audit ``location`` fields point mid-function and
    are deliberately ignored so they never become bogus FUNC_START markers.
    """
    out: dict[int, str] = {}
    slots: dict[int, list[str]] = {}   # handler addr -> ordered slot names
    if not drveye:
        return out
    for f in drveye.get("findings") or []:
        details = f.get("details") or {}
        handler = details.get("handler")
        if handler:
            try:
                addr = int(str(handler), 16)
            except ValueError:
                addr = None
            if addr is not None:
                slot = details.get("slot_name") or "handler"
                if slot not in slots.setdefault(addr, []):
                    slots[addr].append(slot)
        title = f.get("title") or ""
        if _HIDDEN_RE.match(title):
            loc = f.get("location")
            try:
                addr = int(str(loc), 16)
            except (ValueError, TypeError):
                continue
            purpose = details.get("purpose") or title
            out.setdefault(addr, f"hidden_{_slug(purpose)}")
    # Several MajorFunction slots routinely share one handler stub. Name it so
    # every slot stays greppable (e.g. "IRP_MJ_CREATE+CLOSE+DEVICE_CONTROL").
    for addr, names in slots.items():
        if len(names) == 1:
            out[addr] = names[0]
        else:
            short = "+".join(n[len("IRP_MJ_"):] if n.startswith("IRP_MJ_") else n
                             for n in names)
            out[addr] = f"IRP_MJ_{short}"
    return out


# --- inferred signatures (honest: null unless the shape is known) --------------

def _signature_for(name: str, is_entry: bool) -> str | None:
    if is_entry:
        return "NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)"
    if name.startswith("IRP_MJ_"):
        return "NTSTATUS (PDEVICE_OBJECT DeviceObject, PIRP Irp)"
    return None


# --- the sweep ----------------------------------------------------------------

class _Insn:
    __slots__ = ("addr", "raw", "mnem", "ops")

    def __init__(self, addr, raw, mnem, ops):
        self.addr = addr
        self.raw = raw
        self.mnem = mnem
        self.ops = ops


def _sweep_section(md: "capstone.Cs", va: int, data: bytes,
                   forced: list[int]) -> list[_Insn]:
    """Linear sweep of one executable section with resync + forced boundaries.

    `forced` is a sorted list of absolute addresses inside this section that the
    decoder must land on exactly (DrvEye-known function entries). The current
    decode run is clamped so it never crosses the next forced boundary.
    """
    insns: list[_Insn] = []
    n = len(data)
    offset = 0
    fi = 0
    while offset < n:
        chunk_va = va + offset
        while fi < len(forced) and forced[fi] <= chunk_va:
            fi += 1
        limit = (forced[fi] - va) if fi < len(forced) else n
        if limit <= offset:            # safety: a stale boundary
            limit = n
        window = data[offset:limit]
        last_end = 0
        for insn in md.disasm(window, chunk_va):
            insns.append(_Insn(insn.address, insn.bytes, insn.mnemonic, insn.op_str))
            last_end = (insn.address - chunk_va) + insn.size
        if last_end == 0:
            b = data[offset]
            insns.append(_Insn(chunk_va, bytes([b]), "db", f"0x{b:02x}"))
            offset += 1
        else:
            offset += last_end
    return insns


_CALL_IMM_RE = re.compile(r"^0x([0-9a-f]+)$")


def emit(sys_path: Path, known_symbols: dict[int, str] | None = None):
    """Produce (disasm_text, functions_list) for one driver. Pure, no IO."""
    pe = _pe_analyzer(sys_path)
    is_64 = pe.is_64bit
    image_base = pe.pe.OPTIONAL_HEADER.ImageBase
    entry_va = image_base + pe.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # map VA -> section name, for functions.json
    sec_ranges: list[tuple[int, int, str]] = []
    for sec in pe.pe.sections:
        if sec.Characteristics & 0x20000000:  # executable
            s_va = image_base + sec.VirtualAddress
            sec_ranges.append((s_va, s_va + len(sec.get_data()), sec.Name.decode(
                "utf-8", "replace").rstrip("\x00")))

    def _section_of(addr: int) -> str | None:
        for s, e, name in sec_ranges:
            if s <= addr < e:
                return name
        return None

    known_symbols = dict(known_symbols or {})
    # Fallback: if DrvEye gave us nothing, walk DriverEntry ourselves for the
    # MajorFunction table so IOCTL handlers still get named + aligned.
    if not known_symbols:
        try:
            from drivertool.disassembler import Disassembler
            dis = Disassembler(is_64)
            for s_va, s_data in pe.get_code_sections():
                if s_va <= entry_va < s_va + len(s_data):
                    ep_code = s_data[entry_va - s_va:]
                    mf = dis.extract_major_functions(ep_code, entry_va, image_base)
                    _SLOT = {0x0: "IRP_MJ_CREATE", 0xE: "IRP_MJ_DEVICE_CONTROL"}
                    for slot, hva in mf.items():
                        known_symbols.setdefault(hva, _SLOT.get(slot, f"MajorFunction_{slot:#x}"))
                    break
        except Exception:
            pass

    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32)
    md.detail = False

    # Primary (forced-align) starts: entry + every harvested symbol.
    primary: dict[int, str] = dict(known_symbols)
    primary.setdefault(entry_va, "entry_point")

    all_insns: list[_Insn] = []
    for s_va, s_data in pe.get_code_sections():
        forced = sorted(a for a in primary if s_va <= a < s_va + len(s_data))
        all_insns.extend(_sweep_section(md, s_va, s_data, forced))

    insn_addrs = {i.addr for i in all_insns if i.mnem != "db"}

    # Secondary starts: direct-call targets that landed on a real boundary.
    starts: dict[int, str] = dict(primary)
    for ins in all_insns:
        if ins.mnem == "call":
            m = _CALL_IMM_RE.match(ins.ops.strip())
            if m:
                tgt = int(m.group(1), 16)
                if tgt in insn_addrs and tgt not in starts and _section_of(tgt):
                    starts[tgt] = f"sub_{tgt:x}"

    # Keep only starts that sit on a real instruction boundary.
    starts = {a: n for a, n in starts.items() if a in insn_addrs}

    # --- render disasm_full.txt + record each function's line ---
    lines: list[str] = []
    func_line: dict[int, int] = {}
    for ins in all_insns:
        if ins.addr in starts:
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(f"FUNC_START: {starts[ins.addr]} @ 0x{ins.addr:x}")
            func_line[ins.addr] = len(lines) + 1  # the instruction line (1-based)
        lines.append(f"0x{ins.addr:x}\t{ins.raw.hex()}\t{ins.mnem}\t{ins.ops}")
    disasm_text = "\n".join(lines) + "\n"

    # --- functions.json ---
    sorted_starts = sorted(starts)
    func_list = []
    for idx, addr in enumerate(sorted_starts):
        name = starts[addr]
        sec = _section_of(addr)
        # size = gap to next start in the same section, else to section end
        size = None
        if idx + 1 < len(sorted_starts):
            nxt = sorted_starts[idx + 1]
            if _section_of(nxt) == sec:
                size = nxt - addr
        if size is None and sec:
            for s, e, nm in sec_ranges:
                if nm == sec and s <= addr < e:
                    size = e - addr
                    break
        is_entry = (addr == entry_va)
        source = []
        if addr in known_symbols:
            source.append("drveye")
        if is_entry:
            source.append("entry_point")
        if name.startswith("sub_"):
            source.append("call-target")
        func_list.append({
            "addr": f"0x{addr:x}",
            "name": name,
            "section": sec,
            "size": size,
            "inferred_signature": _signature_for(name, is_entry),
            "source": source or ["linear-sweep"],
            "disasm_line": func_line.get(addr),
        })

    functions = {
        "sha256": None,            # filled by ensure_shared_disasm
        "image_base": f"0x{image_base:x}",
        "arch": "x64" if is_64 else "x86",
        "entry_point": f"0x{entry_va:x}",
        "sections": [{"name": nm, "start": f"0x{s:x}", "end": f"0x{e:x}"}
                     for s, e, nm in sec_ranges],
        "count": len(func_list),
        "functions": func_list,
    }
    return disasm_text, functions


# --- public: write the shared artifacts --------------------------------------

def ensure_shared_disasm(sys_path: Path, sha256: str,
                         known_symbols: dict[int, str] | None = None,
                         force: bool = False) -> dict:
    """Write `reports/<sha256>/{disasm_full.txt,functions.json}` if absent.

    Idempotent and cheap to re-check, so every scoped run can call it; the files
    are shared across runs because they depend only on the binary.
    """
    out_dir = REPORTS / sha256
    out_dir.mkdir(parents=True, exist_ok=True)
    disasm_path = out_dir / "disasm_full.txt"
    functions_path = out_dir / "functions.json"

    if disasm_path.exists() and functions_path.exists() and not force:
        return {"disasm": str(disasm_path), "functions": str(functions_path),
                "regenerated": False}

    disasm_text, functions = emit(sys_path, known_symbols)
    functions["sha256"] = sha256
    disasm_path.write_text(disasm_text, encoding="utf-8")
    functions_path.write_text(
        json.dumps(functions, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    return {
        "disasm": str(disasm_path),
        "functions": str(functions_path),
        "regenerated": True,
        "n_insns": disasm_text.count("\n0x") + disasm_text.startswith("0x"),
        "n_funcs": functions["count"],
    }


# --- CLI: backfill an existing driver ----------------------------------------

def _resolve(spec: str) -> tuple[str, Path]:
    from .. import config
    from ..collectors import _common as C
    p = Path(spec)
    if p.is_file():
        return C.sha256_file(p), p
    candidate = config.drivers_dir() / f"{spec}.sys"
    if candidate.is_file():
        return spec, candidate
    raise FileNotFoundError(f"driver not found: {spec}")


def _latest_findings_symbols(sha256: str) -> dict[int, str]:
    """Best-effort: harvest symbols from the most recent bundle's findings_raw."""
    base = REPORTS / sha256
    candidates = sorted(base.glob("*/l3_decomp/findings_raw.json"), reverse=True)
    for c in candidates:
        try:
            findings = json.loads(c.read_text(encoding="utf-8"))
            return harvest_symbols({"findings": findings})
        except Exception:
            continue
    return {}


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="pipeline.adapter.disasm")
    ap.add_argument("spec", help="sha256 under pipeline_out/drivers/ or a .sys path")
    ap.add_argument("--force", action="store_true", help="regenerate even if present")
    args = ap.parse_args(argv)
    try:
        sha, path = _resolve(args.spec)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    symbols = _latest_findings_symbols(sha)
    res = ensure_shared_disasm(path, sha, known_symbols=symbols, force=args.force)
    print(f"[disasm] {sha[:16]}... regenerated={res['regenerated']} "
          f"funcs={res.get('n_funcs','?')} -> {res['disasm']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
