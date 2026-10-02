"""L1 — the cheap, pefile-only fingerprint computed on *every* driver.

The expensive engine (DrvEye: disassembly, dispatch reconstruction, taint) is
wasted on drivers that do not even carry the capability a scope is hunting. But
the signals that *decide* whether a driver is worth that engine — the dangerous
imports, the imphash clone family, and therefore which scope profiles it
qualifies for — all come straight from the PE import table, which is nearly free
to read.

L1 extracts exactly those signals in a single `pefile` parse and emits one row
to `reports/fingerprints.jsonl`. It is designed to run *inside collection*
(`collect_sys_files` calls `fingerprint_driver` as each `.sys` is stored), so by
the time a download finishes the whole corpus is already triaged — no separate
wait. The deep stage (`pipeline.analyze`) then runs only on the drivers L1
flagged (see `pipeline.fingerprint` for emitting that shortlist).

Nothing here is a gate: a driver with no scope match is still recorded, with
`triage.qualifies = false`, so the operator can see what was considered. Hard
viability gating stays in `l0` at deep-analysis time.

Degrades gracefully: if `pefile` is missing or a parse fails, `fingerprint_pe`
returns `None` and the caller skips the row rather than breaking collection.
"""
from __future__ import annotations
import json
import os
import threading
from pathlib import Path

from .. import __version__ as PIPELINE_VERSION
from ..collectors import _common as C
from . import l3
from . import scoring

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS = REPO_ROOT / "reports"
FINGERPRINTS = REPORTS / "fingerprints.jsonl"

# Machine → arch, mirroring l0._MACHINE (kept local so l1 does not depend on the
# rejected-row machinery just for this map).
_MACHINE = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64"}

_append_lock = threading.Lock()


def fingerprint_pe(raw: bytes) -> dict | None:
    """One pefile parse → the PE signals L1 needs. None if not parseable.

    Returns {arch, native, imports (sorted symbol names), imphash}."""
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(data=raw, fast_load=True)
    except Exception:
        return None
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ])
        arch = _MACHINE.get(int(getattr(pe.FILE_HEADER, "Machine", 0)))
        subsystem = int(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0))
        imports: set[str] = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports or []:
                    if imp.name:
                        imports.add(imp.name.decode("utf-8", "replace"))
        try:
            imphash = pe.get_imphash() or None
        except Exception:
            imphash = None
        return {
            "arch": arch,
            "native": subsystem == 1,
            "imports": sorted(imports),
            "imphash": imphash,
        }
    finally:
        pe.close()


def _dangerous_imports(imports: list[str]) -> list[str]:
    """Filter the import list down to symbols in the dangerous-import catalog
    (refs/dangerous_imports.yaml), reusing l3's loader. Sorted, deduped."""
    catalog = l3._dangerous_symbols()
    return sorted({s for s in imports if s.lower() in catalog})


def _project_clone_hits(clone_items: list[dict]) -> list[dict]:
    out = []
    for c in clone_items:
        ref = c.get("ref_id")
        if not ref:
            continue
        out.append({
            "ref_id": str(ref),
            "cve": c.get("cve"),
            "similarity": float(c.get("similarity", 0.0)),
        })
    return out


def build_fingerprint_row(sha256: str, pe_sig: dict, *,
                          original_name: str | None = None,
                          size_bytes: int | None = None,
                          signature_status: str = "unknown") -> dict:
    """Assemble one fingerprints.jsonl row from a `fingerprint_pe` result.

    Cross-profile `scope_matches` and clone hits are computed here, cheaply,
    from imports + imphash alone — the same `scoring.compute_scope_matches` the
    deep bundle uses, so a profile fires identically at both stages."""
    imports = pe_sig.get("imports") or []
    dangerous = _dangerous_imports(imports)
    imphash = pe_sig.get("imphash")

    scope_matches = scoring.compute_scope_matches(
        scoring.synth_drveye_view(dangerous)
    )
    clones = l3.build_clones(sha256, imphash)
    clone_hits = _project_clone_hits(clones.get("items") or [])

    best = scope_matches[0] if scope_matches else None
    qualifies = bool(scope_matches) or bool(clone_hits)

    return {
        "schema_version": 1,
        "sha256": sha256,
        "imphash": imphash,
        "arch": pe_sig.get("arch"),
        "original_name": original_name,
        "size_bytes": size_bytes,
        "signature_status": signature_status,
        "signals": {
            "dangerous_imports": dangerous,
            "clone_hits": clone_hits,
            "scope_matches": scope_matches,
        },
        "triage": {
            "qualifies": qualifies,
            "best_scope": best["scope"] if best else None,
            "best_rank": best["rank"] if best else 0,
        },
        "detected_at": C.utc_now(),
        "pipeline_version": PIPELINE_VERSION,
    }


def append_fingerprint(row: dict, path: Path = FINGERPRINTS) -> None:
    """Append one row to fingerprints.jsonl.

    Collection runs collectors in a thread pool within a single process, so a
    module-level lock makes the append safe there. (Cross-process safety is a
    separate concern; the deep index has the same open question.)"""
    data = (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
    with _append_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)


def fingerprint_driver(sys_path: Path, sha256: str, *,
                       original_name: str | None = None,
                       size_bytes: int | None = None,
                       signature_status: str = "unknown",
                       append: bool = True) -> dict | None:
    """End-to-end for one stored driver: parse → row → (optionally) append.

    Returns the row, or None if the PE could not be fingerprinted (caller then
    simply skips it — collection must never break on a bad binary)."""
    try:
        raw = sys_path.read_bytes()
    except OSError:
        return None
    pe_sig = fingerprint_pe(raw)
    if pe_sig is None:
        return None
    row = build_fingerprint_row(
        sha256, pe_sig,
        original_name=original_name or sys_path.name,
        size_bytes=size_bytes if size_bytes is not None else len(raw),
        signature_status=signature_status,
    )
    if append:
        append_fingerprint(row)
    return row


def _signature_status_from_collector(signature: dict | None) -> str:
    """Map collect_sys_files' signature record to the row's status vocabulary."""
    if not signature:
        return "unknown"
    acc = signature.get("accepted")
    if acc is True:
        return "signed"
    if acc is False:
        return "unsigned"
    return "unknown"
