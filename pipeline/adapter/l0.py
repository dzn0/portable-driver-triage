"""L0 viability gate — cheap, runs on everything before DrvEye.

Discards binaries that could not realistically load as Windows kernel drivers so
the expensive L1-L3+ engine never runs on junk, and — critically — records every
rejection in `reports/rejected.jsonl` so nothing is *silently* dropped (README
L0 section; AGENTS.md Mode C reads this stream).

The gate is deliberately pefile-only (no DrvEye import, no disassembly): a PE
parse plus a handful of header reads. Reasons are the closed vocabulary from
`schemas/rejected_row.schema.json`.
"""
from __future__ import annotations
import json
import os
from pathlib import Path

import pefile

from .. import __version__ as PIPELINE_VERSION
from ..collectors import _common as C

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS = REPO_ROOT / "reports"
REFS = REPO_ROOT / "refs"

# Machine → arch (schema enum: x86 | x64 | arm64 | null)
_MACHINE = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64"}

# IMAGE_SUBSYSTEM
_SUBSYSTEM_NAMES = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
    5: "OS2_CUI", 7: "POSIX_CUI", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM",
    14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
}
_SUBSYSTEM_NATIVE = 1

# DLLs whose presence in the import table marks a real kernel-mode module.
_KERNEL_MODULES = {
    "ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe",
    "hal.dll", "wdfldr.sys", "wdfldr.dll", "wdmaud.sys",
    "ndis.sys", "fltmgr.sys", "ksecdd.sys", "storport.sys", "scsiport.sys",
    "usbd.sys", "wmilib.sys", "ks.sys", "portcls.sys", "tcpip.sys",
    "netio.sys", "classpnp.sys", "videoprt.sys", "dxgkrnl.sys",
    "bootvid.dll", "pshed.dll", "clfs.sys", "cng.sys", "msrpc.sys",
}

_PACK_ENTROPY = 7.5  # per-section Shannon entropy above this = likely packed


class _Verdict:
    def __init__(self, ok, arch=None, reason=None, detail=None):
        self.ok = ok
        self.arch = arch
        self.reason = reason
        self.detail = detail


def _blacklist() -> set[str]:
    path = REFS / "hash_blacklist.txt"
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        h = line.strip().split("#", 1)[0].strip().lower()
        if len(h) == 64:
            out.add(h)
    return out


def check_viability(raw: bytes, sha256: str, *,
                    signature_policy: str = "any") -> _Verdict:
    """Decide whether `raw` is worth handing to DrvEye.

    signature_policy: "any" (default, never rejects on signing) or "present"
    (reject binaries with no Authenticode security directory). The stronger
    "valid-ever" / "valid-now" policies require full Authenticode verification,
    which DrvEye performs downstream; they are not enforced at this cheap gate.
    """
    if sha256.lower() in _blacklist():
        return _Verdict(False, None, "blacklisted",
                        "operator opted this hash out via refs/hash_blacklist.txt")

    if not raw:
        return _Verdict(False, None, "corrupted", "file is empty (0 bytes)")

    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except Exception as e:
        return _Verdict(False, None, "not-pe", f"pefile could not parse: {e}"[:480])

    try:
        arch = _MACHINE.get(getattr(pe.FILE_HEADER, "Machine", 0))

        # --- structural sanity: sections must lie within the file ---
        n = len(raw)
        for sec in pe.sections:
            end = int(sec.PointerToRawData) + int(sec.SizeOfRawData)
            if sec.SizeOfRawData and end > n:
                name = sec.Name.decode("utf-8", "replace").rstrip("\x00")
                return _Verdict(False, arch, "corrupted",
                                f"section {name!r} data ends at {end} but file is {n} bytes")

        # --- subsystem must be NATIVE ---
        subsystem = int(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0))
        if subsystem != _SUBSYSTEM_NATIVE:
            name = _SUBSYSTEM_NAMES.get(subsystem, "UNKNOWN")
            return _Verdict(False, arch, "wrong-subsystem",
                            f"IMAGE_SUBSYSTEM = {subsystem} ({name}) -- expected 1 (NATIVE)")

        # --- imports must resolve against a kernel module ---
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = (entry.dll or b"").decode("utf-8", "replace").lower()
                if dll:
                    imports.append(dll)
        if not imports:
            return _Verdict(False, arch, "kernel-imports-unresolved",
                            "no import table (a kernel driver imports from ntoskrnl/hal/…)")
        if not any(dll in _KERNEL_MODULES for dll in imports):
            return _Verdict(False, arch, "kernel-imports-unresolved",
                            f"imports {imports[0]!r} but no kernel module "
                            f"(ntoskrnl.exe/hal.dll/wdfldr.sys/…) in the table")

        # --- signature policy (cheap presence check only) ---
        if signature_policy == "present":
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # SECURITY
            if not sec_dir.VirtualAddress or not sec_dir.Size:
                return _Verdict(False, arch, "signature-policy-mismatch",
                                "policy=present but binary has no Authenticode security directory")

        # --- packing heuristic (conservative) ---
        exec_secs = [s for s in pe.sections if s.Characteristics & 0x20000000]
        if exec_secs and all(s.get_entropy() > _PACK_ENTROPY for s in exec_secs):
            worst = max(s.get_entropy() for s in exec_secs)
            return _Verdict(False, arch, "packed-unknown",
                            f"entropy heuristic (all exec sections > {_PACK_ENTROPY}, "
                            f"max {worst:.2f}); no known-packer unpacker")

        return _Verdict(True, arch)
    finally:
        pe.close()


# --- rejected.jsonl row + atomic append ---------------------------------------

def build_rejected_row(sha256: str, verdict: _Verdict, *,
                       driver_file: str | None, source_path: str,
                       size_bytes: int | None) -> dict:
    return {
        "schema_version": 1,
        "sha256": sha256,
        "driver_file": driver_file,
        "source_path": source_path,
        "size_bytes": size_bytes,
        "arch": verdict.arch,
        "reason": verdict.reason,
        "reason_detail": (verdict.detail or verdict.reason or "rejected")[:500],
        "detected_at": C.utc_now(),
        "pipeline_version": PIPELINE_VERSION,
    }


def append_rejected(row: dict) -> None:
    """Concurrent-safe append to reports/rejected.jsonl.

    POSIX guarantees atomicity for writes <PIPE_BUF (4096) to a single fd
    opened with O_APPEND, even across processes. Mirrors the same guarantee
    bundle.append_index relies on, closing the "needs a lock for parallel
    analysis" caveat called out in docs/DESIGN.md Pending §3.
    """
    REPORTS.mkdir(parents=True, exist_ok=True)
    target = REPORTS / "rejected.jsonl"
    data = (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
    assert len(data) < 4096, (
        f"rejected row {len(data)} bytes exceeds PIPE_BUF atomic-append guarantee"
    )
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path.resolve())


def gate(sys_path: Path, sha256: str, *, driver_file: str | None = None,
         signature_policy: str = "any") -> _Verdict:
    """Run the gate; on rejection, append the row and return the verdict.

    Caller checks `verdict.ok`: True → proceed to DrvEye; False → already logged
    to rejected.jsonl, do not build a bundle.
    """
    raw = sys_path.read_bytes()
    verdict = check_viability(raw, sha256, signature_policy=signature_policy)
    if not verdict.ok:
        row = build_rejected_row(
            sha256, verdict,
            driver_file=driver_file or sys_path.name,
            source_path=_rel(sys_path),
            size_bytes=len(raw) or None)
        append_rejected(row)
    return verdict


# --- CLI: check one file without analyzing ------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="pipeline.adapter.l0")
    ap.add_argument("path", help="a .sys path to test")
    ap.add_argument("--signature", default="any", choices=["any", "present"])
    ap.add_argument("--no-log", action="store_true",
                    help="print verdict only; do not append to rejected.jsonl")
    args = ap.parse_args(argv)
    p = Path(args.path)
    if not p.is_file():
        print(f"error: not a file: {p}", file=sys.stderr)
        return 2
    sha = C.sha256_file(p)
    raw = p.read_bytes()
    v = check_viability(raw, sha, signature_policy=args.signature)
    if v.ok:
        print(f"[l0] OK  {sha[:16]}... arch={v.arch}")
        return 0
    if not args.no_log:
        append_rejected(build_rejected_row(
            sha, v, driver_file=p.name, source_path=_rel(p),
            size_bytes=len(raw) or None))
    print(f"[l0] REJECT {sha[:16]}... reason={v.reason}: {v.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
