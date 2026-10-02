"""Emit a bundle for `reports/<sha256>/<run_id>/` from DrvEye JSON + scope.

Owns the mapping from DrvEye's output fields into the canonical artifacts
that AGENTS.md tells the AI to read: identity.json, pe_metadata.json,
ioctls_scoped.json, l3_decomp/*, ai_bundle.md, scope_<name>.md, per-bundle
AGENTS.md. Also emits one conforming row for reports/index.jsonl.
"""
from __future__ import annotations
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Template

from .. import __version__ as PIPELINE_VERSION
from ..collectors import _common as C

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS = REPO_ROOT / "reports"
SCHEMAS = REPO_ROOT / "schemas"
SCOPE_PROFILES = REPO_ROOT / "scope_profiles"
TEMPLATE = REPO_ROOT / "pipeline" / "templates" / "per_bundle_agents.md.j2"


# --- severity -----------------------------------------------------------------

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _sev(s: str | None) -> int:
    return SEVERITY_RANK.get((s or "").upper(), 0)


# --- scope profile loading ----------------------------------------------------

def load_scope(name: str) -> dict:
    path = SCOPE_PROFILES / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"scope profile not found: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# --- scope-aware filtering of DrvEye findings ---------------------------------

def scope_filter(drveye: dict, scope: dict) -> dict:
    """Partition DrvEye findings into inside-scope vs out-of-scope.

    DrvEye reports every dangerous import, device-name signal, and bug class
    it finds. The scope profile narrows: an import is in-scope only if it
    appears in the profile's `imports_of_interest` (must_have_one or
    weight_each) or `taint_sinks`; a device-name issue is in-scope only if
    at least one of the driver's device names matches a scope regex. Every
    finding not pulled in by one of those rules lands in `out_of_scope`.
    """
    import re
    imports_wanted = set(
        (scope.get("imports_of_interest") or {}).get("must_have_one", []) or []
    ) | set(
        (scope.get("imports_of_interest") or {}).get("weight_each", []) or []
    ) | set(scope.get("taint_sinks") or [])
    strings_wanted = set(scope.get("strings_of_interest") or [])
    device_patterns = [re.compile(p) for p in (scope.get("device_name_patterns") or [])]
    device_names = drveye.get("device_names") or []
    device_matches = any(
        any(p.search(n) for p in device_patterns) for n in device_names
    )

    inside, outside = [], []
    for f in drveye.get("findings", []):
        details = f.get("details") or {}
        fn = details.get("function") or ""
        title = f.get("title") or ""
        in_scope = False
        if fn in imports_wanted:
            in_scope = True
        if device_matches and ("Device" in title or "SDDL" in title):
            in_scope = True
        for s in strings_wanted:
            if s in title or s in (f.get("description") or ""):
                in_scope = True
                break
        (inside if in_scope else outside).append(f)
    return {"inside": inside, "outside": outside, "device_matches": device_matches}


# --- rank calculation (docs/ranking.md: purely additive) ----------------------

def compute_rank(drveye: dict, scope: dict) -> dict:
    weights = scope.get("rank_weights") or {}
    imports = {
        d.get("details", {}).get("function")
        for d in drveye.get("findings", [])
        if (d.get("title") or "").startswith("Dangerous import:")
    }
    must_have_one = set(
        (scope.get("imports_of_interest") or {}).get("must_have_one", []) or []
    )
    weight_each = set(
        (scope.get("imports_of_interest") or {}).get("weight_each", []) or []
    )
    hits = {
        "must_have_one": len(imports & must_have_one),
        "dangerous_imports": len(imports & weight_each),
        "device_match": 0,
        "string_match": 0,
        "ioctl_match": 0,
        "method_match": 0,
        "clone_hit": 0,
    }
    import re
    for p in (scope.get("device_name_patterns") or []):
        if any(re.search(p, n) for n in (drveye.get("device_names") or [])):
            hits["device_match"] += 1
    rank = sum(hits[k] * int(weights.get(k, 0)) for k in hits)
    return {
        "rank": rank,
        "hits": hits,
        "qualifies": hits["must_have_one"] > 0,
    }


# --- device-class classification ---------------------------------------------
# Rough mapping from DrvEye device_names → the closed vocabulary required by
# index_row.schema.json. Richer classification lives in refs/device_classes.yaml
# but at adapter level we only need the broadest bucketing.

_DEVICE_CLASS_RULES = [
    (r"PhysicalMemory|Phy|MapIo",            "memory"),
    (r"\\Hid|\\Kbd|\\Mou",                   "hid"),
    (r"\\DISK|\\Volume|\\CdRom|Nvme|Scsi",   "disk"),
    (r"\\Nd|\\Tcp|\\Udp|\\Ip",               "net"),
    (r"\\Usb",                               "usb"),
    (r"\\Beep|\\Null|\\Rand",                "generic"),
]


def classify_devices(device_names: list[str]) -> list[str]:
    import re
    out: set[str] = set()
    for n in device_names:
        for pattern, cls in _DEVICE_CLASS_RULES:
            if re.search(pattern, n, re.I):
                out.add(cls)
    if not out and device_names:
        out.add("generic")
    return sorted(out)


# --- bundle writer ------------------------------------------------------------

def _signature_status(drveye: dict) -> str:
    cert = drveye.get("certificate") or {}
    if not cert.get("signed"):
        return "unsigned"
    if cert.get("signer_expired"):
        return "expired"
    return "signed"


def _normalize_ioctl_codes(drveye: dict) -> list[str]:
    """Lower-case hex, strip leading zeros past 0x, dedup, keep order."""
    seen, out = set(), []
    for i in drveye.get("ioctls") or []:
        c = i.get("code")
        if not c:
            continue
        try:
            v = int(c, 16) if isinstance(c, str) else int(c)
            norm = f"0x{v:x}"
        except (TypeError, ValueError):
            continue
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def _count_methods(drveye: dict) -> dict:
    counts = {"METHOD_BUFFERED": 0, "METHOD_IN_DIRECT": 0,
              "METHOD_OUT_DIRECT": 0, "METHOD_NEITHER": 0}
    for i in drveye.get("ioctls") or []:
        m = i.get("method")
        if m in counts:
            counts[m] += 1
    return counts


import re as _re

_INDEX_CVE_RE = _re.compile(r"^CVE-\d{4}-\d{4,}$")


def _index_clone_hits(clone_items: list[dict]) -> list[dict]:
    """Project l3 clone items into the strict index_row.schema shape
    (ref_id, cve, similarity only; cve must match the schema's CVE pattern)."""
    out = []
    for c in clone_items:
        ref = c.get("ref_id")
        if not ref:
            continue
        cve = c.get("cve")
        if cve and not _INDEX_CVE_RE.match(cve):
            cve = None
        out.append({"ref_id": str(ref), "cve": cve,
                    "similarity": float(c.get("similarity", 0.0))})
    return out


def _dangerous_imports(drveye: dict) -> list[str]:
    out = []
    for f in drveye.get("findings", []):
        if (f.get("title") or "").startswith("Dangerous import:"):
            fn = (f.get("details") or {}).get("function")
            if fn:
                out.append(fn)
    return sorted(set(out))


def write_bundle(
    sys_path: Path,
    sha256: str,
    scope_name: str,
    drveye: dict,
    provenance: dict | None = None,
    flags: dict | None = None,
) -> dict:
    """Write the full bundle under `reports/<sha256>/<run_id>/` and return a
    conforming `index.jsonl` row."""
    scope = load_scope(scope_name)
    short = scope.get("short_name") or scope_name[:10]
    run_id = f"{C.utc_now_compact()}-{short}"
    run_dir = REPORTS / sha256 / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    l3 = run_dir / "l3_decomp"
    l3.mkdir(exist_ok=True)

    provenance = provenance or {}
    flags = flags or {
        "signature": "was-valid-ever",
        "clone_ref": "loldrivers@none",
        "l3_mode": "deep",
    }

    # --- shared (driver-level) artifacts ---
    cert = drveye.get("certificate") or {}
    identity = {
        "sha256": sha256,
        "imphash": drveye.get("imphash"),
        "arch": drveye.get("arch"),
        "file": drveye.get("file"),
        "signer_cn": cert.get("signer_cn"),
        "signer_org": cert.get("signer_org"),
        "signer_expired": cert.get("signer_expired"),
        "signed": cert.get("signed"),
        "signature_status": _signature_status(drveye),
        "load_verdict": drveye.get("load_verdict"),
        "provenance": provenance,
    }
    C.save_json(REPORTS / sha256 / "identity.json", identity)
    C.save_json(
        REPORTS / sha256 / "pe_metadata.json",
        {
            "arch": drveye.get("arch"),
            "security": drveye.get("security"),
            "version": drveye.get("version"),
            "device_names": drveye.get("device_names") or [],
        },
    )

    # Shared L2-raw artifacts (disasm_full.txt + functions.json). Depend only on
    # the binary, so they are written once per driver and reused across scopes.
    # These are the citation targets AGENTS.md §6 requires for instruction-level
    # claims. Seeded with DrvEye's resolved handler/hidden-function addresses so
    # every address the AI may cite lands on a real instruction boundary.
    from . import disasm as _disasm
    _disasm.ensure_shared_disasm(
        sys_path, sha256, known_symbols=_disasm.harvest_symbols(drveye)
    )

    # --- scope-aware filtering + ranking ---
    partition = scope_filter(drveye, scope)
    rank_info = compute_rank(drveye, scope)

    # --- per-analysis artifacts ---
    C.save_json(
        run_dir / "ioctls_scoped.json",
        {"ioctls": drveye.get("ioctls") or [], "note":
         "DrvEye-resolved dispatch; empty when the driver uses WDF or "
         "non-IOCTL IPC."},
    )
    C.save_json(l3 / "findings_raw.json", drveye.get("findings") or [])
    C.save_json(l3 / "exploit_chains.json", drveye.get("exploit_chains") or [])
    C.save_json(l3 / "device_access.json", drveye.get("device_access") or {})
    # L3 hint artifacts, mapped from DrvEye's output (taint/validation) and the
    # local LOLDrivers snapshot (clones). See pipeline/adapter/l3.py — these were
    # previously empty-[] placeholders that misread as "analyzed, found nothing".
    from . import l3 as _l3
    l3_counts = _l3.write_l3_hints(l3, drveye, sha256, drveye.get("imphash"))
    (l3 / "summary.md").write_text(
        _l3_summary_md(drveye, partition, rank_info), encoding="utf-8"
    )

    # --- scope view ---
    (run_dir / f"scope_{scope_name}.md").write_text(
        _scope_view_md(scope, scope_name, partition, rank_info),
        encoding="utf-8",
    )

    # --- ai_bundle.md ---
    (run_dir / "ai_bundle.md").write_text(
        _ai_bundle_md(sha256, drveye, scope_name, partition, rank_info),
        encoding="utf-8",
    )

    # --- per-bundle AGENTS.md (Jinja template) ---
    tmpl = Template(TEMPLATE.read_text(encoding="utf-8"))
    (run_dir / "AGENTS.md").write_text(
        tmpl.render(
            sha256=sha256,
            original_filename=(provenance.get("original_name")
                               or drveye.get("file") or "unknown.sys"),
            product_name=(drveye.get("version") or {}).get("ProductName"),
            file_version=(drveye.get("version") or {}).get("FileVersion"),
            company_name=(drveye.get("version") or {}).get("CompanyName"),
            scope_name=scope_name,
            pipeline_version=PIPELINE_VERSION,
            generated_at_utc=C.utc_now(),
            active_flags=json.dumps(flags),
            one_line_scope_summary=scope.get("description", ""),
        ),
        encoding="utf-8",
    )

    # --- index row ---
    device_names = drveye.get("device_names") or []
    row = {
        "schema_version": 1,
        "identity": {
            "sha256": sha256,
            "imphash": drveye.get("imphash"),
            "tlsh": None,  # python-tlsh needs a C compiler; computed lazily later
            "driver_file": provenance.get("original_name") or drveye.get("file"),
            "product": (drveye.get("version") or {}).get("ProductName"),
            "vendor": (drveye.get("version") or {}).get("CompanyName"),
            "file_version": (drveye.get("version") or {}).get("FileVersion"),
            "arch": drveye.get("arch"),
            "size_bytes": sys_path.stat().st_size,
            "signature_status": _signature_status(drveye),
            "signer": cert.get("signer_cn"),
        },
        "run": {
            "run_id": run_id,
            "scope_profile": scope_name,
            "pipeline_version": PIPELINE_VERSION,
            "generated_at": C.utc_now(),
            "flags": flags,
            "bundle_path": f"reports/{sha256}/{run_id}/",
        },
        "signals": {
            "scope_independent": {
                "dangerous_imports": _dangerous_imports(drveye),
                "ioctl_methods": _count_methods(drveye),
                "ioctl_codes": _normalize_ioctl_codes(drveye),
                "device_names": device_names,
                "device_classes": classify_devices(device_names),
                "interesting_strings": [],
                "clone_hits": _index_clone_hits(l3_counts.get("clones_items") or []),
                "scope_matches": (
                    [{"scope": scope_name, "rank": rank_info["rank"]}]
                    if rank_info["qualifies"] else []
                ),
            },
            "scope_dependent": {
                "rank": rank_info["rank"],
                "validation_gaps": l3_counts.get("validation_gaps", 0),
                "taint_sinks": l3_counts.get("taint", 0),
                "decompiled_funcs": 0,
                "top_handler": None,
            },
        },
        "evidence_pointers": {
            "ai_bundle": f"reports/{sha256}/{run_id}/ai_bundle.md",
            "scope_view": f"reports/{sha256}/{run_id}/scope_{scope_name}.md",
            "ioctls_json": f"reports/{sha256}/{run_id}/ioctls_scoped.json",
            "findings_json": f"reports/{sha256}/{run_id}/findings.json",
            "findings_md": f"reports/{sha256}/{run_id}/findings.md",
        },
        "top_findings_preview": [],
    }
    append_index(row)
    return row


# --- atomic append to reports/index.jsonl ------------------------------------

def append_index(row: dict) -> None:
    """Crash-safe append: write to tempfile then os.replace into place."""
    REPORTS.mkdir(parents=True, exist_ok=True)
    target = REPORTS / "index.jsonl"
    line = json.dumps(row, ensure_ascii=False) + "\n"
    # Append is atomic for ≤PIPE_BUF-sized writes on POSIX; on Windows we
    # simulate via copy-to-temp then rename, keyed by (sha256, scope).
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    tmp = tempfile.NamedTemporaryFile(
        "w", delete=False, dir=str(REPORTS), suffix=".jsonl.tmp",
        encoding="utf-8", newline="",
    )
    try:
        tmp.write(existing)
        tmp.write(line)
        tmp.flush()
        os.fsync(tmp.fileno())
    finally:
        tmp.close()
    os.replace(tmp.name, target)


# --- markdown helpers ---------------------------------------------------------

def _ai_bundle_md(sha256, drveye, scope_name, partition, rank_info) -> str:
    cert = drveye.get("certificate") or {}
    lines = [
        f"# AI bundle — {sha256}",
        "",
        f"Scope: **{scope_name}** — rank **{rank_info['rank']}** "
        f"(qualifies: {rank_info['qualifies']}).",
        f"Arch: {drveye.get('arch')}. "
        f"Signed: {cert.get('signed')} / expired: {cert.get('signer_expired')}.",
        f"Attack risk (DrvEye): **{drveye.get('attack_risk')}** "
        f"(score {drveye.get('attack_surface_score')}).",
        "",
        "## Device surface",
    ]
    for n in drveye.get("device_names") or []:
        lines.append(f"- `{n}`")
    da = drveye.get("device_access") or {}
    if da:
        lines += [
            "",
            f"- SDDL: `{da.get('sddl')}`",
            f"- Secure open: {da.get('secure_open')}",
            f"- Issues: {', '.join(da.get('issues') or []) or '(none)'}",
        ]
    lines += ["", "## In-scope findings (DrvEye)"]
    if not partition["inside"]:
        lines.append("_(none — this driver does not match the scope profile)_")
    for f in partition["inside"][:30]:
        lines.append(
            f"- **{f.get('severity','?')}** — {f.get('title','?')} "
            f"({(f.get('details') or {}).get('function','')})"
        )
    lines += ["", "## Entry points"]
    lines += [
        "- `../identity.json` — binary identity + provenance",
        "- `../pe_metadata.json` — PE security + device names",
        "- `ioctls_scoped.json` — IOCTL dispatch (may be empty for WDF drivers)",
        "- `l3_decomp/findings_raw.json` — full DrvEye findings list",
        "- `l3_decomp/exploit_chains.json` — DrvEye exploit chains, if any",
        "- `l3_decomp/device_access.json` — SDDL / symlinks / issues",
        f"- `scope_{scope_name}.md` — scope profile view",
    ]
    return "\n".join(lines) + "\n"


def _scope_view_md(scope, scope_name, partition, rank_info) -> str:
    hits = rank_info["hits"]
    lines = [
        f"# Scope view — {scope_name}",
        "",
        scope.get("description", ""),
        "",
        f"## Rank: {rank_info['rank']} (qualifies: {rank_info['qualifies']})",
        "",
        "| category | hits |",
        "|---|---:|",
    ]
    for k, v in hits.items():
        lines.append(f"| {k} | {v} |")
    lines += ["", "## In-scope DrvEye findings"]
    if not partition["inside"]:
        lines.append("_(none)_")
    for f in partition["inside"]:
        lines.append(
            f"- **{f.get('severity','?')}** {f.get('title','?')} "
            f"— {f.get('description','')}"
        )
    lines += ["", "## Out-of-scope (reported by DrvEye but outside this profile)"]
    for f in partition["outside"][:50]:
        lines.append(
            f"- {f.get('severity','?')} {f.get('title','?')}"
        )
    return "\n".join(lines) + "\n"


def _l3_summary_md(drveye, partition, rank_info) -> str:
    return (
        f"# L3 summary (adapted from DrvEye)\n\n"
        f"- DrvEye attack risk: **{drveye.get('attack_risk')}** "
        f"(score {drveye.get('attack_surface_score')})\n"
        f"- Exploit chains reported: {len(drveye.get('exploit_chains') or [])}\n"
        f"- In-scope findings: {len(partition['inside'])}\n"
        f"- Rank: {rank_info['rank']}\n\n"
        "This file is a hint, not ground truth. Verify every claim against "
        "the primary artifacts before quoting them in `findings.json`.\n"
    )
