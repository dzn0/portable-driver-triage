"""Map DrvEye's JSON into the three L3 hint artifacts the charter promises.

`taint.json`, `validation_gaps.json`, and `clones.json` were previously written
as empty `[]` placeholders. That was a correctness bug: DrvEye *did* compute the
underlying signal, it just lives in other fields (`ioctls[].behavior`,
`findings`), and an empty `[]` reads as "analyzed, found nothing" — silently
suppressing real signals and leaving PLAUSIBLE findings (AGENTS.md §6) with
nothing to cite.

Each file is now a wrapper object:

    {"status": "computed" | "not_computed",
     "source": "<where the data came from>",
     "note":   "<how to read it / caveats>",
     "items":  [ ... ]}

`status: computed` with `items: []` honestly means "we looked and found none".
`status: not_computed` means the input needed to compute it was absent. The AI
cites a specific entry in `items` to satisfy a PLAUSIBLE finding.
"""
from __future__ import annotations
import functools
import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REFS = REPO_ROOT / "refs"
COLLECTORS = REPO_ROOT / "pipeline_out" / "collectors"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


# --- dangerous-import catalog (symbol -> category/severity) --------------------

@functools.lru_cache(maxsize=1)
def _dangerous_symbols() -> dict[str, tuple[str, str]]:
    path = REFS / "dangerous_imports.yaml"
    out: dict[str, tuple[str, str]] = {}
    if not path.exists():
        return out
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for cat, body in (doc.get("categories") or {}).items():
        sev = (body or {}).get("severity", "medium")
        for sym in (body or {}).get("symbols", []) or []:
            out[sym.lower()] = (cat, sev)
    return out


def _classify_sink(name: str) -> tuple[str, str] | None:
    return _dangerous_symbols().get((name or "").lower())


# --- source inference from IOCTL buffering method -----------------------------

_SOURCE_BY_METHOD = {
    "METHOD_BUFFERED":   "IRP->AssociatedIrp.SystemBuffer",
    "METHOD_IN_DIRECT":  "IRP->MdlAddress (direct I/O) + SystemBuffer",
    "METHOD_OUT_DIRECT": "IRP->MdlAddress (direct I/O) + SystemBuffer",
    "METHOD_NEITHER":    "IRP->UserBuffer / Type3InputBuffer (raw, unvalidated user pointers)",
}


def _source_for(method: str | None) -> str:
    return _SOURCE_BY_METHOD.get(method or "", "user-controlled IRP input (method unresolved)")


# --- validation vocab heuristics ----------------------------------------------

def _present_checks(security_checks: list[str]) -> set[str]:
    """Best-effort map DrvEye's free-text security_checks → the vocab in
    docs/validation_checks.md. Conservative: only claims a check is present when
    the text clearly names it."""
    present: set[str] = set()
    blob = " ".join(security_checks or []).lower()
    if "probeforread" in blob or "probe for read" in blob:
        present.add("ProbeForRead")
    if "probeforwrite" in blob or "probe for write" in blob:
        present.add("ProbeForWrite")
    if ("inputbufferlength" in blob or "input length" in blob or
            "input buffer" in blob and "length" in blob):
        present.add("input_length_check")
    if "outputbufferlength" in blob or "output length" in blob:
        present.add("output_length_check")
    if any(w in blob for w in ("privilege", "sedebug", "administrator", "integrity", "token")):
        present.add("caller_privilege_check")
    return present


def _expected_checks(method: str | None, has_dangerous_sink: bool) -> set[str]:
    expected: set[str] = set()
    if has_dangerous_sink:
        expected |= {"input_length_check", "caller_privilege_check"}
    if method == "METHOD_NEITHER":
        expected |= {"ProbeForRead", "ProbeForWrite", "input_length_check"}
    return expected


# --- taint.json ---------------------------------------------------------------

def build_taint(drveye: dict) -> dict:
    items: list[dict] = []
    findings = drveye.get("findings") or []
    ioctls = drveye.get("ioctls") or []

    # 1. Per-IOCTL sink reachability (DrvEye behavior analysis).
    for i, io in enumerate(ioctls):
        beh = io.get("behavior") or {}
        api_calls = beh.get("api_calls") or []
        sinks = []
        for name in api_calls:
            cls = _classify_sink(name)
            if cls:
                sinks.append({"name": name, "category": cls[0], "severity": cls[1]})
        risk = beh.get("risk_factors") or []
        if not sinks and not risk and not (io.get("primitives") or io.get("bug_classes")):
            continue
        items.append({
            "kind": "ioctl-sink-reachability",
            "ioctl": io.get("code"),
            "method": io.get("method"),
            "source": _source_for(io.get("method")),
            "sinks": sinks,
            "sink_categories": sorted({s["category"] for s in sinks}),
            "risk_factors": risk,
            "primitives": io.get("primitives") or [],
            "bug_classes": io.get("bug_classes") or [],
            "evidence": {"ioctls_json": f"ioctls_scoped.json#{io.get('code')}"},
            "confidence": "hint",
            "note": ("Sink reachable from a user-dispatched IOCTL per DrvEye "
                     "behavior analysis; not a fully traced dataflow -- confirm "
                     "with pipeline.decompile on the handler."),
        })

    # 2. Dangerous sinks with no resolved dispatch (WDF / table dispatch):
    #    surface the imported sink + any 'hidden function' DrvEye located so the
    #    AI knows where to point pipeline.decompile.
    if not ioctls:
        hidden = [f for f in findings
                  if (f.get("title") or "").lower().startswith("hidden function")]
        for idx, f in enumerate(findings):
            title = f.get("title") or ""
            if not title.startswith("Dangerous import:"):
                continue
            name = (f.get("details") or {}).get("function") or title.split(":", 1)[-1].strip()
            cls = _classify_sink(name)
            if not cls:
                continue
            items.append({
                "kind": "unresolved-dispatch-sink",
                "ioctl": None,
                "sink": name,
                "category": cls[0],
                "severity": f.get("severity") or cls[1],
                "source": "unresolved (no IOCTL dispatch recovered -- WDF or table dispatch)",
                "candidate_functions": [
                    {"addr": h.get("location"),
                     "purpose": (h.get("details") or {}).get("purpose")}
                    for h in hidden],
                "evidence": {"findings_json": f"findings_raw.json#{idx}"},
                "confidence": "hint",
                "note": ("Dangerous sink is imported but DrvEye did not resolve "
                         "which handler reaches it. Decompile the candidate "
                         "functions (pipeline.decompile) to trace the path."),
            })

    return {
        "status": "computed",
        "source": "DrvEye behavior analysis (ioctls[].behavior, findings)",
        "note": ("Taint HINTS, not fully traced source-to-sink dataflow. Each "
                 "item names a user-controlled source (inferred from the IOCTL "
                 "method) and the dangerous sink(s) DrvEye saw reachable. Verify "
                 "in the pseudo-C before citing as CONFIRMED."),
        "items": items,
    }


# --- validation_gaps.json -----------------------------------------------------

def build_validation_gaps(drveye: dict) -> dict:
    items: list[dict] = []
    for io in drveye.get("ioctls") or []:
        beh = io.get("behavior") or {}
        api_calls = beh.get("api_calls") or []
        dangerous = [n for n in api_calls if _classify_sink(n)]
        security_checks = beh.get("security_checks") or []
        method = io.get("method")
        has_sink = bool(dangerous)
        expected = _expected_checks(method, has_sink)
        if not expected:
            continue
        present = _present_checks(security_checks)
        # hierarchy rule from docs/validation_checks.md
        if {"caller_integrity_check", "caller_sid_check"} & present:
            present.add("caller_privilege_check")
        missing = sorted(expected - present)
        if not missing:
            continue
        if dangerous:
            reason = (f"{method or 'handler'} reaches {', '.join(dangerous)} but "
                      f"DrvEye saw no {', '.join(missing)} on the path.")
        else:
            reason = (f"{method} handler takes raw user pointers "
                      f"(UserBuffer/Type3InputBuffer) but DrvEye saw no "
                      f"{', '.join(missing)}.")
        items.append({
            "ioctl": io.get("code"),
            "method": method,
            "dangerous_apis": dangerous,
            "missing": missing,
            "present_checks_raw": security_checks,
            "reason": reason,
            "evidence": {"ioctls_json": f"ioctls_scoped.json#{io.get('code')}"},
            "confidence": "heuristic",
        })
    return {
        "status": "computed",
        "source": "DrvEye ioctls[].behavior.security_checks vs docs/validation_checks.md",
        "note": ("A gap is an expected check (given the IOCTL method + a dangerous "
                 "sink) that DrvEye's behavior analysis did not observe. Heuristic: "
                 "confirm absence in the pseudo-C before relying on it."),
        "items": items,
    }


# --- clones.json (offline, against the local LOLDrivers snapshot) -------------

@functools.lru_cache(maxsize=4)
def _load_loldrivers(catalog_path: str) -> tuple[dict, dict]:
    """Return (sha256 -> (entry, sample), imphash -> [(entry, sample), ...])."""
    data = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
    by_sha: dict[str, tuple] = {}
    by_imp: dict[str, list] = {}
    for entry in data:
        for s in entry.get("KnownVulnerableSamples") or []:
            sha = (s.get("SHA256") or "").lower()
            if sha:
                by_sha.setdefault(sha, (entry, s))
            imp = (s.get("Imphash") or "").lower()
            if imp:
                by_imp.setdefault(imp, []).append((entry, s))
    return by_sha, by_imp


def _latest_loldrivers_catalog() -> Path | None:
    base = COLLECTORS / "loldrivers"
    if not base.is_dir():
        return None
    cands = sorted(base.glob("*/catalog/drivers.json"), reverse=True)
    return cands[0] if cands else None


def _cve_of(entry: dict) -> str | None:
    cve = entry.get("CVE")
    if isinstance(cve, list):
        cve = next((c for c in cve if c), None)
    if cve and _CVE_RE.search(str(cve)):
        return _CVE_RE.search(str(cve)).group(0).upper()
    # fall back to Tags
    for tag in entry.get("Tags") or []:
        m = _CVE_RE.search(str(tag))
        if m:
            return m.group(0).upper()
    return None


def build_clones(sha256: str, imphash: str | None) -> dict:
    catalog = _latest_loldrivers_catalog()
    if catalog is None:
        return {
            "status": "not_computed",
            "source": "pipeline_out/collectors/loldrivers/",
            "note": ("No local LOLDrivers snapshot found. Run the loldrivers "
                     "collector to enable clone detection."),
            "items": [],
        }
    by_sha, by_imp = _load_loldrivers(str(catalog))
    rel = catalog.relative_to(REPO_ROOT).as_posix()
    items: list[dict] = []
    matched_shas: set[str] = set()

    hit = by_sha.get((sha256 or "").lower())
    if hit:
        entry, sample = hit
        matched_shas.add((sample.get("SHA256") or "").lower())
        items.append({
            "match_type": "sha256-exact",
            "similarity": 1.0,
            "ref_id": entry.get("Id"),
            "cve": _cve_of(entry),
            "category": entry.get("Category"),
            "filename": sample.get("Filename"),
            "sha256": sample.get("SHA256"),
            "imphash": sample.get("Imphash"),
            "source": rel,
            "note": "Byte-for-byte identical to a known-bad LOLDrivers sample.",
        })

    if imphash:
        for entry, sample in by_imp.get(imphash.lower(), []):
            if (sample.get("SHA256") or "").lower() in matched_shas:
                continue
            items.append({
                "match_type": "imphash",
                "similarity": 0.6,
                "ref_id": entry.get("Id"),
                "cve": _cve_of(entry),
                "category": entry.get("Category"),
                "filename": sample.get("Filename"),
                "sha256": sample.get("SHA256"),
                "imphash": sample.get("Imphash"),
                "source": rel,
                "note": ("Identical import table (imphash) to a known-bad sample "
                         "— same driver family or shared codebase; not proof of "
                         "identical code."),
            })

    return {
        "status": "computed",
        "source": rel,
        "note": ("Offline match of this driver's sha256 (exact) and imphash "
                 "(family) against the local LOLDrivers snapshot. No TLSH yet "
                 "(python-tlsh not installed; identity.tlsh is null)."),
        "items": items,
    }


# --- top-level: write all three into a bundle ---------------------------------

def write_l3_hints(l3_dir: Path, drveye: dict, sha256: str,
                   imphash: str | None) -> dict:
    taint = build_taint(drveye)
    gaps = build_validation_gaps(drveye)
    clones = build_clones(sha256, imphash)
    for name, obj in (("taint.json", taint),
                      ("validation_gaps.json", gaps),
                      ("clones.json", clones)):
        (l3_dir / name).write_text(
            json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"taint": len(taint["items"]),
            "validation_gaps": len(gaps["items"]),
            "clones": len(clones["items"]),
            "clones_status": clones["status"],
            "clones_items": clones["items"]}


# --- backfill CLI: regenerate the three files for an existing bundle ----------

def _reconstruct_drveye(run_dir: Path) -> dict:
    """Rebuild the minimal DrvEye dict the mappers need from bundle files."""
    l3 = run_dir / "l3_decomp"
    findings = json.loads((l3 / "findings_raw.json").read_text(encoding="utf-8")) \
        if (l3 / "findings_raw.json").exists() else []
    io_path = run_dir / "ioctls_scoped.json"
    ioctls = []
    if io_path.exists():
        ioctls = (json.loads(io_path.read_text(encoding="utf-8")) or {}).get("ioctls") or []
    return {"findings": findings, "ioctls": ioctls}


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="pipeline.adapter.l3")
    ap.add_argument("sha256", help="driver sha256 (reports/<sha256>/)")
    ap.add_argument("--run-id", help="specific bundle; default: all runs for this sha")
    args = ap.parse_args(argv)

    base = REPO_ROOT / "reports" / args.sha256
    if not base.is_dir():
        print(f"error: no reports dir for {args.sha256}", file=__import__("sys").stderr)
        return 1
    imphash = None
    ident = base / "identity.json"
    if ident.exists():
        imphash = json.loads(ident.read_text(encoding="utf-8")).get("imphash")

    runs = [base / args.run_id] if args.run_id else \
        [d for d in base.iterdir() if d.is_dir()]
    for run_dir in sorted(runs):
        l3 = run_dir / "l3_decomp"
        if not l3.is_dir():
            continue
        drveye = _reconstruct_drveye(run_dir)
        res = write_l3_hints(l3, drveye, args.sha256, imphash)
        print(f"[l3] {run_dir.name}: taint={res['taint']} "
              f"gaps={res['validation_gaps']} clones={res['clones']} "
              f"({res['clones_status']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
