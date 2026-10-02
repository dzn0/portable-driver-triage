"""Entry point: analyze one driver, or the whole collected corpus.

    python -m pipeline.analyze <sha256|path> --scope <name>      # one driver
    python -m pipeline.analyze --all --scope <name>              # every driver
                                                                 # in pipeline_out/drivers/

For each driver it runs the L0 viability gate, then (if viable) DrvEye, then
emits a bundle under reports/<sha256>/<run_id>/ and appends a row to
reports/index.jsonl. Non-viable binaries are logged to reports/rejected.jsonl
and skipped. In batch mode each driver is isolated: a crash or timeout on one
does not abort the run.

Provenance (installer URL / collector / discovery page) is pulled from the most
recent collector manifest that references this sha256, so index rows carry
source attribution end-to-end.
"""
from __future__ import annotations
import argparse
import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from . import collectors as _c  # noqa: F401 — ensures config paths resolve
from . import config
from .adapter import drveye as _drveye
from .adapter import bundle as _bundle
from .adapter import l0 as _l0
from .collectors import _common as C


def _resolve_sys(spec: str) -> tuple[str, Path]:
    """`spec` may be a sha256 (looked up under pipeline_out/drivers/) or a path."""
    p = Path(spec)
    if p.is_file():
        return C.sha256_file(p), p
    candidate = config.drivers_dir() / f"{spec}.sys"
    if candidate.is_file():
        return spec, candidate
    raise FileNotFoundError(f"driver not found: {spec}")


def _lookup_provenance(sha256: str) -> dict:
    """Scan every collector manifest and return provenance for this sha256."""
    root = config.collectors_dir()
    for manifest_path in sorted(root.rglob("manifest.json"), reverse=True):
        try:
            m = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for d in m.get("drivers") or []:
            if d.get("sha256") == sha256:
                return {
                    "original_name": d.get("original_name"),
                    "collector": m.get("collector"),
                    "run_id": m.get("run_id"),
                    **(d.get("provenance") or {}),
                }
    return {}


def _scope_short(scope_name: str) -> str:
    try:
        scope = _bundle.load_scope(scope_name)
        return scope.get("short_name") or scope_name[:10]
    except Exception:
        return scope_name[:10]


def _already_analyzed(sha256: str, scope_name: str) -> bool:
    """True if a bundle for this (driver, scope) already exists."""
    reports = config.REPO_ROOT / "reports"
    short = _scope_short(scope_name)
    return any((reports / sha256).glob(f"*-{short}"))


def analyze_one(sha: str, path: Path, scope: str, signature: str) -> dict:
    """Gate + analyze a single driver. Returns a result dict; never raises for
    an expected outcome (rejection). Unexpected engine failures are caught by the
    batch caller."""
    provenance = _lookup_provenance(sha)
    verdict = _l0.gate(path, sha, driver_file=provenance.get("original_name"),
                       signature_policy=signature)
    if not verdict.ok:
        return {"status": "rejected", "sha": sha,
                "reason": verdict.reason, "detail": verdict.detail}

    drveye_report = _drveye.invoke_drveye(path)
    row = _bundle.write_bundle(path, sha, scope, drveye_report, provenance)
    return {"status": "analyzed", "sha": sha,
            "rank": row["signals"]["scope_dependent"]["rank"],
            "bundle": row["run"]["bundle_path"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline.analyze")
    ap.add_argument("spec", nargs="?",
                    help="sha256 under pipeline_out/drivers/ or a .sys path "
                         "(omit with --all)")
    ap.add_argument("--all", action="store_true",
                    help="analyze every .sys under pipeline_out/drivers/")
    ap.add_argument("--scope", required=True, help="scope profile name (see scope_profiles/)")
    ap.add_argument("--signature", default="any", choices=["any", "present"],
                    help="L0 signature policy: 'any' (default) or 'present' "
                         "(reject binaries with no Authenticode)")
    ap.add_argument("--skip-existing", action="store_true",
                    help="skip drivers that already have a bundle for this scope")
    ap.add_argument("--sha-list", type=Path, default=None,
                    help="path to a file of sha256-per-line; restricts --all "
                         "to that subset (used by shard-parallel runners). "
                         "Ignored unless --all is set.")
    ap.add_argument("--from-fingerprints", action="store_true",
                    help="with --all: analyze only drivers the cheap L1 pass "
                         "(reports/fingerprints.jsonl) flagged as qualifying for "
                         "--scope. This is the intended deep stage — run the "
                         "expensive engine only on the shortlist. Use --deep-all "
                         "to override and analyze everything.")
    ap.add_argument("--min-rank", type=int, default=1,
                    help="with --from-fingerprints: minimum L1 scope rank to "
                         "include (default 1 = any qualifying driver).")
    ap.add_argument("--deep-all", action="store_true",
                    help="explicitly analyze every driver, ignoring the L1 "
                         "shortlist (the pre-L1 behavior). Mutually exclusive "
                         "with --from-fingerprints.")
    ap.add_argument("--jobs", "-j", type=int, default=1, metavar="N",
                    help="run N drivers in parallel inside this container "
                         "(default: 1 = sequential). Writes to index.jsonl / "
                         "rejected.jsonl are concurrency-safe via O_APPEND.")
    args = ap.parse_args(argv)
    if args.jobs < 1:
        ap.error("--jobs must be >= 1")

    if args.all == bool(args.spec):
        ap.error("provide either a driver spec or --all (not both, not neither)")

    if args.from_fingerprints and args.deep_all:
        ap.error("--from-fingerprints and --deep-all are mutually exclusive")

    # Build the work list of (sha, path).
    if args.all:
        drivers = sorted(config.drivers_dir().glob("*.sys"))
        if not drivers:
            print("error: no drivers under pipeline_out/drivers/ (run pipeline.collect first)",
                  file=sys.stderr)
            return 2
        work = [(p.stem, p) for p in drivers]
        if args.sha_list is not None:
            if not args.sha_list.is_file():
                print(f"error: --sha-list file not found: {args.sha_list}", file=sys.stderr)
                return 2
            wanted = {ln.strip() for ln in args.sha_list.read_text(encoding="utf-8").splitlines()
                      if ln.strip() and not ln.startswith("#")}
            before = len(work)
            work = [(s, p) for (s, p) in work if s in wanted]
            print(f"[analyze] shard filter: {before} -> {len(work)} drivers "
                  f"(sha-list={args.sha_list})")
        if args.from_fingerprints:
            from .fingerprint import qualifying_shas
            from .adapter import l1 as _l1
            if not _l1.FINGERPRINTS.is_file():
                print(f"error: --from-fingerprints but no fingerprints at "
                      f"{_l1.FINGERPRINTS}; run `python -m pipeline.fingerprint "
                      f"--all` (or collect) first", file=sys.stderr)
                return 2
            shortlist = qualifying_shas(args.scope, args.min_rank)
            before = len(work)
            work = [(s, p) for (s, p) in work if s in shortlist]
            print(f"[analyze] L1 shortlist for '{args.scope}' (min-rank="
                  f"{args.min_rank}): {before} -> {len(work)} drivers")
    else:
        try:
            work = [_resolve_sys(args.spec)]
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    analyzed = rejected = errors = skipped = 0

    # Pre-filter the already-analyzed drivers up front. Cheap (dir glob) and
    # keeps the pool from spawning no-op workers.
    todo: list[tuple[str, Path]] = []
    for sha, path in work:
        if args.skip_existing and _already_analyzed(sha, args.scope):
            skipped += 1
            print(f"[analyze] SKIP {sha[:16]}... (bundle for {args.scope} exists)")
        else:
            todo.append((sha, path))

    def _emit(sha: str, res: dict) -> None:
        nonlocal analyzed, rejected
        if res["status"] == "rejected":
            rejected += 1
            print(f"[analyze] REJECTED {sha[:16]}... reason={res['reason']}: "
                  f"{res['detail']} -> reports/rejected.jsonl")
        else:
            analyzed += 1
            print(f"[analyze] OK {sha[:16]}... rank={res['rank']} "
                  f"bundle={res['bundle']}")

    if args.jobs == 1 or len(todo) <= 1:
        for sha, path in todo:
            try:
                res = analyze_one(sha, path, args.scope, args.signature)
            except Exception as e:  # engine crash / timeout — isolate in batch
                errors += 1
                print(f"[analyze] ERROR {sha[:16]}...: {type(e).__name__}: {e}",
                      file=sys.stderr)
                continue
            _emit(sha, res)
    else:
        # Parallel: ProcessPoolExecutor fans analyze_one() out across N worker
        # processes in this one container. Each worker is a Python subprocess
        # under the same mounts and same scope, writing to the same
        # index.jsonl / rejected.jsonl (safe thanks to the O_APPEND
        # append_index / append_rejected). Fork on Linux keeps startup cheap.
        print(f"[analyze] parallel: {len(todo)} drivers across {args.jobs} workers")
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures = {pool.submit(analyze_one, sha, path, args.scope,
                                   args.signature): sha
                       for sha, path in todo}
            for fut in as_completed(futures):
                sha = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    errors += 1
                    print(f"[analyze] ERROR {sha[:16]}...: "
                          f"{type(e).__name__}: {e}", file=sys.stderr)
                    continue
                _emit(sha, res)

    if args.all or skipped:
        print(f"[analyze] done: analyzed={analyzed} rejected={rejected} "
              f"errors={errors} skipped={skipped} total={len(work)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
