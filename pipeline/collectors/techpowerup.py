"""TechPowerUp — driver-download mirror collector.

TechPowerUp hosts a large, enumerable driver mirror. Each category page
(`/download/<category>/`) lists many versions, every version an HTML form with a
numeric download `id`, its filename and size. The file is fetched over plain
HTTPS through a tokenised CDN via a 2-step POST flow (no login, no CAPTCHA, Range
honoured). The ZIP-delivered categories (Intel wired networking, AMD Ryzen
chipset) crack straight to dozens of `.sys` each.

Shape:
  1. discover(): GET each category page and scrape (size, name, id) for every
     version; de-dup by id; sort smallest first.
  2. acquire(): a thread pool, per version: POST id -> mirror list, POST
     id+server_id -> 302 to the direct CDN URL; download it (HTTPS, archive-magic
     validated, host-pinned to *.techpowerup.com), 7-Zip extract, and
     `collect_sys_files` harvests drivers by content. Each package folder is
     pruned right after; a resume ledger keyed on the download id makes runs
     resumable. Versions that yield no `.sys` (e.g. InstallShield PE wrappers 7z
     cannot open) are recorded `no_sys` so they are not re-fetched.

Note: consecutive versions of one driver family overlap heavily, so raw `.sys`
count far exceeds unique drivers — the content-addressed store dedups that for
free; the resume ledger keeps re-runs from re-downloading the same versions.

Provenance: rows are marked `techpowerup-mirror` (third-party mirror, not the
original vendor domain; no catalog (.cat) trust path assumed — authenticity left
to the L0 gate / DrvEye).

Environment knobs:
- `PDT_TPU_CATEGORIES` (`;`/`,` slugs)  override the category set (default: the
  ZIP-delivered Intel-ethernet + AMD-Ryzen-chipset categories, which 7z opens;
  InstallShield-wrapped Bluetooth/WiFi categories are excluded by default).
- `PDT_TPU_JOBS`      (default 5)   parallel workers.
- `PDT_TPU_MAX_MB`    (default 120) per-package size cap.
- `PDT_TPU_MAX_PACKS` (default 0 = unlimited) cap total versions this run.
- `PDT_TPU_REFRESH=1` ignore the resume ledger and re-process.
"""
from __future__ import annotations
import json
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import config
from .. import progress
from .base import Collector
from . import _common as C

BASE = "https://www.techpowerup.com/download/"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# ZIP-delivered, .sys-dense categories 7z opens directly. Bluetooth/WiFi ship as
# InstallShield PE wrappers 7z cannot unpack, so they are not default.
DEFAULT_CATEGORIES = ["intel-ethernet-networking-drivers", "amd-ryzen-chipset-drivers"]

RX_FILE = re.compile(
    r'<div class="filesize">\s*([\d.]+)\s*(KB|MB|GB)\s*</div>.*?'
    r'<div class="filename"[^>]*>([^<]+)</div>.*?'
    r'name="id"\s+value="(\d+)"',
    re.I | re.S)
RX_SERVER = re.compile(r'name="server_id"\s+value="(\d+)"', re.I)
UNIT = {"KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_list(name: str) -> list[str] | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    out = [s.strip() for s in re.split(r"[;,]", raw) if s.strip()]
    return out or None


class TechPowerUpCollector(Collector):
    name = "techpowerup"
    role = "TechPowerUp (third-party driver-download mirror)"
    allowed_hosts = ["techpowerup.com"]  # covers the *-dl.techpowerup.com CDN

    def __init__(
        self,
        categories: list[str] | None = None,
        *,
        jobs: int | None = None,
        max_mb: int | None = None,
        max_packs: int | None = None,
    ) -> None:
        self.categories = categories or _env_list("PDT_TPU_CATEGORIES") or list(DEFAULT_CATEGORIES)
        self.jobs = jobs or _env_int("PDT_TPU_JOBS", 5)
        self.max_mb = max_mb or _env_int("PDT_TPU_MAX_MB", 120)
        self.max_packs = max_packs if max_packs is not None else _env_int("PDT_TPU_MAX_PACKS", 0)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._units: list[dict] = []

    # ----- discovery (scrape category pages for version ids) -----

    def _get(self, url: str, data: bytes | None = None, timeout: int = 90) -> str:
        req = urllib.request.Request(url, data=data, headers={
            "User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*",
            "Referer": BASE})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")

    def discover(self) -> dict:
        progress.report("enumerating TechPowerUp category pages")
        best: dict[str, dict] = {}
        for cat in self.categories:
            cat = cat.strip()
            if not cat:
                continue
            cat_url = BASE + cat + "/"
            try:
                html = self._get(cat_url)
            except Exception:
                continue
            for size_s, unit, name, fid in RX_FILE.findall(html):
                size = int(float(size_s) * UNIT[unit.upper()])
                if fid not in best or size < best[fid]["size"]:
                    best[fid] = {"size": size, "name": name.strip(), "key": fid,
                                 "id": fid, "cat_url": cat_url, "cat": cat}
        units = sorted(best.values(), key=lambda u: u["size"] or 1 << 62)
        if self.max_packs:
            units = units[: self.max_packs]
        self._units = units
        progress.report(f"discovered {len(units)} version(s)")
        return {
            "discovery_page": BASE,
            "installer_url": None,
            "categories": self.categories,
            "jobs": self.jobs,
            "max_mb": self.max_mb,
            "packs_found": len(units),
        }

    # ----- acquisition (resolve direct URL -> download -> extract -> harvest) -----

    def _resolve_direct(self, fid: str, cat_url: str) -> str | None:
        """POST id, read mirror list, POST id+server_id, return the 302 Location."""
        html = self._get(cat_url, data=urllib.parse.urlencode({"id": fid}).encode())
        m = RX_SERVER.search(html)
        if not m:
            return None
        body = urllib.parse.urlencode({"id": fid, "server_id": m.group(1)}).encode()
        req = urllib.request.Request(cat_url, data=body, headers={
            "User-Agent": UA, "Referer": cat_url, "Accept": "text/html,*/*"})

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        opener = urllib.request.build_opener(_NoRedirect)
        try:
            opener.open(req, timeout=90)
            return None
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                return e.headers.get("Location")
            return None

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_TPU_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        units = self._units

        rows: list[dict] = []
        errors: list[dict] = []
        downloads: list[dict] = []
        stats = {"found": len(units), "attempted": 0, "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0}

        rep_fn, cnt_fn = progress.current_reporters()

        def handle(unit: dict) -> None:
            progress.set_reporter(rep_fn)
            progress.set_count_reporter(cnt_fn)
            if unit["key"] in processed:
                with self._lock:
                    stats["skipped_seen"] += 1
                return
            with self._lock:
                stats["attempted"] += 1
            got, rec = self._fetch_unit(work_dir, unit)
            if got is None:  # transient failure: leave off ledger so it retries
                with self._lock:
                    stats["failed"] += 1
                    errors.append({"pack": unit["name"], "id": unit["id"], "error": rec})
                return
            with self._lock:
                if rec:
                    downloads.append(rec)
                rows.extend(got)
                stats["packages"] += 1
                stats["sys"] += len(got)
                if not got:
                    stats["no_sys"] += 1
            # Live count is driven by collect_sys_files (new-to-corpus only).
            # `ok` even with zero .sys: a version is deterministic (InstallShield
            # wrappers yield none), so record it permanent to avoid re-fetching.
            self._record(unit, [r["sha256"] for r in got], status="ok" if got else "no_sys")

        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            list(pool.map(handle, units))

        info["stats"] = stats
        info["errors"] = errors[:500]
        info["error_count"] = len(errors)
        info["downloads_top"] = downloads
        info["ledger_at_start"] = len(processed)
        info["resumed"] = (not refresh) and stats["skipped_seen"] > 0
        return rows

    def _fetch_unit(self, work_dir: Path, unit: dict):
        """Resolve + download + extract + harvest one version. Returns (rows, rec)
        on success, or (None, error_message) on a transient failure."""
        name, fid, cat_url = unit["name"], unit["id"], unit["cat_url"]
        progress.report(f"resolving id={fid}")
        try:
            loc = self._resolve_direct(fid, cat_url)
        except Exception as exc:
            return None, f"resolve: {exc}"
        if not loc:
            return None, "could not resolve direct URL"
        folder = work_dir / "packages" / fid
        pkg = folder / name
        progress.report(f"pack: {name[:44]}")
        try:
            rec = C.download(loc, pkg, self.allowed_hosts, max_mb=self.max_mb,
                             timeout=180, referer=cat_url)
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        try:
            extracted = folder / "extracted"
            C.extract(pkg, extracted)
            got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
            tries = 0
            while not got and tries < 2:
                # TechPowerUp zips wrap a vendor self-extractor .exe (e.g. Intel
                # PROWin) whose .sys only surface after a second extraction pass.
                if not C.extract_nested(extracted):
                    break
                got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
                tries += 1
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        for r in got:
            r["provenance"] = {
                "source_kind": "techpowerup-mirror",
                "aggregator": "techpowerup.com (driver mirror)",
                "trust_note": ("third-party mirror, not the original vendor domain; "
                               "no catalog (.cat) trust path assumed — authenticity "
                               "left to the L0 gate / DrvEye"),
                "category": unit["cat"],
                "download_id": fid,
                "package_name": name,
                "package_url": loc,
                "package_final_url": rec["final_url"],
                "package_sha256": rec["sha256"],
                "package_size": rec["size"],
            }
        C.prune_dir(folder)
        return got, rec

    # ----- resume ledger (shared across worker threads) -----

    def _ledger_path(self) -> Path:
        return config.collectors_dir() / self.name / "processed.jsonl"

    def _load_ledger(self) -> set[str]:
        p = self._ledger_path()
        seen: set[str] = set()
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    seen.add(json.loads(line)["key"])
                except Exception:
                    continue
        return seen

    def _record(self, unit: dict, sys_shas: list[str], *, status: str) -> None:
        p = self._ledger_path()
        with self._ledger_lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "key": unit["key"],
                    "pack": unit["name"],
                    "id": unit["id"],
                    "category": unit["cat"],
                    "status": status,
                    "sys": sys_shas,
                    "ts": C.utc_now(),
                }, ensure_ascii=False) + "\n")


def collector() -> TechPowerUpCollector:
    return TechPowerUpCollector()
