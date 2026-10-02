"""CPUID (CPU-Z / HWMonitor / …) — embedded-PE-resource driver collector.

CPUID's utilities (CPU-Z, HWMonitor, PerfMonitor, …) ship their kernel driver
**embedded inside the application `.exe`** as a PE resource — one native-subsystem
PE per CPU architecture (x86 / x64 / ia64). The `.sys` never exists as a file on
disk in the distribution ZIP, so plain extraction recovers nothing; the driver is
recovered by byte-carving the app binary (`_common.collect_carved_drivers`). Each
historical version embeds that version's signed driver, so the long archive of
past releases is a deep, enumerable, HTTPS-only source of distinct signed drivers.

Shape:
  1. discover(): scrape the product pages on www.cpuid.com for the historical
     `download.cpuid.com/<product>/*.zip` release links (both ASCII, HTTPS).
  2. acquire(): a thread pool downloads each ZIP (HTTPS, magic-validated),
     7-Zip extracts it to reach the app `.exe`(s), then `collect_carved_drivers`
     carves the embedded native-subsystem driver PEs out of those binaries and
     dedups them into the content-addressed store. A resume ledger keyed on the
     ZIP filename makes runs resumable.

Provenance: rows are marked `cpuid-embedded` (official vendor host; driver carved
from the app binary's PE resources, so no detached `.cat` trust path exists —
authenticity is left to the L0 gate / DrvEye).

Environment knobs:
- `PDT_CPUID_PRODUCTS` (`;`/`,` slugs)  product pages to scrape (default: the
  driver-bearing utilities).
- `PDT_CPUID_JOBS`      (default 6)   parallel download workers.
- `PDT_CPUID_MAX_MB`    (default 40)  per-ZIP size cap.
- `PDT_CPUID_MAX_PACKS` (default 0 = unlimited) cap total ZIPs this run.
- `PDT_CPUID_REFRESH=1` ignore the resume ledger and re-process.
"""
from __future__ import annotations
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .. import config
from .. import progress
from .base import Collector
from . import _common as C

BASE = "https://www.cpuid.com"
# Product landing pages that link the historical release ZIPs.
DEFAULT_PRODUCTS = ["cpu-z", "hwmonitor", "perfmonitor", "powermonitor"]
# Direct release archives live on download.cpuid.com (…endswith .cpuid.com).
# The product pages link them as site-relative paths (/cpu-z/cpu-z_*.zip), with
# the host occasionally spelled out; capture both and normalize to absolute.
_DL_HOST = "https://download.cpuid.com"
RX_ZIP = re.compile(r'(?:https?://download\.cpuid\.com)?(/[^\s"\'<>]+?\.zip)', re.I)


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


class CpuidCollector(Collector):
    name = "cpuid"
    role = "CPUID (CPU-Z/HWMonitor; driver carved from app-EXE PE resources)"
    allowed_hosts = ["cpuid.com"]  # covers www. and download. (*.cpuid.com)

    def __init__(
        self,
        products: list[str] | None = None,
        *,
        jobs: int | None = None,
        max_mb: int | None = None,
        max_packs: int | None = None,
    ) -> None:
        self.products = products or _env_list("PDT_CPUID_PRODUCTS") or list(DEFAULT_PRODUCTS)
        self.jobs = jobs or _env_int("PDT_CPUID_JOBS", 6)
        self.max_mb = max_mb or _env_int("PDT_CPUID_MAX_MB", 40)
        self.max_packs = max_packs if max_packs is not None else _env_int("PDT_CPUID_MAX_PACKS", 0)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []

    # ----- discovery (scrape product pages for release ZIP links) -----

    def _get_text(self, url: str, timeout: int = 30) -> str:
        req = Request(url, headers={"User-Agent": C.UA})
        with urlopen(req, timeout=timeout) as r:
            return r.read(8 << 20).decode("utf-8", "replace")

    def discover(self) -> dict:
        progress.report("enumerating CPUID release ZIPs")
        urls: set[str] = set()
        for slug in self.products:
            for page in (f"{BASE}/softwares/{slug}.html", f"{BASE}/{slug}.html"):
                try:
                    for rel in RX_ZIP.findall(self._get_text(page)):
                        # the page spells the link as the site route /downloads/<p>,
                        # but the CDN serves it at download.cpuid.com/<p>.
                        if rel.lower().startswith("/downloads/"):
                            rel = rel[len("/downloads"):]
                        urls.add(_DL_HOST + rel)
                except Exception:
                    continue
        # newest first: the modern releases carry an embedded native .sys, while
        # the very oldest (win9x/1.0x) predate it; a capped run should see the
        # ones that actually carve.
        ordered = sorted(urls, reverse=True)
        if self.max_packs:
            ordered = ordered[: self.max_packs]
        self._urls = ordered
        progress.report(f"discovered {len(ordered)} release ZIP(s)")
        return {
            "discovery_page": f"{BASE}/softwares.html",
            "installer_url": None,  # many releases; real URLs are per-row provenance
            "products": self.products,
            "jobs": self.jobs,
            "max_mb": self.max_mb,
            "packs_found": len(ordered),
        }

    # ----- acquisition (thread pool: download -> extract -> carve -> prune) -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_CPUID_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        urls = self._urls

        rows: list[dict] = []
        errors: list[dict] = []
        downloads: list[dict] = []
        stats = {"found": len(urls), "attempted": 0, "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0}
        rep_fn, cnt_fn = progress.current_reporters()

        def handle(url: str) -> None:
            progress.set_reporter(rep_fn)
            progress.set_count_reporter(cnt_fn)
            name = Path(urlparse(url).path).name
            if name in processed:
                with self._lock:
                    stats["skipped_seen"] += 1
                return
            with self._lock:
                stats["attempted"] += 1
            got, rec = self._fetch(work_dir, url, name)
            if got is None:
                with self._lock:
                    stats["failed"] += 1
                    errors.append({"package": name, "url": url, "error": rec})
                return
            with self._lock:
                if rec:
                    downloads.append(rec)
                rows.extend(got)
                stats["packages"] += 1
                stats["sys"] += len(got)
                if not got:
                    stats["no_sys"] += 1
            self._record(name, url, [r["sha256"] for r in got],
                         status="ok" if got else "no_sys")

        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            list(pool.map(handle, urls))

        info["stats"] = stats
        info["errors"] = errors[:500]
        info["error_count"] = len(errors)
        info["downloads_top"] = downloads
        info["ledger_at_start"] = len(processed)
        info["resumed"] = (not refresh) and stats["skipped_seen"] > 0
        return rows

    def _fetch(self, work_dir: Path, url: str, name: str):
        folder = work_dir / "packages" / Path(name).stem
        pkg = folder / name
        progress.report(f"pack: {name[:44]}")
        try:
            rec = C.download(url, pkg, self.allowed_hosts, max_mb=self.max_mb,
                             timeout=120, referer=f"{BASE}/")
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        extracted = folder / "extracted"
        try:
            C.extract(pkg, extracted)
            # the driver is embedded in the app .exe as a PE resource/blob, not a
            # standalone .sys — carve the native-subsystem PEs out of every binary.
            got = C.collect_carved_drivers(extracted, config.drivers_dir())
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        for r in got:
            r["provenance"] = {
                "source_kind": "cpuid-embedded",
                "aggregator": "cpuid.com (official)",
                "trust_note": ("official vendor host; driver carved from the app "
                               "binary's PE resources, so no detached .cat trust "
                               "path exists — authenticity left to the L0 gate / "
                               "DrvEye"),
                "package_name": name,
                "package_url": url,
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
                    seen.add(json.loads(line)["pack"])
                except Exception:
                    continue
        return seen

    def _record(self, name: str, url: str, sys_shas: list[str], *, status: str) -> None:
        p = self._ledger_path()
        with self._ledger_lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "pack": name,
                    "url": url,
                    "status": status,
                    "sys": sys_shas,
                    "ts": C.utc_now(),
                }, ensure_ascii=False) + "\n")


def collector() -> CpuidCollector:
    return CpuidCollector()
