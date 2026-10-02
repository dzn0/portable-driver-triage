"""TousLesDrivers.com — French driver-download aggregator collector.

TousLesDrivers.com indexes vendor driver packages for a large manufacturer
catalog and serves each package as a **direct HTTPS** file from its own CDN
(`fichiers*.touslesdrivers.com`). Like DriversCollection / SamLab it is an
aggregator rather than a single vendor, but its packages are plain enumerable
HTTPS archives (ZIP / 7z / CAB / MSI, and self-extracting EXE), which makes it a
broad, high-quantity source.

Shape:
  1. discover(): for each manufacturer code, the brand listing
     (`index.php?v_page=12&v_code=<brand>`) yields package IDs
     (`v_page=23&v_code=<id>`); each package's download popup
     (`telechargement.php?v_code=<id>`) exposes a direct
     `fichiers*.touslesdrivers.com/...` archive URL. Linux/cleaner entries are
     filtered out; the rest become work units (deduped by URL).
  2. acquire(): a thread pool downloads each archive (HTTPS, magic-validated),
     7-Zip extracts it (with a nested pass for installer-in-installer), and
     `collect_sys_files` harvests drivers by content; `collect_carved_drivers` is
     a final fallback for packages whose driver is embedded in an app binary.
     A resume ledger keyed on the archive path makes runs resumable.

Provenance: rows are marked `touslesdrivers-aggregator` (third-party aggregator,
not the original vendor domain; no catalog (.cat) trust path assumed —
authenticity left to the L0 gate / DrvEye).

Environment knobs:
- `PDT_TLD_BRANDS`    (`;`/`,` codes)  manufacturer codes to crawl (default: a
  proven seed set; extend it to scale breadth).
- `PDT_TLD_IDS`       (default 60)  max package IDs per brand.
- `PDT_TLD_JOBS`      (default 6)   parallel download workers.
- `PDT_TLD_CRAWL_JOBS`(default 6)   parallel popup-resolving crawlers.
- `PDT_TLD_MAX_MB`    (default 60)  per-package size cap.
- `PDT_TLD_MAX_PACKS` (default 0 = unlimited) cap total packages this run.
- `PDT_TLD_REFRESH=1` ignore the resume ledger and re-process.
"""
from __future__ import annotations
import json
import os
import re
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen

from .. import config
from .. import progress
from .base import Collector
from . import _common as C

BASE = "https://www.touslesdrivers.com"
# Proven manufacturer codes (from the PoC). Extend via PDT_TLD_BRANDS to scale.
DEFAULT_BRANDS = ["1305", "604", "927"]
RX_ID = re.compile(r'v_page=23&(?:amp;)?v_code=(\d+)')
RX_FILE = re.compile(
    r'href="(https://fichiers\d*\.touslesdrivers\.com/[^"<> ]+?'
    r'\.(?:zip|7z|cab|msi|exe))"', re.I)
JUNK = re.compile(r"(linux|cleaner|setup_cleaner|mac_?os)", re.I)


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


class TousLesDriversCollector(Collector):
    name = "touslesdrivers"
    role = "TousLesDrivers.com (French driver-download aggregator, direct HTTPS)"
    allowed_hosts = ["touslesdrivers.com"]  # covers www. and fichiers*. (*.touslesdrivers.com)

    def __init__(
        self,
        brands: list[str] | None = None,
        *,
        ids_per_brand: int | None = None,
        jobs: int | None = None,
        crawl_jobs: int | None = None,
        max_mb: int | None = None,
        max_packs: int | None = None,
    ) -> None:
        self.brands = brands or _env_list("PDT_TLD_BRANDS") or list(DEFAULT_BRANDS)
        self.ids_per_brand = ids_per_brand or _env_int("PDT_TLD_IDS", 60)
        self.jobs = jobs or _env_int("PDT_TLD_JOBS", 6)
        self.crawl_jobs = crawl_jobs or _env_int("PDT_TLD_CRAWL_JOBS", 6)
        self.max_mb = max_mb or _env_int("PDT_TLD_MAX_MB", 60)
        self.max_packs = max_packs if max_packs is not None else _env_int("PDT_TLD_MAX_PACKS", 0)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []

    # ----- discovery (brand -> package IDs -> direct CDN archive URL) -----

    def _get_text(self, url: str, timeout: int = 30) -> str:
        req = Request(url, headers={"User-Agent": C.UA})
        with urlopen(req, timeout=timeout) as r:
            return r.read(4 << 20).decode("latin-1", "replace")

    def _brand_ids(self, brand: str) -> list[str]:
        url = f"{BASE}/index.php?v_page=12&v_code={brand}"
        try:
            html = self._get_text(url)
        except Exception:
            return []
        ids = list(dict.fromkeys(RX_ID.findall(html)))
        return ids[: self.ids_per_brand]

    def _package_url(self, ident: str) -> str | None:
        """Resolve one package ID's direct CDN archive URL (first eligible)."""
        popup = (f"{BASE}/php/constructeurs/telechargement.php"
                 f"?v_code={ident}&v_langue=fr")
        try:
            html = self._get_text(popup)
        except Exception:
            return None
        for link in RX_FILE.findall(html):
            if JUNK.search(link):
                continue
            return link
        return None

    def discover(self) -> dict:
        progress.report("enumerating package IDs per brand")
        ids: list[str] = []
        seen_ids: set[str] = set()
        for brand in self.brands:
            for ident in self._brand_ids(brand):
                if ident not in seen_ids:
                    seen_ids.add(ident)
                    ids.append(ident)

        progress.report(f"resolving download URLs for {len(ids)} package(s)")
        urls: list[str] = []
        seen_urls: set[str] = set()
        workers = max(1, min(self.crawl_jobs, len(ids) or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for url in pool.map(self._package_url, ids):
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    urls.append(url)

        if self.max_packs:
            urls = urls[: self.max_packs]
        self._urls = urls
        progress.report(f"discovered {len(urls)} package(s)")
        return {
            "discovery_page": BASE + "/",
            "installer_url": None,  # many packages; real URLs are per-row provenance
            "brands": self.brands,
            "ids_resolved": len(ids),
            "jobs": self.jobs,
            "max_mb": self.max_mb,
            "packs_found": len(urls),
        }

    # ----- acquisition (thread pool: download -> extract -> harvest -> prune) -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_TLD_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        urls = self._urls

        rows: list[dict] = []
        errors: list[dict] = []
        downloads: list[dict] = []
        stats = {"found": len(urls), "attempted": 0, "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0}
        rep_fn, cnt_fn = progress.current_reporters()

        def key_of(url: str) -> str:
            return urllib.parse.unquote(urllib.parse.urlparse(url).path)

        def handle(url: str) -> None:
            progress.set_reporter(rep_fn)
            progress.set_count_reporter(cnt_fn)
            key = key_of(url)
            if key in processed:
                with self._lock:
                    stats["skipped_seen"] += 1
                return
            with self._lock:
                stats["attempted"] += 1
            got, rec = self._fetch(work_dir, url)
            if got is None:
                with self._lock:
                    stats["failed"] += 1
                    errors.append({"url": url, "error": rec})
                return
            with self._lock:
                if rec:
                    downloads.append(rec)
                rows.extend(got)
                stats["packages"] += 1
                stats["sys"] += len(got)
                if not got:
                    stats["no_sys"] += 1
            self._record(key, url, [r["sha256"] for r in got],
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

    def _fetch(self, work_dir: Path, url: str):
        name = Path(urllib.parse.unquote(urllib.parse.urlparse(url).path)).name
        folder = work_dir / "packages" / (str(abs(hash(url)) % (10 ** 9)) + "__" + Path(name).stem)
        pkg = folder / name
        progress.report(f"pack: {name[:44]}")
        try:
            rec = C.download(url, pkg, self.allowed_hosts, max_mb=self.max_mb,
                             timeout=180, referer=f"{BASE}/")
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        extracted = folder / "extracted"
        try:
            C.extract(pkg, extracted)
            got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
            tries = 0
            while not got and tries < 2:
                if not C.extract_nested(extracted):
                    break
                got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
                tries += 1
            if not got:
                # last resort: driver embedded inside an app/self-extractor binary
                got = C.collect_carved_drivers(extracted, config.drivers_dir())
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        for r in got:
            r["provenance"] = {
                "source_kind": "touslesdrivers-aggregator",
                "aggregator": "touslesdrivers.com",
                "trust_note": ("third-party aggregator, not the original vendor "
                               "domain; no catalog (.cat) trust path assumed — "
                               "authenticity left to the L0 gate / DrvEye"),
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
                    seen.add(json.loads(line)["key"])
                except Exception:
                    continue
        return seen

    def _record(self, key: str, url: str, sys_shas: list[str], *, status: str) -> None:
        p = self._ledger_path()
        with self._ledger_lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "key": key,
                    "url": url,
                    "status": status,
                    "sys": sys_shas,
                    "ts": C.utc_now(),
                }, ensure_ascii=False) + "\n")


def collector() -> TousLesDriversCollector:
    return TousLesDriversCollector()
