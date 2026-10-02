"""DriverOff.net / SamLab — direct-HTTPS `.7z` driver-release collector.

DriverOff.net is a Russian driver-release index that links, for each release, a
**direct HTTPS** `.7z` on `soft.samlab.ws/drivers/`. Unlike the DriversCollection
aggregator (deep per-driver crawl, single rate-limited host) and unlike the full
SamDrivers/SDI pack set (50 GB, torrent-only), the per-release archives here are
plain, enumerable, resumable HTTPS downloads — each a real 7-Zip archive that
expands to one or more drivers. That makes this the project's high-throughput,
HTTPS-only bulk source.

Shape:
  1. discover(): scrape the category index pages on driveroff.net for direct
     `soft.samlab.ws/.../*.7z` links (HTTPS). The directory listing itself is
     403, so enumeration comes from the HTML index, not a dir walk.
  2. acquire(): a thread pool downloads each `.7z` (HTTPS, 7z-magic validated by
     `_common.download`), 7-Zip extracts it, and `collect_sys_files` harvests
     drivers by content (IMAGE_SUBSYSTEM_NATIVE, so suffix-less payloads are
     caught too). Each package folder is pruned right after, so peak disk stays
     ~one pack per worker. A resume ledger keyed on the `.7z` filename makes runs
     resumable and stops re-downloading packs already processed.

Provenance: rows are marked `samlab-rehost` (third-party re-host, not the
original vendor domain; no catalog (.cat) trust path assumed — authenticity is
left to the L0 gate / DrvEye), mirroring the DriversCollection note.

Environment knobs:
- `PDT_SL_CATEGORIES` (`;`/`,` slugs)  override the category set (default: the
  device-type taxonomy, which avoids the vendor-slug overlap).
- `PDT_SL_JOBS`         (default 6)   parallel download workers.
- `PDT_SL_CRAWL_JOBS`   (default 4)   parallel category crawlers.
- `PDT_SL_PAGE_MAX`     (default 10)  max index pages to follow per category.
- `PDT_SL_MAX_MB`       (default 400) per-package size cap (skips the giant GPU
  packs by default; raise it to include them).
- `PDT_SL_MAX_PACKS`    (default 0 = unlimited) cap total packs this run.
- `PDT_SL_REFRESH=1`    ignore the resume ledger and re-process.
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

BASE = "https://driveroff.net"
# Direct per-release archives live here; the endswith('.'+host) rule in
# _common._host_allowed lets "samlab.ws" cover "soft.samlab.ws".
RX_7Z = re.compile(r'https://soft\.samlab\.ws/drivers/[^\s"\'<>]+\.7z', re.I)

# Device-type taxonomy (not the vendor slugs, which overlap these). Broad by
# default for raw quantity; override with PDT_SL_CATEGORIES.
DEFAULT_CATEGORIES = [
    "chipset", "cpu", "massstorage", "lan", "wifi", "bluetooth", "sound",
    "video", "cardreader", "usb", "inputdev", "tvtuner", "webcamera", "modem",
    "printer", "scaner", "monitor", "phone", "other",
]


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


class SamLabCollector(Collector):
    name = "samlab"
    role = "DriverOff.net / SamLab (direct-HTTPS .7z driver-release archive)"
    allowed_hosts = ["driveroff.net", "samlab.ws"]

    def __init__(
        self,
        categories: list[str] | None = None,
        *,
        jobs: int | None = None,
        crawl_jobs: int | None = None,
        page_max: int | None = None,
        max_mb: int | None = None,
        max_packs: int | None = None,
    ) -> None:
        self.categories = categories or _env_list("PDT_SL_CATEGORIES") or list(DEFAULT_CATEGORIES)
        self.jobs = jobs or _env_int("PDT_SL_JOBS", 6)
        self.crawl_jobs = crawl_jobs or _env_int("PDT_SL_CRAWL_JOBS", 4)
        self.page_max = page_max or _env_int("PDT_SL_PAGE_MAX", 10)
        self.max_mb = max_mb or _env_int("PDT_SL_MAX_MB", 400)
        self.max_packs = max_packs if max_packs is not None else _env_int("PDT_SL_MAX_PACKS", 0)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()

    # ----- discovery (scrape the HTML index for direct .7z links) -----

    def _get_text(self, url: str, timeout: int = 30) -> str:
        req = Request(url, headers={"User-Agent": C.UA})
        with urlopen(req, timeout=timeout) as r:
            # driveroff.net serves windows-1251; the .7z URLs are ASCII, so a
            # lenient decode is enough to regex them out.
            return r.read(4 << 20).decode("latin-1", "replace")

    def _crawl_category(self, slug: str) -> set[str]:
        """Walk up to page_max index pages of one category, collecting .7z URLs."""
        base = f"{BASE}/category/{slug}/"
        rx_page = re.compile(
            re.escape(f"/category/{slug}/") + r'(?:page/\d+/|index\d+\.html)', re.I)
        to_visit = [base]
        seen_pages: set[str] = set()
        packs: set[str] = set()
        while to_visit and len(seen_pages) < self.page_max:
            url = to_visit.pop(0)
            if url in seen_pages:
                continue
            seen_pages.add(url)
            try:
                html = self._get_text(url)
            except Exception:
                continue
            packs.update(RX_7Z.findall(html))
            for frag in rx_page.findall(html):
                nxt = BASE + frag if frag.startswith("/") else f"{BASE}/category/{slug}/{frag}"
                if nxt not in seen_pages:
                    to_visit.append(nxt)
        return packs

    def discover(self) -> dict:
        progress.report("enumerating .7z links from driveroff.net")
        packs: set[str] = set()
        with ThreadPoolExecutor(max_workers=min(self.crawl_jobs, len(self.categories))) as pool:
            for got in pool.map(self._crawl_category, self.categories):
                packs.update(got)
        # the home page carries the newest releases across all categories
        try:
            packs.update(RX_7Z.findall(self._get_text(f"{BASE}/")))
        except Exception:
            pass
        urls = sorted(packs)
        if self.max_packs:
            urls = urls[: self.max_packs]
        self._pack_urls = urls
        progress.report(f"discovered {len(urls)} package(s)")
        return {
            "discovery_page": f"{BASE}/",
            "installer_url": None,  # many packages; real URLs are per-row provenance
            "categories": self.categories,
            "jobs": self.jobs,
            "page_max": self.page_max,
            "max_mb": self.max_mb,
            "packages_found": len(urls),
        }

    # ----- acquisition (thread pool: download -> extract -> harvest -> prune) -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_SL_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        urls = getattr(self, "_pack_urls", [])

        rows: list[dict] = []
        errors: list[dict] = []
        downloads: list[dict] = []
        stats = {"found": len(urls), "attempted": 0, "packages": 0, "sys": 0,
                 "no_sys": 0, "skipped_seen": 0, "failed": 0}

        # bridge the thread-local progress channel into the pool's worker threads
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
            got, rec = self._fetch_pack(work_dir, url, name)
            if got is None:  # transient failure: leave off ledger so it retries
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
            if got:
                progress.add_count(len(got))
            # `ok` even with zero .sys: the pack is deterministic (often INF-only),
            # so record it permanent to avoid re-downloading it every run.
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

    def _fetch_pack(self, work_dir: Path, url: str, name: str):
        """Download + extract + harvest one pack. Returns (rows, rec) on success,
        or (None, error_message) on a transient failure."""
        folder = work_dir / "packages" / Path(name).stem
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
            # scan the whole folder (pack + extraction tree): some releases ship
            # the driver as the archive payload itself; collect_sys_files detects
            # drivers by content (native subsystem), not just by .sys suffix.
            got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        for r in got:
            r["provenance"] = {
                "source_kind": "samlab-rehost",
                "aggregator": "driveroff.net / soft.samlab.ws",
                "trust_note": ("third-party re-host, not the original vendor domain; "
                               "no catalog (.cat) trust path assumed — authenticity "
                               "left to the L0 gate / DrvEye"),
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


def collector() -> SamLabCollector:
    return SamLabCollector()
