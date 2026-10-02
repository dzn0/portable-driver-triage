"""RW-Everything — embedded-PE driver collector (RwDrv.sys).

RW-Everything is a low-level hardware read/write utility whose signed kernel
driver `RwDrv.sys` is a textbook BYOVD primitive (arbitrary port / PCI / MSR /
physical-memory access). The distribution ZIPs carry the driver **embedded inside
the `Rw.exe` application binary** (two native PEs — x64 + x86 — concatenated in a
resource blob), not as a standalone file, so plain extraction recovers nothing;
the driver is recovered by byte-carving the app binary
(`_common.collect_carved_drivers`).

Shape:
  1. discover(): scrape rweverything.com/downloads/ for the release ZIP links.
  2. acquire(): a thread pool downloads each ZIP (HTTPS, magic-validated), 7-Zip
     extracts it to reach `Rw.exe`, then `collect_carved_drivers` carves the
     embedded native-subsystem driver PEs and dedups them into the store. A
     resume ledger keyed on the ZIP filename makes runs resumable.

Provenance: rows are marked `rweverything-embedded` (official vendor host; driver
carved from the app binary, no detached `.cat` — authenticity left to the L0 gate
/ DrvEye).

Environment knobs:
- `PDT_RWE_JOBS`      (default 4)   parallel download workers.
- `PDT_RWE_MAX_MB`    (default 40)  per-ZIP size cap.
- `PDT_RWE_MAX_PACKS` (default 0 = unlimited) cap total ZIPs this run.
- `PDT_RWE_REFRESH=1` ignore the resume ledger and re-process.
"""
from __future__ import annotations
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from .. import config
from .. import progress
from .base import Collector
from . import _common as C

BASE = "https://rweverything.com"
DOWNLOADS = BASE + "/downloads/"
RX_ZIP = re.compile(r'href="([^"]+\.zip)"', re.I)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


class RwEverythingCollector(Collector):
    name = "rweverything"
    role = "RW-Everything (RwDrv.sys carved from the app-EXE binary)"
    allowed_hosts = ["rweverything.com"]

    def __init__(
        self,
        *,
        jobs: int | None = None,
        max_mb: int | None = None,
        max_packs: int | None = None,
    ) -> None:
        self.jobs = jobs or _env_int("PDT_RWE_JOBS", 4)
        self.max_mb = max_mb or _env_int("PDT_RWE_MAX_MB", 40)
        self.max_packs = max_packs if max_packs is not None else _env_int("PDT_RWE_MAX_PACKS", 0)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._urls: list[str] = []

    # ----- discovery -----

    def _get_text(self, url: str, timeout: int = 30) -> str:
        req = Request(url, headers={"User-Agent": C.UA})
        with urlopen(req, timeout=timeout) as r:
            return r.read(4 << 20).decode("utf-8", "replace")

    def discover(self) -> dict:
        progress.report("enumerating RW-Everything release ZIPs")
        urls: set[str] = set()
        try:
            html = self._get_text(DOWNLOADS)
            for href in RX_ZIP.findall(html):
                full = urljoin(DOWNLOADS, href)
                if urlparse(full).scheme == "https":
                    urls.add(full)
        except Exception:
            pass
        ordered = sorted(urls)
        if self.max_packs:
            ordered = ordered[: self.max_packs]
        self._urls = ordered
        progress.report(f"discovered {len(ordered)} release ZIP(s)")
        return {
            "discovery_page": DOWNLOADS,
            "installer_url": None,
            "jobs": self.jobs,
            "max_mb": self.max_mb,
            "packs_found": len(ordered),
        }

    # ----- acquisition -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_RWE_REFRESH", "") not in ("", "0", "false")
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
                             timeout=120, referer=DOWNLOADS)
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        extracted = folder / "extracted"
        try:
            C.extract(pkg, extracted)
            # RwDrv.sys is embedded inside Rw.exe (concatenated native PEs), not a
            # standalone .sys — carve it out of the app binary.
            got = C.collect_carved_drivers(extracted, config.drivers_dir())
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        for r in got:
            r["provenance"] = {
                "source_kind": "rweverything-embedded",
                "aggregator": "rweverything.com (official)",
                "trust_note": ("official vendor host; driver carved from the app "
                               "binary, no detached .cat — authenticity left to "
                               "the L0 gate / DrvEye"),
                "package_name": name,
                "package_url": url,
                "package_final_url": rec["final_url"],
                "package_sha256": rec["sha256"],
                "package_size": rec["size"],
            }
        C.prune_dir(folder)
        return got, rec

    # ----- resume ledger -----

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


def collector() -> RwEverythingCollector:
    return RwEverythingCollector()
