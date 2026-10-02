"""Dell — downloads.dell.com Update-Package (DUP) catalog collector.

Dell publishes a single authoritative catalog — `catalog/CatalogPC.cab` — that
lists metadata for EVERY Dell Update Package on downloads.dell.com: thousands of
individually-sized, individually-downloadable, signed driver packages served over
a fast HTTPS CDN with no login and no JS challenge. That makes it a deep, clean,
first-party OEM source.

Shape:
  1. discover(): download `CatalogPC.cab` (cached across runs), 7-Zip it to the
     utf-16 `CatalogPC.xml`, and parse every `<SoftwareComponent>` whose
     `<ComponentType value="DRVR">` sits in a .sys-dense `<Category>`. Each entry
     carries path/size/dateTime; the download URL is downloads.dell.com + path.
     Entries are sorted OLDEST-FIRST: older DUPs ship as an appended-archive
     self-extractor that 7-Zip (or a zipfile fallback) opens directly, whereas
     newer "DUPFramework" wrappers need the installer executed — which this
     static pipeline never does.
  2. acquire(): a thread pool downloads each DUP `.exe` (HTTPS, PE-magic
     validated, host-pinned to downloads.dell.com), extracts it two ways (7z,
     then a zipfile fallback for appended-ZIP SFX that 7z's PE handler shadows),
     and `collect_sys_files` harvests drivers by content. Each DUP folder is
     pruned right after; a resume ledger keyed on the DUP path makes runs
     resumable. DUPs that yield no `.sys` (DUPFramework wrappers) are recorded
     `no_sys` so they are not re-downloaded.

Provenance: rows are marked `dell-oem-catalog` (first-party vendor catalog; the
DUP is signed, but no detached `.cat` trust path is re-verified here —
authenticity is left to the L0 gate / DrvEye).

Environment knobs:
- `PDT_DELL_CATEGORIES` (`;`/`,` codes)  override the Dell category set (default:
  CS/NI/SG/SA/SE/IN/AU/CM — chipset, network, storage, SAS, input, audio, comms).
- `PDT_DELL_JOBS`         (default 6)   parallel download workers.
- `PDT_DELL_MAX_MB`       (default 25)  per-DUP size cap.
- `PDT_DELL_MAX_PACKS`    (default 0 = unlimited) cap total DUPs this run.
- `PDT_DELL_CATALOG_DAYS` (default 7)   re-download the catalog if older than this.
- `PDT_DELL_REFRESH=1`    ignore the resume ledger and re-process.
"""
from __future__ import annotations
import json
import os
import re
import shutil
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import config
from .. import progress
from .base import Collector
from . import _common as C

BASE = "https://downloads.dell.com/"
CATALOG = BASE + "catalog/CatalogPC.cab"

# Dell <Category value=...> codes that are .sys-dense (chipset, network, storage,
# SAS-RAID, SATA, input, audio, communications). Others (video/BIOS/firmware and
# the generic "software component" wrappers) are sparse or non-extractable.
DEFAULT_CATEGORIES = {"CS", "NI", "SG", "SA", "SE", "IN", "AU", "CM"}

RX_COMP = re.compile(r'<SoftwareComponent\b[^>]*\bpath="([^"]+)"[^>]*?'
                     r'\bdateTime="([^"]+)"[^>]*?\bsize="(\d+)"(.*?)</SoftwareComponent>',
                     re.I | re.S)
RX_DRVR = re.compile(r'<ComponentType value="DRVR"', re.I)
RX_CAT = re.compile(r'<Category value="([^"]+)"', re.I)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_set(name: str) -> set[str] | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    out = {s.strip().upper() for s in re.split(r"[;,]", raw) if s.strip()}
    return out or None


class DellCollector(Collector):
    name = "dell"
    role = "Dell (downloads.dell.com Update-Package driver catalog)"
    allowed_hosts = ["downloads.dell.com"]

    def __init__(
        self,
        categories: set[str] | None = None,
        *,
        jobs: int | None = None,
        max_mb: int | None = None,
        max_packs: int | None = None,
        catalog_days: int | None = None,
    ) -> None:
        self.categories = categories or _env_set("PDT_DELL_CATEGORIES") or set(DEFAULT_CATEGORIES)
        self.jobs = jobs or _env_int("PDT_DELL_JOBS", 6)
        self.max_mb = max_mb or _env_int("PDT_DELL_MAX_MB", 25)
        self.max_packs = max_packs if max_packs is not None else _env_int("PDT_DELL_MAX_PACKS", 0)
        self.catalog_days = catalog_days or _env_int("PDT_DELL_CATALOG_DAYS", 7)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._units: list[dict] = []

    # ----- discovery (fetch catalog -> parse DRVR components) -----

    def _catalog_xml(self) -> Path:
        cat_dir = config.collectors_dir() / self.name / "_catalog"
        cat_dir.mkdir(parents=True, exist_ok=True)
        cab = cat_dir / "CatalogPC.cab"
        fresh = (cab.exists() and cab.stat().st_size > 1_000_000 and
                 (time.time() - cab.stat().st_mtime) < self.catalog_days * 86400)
        if not fresh:
            progress.report("downloading Dell CatalogPC.cab")
            C.download(CATALOG, cab, self.allowed_hosts, max_mb=200, timeout=180)
        xml_dir = cat_dir / "xml"
        shutil.rmtree(xml_dir, ignore_errors=True)
        progress.report("extracting CatalogPC.xml")
        C.extract(cab, xml_dir)
        xmls = sorted(xml_dir.glob("*.xml"))
        if not xmls:
            raise RuntimeError("no XML inside CatalogPC.cab")
        return xmls[0]

    def discover(self) -> dict:
        xml = self._catalog_xml()
        data = xml.read_text(encoding="utf-16", errors="replace")
        units: list[dict] = []
        total = 0
        for m in RX_COMP.finditer(data):
            path, dt, size, body = m.group(1), m.group(2), int(m.group(3)), m.group(4)
            if not RX_DRVR.search(body):
                continue
            total += 1
            cat_m = RX_CAT.search(body)
            cat = cat_m.group(1) if cat_m else "?"
            if cat not in self.categories or size > self.max_mb << 20:
                continue
            rel = path.replace("\\", "/")
            units.append({"url": BASE + rel, "key": rel, "size": size,
                          "dt": dt, "cat": cat, "name": rel.rsplit("/", 1)[-1]})
        # oldest first: the appended-archive SFX generation extracts statically
        units.sort(key=lambda u: u["dt"])
        if self.max_packs:
            units = units[: self.max_packs]
        self._units = units
        progress.report(f"discovered {len(units)} DUP(s) of {total} DRVR components")
        return {
            "discovery_page": CATALOG,
            "installer_url": None,
            "categories": sorted(self.categories),
            "drvr_components_total": total,
            "jobs": self.jobs,
            "max_mb": self.max_mb,
            "packs_found": len(units),
        }

    # ----- acquisition (thread pool: download -> extract -> harvest -> prune) -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_DELL_REFRESH", "") not in ("", "0", "false")
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
                    errors.append({"pack": unit["name"], "url": unit["url"], "error": rec})
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
            # `ok` even with zero .sys: a DUPFramework wrapper is deterministic,
            # so record it permanent to avoid re-downloading it every run.
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
        """Download + extract + harvest one DUP. Returns (rows, rec) on success,
        or (None, error_message) on a transient failure."""
        url, name = unit["url"], unit["name"]
        folder = work_dir / "packages" / Path(name).stem
        pkg = folder / name
        progress.report(f"DUP: {name[:44]}")
        try:
            rec = C.download(url, pkg, self.allowed_hosts, max_mb=self.max_mb,
                             timeout=180, referer=BASE)
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        try:
            # (a) 7-Zip handles appended CAB/ZIP SFX DUPs
            extracted = folder / "extracted"
            C.extract(pkg, extracted)
            # (b) zipfile fallback: an appended-ZIP SFX whose PE stub 7z's handler
            # extracts instead of the payload — locate the ZIP by its EOCD.
            self._zip_fallback(pkg, folder / "zipped")
            got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
            tries = 0
            while not got and tries < 2:
                # some DUPs wrap the payload in an inner CAB/MSI the first 7z
                # pass only unpacks one layer of.
                if not C.extract_nested(extracted):
                    break
                got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
                tries += 1
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        for r in got:
            r["provenance"] = {
                "source_kind": "dell-oem-catalog",
                "aggregator": "downloads.dell.com (Dell Update Package catalog)",
                "trust_note": ("first-party OEM vendor catalog; the DUP is signed, "
                               "but no detached .cat trust path is re-verified here "
                               "— authenticity left to the L0 gate / DrvEye"),
                "dup_path": unit["key"],
                "category": unit["cat"],
                "release_date": unit["dt"],
                "package_name": name,
                "package_url": url,
                "package_final_url": rec["final_url"],
                "package_sha256": rec["sha256"],
                "package_size": rec["size"],
            }
        C.prune_dir(folder)
        return got, rec

    @staticmethod
    def _zip_fallback(pkg: Path, dest: Path) -> None:
        """Best-effort: extract .sys members if the DUP is a ZIP-appended SFX."""
        try:
            with zipfile.ZipFile(pkg) as z:
                members = [n for n in z.namelist() if n.lower().endswith(".sys")]
                if not members:
                    return
                dest.mkdir(parents=True, exist_ok=True)
                for n in members:
                    tgt = dest / Path(n).name
                    with z.open(n) as src, tgt.open("wb") as out:
                        shutil.copyfileobj(src, out)
        except Exception:
            pass

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
                    "category": unit["cat"],
                    "url": unit["url"],
                    "status": status,
                    "sys": sys_shas,
                    "ts": C.utc_now(),
                }, ensure_ascii=False) + "\n")


def collector() -> DellCollector:
    return DellCollector()
