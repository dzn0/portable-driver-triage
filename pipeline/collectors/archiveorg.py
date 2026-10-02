"""Internet Archive — driver-pack ISO/ZIP mirror, inner `.7z` sub-pack collector.

The Internet Archive mirrors the big driver-pack distributions (DriverPack
Solution, SamDrivers, DP_Offline, …) as `software` items, each an ISO/ZIP whose
inner files the Archive serves **individually** over its CDN. That makes it the
project's deepest clean-HTTPS source: enumerable at every level, no login, fast,
and with inner-file sizes visible up front so the giant GPU packs can be skipped
and the dense small category packs (chipset / LAN / mass-storage / sound / …)
pulled first.

Shape:
  1. discover(): advancedsearch.php enumerates driver-pack items; for each item
     metadata.php resolves its ISO/ZIP container; the Archive's auto-generated
     container listing (`/download/<id>/<container>/`) yields a direct HTTPS URL
     and size for every inner `.7z`. Giant / GPU / fixture entries are filtered
     out; the rest become the work units.
  2. acquire(): a thread pool downloads each inner `.7z` (HTTPS, 7z-magic
     validated by `_common.download`, host-pinned to *.archive.org), 7-Zip
     extracts it, and `collect_sys_files` harvests drivers by content
     (IMAGE_SUBSYSTEM_NATIVE, so suffix-less payloads are caught too). Each unit
     folder is pruned right after; a resume ledger keyed on the item+inner path
     makes runs resumable and stops re-downloading packs already processed.

Provenance: rows are marked `archive-org-mirror` (community-uploaded re-host, not
the original vendor domain; no catalog (.cat) trust path assumed — authenticity
is left to the L0 gate / DrvEye), mirroring the DriversCollection / SamLab notes.

Environment knobs:
- `PDT_AO_QUERIES`   (`;`/`,` terms)  override the search terms (default: the
  driver-pack distribution names).
- `PDT_AO_ITEMS`     (default 8)   max items to scan per query.
- `PDT_AO_JOBS`      (default 6)   parallel download workers.
- `PDT_AO_CRAWL_JOBS`(default 4)   parallel item-listing crawlers.
- `PDT_AO_MAX_MB`    (default 120) per inner-pack size cap (skips the giant GPU
  packs by default; raise it to include them).
- `PDT_AO_MAX_PACKS` (default 0 = unlimited) cap total inner packs this run.
- `PDT_AO_REFRESH=1` ignore the resume ledger and re-process.
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

BASE = "https://archive.org"
ADV = BASE + "/advancedsearch.php"

# Driver-pack distributions mirrored on the Archive as `software` items.
DEFAULT_QUERIES = ["driverpack", "samdrivers", "snappy driver installer",
                   "driver pack solution", "DP_Offline"]

# .sys-dense, small categories worth pulling first; the rest (video/gpu/printer)
# are huge and sparse in distinct kernel drivers.
GOOD = re.compile(r"(chipset|lan|massstorage|mass_storage|cardreader|card_reader|"
                  r"bluetooth|xusb|usb|modem|monitor|wlan|wifi|network|misc|sound|"
                  r"telephone|biometric|hid|input|touchpad)", re.I)
BAD = re.compile(r"(video|nvidia|_amd|radeon|geforce|graphic|printer)", re.I)
# fixtures / tooling bundled inside some ISOs that are not real driver packs
JUNK = re.compile(r"(node_modules|/test/|/tests/|sample|blank|example|/catalog/)", re.I)
RX_INNER = re.compile(r'href="(\/\/[^"]+?\.7z)"', re.I)
RX_ORIG = re.compile(r'"name":"([^"]+\.(?:iso|zip|7z))"[^}]*?"source":"original"', re.I)
RX_ANY = re.compile(r'"name":"([^"]+\.(?:iso|zip|7z))"', re.I)


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


def _base_name(url: str) -> str:
    """Clean inner-pack basename from a (possibly %2F-encoded) href."""
    return Path(urllib.parse.unquote(url)).name


class ArchiveOrgCollector(Collector):
    name = "archiveorg"
    role = "Internet Archive (driver-pack ISO/ZIP mirror, inner .7z sub-packs)"
    allowed_hosts = ["archive.org"]  # covers the ia*/dn* CDN nodes (*.archive.org)

    def __init__(
        self,
        queries: list[str] | None = None,
        *,
        items: int | None = None,
        jobs: int | None = None,
        crawl_jobs: int | None = None,
        max_mb: int | None = None,
        max_packs: int | None = None,
    ) -> None:
        self.queries = queries or _env_list("PDT_AO_QUERIES") or list(DEFAULT_QUERIES)
        self.items = items or _env_int("PDT_AO_ITEMS", 8)
        self.jobs = jobs or _env_int("PDT_AO_JOBS", 6)
        self.crawl_jobs = crawl_jobs or _env_int("PDT_AO_CRAWL_JOBS", 4)
        self.max_mb = max_mb or _env_int("PDT_AO_MAX_MB", 120)
        self.max_packs = max_packs if max_packs is not None else _env_int("PDT_AO_MAX_PACKS", 0)
        self._lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._units: list[dict] = []

    # ----- discovery (search -> item container -> inner .7z listing) -----

    def _get_text(self, url: str, timeout: int = 40) -> str:
        req = Request(url, headers={"User-Agent": C.UA})
        with urlopen(req, timeout=timeout) as r:
            return r.read(8 << 20).decode("utf-8", "replace")

    def _search(self, query: str) -> list[str]:
        u = (ADV + "?q=" +
             urllib.parse.quote(f"{query} AND mediatype:software") +
             "&fl[]=identifier&sort[]=downloads+desc&rows=" + str(self.items * 3) +
             "&output=json")
        try:
            data = self._get_text(u)
        except Exception:
            return []
        return list(dict.fromkeys(re.findall(r'"identifier":"([^"]+)"', data)))[: self.items]

    def _item_container(self, identifier: str) -> str | None:
        """Resolve an item's primary ISO/ZIP/7z container filename."""
        try:
            meta = self._get_text(f"{BASE}/metadata/{identifier}")
        except Exception:
            return None
        m = RX_ORIG.search(meta) or RX_ANY.search(meta)
        return m.group(1) if m else None

    def _list_inner(self, identifier: str, container: str) -> list[dict]:
        """Return the item's inner .7z packs as unit dicts (url, size, name, key).

        Sizes come straight from the Archive's container listing (the last
        numeric cell per row); its inner-file endpoint ignores Range, so a
        HEAD/Range probe would be useless.
        """
        listing = (f"{BASE}/download/{identifier}/" +
                   urllib.parse.quote(container) + "/")
        try:
            html = self._get_text(listing)
        except Exception:
            return []
        units: list[dict] = []
        seen: set[str] = set()
        for row in html.split("<tr")[1:]:
            m = RX_INNER.search(row)
            if not m:
                continue
            url = "https:" + m.group(1)
            if url in seen:
                continue
            seen.add(url)
            name = _base_name(url)
            if JUNK.search(urllib.parse.unquote(url)) or BAD.search(name):
                continue
            if not GOOD.search(name):
                continue
            nums = re.findall(r">(\d{3,})<", row)
            size = int(nums[-1]) if nums else 0
            if size and size > self.max_mb * (1 << 20):
                continue  # skip the giant packs up front (download guard is the backstop)
            # stable resume key: item + inner path (basenames repeat across ISOs)
            key = urllib.parse.unquote(urllib.parse.urlparse(url).path)
            units.append({"url": url, "size": size, "name": name,
                          "key": key, "item": identifier, "container": container})
        return units

    def discover(self) -> dict:
        progress.report("searching archive.org for driver-pack items")
        identifiers: list[str] = []
        seen_ids: set[str] = set()
        for q in self.queries:
            for ident in self._search(q):
                if ident not in seen_ids:
                    seen_ids.add(ident)
                    identifiers.append(ident)

        progress.report(f"listing inner packs of {len(identifiers)} item(s)")
        units: list[dict] = []
        seen_keys: set[str] = set()

        def expand(identifier: str) -> list[dict]:
            cont = self._item_container(identifier)
            return self._list_inner(identifier, cont) if cont else []

        workers = max(1, min(self.crawl_jobs, len(identifiers) or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for got in pool.map(expand, identifiers):
                for unit in got:
                    if unit["key"] in seen_keys:
                        continue
                    seen_keys.add(unit["key"])
                    units.append(unit)

        # smallest first: dense category packs before anything bulky
        units.sort(key=lambda u: u["size"] or 1 << 62)
        if self.max_packs:
            units = units[: self.max_packs]
        self._units = units
        progress.report(f"discovered {len(units)} inner pack(s)")
        return {
            "discovery_page": f"{BASE}/search?query=driverpack",
            "installer_url": None,  # many packs; real URLs are per-row provenance
            "queries": self.queries,
            "items_scanned": len(identifiers),
            "jobs": self.jobs,
            "max_mb": self.max_mb,
            "packs_found": len(units),
        }

    # ----- acquisition (thread pool: download -> extract -> harvest -> prune) -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_AO_REFRESH", "") not in ("", "0", "false")
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
            # Live count is driven by collect_sys_files, which reports only
            # drivers NEW to the content-addressed corpus — counting len(got)
            # here too would double-count and re-inflate with pre-dedup rows.
            # `ok` even with zero .sys: the pack is deterministic (INF-only packs
            # exist), so record it permanent to avoid re-downloading every run.
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
        """Download + extract + harvest one inner pack. Returns (rows, rec) on
        success, or (None, error_message) on a transient failure."""
        url, name = unit["url"], unit["name"]
        # namespace the work folder by item so identically-named packs
        # (DP_Chipset across ISOs) do not collide on disk
        folder = work_dir / "packages" / (unit["item"] + "__" + Path(name).stem)
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
            # scan the whole folder (pack + extraction tree): collect_sys_files
            # detects drivers by content (native subsystem), not just .sys suffix.
            got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
        except Exception as exc:
            C.prune_dir(folder)
            return None, str(exc)
        for r in got:
            r["provenance"] = {
                "source_kind": "archive-org-mirror",
                "aggregator": "archive.org (Internet Archive)",
                "trust_note": ("community-uploaded driver-pack mirror, not the "
                               "original vendor domain; no catalog (.cat) trust "
                               "path assumed — authenticity left to the L0 gate / "
                               "DrvEye"),
                "item_identifier": unit["item"],
                "container": unit["container"],
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

    def _record(self, unit: dict, sys_shas: list[str], *, status: str) -> None:
        p = self._ledger_path()
        with self._ledger_lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "key": unit["key"],
                    "pack": unit["name"],
                    "item": unit["item"],
                    "url": unit["url"],
                    "status": status,
                    "sys": sys_shas,
                    "ts": C.utc_now(),
                }, ensure_ascii=False) + "\n")


def collector() -> ArchiveOrgCollector:
    return ArchiveOrgCollector()
