"""DriversCollection.com — concurrent enumerating collector (pure HTTP).

A second scalable source, complementary to the Microsoft Update Catalog. Where
the MS catalog is an *official* index whose download host is the vendor itself,
DriversCollection.com is a large third-party **aggregator** (≈6.7M files, 565
manufacturers) that *re-hosts* driver packages gathered from many upstreams. It
is valuable for sheer breadth — raw driver-corpus volume — and for the long tail
of consumer hardware the official catalog never carried. Its provenance is
weaker, so every row it produces is marked accordingly (see `_fetch_package`)
and authenticity policy is left to the L0 gate / DrvEye, as for every source.

Navigation is deterministic (no search needed); the whole site is a hardware
taxonomy reachable by URL, and — crucially — every listing page is plain
server-rendered HTML and the real file URL is fetchable over ordinary HTTPS, so
this collector needs **no browser** at all (unlike the MS-catalog one). That is
what lets it run *concurrently*: urllib + a per-thread cookie jar are
thread-safe, so a pool of workers crawls and downloads in parallel. Throughput,
not politeness-to-a-fault, is the goal here — the objective for this source is
raw quantity.

    ?C=<catId>                     -> vendors in that category: ?V=<vendor>&S=<catId>
    ?V=<vendor>&S=<catId>[&hpage=N]-> devices: ?H=<hw>&By=<vendor>
    ?H=<hw>&By=<vendor>            -> landings: /_<ff>/Download-...  (or ?file_cid=<ff>)
    POST download=1&ff=<ff>        -> "preparing" page whose inline CheckBundle()
                                      JS embeds the real URLs:
                                        l0        = clean default file  (dN.  host)
                                        l1..l3    = opt-in adware *bundles* (dNb. host)

`<ff>` is exactly the hex token in the `/_<ff>/` landing URL (also `?file_cid=`),
so a landing's download token is known without loading the landing page. We take
**l0** only, never the bundles. The l0 host rotates across storage nodes
(`d2`, `d4`, `d4b`, …); some of these have no public DNS and are unreachable by
*any* client (browser included), so a download whose host does not resolve is
skipped and recorded rather than retried forever.

Concurrency & scale levers (env; `collect` needs no new CLI beyond `--scope`):

- `PDT_DC_JOBS`            (default 8)  parallel download workers.
- `PDT_DC_CRAWL_JOBS`      (default 4)  parallel category crawlers.
- `PDT_DC_CATEGORIES`      (`;`/`,` ids) overrides the category set outright.
- `PDT_DC_MAX_DRIVERS_PER_CAT` (default 0 = unlimited) cap per category.
- `PDT_DC_MAX_VENDORS_PER_CAT` (default 0 = unlimited).
- `PDT_DC_MAX_HW_PER_VENDOR`   (default 0 = unlimited).
- `PDT_DC_HPAGE_MAX`           (default 50) device-list pagination safety bound.
- `PDT_DC_MAX_MB`              (default 400) per-package size cap.
- `PDT_DC_DISCOVER_ONLY=1`     resolve l0 URLs without downloading (smoke test).
- `PDT_DC_REFRESH=1`           ignore the resume ledger and re-process.

`--scope` narrows *which hardware categories* are crawled, by matching a scope's
device classes / queries / label against this site's category taxonomy
(`CATEGORY_IDS`). A free-text `--scope mouse` matches the `Mouse` category; a
pure capability scope (e.g. `msr-access`), which the hardware taxonomy has no
column for, resolves to nothing here and the broad default set is used.
"""
from __future__ import annotations
import html
import json
import os
import re
import socket
import threading
import time
from http.cookiejar import CookieJar
from pathlib import Path
from queue import Empty, Queue
from urllib.parse import unquote, urlencode, urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener

from .. import config
from .. import progress
from . import _common as C
from .base import Collector

BASE = "https://driverscollection.com"

# Site hardware taxonomy: category name -> ?C= id, harvested from the homepage.
# Stable, slow-changing site structure; used to turn a --scope into category ids.
CATEGORY_IDS: dict[str, int] = {
    "video": 1, "scsi-raid": 2, "sound": 3, "mainboards": 4, "others": 6,
    "scsi": 7, "network": 8, "keyboards": 9, "printers": 10, "modems": 12,
    "irda": 13, "scanners": 14, "monitors": 15, "plotters": 16, "chipset": 17,
    "joysticks": 19, "mouse": 21, "ide-raid": 22, "windows": 23, "tv tuner": 27,
    "bd/dvd/cd": 33, "tape backup": 35, "all-in-one (multifunctional)": 36,
    "video capture": 38, "tablets": 40, "pc camera": 41, "mp3 players": 42,
    "notebooks": 43, "ups": 47, "usb": 48, "projectors": 49, "telephony": 52,
    "fax machines": 53, "print servers": 55, "copiers": 56, "card readers": 57,
    "sata-raid": 58, "digital photo": 66, "ic controllers": 68, "trackballs": 69,
    "gps receivers": 70, "sata": 71, "digital camcorders": 73, "wireless": 74,
    "pda": 75, "digital albums": 76, "barebones": 77, "tablet pc": 78,
    "multimedia players": 79, "controllers": 80, "add-on cards": 81,
    "midi-keyboards": 82, "voice recorders": 84, "server products": 88, "pc": 90,
    "tv": 91, "wearables": 92, "robots": 93,
}

# Broad default = every category. The objective for this aggregator source is
# raw quantity, so collection is deliberately not narrowed; downstream (L0 /
# DrvEye) decides what matters. Ordered kernel-driver-bearing classes first so a
# run that is stopped early still skews toward the interesting binaries.
_HIGH_YIELD_FIRST = [1, 3, 4, 8, 74, 17, 71, 58, 7, 2, 22, 48, 57, 80, 81, 21, 9, 27]
DEFAULT_CATEGORY_IDS = _HIGH_YIELD_FIRST + [
    c for c in sorted(set(CATEGORY_IDS.values())) if c not in _HIGH_YIELD_FIRST
]

# href extraction (single-quoted, &amp;-encoded) at each navigation level.
_RE_VENDOR = re.compile(r"href=['\"]([^'\"]*\?V=[^'\"]*(?:&amp;|&)S=\d+)['\"]", re.I)
_RE_HW = re.compile(r"href=['\"]([^'\"]*\?H=[^'\"]*(?:&amp;|&)By=[^'\"]*)['\"]", re.I)
_RE_LANDING = re.compile(r"href=['\"]([^'\"]*/_[0-9a-f]{6,}/[^'\"]*)['\"]", re.I)
_RE_LANDING_CID = re.compile(r"href=['\"]([^'\"]*\?file_cid=[0-9a-f]+)['\"]", re.I)
_RE_FF_PATH = re.compile(r"/_([0-9a-f]{6,})/", re.I)
_RE_FF_CID = re.compile(r"[?&]file_cid=([0-9a-f]+)", re.I)
# the clean (non-bundle) default link inside the CheckBundle() function
_RE_L0 = re.compile(r"var\s+l0\s*=\s*'([^']+)'")
_RE_L1 = re.compile(r"var\s+l1\s*=\s*'([^']+)'")


class _StopCategory(Exception):
    """Raised by the emit callback to stop crawling a category (cap reached)."""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_ids(name: str) -> list[int] | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    out = [int(p) for p in re.split(r"[;,]", raw) if p.strip().isdigit()]
    return out or None


class DriversCollectionCollector(Collector):
    name = "driverscollection"
    role = "DriversCollection.com (third-party aggregator / re-host — scalable, weaker provenance)"
    # covers driverscollection.com and its dN./dNb. file CDNs via the
    # endswith('.'+h) rule in _common._host_allowed.
    allowed_hosts = ["driverscollection.com"]

    def __init__(
        self,
        category_ids: list[int] | None = None,
        *,
        jobs: int | None = None,
        crawl_jobs: int | None = None,
        max_vendors_per_cat: int | None = None,
        max_hw_per_vendor: int | None = None,
        max_drivers_per_cat: int | None = None,
        hpage_max: int | None = None,
        max_mb: int | None = None,
        discover_only: bool | None = None,
        scope_label: str | None = None,
    ) -> None:
        self.category_ids = category_ids or _env_ids("PDT_DC_CATEGORIES") or list(DEFAULT_CATEGORY_IDS)
        # Modest download concurrency by default: the bottleneck is the
        # aggregator's rate limit, not local parallelism, and global pacing
        # (_pace) caps the aggregate request rate regardless of worker count.
        # More workers mainly overlap crawl/extract with download waits.
        self.jobs = jobs or _env_int("PDT_DC_JOBS", 4)
        self.crawl_jobs = crawl_jobs or _env_int("PDT_DC_CRAWL_JOBS", 3)
        # 0 == unlimited (the raw-quantity default).
        self.max_vendors_per_cat = max_vendors_per_cat if max_vendors_per_cat is not None else _env_int("PDT_DC_MAX_VENDORS_PER_CAT", 0)
        self.max_hw_per_vendor = max_hw_per_vendor if max_hw_per_vendor is not None else _env_int("PDT_DC_MAX_HW_PER_VENDOR", 0)
        self.max_drivers_per_cat = max_drivers_per_cat if max_drivers_per_cat is not None else _env_int("PDT_DC_MAX_DRIVERS_PER_CAT", 0)
        self.hpage_max = hpage_max or _env_int("PDT_DC_HPAGE_MAX", 50)
        self.max_mb = max_mb or _env_int("PDT_DC_MAX_MB", 400)
        self.discover_only = (
            discover_only if discover_only is not None
            else os.environ.get("PDT_DC_DISCOVER_ONLY", "") not in ("", "0", "false"))
        self.scope_label = scope_label
        # adaptive rate control (AIMD): the aggregator stops serving download
        # links under sustained load and returns the landing page instead. We
        # pace download attempts and widen the delay on each throttle, shrink it
        # on success, and give the whole run up after a sustained throttle streak
        # so it can be resumed later (the ledger preserves progress).
        self.min_delay = float(os.environ.get("PDT_DC_MIN_DELAY", "0.5"))
        self.max_delay = float(os.environ.get("PDT_DC_MAX_DELAY", "20"))
        self.throttle_giveup = _env_int("PDT_DC_THROTTLE_GIVEUP", 15)
        self._delay = self.min_delay
        self._throttle_streak = 0
        self._stop = threading.Event()
        # concurrency state (set/used in acquire)
        self._lock = threading.Lock()
        self._pace_lock = threading.Lock()
        self._ledger_lock = threading.Lock()
        self._dns_lock = threading.Lock()
        self._dns_cache: dict[str, bool] = {}

    # ----- discovery -----

    def discover(self) -> dict:
        names = {v: k for k, v in CATEGORY_IDS.items()}
        return {
            "discovery_page": f"{BASE}/",
            "installer_url": None,  # many packages; real URLs are per-row provenance
            "search_scope": self.scope_label or "broad (default: all categories)",
            "categories": [{"id": i, "name": names.get(i, "?")} for i in self.category_ids],
            "jobs": self.jobs,
            "crawl_jobs": self.crawl_jobs,
            "caps": {"vendors_per_cat": self.max_vendors_per_cat or "unlimited",
                     "hw_per_vendor": self.max_hw_per_vendor or "unlimited",
                     "drivers_per_cat": self.max_drivers_per_cat or "unlimited"},
            "discover_only": self.discover_only,
        }

    # ----- acquisition -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        refresh = os.environ.get("PDT_DC_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        ledger_start = len(processed)

        rows: list[dict] = []
        errors: list[dict] = []
        downloads: list[dict] = []
        stats = {"categories": len(self.category_ids), "enqueued": 0, "kept": 0,
                 "packages": 0, "sys": 0, "skipped_seen": 0, "bundles_skipped": 0,
                 "dns_dead": 0, "no_l0": 0, "throttled": 0, "failed": 0}
        self._stop.clear()
        seen_ff: set[str] = set(processed)          # in-run dedup ∪ already-done
        cat_counts: dict[int, int] = {c: 0 for c in self.category_ids}

        # bridge the thread-local progress channel to the worker threads
        rep_fn, cnt_fn = progress.current_reporters()

        def bind_progress() -> None:
            progress.set_reporter(rep_fn)
            progress.set_count_reporter(cnt_fn)

        landing_q: Queue = Queue(maxsize=self.jobs * 8)
        cat_q: Queue = Queue()
        for cid in self.category_ids:
            cat_q.put(cid)

        def emit(entry: dict) -> None:
            """Enqueue a landing for download. Dedups across threads and enforces
            the per-category cap (raising _StopCategory so the crawler moves on)."""
            if self._stop.is_set():
                raise _StopCategory  # run is winding down (throttled) — stop crawling
            cid = entry["category_id"]
            with self._lock:
                if entry["ff"] in seen_ff:
                    return  # already done or already queued by another crawler
                if self.max_drivers_per_cat and cat_counts[cid] >= self.max_drivers_per_cat:
                    raise _StopCategory
                seen_ff.add(entry["ff"])
                cat_counts[cid] += 1
                stats["enqueued"] += 1
            landing_q.put(entry)  # blocks when full -> natural backpressure

        def crawl_worker() -> None:
            bind_progress()
            opener = _new_opener()
            while True:
                try:
                    cid = cat_q.get_nowait()
                except Empty:
                    return
                try:
                    self._crawl_category(opener, cid, emit)
                except _StopCategory:
                    pass
                except Exception as exc:
                    with self._lock:
                        errors.append({"stage": "crawl", "category": cid, "error": str(exc)})
                finally:
                    cat_q.task_done()

        def download_worker() -> None:
            bind_progress()
            opener = _new_opener()
            while True:
                entry = landing_q.get()
                try:
                    if entry is None:
                        return
                    self._process_entry(opener, work_dir, entry, rows, errors,
                                        downloads, stats)
                finally:
                    landing_q.task_done()

        dls = [threading.Thread(target=download_worker, name=f"dc-dl-{i}", daemon=True)
               for i in range(self.jobs)]
        cws = [threading.Thread(target=crawl_worker, name=f"dc-cw-{i}", daemon=True)
               for i in range(min(self.crawl_jobs, len(self.category_ids)))]
        for t in dls:
            t.start()
        for t in cws:
            t.start()
        for t in cws:          # crawling complete when every category is walked
            t.join()
        for _ in dls:          # then drain the download queue and stop workers
            landing_q.put(None)
        for t in dls:
            t.join()

        info["stats"] = stats
        info["errors"] = errors[:500]
        info["error_count"] = len(errors)
        info["downloads_top"] = downloads
        info["ledger_at_start"] = ledger_start
        info["resumed"] = (not refresh) and stats["skipped_seen"] > 0
        return rows

    # ----- crawl (pure HTTP, one opener per crawler thread) -----

    def _get_text(self, opener, url: str, timeout: int = 30) -> str:
        with opener.open(Request(url, headers={"User-Agent": C.UA}), timeout=timeout) as r:
            return r.read(16 << 20).decode("utf-8", "replace")

    def _crawl_category(self, opener, cat_id: int, emit) -> None:
        names = {v: k for k, v in CATEGORY_IDS.items()}
        cat_name = names.get(cat_id, str(cat_id))
        cat_html = self._get_text(opener, f"{BASE}/?C={cat_id}")
        vendors = [u for u in _dedupe(_abs(h) for h in _RE_VENDOR.findall(cat_html))
                   if _same_site(u)]
        if self.max_vendors_per_cat:
            vendors = vendors[: self.max_vendors_per_cat]
        progress.report(f"{cat_name}: {len(vendors)} vendor(s)")
        seen_ff: set[str] = set()
        for vi, v_url in enumerate(vendors, 1):
            vendor = _param(v_url, "V")
            progress.report(f"{cat_name} [{vi}/{len(vendors)}] {vendor}: devices")
            hw_urls: list[str] = []
            for hpage in range(1, self.hpage_max + 1):
                page_url = v_url if hpage == 1 else f"{v_url}&hpage={hpage}"
                try:
                    v_html = self._get_text(opener, page_url)
                except Exception:
                    break
                page_hw = [u for u in _dedupe(_abs(h) for h in _RE_HW.findall(v_html))
                           if _same_site(u)]
                new = [h for h in page_hw if h not in hw_urls]
                if not new:
                    break  # pagination exhausted
                hw_urls.extend(new)
                if self.max_hw_per_vendor and len(hw_urls) >= self.max_hw_per_vendor:
                    break
            if self.max_hw_per_vendor:
                hw_urls = hw_urls[: self.max_hw_per_vendor]
            for hw_url in hw_urls:
                hardware = _param(hw_url, "H")
                try:
                    hw_html = self._get_text(opener, hw_url)
                except Exception:
                    continue
                for href in _RE_LANDING.findall(hw_html) + _RE_LANDING_CID.findall(hw_html):
                    landing = _abs(href)
                    if not _same_site(landing):
                        continue
                    ff = _ff_of(landing)
                    if not ff or ff in seen_ff:
                        continue
                    seen_ff.add(ff)
                    emit({
                        "ff": ff,
                        "landing_url": landing,
                        "title": _title_of(landing),
                        "vendor": vendor,
                        "hardware": hardware,
                        "category_id": cat_id,
                        "category": cat_name,
                    })

    # ----- download (one opener/cookie-jar per download thread) -----

    def _resolve_l0(self, opener, entry: dict) -> tuple[str, str | None, bool]:
        """POST the download form and classify the response.

        Returns (state, l0_url, bundle_present):
          - ("ok", <l0>, bundle?)   the clean default package resolved;
          - ("bundle_only", None, True)  the "preparing" page came back but had
            only l1..l3 wrappers (no clean file) — permanent for this entry;
          - ("throttled", None, False)  the aggregator returned the *landing*
            page instead of the download page. Under sustained automated load it
            stops serving download links and hands back the landing; this is a
            transient rate-limit, NOT a missing file, so the caller must back off
            and leave the entry off the ledger to retry later.

        The session cookie set while visiting the landing travels on `opener`."""
        self._get_text(opener, entry["landing_url"])  # seed session cookies
        data = urlencode({"download": "1", "ff": entry["ff"]}).encode()
        req = Request(f"{BASE}/", data=data, method="POST", headers={
            "User-Agent": C.UA, "Referer": entry["landing_url"],
            "Content-Type": "application/x-www-form-urlencoded"})
        with opener.open(req, timeout=30) as r:
            page = r.read(4 << 20).decode("utf-8", "replace")
        m0 = _RE_L0.search(page)
        if m0:
            return "ok", _abs(m0.group(1)), bool(_RE_L1.search(page))
        # The real download page defines the CheckBundle() JS; its absence means
        # we got the landing page back → throttled. A CheckBundle page with only
        # l1 (no l0) is a genuine bundle-only entry.
        if "CheckBundle" in page or _RE_L1.search(page):
            return "bundle_only", None, True
        return "throttled", None, False

    def _resolves(self, host: str) -> bool:
        """DNS check with a shared cache; some l0 storage nodes (e.g. d2) have no
        public record and are unreachable by any client."""
        with self._dns_lock:
            if host in self._dns_cache:
                return self._dns_cache[host]
        try:
            socket.gethostbyname(host)
            ok = True
        except Exception:
            ok = False
        with self._dns_lock:
            self._dns_cache[host] = ok
        return ok

    def _pace(self) -> None:
        """Block until the next global download attempt is allowed. Enforces an
        aggregate rate of one attempt per `self._delay` seconds across all
        workers (AIMD-adjusted), so adding workers speeds up crawl/extract but
        does not increase the request rate the aggregator sees."""
        with self._pace_lock:
            now = time.monotonic()
            wait = max(0.0, getattr(self, "_next_allowed", 0.0) - now)
            self._next_allowed = max(now, getattr(self, "_next_allowed", 0.0)) + self._delay
        if wait > 0:
            self._stop.wait(wait)  # interruptible sleep

    def _on_throttle(self) -> bool:
        """Widen the delay and extend the next-allowed time. Returns True if the
        sustained-throttle give-up threshold has been crossed (run should stop)."""
        with self._pace_lock:
            self._delay = min(self.max_delay, max(self.min_delay, self._delay * 1.8))
            self._next_allowed = time.monotonic() + self._delay * 2  # cooldown
            self._throttle_streak += 1
            streak = self._throttle_streak
        return streak >= self.throttle_giveup

    def _on_success(self) -> None:
        with self._pace_lock:
            self._delay = max(self.min_delay, self._delay * 0.9)
            self._throttle_streak = 0

    def _process_entry(self, opener, work_dir: Path, entry: dict, rows: list[dict],
                       errors: list[dict], downloads: list[dict], stats: dict) -> None:
        ff = entry["ff"]
        self._pace()
        if self._stop.is_set():
            return
        try:
            state, l0, bundle = self._resolve_l0(opener, entry)
        except Exception as exc:
            with self._lock:
                stats["failed"] += 1
                errors.append({"stage": "resolve", "ff": ff, "error": str(exc)})
            return  # transient: leave off ledger so it retries next run
        if state == "throttled":
            with self._lock:
                stats["throttled"] += 1
            if self._on_throttle():  # sustained throttle → stop the run (resumable)
                self._stop.set()
                progress.report("throttled by aggregator — stopping (resume later)")
            return  # NOT recorded: retry next run after cooldown
        if state == "bundle_only":
            with self._lock:
                stats["no_l0"] += 1
            self._record_processed(entry, [], status="bundle_only")  # permanent
            return
        self._on_success()
        if bundle:
            with self._lock:
                stats["bundles_skipped"] += 1  # provenance note only; we take l0
        if self.discover_only:
            progress.report(f"resolve ok: {entry['title'][:38]}")
            self._record_processed(entry, [], status="discovered")
            return
        host = urlparse(l0).hostname or ""
        if not self._resolves(host):
            with self._lock:
                stats["dns_dead"] += 1
                errors.append({"stage": "dns", "ff": ff, "host": host})
            self._record_processed(entry, [], status="dns_dead")  # unreachable by anyone
            return
        try:
            got, rec = self._fetch_package(work_dir, opener, entry, l0, bundle)
        except Exception as exc:
            with self._lock:
                stats["failed"] += 1
                errors.append({"stage": "package", "ff": ff, "url": l0, "error": str(exc)})
            return  # transient: retry next run
        with self._lock:
            downloads.append(rec)
            rows.extend(got)
            stats["packages"] += 1
            stats["sys"] += len(got)
            stats["kept"] += 1
        self._record_processed(entry, [r["sha256"] for r in got], status="ok")

    def _fetch_package(self, work_dir: Path, opener, entry: dict, l0: str,
                       bundle_present: bool) -> tuple[list[dict], dict]:
        fname = Path(l0.split("?")[0]).name or "package.bin"
        folder = work_dir / "packages" / entry["ff"]
        pkg = folder / fname
        progress.report(f"download: {entry['title'][:38]}")
        # opener carries the session cookie set at the landing POST, in case the
        # CDN node gates the file on it; referer is the landing page.
        rec = C.download(l0, pkg, self.allowed_hosts, max_mb=self.max_mb,
                         timeout=180, referer=entry["landing_url"], opener=opener)
        rec["ff"] = entry["ff"]
        extracted = folder / "extracted"
        C.extract(pkg, extracted)
        # Scan the whole package folder, not just the extraction tree: a
        # DriversCollection payload is sometimes the bare driver itself (a
        # native-subsystem PE handed out with a .bin/.sys name), in which case
        # 7-Zip either refuses it or decomposes the PE into section dumps under
        # extracted/ — the driver file never lands there. collect_sys_files
        # detects drivers by *content* (IMAGE_SUBSYSTEM_NATIVE) regardless of
        # suffix, so pointing it at `folder` recovers the package-is-driver case
        # while still picking up the normal archive case from extracted/.
        got = C.collect_sys_files(folder, config.drivers_dir(), include_native_pe=True)
        # Aggregator re-host: no .cat trust path assumed; mark the quality bar and
        # leave signing policy to the L0 gate / DrvEye (see module docstring).
        for r in got:
            r["provenance"] = {
                "source_kind": "aggregator-rehost",
                "aggregator": "driverscollection.com",
                "trust_note": ("third-party re-host, not the original vendor domain; "
                               "no catalog (.cat) trust path assumed — authenticity "
                               "left to the L0 gate / DrvEye"),
                "vendor": entry["vendor"],
                "hardware": entry["hardware"],
                "category": entry["category"],
                "category_id": entry["category_id"],
                "title": entry["title"],
                "search_scope": self.scope_label or "broad",
                "landing_url": entry["landing_url"],
                "ff": entry["ff"],
                "bundle_offer_present": bundle_present,
                "package_name": fname,
                "package_url": l0,
                "package_final_url": rec["final_url"],
                "package_sha256": rec["sha256"],
                "package_size": rec["size"],
            }
        # durable output is the deduped .sys now in drivers_dir; prune the raw
        # package + extraction tree so peak disk stays ~one package per worker.
        C.prune_dir(folder)
        return got, rec

    # ----- resume ledger (shared across threads) -----

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
                    seen.add(json.loads(line)["ff"])
                except Exception:
                    continue
        return seen

    def _record_processed(self, entry: dict, sys_shas: list[str], *, status: str) -> None:
        """Append one ledger line (under a lock — many workers share the file).

        Every terminal outcome is recorded, not just successes: `no_l0` and
        `dns_dead` are permanent for a given file, so recording them stops a
        re-run from wasting time on them again. Transient failures are *not*
        recorded (the caller returns before here), so they retry next run."""
        p = self._ledger_path()
        with self._ledger_lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ff": entry["ff"],
                    "status": status,
                    "title": entry["title"],
                    "vendor": entry["vendor"],
                    "category": entry["category"],
                    "sys": sys_shas,
                    "ts": C.utc_now(),
                }, ensure_ascii=False) + "\n")


# ----- module helpers -----

def _new_opener():
    """A fresh urllib opener with its own cookie jar — one per worker thread
    (urllib openers/jars are not meant to be shared across threads)."""
    return build_opener(HTTPCookieProcessor(CookieJar()))


def _dedupe(it) -> list[str]:
    return list(dict.fromkeys(it))


def _same_site(url: str) -> bool:
    """Keep only canonical driverscollection.com links, dropping the language
    mirrors (us./de./fr.driverscollection.com, driver.ru) the site cross-links —
    otherwise the crawl would re-walk every vendor once per mirror."""
    return (urlparse(url).hostname or "").lower() == "driverscollection.com"


def _abs(href: str) -> str:
    """Resolve a site href ('//host/..', '/path', or full) to an https URL."""
    href = html.unescape(href.strip())
    if href.startswith("//"):
        return "https:" + href
    if href.startswith("/"):
        return BASE + href
    if href.startswith("http://"):
        return "https://" + href[len("http://"):]
    return href


def _param(url: str, key: str) -> str:
    m = re.search(rf"[?&]{key}=([^&]+)", url)
    return unquote(m.group(1)) if m else ""


def _ff_of(url: str) -> str | None:
    m = _RE_FF_PATH.search(url) or _RE_FF_CID.search(url)
    return m.group(1) if m else None


def _title_of(url: str) -> str:
    """Human title from a landing URL's slug (…/Download-A4Tech-6100F-Driver-…)."""
    if "/_" in url:
        tail = url.split("/_", 1)[-1]
        slug = tail.split("/", 1)[1] if "/" in tail else tail
        slug = unquote(slug).replace("Download-", "").replace("-free", "")
        return slug.replace("-", " ").strip() or url
    return url


def collector(scope_search: dict | None = None) -> DriversCollectionCollector:
    """Factory. `scope_search` (from pipeline.search_scope.resolve) narrows the
    crawl to matching hardware categories; without it, every category is crawled
    (raw-quantity default)."""
    if scope_search:
        ids = _scope_to_category_ids(scope_search)
        return DriversCollectionCollector(
            category_ids=ids or None,  # None -> broad default
            scope_label=scope_search.get("label"))
    return DriversCollectionCollector()


def _scope_to_category_ids(scope_search: dict) -> list[int]:
    """Map a resolved scope to this site's category ids by name match.

    The aggregator is organized by hardware class, so a scope's device classes /
    free-text term / label are matched against CATEGORY_IDS. A pure capability
    scope (e.g. msr-access) that names no hardware class yields nothing — the
    factory then falls back to the broad default."""
    terms = [str(c) for c in (scope_search.get("categories") or [])]
    terms += [str(q) for q in (scope_search.get("queries") or [])]
    if scope_search.get("label"):
        terms.append(str(scope_search["label"]))
    ids: list[int] = []
    for t in terms:
        t = t.strip().lower()
        if not t:
            continue
        for name, cid in CATEGORY_IDS.items():
            if (t == name or t in name or name in t) and cid not in ids:
                ids.append(cid)
    return ids
