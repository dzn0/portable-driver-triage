"""Microsoft Update Catalog — enumerating collector (Playwright-driven).

This is the project's one *scalable* source: catalog.update.microsoft.com is an
official, legal index where the download host is Microsoft itself, so it fits the
"download always comes from the vendor's original URL" principle exactly. Unlike
the single-archive collectors, it does not pin one package — it drives a headless
Chromium to *search*, *paginate*, resolve each update's real download URL from
the JS download dialog, pull the CAB, and extract the drivers inside.

**By default it searches broadly** — a generic sweep across device classes, no
category filter, i.e. "collect anything." A *search scope* narrows that: when
`pipeline.collect --scope <name>` is given, the scope's `search:` block (queries
+ catalog-category tokens) is passed here, so `--scope network` or
`--scope hid-input-control` filters what the catalog search returns. This is the
collection-time half of the single scope vocabulary whose analysis-time half
`pipeline.analyze --scope <name>` already uses — one scope, two application
points (see `pipeline/search_scope.py`).

Scaling levers (overridable by env so `collect` needs no new CLI surface beyond
`--scope`):

- `PDT_MSCATALOG_QUERIES` (`;`- or `,`-separated) overrides the query set.
- `PDT_MSCATALOG_MAX_PAGES` (default 10) caps pagination per query.
- `PDT_MSCATALOG_CATEGORIES` restricts results to rows whose catalog
  classification contains one of these tokens (default: no filter).
- `PDT_MSCATALOG_MAX_MB` caps per-CAB size; `PDT_MSCATALOG_DISCOVER_ONLY=1`
  resolves and logs URLs without downloading (smoke test).

Signatures are verified best-effort and **catalog-aware** (these drivers are
almost always `.cat`-signed, not embedded) via `_common.verify_signature`; on the
Linux container, where there is no SignTool, signature is recorded as unverified
and signing policy is left to the L0 gate / DrvEye, exactly like every other
source. Nothing is ever executed — CABs are extracted with 7-Zip and `.sys`
files are parsed as bytes downstream.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import quote

from .. import config
from .. import progress
from . import _common as C
from .base import Collector

BASE = "https://www.catalog.update.microsoft.com"

# Default = broad sweep across device classes, no category filter: "anything".
# Narrowing is the job of a search scope (--scope), not of this default.
DEFAULT_QUERIES = [
    "Display", "Graphics", "Network", "Ethernet", "Wireless", "WiFi",
    "Bluetooth", "Audio", "Sound", "Storage", "SATA", "NVMe", "RAID",
    "USB", "Chipset", "System", "Firmware", "Printer", "Camera", "Imaging",
    "Scanner", "Mouse", "Keyboard", "HID", "Touchpad", "Sensor", "Monitor",
    "Card Reader", "Modem", "Serial", "SCSI", "Fingerprint", "Smart Card",
    "Thunderbolt",
]

# Download URLs the dialog may expose; only .cab is extractable here.
_URL_RE = re.compile(r'https?://[^\s"\';<>]+\.(?:cab|msu|exe|msi|psf)', re.I)


def _env_list(name: str) -> list[str] | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    parts = [p.strip() for p in re.split(r"[;,]", raw) if p.strip()]
    return parts or None


class MSUpdateCatalogCollector(Collector):
    name = "msupdate-catalog"
    role = "Microsoft Update Catalog (official, enumerated — scalable source)"
    allowed_hosts = ["microsoft.com", "windowsupdate.com"]

    def __init__(
        self,
        queries: list[str] | None = None,
        *,
        max_pages: int | None = None,
        max_results_per_query: int | None = None,
        max_mb: int | None = None,
        categories: list[str] | tuple[str, ...] | None = None,
        discover_only: bool | None = None,
        scope_label: str | None = None,
    ) -> None:
        self.queries = queries or _env_list("PDT_MSCATALOG_QUERIES") or DEFAULT_QUERIES
        self.max_pages = max_pages or int(os.environ.get("PDT_MSCATALOG_MAX_PAGES", "10"))
        self.max_results_per_query = max_results_per_query or int(
            os.environ.get("PDT_MSCATALOG_MAX_RESULTS", "1000"))
        self.max_mb = max_mb or int(os.environ.get("PDT_MSCATALOG_MAX_MB", "300"))
        # Category filter: None = "not specified" → fall back to env, else no
        # filter (broad default). An explicit (possibly empty) list is honored
        # as-is, so a scope can deliberately pass no categories.
        if categories is None:
            categories = _env_list("PDT_MSCATALOG_CATEGORIES") or ()
        self.categories = tuple(c.lower() for c in categories)
        self.discover_only = (
            discover_only if discover_only is not None
            else os.environ.get("PDT_MSCATALOG_DISCOVER_ONLY", "") not in ("", "0", "false"))
        self.scope_label = scope_label  # provenance only: which search scope drove this

    # ----- discovery -----

    def discover(self) -> dict:
        return {
            "discovery_page": f"{BASE}/",
            "installer_url": None,  # many packages; real URLs are per-row provenance
            "search_scope": self.scope_label or "broad (default)",
            "queries": list(self.queries),
            "max_pages": self.max_pages,
            "max_results_per_query": self.max_results_per_query,
            "categories": list(self.categories),
            "discover_only": self.discover_only,
        }

    # ----- acquisition -----

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        # Lazy import so `collect --list` / other collectors work on a box
        # without Playwright installed; only this collector needs it.
        os.environ.setdefault(
            "PLAYWRIGHT_BROWSERS_PATH",
            str(config.REPO_ROOT / "vendor" / "pw-browsers"))
        from playwright.sync_api import sync_playwright

        refresh = os.environ.get("PDT_MSCATALOG_REFRESH", "") not in ("", "0", "false")
        processed = set() if refresh else self._load_ledger()
        ledger_start = len(processed)  # size before this run, for reporting
        sessions_max = max(1, int(os.environ.get("PDT_MSCATALOG_SESSIONS", "6")))

        rows: list[dict] = []
        errors: list[dict] = []
        downloads: list[dict] = []
        seen_updates: set[str] = set()
        stats = {"discovered": 0, "kept": 0, "packages": 0, "sys": 0, "skipped_seen": 0}

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                queue = list(self.queries)
                sessions: list[dict] = []

                def start(query: str):
                    try:
                        pg = browser.new_page()
                        pg.goto(f"{BASE}/Search.aspx?q={quote(query)}",
                                wait_until="domcontentloaded", timeout=60000)
                        return {"query": query, "page": pg, "page_num": 1,
                                "kept": 0, "buf": [], "done": False}
                    except Exception as exc:
                        errors.append({"stage": "search", "query": query, "error": str(exc)})
                        return None

                def refill_sessions():
                    while queue and len(sessions) < sessions_max:
                        s = start(queue.pop(0))
                        if s:
                            sessions.append(s)

                def want_more(sess) -> bool:
                    return (sess["kept"] < self.max_results_per_query
                            and sess["page_num"] < self.max_pages)

                refill_sessions()

                # True per-entry round-robin: each active query does at most ONE
                # download per round (free ledger/category skips are consumed in the
                # same turn), so a low-yield class (e.g. Display — mostly monitor INFs
                # / usermode IDD .dlls with no kernel .sys) never blocks the others and
                # drivers from many classes start landing within the first rounds.
                while sessions:
                    for sess in list(sessions):
                        page, q = sess["page"], sess["query"]
                        # (re)fill this session's buffer from its current results page
                        if not sess["buf"]:
                            try:
                                entries = self._harvest_page(page, q, seen_updates)
                            except Exception as exc:
                                errors.append({"stage": "search", "query": q, "error": str(exc)})
                                entries = []
                            stats["discovered"] += len(entries)
                            sess["buf"] = entries
                            if not entries:  # nothing new here → next page, or retire
                                if want_more(sess) and self._go_next_page(page):
                                    sess["page_num"] += 1
                                else:
                                    sess["done"] = True
                        # process at most one download this turn; skips are free
                        did_download = False
                        while sess["buf"] and not did_download:
                            if sess["kept"] >= self.max_results_per_query:
                                sess["buf"] = []
                                sess["done"] = True
                                break
                            entry = sess["buf"].pop(0)
                            uid = entry["update_id"]
                            if uid in processed:
                                stats["skipped_seen"] += 1  # resume: already done
                                continue
                            if not self._category_ok(entry):
                                continue
                            stats["kept"] += 1
                            sess["kept"] += 1
                            if self.discover_only:
                                did_download = True  # counts as a turn to keep rotating
                                continue
                            ok, sys_shas = self._process_entry(
                                work_dir, page, entry, downloads, errors, stats, rows)
                            if ok:
                                # Record on clean completion (incl. 0-yield) so a
                                # re-run skips it; leave failures off the ledger so
                                # they retry next time.
                                processed.add(uid)
                                self._record_processed(entry, sys_shas)
                            did_download = True
                            time.sleep(0.3)  # be polite to the catalog
                        # page fully consumed → advance for this session's next turn
                        if not sess["buf"] and not sess["done"]:
                            if want_more(sess) and self._go_next_page(page):
                                sess["page_num"] += 1
                            else:
                                sess["done"] = True
                        if sess["done"]:
                            try:
                                page.close()
                            except Exception:
                                pass
                            sessions.remove(sess)
                    refill_sessions()
            finally:
                browser.close()

        info["stats"] = stats
        info["errors"] = errors
        info["downloads_top"] = downloads
        info["ledger_at_start"] = ledger_start
        info["resumed"] = (not refresh) and stats["skipped_seen"] > 0
        return rows

    # ----- resume ledger -----

    def _ledger_path(self) -> Path:
        """Persistent record of processed update_ids, shared across runs."""
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
                    seen.add(json.loads(line)["update_id"])
                except Exception:
                    continue
        return seen

    def _record_processed(self, entry: dict, sys_shas: list[str]) -> None:
        p = self._ledger_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        # Append-per-entry so an interrupted run still records what it finished —
        # that is what makes a re-run continue instead of restarting.
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "update_id": entry["update_id"],
                "title": entry["title"],
                "query": entry["query"],
                "sys": sys_shas,
                "ts": C.utc_now(),
            }, ensure_ascii=False) + "\n")

    # ----- helpers -----

    def _harvest_page(self, page, query: str, seen_global: set[str]) -> list[dict]:
        """Return the NEW update entries on the page currently loaded in `page`."""
        table = page.locator("#ctl00_catalogBody_updateMatches")
        try:
            table.wait_for(timeout=30000)
        except Exception:
            return []  # a "no results" page has no match table
        rows = table.locator("tr")
        out: list[dict] = []
        for index in range(1, rows.count()):
            row = rows.nth(index)
            link = row.locator('a[onclick*="goToDetails"]').first
            if not link.count():
                continue
            m = re.search(r"goToDetails\(['\"]([^'\"]+)",
                          link.get_attribute("onclick") or "")
            if not m:
                continue
            uid = m[1]
            if uid in seen_global:
                continue
            seen_global.add(uid)
            out.append({
                "update_id": uid,
                "title": link.inner_text().strip(),
                "query": query,
                "columns": row.locator("td").all_inner_texts(),
            })
        progress.report(f"{query}: +{len(out)} new ({len(seen_global)} seen)")
        return out

    def _process_entry(self, work_dir: Path, page, entry: dict, downloads: list[dict],
                       errors: list[dict], stats: dict, rows: list[dict]) -> tuple[bool, list[str]]:
        """Resolve an entry's download URLs and fetch each CAB.

        Returns (ok, sys_shas). ok is False — so the entry is NOT written to the
        ledger and retries next run — when URL resolution or any CAB download
        fails; it is True on a clean completion, including a legitimate 0-yield
        (e.g. a monitor INF package with no kernel driver)."""
        try:
            urls = self._resolve_urls(page, entry)
        except Exception as exc:
            errors.append({"stage": "resolve", "update_id": entry["update_id"],
                           "title": entry["title"], "error": str(exc)})
            return False, []
        sys_shas: list[str] = []
        ok = True
        for url in urls:
            if not url.lower().split("?")[0].endswith(".cab"):
                continue  # only CABs are extractable in this path
            try:
                got = self._fetch_package(work_dir, entry, url, downloads)
                stats["packages"] += 1
                stats["sys"] += len(got)
                rows.extend(got)
                sys_shas.extend(r["sha256"] for r in got)
            except Exception as exc:
                ok = False
                errors.append({"stage": "package", "update_id": entry["update_id"],
                               "url": url, "error": str(exc)})
        return ok, sys_shas

    @staticmethod
    def _go_next_page(page) -> bool:
        """Click the catalog's Next-page control; return False if there is none.

        Captures the current first-row id itself and waits for it to change after
        the click (the postback swaps the table in place), so callers need not
        track pagination state."""
        nxt = page.locator("#ctl00_catalogBody_nextPage")
        if not nxt.count() or not nxt.is_enabled():
            return False
        first_id_js = """() => {
            const t = document.querySelector('#ctl00_catalogBody_updateMatches');
            if (!t) return null;
            const a = t.querySelector('a[onclick*="goToDetails"]');
            if (!a) return null;
            const m = /goToDetails\\(['\"]([^'\"]+)/.exec(a.getAttribute('onclick')||'');
            return m ? m[1] : null;
        }"""
        try:
            prev = page.evaluate(first_id_js)
        except Exception:
            prev = None
        try:
            nxt.click(timeout=5000)
            page.wait_for_function(
                """(prev) => {
                    const t = document.querySelector('#ctl00_catalogBody_updateMatches');
                    if (!t) return false;
                    const a = t.querySelector('a[onclick*="goToDetails"]');
                    if (!a) return false;
                    const m = /goToDetails\\(['\"]([^'\"]+)/.exec(a.getAttribute('onclick')||'');
                    return m && m[1] !== prev;
                }""",
                arg=prev, timeout=15000)
            return True
        except Exception:
            return False

    def _category_ok(self, entry: dict) -> bool:
        if not self.categories:
            return True
        blob = " ".join(entry.get("columns") or []).lower()
        return any(tok in blob for tok in self.categories)

    def _resolve_urls(self, page, entry: dict) -> list[str]:
        """Open the update's download dialog and scrape its real download URLs."""
        popup = None
        try:
            with page.expect_popup(timeout=30000) as event:
                page.locator(f'input[id="{entry["update_id"]}"]').click()
            popup = event.value
            popup.wait_for_load_state("domcontentloaded", timeout=30000)
            popup.wait_for_function(
                "() => /https?:.*\\.(cab|msu|exe|msi|psf)/i.test("
                "document.documentElement.outerHTML)", timeout=30000)
            content = popup.content().replace("\\/", "/")
        finally:
            if popup and not popup.is_closed():
                popup.close()
        urls = list(dict.fromkeys(re.findall(_URL_RE, content)))
        # Force HTTPS; the host allowlist is re-checked at download time.
        return [re.sub(r"^http://", "https://", u) for u in urls]

    def _fetch_package(self, work_dir: Path, entry: dict, url: str,
                       downloads: list[dict]) -> list[dict]:
        key = hashlib.sha256(url.encode()).hexdigest()[:16]
        folder = work_dir / "packages" / entry["update_id"] / key
        cab = folder / "package.cab"
        progress.report(f"download: {entry['title'][:40]}")
        rec = C.download(url, cab, self.allowed_hosts, max_mb=self.max_mb)
        rec["update_id"] = entry["update_id"]
        downloads.append(rec)
        extracted = folder / "extracted"
        C.extract(cab, extracted)
        catalogs = sorted(p for p in extracted.rglob("*")
                          if p.is_file() and p.suffix.lower() == ".cat")
        got = C.collect_sys_files(extracted, config.drivers_dir(),
                                  include_native_pe=True, catalogs=catalogs)
        for r in got:
            r["provenance"] = {
                "update_id": entry["update_id"],
                "update_title": entry["title"],
                "query": entry["query"],
                "search_scope": self.scope_label or "broad",
                "categories": entry.get("columns"),
                "package_url": url,
                "package_final_url": rec["final_url"],
                "package_sha256": rec["sha256"],
                "package_size": rec["size"],
            }
        # Durable output is the deduped .sys now in drivers_dir; the CAB and its
        # extraction tree are disposable (this is what otherwise grows the run
        # dir to tens of GB). Prune per package; PDT_KEEP_PACKAGES=1 retains.
        C.prune_dir(folder)
        return got


def collector(scope_search: dict | None = None) -> MSUpdateCatalogCollector:
    """Factory. `scope_search` (from pipeline.search_scope.resolve) narrows the
    catalog search when `collect --scope <name>` is used; without it, the broad
    default applies."""
    if scope_search:
        return MSUpdateCatalogCollector(
            queries=scope_search.get("queries") or None,
            categories=scope_search.get("categories"),
            scope_label=scope_search.get("label"),
        )
    return MSUpdateCatalogCollector()
