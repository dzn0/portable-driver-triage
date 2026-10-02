"""LOLDrivers collector — reference set for L3 clone detection.

Not a vendor collection source: LOLDrivers catalogs *known-vulnerable* drivers
by hash so this project can match a freshly collected binary against them.
The collector downloads:

  1. `api/drivers.json` — the full catalog (metadata, hashes, references).
  2. A small number of classified-vulnerable `.sys` samples from the Git LFS
     mirror, verified against the catalog's recorded SHA-256.

Full reference-set ingestion (every blob in the catalog, plus `detections/`)
is deferred to Pending #6 in README.md. This collector proves the mechanism
and seeds the ref-set with at least one validated sample so downstream code
can start exercising the clone-detection path.
"""
from __future__ import annotations
import json
import shutil
from pathlib import Path

from .. import config
from . import _common as C
from .base import Collector


class LOLDriversCollector(Collector):
    name = "loldrivers"
    role = "Reference set — known-vulnerable drivers (not a vendor source)"
    allowed_hosts = [
        "loldrivers.io",
        "githubusercontent.com",  # media.githubusercontent.com Git-LFS media
    ]

    CATALOG_URL = "https://www.loldrivers.io/api/drivers.json"
    LFS_BASE = "https://media.githubusercontent.com/media/magicsword-io/LOLDrivers/main/drivers/"

    def __init__(self, max_samples: int = 1):
        self.max_samples = max_samples

    def discover(self) -> dict:
        return {
            "discovery_page": "https://www.loldrivers.io/",
            "catalog_url": self.CATALOG_URL,
            "installer_url": self.CATALOG_URL,  # for provenance uniformity
            "max_samples": self.max_samples,
        }

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        catalog_path = work_dir / "catalog" / "drivers.json"
        catalog_rec = C.download(
            self.CATALOG_URL, catalog_path, self.allowed_hosts, max_mb=100
        )
        info.setdefault("downloads_top", []).append(catalog_rec)

        # LOLDrivers serves the catalog with a BOM.
        entries = json.loads(catalog_path.read_text(encoding="utf-8-sig"))
        info["catalog_entries"] = len(entries)

        candidates = []
        for entry in entries:
            if str(entry.get("Category", "")).lower() not in (
                "vulnerable", "vulnerable driver",
            ):
                continue
            for sample in entry.get("KnownVulnerableSamples", []):
                md5 = (sample.get("MD5") or "").lower()
                sha = (sample.get("SHA256") or "").lower()
                if md5 and sha:
                    candidates.append((entry, sample, md5, sha))

        info["vulnerable_candidates"] = len(candidates)

        rows: list[dict] = []
        attempts: list[dict] = []
        # Scan more than max_samples because some LFS blobs may 404 or fail
        # hash verification; we stop once we have max_samples good ones.
        scan_budget = min(len(candidates), max(self.max_samples * 4, 8))
        for entry, sample, md5, expected_sha in candidates[:scan_budget]:
            if len(rows) >= self.max_samples:
                break
            name = (
                sample.get("OriginalFilename")
                or sample.get("Filename")
                or f"loldrivers_{md5}.sys"
            )
            name = Path(name).name
            url = self.LFS_BASE + md5 + ".bin"
            tmp = work_dir / "samples" / f"{md5}.bin"
            attempt: dict = {
                "catalog_entry_id": entry.get("Id"),
                "original_name": name,
                "expected_sha256": expected_sha,
                "url": url,
            }
            try:
                dl = C.download(url, tmp, self.allowed_hosts, max_mb=40)
                actual = C.sha256_file(tmp)
                attempt["downloaded_sha256"] = actual
                if actual != expected_sha:
                    raise ValueError(
                        f"catalog SHA-256 mismatch (expected {expected_sha}, got {actual})"
                    )
                ident = C.pe_identity(tmp)
                attempt["pe"] = ident
                if not ident or not ident["native"]:
                    raise ValueError("not a native-subsystem PE")
                signature = C.verify_signature(tmp)
                target = config.drivers_dir() / f"{actual}.sys"
                if not target.exists():
                    shutil.copy2(tmp, target)
                attempt["status"] = "success"
                attempt["stored_path"] = str(target)
                rows.append({
                    "sha256": actual,
                    "original_name": name,
                    "size": tmp.stat().st_size,
                    "pe": ident,
                    "signature": signature,
                    "extraction_path": f"loldrivers:{md5}.bin",
                    "stored_path": str(target),
                    "provenance": {
                        "catalog_entry_id": entry.get("Id"),
                        "catalog_sha256": catalog_rec["sha256"],
                        "lfs_blob_url": url,
                        "lfs_blob_sha256": actual,
                        "lol_cves": entry.get("CVE") or [],
                        "lol_tags": entry.get("Tags") or [],
                    },
                })
            except Exception as exc:
                attempt["status"] = "failed"
                attempt["error"] = str(exc)
            attempts.append(attempt)

        info["sample_attempts"] = attempts
        return rows


def collector() -> LOLDriversCollector:
    return LOLDriversCollector()
