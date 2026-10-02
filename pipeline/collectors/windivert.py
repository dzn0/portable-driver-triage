"""WinDivert collector — binary ZIP from the official project page.

Chosen as the reference implementation because its acquisition path is the
simplest possible (download ZIP → extract → emit). Any new collector that
cannot at least match this shape has a design problem.

Source: `SOURCES.md` → WinDivert.
"""
from __future__ import annotations
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .. import config
from . import _common as C
from .base import Collector


class WinDivertCollector(Collector):
    name = "windivert"
    role = "Open-source project (network driver)"
    allowed_hosts = ["reqrypt.org"]

    PAGE = "https://reqrypt.org/windivert.html"

    def discover(self) -> dict:
        html = C.fetch_text(self.PAGE, self.allowed_hosts)
        links = re.findall(r'href="([^"]+WinDivert[^" ]+\.zip)"', html, re.I)
        links = [x for x in links if "source" not in x.lower()]
        if not links:
            raise RuntimeError("no binary ZIP link on WinDivert official page")
        return {
            "discovery_page": self.PAGE,
            "installer_url": urljoin(self.PAGE, links[0]),
            "candidates": [urljoin(self.PAGE, x) for x in links],
        }

    def acquire(self, work_dir: Path, info: dict) -> list[dict]:
        url = info["installer_url"]
        pkg = work_dir / "packages" / Path(urlparse(url).path).name
        extracted = work_dir / "extracted"
        download_rec = C.download(url, pkg, self.allowed_hosts, max_mb=30)
        info.setdefault("downloads_top", []).append(download_rec)  # bubbled up by base.run
        C.extract(pkg, extracted)
        rows = C.collect_sys_files(extracted, config.drivers_dir())
        for r in rows:
            r["provenance"] = {
                "installer_sha256": download_rec["sha256"],
                "installer_size": download_rec["size"],
                "installer_final_url": download_rec["final_url"],
            }
        return rows


def collector() -> WinDivertCollector:
    return WinDivertCollector()
