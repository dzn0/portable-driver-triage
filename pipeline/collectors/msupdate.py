"""Microsoft Update Catalog — a pinned driver CAB from windowsupdate.com.

The browser-search discovery step is not reproduced; this pins one proven CAB
(SOURCES.md -> Microsoft Update Catalog). 7-Zip extracts the CAB and the base
recovers the driver by content.
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class MSUpdateCatalogCollector(SimpleArchiveCollector):
    name = "msupdate-catalog"
    role = "Microsoft Update Catalog (driver CAB)"
    allowed_hosts = ["windowsupdate.com"]
    discovery_page = "https://www.catalog.update.microsoft.com/"
    installer_url = ("https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/"
                     "drvs/2026/04/680990a5-1908-4a37-9520-e6d70bf34a2d_"
                     "c37c679071e1ea1a64bcfed1c89b914d3fcdce3d.cab")
    max_mb = 200
    include_native_pe = True


def collector() -> MSUpdateCatalogCollector:
    return MSUpdateCatalogCollector()
