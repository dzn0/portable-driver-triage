"""Dell — WinPE driver-pack CAB from downloads.dell.com.

Pinned WinPE CAB (SOURCES.md -> Dell); 7-Zip extracts the CAB and the base's
content detection recovers the driver payloads.
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class DellCollector(SimpleArchiveCollector):
    name = "dell"
    role = "OEM (Dell) WinPE driver pack"
    allowed_hosts = ["dell.com"]
    discovery_page = "https://downloads.dell.com/catalog/DriverPackCatalog.cab"
    installer_url = "https://downloads.dell.com/FOLDER14542934M/1/WinPE11.0-Drivers-A10-XCXDW.cab"
    max_mb = 600
    include_native_pe = True


def collector() -> DellCollector:
    return DellCollector()
