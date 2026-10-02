"""GIGABYTE Control Center package — NSIS ZIP from download1.gigabyte.com.

Yields `amdtools.sys` (GIGABYTE BYOVD lineage). Large (~436 MiB); 7-Zip handles
the NSIS layout directly. Pinned per SOURCES.md → GIGABYTE.
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class GigabyteCollector(SimpleArchiveCollector):
    name = "gigabyte"
    role = "Mainboard/GPU vendor (control utility)"
    allowed_hosts = ["gigabyte.com"]
    discovery_page = "https://download1.gigabyte.com/Files/Driver/"
    installer_url = ("https://download1.gigabyte.com/Files/Driver/"
                     "nb-driver-64bit-win11-dchu-gcc-22.06.23.01.zip")
    max_mb = 600


def collector() -> GigabyteCollector:
    return GigabyteCollector()
