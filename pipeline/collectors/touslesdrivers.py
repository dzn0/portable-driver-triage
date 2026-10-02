"""TousLesDrivers (discovery only) → original NVIDIA-hosted nForce installer.

TLD is used purely to *locate* a legacy package; the download goes to the
original NVIDIA vendor host over HTTPS (SOURCES.md → TousLesDrivers). Yields
nForce-era drivers such as `nvefd2k.sys`.
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class TousLesDriversCollector(SimpleArchiveCollector):
    name = "touslesdrivers"
    role = "Discovery index → vendor-hosted legacy driver"
    allowed_hosts = ["nvidia.com"]
    discovery_page = "https://www.touslesdrivers.com/"
    installer_url = ("https://us.download.nvidia.com/Windows/nForce/15.26/"
                     "15.26_nforce_winxp32_international_whql.exe")
    max_mb = 120


def collector() -> TousLesDriversCollector:
    return TousLesDriversCollector()
