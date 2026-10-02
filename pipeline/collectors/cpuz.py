"""CPU-Z — portable ZIP whose application .exe carries the driver as a PE resource.

The driver is embedded as a PE resource in the app binary, so the base's nested
pass runs 7-Zip on the .exe and `include_native_pe` recovers the driver by
content (native-subsystem PE), no `.sys` name required (SOURCES.md → CPU-Z).
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class CPUZCollector(SimpleArchiveCollector):
    name = "cpuz"
    role = "Hardware monitoring utility (embedded driver)"
    allowed_hosts = ["cpuid.com"]
    discovery_page = "https://www.cpuid.com/softwares/cpu-z.html"
    installer_url = "https://download.cpuid.com/cpu-z/cpu-z_3.01-en.zip"
    max_mb = 60
    include_native_pe = True
    pe_resource = True


def collector() -> CPUZCollector:
    return CPUZCollector()
