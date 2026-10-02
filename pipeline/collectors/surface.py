"""Microsoft Surface 3 driver MSI from download.microsoft.com.

7-Zip extracts MSI streams; `include_native_pe` recovers the driver payloads by
content (native-subsystem PE) rather than relying on Windows-only MSI File-table
name restoration, so it works in the Linux container too (SOURCES.md → Surface).
Original `.sys` names are not preserved — drivers are stored by sha256 as usual.
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class SurfaceCollector(SimpleArchiveCollector):
    name = "surface"
    role = "OEM (Surface) driver pack"
    allowed_hosts = ["microsoft.com"]
    discovery_page = "https://www.microsoft.com/download/details.aspx?id=49040"
    installer_url = ("https://download.microsoft.com/download/c/5/c/"
                     "c5c75dc4-0807-44a8-bcc1-6064cfd150f2/"
                     "Surface3_WiFi_Win10_18362_1902003_0.msi")
    max_mb = 200
    include_native_pe = True


def collector() -> SurfaceCollector:
    return SurfaceCollector()
