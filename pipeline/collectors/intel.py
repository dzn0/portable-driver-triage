"""Intel network-adapter driver — Windows Ethernet ZIP from downloadmirror.intel.com.

Pinned to the version proven in the source survey (SOURCES.md → Intel). urllib
TLS to Intel is flaky; `_common.download` falls back to Windows curl (IPv4,
certs on) automatically.
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class IntelCollector(SimpleArchiveCollector):
    name = "intel"
    role = "NIC vendor (Ethernet drivers)"
    allowed_hosts = ["intel.com"]
    discovery_page = ("https://www.intel.com/content/www/us/en/download/18293/"
                      "intel-network-adapter-driver-for-windows-10.html")
    installer_url = "https://downloadmirror.intel.com/923982/Wired_driver_31.2.2_x64.zip"
    max_mb = 120


def collector() -> IntelCollector:
    return IntelCollector()
