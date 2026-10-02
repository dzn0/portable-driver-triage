"""CORSAIR — legacy LINK installer ZIP (WiX Burn) from downloads.corsair.com.

The ZIP carries a WiX Burn bootstrapper whose attached CABs hold the drivers;
the base's multi-level nested extraction + content detection recover them
(SOURCES.md -> CORSAIR). Payload names are not restored (stored by sha256).
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class CorsairCollector(SimpleArchiveCollector):
    name = "corsair"
    role = "Peripheral vendor (LINK utility)"
    allowed_hosts = ["corsair.com"]
    discovery_page = "https://downloads.corsair.com/Files/Corsair-Link/"
    installer_url = "https://downloads.corsair.com/Files/Corsair-Link/Corsair-LINK-Installer-v4.9.9.3.zip"
    max_mb = 200
    include_native_pe = True


def collector() -> CorsairCollector:
    return CorsairCollector()
