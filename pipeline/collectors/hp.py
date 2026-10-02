"""HP — WinPE SoftPaq (self-extracting EXE) from ftp.ext.hp.com.

The SoftPaq is a self-extractor; the base's nested pass unpacks it and recovers
the driver payloads (SOURCES.md -> HP). Pinned to a proven SoftPaq.
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class HPCollector(SimpleArchiveCollector):
    name = "hp"
    role = "OEM (HP) WinPE driver pack"
    allowed_hosts = ["hp.com"]
    discovery_page = "https://ftp.hp.com/pub/caps-softpaq/cmit/HP_WinPE_DriverPack.html"
    installer_url = "https://ftp.ext.hp.com/pub/softpaq/sp173001-173500/sp173204.exe"
    max_mb = 400
    include_native_pe = True


def collector() -> HPCollector:
    return HPCollector()
