"""MSI Afterburner — yields RTCore32/RTCore64.sys (CVE-2019-16098 lineage).

MSI's own and Guru3D's landing endpoints return HTTP 403; the download goes to
Guru3D's explicitly-authorized NLUUG mirror, whose ZIP SHA-256 matches the
Microsoft winget manifest (SOURCES.md → MSI Afterburner). This is a documented
authorized mirror, not a direct MSI-hosted download.
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class MSIAfterburnerCollector(SimpleArchiveCollector):
    name = "msi-afterburner"
    role = "GPU overclock utility (RTCore driver)"
    allowed_hosts = ["nluug.nl"]
    discovery_page = "https://ftp.nluug.nl/pub/games/PC/guru3d/afterburner/"
    installer_url = ("https://ftp.nluug.nl/pub/games/PC/guru3d/afterburner/"
                     "[Guru3D]-MSIAfterburnerSetup466Build16757.zip")
    max_mb = 120


def collector() -> MSIAfterburnerCollector:
    return MSIAfterburnerCollector()
