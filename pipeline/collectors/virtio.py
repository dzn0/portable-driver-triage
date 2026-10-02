"""VirtIO (virtio-win) — Fedora-hosted stable driver MSI.

urllib gets an HTML anti-bot response (HTTP 200); `_common.download` rejects it
by magic and curl (IPv4) retrieves the genuine MSI (SOURCES.md → VirtIO).
`include_native_pe` recovers drivers whether 7-Zip emits real `.sys` names or
MSI `fil<hex>` stream names.
"""
from __future__ import annotations
from .base import SimpleArchiveCollector


class VirtIOCollector(SimpleArchiveCollector):
    name = "virtio"
    role = "Virtualization guest drivers"
    allowed_hosts = ["fedorapeople.org"]
    discovery_page = ("https://fedorapeople.org/groups/virt/virtio-win/"
                      "direct-downloads/stable-virtio/")
    installer_url = ("https://fedorapeople.org/groups/virt/virtio-win/"
                     "direct-downloads/stable-virtio/virtio-win-gt-x64.msi")
    max_mb = 60
    include_native_pe = True


def collector() -> VirtIOCollector:
    return VirtIOCollector()
