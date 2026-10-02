"""Collector registry.

New collectors are added here so `python -m pipeline.collect <name>` can find
them without import side effects elsewhere.
"""
from __future__ import annotations
from typing import Callable

from .base import Collector
from .loldrivers import collector as _loldrivers
from .windivert import collector as _windivert
from .intel import collector as _intel
from .gigabyte import collector as _gigabyte
from .msi_afterburner import collector as _msi_afterburner
from .touslesdrivers import collector as _touslesdrivers
from .virtio import collector as _virtio
from .surface import collector as _surface
from .cpuz import collector as _cpuz
from .hwmonitor import collector as _hwmonitor
from .hwinfo import collector as _hwinfo
from .hp import collector as _hp
from .dell import collector as _dell
from .corsair import collector as _corsair
from .msupdate import collector as _msupdate


REGISTRY: dict[str, Callable[[], Collector]] = {
    "loldrivers": _loldrivers,
    "windivert": _windivert,
    "intel": _intel,
    "gigabyte": _gigabyte,
    "msi-afterburner": _msi_afterburner,
    "touslesdrivers": _touslesdrivers,
    "virtio": _virtio,
    "surface": _surface,
    "cpuz": _cpuz,
    "hwmonitor": _hwmonitor,
    "hwinfo": _hwinfo,
    "hp": _hp,
    "dell": _dell,
    "corsair": _corsair,
    "msupdate-catalog": _msupdate,
}


def available() -> list[str]:
    return sorted(REGISTRY.keys())


def get(name: str) -> Collector:
    if name not in REGISTRY:
        raise KeyError(f"unknown collector '{name}'. available: {available()}")
    return REGISTRY[name]()
