"""Collector registry.

The corpus is sourced from the Microsoft Update Catalog alone — an official,
enumerable index where the download host is the vendor (Microsoft) itself. The
earlier per-vendor collectors (dell, hp, intel, …) each pinned a single installer
and together yielded only a few hundred drivers; they were removed in favor of
this one scalable source. The LOLDrivers reference-set collector was removed too,
so clone detection (`pipeline/adapter/l3.py`) reports `not_computed` until a
reference snapshot is wired back in.

New collectors are added here so `python -m pipeline.collect <name>` can find
them without import side effects elsewhere.
"""
from __future__ import annotations
from typing import Callable

from .base import Collector
from .archiveorg import collector as _archiveorg
from .cpuid import collector as _cpuid
from .dell import collector as _dell
from .driverscollection import collector as _driverscollection
from .msupdate import collector as _msupdate
from .rweverything import collector as _rweverything
from .samlab import collector as _samlab
from .techpowerup import collector as _techpowerup
from .touslesdrivers import collector as _touslesdrivers


REGISTRY: dict[str, Callable[[], Collector]] = {
    "msupdate-catalog": _msupdate,
    "driverscollection": _driverscollection,
    "samlab": _samlab,
    "archiveorg": _archiveorg,
    "dell": _dell,
    "techpowerup": _techpowerup,
    "cpuid": _cpuid,
    "rweverything": _rweverything,
    "touslesdrivers": _touslesdrivers,
}


def available() -> list[str]:
    return sorted(REGISTRY.keys())


def get(name: str, scope_search: dict | None = None) -> Collector:
    if name not in REGISTRY:
        raise KeyError(f"unknown collector '{name}'. available: {available()}")
    factory = REGISTRY[name]
    # Only scope-aware collectors (currently msupdate-catalog) accept a search
    # scope; pass it when the factory takes the kwarg, else construct plainly.
    try:
        return factory(scope_search=scope_search)
    except TypeError:
        return factory()
