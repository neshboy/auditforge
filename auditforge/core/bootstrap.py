"""Imports the primitive modules for a given OS, which populates
core.registry as a side effect. Kept as one chokepoint so the CLI (and
tests) never have to remember which module defines which primitives.
"""

from __future__ import annotations

import importlib

from auditforge.core.models import OperatingSystem

_MODULES = {
    OperatingSystem.WINDOWS: "auditforge.controls.windows.primitives",
    OperatingSystem.LINUX: "auditforge.controls.linux.primitives",
    OperatingSystem.MACOS: "auditforge.controls.macos.primitives",
}

_loaded: set = set()


def load_primitives_for(os_name: OperatingSystem) -> None:
    if os_name in _loaded:
        return
    importlib.import_module(_MODULES[os_name])
    _loaded.add(os_name)
