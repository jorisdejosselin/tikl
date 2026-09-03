"""Tikl — recovery CLI for MikroTik/RouterOS over MAC-Telnet (L2) or SSH."""

from __future__ import annotations

import os as _os
import sys as _sys

# MAC-Telnet runs under sudo; without this, root would write root-owned .pyc into
# the install tree, which then blocks the next (non-root) reinstall. Set before
# importing any submodule so none of tikl's bytecode is written as root.
if getattr(_os, "geteuid", None) is not None and _os.geteuid() == 0:
    _sys.dont_write_bytecode = True

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("tikl")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0.dev0"
