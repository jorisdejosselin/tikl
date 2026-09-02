"""Tikl — recovery CLI for MikroTik/RouterOS over MAC-Telnet (L2) or SSH."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("tikl")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0.dev0"
