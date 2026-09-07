"""Tikl exception hierarchy."""

from __future__ import annotations


class TiklError(Exception):
    """Base class for all Tikl errors."""


class ConnectionFailed(TiklError):
    """A transport could not establish or lost its connection."""


class SessionClosed(TiklError):
    """The remote side ended the session (MAC-Telnet END / SSH EOF)."""


class AuthFailed(TiklError):
    """Authentication was rejected by the router."""


class UnsupportedRouterOS(TiklError):
    """The router uses pre-6.43 auth, which Tikl does not implement."""


class NeedsPrivileges(TiklError):
    """Raw packet access (libpcap/Npcap + root/Administrator) was denied."""
