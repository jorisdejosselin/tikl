"""The Transport seam.

A transport is a bidirectional byte channel plus a resize signal. Everything
above the byte stream — the batch command loop, the interactive PTY pump, prompt
detection, ANSI stripping — lives in :mod:`tikl.session` and is shared by every
transport. A transport implementation is therefore only responsible for its own
framing/reliability/auth (MAC-Telnet) or channel setup (SSH).

See DESIGN.md #3.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Transport(Protocol):
    """A connected, bidirectional byte channel to a RouterOS device."""

    def connect(self) -> None:
        """Establish the connection and authenticate. Raises on failure."""
        ...

    def write(self, data: bytes) -> None:
        """Send bytes to the remote shell."""
        ...

    def read(self, timeout: float) -> bytes:
        """Return bytes received within ``timeout`` seconds, or ``b''`` if idle.

        Raises :class:`tikl.errors.SessionClosed` when the remote ends the
        session.
        """
        ...

    def resize(self, cols: int, rows: int) -> None:
        """Inform the remote of a new terminal size (best effort)."""
        ...

    def close(self) -> None:
        """Tear down the connection. Idempotent."""
        ...
