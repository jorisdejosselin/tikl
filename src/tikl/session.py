"""Shared session logic driven over any :class:`~tikl.transport.Transport`.

Everything above the byte stream lives here: prompt detection, ANSI stripping,
and the batch command loop. The interactive PTY pump (raw terminal, SIGWINCH)
will join it in a later milestone; both transports reuse whatever lives here.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import sys
import time
from collections.abc import Iterator

from .errors import AuthFailed, SessionClosed
from .mac.protocol import strip_ansi
from .transport import Transport

# RouterOS shell prompt, e.g. ``[admin@MikroTik] >`` (ANSI already stripped).
_PROMPT_RE = re.compile(r"[\]>]\s*>\s*$")
_FAIL_RE = re.compile(r"incorrect|denied|wrong|failed|bad", re.IGNORECASE)

DEFAULT_COMMANDS = (
    "/system resource print",
    "/ip address print",
    "/ip dhcp-client print",
)


def _read_until_prompt(transport: Transport, timeout: float) -> tuple[str, bool]:
    """Accumulate output until a RouterOS prompt appears or ``timeout`` elapses.

    Returns ``(text, saw_prompt)`` with ANSI stripped.
    """
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = transport.read(min(2.0, deadline - time.time()))
        except SessionClosed:
            break
        if not chunk:
            continue
        buf += chunk.decode("utf-8", errors="replace")
        if _PROMPT_RE.search(strip_ansi(buf)):
            return strip_ansi(buf), True
    return strip_ansi(buf), False


def wait_for_prompt(transport: Transport, timeout: float = 25.0) -> None:
    """Block until the first shell prompt; raise :class:`AuthFailed` otherwise."""
    text, ok = _read_until_prompt(transport, timeout)
    if not ok:
        if _FAIL_RE.search(text):
            raise AuthFailed(text.strip()[:200] or "authentication failed")
        raise AuthFailed("no prompt from router (authentication likely failed)")


def run_command(transport: Transport, command: str, timeout: float = 30.0) -> str:
    """Send one RouterOS command and return its output (ANSI stripped)."""
    transport.write((command + "\r").encode())
    text, _ = _read_until_prompt(transport, timeout)
    return text


def run_batch(
    transport: Transport,
    commands: tuple[str, ...] | list[str],
    timeout: float = 30.0,
    ready_timeout: float = 25.0,
) -> Iterator[tuple[str, str]]:
    """Wait for the shell, then run each command, yielding ``(command, output)``."""
    wait_for_prompt(transport, ready_timeout)
    for command in commands:
        yield command, run_command(transport, command, timeout)


def terminal_size() -> tuple[int, int]:
    """Current terminal size as ``(cols, rows)``, with a sane fallback."""
    size = shutil.get_terminal_size(fallback=(80, 24))
    return size.columns, size.lines


def terminal_type() -> str:
    return os.environ.get("TERM", "vt100")


def interactive_shell(transport: Transport) -> None:
    """Run a real interactive PTY session over the transport.

    Pumps the local terminal (raw mode) to/from the remote byte stream. Unix
    uses ``termios``; Windows uses ``msvcrt`` (best effort, see DESIGN.md).
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise RuntimeError("interactive shell requires a TTY; give a command to run instead")
    if os.name == "nt":
        _interactive_windows(transport)
    else:
        _interactive_posix(transport)


# Local escape key: Ctrl-] (like telnet) breaks out of the shell even if the
# remote session is dead, since in raw mode Ctrl-C is forwarded, not local.
_ESCAPE = b"\x1d"
_KEEPALIVE_INTERVAL = 15.0


def _drain_to_stdout(transport: Transport) -> bool:
    """Read one chunk from the transport to stdout. Returns False when closed."""
    try:
        out = transport.read(0.02)
    except SessionClosed:
        return False
    if out:
        os.write(sys.stdout.fileno(), out)
    return True


def _keepalive(transport: Transport) -> None:
    """Best-effort idle keepalive, if the transport supports it."""
    ka = getattr(transport, "keepalive", None)
    if callable(ka):
        with contextlib.suppress(Exception):
            ka()


def _interactive_posix(transport: Transport) -> None:
    import select  # noqa: PLC0415
    import signal  # noqa: PLC0415
    import termios  # noqa: PLC0415
    import tty  # noqa: PLC0415

    stdin_fd = sys.stdin.fileno()
    old_attr = termios.tcgetattr(stdin_fd)

    def on_winch(_signum: int, _frame: object) -> None:
        cols, rows = terminal_size()
        with contextlib.suppress(Exception):  # resize is best effort
            transport.resize(cols, rows)

    prev_winch = signal.getsignal(signal.SIGWINCH)
    last_ka = time.time()
    try:
        tty.setraw(stdin_fd)
        signal.signal(signal.SIGWINCH, on_winch)
        while True:
            if not _drain_to_stdout(transport):
                break
            ready, _, _ = select.select([stdin_fd], [], [], 0.02)
            if stdin_fd in ready:
                data = os.read(stdin_fd, 1024)
                if not data or _ESCAPE in data:
                    break
                transport.write(data)
            if time.time() - last_ka >= _KEEPALIVE_INTERVAL:
                last_ka = time.time()
                _keepalive(transport)
    finally:
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attr)
        signal.signal(signal.SIGWINCH, prev_winch)


def _interactive_windows(transport: Transport) -> None:  # pragma: no cover - Windows only
    import msvcrt  # noqa: PLC0415

    last_ka = time.time()
    while True:
        if not _drain_to_stdout(transport):
            break
        while msvcrt.kbhit():  # type: ignore[attr-defined]
            ch = msvcrt.getwch().encode()  # type: ignore[attr-defined]
            if ch == _ESCAPE:
                return
            transport.write(ch)
        if time.time() - last_ka >= _KEEPALIVE_INTERVAL:
            last_ka = time.time()
            _keepalive(transport)
        time.sleep(0.005)
