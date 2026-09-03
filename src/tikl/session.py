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
from .mac.protocol import strip_ansi_bytes
from .transport import Transport

# RouterOS shell prompt, e.g. ``[admin@MikroTik] >`` (ANSI already stripped).
_PROMPT_RE = re.compile(r"[\]>]\s*>\s*$")
_FAIL_RE = re.compile(r"incorrect|denied|wrong|failed|bad", re.IGNORECASE)

DEFAULT_COMMANDS = (
    "/system resource print",
    "/ip address print",
    "/ip dhcp-client print",
)


_CSI_RE = re.compile(rb"\x1b\[([0-9;]*)([A-Za-z])|\x1b([DMZ])|([\r\n])")


class TerminalResponder:
    """Minimal cursor emulator that answers RouterOS's size-detection probes.

    At shell start RouterOS parks the cursor at various positions (home, far
    right/bottom via ESC[9999C/B) and asks ESC[6n for the cursor position to
    triangulate the terminal size, blocking ~10s if unanswered. In batch mode no
    real terminal replies, so we track the cursor against a declared size and
    answer each probe with the correct position — detection then completes in
    milliseconds. A tall height avoids RouterOS paginating long output.
    """

    def __init__(self, cols: int, rows: int) -> None:
        self.cols = max(1, cols)
        self.rows = max(1, rows)
        self.row = 1
        self.col = 1

    @staticmethod
    def _num(params: bytes, default: int = 1) -> int:
        first = params.split(b";")[0] if params else b""
        return int(first) if first.isdigit() else default

    def feed(self, chunk: bytes) -> bytes:
        """Advance the cursor over ``chunk``; return bytes to send back (replies)."""
        out = b""
        for m in _CSI_RE.finditer(chunk):
            params, letter, esc, nl = m.group(1), m.group(2), m.group(3), m.group(4)
            if letter:
                n = self._num(params)
                if letter == b"A":
                    self.row = max(1, self.row - n)
                elif letter == b"B":
                    self.row = min(self.rows, self.row + n)
                elif letter == b"C":
                    self.col = min(self.cols, self.col + n)
                elif letter == b"D":
                    self.col = max(1, self.col - n)
                elif letter in (b"H", b"f"):
                    parts = params.split(b";") if params else []
                    r = int(parts[0]) if parts and parts[0].isdigit() else 1
                    c = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
                    self.row = min(max(1, r), self.rows)
                    self.col = min(max(1, c), self.cols)
                elif letter == b"n" and params == b"6":
                    out += b"\x1b[%d;%dR" % (self.row, self.col)
                elif letter == b"c":
                    out += b"\x1b[?1;0c"
            elif esc == b"D":
                self.row = min(self.rows, self.row + 1)
            elif esc == b"M":
                self.row = max(1, self.row - 1)
            elif esc == b"Z":
                out += b"\x1b[?1;0c"
            elif nl == b"\r":
                self.col = 1
            elif nl == b"\n":
                self.row = min(self.rows, self.row + 1)
        return out


def _read_until_prompt(
    transport: Transport, timeout: float, responder: TerminalResponder | None = None
) -> tuple[str, bool]:
    """Accumulate output until a RouterOS prompt appears or ``timeout`` elapses.

    Returns ``(text, saw_prompt)`` with ANSI stripped.
    """
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = transport.read(min(2.0, deadline - time.time()))
        except SessionClosed:
            break
        if not chunk:
            continue
        if responder is not None:
            reply = responder.feed(chunk)
            if reply:
                transport.write(reply)
        buf += chunk  # strip escapes at byte level (keeps 8-bit CSI), then decode
        text = strip_ansi_bytes(buf).decode("utf-8", "replace")
        if _PROMPT_RE.search(text):
            return text, True
    return strip_ansi_bytes(buf).decode("utf-8", "replace"), False


def wait_for_prompt(
    transport: Transport, timeout: float = 25.0, responder: TerminalResponder | None = None
) -> None:
    """Block until the first shell prompt; raise :class:`AuthFailed` otherwise."""
    text, ok = _read_until_prompt(transport, timeout, responder)
    if not ok:
        if _FAIL_RE.search(text):
            raise AuthFailed(text.strip()[:200] or "authentication failed")
        raise AuthFailed("no prompt from router (authentication likely failed)")


def run_command(
    transport: Transport,
    command: str,
    timeout: float = 30.0,
    responder: TerminalResponder | None = None,
) -> str:
    """Send one RouterOS command and return its output (ANSI stripped)."""
    transport.write((command + "\r").encode())
    text, _ = _read_until_prompt(transport, timeout, responder)
    return text


def run_batch(
    transport: Transport,
    commands: tuple[str, ...] | list[str],
    timeout: float = 30.0,
    ready_timeout: float = 25.0,
) -> Iterator[tuple[str, str]]:
    """Wait for the shell, then run each command, yielding ``(command, output)``."""
    # Answer RouterOS's terminal size-detection so it doesn't stall; a tall
    # height keeps long output from being paginated.
    responder = TerminalResponder(cols=terminal_size()[0], rows=10000)
    wait_for_prompt(transport, ready_timeout, responder)
    for command in commands:
        yield command, run_command(transport, command, timeout, responder)


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
