"""Session command loop, driven over a fake byte-channel transport.

This is a minimal stand-in for the full loopback peer (DESIGN.md #8): it feeds
canned RouterOS output so the shared prompt/batch logic is exercised with no
hardware and no root.
"""

from __future__ import annotations

import pytest

from tikl.errors import AuthFailed, SessionClosed
from tikl.session import run_batch, run_command, wait_for_prompt

PROMPT = b"[admin@MikroTik] > "


class FakeTransport:
    """Replays a scripted sequence of read() chunks; records writes."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.writes: list[bytes] = []
        self.closed = False

    def connect(self) -> None: ...

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def read(self, timeout: float) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def resize(self, cols: int, rows: int) -> None: ...

    def close(self) -> None:
        self.closed = True


def test_wait_for_prompt_ok() -> None:
    t = FakeTransport([b"\r\n\r\n  MikroTik RouterOS\r\n", PROMPT])
    wait_for_prompt(t, timeout=2)  # must not raise


def test_first_login_prompts_are_auto_handled() -> None:
    # Factory-fresh: software license [Y/n] then a forced password change, before
    # the shell prompt. wait_for_prompt must decline (n) and skip (Ctrl-C).
    t = FakeTransport(
        [
            b"  MikroTik RouterOS 7.24.1\r\n",
            b"Do you want to see the software license? [Y/n]: ",
            b"\r\nChange your password (Ctrl-C to skip)\r\nnew password> ",
            b"\r\n" + PROMPT,
        ]
    )
    wait_for_prompt(t, timeout=2)  # must not raise
    assert b"n\r" in t.writes  # declined the license
    assert b"\x03" in t.writes  # Ctrl-C skipped the password change


def test_wait_for_prompt_auth_failure() -> None:
    t = FakeTransport([b"login failed, incorrect password\r\n"])
    with pytest.raises(AuthFailed):
        wait_for_prompt(t, timeout=1)


def test_run_command_returns_output_and_sends_cr() -> None:
    t = FakeTransport([b"uptime: 1d2h\r\n", PROMPT])
    out = run_command(t, "/system resource print", timeout=2)
    assert "uptime: 1d2h" in out
    assert t.writes == [b"/system resource print\r"]


def test_run_batch_yields_each_command() -> None:
    t = FakeTransport(
        [
            PROMPT,  # initial ready prompt
            b"addr 192.168.88.1/24\r\n",
            PROMPT,
            b"dhcp bound\r\n",
            PROMPT,
        ]
    )
    results = list(run_batch(t, ["/ip address print", "/ip dhcp-client print"], timeout=2))
    assert [c for c, _ in results] == ["/ip address print", "/ip dhcp-client print"]
    assert "192.168.88.1" in results[0][1]
    assert "dhcp bound" in results[1][1]


def test_read_until_prompt_handles_session_closed() -> None:
    class Closing(FakeTransport):
        def read(self, timeout: float) -> bytes:
            raise SessionClosed

    # Router ended the session after login -> explicit rejection message.
    with pytest.raises(AuthFailed, match="rejected"):
        wait_for_prompt(Closing([]), timeout=1)


def test_wait_for_prompt_silent_timeout() -> None:
    # No data at all -> "no response" (distinct from an explicit rejection).
    with pytest.raises(AuthFailed, match="no response"):
        wait_for_prompt(FakeTransport([]), timeout=0.2)
