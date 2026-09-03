"""SSH transport, with paramiko mocked (no network)."""

from __future__ import annotations

import pytest

import tikl.ssh.client as ssh_mod
from tikl.errors import ConnectionFailed, SessionClosed
from tikl.ssh.client import SshTransport


class FakeChannel:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self._recv_queue: list[bytes] = [b"[admin@MikroTik] > "]
        self.resized: tuple[int, int] | None = None
        self.closed = False
        self._exit = False

    def settimeout(self, t: float) -> None: ...
    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv_ready(self) -> bool:
        return bool(self._recv_queue)

    def recv(self, n: int) -> bytes:
        return self._recv_queue.pop(0) if self._recv_queue else b""

    def exit_status_ready(self) -> bool:
        return self._exit

    def resize_pty(self, width: int, height: int) -> None:
        self.resized = (width, height)

    def close(self) -> None:
        self.closed = True


class FakeTransport:
    def set_keepalive(self, interval: int) -> None:
        self.interval = interval


class FakeClient:
    last: FakeClient | None = None

    def __init__(self) -> None:
        self.connect_kwargs: dict = {}
        self.channel = FakeChannel()
        self.closed = False
        FakeClient.last = self

    def set_missing_host_key_policy(self, policy: object) -> None: ...
    def connect(self, host: str, **kwargs: object) -> None:
        self.connect_kwargs = {"host": host, **kwargs}

    def get_transport(self) -> FakeTransport:
        return FakeTransport()

    def invoke_shell(self, **kwargs: object) -> FakeChannel:
        return self.channel

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def patched(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ssh_mod.paramiko, "SSHClient", FakeClient)
    # select.select over the fake channel: report ready when data is queued
    monkeypatch.setattr(
        ssh_mod.select,
        "select",
        lambda r, w, x, t: ((r if r and r[0].recv_ready() else []), [], []),
    )


def test_connect_uses_safe_defaults(patched: None) -> None:
    t = SshTransport("192.168.88.1", user="admin", password="pw", port=2222)
    t.connect()
    kw = FakeClient.last.connect_kwargs
    assert kw["host"] == "192.168.88.1"
    assert kw["port"] == 2222
    assert kw["username"] == "admin"
    assert kw["look_for_keys"] is False
    assert kw["allow_agent"] is False


def test_write_read_resize(patched: None) -> None:
    t = SshTransport("host", password="pw")
    t.connect()
    t.write(b"/system resource print\r")
    assert t._chan.sent == [b"/system resource print\r"]  # type: ignore[union-attr]
    assert t.read(0.1) == b"[admin@MikroTik] > "
    assert t.read(0.1) == b""  # nothing queued -> idle
    t.resize(120, 40)
    assert t._chan.resized == (120, 40)  # type: ignore[union-attr]
    t.close()
    assert FakeClient.last.closed


def test_auth_failure_wrapped(patched: None, monkeypatch: pytest.MonkeyPatch) -> None:
    def bad_connect(self: FakeClient, host: str, **kwargs: object) -> None:
        raise ssh_mod.paramiko.AuthenticationException("bad creds")

    monkeypatch.setattr(FakeClient, "connect", bad_connect)
    with pytest.raises(ConnectionFailed):
        SshTransport("host", password="pw").connect()


def test_read_raises_when_channel_closed(patched: None) -> None:
    t = SshTransport("host", password="pw")
    t.connect()
    t._chan._recv_queue.clear()  # type: ignore[union-attr]
    t._chan._exit = True  # type: ignore[union-attr]
    with pytest.raises(SessionClosed):
        t.read(0.1)
