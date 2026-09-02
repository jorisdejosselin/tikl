"""SSH transport — the convenient path when the router has a reachable IP.

Implements the :class:`tikl.transport.Transport` byte-channel seam over a
paramiko interactive-shell channel, so :mod:`tikl.session` drives it exactly
like MAC-Telnet. No pcap, no root.
"""

from __future__ import annotations

import select

import paramiko

from ..errors import ConnectionFailed, SessionClosed


class SshTransport:
    """An SSH byte channel to a RouterOS device."""

    def __init__(
        self,
        host: str,
        user: str = "admin",
        password: str = "",
        port: int = 22,
        *,
        term: str = "vt100",
        term_size: tuple[int, int] = (80, 24),
        connect_timeout: float = 10.0,
        legacy_algorithms: bool = False,
    ) -> None:
        self.host = host
        self.user = user
        self.pwd = password
        self.port = port
        self.term = term
        self.cols, self.rows = term_size
        self.connect_timeout = connect_timeout
        self.legacy_algorithms = legacy_algorithms
        self._client: paramiko.SSHClient | None = None
        self._chan: paramiko.Channel | None = None

    def connect(self) -> None:
        client = paramiko.SSHClient()
        # Recovery tool: trust-on-first-use for boxes you own. A stricter policy
        # (known_hosts) is a possible later option.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # RouterOS builds occasionally need older SSH primitives re-enabled.
        disabled: dict[str, list[str]] = {"keys": [], "kex": [], "ciphers": []}
        kwargs = {} if self.legacy_algorithms else {"disabled_algorithms": disabled}
        try:
            client.connect(
                self.host,
                port=self.port,
                username=self.user,
                password=self.pwd,
                look_for_keys=False,
                allow_agent=False,
                timeout=self.connect_timeout,
                **kwargs,
            )
        except paramiko.AuthenticationException as exc:
            raise ConnectionFailed(f"SSH authentication failed: {exc}") from exc
        except (OSError, paramiko.SSHException) as exc:
            raise ConnectionFailed(f"SSH connection failed: {exc}") from exc
        self._client = client
        self._chan = client.invoke_shell(term=self.term, width=self.cols, height=self.rows)
        self._chan.settimeout(0.0)

    def write(self, data: bytes) -> None:
        if self._chan is None:
            raise SessionClosed("SSH channel not open")
        self._chan.sendall(data)

    def read(self, timeout: float) -> bytes:
        if self._chan is None:
            raise SessionClosed("SSH channel not open")
        if self._chan.exit_status_ready() and not self._chan.recv_ready():
            raise SessionClosed("SSH channel closed")
        ready, _, _ = select.select([self._chan], [], [], timeout)
        if not ready or not self._chan.recv_ready():
            return b""
        data = bytes(self._chan.recv(4096))
        if data == b"":
            raise SessionClosed("SSH channel closed")
        return data

    def resize(self, cols: int, rows: int) -> None:
        self.cols, self.rows = cols, rows
        if self._chan is not None:
            self._chan.resize_pty(width=cols, height=rows)

    def close(self) -> None:
        if self._chan is not None:
            self._chan.close()
            self._chan = None
        if self._client is not None:
            self._client.close()
            self._client = None
