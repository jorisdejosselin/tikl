"""MAC-Telnet transport: reliable-broadcast state machine + EC-SRP5 auth.

Implements the :class:`tikl.transport.Transport` byte-channel seam. The session
state machine, counters, ACKing, sniffer thread and EC-SRP5 handshake are the
behaviour of the seed ``mac_telnet.py``; here they sit behind
``connect/write/read/resize/close`` so :mod:`tikl.session` can drive them the
same way it drives SSH.

Requires libpcap (Linux/macOS) or Npcap (Windows) and root/Administrator.
"""

from __future__ import annotations

import contextlib
import queue
import random
import secrets
import struct
import time
from collections.abc import Callable
from typing import Any

from ..errors import AuthFailed, ConnectionFailed, SessionClosed
from . import protocol as p
from .curve import WCurve
from .ecsrp5 import HandshakeCapture, compute_confirmation
from .link import Link, ScapyLink, candidate_ifaces, local_mac

CaptureHook = Callable[[HandshakeCapture], None]

__all__ = ["MacTransport", "local_mac"]


class MacTransport:
    """A MAC-Telnet byte channel to a RouterOS device."""

    def __init__(
        self,
        dst_mac: str,
        user: str = "admin",
        password: str = "",
        iface: str | None = None,
        *,
        term: str = "vt100",
        term_size: tuple[int, int] = (220, 50),
        client_private: bytes | None = None,
        on_capture: CaptureHook | None = None,
        link: Link | None = None,
    ) -> None:
        self.dst = dst_mac
        self.iface = iface
        self.user = user
        self.pwd = password
        self.term = term
        self.cols, self.rows = term_size
        # Testing seam: a fixed client_private makes the handshake deterministic
        # so the loopback peer can replay the golden KAT (DESIGN.md #8).
        self._client_private = client_private
        self._on_capture = on_capture

        self.sk = random.randint(1, 0xFFFF)
        self.out_c = 0
        self.in_c = -1
        self._q: queue.Queue[tuple[dict[str, Any], int]] = queue.Queue()
        self._sport = random.randint(10000, 55000)
        self._w = WCurve()
        # When no iface and no injected link, auto-detect the NIC at connect().
        self._auto_iface = link is None and iface is None
        # A Link handles L2 I/O; default is the real scapy link (needs root).
        self._link: Link = link if link is not None else ScapyLink(iface, self._sport)
        self.me = self._link.hwaddr

    # -- raw send/recv -----------------------------------------------------

    def _send_raw(self, payload: bytes) -> None:
        self._link.send(payload)

    def _emit(
        self,
        ptype: int,
        cpackets: list[tuple[int, bytes | str]] | None = None,
        plain: bytes | str | None = None,
    ) -> bytes:
        data = p.pack(ptype, self.me, self.dst, self.sk, self.out_c, cpackets, plain)
        self._send_raw(data)
        return data

    def _start_sniffer(self) -> None:
        sk = self.sk

        def on_payload(raw: bytes) -> None:
            msg, plen = p.unpack(raw)
            if msg and msg["sk"] == sk:
                self._q.put((msg, plen))

        self._link.start(on_payload)

    def _recv(self, timeout: float, skip_ack: bool = False) -> dict[str, Any] | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            try:
                msg, plen = self._q.get(timeout=max(0.05, remaining))
            except queue.Empty:
                return None
            if skip_ack and msg["type"] == p.PTYPE_ACK:
                continue
            if msg["type"] == p.PTYPE_DATA:
                self._send_raw(p.pack(p.PTYPE_ACK, self.me, self.dst, self.sk, msg["cnt"] + plen))
                if 0 <= (self.in_c - msg["cnt"]) < 65535:
                    continue
                self.in_c = msg["cnt"]
            return msg
        return None

    def _detect_iface(self) -> str | None:
        """Find which interface the router answers MAC-Telnet on (START probe).

        Uses a throwaway session key per probe so the real connect() opens a
        fresh session the router will answer (reusing the key would look like a
        duplicate START and be ignored).
        """
        for iface in candidate_ifaces():
            probe_sk = random.randint(1, 0xFFFF)
            link = ScapyLink(iface, self._sport)
            hit: queue.Queue[bool] = queue.Queue()

            def on_payload(raw: bytes, _hit: queue.Queue[bool] = hit, _sk: int = probe_sk) -> None:
                msg, _ = p.unpack(raw)
                if msg and msg["sk"] == _sk:
                    _hit.put(True)

            link.start(on_payload)
            time.sleep(0.2)
            link.send(p.pack(p.PTYPE_START, link.hwaddr, self.dst, probe_sk, 0))
            try:
                hit.get(timeout=1.2)
                link.close()
                return iface
            except queue.Empty:
                link.close()
        return None

    # -- Transport interface ----------------------------------------------

    def connect(self) -> None:
        if self._auto_iface:
            iface = self._detect_iface()
            if iface is None:
                raise ConnectionFailed(
                    "no MAC-Telnet reply on any interface "
                    "(wrong MAC, or router not reachable at layer 2)"
                )
            self.iface = iface
            self._link = ScapyLink(iface, self._sport)
            self.me = self._link.hwaddr

        self._start_sniffer()
        time.sleep(0.3)

        self._send_raw(p.pack(p.PTYPE_START, self.me, self.dst, self.sk, 0))
        if not self._recv(4):
            raise ConnectionFailed("no reply to SESSION_START (wrong MAC or interface?)")

        client_private = self._client_private or secrets.token_bytes(32)
        client_public, client_parity = self._w.gen_public_key(client_private)
        key_data = (
            self.user.encode() + b"\x00" + client_public + int(client_parity).to_bytes(1, "big")
        )
        data = self._emit(
            p.PTYPE_DATA,
            cpackets=[(p.CPTYPE_BEGINAUTH, b""), (p.CPTYPE_ENCKEY, key_data)],
        )
        self.out_c += len(data) - p.HDR_LEN

        reply = self._recv(8, skip_ack=True)
        if not reply or reply["type"] != p.PTYPE_DATA:
            raise ConnectionFailed("no server key reply")

        server_public = server_parity = salt = None
        for cptype, cpdata in reply.get("cpackets", []):
            if cptype == p.CPTYPE_ENCKEY:
                server_public = cpdata[:0x20]
                server_parity = cpdata[0x20]
                salt = cpdata[0x21:]
                break

        if server_public is None or server_parity is None or salt is None or len(salt) != 16:
            raise AuthFailed("server key invalid — username may not exist on router")

        confirmation = compute_confirmation(
            self._w,
            self.user,
            self.pwd,
            client_private,
            client_public,
            server_public,
            server_parity,
            salt,
        )

        if self._on_capture is not None:
            self._on_capture(
                HandshakeCapture(
                    username=self.user,
                    password=self.pwd,
                    client_private=client_private.hex(),
                    client_public=client_public.hex(),
                    client_parity=int(client_parity),
                    server_public=server_public.hex(),
                    server_parity=int(server_parity),
                    salt=salt.hex(),
                    confirmation=confirmation.hex(),
                )
            )

        data = self._emit(
            p.PTYPE_DATA,
            cpackets=[
                (p.CPTYPE_PASSWORD, confirmation),
                (p.CPTYPE_USERNAME, self.user.encode()),
                (p.CPTYPE_TERMTYPE, self.term.encode()),
                (p.CPTYPE_TERMWIDTH, struct.pack("<H", self.cols)),
                (p.CPTYPE_TERMHEIGHT, struct.pack("<H", self.rows)),
            ],
        )
        self.out_c += len(data) - p.HDR_LEN

    def write(self, data: bytes) -> None:
        sent = self._emit(p.PTYPE_DATA, plain=data)
        self.out_c += len(sent) - p.HDR_LEN

    def read(self, timeout: float) -> bytes:
        msg = self._recv(timeout, skip_ack=True)
        if msg is None:
            return b""
        if msg["type"] == p.PTYPE_END:
            raise SessionClosed("router ended the session")
        plain = msg.get("plain")
        return plain if plain else b""

    def resize(self, cols: int, rows: int) -> None:
        self.cols, self.rows = cols, rows
        data = self._emit(
            p.PTYPE_DATA,
            cpackets=[
                (p.CPTYPE_TERMWIDTH, struct.pack("<H", cols)),
                (p.CPTYPE_TERMHEIGHT, struct.pack("<H", rows)),
            ],
        )
        self.out_c += len(data) - p.HDR_LEN

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._emit(p.PTYPE_END)
        self._link.close()
