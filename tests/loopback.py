"""In-process fake MAC-Telnet peer for CI (DESIGN.md #8, ADR 0003).

Not a test module itself — support code for test_loopback.py. Provides a pair of
in-memory Links and a `LoopbackPeer` that speaks enough of the server side of
MAC-Telnet to drive the real `MacTransport` through START -> EC-SRP5 key
exchange -> shell, with no root and no hardware.

The peer does NOT verify the EC-SRP5 confirmation cryptographically (the server
side of EC-SRP5 is out of scope; crypto correctness is anchored by the frozen
curve vectors and the live hardware validation). It exercises the framing, the
reliable-delivery state machine, the client's full crypto path (the client
really computes a confirmation against the peer's server key), and the session
command loop.
"""

from __future__ import annotations

import queue
import secrets
import struct
import threading
from collections.abc import Callable

from tikl.mac import protocol as p
from tikl.mac.curve import WCurve


class InMemoryLink:
    """One endpoint of an in-memory L2 link (implements tikl.mac.link.Link)."""

    def __init__(self, hwaddr: str) -> None:
        self.hwaddr = hwaddr
        self._on: Callable[[bytes], None] | None = None
        self.peer: InMemoryLink | None = None

    def start(self, on_payload: Callable[[bytes], None]) -> None:
        self._on = on_payload

    def send(self, payload: bytes) -> None:
        if self.peer is not None and self.peer._on is not None:
            self.peer._on(payload)

    def close(self) -> None:
        self._on = None


def link_pair(client_mac: str, server_mac: str) -> tuple[InMemoryLink, InMemoryLink]:
    client, server = InMemoryLink(client_mac), InMemoryLink(server_mac)
    client.peer, server.peer = server, client
    return client, server


def _swap_header_fields(raw: bytes) -> bytes:
    """Swap the two 16-bit header fields (seskey <-> clienttype) at bytes 14-18."""
    b = bytearray(raw)
    b[14:16], b[16:18] = b[16:18], b[14:16]
    return bytes(b)


class LoopbackPeer:
    """A fake RouterOS MAC-Telnet server, driven on its own thread."""

    def __init__(
        self,
        link: InMemoryLink,
        client_mac: str,
        server_mac: str,
        *,
        prompt: bytes = b"[admin@test] > ",
        server_private: bytes | None = None,
        salt: bytes | None = None,
        command_output: bytes = b"result\r\n",
    ) -> None:
        self.link = link
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.prompt = prompt
        self.command_output = command_output
        self._w = WCurve()
        self._server_private = server_private or secrets.token_bytes(32)
        self._salt = salt or secrets.token_bytes(16)

        self.sk = 0
        self.out_c = 0
        self.received_confirmation: bytes | None = None
        self.commands: list[bytes] = []
        self._q: queue.Queue[bytes] = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        link.start(self._q.put)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # -- framing -----------------------------------------------------------

    def _send(
        self,
        ptype: int,
        cpackets: list[tuple[int, bytes | str]] | None = None,
        plain: bytes | str | None = None,
    ) -> None:
        # Client parses server packets as (clienttype, seskey): build a normal
        # client-order packet, then swap the two header fields.
        raw = p.pack(ptype, self.server_mac, self.client_mac, self.sk, self.out_c, cpackets, plain)
        self.link.send(_swap_header_fields(raw))

    def _advance(self, payload_len: int) -> None:
        self.out_c += payload_len

    # -- state machine -----------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                raw = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            # Client sends (seskey, clienttype); swap so unpack() reads it right.
            msg, _ = p.unpack(_swap_header_fields(raw))
            if msg is None:
                continue
            self.sk = msg["sk"]
            self._handle(msg)

    def _handle(self, msg: dict) -> None:
        if msg["type"] == p.PTYPE_START:
            self._send(p.PTYPE_ACK)
            return
        if msg["type"] == p.PTYPE_ACK:
            return
        if msg["type"] != p.PTYPE_DATA:
            return

        cptypes = {t for t, _ in msg["cpackets"]}
        if p.CPTYPE_ENCKEY in cptypes and p.CPTYPE_PASSWORD not in cptypes:
            self._reply_server_key()
        elif p.CPTYPE_PASSWORD in cptypes:
            for t, data in msg["cpackets"]:
                if t == p.CPTYPE_PASSWORD:
                    self.received_confirmation = data
            self._send_shell(self.prompt)
        elif msg.get("plain"):
            self.commands.append(msg["plain"])
            self._send_shell(self.command_output + self.prompt)

    def _reply_server_key(self) -> None:
        server_public, server_parity = self._w.gen_public_key(self._server_private)
        enckey = server_public + bytes([server_parity]) + self._salt
        self._send(p.PTYPE_DATA, cpackets=[(p.CPTYPE_ENCKEY, enckey)])
        self._advance(p.CP_HDR_LEN + len(enckey))

    def _send_shell(self, data: bytes) -> None:
        self._send(p.PTYPE_DATA, plain=data)
        self._advance(len(data))


def struct_le16(value: int) -> bytes:
    return struct.pack("<H", value)
