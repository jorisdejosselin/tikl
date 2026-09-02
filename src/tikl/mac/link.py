"""The L2 I/O seam under MAC-Telnet.

`MacTransport` speaks the MAC-Telnet protocol; a `Link` moves raw payload bytes
on and off the wire. The real link (`ScapyLink`) broadcasts via scapy and needs
root + pcap; tests inject an in-memory link instead, so the whole state machine
runs in CI with no hardware (DESIGN.md #8).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Protocol

from . import protocol as p


class Link(Protocol):
    """Moves raw MAC-Telnet payloads between this host and the router."""

    hwaddr: str

    def start(self, on_payload: Callable[[bytes], None]) -> None:
        """Begin delivering received payloads to ``on_payload``."""
        ...

    def send(self, payload: bytes) -> None:
        """Transmit one raw payload."""
        ...

    def close(self) -> None: ...


def local_mac(iface: str | None) -> str:
    """MAC of ``iface`` via scapy, falling back to the host node id."""
    try:
        from scapy.all import get_if_hwaddr  # noqa: PLC0415

        if iface:
            return str(get_if_hwaddr(iface))
    except Exception:
        pass
    return p.fallback_local_mac()


class ScapyLink:
    """Real L2 link: UDP broadcast on port 20561 via scapy. Needs root + pcap."""

    def __init__(self, iface: str | None, sport: int) -> None:
        self.iface = iface
        self.sport = sport
        self.hwaddr = local_mac(iface)
        self._stop = threading.Event()

    def start(self, on_payload: Callable[[bytes], None]) -> None:
        from scapy.all import UDP, Raw, sniff  # noqa: PLC0415

        sport = self.sport

        def handler(pkt: object) -> None:
            if UDP not in pkt or Raw not in pkt:  # type: ignore[operator]
                return
            if pkt[UDP].dport != sport:  # type: ignore[index]
                return
            on_payload(bytes(pkt[Raw]))  # type: ignore[index]

        threading.Thread(
            target=sniff,
            kwargs={
                "iface": self.iface,
                "prn": handler,
                "store": False,
                "filter": f"udp dst port {sport}",
                "stop_filter": lambda _: self._stop.is_set(),
            },
            daemon=True,
        ).start()

    def send(self, payload: bytes) -> None:
        from scapy.all import IP, UDP, Ether, Raw, sendp  # noqa: PLC0415

        pkt = (
            Ether(src=self.hwaddr, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=self.sport, dport=p.MACTELNET_PORT)
            / Raw(load=payload)
        )
        sendp(pkt, iface=self.iface, verbose=False)

    def close(self) -> None:
        self._stop.set()
