"""MikroTik Neighbor Discovery Protocol (MNDP).

RouterOS devices announce themselves over UDP broadcast on port 5678. MNDP is
received over a plain UDP socket, so discovery needs **no root and no pcap** —
unlike MAC-Telnet itself. That makes ``tikl discover`` and the bare-``tikl``
picker usable as an unprivileged first step in the recovery flow.

Packet layout: a 4-byte header followed by TLVs, each ``(type: u16, len: u16,
value)`` big-endian. Parsed against a real hAP be3 packet (see
tests/fixtures/mndp_hap_be3.hex).
"""

from __future__ import annotations

import contextlib
import dataclasses
import socket
import struct
import time

MNDP_PORT = 5678
MNDP_PROBE = b"\x00\x00\x00\x00"

# TLV type codes
_T_MAC = 1
_T_IDENTITY = 5
_T_VERSION = 7
_T_PLATFORM = 8
_T_UPTIME = 10
_T_SOFTWARE_ID = 11
_T_BOARD = 12
_T_UNPACK = 14
_T_IPV6 = 15
_T_INTERFACE = 16
_T_IPV4 = 17


@dataclasses.dataclass
class MndpDevice:
    """A MikroTik device heard via MNDP."""

    mac: str
    identity: str = ""
    version: str = ""
    platform: str = ""
    board: str = ""
    software_id: str = ""
    uptime: int = 0
    interface: str = ""  # the router's own interface it announced from
    ipv4: str = ""
    ipv6: str = ""
    heard_from: str = ""  # source IP of the UDP datagram


def _mac_from_bytes(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse(data: bytes) -> MndpDevice | None:
    """Parse one MNDP datagram into an :class:`MndpDevice` (``None`` if invalid)."""
    if len(data) < 4:
        return None
    dev = MndpDevice(mac="")
    pos = 4  # skip header
    while pos + 4 <= len(data):
        ttype, tlen = struct.unpack_from("!HH", data, pos)
        pos += 4
        if pos + tlen > len(data):
            break
        value = data[pos : pos + tlen]
        pos += tlen
        if ttype == _T_MAC and tlen == 6:
            dev.mac = _mac_from_bytes(value)
        elif ttype == _T_IDENTITY:
            dev.identity = value.decode("utf-8", "replace")
        elif ttype == _T_VERSION:
            dev.version = value.decode("utf-8", "replace")
        elif ttype == _T_PLATFORM:
            dev.platform = value.decode("utf-8", "replace")
        elif ttype == _T_SOFTWARE_ID:
            dev.software_id = value.decode("utf-8", "replace")
        elif ttype == _T_BOARD:
            dev.board = value.decode("utf-8", "replace")
        elif ttype == _T_UPTIME and tlen == 4:
            dev.uptime = struct.unpack("<I", value)[0]
        elif ttype == _T_INTERFACE:
            dev.interface = value.decode("utf-8", "replace")
        elif ttype == _T_IPV4 and tlen == 4:
            dev.ipv4 = socket.inet_ntoa(value)
        elif ttype == _T_IPV6 and tlen == 16:
            dev.ipv6 = socket.inet_ntop(socket.AF_INET6, value)
    if not dev.mac:
        return None
    return dev


def _local_ipv4s() -> list[str]:
    """Best-effort list of local IPv4 addresses (one per interface), via scapy.

    Used only to steer broadcast probes out every interface; failures are
    non-fatal (we still send a limited broadcast on the default route).
    """
    addrs: set[str] = set()
    try:
        from scapy.all import get_if_addr, get_if_list  # noqa: PLC0415

        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
            except Exception:
                continue
            if addr and addr != "0.0.0.0" and not addr.startswith("127."):
                addrs.add(addr)
    except Exception:
        pass
    return sorted(addrs)


def _send_probes() -> None:
    """Broadcast an MNDP probe out every interface so routers reply at once.

    A single limited broadcast only egresses the default route, so a router on
    a non-default NIC is otherwise found only via its periodic announcement.
    Binding a probe socket to each local address steers one out each interface.
    """
    for src in [None, *_local_ipv4s()]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if src is not None:
                s.bind((src, 0))
            s.sendto(MNDP_PROBE, ("255.255.255.255", MNDP_PORT))
            s.close()
        except OSError:
            continue


def _open_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        with contextlib.suppress(OSError):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("0.0.0.0", MNDP_PORT))
    return s


def discover(timeout: float = 4.0, probe: bool = True) -> list[MndpDevice]:
    """Listen for MNDP announcements for ``timeout`` seconds; return unique devices.

    Sends a broadcast probe first (routers reply immediately) then collects both
    solicited and periodic announcements, de-duplicated by MAC.
    """
    sock = _open_socket()
    try:
        if probe:
            _send_probes()
        found: dict[str, MndpDevice] = {}
        deadline = time.time() + timeout
        while time.time() < deadline:
            sock.settimeout(max(0.1, deadline - time.time()))
            try:
                data, addr = sock.recvfrom(4096)
            except (TimeoutError, OSError):
                break
            dev = parse(data)
            if dev is not None:
                dev.heard_from = addr[0]
                found[dev.mac] = dev
        return list(found.values())
    finally:
        sock.close()
