"""MAC-Telnet wire protocol: constants, framing, and helpers.

The pack/unpack logic and constants are lifted unchanged from the working
``mac_telnet.py`` seed script so behaviour is identical; only the organisation
changed. MAC-Telnet is a small reliable-delivery protocol carried in a
UDP-shaped payload broadcast at layer 2 on port 20561.
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import uuid
from typing import Any

MACTELNET_PORT = 20561
CLIENT_TYPE = 0x0015
CPMAGIC = 0x563412FF
HDR_LEN = 22
CP_HDR_LEN = 9

# Session packet types
PTYPE_START = 0
PTYPE_DATA = 1
PTYPE_ACK = 2
PTYPE_END = 255

# Control-packet types
CPTYPE_BEGINAUTH = 0
CPTYPE_ENCKEY = 1
CPTYPE_PASSWORD = 2
CPTYPE_USERNAME = 3
CPTYPE_TERMTYPE = 4
CPTYPE_TERMWIDTH = 5
CPTYPE_TERMHEIGHT = 6

# CSI (7-bit ESC[ and 8-bit \x9b), simple ESC sequences, and charset selects.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x9b[0-9;?]*[A-Za-z]|\x1b[()][0-9A-B]|\x1b[DMZ=>]")
_ANSI_BYTES_RE = re.compile(
    rb"\x1b\[[0-9;?]*[A-Za-z]|\x9b[0-9;?]*[A-Za-z]|\x1b[()][0-9A-B]|\x1b[DMZ=>]"
)


def mac_to_bytes(mac: str) -> bytes:
    """``"38:32:7A:26:8E:BD"`` (or dash-separated) -> 6 raw bytes."""
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def mac_to_str(b: bytes) -> str:
    """6 raw bytes -> lower-case colon-separated MAC string."""
    return ":".join(f"{x:02x}" for x in b)


def strip_ansi(s: str) -> str:
    """Remove the subset of ANSI escapes RouterOS emits."""
    return _ANSI_RE.sub("", s)


def strip_ansi_bytes(b: bytes) -> bytes:
    """Strip ANSI escapes at the byte level (before decoding).

    Must run on bytes: the 8-bit CSI byte 0x9b would otherwise become U+FFFD on
    a utf-8 decode and no longer match.
    """
    return _ANSI_BYTES_RE.sub(b"", b)


def sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


def fallback_local_mac() -> str:
    """A best-effort local MAC when the interface can't report one."""
    n = uuid.getnode()
    return ":".join(f"{(n >> (i * 8)) & 0xFF:02x}" for i in range(5, -1, -1))


def pack(
    ptype: int,
    src: str,
    dst: str,
    sk: int,
    counter: int,
    cpackets: list[tuple[int, bytes | str]] | None = None,
    plain: bytes | str | None = None,
) -> bytes:
    """Build a MAC-Telnet session packet."""
    buf = io.BytesIO()
    buf.write(struct.pack("BB", 1, ptype))
    buf.write(mac_to_bytes(src))
    buf.write(mac_to_bytes(dst))
    buf.write(struct.pack("!HHI", sk, CLIENT_TYPE, counter))
    for cptype, cpdata in cpackets or []:
        buf.write(struct.pack("!IB", CPMAGIC, cptype))
        data = cpdata or b""
        if isinstance(data, str):
            data = data.encode()
        buf.write(struct.pack("!I", len(data)))
        buf.write(data)
    if plain:
        if isinstance(plain, str):
            plain = plain.encode()
        buf.write(plain)
    return buf.getvalue()


def unpack(raw: bytes) -> tuple[dict[str, Any] | None, int]:
    """Parse a MAC-Telnet session packet. Returns ``(message, payload_len)``.

    ``message`` is ``None`` for anything that isn't a valid v1 client packet.
    """
    if len(raw) < HDR_LEN:
        return None, 0
    # MAC-Telnet framing is ASYMMETRIC (confirmed by capturing a real hAP be3
    # reply, tests/fixtures/mt_reply_start_ack.hex): the client SENDS the two
    # 16-bit fields as (seskey, clienttype) — see pack() — but the server REPLIES
    # with them as (clienttype, seskey). unpack() only ever parses server->client
    # packets, so here the first 16-bit field is clienttype and the second is the
    # session key. (Do not "symmetrise" this with pack — it breaks reception.)
    ver, ptype, src_r, dst_r, clienttype, seskey, cnt = struct.unpack_from("!BB6s6sHHI", raw, 0)
    if ver != 1 or clienttype != CLIENT_TYPE:
        return None, 0
    cpackets: list[tuple[int, bytes]] = []
    plain: bytes | None = None
    pos = HDR_LEN
    while pos < len(raw):
        start = pos
        if pos + CP_HDR_LEN <= len(raw):
            magic, cpt, cpdl = struct.unpack_from("!IBI", raw, pos)
            if magic == CPMAGIC and pos + CP_HDR_LEN + cpdl <= len(raw):
                pos += CP_HDR_LEN
                cpackets.append((cpt, raw[pos : pos + cpdl]))
                pos += cpdl
                continue
        plain = raw[start:]
        break
    msg = {
        "type": ptype,
        "src": mac_to_str(src_r),
        "dst": mac_to_str(dst_r),
        "sk": seskey,
        "cnt": cnt,
        "cpackets": cpackets,
        "plain": plain,
    }
    return msg, len(raw) - HDR_LEN
