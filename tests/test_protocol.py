"""MAC-Telnet framing.

Note the protocol is ASYMMETRIC: pack() emits the client->server header order
(seskey, clienttype); unpack() parses the server->client order
(clienttype, seskey). These tests reflect that — verified against a real hAP be3
reply (tests/fixtures/mt_reply_start_ack.hex).
"""

from __future__ import annotations

import struct
from pathlib import Path

from tikl.mac import protocol as p

SRC = "aa:bb:cc:dd:ee:01"
DST = "38:32:7a:26:8e:bd"
REPLY_FIXTURE = Path(__file__).parent / "fixtures" / "mt_reply_start_ack.hex"


def _server_packet(
    ptype: int,
    src: str,
    dst: str,
    sk: int,
    counter: int,
    cpackets: list[tuple[int, bytes | str]] | None = None,
    plain: bytes | str | None = None,
) -> bytes:
    """A server->client packet: like pack() but with the two 16-bit header
    fields swapped into (clienttype, seskey) order, as the router sends them."""
    b = bytearray(p.pack(ptype, src, dst, sk, counter, cpackets, plain))
    b[14:16], b[16:18] = b[16:18], b[14:16]
    return bytes(b)


def test_mac_str_bytes_roundtrip() -> None:
    assert p.mac_to_str(p.mac_to_bytes(DST)) == DST
    assert p.mac_to_bytes("38-32-7A-26-8E-BD") == p.mac_to_bytes(DST)


def test_pack_emits_client_header_order() -> None:
    raw = p.pack(p.PTYPE_DATA, SRC, DST, sk=0x1234, counter=7, plain=b"x")
    h1, h2, cnt = struct.unpack_from("!HHI", raw, 14)
    assert h1 == 0x1234  # seskey first on the wire (client -> server)
    assert h2 == p.CLIENT_TYPE
    assert cnt == 7


def test_unpack_real_hardware_reply() -> None:
    raw = bytes.fromhex(REPLY_FIXTURE.read_text().strip())
    msg, plen = p.unpack(raw)
    assert msg is not None
    assert msg["type"] == p.PTYPE_ACK
    assert msg["src"] == DST
    assert msg["sk"] == 0x60E2  # our session key, echoed in the 2nd field
    assert msg["cnt"] == 0
    assert plen == 0


def test_unpack_server_plain_roundtrip() -> None:
    raw = _server_packet(p.PTYPE_DATA, DST, SRC, sk=0x60E2, counter=7, plain=b"/system\r")
    msg, plen = p.unpack(raw)
    assert msg is not None
    assert msg["sk"] == 0x60E2
    assert msg["cnt"] == 7
    assert msg["plain"] == b"/system\r"
    assert plen == len(raw) - p.HDR_LEN


def test_unpack_server_control_packets() -> None:
    cps: list[tuple[int, bytes | str]] = [
        (p.CPTYPE_ENCKEY, b"\x01\x02\x03\x04"),
        (p.CPTYPE_USERNAME, "admin"),
    ]
    raw = _server_packet(p.PTYPE_DATA, DST, SRC, sk=1, counter=0, cpackets=cps)
    msg, _ = p.unpack(raw)
    assert msg is not None
    assert msg["cpackets"][0] == (p.CPTYPE_ENCKEY, b"\x01\x02\x03\x04")
    assert msg["cpackets"][1] == (p.CPTYPE_USERNAME, b"admin")
    assert msg["plain"] is None


def test_unpack_rejects_short_and_wrong_client_type() -> None:
    assert p.unpack(b"\x00" * 4) == (None, 0)
    raw = bytearray(_server_packet(p.PTYPE_START, DST, SRC, sk=1, counter=0))
    raw[14:16] = b"\xff\xff"  # corrupt clienttype (1st field in server order)
    assert p.unpack(bytes(raw)) == (None, 0)


def test_strip_ansi() -> None:
    assert p.strip_ansi("\x1b[32mhello\x1b[0m") == "hello"
    assert p.strip_ansi("[admin@MikroTik] > ") == "[admin@MikroTik] > "
