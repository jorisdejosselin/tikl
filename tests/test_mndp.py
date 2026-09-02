"""MNDP parsing, verified against a real hAP be3 packet."""

from __future__ import annotations

from pathlib import Path

from tikl.mac.mndp import parse

FIXTURE = Path(__file__).parent / "fixtures" / "mndp_hap_be3.hex"


def _real_packet() -> bytes:
    return bytes.fromhex(FIXTURE.read_text().strip())


def test_parse_real_hap_be3() -> None:
    dev = parse(_real_packet())
    assert dev is not None
    assert dev.mac == "38:32:7a:26:8e:bd"
    assert dev.identity == "hAP"
    assert dev.version == "7.24.1 (stable) 2026-08-21 13:06:38"
    assert dev.platform == "MikroTik"
    assert dev.board == "MA53UG+HbeH"
    assert dev.software_id == "CAKW-KLHU"
    assert dev.interface == "bridgeLocal/ether1"
    assert dev.ipv4 == "192.168.137.80"
    assert dev.ipv6 == "fe80::3a32:7aff:fe26:8ebd"
    assert dev.uptime == 0x11DA


def test_parse_rejects_short() -> None:
    assert parse(b"\x00\x00") is None


def test_parse_requires_mac() -> None:
    # header + an identity TLV but no MAC TLV -> not a usable device
    pkt = b"\x00\x00\x00\x00" + b"\x00\x05\x00\x03abc"
    assert parse(pkt) is None


def test_parse_truncated_tlv_stops_cleanly() -> None:
    # MAC TLV then a TLV claiming more bytes than remain
    pkt = b"\x00\x00\x00\x00" + b"\x00\x01\x00\x06\x38\x32\x7a\x26\x8e\xbd" + b"\x00\x07\x00\xff"
    dev = parse(pkt)
    assert dev is not None
    assert dev.mac == "38:32:7a:26:8e:bd"
    assert dev.version == ""
