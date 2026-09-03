"""MNDP parsing, verified against a real hAP be3 packet."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tikl.mac import mndp
from tikl.mac.mndp import _broadcast_targets, parse

FIXTURE = Path(__file__).parent / "fixtures" / "mndp_hap_be3.hex"

_IFCONFIG = """\
lo0: flags=8049 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863 mtu 1500
\tinet 192.168.178.152 netmask 0xffffff00 broadcast 192.168.178.255
en6: flags=8863 mtu 1500
\tinet 192.168.88.254 netmask 0xffffff00 broadcast 192.168.88.255
"""

_IP_ADDR = (
    "1: lo    inet 127.0.0.1/8 scope host lo\n"
    "2: eth0    inet 192.168.88.254/24 brd 192.168.88.255 scope global eth0\n"
)


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


def _fake_run(stdout: str):
    def run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    return run


def test_broadcast_targets_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mndp.sys, "platform", "darwin")
    monkeypatch.setattr(mndp.subprocess, "run", _fake_run(_IFCONFIG))
    targets = _broadcast_targets()
    assert (None, "255.255.255.255") in targets
    assert ("192.168.178.152", "192.168.178.255") in targets
    assert ("192.168.88.254", "192.168.88.255") in targets
    # loopback excluded
    assert all(src != "127.0.0.1" for src, _ in targets)


def test_broadcast_targets_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mndp.sys, "platform", "linux")
    monkeypatch.setattr(mndp.subprocess, "run", _fake_run(_IP_ADDR))
    targets = _broadcast_targets()
    assert ("192.168.88.254", "192.168.88.255") in targets
    assert all(src != "127.0.0.1" for src, _ in targets)
