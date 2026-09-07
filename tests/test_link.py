"""ScapyLink privilege-error handling (issue #4)."""

from __future__ import annotations

import pytest
import scapy.all as scapy
from scapy.error import Scapy_Exception

from tikl.errors import NeedsPrivileges
from tikl.mac.link import ScapyLink


def test_send_permission_error_becomes_needsprivileges(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise Scapy_Exception("Permission denied: could not open /dev/bpf0")

    monkeypatch.setattr(scapy, "sendp", boom)
    link = ScapyLink(iface=None, sport=20000)
    with pytest.raises(NeedsPrivileges, match="raw socket access|Npcap"):
        link.send(b"payload")


def test_send_oserror_becomes_needsprivileges(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(scapy, "sendp", boom)
    with pytest.raises(NeedsPrivileges):
        ScapyLink(iface=None, sport=20001).send(b"x")
