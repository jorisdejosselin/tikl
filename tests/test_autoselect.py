"""Target auto-select: a MAC -> MAC-Telnet, an IP/host -> SSH."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

import tikl.cli as cli_mod
from tikl.cli import _looks_like_mac, cli


def test_looks_like_mac() -> None:
    assert _looks_like_mac("38:32:7A:26:8E:BD")
    assert _looks_like_mac("38-32-7a-26-8e-bd")
    assert not _looks_like_mac("192.168.88.1")
    assert not _looks_like_mac("router.local")
    assert not _looks_like_mac("38:32:7a:26:8e")  # too short


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    calls: dict[str, object] = {}
    monkeypatch.setenv("TIKL_PASS", "pw")
    monkeypatch.setattr(cli_mod, "_build_mac", lambda *a, **k: ("MAC", a, k))
    monkeypatch.setattr(cli_mod, "_build_ssh", lambda *a, **k: ("SSH", a, k))

    def fake_run(transport, desc, commands, timeout):  # type: ignore[no-untyped-def]
        calls["kind"] = transport[0]
        calls["desc"] = desc
        calls["commands"] = commands

    monkeypatch.setattr(cli_mod, "_run", fake_run)
    return calls


def test_bare_mac_routes_to_mactelnet(spy: dict) -> None:
    result = CliRunner().invoke(cli, ["38:32:7A:26:8E:BD", "/system resource print"])
    assert result.exit_code == 0, result.output
    assert spy["kind"] == "MAC"
    assert "MAC-Telnet" in spy["desc"]
    assert spy["commands"] == ["/system resource print"]


def test_bare_ip_routes_to_ssh(spy: dict) -> None:
    result = CliRunner().invoke(cli, ["192.168.88.1", "/system resource print"])
    assert result.exit_code == 0, result.output
    assert spy["kind"] == "SSH"
    assert "SSH" in spy["desc"]


def test_transport_override_forces_ssh_for_mac_target(spy: dict) -> None:
    result = CliRunner().invoke(cli, ["38:32:7A:26:8E:BD", "cmd", "--transport", "ssh"])
    assert result.exit_code == 0, result.output
    assert spy["kind"] == "SSH"
